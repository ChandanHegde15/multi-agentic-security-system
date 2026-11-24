"""Source adapter: OSV.dev PyPI export -> vulnerable-family evidence records.

Scope (DATASET_CATALOG.md; DATASET_CATALOG.md):

* Only advisories that are not malicious-package reports are mapped. ``MAL-``
  records republish OpenSSF Malicious Packages and belong to the malicious
  family; they are skipped here and handled by the OpenSSF adapter.
* Withdrawn advisories are skipped and reported. They are *not* the
  ``withdrawn`` label family, which is reserved for retracted malicious reports.
* Only ``affected`` entries whose ecosystem is exactly ``PyPI`` are mapped.
* One evidence record per affected interval. ``ECOSYSTEM`` ranges are kept
  as intervals in the source's own version strings:
  ``introduced`` -> ``>=v``, ``fixed`` -> ``<v``, ``last_affected`` -> ``<=v``,
  ``limit`` -> ``<v``. An interval that is never closed stays open-ended
  (``>=v``). A claim is never widened to the whole package.
* An explicit ``versions`` list is used (one ``listed`` record per version)
  only when the entry has no interpretable ``ECOSYSTEM`` range. A range whose
  events do not follow ``introduced`` -> close (e.g. several unordered
  ``last_affected`` events) is not interpreted; it is skipped and reported. ``GIT`` ranges carry commit
  hashes, not PyPI versions, and are skipped.
* ``published`` is the UTC date of the advisory's ``published`` timestamp;
  an advisory without one can never be "known before" a cut-off.
* Aliases (e.g. GHSA <-> PYSEC) are recorded in ``corroborating_sources``.
  They are links to the same claim, not independent confirmations.

The adapter only reads JSON text. It never runs, extracts or installs anything.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from multi_agentic_security.contracts.evidence import (
    EvidenceRecord,
    LabelFamily,
    Provenance,
    VersionScope,
)
from multi_agentic_security.datasets.names import PYPI, normalize_name

SOURCE_DATASET = "osv_pypi"
ADAPTER_VERSION = "osv_pypi/2"  # 2: listed versions used when every ECOSYSTEM range is malformed


@dataclass(frozen=True)
class OsvSnapshot:
    """Identifies the export the files came from (download_log.jsonl)."""

    source_version: str
    retrieved_at: datetime
    license: str = "unverified (OSV.dev aggregate; per-upstream terms)"


@dataclass(frozen=True)
class Skip:
    record_id: str
    reason: str
    detail: str = ""


@dataclass
class AdapterResult:
    records: list[EvidenceRecord] = field(default_factory=list)
    skips: list[Skip] = field(default_factory=list)   # input not mapped, with the reason
    notes: list[Skip] = field(default_factory=list)   # mapped, but with a caveat
    duplicates_dropped: int = 0

    def extend(self, other: "AdapterResult") -> None:
        self.records.extend(other.records)
        self.skips.extend(other.skips)
        self.notes.extend(other.notes)
        self.duplicates_dropped += other.duplicates_dropped


def _parse_published(value: Any) -> Optional[date]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).date()


def ecosystem_intervals(events: Iterable[dict]) -> list[str]:
    """Turn an OSV ECOSYSTEM ``events`` list into interval strings, in source order."""
    intervals: list[str] = []
    lower: Optional[str] = None
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise ValueError(f"malformed range event: {event!r}")
        (kind, value), = event.items()
        value = str(value).strip()
        if not value:
            raise ValueError(f"empty version in range event: {event!r}")
        if kind == "introduced":
            if lower is not None:  # a new interval opens before the previous closed
                intervals.append(f">={lower}")
            lower = value
        elif kind in ("fixed", "last_affected", "limit"):
            op = "<=" if kind == "last_affected" else "<"
            if lower is None:
                raise ValueError(f"{kind} event without a preceding introduced event")
            intervals.append(f">={lower},{op}{value}")
            lower = None
        else:
            raise ValueError(f"unknown range event type: {kind!r}")
    if lower is not None:
        intervals.append(f">={lower}")
    return intervals


def parse_record(
    data: dict,
    *,
    source_file: str,
    source_file_sha256: str,
    snapshot: OsvSnapshot,
) -> AdapterResult:
    """Map one parsed OSV record to vulnerable-family evidence records."""
    result = AdapterResult()
    record_id = str(data.get("id") or "").strip()
    if not record_id:
        result.skips.append(Skip("<no id>", "missing_id", source_file))
        return result
    if record_id.upper().startswith("MAL-"):
        result.skips.append(Skip(record_id, "malicious_report_out_of_scope"))
        return result
    if data.get("withdrawn"):
        result.skips.append(Skip(record_id, "withdrawn_advisory", str(data["withdrawn"])))
        return result

    provenance = Provenance(
        source_dataset=SOURCE_DATASET,
        source_version=snapshot.source_version,
        source_record_id=record_id,
        source_file=source_file,
        source_file_sha256=source_file_sha256,
        license=snapshot.license,
        retrieved_at=snapshot.retrieved_at,
    )
    published = _parse_published(data.get("published"))
    aliases = tuple(sorted({str(a).strip() for a in data.get("aliases") or [] if str(a).strip()} - {record_id}))
    if published is None:
        result.notes.append(Skip(record_id, "no_published_date"))

    seen: set[str] = set()
    pypi_entries = 0
    for index, affected in enumerate(data.get("affected") or []):
        package = (affected or {}).get("package") or {}
        ecosystem = package.get("ecosystem")
        if ecosystem != "PyPI":
            result.skips.append(Skip(record_id, "other_ecosystem", f"affected[{index}] {ecosystem!r}"))
            continue
        pypi_entries += 1
        name_raw = str(package.get("name") or "").strip()
        if not name_raw:
            result.skips.append(Skip(record_id, "missing_package_name", f"affected[{index}]"))
            continue
        name_normalized = normalize_name(PYPI, name_raw)

        candidates: list[tuple[VersionScope, Optional[str], Optional[str]]] = []
        ranges = affected.get("ranges") or []
        eco_ranges = [r for r in ranges if (r or {}).get("type") == "ECOSYSTEM"]
        for r in ranges:
            rtype = (r or {}).get("type")
            if rtype != "ECOSYSTEM":
                result.skips.append(Skip(record_id, "non_ecosystem_range", f"affected[{index}] {rtype}"))
        usable_ranges = 0
        for r in eco_ranges:
            try:
                intervals = ecosystem_intervals(r.get("events") or [])
            except ValueError as exc:
                result.skips.append(Skip(record_id, "malformed_range", f"affected[{index}] {exc}"))
                continue
            usable_ranges += 1
            candidates.extend((VersionScope.RANGE, None, interval) for interval in intervals)
        if usable_ranges == 0:
            # No interpretable ECOSYSTEM range: fall back to the explicitly listed versions.
            versions = [str(v).strip() for v in affected.get("versions") or [] if str(v).strip()]
            candidates.extend((VersionScope.LISTED, v, None) for v in versions)
            if eco_ranges and versions:
                result.notes.append(Skip(record_id, "malformed_range_listed_versions_used", f"affected[{index}]"))
        if not candidates:
            result.skips.append(Skip(record_id, "no_version_information", f"affected[{index}] {name_raw}"))
            continue

        for scope, version, version_range in candidates:
            key = f"{name_normalized}\x1f{scope.value}\x1f{version or ''}\x1f{version_range or ''}"
            if key in seen:
                result.duplicates_dropped += 1
                continue
            seen.add(key)
            result.records.append(
                EvidenceRecord(
                    family=LabelFamily.VULNERABLE,
                    ecosystem=PYPI,
                    name_raw=name_raw,
                    name_normalized=name_normalized,
                    version_scope=scope,
                    version=version,
                    version_range=version_range,
                    published=published,
                    corroborating_sources=aliases,
                    provenance=provenance,
                )
            )
    if pypi_entries == 0:
        result.skips.append(Skip(record_id, "no_pypi_affected_entry"))
    return result


def load_file(path: Path, *, data_root: Path, snapshot: OsvSnapshot) -> AdapterResult:
    """Read one OSV JSON file (text only) and map it."""
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        source_file = Path(path).resolve().relative_to(Path(data_root).resolve()).as_posix()
    except ValueError:
        source_file = Path(path).name
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        result = AdapterResult()
        result.skips.append(Skip(Path(path).stem, "unreadable_json", str(exc)))
        return result
    return parse_record(data, source_file=source_file, source_file_sha256=digest, snapshot=snapshot)


def load_directory(directory: Path, *, data_root: Path, snapshot: OsvSnapshot) -> AdapterResult:
    result = AdapterResult()
    for path in sorted(Path(directory).glob("*.json")):
        result.extend(load_file(path, data_root=data_root, snapshot=snapshot))
    return result
