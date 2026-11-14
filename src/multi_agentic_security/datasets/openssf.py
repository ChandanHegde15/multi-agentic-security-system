"""Source adapter: OpenSSF Malicious Packages (OSV JSON) -> malicious and withdrawn families.

Rules (D-048):
* Reports under ``osv/malicious/`` map to ``malicious``; reports under
  ``osv/withdrawn/`` or carrying a ``withdrawn`` timestamp map to ``withdrawn``
  (a retracted malicious report). They are never merged.
* Only ``affected`` entries with ecosystem PyPI or npm are mapped.
* ``versions`` -> one ``listed`` record per version. Otherwise an ``ECOSYSTEM``
  or ``SEMVER`` range (both order versions; ``GIT`` ranges do not) that is exactly ``introduced: 0`` with no end means every version, as the
  OSV schema defines it, and maps to scope ``all``; other ranges keep their
  intervals (same rules as the OSV adapter). Nothing else is widened.
* ``published`` is the report's publication date (UTC).
* ``aliases`` and the reporting origins (``database_specific.malicious-packages-origins``)
  go to ``corroborating_sources``: they are links, not independent confirmations.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable

from multi_agentic_security.contracts.evidence import EvidenceRecord, LabelFamily, Provenance, VersionScope
from multi_agentic_security.datasets.adapter_common import (
    AdapterResult, Skip, Snapshot, map_ecosystem, parse_utc_date, relative,
)
from multi_agentic_security.datasets.names import normalize_name
from multi_agentic_security.datasets.osv_pypi import ecosystem_intervals

SOURCE_DATASET = "openssf_malicious_packages"
ADAPTER_VERSION = "openssf/2"  # 2: SEMVER ranges read like ECOSYSTEM ranges


def _corroborating(data: dict, record_id: str) -> tuple[str, ...]:
    items = {str(a).strip() for a in data.get("aliases") or [] if str(a).strip()}
    for origin in (data.get("database_specific") or {}).get("malicious-packages-origins") or []:
        src, oid = origin.get("source"), origin.get("id")
        if src:
            items.add(f"origin:{src}:{oid}" if oid else f"origin:{src}")
    items.discard(record_id)
    return tuple(sorted(items))


def parse_report(data: dict, *, in_withdrawn_dir: bool, source_file: str, sha256: str, snapshot: Snapshot) -> AdapterResult:
    result = AdapterResult()
    record_id = str(data.get("id") or "").strip()
    if not record_id:
        result.skips.append(Skip("<no id>", "missing_id", source_file))
        return result
    withdrawn = in_withdrawn_dir or bool(data.get("withdrawn"))
    family = LabelFamily.WITHDRAWN if withdrawn else LabelFamily.MALICIOUS
    if withdrawn and not in_withdrawn_dir:
        result.notes.append(Skip(record_id, "withdrawn_field_in_malicious_dir"))
    provenance = Provenance(
        source_dataset=SOURCE_DATASET, source_version=snapshot.source_version, source_record_id=record_id,
        source_file=source_file, source_file_sha256=sha256, license=snapshot.license, retrieved_at=snapshot.retrieved_at,
    )
    published = parse_utc_date(data.get("published"))
    if published is None:
        result.notes.append(Skip(record_id, "no_published_date"))
    corroborating = _corroborating(data, record_id)
    seen: set[str] = set()
    for index, affected in enumerate(data.get("affected") or []):
        package = (affected or {}).get("package") or {}
        eco = map_ecosystem(package.get("ecosystem"))
        if eco is None:
            result.skips.append(Skip(record_id, "unsupported_ecosystem", f"affected[{index}] {package.get('ecosystem')!r}"))
            continue
        name = str(package.get("name") or "").strip()
        if not name:
            result.skips.append(Skip(record_id, "missing_package_name", f"affected[{index}]"))
            continue
        base = dict(family=family, ecosystem=eco, name_raw=name, name_normalized=normalize_name(eco, name),
                    provenance=provenance, published=published, corroborating_sources=corroborating)
        versions = [str(v).strip() for v in affected.get("versions") or [] if str(v).strip()]
        candidates: list[dict] = [dict(version_scope=VersionScope.LISTED, version=v) for v in versions]
        if not candidates:
            for r in affected.get("ranges") or []:
                if (r or {}).get("type") not in ("ECOSYSTEM", "SEMVER"):
                    result.skips.append(Skip(record_id, "non_ecosystem_range", f"affected[{index}] {(r or {}).get('type')}"))
                    continue
                events = r.get("events") or []
                if events == [{"introduced": "0"}]:
                    candidates.append(dict(version_scope=VersionScope.ALL))
                    continue
                try:
                    candidates.extend(dict(version_scope=VersionScope.RANGE, version_range=i) for i in ecosystem_intervals(events))
                except ValueError as exc:
                    result.skips.append(Skip(record_id, "malformed_range", f"affected[{index}] {exc}"))
        if not candidates:
            result.skips.append(Skip(record_id, "no_version_information", f"affected[{index}] {name}"))
            continue
        for cand in candidates:
            result.add_unique(EvidenceRecord(**base, **cand), seen)
    return result


def _iter_files(root: Path) -> Iterable[tuple[Path, bool]]:
    for sub, withdrawn in (("malicious", False), ("withdrawn", True)):
        base = root / sub
        if base.is_dir():
            for path in sorted(base.rglob("*.json")):
                yield path, withdrawn


def load(osv_root: Path, *, data_root: Path, snapshot: Snapshot) -> AdapterResult:
    """``osv_root`` is the repository's ``osv/`` folder (with ``malicious/`` and ``withdrawn/``)."""
    result = AdapterResult()
    for path, withdrawn in _iter_files(Path(osv_root)):
        result.files_read += 1
        raw = path.read_bytes()
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            result.skips.append(Skip(path.stem, "unreadable_json", str(exc)))
            continue
        result.extend(parse_report(data, in_withdrawn_dir=withdrawn, source_file=relative(path, data_root),
                                   sha256=hashlib.sha256(raw).hexdigest(), snapshot=snapshot))
    return result
