"""Source adapters for name lists (D-048):

* DataDog malicious-packages manifests -> ``malicious``
  (name -> null means the whole package; a version list means those versions only).
* PyPI MalRegistry path listing -> ``malicious`` (``name/version/file`` -> listed version).
* Ecosyste.ms typosquatting pairs -> ``typosquat`` (variant with its target).
  Its README says inclusion does not prove maliciousness, so nothing here is
  mapped to ``malicious``.
* You Can't Touch This npm typosquatting pairs -> ``typosquat`` (dated by the
  dataset release, not the package upload time) and its npm target list -> ``benign_reference``.
* PyPI popular-package list -> ``benign_reference`` (a candidate, never proof of safety).

Only the YCTT release date and the popular-list date give a publication date; records without one are never "known before" a cut-off.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import date
from pathlib import Path
from typing import Optional

from multi_agentic_security.contracts.evidence import EvidenceRecord, LabelFamily, Provenance, VersionScope
from multi_agentic_security.datasets.adapter_common import (
    AdapterResult, Skip, Snapshot, file_sha256, map_ecosystem, parse_utc_date, relative,
)
from multi_agentic_security.datasets.names import normalize_name


def _prov(dataset: str, record_id: str, path: Path, data_root: Path, sha: str, snap: Snapshot) -> Provenance:
    return Provenance(source_dataset=dataset, source_version=snap.source_version, source_record_id=record_id,
                      source_file=relative(path, data_root), source_file_sha256=sha, license=snap.license,
                      retrieved_at=snap.retrieved_at)


def _valid_name(eco: str, name: str) -> Optional[str]:
    try:
        return normalize_name(eco, name)
    except ValueError:
        return None


# --------------------------------------------------------------------------- DataDog

def load_datadog(samples_dir: Path, *, data_root: Path, snapshot: Snapshot) -> AdapterResult:
    """``samples_dir`` holds ``<ecosystem>/manifest.json``."""
    result, seen = AdapterResult(), set()
    for manifest in sorted(Path(samples_dir).glob("*/manifest.json")):
        result.files_read += 1
        eco_label = manifest.parent.name
        eco = map_ecosystem(eco_label)
        data = json.loads(manifest.read_text(encoding="utf-8"))
        if eco is None:
            result.skips.append(Skip(f"datadog:{eco_label}", "unsupported_ecosystem", f"{len(data)} names"))
            continue
        sha = file_sha256(manifest)
        for name, versions in sorted(data.items()):
            rid = f"{eco}:{name}"
            if _valid_name(eco, name) is None:
                result.skips.append(Skip(rid, "invalid_name"))
                continue
            prov = _prov("datadog_malicious_packages", rid, manifest, data_root, sha, snapshot)
            base = dict(family=LabelFamily.MALICIOUS, ecosystem=eco, name_raw=name,
                        name_normalized=normalize_name(eco, name), provenance=prov)
            if versions is None:
                result.add_unique(EvidenceRecord(**base, version_scope=VersionScope.ALL), seen)
            elif isinstance(versions, list) and versions:
                for v in versions:
                    result.add_unique(EvidenceRecord(**base, version_scope=VersionScope.LISTED, version=str(v).strip()), seen)
            else:
                result.skips.append(Skip(rid, "unrecognised_version_field", repr(versions)[:60]))
    return result


# --------------------------------------------------------------------------- MalRegistry

def load_malregistry(listing: Path, *, data_root: Path, snapshot: Snapshot) -> AdapterResult:
    result, seen = AdapterResult(files_read=1), set()
    sha = file_sha256(listing)
    for line_no, line in enumerate(Path(listing).read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        parts = line.split("/")
        if len(parts) != 3:
            result.skips.append(Skip(f"line{line_no}", "not_name_version_file", line[:80]))
            continue
        name, version, _file = parts
        if _valid_name("pypi", name) is None or not version:
            result.skips.append(Skip(f"line{line_no}", "invalid_name_or_version", line[:80]))
            continue
        prov = _prov("pypi_malregistry", f"{name}/{version}", listing, data_root, sha, snapshot)
        result.add_unique(EvidenceRecord(family=LabelFamily.MALICIOUS, ecosystem="pypi", name_raw=name,
                                         name_normalized=normalize_name("pypi", name), version_scope=VersionScope.LISTED,
                                         version=version, provenance=prov), seen)
    return result


# --------------------------------------------------------------------------- typosquat pairs

def _pair(eco: str, variant: str, target: str, prov: Provenance, published: Optional[date],
          corroborating: tuple[str, ...] = ()) -> EvidenceRecord:
    return EvidenceRecord(family=LabelFamily.TYPOSQUAT, ecosystem=eco, name_raw=variant,
                          name_normalized=normalize_name(eco, variant), version_scope=VersionScope.ALL,
                          target_name_raw=target, target_name_normalized=normalize_name(eco, target),
                          provenance=prov, published=published, corroborating_sources=corroborating)


def load_ecosystems_typosquats(csv_path: Path, *, data_root: Path, snapshot: Snapshot) -> AdapterResult:
    result, seen = AdapterResult(files_read=1), set()
    sha = file_sha256(csv_path)
    for row in csv.DictReader(io.StringIO(Path(csv_path).read_text(encoding="utf-8"))):
        variant, target = (row.get("malicious_package") or "").strip(), (row.get("target_package") or "").strip()
        eco = map_ecosystem(row.get("ecosystem"))
        rid = f"{row.get('ecosystem')}:{variant}->{target}"
        if eco is None:
            result.skips.append(Skip(rid, "unsupported_ecosystem"))
            continue
        if not variant or not target or _valid_name(eco, variant) is None or _valid_name(eco, target) is None:
            result.skips.append(Skip(rid, "invalid_name"))
            continue
        if normalize_name(eco, variant) == normalize_name(eco, target):
            result.skips.append(Skip(rid, "variant_equals_target"))
            continue
        corr = tuple(sorted({f"listed_by:{row['source'].strip()}"} if (row.get("source") or "").strip() else set()))
        prov = _prov("ecosyste_ms_typosquatting", rid, csv_path, data_root, sha, snapshot)
        result.add_unique(_pair(eco, variant, target, prov, None, corr), seen)
        if (row.get("classification") or "").strip():
            result.notes.append(Skip(rid, "classification", row["classification"].strip()))
    return result


def load_yctt_pairs(csv_path: Path, *, data_root: Path, snapshot: Snapshot, release_date: Optional[date]) -> AdapterResult:
    """``published`` is the dataset's release date, not the CSV's ``published`` column:
    that column is when the typosquat package was uploaded, which is earlier than any
    report of it and would leak knowledge across a cut-off."""
    result, seen = AdapterResult(files_read=1), set()
    sha = file_sha256(csv_path)
    for row in csv.DictReader(io.StringIO(Path(csv_path).read_text(encoding="utf-8"))):
        variant, target = (row.get("package_name") or "").strip(), (row.get("target") or "").strip()
        rid = f"npm:{variant}->{target}"
        if not variant or not target or _valid_name("npm", variant) is None or _valid_name("npm", target) is None:
            result.skips.append(Skip(rid, "invalid_name"))
            continue
        if normalize_name("npm", variant) == normalize_name("npm", target):
            result.skips.append(Skip(rid, "variant_equals_target"))
            continue
        prov = _prov("you_cant_touch_this", rid, csv_path, data_root, sha, snapshot)
        result.add_unique(_pair("npm", variant, target, prov, release_date), seen)
    return result


# --------------------------------------------------------------------------- benign reference

def load_yctt_targets(csv_path: Path, *, data_root: Path, snapshot: Snapshot) -> AdapterResult:
    result, seen = AdapterResult(files_read=1), set()
    sha = file_sha256(csv_path)
    reader = csv.DictReader(io.StringIO(Path(csv_path).read_text(encoding="utf-8")))
    name_field = next((f for f in (reader.fieldnames or []) if f in ("package_name", "target", "name")), None)
    if name_field is None:
        result.skips.append(Skip(csv_path.name, "no_name_column", ",".join(reader.fieldnames or [])))
        return result
    for row in reader:
        name = (row.get(name_field) or "").strip()
        if _valid_name("npm", name) is None:
            result.skips.append(Skip(f"npm:{name}", "invalid_name"))
            continue
        prov = _prov("you_cant_touch_this", f"npm-target:{name}", csv_path, data_root, sha, snapshot)
        result.add_unique(EvidenceRecord(family=LabelFamily.BENIGN_REFERENCE, ecosystem="npm", name_raw=name,
                                         name_normalized=normalize_name("npm", name), version_scope=VersionScope.ALL,
                                         provenance=prov), seen)
    return result


def load_pypi_popular(json_path: Path, *, data_root: Path, snapshot: Snapshot) -> AdapterResult:
    result, seen = AdapterResult(files_read=1), set()
    sha = file_sha256(json_path)
    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    listed = parse_utc_date((data.get("last_update") or "").replace(" ", "T", 1))
    for rank, row in enumerate(data.get("rows") or [], start=1):
        name = str(row.get("project") or "").strip()
        if _valid_name("pypi", name) is None:
            result.skips.append(Skip(f"rank{rank}", "invalid_name", name))
            continue
        prov = _prov("pypi_popular", f"rank:{rank}:{name}", json_path, data_root, sha, snapshot)
        result.add_unique(EvidenceRecord(family=LabelFamily.BENIGN_REFERENCE, ecosystem="pypi", name_raw=name,
                                         name_normalized=normalize_name("pypi", name), version_scope=VersionScope.ALL,
                                         provenance=prov, published=listed), seen)
    return result
