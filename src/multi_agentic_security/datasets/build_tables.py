"""Build normalized evidence tables (one folder per table) from the extracted sources.

Usage (from the repository root):

    python -m multi_agentic_security.datasets.build_tables --data-root research/datasets --all
    python -m multi_agentic_security.datasets.build_tables --data-root research/datasets --table openssf

Each table goes to ``verified/normalized/v1/<family>/<table>/`` with
``records.jsonl``, ``skips.csv``, ``notes.csv`` and ``MANIFEST.json``. An existing
folder is never overwritten. The OSV PyPI table is built by ``build_osv_pypi``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from multi_agentic_security.contracts.evidence import SCHEMA_VERSION
from multi_agentic_security.datasets import listings, openssf
from multi_agentic_security.datasets.adapter_common import AdapterResult, Snapshot

V1 = Path("extracted/v1/data")
EXTRAS = Path("extracted/extras_v1/data")
YCTT = V1 / "sources/you_cant_touch_this/raw/you_cant_touch_this_v1.1.0.verified/minh-tg-nss2024-typosquatting-mitigation-and-detection-673ae0a/String Matching"
OUT = Path("verified/normalized/v1")


def _log(data_root: Path) -> list[dict]:
    lines = (data_root / V1 / "manifests/download_log.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _git_snapshot(data_root: Path, source: str, license: str) -> Snapshot:
    entries = [e for e in _log(data_root) if e.get("source") == source and e.get("commit")]
    if len(entries) != 1:
        raise SystemExit(f"expected one commit entry for {source}, found {len(entries)}")
    e = entries[0]
    return Snapshot(source_version=f"git {e['commit']}", retrieved_at=datetime.fromisoformat(e["at"]), license=license)


def _yctt_snapshot(data_root: Path) -> Snapshot:
    times = [e["at"] for e in _log(data_root) if e.get("source") == "you_cant_touch_this"]
    return Snapshot(source_version="Zenodo 23520699 v1.1.0 (MD5 verified)", retrieved_at=datetime.fromisoformat(max(times)),
                    license="MIT (c) 2024 Minh Truong")


def _yctt_release(data_root: Path):
    from datetime import date
    meta = json.loads((data_root / V1 / "sources/you_cant_touch_this/record_metadata.json").read_text(encoding="utf-8"))
    return date.fromisoformat(meta["metadata"]["publication_date"])


def _popular_snapshot(data_root: Path) -> Snapshot:
    meta = json.loads((data_root / EXTRAS / "manifests/extras_sources.json").read_text(encoding="utf-8"))["pypi_popular"]
    return Snapshot(source_version=f"top-pypi-packages-30-days last_update {meta['last_update']} sha256:{meta['sha256']}",
                    retrieved_at=datetime.fromisoformat(meta["updated_at"]), license="unverified (hugovk/top-pypi-packages; PSF BigQuery data)")


@dataclass(frozen=True)
class Table:
    family: str
    adapter_version: str
    input_path: Path
    run: Callable[[Path], AdapterResult]


def tables(data_root: Path) -> dict[str, Table]:
    r = data_root
    return {
        "openssf_a2": Table("malicious_withdrawn", openssf.ADAPTER_VERSION, V1 / "sources/openssf_malicious_packages/raw/osv",
                         lambda p: openssf.load(p, data_root=r, snapshot=_git_snapshot(r, "openssf_malicious_packages", "Apache-2.0"))),
        "datadog_manifests": Table("malicious", "datadog/1", V1 / "sources/datadog_malicious_packages/raw/samples",
                                   lambda p: listings.load_datadog(p, data_root=r, snapshot=_git_snapshot(r, "datadog_malicious_packages", "Apache-2.0 (+NOTICE)"))),
        "malregistry_listing": Table("malicious", "malregistry/1", V1 / "sources/pypi_malregistry/tree_listing.txt",
                                     lambda p: listings.load_malregistry(p, data_root=r, snapshot=_git_snapshot(r, "pypi_malregistry", "none stated; do not redistribute"))),
        "ecosystems_typosquats": Table("typosquat", "ecosystems/1", V1 / "sources/ecosyste_ms_typosquatting/raw/typosquats.csv",
                                       lambda p: listings.load_ecosystems_typosquats(p, data_root=r, snapshot=_git_snapshot(r, "ecosyste_ms_typosquatting", "CC0-1.0"))),
        "yctt_pairs": Table("typosquat", "yctt/1", YCTT / "npm_typosquatting_data.csv",
                            lambda p: listings.load_yctt_pairs(p, data_root=r, snapshot=_yctt_snapshot(r), release_date=_yctt_release(r))),
        "yctt_targets": Table("benign_reference", "yctt/1", YCTT / "npm_target_package_data.csv",
                              lambda p: listings.load_yctt_targets(p, data_root=r, snapshot=_yctt_snapshot(r))),
        "pypi_popular": Table("benign_reference", "popular/1", EXTRAS / "sources/pypi_popular/raw/top-pypi-packages-30-days.min.json",
                              lambda p: listings.load_pypi_popular(p, data_root=r, snapshot=_popular_snapshot(r))),
    }


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_table(name: str, table: Table, result: AdapterResult, out_dir: Path, data_root: Path) -> dict:
    if out_dir.exists():
        raise SystemExit(f"output folder exists, refusing to overwrite: {out_dir}")
    rows = sorted((r.to_dict() for r in result.records), key=lambda d: d["evidence_id"])
    if len({r["evidence_id"] for r in rows}) != len(rows):
        raise SystemExit(f"{name}: evidence_id collision; refusing to write")
    out_dir.mkdir(parents=True)
    with (out_dir / "records.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    for fname, items in (("skips.csv", result.skips), ("notes.csv", result.notes)):
        with (out_dir / fname).open("w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(["record_id", "reason", "detail"])
            for s in sorted(items, key=lambda s: (s.record_id, s.reason, s.detail)):
                w.writerow([s.record_id, s.reason, s.detail])
    dated = [r["published"] for r in rows if r["published"]]
    manifest = {
        "table": name,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "schema_version": SCHEMA_VERSION,
        "adapter_version": table.adapter_version,
        "input_path": table.input_path.as_posix(),
        "source_versions": sorted({r["provenance"]["source_version"] for r in rows}),
        "licenses": sorted({r["provenance"]["license"] for r in rows}),
        "counts": {
            "files_read": result.files_read,
            "records": len(rows),
            "by_family": dict(sorted(Counter(r["family"] for r in rows).items())),
            "by_ecosystem": dict(sorted(Counter(r["ecosystem"] for r in rows).items())),
            "by_scope": dict(sorted(Counter(r["version_scope"] for r in rows).items())),
            "distinct_packages": len({(r["ecosystem"], r["name_normalized"]) for r in rows}),
            "records_without_published": len(rows) - len(dated),
            "duplicates_dropped": result.duplicates_dropped,
            "skips_by_reason": dict(sorted(Counter(s.reason for s in result.skips).items())),
            "notes_by_reason": dict(sorted(Counter(s.reason for s in result.notes).items())),
        },
        "published_range": [min(dated), max(dated)] if dated else [None, None],
        "files": {f: {"sha256": _sha(out_dir / f), "bytes": (out_dir / f).stat().st_size}
                  for f in ("records.jsonl", "skips.csv", "notes.csv")},
    }
    (out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def build(data_root: Path, names: list[str]) -> dict[str, dict]:
    registry = tables(data_root)
    unknown = set(names) - set(registry)
    if unknown:
        raise SystemExit(f"unknown tables: {sorted(unknown)}; known: {sorted(registry)}")
    out = {}
    for name in names:
        table = registry[name]
        result = table.run(data_root / table.input_path)
        out[name] = write_table(name, table, result, data_root / OUT / table.family / name, data_root)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-root", type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--table", action="append")
    group.add_argument("--all", action="store_true")
    args = parser.parse_args(argv)
    names = sorted(tables(args.data_root)) if args.all else args.table
    for name, manifest in build(args.data_root, names).items():
        print(name, json.dumps(manifest["counts"]), manifest["published_range"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
