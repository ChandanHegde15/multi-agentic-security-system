"""Build the vulnerable-family evidence table from the OSV PyPI export.

Usage (from the repository root):

    python -m multi_agentic_security.datasets.build_osv_pypi \
        --data-root research/datasets \
        --out research/datasets/verified/normalized/v1/vulnerable/osv_pypi

Reads the extracted OSV JSON files (text only), writes ``records.jsonl``,
``skips.csv``, ``notes.csv`` and ``MANIFEST.json`` into a new output folder and
refuses to overwrite an existing one. Records quarantined during extraction are
listed as expected-missing and are not read (QUARANTINE_RECORD.md).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from multi_agentic_security.contracts.evidence import SCHEMA_VERSION
from multi_agentic_security.datasets.osv_pypi import ADAPTER_VERSION, OsvSnapshot, load_directory

OSV_DIR = Path("extracted/v1/data/sources/osv/raw/osv_PyPI")
DOWNLOAD_LOG = Path("extracted/v1/data/manifests/download_log.jsonl")
# Advisory records removed by Microsoft Defender during extraction (MAL- ones are out of scope anyway).
EXPECTED_MISSING = ("GHSA-wx9m-wx4f-4cmg", "MAL-2026-1261", "MAL-2026-1262", "MAL-2026-4174")


def snapshot_from_log(log_path: Path) -> OsvSnapshot:
    downloads = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("source") == "osv" and entry.get("action") == "download":
            downloads.append(entry)
    if len(downloads) != 1:
        raise SystemExit(f"expected exactly one OSV download entry in {log_path}, found {len(downloads)}")
    d = downloads[0]
    retrieved = datetime.fromisoformat(d["at"])
    version = f"{d['url'].rsplit('/', 2)[-2]}/all.zip last-modified {d['last_modified']} sha256:{d['sha256']}"
    return OsvSnapshot(source_version=version, retrieved_at=retrieved)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(data_root: Path, out_dir: Path) -> dict:
    if out_dir.exists():
        raise SystemExit(f"output folder exists, refusing to overwrite: {out_dir}")
    osv_dir = data_root / OSV_DIR
    snapshot = snapshot_from_log(data_root / DOWNLOAD_LOG)
    present = {p.stem for p in osv_dir.glob("*.json")}
    missing = sorted(set(EXPECTED_MISSING) - present)
    unexpected_present = sorted(set(EXPECTED_MISSING) & present)

    result = load_directory(osv_dir, data_root=data_root, snapshot=snapshot)
    rows = sorted((r.to_dict() for r in result.records), key=lambda d: d["evidence_id"])
    ids = [r["evidence_id"] for r in rows]
    if len(ids) != len(set(ids)):
        raise SystemExit("evidence_id collision; refusing to write")

    out_dir.mkdir(parents=True)
    with (out_dir / "records.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    for name, items in (("skips.csv", result.skips), ("notes.csv", result.notes)):
        with (out_dir / name).open("w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh, lineterminator="\n")
            writer.writerow(["record_id", "reason", "detail"])
            for s in sorted(items, key=lambda s: (s.record_id, s.reason, s.detail)):
                writer.writerow([s.record_id, s.reason, s.detail])

    scope = Counter(r["version_scope"] for r in rows)
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "schema_version": SCHEMA_VERSION,
        "adapter_version": ADAPTER_VERSION,
        "family": "vulnerable",
        "source_dataset": "osv_pypi",
        "source_version": snapshot.source_version,
        "retrieved_at": snapshot.retrieved_at.isoformat(),
        "license": snapshot.license,
        "input_dir": OSV_DIR.as_posix(),
        "input_files_read": len(present),
        "expected_missing_quarantined": missing,
        "expected_missing_but_present": unexpected_present,
        "counts": {
            "records": len(rows),
            "records_by_scope": dict(sorted(scope.items())),
            "records_without_published": sum(1 for r in rows if r["published"] is None),
            "advisories_with_records": len({r["provenance"]["source_record_id"] for r in rows}),
            "distinct_packages": len({r["name_normalized"] for r in rows}),
            "duplicates_dropped": result.duplicates_dropped,
            "skips_by_reason": dict(sorted(Counter(s.reason for s in result.skips).items())),
            "notes_by_reason": dict(sorted(Counter(s.reason for s in result.notes).items())),
        },
        "published_range": [
            min((r["published"] for r in rows if r["published"]), default=None),
            max((r["published"] for r in rows if r["published"]), default=None),
        ],
        "files": {},
    }
    for name in ("records.jsonl", "skips.csv", "notes.csv"):
        manifest["files"][name] = {"sha256": _sha256(out_dir / name), "bytes": (out_dir / name).stat().st_size}
    (out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    manifest = build(args.data_root, args.out)
    print(json.dumps(manifest["counts"], indent=2))
    print("missing (expected, quarantined):", manifest["expected_missing_quarantined"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
