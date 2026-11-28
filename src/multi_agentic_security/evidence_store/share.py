"""Share the normalized evidence tables with a teammate, privately, so the web interface runs on their machine.

Only the tables whose source licence allows redistribution are packed, and only their ``MANIFEST.json`` and
``records.jsonl`` (names, versions and advisory facts; no package code). ``malicious/malregistry_listing`` is
left out because its source states no licence. Without it the store reports one missing table, and Agents 2 and 3
then never report "no evidence" where that table could have held a record.

Make the package (owner, where the full store exists)::

    python -m multi_agentic_security.evidence_store.share make --out runtime/evidence_share.zip

Install it (teammate, in their own copy of the repository)::

    python -m multi_agentic_security.evidence_store.share install evidence_share.zip

The package is private: send it directly (for example a link restricted to one person), never commit or publish it.
Nothing is ever overwritten; every file is checked against its SHA-256 before it is packed and again before it is
written.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Optional

SHARE_VERSION = "evidence_share/1"
DEFAULT_ROOT = Path("research") / "datasets" / "verified" / "normalized" / "v1"
TABLE_FILES = ("MANIFEST.json", "records.jsonl")
PREFIX = "evidence_share/v1"


@dataclass(frozen=True)
class ShareTable:
    folder: str
    table: str
    licence: str

    @property
    def key(self) -> str:
        return f"{self.folder}/{self.table}"


SHAREABLE: tuple[ShareTable, ...] = (
    ShareTable("vulnerable", "osv_pypi_a2",
               "OSV.dev PyPI advisories (PyPA Advisory Database and GitHub Advisory Database, CC-BY 4.0 per upstream)"),
    ShareTable("malicious_withdrawn", "openssf_a2", "OpenSSF Malicious Packages, Apache-2.0"),
    ShareTable("malicious", "datadog_manifests", "Datadog malicious software packages dataset (manifests only), Apache-2.0"),
    ShareTable("typosquat", "ecosystems_typosquats", "Ecosyste.ms typosquatting dataset, CC0 1.0"),
    ShareTable("typosquat", "yctt_pairs", "You Can't Touch This (Truong et al.), MIT"),
    ShareTable("benign_reference", "pypi_popular", "Top PyPI packages (H. van Kemenade)"),
    ShareTable("benign_reference", "yctt_targets", "You Can't Touch This (Truong et al.), MIT"),
)
EXCLUDED = {"malicious/malregistry_listing": "PyPI MalRegistry listing: no licence stated, not redistributed"}

NOTICE = """PRIVATE EVIDENCE SHARE - do not publish, commit or forward.

These are the normalized evidence tables of the Multi-Agentic Security System, shared for running the
software locally. They contain package names, versions and advisory facts only; no package code.

Sources and licences (attribution required where stated):
{lines}

Not included: {excluded}

Install with:  python -m multi_agentic_security.evidence_store.share install <this zip>
"""


class ShareError(Exception):
    """A refusal; nothing has been written when it is raised."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _checked_table(root: Path, spec: ShareTable) -> dict[str, bytes]:
    folder = root / spec.folder / spec.table
    files = {}
    for name in TABLE_FILES:
        path = folder / name
        if not path.is_file():
            raise ShareError(f"{spec.key}: {name} missing")
        files[name] = path.read_bytes()
    try:
        expected = json.loads(files["MANIFEST.json"])["files"]["records.jsonl"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ShareError(f"{spec.key}: MANIFEST.json unusable ({type(exc).__name__})") from exc
    data = files["records.jsonl"]
    if _sha256(data) != expected["sha256"] or len(data) != int(expected["bytes"]):
        raise ShareError(f"{spec.key}: records.jsonl does not match its MANIFEST.json")
    return files


def make_share(root: Path, out: Path) -> dict:
    """Pack the shareable tables of ``root`` into a new zip at ``out``; refuses to overwrite."""
    root, out = Path(root), Path(out)
    if out.exists():
        raise ShareError(f"{out} already exists; choose another name")
    tables = {spec.key: _checked_table(root, spec) for spec in SHAREABLE}
    record = {"format": SHARE_VERSION, "tables": {}, "excluded": EXCLUDED}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for spec in SHAREABLE:
            for name, data in tables[spec.key].items():
                zf.writestr(f"{PREFIX}/{spec.key}/{name}", data)
            record["tables"][spec.key] = {"licence": spec.licence,
                                          "files": {n: _sha256(d) for n, d in tables[spec.key].items()}}
        lines = "\n".join(f"- {spec.key}: {spec.licence}" for spec in SHAREABLE)
        zf.writestr(f"{PREFIX}/NOTICE.txt", NOTICE.format(lines=lines, excluded="; ".join(EXCLUDED.values())))
        zf.writestr(f"{PREFIX}/SHARE_MANIFEST.json", json.dumps(record, indent=1, sort_keys=True))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(buf.getvalue())
    return {"out": str(out), "tables": sorted(record["tables"]), "excluded": sorted(EXCLUDED), "bytes": out.stat().st_size}


def install_share(zip_path: Path, root: Path) -> dict:
    """Unpack a share made by ``make_share`` into ``root`` after checking every file; never overwrites."""
    zip_path, root = Path(zip_path), Path(root)
    allowed = {f"{PREFIX}/{spec.key}/{name}" for spec in SHAREABLE for name in TABLE_FILES}
    allowed |= {f"{PREFIX}/NOTICE.txt", f"{PREFIX}/SHARE_MANIFEST.json"}
    try:
        zf = zipfile.ZipFile(zip_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ShareError(f"{zip_path}: not a readable zip ({type(exc).__name__})") from exc
    with zf:
        names = [i.filename for i in zf.infolist() if not i.is_dir()]
        unexpected = [n for n in names if n not in allowed or PurePosixPath(n).is_absolute() or ".." in n.split("/")]
        if unexpected:
            raise ShareError(f"unexpected entries in the package: {unexpected[:3]}")
        try:
            record = json.loads(zf.read(f"{PREFIX}/SHARE_MANIFEST.json"))
        except (KeyError, ValueError) as exc:
            raise ShareError("SHARE_MANIFEST.json missing or unreadable") from exc
        if record.get("format") != SHARE_VERSION:
            raise ShareError(f"unknown package format {record.get('format')!r}")
        to_write: list[tuple[Path, bytes]] = []
        for key, info in record.get("tables", {}).items():
            spec = next((s for s in SHAREABLE if s.key == key), None)
            if spec is None:
                raise ShareError(f"table {key!r} is not shareable")
            target = root / spec.folder / spec.table
            if target.exists():
                raise ShareError(f"{target} already exists; nothing was installed")
            for name in TABLE_FILES:
                data = zf.read(f"{PREFIX}/{key}/{name}")
                if _sha256(data) != info["files"][name]:
                    raise ShareError(f"{key}/{name}: checksum mismatch; the package is damaged")
                to_write.append((target / name, data))
            manifest = json.loads(dict((p.name, d) for p, d in to_write[-2:])["MANIFEST.json"])
            rec = dict((p.name, d) for p, d in to_write[-2:])["records.jsonl"]
            if _sha256(rec) != manifest["files"]["records.jsonl"]["sha256"]:
                raise ShareError(f"{key}: records.jsonl does not match its MANIFEST.json")
    for path, data in to_write:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return {"root": str(root), "tables": sorted(record["tables"]), "files": len(to_write)}


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m multi_agentic_security.evidence_store.share",
                                 description="Share the normalized evidence tables privately with a teammate.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    mk = sub.add_parser("make", help="pack the shareable tables into a zip")
    mk.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    mk.add_argument("--out", type=Path, default=Path("runtime") / "evidence_share.zip")
    ins = sub.add_parser("install", help="unpack a share into this repository")
    ins.add_argument("zip", type=Path)
    ins.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = ap.parse_args(argv)
    try:
        result = make_share(args.root, args.out) if args.cmd == "make" else install_share(args.zip, args.root)
    except ShareError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
