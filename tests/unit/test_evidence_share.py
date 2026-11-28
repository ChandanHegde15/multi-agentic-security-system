"""Private evidence share (evidence_store.share) on the fixture store; no network, no real data."""

from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

import pytest

from multi_agentic_security.evidence_store import EvidenceStore
from multi_agentic_security.evidence_store.share import (
    EXCLUDED, PREFIX, SHAREABLE, ShareError, install_share, main, make_share,
)

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "agent2" / "evidence" / "v1"


def test_make_packs_only_shareable_tables(tmp_path: Path):
    out = tmp_path / "share.zip"
    result = make_share(FIX, out)
    assert result["tables"] == sorted(s.key for s in SHAREABLE)
    names = zipfile.ZipFile(out).namelist()
    assert not any("malregistry" in n for n in names)
    assert not any(n.endswith(("skips.csv", "notes.csv")) for n in names)
    assert f"{PREFIX}/NOTICE.txt" in names
    notice = zipfile.ZipFile(out).read(f"{PREFIX}/NOTICE.txt").decode()
    assert "PRIVATE" in notice and "CC-BY 4.0" in notice and "malregistry" not in notice.lower().split("not included")[0]


def test_install_gives_a_store_missing_only_the_excluded_table(tmp_path: Path):
    out = tmp_path / "share.zip"
    make_share(FIX, out)
    target = tmp_path / "friend" / "v1"
    install_share(out, target)
    store = EvidenceStore.load(target)
    assert store.complete is False
    assert [k.replace("\\", "/") for k in store.missing_tables] == sorted(EXCLUDED)
    full = EvidenceStore.load(FIX)
    assert store.run_record()["records_indexed"] > 0
    assert store.run_record()["records_indexed"] < full.run_record()["records_indexed"]


def test_make_refuses_a_table_that_does_not_match_its_manifest(tmp_path: Path):
    root = tmp_path / "v1"
    shutil.copytree(FIX, root)
    rec = root / "typosquat" / "yctt_pairs" / "records.jsonl"
    rec.write_bytes(rec.read_bytes() + b"\n")
    with pytest.raises(ShareError, match="does not match"):
        make_share(root, tmp_path / "share.zip")
    assert not (tmp_path / "share.zip").exists()


def test_make_and_install_never_overwrite(tmp_path: Path):
    out = tmp_path / "share.zip"
    make_share(FIX, out)
    with pytest.raises(ShareError, match="already exists"):
        make_share(FIX, out)
    target = tmp_path / "v1"
    (target / "typosquat" / "yctt_pairs").mkdir(parents=True)
    with pytest.raises(ShareError, match="already exists"):
        install_share(out, target)
    assert not (target / "vulnerable").exists()   # nothing was written


def test_install_refuses_unexpected_or_damaged_entries(tmp_path: Path):
    out = tmp_path / "share.zip"
    make_share(FIX, out)
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(out) as src, zipfile.ZipFile(evil, "w") as dst:
        for item in src.infolist():
            dst.writestr(item, src.read(item))
        dst.writestr("../outside.txt", "x")
    with pytest.raises(ShareError, match="unexpected"):
        install_share(evil, tmp_path / "a")

    damaged = tmp_path / "damaged.zip"
    with zipfile.ZipFile(out) as src, zipfile.ZipFile(damaged, "w") as dst:
        for item in src.infolist():
            data = src.read(item)
            if item.filename.endswith("benign_reference/pypi_popular/records.jsonl"):
                data += b"\n"
            dst.writestr(item, data)
    with pytest.raises(ShareError, match="checksum"):
        install_share(damaged, tmp_path / "b")
    assert not (tmp_path / "a").exists() and not (tmp_path / "b").exists()


def test_cli_reports_refusals(tmp_path: Path, capsys):
    out = tmp_path / "share.zip"
    assert main(["make", "--root", str(FIX), "--out", str(out)]) == 0
    assert json.loads(capsys.readouterr().out)["tables"]
    assert main(["make", "--root", str(FIX), "--out", str(out)]) == 1
    assert "refused" in capsys.readouterr().err
