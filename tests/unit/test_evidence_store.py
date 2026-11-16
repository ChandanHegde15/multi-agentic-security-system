"""Evidence-store index: allow-list, hash checks, family separation, typosquat roles, cut-off.

Uses only the hand-written tables in tests/fixtures/agent2/evidence/v1/ (same format
as the real tables). No dataset files.
"""

import json
import shutil
import socket
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.evidence_store import CURRENT_TABLES, EvidenceStore

EVID = Path(__file__).resolve().parents[1] / "fixtures" / "agent2" / "evidence" / "v1"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture(scope="module")
def store():
    return EvidenceStore.load(EVID)


def copy_store(tmp_path):
    dst = tmp_path / "v1"
    shutil.copytree(EVID, dst)
    return dst


def test_all_current_tables_load_and_verify(store):
    assert store.complete and store.failures == []
    assert [t.key for t in store.tables] == [s.key for s in CURRENT_TABLES]
    assert all(t.loaded and len(t.records_sha256) == 64 for t in store.tables)
    assert len(store) == 18


def test_superseded_tables_are_never_loaded(store):
    assert "vulnerable/osv_pypi" not in [t.key for t in store.tables]
    assert store.query("pypi", "superseded-only").matches == ()


def test_families_stay_separate(store):
    q = store.query("pypi", "compromised-lib")
    fams = sorted({m.record.family.value for m in q.matches})
    assert fams == ["benign_reference", "malicious", "vulnerable"]
    mal = q.by_family("malicious")
    assert len(mal) == 1 and mal[0].record.version == "1.2.0" and mal[0].table == "malicious_withdrawn/openssf_a2"


def test_withdrawn_is_its_own_family(store):
    q = store.query("npm", "lodash")
    assert [m.record.family.value for m in q.matches] == ["benign_reference", "withdrawn"]
    assert q.by_family("malicious") == []


def test_typosquat_matched_by_name_and_by_target(store):
    squat = store.query("pypi", "reqeusts")
    assert [m.role for m in squat.matches] == ["name"]
    target = store.query("pypi", "requests")
    roles = {(m.record.family.value, m.role) for m in target.matches}
    assert ("typosquat", "target") in roles and ("typosquat", "name") not in roles
    assert target.by_family("typosquat") == [] and len(target.by_family("typosquat", role="target")) == 1


def test_cutoff_excludes_later_and_undated(store):
    q = store.query("pypi", "requests", cutoff=date(2024, 1, 1))
    ids = {m.record.provenance.source_record_id for m in q.matches}
    assert ids == {"GHSA-test-0001"}
    assert len(q.excluded_after_cutoff) == 2      # GHSA-test-0002 (2024-05-20), popular list (2026-11-01)
    assert len(q.excluded_undated) == 1           # Ecosyste.ms typosquat pair (target role)


def test_cutoff_is_strictly_before(store):
    q = store.query("pypi", "requests", cutoff=date(2023, 5, 22))
    assert all(m.record.provenance.source_record_id != "GHSA-test-0001" for m in q.matches)


def test_no_cutoff_includes_undated_and_lists_them(store):
    q = store.query("pypi", "undated-bad")
    assert len(q.matches) == 2 and len(q.undated_included) == 2 and q.excluded_undated == ()
    held_out = store.query("pypi", "undated-bad", cutoff=date(2026, 11, 1))
    assert held_out.matches == () and len(held_out.excluded_undated) == 2


def test_datetime_cutoff_is_refused(store):
    with pytest.raises(TypeError):
        store.query("pypi", "requests", cutoff=datetime(2024, 1, 1, tzinfo=timezone.utc))


def test_get_by_evidence_id(store):
    m = store.query("npm", "evil-pkg").matches[0]
    assert store.get(m.evidence_id) is m.record and store.table_of(m.evidence_id) == m.table


def test_hash_mismatch_rejects_the_table(tmp_path):
    root = copy_store(tmp_path)
    p = root / "malicious" / "datadog_manifests" / "records.jsonl"
    p.write_bytes(p.read_bytes().replace(b"evil-pkg", b"evil-pkh"))
    s = EvidenceStore.load(root)
    assert not s.complete and s.missing_tables == ["malicious/datadog_manifests"]
    assert [f.code for f in s.failures] == ["evidence_store.hash_mismatch"]
    assert all(m.table != "malicious/datadog_manifests" for m in s.query("npm", "evil-pkg").matches)


def test_crlf_conversion_is_detected(tmp_path):
    root = copy_store(tmp_path)
    p = root / "typosquat" / "yctt_pairs" / "records.jsonl"
    p.write_bytes(p.read_bytes().replace(b"\n", b"\r\n"))
    assert [f.code for f in EvidenceStore.load(root).failures] == ["evidence_store.hash_mismatch"]


def test_missing_table_is_a_failure(tmp_path):
    root = copy_store(tmp_path)
    shutil.rmtree(root / "typosquat" / "yctt_pairs")
    s = EvidenceStore.load(root)
    assert s.missing_tables == ["typosquat/yctt_pairs"] and s.failures[0].code == "evidence_store.table_missing"


def rewrite_with_manifest(folder, data: bytes, count_delta=0):
    (folder / "records.jsonl").write_bytes(data)
    m = json.loads((folder / "MANIFEST.json").read_text(encoding="utf-8"))
    import hashlib
    m["files"]["records.jsonl"] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    m["counts"]["records"] += count_delta
    (folder / "MANIFEST.json").write_text(json.dumps(m), encoding="utf-8")


def test_tampered_record_with_matching_hash_is_still_rejected(tmp_path):
    root = copy_store(tmp_path)
    folder = root / "malicious_withdrawn" / "openssf_a2"
    data = (folder / "records.jsonl").read_bytes().replace(b'"version": "1.2.0"', b'"version": "9.9.9"')
    rewrite_with_manifest(folder, data)
    assert [f.code for f in EvidenceStore.load(root).failures] == ["evidence_store.invalid_record"]


def test_wrong_family_in_table_is_rejected(tmp_path):
    root = copy_store(tmp_path)
    src = (root / "malicious" / "datadog_manifests" / "records.jsonl").read_bytes()
    folder = root / "typosquat" / "yctt_pairs"
    rewrite_with_manifest(folder, (folder / "records.jsonl").read_bytes() + src, count_delta=2)
    assert [f.code for f in EvidenceStore.load(root).failures] == ["evidence_store.invalid_record"]


def test_count_mismatch_is_rejected(tmp_path):
    root = copy_store(tmp_path)
    folder = root / "typosquat" / "yctt_pairs"
    rewrite_with_manifest(folder, (folder / "records.jsonl").read_bytes(), count_delta=1)
    assert [f.code for f in EvidenceStore.load(root).failures] == ["evidence_store.count_mismatch"]


def test_run_record_lists_tables_versions_and_hashes(store):
    r = store.run_record()
    assert r["store_version"] == "evidence_store/1" and r["complete"] is True and r["records_indexed"] == 18
    t = r["tables"][0]
    assert t["table"] == "vulnerable/osv_pypi_a2" and t["adapter_version"] == "fixture/1" and t["records_sha256"]
    assert "root_name" in r and str(EVID) not in json.dumps(r)  # no local path in the run record


def test_store_writes_nothing(tmp_path):
    root = copy_store(tmp_path)
    before = sorted((p.relative_to(root), p.stat().st_mtime_ns) for p in root.rglob("*"))
    EvidenceStore.load(root).query("pypi", "requests")
    assert sorted((p.relative_to(root), p.stat().st_mtime_ns) for p in root.rglob("*")) == before
