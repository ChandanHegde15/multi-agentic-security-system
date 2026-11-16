"""Regression tests for the confirmed findings of the Agent 2 review (pipeline review 1).

Each test names the finding it guards. Hand-written inputs only; sockets blocked.
"""

import json
import shutil
import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
from multi_agentic_security.agents.agent2_registry import (
    PRIVATE_INDEX_MARKERS, HttpRegistryClient, SnapshotRegistryClient, valid_registry_name, verify,
)
from multi_agentic_security.agents.agent2_registry.client import HttpResponse, TransportError, outcome_from_response
from multi_agentic_security.evidence_store import EvidenceStore

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "agent2"
T0 = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


class FakeTransport:
    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def get(self, url, *, timeout, max_bytes, deadline_s):
        self.calls.append((url, timeout, deadline_s))
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a


def pypi_body(name="requests", upload="2024-05-29T15:37:47Z"):
    return json.dumps({"info": {"name": name, "version": "1"},
                       "releases": {"1": [{"upload_time_iso_8601": upload}]}}).encode()


# --------------------------------------------------------------------------- finding 1

@pytest.mark.parametrize("body", [pypi_body(upload="0001-01-01T00:00:00+01:00"),
                                  b'{"info": {"name": "requests", "version": ' + b"9" * 5000 + b'}, "releases": {}}'],
                         ids=["date_overflow", "huge_integer"])
def test_f1_parser_edge_cases_are_invalid_response_with_url(body):
    o = HttpRegistryClient(transport=FakeTransport(HttpResponse(200, "https://pypi.org/x", {}, body)),
                           clock=lambda: T0).lookup("pypi", "requests")
    assert o.status in ("found", "invalid_response")
    assert o.source_url == "https://pypi.org/pypi/requests/json"
    if o.status == "found":  # an out-of-range upload time is unknown, never a crash
        assert o.upload_times == {"1": None}


def test_f1_huge_integer_is_invalid_response():
    body = b'{"info": {"name": "requests", "version": ' + b"9" * 5000 + b'}, "releases": {}}'
    assert outcome_from_response("pypi", "u", 200, body, T0).status == "invalid_response"


# --------------------------------------------------------------------------- finding 2

def test_f2_typosquat_target_records_are_not_in_evidence_ids():
    store = EvidenceStore.load(FIX / "evidence" / "v1")
    ex = extract_files("p", [UploadedFile("package.json", b'{"dependencies": {"string-width": "^7"}}')],
                       clock=lambda: T0)
    r = verify(ex, mode="off", client=None, evidence_store=store, clock=lambda: T0).results[0]
    target = next(x for x in r.reasons if x.rule_id == "a2.evidence.typosquat_target")
    assert target.evidence_ids and not set(target.evidence_ids) & set(r.evidence_ids)
    assert all(store.get(e).name_normalized == "string-width" for e in r.evidence_ids)


# --------------------------------------------------------------------------- finding 4

def test_f4_one_overall_deadline_across_retries():
    now = [0.0]
    sleeps = []

    def sleep(s):
        sleeps.append(s)
        now[0] += s

    class SlowTransport(FakeTransport):
        def get(self, url, *, timeout, max_bytes, deadline_s):
            now[0] += min(25.0, deadline_s)  # a real transport stops at the deadline it is given
            return super().get(url, timeout=timeout, max_bytes=max_bytes, deadline_s=deadline_s)

    t = SlowTransport(*[TransportError("timeout", "t")] * 6)
    o = HttpRegistryClient(transport=t, clock=lambda: T0, deadline_s=60, sleep=sleep, monotonic=lambda: now[0],
                           backoff_s=1.0, retries=5).lookup("pypi", "requests")
    assert o.status == "lookup_error" and "overall deadline" in o.error
    assert now[0] <= 60                       # attempts and waits together stay inside one deadline
    assert len(t.calls) == 3 and t.calls[-1][2] == pytest.approx(7.0)  # the last attempt gets only the time left


@pytest.mark.parametrize("kw", [{"timeout": 0}, {"deadline_s": 10_000}, {"backoff_s": -1}, {"max_bytes": 0}])
def test_f14_client_parameters_are_range_checked(kw):
    with pytest.raises(ValueError):
        HttpRegistryClient(transport=FakeTransport(), **kw)


# --------------------------------------------------------------------------- finding 5

def test_f5_npm_private_registry_wording_contract_with_agent1():
    ex = extract_files("p", [UploadedFile("setup.sh", b"npm install --registry https://npm.example.org left-pad\n")],
                       clock=lambda: T0)
    dep = next(d for d in ex.dependencies if d.package and d.package.name_normalized == "left-pad")
    assert any(PRIVATE_INDEX_MARKERS[1] in w for w in dep.warnings)

    class Client:
        mode = "snapshot"

        def supports(self, eco):
            return True

        def lookup(self, eco, name):
            return outcome_from_response("npm", "https://registry.npmjs.org/left-pad", 404, b"{}", T0)

    r = verify(ex, mode="snapshot", client=Client(), evidence_store=None, clock=lambda: T0).results[0]
    assert "a2.registry.private_index" in [x.rule_id for x in r.reasons]


# --------------------------------------------------------------------------- finding 6

def test_f6_snapshot_with_overflowing_time_is_a_load_failure(tmp_path):
    (tmp_path / "x.json").write_text(json.dumps({
        "format": "registry_snapshot/1", "ecosystem": "pypi", "name": "x",
        "retrieved_at": "0001-01-01T00:00:00+01:00", "http_status": 404}), encoding="utf-8")
    c = SnapshotRegistryClient(tmp_path)
    assert [f for f, _ in c.load_failures] == ["x.json"] and c.lookup("pypi", "x") is None


# --------------------------------------------------------------------------- finding 7

@pytest.mark.parametrize("eco,name", [("npm", "lodash\n"), ("pypi", "requests\n")])
def test_f7_trailing_newline_is_not_a_valid_name(eco, name):
    assert not valid_registry_name(eco, name)


# --------------------------------------------------------------------------- finding 8

def test_f8_response_for_another_package_is_invalid():
    o = outcome_from_response("pypi", "u", 200, pypi_body(name="other-package"), T0, requested="requests")
    assert o.status == "invalid_response" and "not the requested package" in o.error


def test_f8_canonical_spelling_differences_are_accepted():
    o = outcome_from_response("pypi", "u", 200, pypi_body(name="PyYAML"), T0, requested="pyyaml")
    assert o.status == "found" and o.canonical_name == "PyYAML"


def test_f8_snapshot_with_mismatched_body(tmp_path):
    (tmp_path / "x.json").write_text(json.dumps({
        "format": "registry_snapshot/1", "ecosystem": "pypi", "name": "requests",
        "retrieved_at": "2026-11-15T10:00:00+00:00", "http_status": 200,
        "body": json.loads(pypi_body(name="evil-other"))}), encoding="utf-8")
    assert SnapshotRegistryClient(tmp_path).lookup("pypi", "requests").status == "invalid_response"


# --------------------------------------------------------------------------- findings 9-11

def test_f9_f10_f11_reason_texts_excluded_ids_and_non_utc_cutoff():
    store = EvidenceStore.load(FIX / "evidence" / "v1")
    ex = extract_files("p", [UploadedFile("requirements.txt", b"requests\nundated-bad\n")], clock=lambda: T0)
    from datetime import timedelta
    cutoff = datetime(2024, 1, 1, 3, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))  # 2023-12-31 UTC
    res = verify(ex, mode="off", client=None, evidence_store=store, evidence_cutoff=cutoff, clock=lambda: T0)
    req = res.results[0]
    after = next(x for x in req.reasons if x.rule_id == "a2.evidence.excluded_after_cutoff")
    assert after.inputs["cutoff"] == "2023-12-31" and "UTC date" in after.explanation
    assert after.inputs["excluded_ids"] and not set(after.inputs["excluded_ids"]) & set(req.evidence_ids)
    undated = next(x for x in res.results[1].reasons if x.rule_id == "a2.evidence.excluded_undated")
    assert len(undated.inputs["excluded_ids"]) == 2
    no_cut = verify(ex, mode="off", client=None, evidence_store=store, clock=lambda: T0).results[1]
    flagged = next(x for x in no_cut.reasons if x.rule_id == "a2.evidence.undated_included")
    assert "DataDog" not in flagged.explanation


# --------------------------------------------------------------------------- findings 12-13

def copy(tmp_path):
    dst = tmp_path / "v1"
    shutil.copytree(FIX / "evidence" / "v1", dst)
    return dst


@pytest.mark.parametrize("change", [{"schema_version": "other/2"}, {"table": "malregistry_listing"}])
def test_f12_manifest_schema_and_table_name_are_checked(tmp_path, change):
    root = copy(tmp_path)
    mpath = root / "malicious" / "datadog_manifests" / "MANIFEST.json"
    m = json.loads(mpath.read_text(encoding="utf-8"))
    m.update(change)
    mpath.write_text(json.dumps(m), encoding="utf-8")
    s = EvidenceStore.load(root)
    assert s.missing_tables == ["malicious/datadog_manifests"]
    assert s.failures[0].code == "evidence_store.manifest_invalid"


def test_f12_unicode_line_separator_inside_a_record_does_not_split_it(tmp_path):
    import hashlib
    root = copy(tmp_path)
    folder = root / "typosquat" / "yctt_pairs"
    rec = json.loads((folder / "records.jsonl").read_text(encoding="utf-8"))
    rec["corroborating_sources"] = ["note with separator"]  # not an identifying field
    data = (json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    (folder / "records.jsonl").write_bytes(data)
    m = json.loads((folder / "MANIFEST.json").read_text(encoding="utf-8"))
    m["files"]["records.jsonl"] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    (folder / "MANIFEST.json").write_text(json.dumps(m), encoding="utf-8")
    s = EvidenceStore.load(root)
    assert s.complete, s.failures


def test_f13_deeply_nested_record_rejects_the_table(tmp_path):
    import hashlib
    root = copy(tmp_path)
    folder = root / "typosquat" / "yctt_pairs"
    data = ("[" * 100000 + "]" * 100000 + "\n").encode()
    (folder / "records.jsonl").write_bytes(data)
    m = json.loads((folder / "MANIFEST.json").read_text(encoding="utf-8"))
    m["files"]["records.jsonl"] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    (folder / "MANIFEST.json").write_text(json.dumps(m), encoding="utf-8")
    s = EvidenceStore.load(root)
    assert s.missing_tables == ["typosquat/yctt_pairs"] and s.failures[0].code == "evidence_store.invalid_record"
