"""Agent 2 ``verify``: modes, not_checked rules, shared lookups, cut-off handling,
evidence reasons per family, failure states and contract validity.

Inputs come from Agent 1 on inline hand-written files; registry answers from the
hand-written snapshot or fake clients; evidence from tests/fixtures/agent2/evidence/v1/.
No network, no dataset files.
"""

import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
from multi_agentic_security.agents.agent2_registry import LookupOutcome, SnapshotRegistryClient, verify
from multi_agentic_security.contracts.pipeline import RegistryResult
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


@pytest.fixture(scope="module")
def store():
    return EvidenceStore.load(FIX / "evidence" / "v1")


@pytest.fixture(scope="module")
def snap():
    return SnapshotRegistryClient(FIX / "registry_snapshot")


def extract(*files):
    return extract_files("proj-a2", [UploadedFile(p, d.encode()) for p, d in files], clock=lambda: T0)


def run(ex, store, *, mode="snapshot", client=None, cutoff=None):
    res = verify(ex, mode=mode, client=client, evidence_store=store, evidence_cutoff=cutoff, clock=lambda: T0)
    RegistryResult.model_validate(res.model_dump())  # round-trip validates against the contract
    return res


def by_name(ex, res, name):
    ids = [d.dependency_id for d in ex.dependencies if d.package and d.package.name_normalized == name]
    return [r for r in res.results if r.dependency_id in ids]


def rules(r):
    return [x.rule_id for x in r.reasons]


class CountingClient:
    mode = "snapshot"

    def __init__(self, outcome=None, exc=None):
        self.calls, self.outcome, self.exc = [], outcome, exc

    def supports(self, eco):
        return eco in ("pypi", "npm")

    def lookup(self, eco, name):
        self.calls.append((eco, name))
        if self.exc:
            raise self.exc
        return self.outcome


# --------------------------------------------------------------------------- traceability

def test_one_result_per_dependency_in_order(store, snap):
    ex = extract(("requirements.txt", "requests\nnumpy\nnot-recorded\n"), ("app.py", "import made_up_x\n"))
    res = run(ex, store, client=snap)
    assert [r.dependency_id for r in res.results] == [d.dependency_id for d in ex.dependencies]
    assert all(r.reasons and all(x.rule_id.startswith("a2.") for x in r.reasons) for r in res.results)
    assert res.stage_version == "agent2/0.1" and res.registry_mode == "snapshot" and res.project_id == "proj-a2"


def test_empty_extraction(store, snap):
    res = run(extract(("requirements.txt", "# nothing\n")), store, client=snap)
    assert res.results == []


# --------------------------------------------------------------------------- not_checked rules

def test_mode_off_checks_nothing_but_still_reports_evidence(store):
    ex = extract(("requirements.txt", "compromised-lib==1.2.0\n"))
    r = run(ex, store, mode="off").results[0]
    assert r.status == "not_checked" and r.retrieved_at is None and "a2.not_checked.mode_off" in rules(r)
    assert "a2.evidence.malicious" in rules(r) and r.evidence_ids


def test_unresolved_import_is_not_checked_and_never_looked_up(store):
    c = CountingClient()
    ex = extract(("app.py", "import totally_made_up_mod\n"))
    r = run(ex, store, client=c).results[0]
    assert r.status == "not_checked" and r.registry is None and c.calls == []
    assert rules(r) == ["a2.not_checked.unresolved", "a2.evidence.not_looked_up"]
    assert "not treated as a package name" in r.reasons[0].explanation


@pytest.mark.parametrize("decl,origin", [("git+https://github.com/example/proj.git#egg=gitpkg", "vcs"),
                                          ("https://example.org/pkgs/gitpkg-1.0.tar.gz#egg=gitpkg", "url")])
def test_non_registry_origin_is_not_checked(store, decl, origin):
    c = CountingClient()
    ex = extract(("requirements.txt", decl + "\n"))
    r = run(ex, store, client=c).results[0]
    assert r.status == "not_checked" and c.calls == [] and "a2.not_checked.non_registry_origin" in rules(r)
    assert r.reasons[0].inputs["origin"] == ex.dependencies[0].origin


def test_path_origin_evidence_carries_origin_note(store):
    ex = extract(("package.json", '{"dependencies": {"evil-pkg": "file:../evil-pkg"}}'))
    r = run(ex, store, client=CountingClient()).results[0]
    assert "a2.not_checked.non_registry_origin" in rules(r)
    mal = next(x for x in r.reasons if x.rule_id == "a2.evidence.malicious")
    assert "may not apply" in mal.explanation


def test_unsupported_ecosystem(store):
    class PypiOnly(CountingClient):
        def supports(self, eco):
            return eco == "pypi"
    c = PypiOnly()
    r = run(extract(("package.json", '{"dependencies": {"lodash": "^4"}}')), store, client=c).results[0]
    assert r.status == "not_checked" and "a2.not_checked.unsupported_ecosystem" in rules(r) and c.calls == []


def test_not_in_snapshot(store, snap):
    r = run(extract(("requirements.txt", "not-recorded\n")), store, client=snap).results[0]
    assert r.status == "not_checked" and "a2.not_checked.not_in_snapshot" in rules(r)


def test_missing_client_is_a_failure_state(store):
    res = run(extract(("requirements.txt", "requests\n")), store, mode="live", client=None)
    assert res.results[0].status == "not_checked" and "a2.not_checked.no_client" in rules(res.results[0])
    assert [f.code for f in res.failures] == ["a2.mode.client_missing"]


def test_client_mode_mismatch(store, snap):
    res = run(extract(("requirements.txt", "requests\n")), store, mode="live", client=snap)
    assert res.results[0].status == "not_checked" and [f.code for f in res.failures] == ["a2.mode.client_mismatch"]


def test_live_with_cutoff_is_refused(store):
    class Live(CountingClient):
        mode = "live"
    c = Live()
    res = run(extract(("requirements.txt", "requests\n")), store, mode="live", client=c,
              cutoff=datetime(2025, 1, 1, tzinfo=timezone.utc))
    assert c.calls == [] and res.results[0].status == "not_checked"
    assert "a2.not_checked.live_refused_held_out" in rules(res.results[0])
    assert [f.code for f in res.failures] == ["a2.mode.live_with_cutoff"]


def test_invalid_mode_and_naive_cutoff_raise(store):
    ex = extract(("requirements.txt", "requests\n"))
    with pytest.raises(ValueError):
        verify(ex, mode="online", client=None, evidence_store=store)
    with pytest.raises(ValueError):
        verify(ex, mode="off", client=None, evidence_store=store, evidence_cutoff=datetime(2025, 1, 1))


# --------------------------------------------------------------------------- lookups

def test_one_lookup_per_normalized_name(store):
    c = CountingClient(outcome=LookupOutcome(status="not_found", rule_id="a2.status.not_found", explanation="x",
                                             retrieved_at=T0, source_url="https://pypi.org/pypi/a/json"))
    ex = extract(("requirements.txt", "Foo_Bar==1\n"), ("requirements-dev.txt", "foo.bar>=1\nfoo-bar\n"))
    res = run(ex, store, client=c)
    assert c.calls == [("pypi", "foo-bar")] and len(res.results) == 3
    assert all(r.reasons[0].inputs["dependencies_sharing_lookup"] == 3 for r in res.results)


def test_broken_client_is_lookup_error(store):
    res = run(extract(("requirements.txt", "requests\n")), store, client=CountingClient(exc=RuntimeError("x")))
    r = res.results[0]
    assert r.status == "lookup_error" and "RuntimeError" in r.error and r.retrieved_at == T0


def test_found_carries_registry_facts(store, snap):
    ex = extract(("requirements.txt", "pyyaml\n"))
    r = run(ex, store, client=snap).results[0]
    assert r.status == "found" and r.canonical_name == "PyYAML" and r.versions == ["6.0.1", "6.0.2"]
    assert r.latest_version == "6.0.2" and r.version_upload_times["6.0.2"] is not None
    assert r.retrieved_at == datetime(2026, 11, 15, 10, tzinfo=timezone.utc)
    assert r.source_url == "https://pypi.org/pypi/pyyaml/json"


@pytest.mark.parametrize("name,status", [("reqeusts-hallucinated", "not_found"), ("numpy", "lookup_error"),
                                          ("timeoutpkg", "lookup_error"), ("brokenpkg", "invalid_response")])
def test_failure_statuses_from_snapshot(store, snap, name, status):
    r = run(extract(("requirements.txt", name + "\n")), store, client=snap).results[0]
    assert r.status == status and r.retrieved_at is not None and r.versions is None


def test_private_index_still_looked_up_with_reason(store, snap):
    ex = extract(("requirements.txt", "--extra-index-url https://pkgs.example/simple\nrequests\n"))
    r = run(ex, store, client=snap).results[0]
    assert r.status == "found" and "a2.registry.private_index" in rules(r)


def test_snapshot_load_failures_are_reported(tmp_path, store):
    (tmp_path / "bad.json").write_text("{", encoding="utf-8")
    res = run(extract(("requirements.txt", "requests\n")), store, client=SnapshotRegistryClient(tmp_path))
    assert [f.code for f in res.failures] == ["a2.snapshot.unusable_file"]


# --------------------------------------------------------------------------- cut-off

def test_cutoff_filters_versions_and_withholds_latest(store, snap):
    ex = extract(("requirements.txt", "compromised-lib==1.2.0\n"))
    r = run(ex, store, client=snap, cutoff=datetime(2026, 6, 1, tzinfo=timezone.utc)).results[0]
    assert r.status == "found" and r.versions == ["1.0.0", "1.1.0"] and r.latest_version is None
    assert set(r.version_upload_times) == {"1.0.0", "1.1.0"}
    assert {"a2.cutoff.versions_filtered", "a2.cutoff.snapshot_after_cutoff"} <= set(rules(r))
    # malicious report (2026-08-05), advisory (2026-09-01) and popular list (2026-11-01) are all later
    assert r.evidence_ids == [] and "a2.evidence.excluded_after_cutoff" in rules(r)
    assert "a2.evidence.no_match" in rules(r)


def test_cutoff_with_no_version_before_it(store, snap):
    r = run(extract(("requirements.txt", "pyyaml\n")), store, client=snap,
            cutoff=datetime(2020, 1, 1, tzinfo=timezone.utc)).results[0]
    assert r.status == "found" and r.versions == [] and "a2.cutoff.no_version_before_cutoff" in rules(r)


def test_undated_evidence_excluded_with_cutoff_and_flagged_without(store):
    ex = extract(("requirements.txt", "undated-bad==0.1\n"))
    live = run(ex, store, mode="off").results[0]
    assert len(live.evidence_ids) == 2 and "a2.evidence.undated_included" in rules(live)
    mal = next(x for x in live.reasons if x.rule_id == "a2.evidence.malicious")
    assert sorted(mal.inputs["undated"]) == sorted(live.evidence_ids)
    held = run(ex, store, mode="off", cutoff=datetime(2026, 11, 1, tzinfo=timezone.utc)).results[0]
    assert held.evidence_ids == [] and "a2.evidence.excluded_undated" in rules(held)


# --------------------------------------------------------------------------- evidence reasons

def test_families_reported_separately(store):
    ex = extract(("package.json", '{"dependencies": {"lodash": "^4", "evil-pkg": "1.0.0"}}'))
    res = run(ex, store, mode="off")
    lodash = by_name(ex, res, "lodash")[0]
    assert "a2.evidence.withdrawn" in rules(lodash) and "a2.evidence.malicious" not in rules(lodash)
    assert "never counts as malicious" in next(x for x in lodash.reasons if x.rule_id == "a2.evidence.withdrawn").explanation
    evil = by_name(ex, res, "evil-pkg")[0]
    mal = next(x for x in evil.reasons if x.rule_id == "a2.evidence.malicious")
    assert mal.inputs["records"] == 2 and mal.inputs["tables"] == ["malicious/datadog_manifests",
                                                                   "malicious_withdrawn/openssf_a2"]


def test_typosquat_target_is_context_not_a_finding(store):
    ex = extract(("requirements.txt", "requests\nreqeusts\n"))
    res = run(ex, store, mode="off")
    target = by_name(ex, res, "requests")[0]
    assert "a2.evidence.typosquat_target" in rules(target) and "a2.evidence.typosquat_name" not in rules(target)
    assert "not a finding against this one" in next(
        x for x in target.reasons if x.rule_id == "a2.evidence.typosquat_target").explanation
    squat = by_name(ex, res, "reqeusts")[0]
    assert "a2.evidence.typosquat_name" in rules(squat)


def test_benign_reference_is_context_only(store):
    r = run(extract(("requirements.txt", "numpy\n")), store, mode="off").results[0]
    br = next(x for x in r.reasons if x.rule_id == "a2.evidence.benign_reference")
    assert "never proof that the package is safe" in br.explanation


def test_no_match_is_not_a_safety_statement(store):
    r = run(extract(("requirements.txt", "unknown-thing\n")), store, mode="off").results[0]
    assert r.evidence_ids == [] and "not a statement that the package is safe" in r.reasons[-1].explanation


def test_evidence_ids_are_traceable_to_reasons_and_store(store):
    ex = extract(("requirements.txt", "compromised-lib==1.2.0\nrequests\n"))
    for r in run(ex, store, mode="off").results:
        cited = {e for x in r.reasons for e in x.evidence_ids}
        assert set(r.evidence_ids) <= cited and all(store.get(e) is not None for e in r.evidence_ids)


def test_missing_store_is_a_failure_state():
    res = run(extract(("requirements.txt", "requests\n")), None, mode="off")
    assert [f.code for f in res.failures] == ["a2.evidence.store_missing"]
    assert "a2.evidence.not_available" in rules(res.results[0])


def test_incomplete_store_is_reported_on_every_result(tmp_path):
    import shutil
    root = tmp_path / "v1"
    shutil.copytree(FIX / "evidence" / "v1", root)
    shutil.rmtree(root / "malicious" / "datadog_manifests")
    res = run(extract(("requirements.txt", "requests\nnumpy\n")), EvidenceStore.load(root), mode="off")
    assert "evidence_store.table_missing" in [f.code for f in res.failures]
    assert all("a2.evidence.store_incomplete" in rules(r) for r in res.results)


# --------------------------------------------------------------------------- pipeline/0.2 store record (D-054)

def test_result_records_the_evidence_tables_used(store):
    res = run(extract(("requirements.txt", "requests\n")), store, mode="off")
    assert res.contract_version == "pipeline/0.2"
    info = res.evidence_store
    assert info.complete and info.records_indexed == len(store)
    assert [t.table for t in info.tables][:2] == ["vulnerable/osv_pypi_a2", "malicious_withdrawn/openssf_a2"]
    assert all(t.loaded and len(t.records_sha256) == 64 for t in info.tables)


def test_no_store_means_no_store_record():
    assert run(extract(("requirements.txt", "requests\n")), None, mode="off").evidence_store is None


def test_incomplete_store_record_shows_unloaded_table(tmp_path):
    import shutil
    root = tmp_path / "v1"
    shutil.copytree(FIX / "evidence" / "v1", root)
    shutil.rmtree(root / "typosquat" / "yctt_pairs")
    info = run(extract(("requirements.txt", "requests\n")), EvidenceStore.load(root), mode="off").evidence_store
    assert not info.complete and [t.table for t in info.tables if not t.loaded] == ["typosquat/yctt_pairs"]
