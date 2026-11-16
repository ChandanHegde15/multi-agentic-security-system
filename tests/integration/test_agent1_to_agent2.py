"""Integration: Agent 1 ``extract_files`` on hand-written upload files -> Agent 2 ``verify``
in snapshot mode with hand-written registry recordings and evidence tables.

Checks statuses, evidence IDs and reasons end to end, that every Agent 1 identifier
reaches Agent 2 exactly once, and that the Agent 1 private-index wording still
triggers Agent 2's rule. No network, no dataset files.
"""

import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
from multi_agentic_security.agents.agent2_registry import SnapshotRegistryClient, verify
from multi_agentic_security.contracts.pipeline import PipelineReport, PipelineSummary, RegistryResult
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
def pipeline():
    files = [UploadedFile(p.name, p.read_bytes()) for p in sorted((FIX / "upload").iterdir())]
    ex = extract_files("proj-int", files, clock=lambda: T0)
    store = EvidenceStore.load(FIX / "evidence" / "v1")
    res = verify(ex, mode="snapshot", client=SnapshotRegistryClient(FIX / "registry_snapshot"),
                 evidence_store=store, clock=lambda: T0)
    return ex, res, store


def results_for(ex, res, eco, name):
    ids = {d.dependency_id for d in ex.dependencies if d.package and (d.package.ecosystem, d.package.name_normalized) == (eco, name)}
    return [r for r in res.results if r.dependency_id in ids]


def one(ex, res, eco, name):
    found = results_for(ex, res, eco, name)
    assert len(found) == 1, (name, len(found))
    return found[0]


def rules(r):
    return [x.rule_id for x in r.reasons]


def test_ids_traceable_none_invented_or_dropped(pipeline):
    ex, res, _ = pipeline
    assert [r.dependency_id for r in res.results] == [d.dependency_id for d in ex.dependencies]
    report = PipelineReport(project_id="proj-int", created_at=T0, extraction=ex, registry=res,
                            summary=PipelineSummary(total_dependencies=len(ex.dependencies), by_ecosystem={},
                                                    registry_status_counts={}, finding_counts={},
                                                    baseline_level_counts={}, action_counts={}, verdict_counts={},
                                                    failures=0))
    assert report.registry is res
    RegistryResult.model_validate_json(res.model_dump_json())


def test_statuses_end_to_end(pipeline):
    ex, res, _ = pipeline
    expected = {
        ("pypi", "compromised-lib"): "found",
        ("pypi", "reqeusts-hallucinated"): "not_found",
        ("pypi", "numpy"): "lookup_error",
        ("pypi", "brokenpkg"): "invalid_response",
        ("pypi", "undated-bad"): "not_checked",          # no recording in the snapshot
        ("pypi", "gitpkg"): "not_checked",               # vcs origin
        ("npm", "lodash"): "found",
        ("npm", "@types/node"): "found",
        ("npm", "evil-pkg"): "security_placeholder",
        ("npm", "gone-pkg"): "not_found",
        ("npm", "string-width"): "found",
        ("npm", "strign-width"): "not_found",
        ("npm", "local-thing"): "not_checked",           # path origin
    }
    for (eco, name), status in expected.items():
        assert one(ex, res, eco, name).status == status, (eco, name)
    # PyYAML: declared and imported as 'yaml' (import_map/1)
    assert [r.status for r in results_for(ex, res, "pypi", "pyyaml")] == ["found", "found"]
    # requests appears three times (two requirements files and the import); all share one lookup
    req = results_for(ex, res, "pypi", "requests")
    assert len(req) == 3 and {r.status for r in req} == {"found"}
    assert {r.reasons[0].inputs["dependencies_sharing_lookup"] for r in req} == {3}


def test_unresolved_import_reaches_agent2_as_not_checked(pipeline):
    ex, res, _ = pipeline
    unresolved = [d.dependency_id for d in ex.dependencies if d.package is None]
    assert len(unresolved) == 1
    r = next(r for r in res.results if r.dependency_id == unresolved[0])
    assert r.status == "not_checked" and r.evidence_ids == [] and rules(r)[0] == "a2.not_checked.unresolved"


def test_private_index_wording_contract_with_agent1(pipeline):
    ex, res, _ = pipeline
    private = [d for d in ex.dependencies if d.source_path == "requirements-private.txt"]
    assert len(private) == 1
    r = next(r for r in res.results if r.dependency_id == private[0].dependency_id)
    assert "a2.registry.private_index" in rules(r)
    others = [r for r in results_for(ex, res, "pypi", "requests") if r.dependency_id != private[0].dependency_id]
    assert all("a2.registry.private_index" not in rules(o) for o in others)


def test_evidence_end_to_end(pipeline):
    ex, res, store = pipeline
    comp = one(ex, res, "pypi", "compromised-lib")
    fams = {store.get(e).family.value for e in comp.evidence_ids}
    assert fams == {"malicious", "vulnerable", "benign_reference"}
    assert {"a2.evidence.malicious", "a2.evidence.vulnerable", "a2.evidence.benign_reference"} <= set(rules(comp))

    evil = one(ex, res, "npm", "evil-pkg")
    assert len(evil.evidence_ids) == 2 and "a2.evidence.undated_included" in rules(evil)

    sw = one(ex, res, "npm", "string-width")
    assert "a2.evidence.typosquat_target" in rules(sw)
    squat = one(ex, res, "npm", "strign-width")
    assert "a2.evidence.typosquat_name" in rules(squat)

    lodash = one(ex, res, "npm", "lodash")
    assert "a2.evidence.withdrawn" in rules(lodash) and "a2.evidence.malicious" not in rules(lodash)

    local = one(ex, res, "npm", "local-thing")
    assert local.evidence_ids == [] and "a2.evidence.no_match" in rules(local)


def test_no_run_failures_with_clean_inputs(pipeline):
    _, res, store = pipeline
    assert res.failures == [] and store.complete


def test_held_out_run_from_the_same_upload():
    files = [UploadedFile(p.name, p.read_bytes()) for p in sorted((FIX / "upload").iterdir())]
    ex = extract_files("proj-int", files, clock=lambda: T0)
    res = verify(ex, mode="snapshot", client=SnapshotRegistryClient(FIX / "registry_snapshot"),
                 evidence_store=EvidenceStore.load(FIX / "evidence" / "v1"),
                 evidence_cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc), clock=lambda: T0)
    evil = one(ex, res, "npm", "evil-pkg")
    # OpenSSF report (2025-12-20) is before the cut-off; the undated DataDog record is excluded
    assert len(evil.evidence_ids) == 1 and "a2.evidence.excluded_undated" in rules(evil)
    lodash = one(ex, res, "npm", "lodash")
    assert lodash.latest_version is None and lodash.versions == ["4.17.20", "4.17.21"]
