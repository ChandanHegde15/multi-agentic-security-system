"""Integration: Agent 1 -> 2 (snapshot) -> 3 -> 4 (R0) -> 5 on tests/fixtures/agent2 (D-062).

Pins R0's action and Agent 5's verdict for every dependency, with and without a cut-off.
The only verdict that is not 'accept' is compromised-lib under the cut-off: its pin 1.2.0
was uploaded after the cut-off, so 'keep' cannot be checked and needs review. That is a
correct verifier decision, not an R0 defect (D-062). No network, no dataset files.
"""

import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
from multi_agentic_security.agents.agent2_registry import SnapshotRegistryClient, verify
from multi_agentic_security.agents.agent3_risk import assess
from multi_agentic_security.agents.agent4_recommendation import recommend
from multi_agentic_security.agents.agent5_verification import verify_recommendations
from multi_agentic_security.contracts.pipeline import PipelineReport, PipelineSummary
from multi_agentic_security.evidence_store import EvidenceStore

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "agent2"
T0 = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
CUT = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def run(cutoff=None):
    files = [UploadedFile(p.name, p.read_bytes()) for p in sorted((FIX / "upload").iterdir())]
    ex = extract_files("proj-int", files, clock=lambda: T0)
    store = EvidenceStore.load(FIX / "evidence" / "v1")
    client = SnapshotRegistryClient(FIX / "registry_snapshot")
    rg = verify(ex, mode="snapshot", client=client, evidence_store=store, evidence_cutoff=cutoff, clock=lambda: T0)
    rr = assess(ex, rg, evidence_store=store, clock=lambda: T0)
    rs = recommend(ex, rg, rr, evidence_store=store, variant="R0", clock=lambda: T0)
    vs = verify_recommendations(ex, rg, rs, evidence_store=store, target_client=client, clock=lambda: T0)
    return ex, rg, rr, rs, vs


def table(ex, rs, vs):
    out = {}
    for d, r, v in zip(ex.dependencies, rs.recommendations, vs.verifications):
        assert d.dependency_id == r.dependency_id == v.dependency_id
        key = (d.package.name_normalized if d.package else "<unresolved>", d.version_constraint_raw)
        tgt = (r.target.package.name_normalized, r.target.version) if r.target else None
        out[key] = (r.action, tgt, v.verdict)
    return out


COMMON = {
    ("lodash", "^4.17.21"): ("keep", None, "accept"),
    ("@types/node", "22.0.0"): ("keep", None, "accept"),
    ("string-width", "^7.0.0"): ("keep", None, "accept"),
    ("local-thing", "file:../local-thing"): ("abstain", None, "accept"),
    ("requests", None): ("keep", None, "accept"),
    ("pyyaml", ">=6"): ("keep", None, "accept"),
    ("pyyaml", None): ("keep", None, "accept"),
    ("numpy", None): ("abstain", None, "accept"),
    ("brokenpkg", None): ("abstain", None, "accept"),
    ("gitpkg", None): ("abstain", None, "accept"),
    ("<unresolved>", None): ("abstain", None, "accept"),
}


def test_r0_through_agent5_without_cutoff():
    ex, rg, rr, rs, vs = run()
    assert table(ex, rs, vs) == {
        **COMMON,
        ("evil-pkg", "1.0.0"): ("remove", None, "accept"),
        ("gone-pkg", "1.0.0"): ("remove", None, "accept"),
        ("strign-width", "1.0.0"): ("replace", ("string-width", None), "accept"),
        # 2.32.0 (the stated fix) is yanked on PyPI: the next final release is recommended.
        ("requests", "==2.31.0"): ("upgrade", ("requests", "2.32.3"), "accept"),
        # The stated fix 1.2.1 was never released and no record names another safe version.
        ("compromised-lib", "==1.2.0"): ("abstain", None, "accept"),
        ("reqeusts-hallucinated", None): ("remove", None, "accept"),
        ("undated-bad", "==0.1"): ("remove", None, "accept"),
    }
    assert rs.failures == []
    PipelineReport(project_id="proj-int", created_at=T0, extraction=ex, registry=rg, risk=rr, recommendations=rs,
                   verification=vs,
                   summary=PipelineSummary(total_dependencies=len(ex.dependencies), by_ecosystem={},
                                           registry_status_counts={}, finding_counts={}, baseline_level_counts={},
                                           action_counts={}, verdict_counts={}, failures=0))


def test_r0_through_agent5_with_cutoff():
    ex, _, _, rs, vs = run(CUT)
    assert table(ex, rs, vs) == {
        **COMMON,
        ("evil-pkg", "1.0.0"): ("remove", None, "accept"),
        # Registry state recorded after the cut-off says nothing about the cut-off: unknown -> abstain.
        ("gone-pkg", "1.0.0"): ("abstain", None, "accept"),
        ("strign-width", "1.0.0"): ("abstain", None, "accept"),
        ("reqeusts-hallucinated", None): ("abstain", None, "accept"),
        ("undated-bad", "==0.1"): ("abstain", None, "accept"),
        # Under a cut-off today's yanked list is ignored (D-057), so the stated fix is used.
        ("requests", "==2.31.0"): ("upgrade", ("requests", "2.32.0"), "accept"),
        # The 2026 reports are after the cut-off; the pin 1.2.0 was uploaded after it too, so
        # Agent 5 cannot check 'keep' (needs review): a correct verifier decision.
        ("compromised-lib", "==1.2.0"): ("keep", None, "abstain"),
    }
    v = next(v for d, v in zip(ex.dependencies, vs.verifications)
             if d.package and d.package.name_normalized == "compromised-lib")
    assert [c.check for c in v.checks if c.result == "not_run"] == ["action_consistent"]
