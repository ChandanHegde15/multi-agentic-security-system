"""Integration: Agent 1 -> Agent 2 (snapshot) -> Agent 3 -> hand-written recommendations -> Agent 5.

Agent 4 does not exist yet, so the recommendations are written by hand in the contract's
shape. Agent 5 receives the same snapshot client for its target lookups and its own view of
the evidence store; it never reads Agent 3's output. The full trace must validate as a
``PipelineReport``. No network, no dataset files.
"""

import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
from multi_agentic_security.agents.agent2_registry import SnapshotRegistryClient, verify
from multi_agentic_security.agents.agent3_risk import assess
from multi_agentic_security.agents.agent5_verification import verify_recommendations
from multi_agentic_security.contracts.pipeline import (
    PackageRef, PipelineReport, PipelineSummary, Reason, Recommendation, RecommendationResult, Target,
)
from multi_agentic_security.evidence_store import EvidenceStore

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "agent2"
T0 = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
WHY = [Reason(rule_id="a4.hand_written", outcome="fixture", explanation="Hand-written recommendation for the test.")]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def dep(ex, eco, name, constraint="__any__"):
    for d in ex.dependencies:
        if d.package and (d.package.ecosystem, d.package.name_normalized) == (eco, name) and (
                constraint == "__any__" or d.version_constraint_raw == constraint):
            return d
    raise AssertionError((eco, name, constraint))


def rec(d, action, target=None, version=None):
    t = Target(package=PackageRef.of(d.ecosystem, target), version=version) if target else None
    return Recommendation(dependency_id=d.dependency_id, action=action, target=t, backend="rules", reasons=WHY)


def run(cutoff=None):
    files = [UploadedFile(p.name, p.read_bytes()) for p in sorted((FIX / "upload").iterdir())]
    ex = extract_files("proj-int", files, clock=lambda: T0)
    store = EvidenceStore.load(FIX / "evidence" / "v1")
    client = SnapshotRegistryClient(FIX / "registry_snapshot")
    rg = verify(ex, mode="snapshot", client=client, evidence_store=store, evidence_cutoff=cutoff, clock=lambda: T0)
    rr = assess(ex, rg, evidence_store=store, clock=lambda: T0)
    cases = {
        "squat_replace": rec(dep(ex, "npm", "strign-width"), "replace", "string-width"),
        "malicious_keep": rec(dep(ex, "npm", "evil-pkg"), "keep"),
        "malicious_remove": rec(dep(ex, "npm", "evil-pkg"), "remove"),
        "vulnerable_keep": rec(dep(ex, "pypi", "requests", "==2.31.0"), "keep"),
        "vulnerable_upgrade": rec(dep(ex, "pypi", "requests", "==2.31.0"), "upgrade", "requests", "2.32.0"),
        "hallucinated_remove": rec(dep(ex, "pypi", "reqeusts-hallucinated"), "remove"),
    }
    # One recommendation per dependency: the remove and the upgrade variants are verified in a second result.
    first = [cases[k] for k in ("squat_replace", "malicious_keep", "vulnerable_keep", "hallucinated_remove")]
    second = [cases[k] for k in ("malicious_remove", "vulnerable_upgrade")]
    out = []
    for recs in (first, second):
        rres = RecommendationResult(project_id="proj-int", stage_version="hand/0", started_at=T0, finished_at=T0,
                                    recommendations=recs)
        out.append((rres, verify_recommendations(ex, rg, rres, evidence_store=store, target_client=client,
                                                 clock=lambda: T0)))
    return ex, rg, rr, out


def verdicts(ex, results):
    names = {d.dependency_id: d.package.name_normalized for d in ex.dependencies if d.package}
    got = {}
    for rres, vres in results:
        for r, v in zip(rres.recommendations, vres.verifications):
            assert r.dependency_id == v.dependency_id
            got[(names[r.dependency_id], r.action)] = v.verdict
    return got


def test_end_to_end_verdicts_and_report():
    ex, rg, rr, results = run()
    assert verdicts(ex, results) == {
        ("strign-width", "replace"): "accept",
        ("evil-pkg", "keep"): "reject",
        ("requests", "keep"): "reject",
        ("reqeusts-hallucinated", "remove"): "accept",
        ("evil-pkg", "remove"): "accept",
        ("requests", "upgrade"): "accept",
    }
    rres, vres = results[0]
    PipelineReport(project_id="proj-int", created_at=T0, extraction=ex, registry=rg, risk=rr, recommendations=rres,
                   verification=vres,
                   summary=PipelineSummary(total_dependencies=len(ex.dependencies), by_ecosystem={},
                                           registry_status_counts={}, finding_counts={}, baseline_level_counts={},
                                           action_counts={}, verdict_counts={}, failures=0))
    assert all(v.reasons[-1].rule_id.startswith("a5.verdict.") for v in vres.verifications)


def test_held_out_run_does_not_use_post_cutoff_registry_state():
    ex, _, _, results = run(cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc))
    got = verdicts(ex, results)
    # The snapshot is from after the cut-off: the security hold on evil-pkg says nothing about
    # the cut-off, but the OpenSSF report (2025-12-20) still makes 'keep' a reject.
    assert got[("evil-pkg", "keep")] == "reject"
    # The requests advisories (2023, 2024) and the strign-width listing are dated before the cut-off.
    assert got[("requests", "keep")] == "reject"
    assert got[("strign-width", "replace")] == "accept" and got[("requests", "upgrade")] == "accept"
