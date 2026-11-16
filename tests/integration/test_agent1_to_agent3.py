"""Integration: Agent 1 -> Agent 2 (snapshot) -> Agent 3 on the hand-written Agent 2 fixtures.

Checks that every dependency gets exactly one assessment with the frozen v1 score next to
the v2 findings, that the trace validates as a ``PipelineReport``, and the key family
decisions end to end. No network, no dataset files.
"""

import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
from multi_agentic_security.agents.agent2_registry import SnapshotRegistryClient, verify
from multi_agentic_security.agents.agent3_risk import assess
from multi_agentic_security.contracts.pipeline import PipelineReport, PipelineSummary
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


def run(cutoff=None):
    files = [UploadedFile(p.name, p.read_bytes()) for p in sorted((FIX / "upload").iterdir())]
    ex = extract_files("proj-int", files, clock=lambda: T0)
    store = EvidenceStore.load(FIX / "evidence" / "v1")
    rg = verify(ex, mode="snapshot", client=SnapshotRegistryClient(FIX / "registry_snapshot"), evidence_store=store,
                evidence_cutoff=cutoff, clock=lambda: T0)
    rr = assess(ex, rg, evidence_store=store, clock=lambda: T0)
    return ex, rg, rr


@pytest.fixture(scope="module")
def result():
    return run()


def by(ex, rr, eco, name, constraint="__any__"):
    out = []
    for d, a in zip(ex.dependencies, rr.assessments):
        if d.package and (d.package.ecosystem, d.package.name_normalized) == (eco, name) and (
                constraint == "__any__" or d.version_constraint_raw == constraint):
            out.append(a)
    assert out, (eco, name, constraint)
    return out[0]


def kinds(a):
    return [f.finding for f in a.findings]


def test_trace_and_report(result):
    ex, rg, rr = result
    assert [a.dependency_id for a in rr.assessments] == [d.dependency_id for d in ex.dependencies]
    assert rr.failures == [] and all(a.baseline_v1 is not None and a.findings for a in rr.assessments)
    PipelineReport(project_id="proj-int", created_at=T0, extraction=ex, registry=rg, risk=rr,
                   summary=PipelineSummary(total_dependencies=len(ex.dependencies), by_ecosystem={},
                                           registry_status_counts={}, finding_counts={}, baseline_level_counts={},
                                           action_counts={}, verdict_counts={}, failures=0))


def test_family_decisions_end_to_end(result):
    ex, _, rr = result
    evil = by(ex, rr, "npm", "evil-pkg")
    assert {"malicious_reported", "registry_security_hold"} <= set(kinds(evil)) and evil.baseline_v1.risk_level == "low"
    comp = by(ex, rr, "pypi", "compromised-lib")
    assert {"compromised_version", "vulnerable"} <= set(kinds(comp))
    assert by(ex, rr, "pypi", "requests", "==2.31.0").findings[0].detail["applicability"] == "affected"
    assert by(ex, rr, "npm", "lodash").findings[0].finding == "withdrawn_only"
    squat = by(ex, rr, "npm", "strign-width")
    assert "typosquat_listed" in kinds(squat) and squat.reference_package.name_normalized == "string-width"
    assert "typosquat_listed" not in kinds(by(ex, rr, "npm", "string-width"))
    assert "nonexistent" in kinds(by(ex, rr, "pypi", "reqeusts-hallucinated"))
    assert "unknown" in kinds(by(ex, rr, "pypi", "numpy"))


def test_held_out_run_withholds_post_cutoff_knowledge():
    ex, _, rr = run(cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc))
    comp = by(ex, rr, "pypi", "compromised-lib")       # its reports are from 2026-08 and 2026-09
    assert "compromised_version" not in kinds(comp) and "vulnerable" not in kinds(comp)
    hallu = by(ex, rr, "pypi", "reqeusts-hallucinated")
    assert "nonexistent" not in kinds(hallu) and "unknown" in kinds(hallu)   # snapshot is from after the cut-off
    evil = by(ex, rr, "npm", "evil-pkg")
    assert "registry_security_hold" not in kinds(evil) and "malicious_reported" in kinds(evil)  # OpenSSF 2025-12-20
