"""Agent 4 R0 (deterministic rules) unit tests: one or more per rule and failure code (D-062).

Each test runs the real Agents 1 -> 2 (fake snapshot client) -> 3 on a hand-written input,
then R0, and checks the recommendation, its claims and reasons, and Agent 5's verdict on it.
No network, no dataset files.
"""

import ast
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
from multi_agentic_security.agents.agent2_registry import LookupOutcome, verify
from multi_agentic_security.agents.agent3_risk import assess
from multi_agentic_security.agents.agent4_recommendation import recommend
from multi_agentic_security.agents.agent5_verification import verify_recommendations
from multi_agentic_security.contracts.evidence import LabelFamily as F, VersionScope as S
from multi_agentic_security.contracts.pipeline import RecommendationResult
from multi_agentic_security.evidence_store import EvidenceStore, TableInfo

from test_agent3_review import T0, Client, found, nf, rec, store_of  # same folder (pytest rootdir import mode)

CUT = datetime(2025, 6, 1, tzinfo=timezone.utc)
AGENT4_DIR = Path(__file__).resolve().parents[2] / "src" / "multi_agentic_security" / "agents" / "agent4_recommendation"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    import socket

    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def req(text):
    return [("requirements.txt", text)]


def pkg_json(name, spec):
    import json
    return [("package.json", json.dumps({"name": "app", "dependencies": {name: spec}}))]


def run(files, records=(), answers=None, *, cutoff=None, a4_store="same", risk_edit=None):
    store = store_of(*records)
    answers = answers or {}
    ex = extract_files("p", [UploadedFile(p, d.encode()) for p, d in files], clock=lambda: T0)
    rg = verify(ex, mode="snapshot", client=Client(answers), evidence_store=store, evidence_cutoff=cutoff,
                clock=lambda: T0)
    rr = assess(ex, rg, evidence_store=store, clock=lambda: T0)
    if risk_edit is not None:
        rr = risk_edit(rr)
    s4 = store if a4_store == "same" else a4_store
    rs = recommend(ex, rg, rr, evidence_store=s4, clock=lambda: T0)
    RecommendationResult.model_validate_json(rs.model_dump_json())
    vs = verify_recommendations(ex, rg, rs, evidence_store=store, target_client=Client(answers), clock=lambda: T0)
    _invariants(ex, rs)
    return ex, rr, rs, vs


def _invariants(ex, rs):
    assert [r.dependency_id for r in rs.recommendations] == [d.dependency_id for d in ex.dependencies]
    for r in rs.recommendations:
        assert r.backend == "rules" and r.model is None and r.generation_status == "ok"
        assert r.reasons[0].rule_id == "a4.input.packet"
        assert all(x.rule_id.startswith("a4.") for x in r.reasons)
        given = set(r.reasons[0].evidence_ids)
        for c in r.claims:
            assert set(c.evidence_ids) <= given, "R0 cited an evidence ID it was not given"


def only(rs, vs):
    assert len(rs.recommendations) == 1, [r.dependency_id for r in rs.recommendations]
    return rs.recommendations[0], vs.verifications[0]


def claims(r):
    return [(c.type, c.object) for c in r.claims]


def rule(r):
    return r.reasons[1].rule_id


# --------------------------------------------------------------------------- rules

def test_nonexistent_is_removed_with_is_nonexistent_claim():
    _, _, rs, vs = run(req("ghostpkg\n"), answers={("pypi", "ghostpkg"): nf()})
    r, v = only(rs, vs)
    assert r.action == "remove" and claims(r) == [("is_nonexistent", None)] and r.claims[0].evidence_ids == []
    assert rule(r) == "a4.r0.nonexistent.remove" and v.verdict == "accept"


def test_typosquat_with_one_target_is_replaced_by_the_target():
    sq = rec(F.TYPOSQUAT, "pypi", "reqeusts", target="requests")
    ans = {("pypi", "reqeusts"): found("reqeusts", ["1.0"]), ("pypi", "requests"): found("requests", ["2.32.3"])}
    _, _, rs, vs = run(req("reqeusts==1.0\n"), [sq], ans)
    r, v = only(rs, vs)
    assert r.action == "replace" and r.target.package.name_normalized == "requests" and r.target.version is None
    assert claims(r) == [("is_typosquat_of", "requests")] and r.claims[0].evidence_ids == [sq.evidence_id]
    assert rule(r) == "a4.r0.typosquat.replace" and v.verdict == "accept"


def test_typosquat_with_several_targets_is_removed():
    a = rec(F.TYPOSQUAT, "pypi", "reqests", target="requests", rid="a")
    b = rec(F.TYPOSQUAT, "pypi", "reqests", target="rests", rid="b")
    _, _, rs, vs = run(req("reqests==1.0\n"), [a, b], {("pypi", "reqests"): found("reqests", ["1.0"])})
    r, v = only(rs, vs)
    assert r.action == "remove" and sorted(claims(r)) == [("is_typosquat_of", "requests"), ("is_typosquat_of", "rests")]
    assert rule(r) == "a4.r0.typosquat.several_targets_remove" and v.verdict == "accept"


def test_malicious_typosquat_is_replaced_and_both_claims_are_made():
    sq = rec(F.TYPOSQUAT, "pypi", "reqeusts", target="requests")
    mal = rec(F.MALICIOUS, "pypi", "reqeusts")
    ans = {("pypi", "reqeusts"): found("reqeusts", ["1.0"]), ("pypi", "requests"): found("requests", ["2.32.3"])}
    _, _, rs, vs = run(req("reqeusts==1.0\n"), [sq, mal], ans)
    r, v = only(rs, vs)
    assert r.action == "replace" and ("is_reported_malicious", None) in claims(r) and v.verdict == "accept"


def test_reported_malicious_package_is_removed():
    mal = rec(F.MALICIOUS, "pypi", "evilpkg")
    _, _, rs, vs = run(req("evilpkg==1.0\n"), [mal], {("pypi", "evilpkg"): found("evilpkg", ["1.0"])})
    r, v = only(rs, vs)
    assert r.action == "remove" and claims(r) == [("is_reported_malicious", None)]
    assert r.claims[0].evidence_ids == [mal.evidence_id] and rule(r) == "a4.r0.malicious.remove"
    assert v.verdict == "accept"


def test_security_hold_is_removed_without_claims():
    hold = LookupOutcome(status="security_placeholder", rule_id="a2.status.security_placeholder", explanation="x",
                         retrieved_at=T0, source_url="u", canonical_name="badnpm", versions=[],
                         metadata={"removed_versions": {"1.0.0": None}})
    _, rr, rs, vs = run(pkg_json("badnpm", "1.0.0"), answers={("npm", "badnpm"): hold})
    r, v = only(rs, vs)
    assert "registry_security_hold" in [f.finding for f in rr.assessments[0].findings]
    assert r.action == "remove" and r.claims == [] and rule(r) == "a4.r0.security_hold.remove"
    assert v.verdict == "accept"


def test_compromised_listed_version_without_a_named_safe_version_abstains_with_claim():
    bad = rec(F.MALICIOUS, "pypi", "libx", S.LISTED, version="1.2.0")
    _, _, rs, vs = run(req("libx==1.2.0\n"), [bad], {("pypi", "libx"): found("libx", ["1.1.0", "1.2.0", "1.3.0"])})
    r, v = only(rs, vs)
    assert r.action == "abstain" and claims(r) == [("is_compromised_version", "1.2.0")]
    assert rule(r) == "a4.r0.version.no_target" and r.reasons[1].inputs["candidates"] == []
    assert v.verdict == "accept"


def test_compromised_range_with_stated_upper_bound_upgrades_to_it():
    bad = rec(F.MALICIOUS, "pypi", "libx", S.RANGE, rng=">=1.0,<1.3")
    _, _, rs, vs = run(req("libx==1.2\n"), [bad], {("pypi", "libx"): found("libx", ["1.0", "1.2", "1.3"])})
    r, v = only(rs, vs)
    assert (r.action, r.target.version) == ("upgrade", "1.3")
    assert claims(r) == [("is_compromised_version", "1.2")] and v.verdict == "accept"


def test_vulnerable_upgrades_to_lowest_stated_fixed_version_with_fixed_in_claim():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0", rid="GHSA-1")
    ans = {("pypi", "web"): found("web", ["1.0", "2.0", "2.1"])}
    _, _, rs, vs = run(req("web==1.0\n"), [adv], ans)
    r, v = only(rs, vs)
    assert (r.action, r.target.version) == ("upgrade", "2.0") and rule(r) == "a4.r0.version.upgrade"
    assert claims(r) == [("is_vulnerable", "1.0"), ("fixed_in", "2.0")]
    assert r.reasons[1].inputs["next_release"] is False and v.verdict == "accept"


def test_vulnerable_skips_a_fix_inside_another_advisory():
    a = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<1.5", rid="A")
    b = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng=">=1.5,<1.7", rid="B")
    _, _, rs, vs = run(req("web==1.0\n"), [a, b], {("pypi", "web"): found("web", ["1.0", "1.5", "1.7"])})
    r, v = only(rs, vs)
    # D-063 (review L4): a stated fix that is itself covered leads to the next clean final release.
    assert r.target.version == "1.7" and r.reasons[1].inputs["stated_fix"] == "1.5"
    assert r.reasons[1].inputs["next_release"] is True
    assert v.verdict == "accept"


def test_vulnerable_yanked_fix_moves_to_next_final_release_without_cutoff():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0")
    ans = {("pypi", "web"): found("web", ["1.0", "2.0", "2.1rc1", "2.1"], yanked=["2.0"])}
    _, _, rs, vs = run(req("web==1.0\n"), [adv], ans)
    r, v = only(rs, vs)
    assert r.target.version == "2.1" and r.reasons[1].inputs["next_release"] is True
    assert r.reasons[1].inputs["stated_fix"] == "2.0" and v.verdict == "accept"


def test_vulnerable_yanked_list_is_ignored_under_cutoff():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0", pub=date(2024, 1, 1))
    ans = {("pypi", "web"): found("web", ["1.0", "2.0", "2.1"], yanked=["2.0"])}
    _, _, rs, vs = run(req("web==1.0\n"), [adv], ans, cutoff=CUT)
    r, v = only(rs, vs)
    assert r.target.version == "2.0" and v.verdict == "accept"


def test_vulnerable_without_released_fix_abstains():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<3.0")
    _, _, rs, vs = run(req("web==1.0\n"), [adv], {("pypi", "web"): found("web", ["1.0", "2.0"])})
    r, v = only(rs, vs)
    assert r.action == "abstain" and rule(r) == "a4.r0.version.no_target"
    assert claims(r) == [("is_vulnerable", "1.0")] and v.verdict == "accept"


def test_vulnerable_unpinned_likely_affected_upgrades_without_version_object():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0")
    _, rr, rs, vs = run(req("web>=1.0,<2\n"), [adv], {("pypi", "web"): found("web", ["1.0", "1.5", "2.0"])})
    r, v = only(rs, vs)
    assert rr.assessments[0].findings[0].detail["applicability"] == "likely_affected"
    assert (r.action, r.target.version) == ("upgrade", "2.0") and ("is_vulnerable", None) in claims(r)
    assert r.uncertainty and v.verdict == "accept"


def test_undetermined_applicability_gives_investigate_without_claims():
    bad = rec(F.MALICIOUS, "npm", "tagged", S.LISTED, version="1.0.0")
    ans = {("npm", "tagged"): found("tagged", ["0.9.0", "1.0.0"])}
    _, rr, rs, vs = run(pkg_json("tagged", "beta"), [bad], ans)
    r, v = only(rs, vs)
    assert rr.assessments[0].findings[0].detail["applicability"] == "undetermined"
    assert r.action == "investigate" and r.claims == [] and rule(r) == "a4.r0.version.undetermined_investigate"
    assert v.verdict == "accept"


def test_similar_name_gives_investigate():
    pop = rec(F.BENIGN_REFERENCE, "pypi", "requests")
    _, rr, rs, vs = run(req("requestz==1.0\n"), [pop], {("pypi", "requestz"): found("requestz", ["1.0"])})
    r, v = only(rs, vs)
    assert "name_similar_to_popular" in [f.finding for f in rr.assessments[0].findings]
    assert r.action == "investigate" and r.claims == [] and rule(r) == "a4.r0.similar_name.investigate"
    assert r.reasons[1].evidence_ids == [pop.evidence_id] and v.verdict == "accept"


def test_unknown_registry_state_abstains():
    err = LookupOutcome(status="lookup_error", rule_id="a2.status.lookup_error", explanation="x", retrieved_at=T0,
                        source_url="u", error="timeout")
    _, _, rs, vs = run(req("slowpkg==1.0\n"), answers={("pypi", "slowpkg"): err})
    r, v = only(rs, vs)
    assert r.action == "abstain" and rule(r) == "a4.r0.unknown.abstain" and v.verdict == "accept"


def test_withdrawn_only_is_kept_with_report_withdrawn_claim():
    w = rec(F.WITHDRAWN, "pypi", "okpkg")
    _, _, rs, vs = run(req("okpkg==1.0\n"), [w], {("pypi", "okpkg"): found("okpkg", ["1.0"])})
    r, v = only(rs, vs)
    assert r.action == "keep" and claims(r) == [("report_withdrawn", None)] and r.claims[0].evidence_ids == [w.evidence_id]
    assert v.verdict == "accept"


def test_no_evidence_is_kept_with_no_evidence_found_claim():
    _, _, rs, vs = run(req("plain==1.0\n"), answers={("pypi", "plain"): found("plain", ["1.0"])})
    r, v = only(rs, vs)
    assert r.action == "keep" and claims(r) == [("no_evidence_found", None)] and rule(r) == "a4.r0.no_evidence.keep"
    assert v.verdict == "accept"


def test_no_evidence_with_records_for_other_versions_keeps_without_claim():
    """Defect found in the integration run: the claim no_evidence_found is false when records name the
    package, even if none covers the installed version; Agent 5 rejected it."""
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<1.0")
    _, rr, rs, vs = run(req("web\n"), [adv], {("pypi", "web"): found("web", ["0.9", "1.0", "2.0"])})
    r, v = only(rs, vs)
    assert [f.finding for f in rr.assessments[0].findings] == ["no_evidence"]
    assert r.action == "keep" and r.claims == [] and rule(r) == "a4.r0.no_evidence.keep_other_versions"
    assert r.reasons[1].evidence_ids == [adv.evidence_id] and v.verdict == "accept"


def test_unresolved_import_abstains():
    _, _, rs, vs = run([("app.py", "import totally_unknown_mod\n")])
    r, v = only(rs, vs)
    assert r.action == "abstain" and rule(r) == "a4.r0.no_package" and v.verdict == "accept"


# --------------------------------------------------------------------------- failure states

def test_missing_assessment_abstains_and_is_a_failure():
    def drop(rr):
        return rr.model_copy(update={"assessments": []})
    _, _, rs, _ = run(req("plain==1.0\n"), answers={("pypi", "plain"): found("plain", ["1.0"])}, risk_edit=drop)
    r = rs.recommendations[0]
    assert r.action == "abstain" and rule(r) == "a4.r0.no_assessment"
    assert "a4.input.missing_assessment" in [f.code for f in rs.failures]


def test_store_mismatch_gives_no_evidence_and_evidence_findings_abstain():
    mal = rec(F.MALICIOUS, "pypi", "evilpkg")
    other = EvidenceStore(Path("mem"), [TableInfo(key="mem/table", loaded=True, records=1, records_sha256="b" * 64)],
                          [], [("mem/table", mal)])
    _, _, rs, vs = run(req("evilpkg==1.0\n"), [mal], {("pypi", "evilpkg"): found("evilpkg", ["1.0"])}, a4_store=other)
    r, _ = only(rs, vs)
    assert "a4.evidence.store_mismatch" in [f.code for f in rs.failures]
    assert r.action == "abstain" and rule(r) == "a4.r0.malicious_reported.evidence_not_given"
    assert r.reasons[0].evidence_ids == [] and r.reasons[0].inputs["evidence_usable"] is False


def test_missing_store_is_a_failure():
    _, _, rs, _ = run(req("plain==1.0\n"), answers={("pypi", "plain"): found("plain", ["1.0"])}, a4_store=None)
    assert "a4.evidence.store_missing" in [f.code for f in rs.failures]


def test_evidence_after_cutoff_is_never_given():
    late = rec(F.MALICIOUS, "pypi", "evilpkg", pub=date(2026, 1, 1))

    def cite_late(rr):
        a = rr.assessments[0]
        f = a.findings[0].model_copy(update={"evidence_ids": [late.evidence_id]})
        return rr.model_copy(update={"assessments": [a.model_copy(update={"findings": [f]})]})
    _, _, rs, _ = run(req("evilpkg==1.0\n"), [late], {("pypi", "evilpkg"): found("evilpkg", ["1.0"])}, cutoff=CUT,
                      risk_edit=cite_late)
    r = rs.recommendations[0]
    assert late.evidence_id not in r.reasons[0].evidence_ids
    assert "a4.evidence.after_cutoff" in [f.code for f in rs.failures]


def test_project_mismatch_is_a_failure():
    def other_project(rr):
        return rr.model_copy(update={"project_id": "other"})
    _, _, rs, _ = run(req("plain==1.0\n"), answers={("pypi", "plain"): found("plain", ["1.0"])}, risk_edit=other_project)
    assert "a4.input.project_mismatch" in [f.code for f in rs.failures]
    assert rs.recommendations[0].action == "abstain"


def test_unknown_variant_and_llm_without_client_are_configuration_errors():
    ex = extract_files("p", [UploadedFile("requirements.txt", b"plain==1.0\n")], clock=lambda: T0)
    rg = verify(ex, mode="off", client=None, evidence_store=None, clock=lambda: T0)
    rr = assess(ex, rg, evidence_store=None, clock=lambda: T0)
    with pytest.raises(ValueError):
        recommend(ex, rg, rr, evidence_store=None, variant="LLM-X")
    with pytest.raises(ValueError):
        recommend(ex, rg, rr, evidence_store=None, variant="LLM-G")


# --------------------------------------------------------------------------- boundaries

def _imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            yield ("." * node.level) + (node.module or "")


def test_agent4_imports_no_network_library_and_no_other_agent():
    banned = ("socket", "http", "urllib", "requests", "httpx", "aiohttp", "subprocess",
              "multi_agentic_security.agents.agent5", "multi_agentic_security.agents.agent3",
              "multi_agentic_security.agents.agent2", "multi_agentic_security.agents.agent1")
    files = sorted(AGENT4_DIR.glob("*.py"))
    assert files
    for f in files:
        for name in _imports(f):
            assert not any(name == b or name.startswith(b + ".") or name.startswith(b) and "agents" in b
                           for b in banned), (f.name, name)
