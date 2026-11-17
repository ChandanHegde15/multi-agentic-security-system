"""Regression tests for the independent review of Agent 4 (D-063): one or more per confirmed
finding, plus the tests the review listed as missing. No network, no dataset files.
"""

import json
from datetime import date

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
from multi_agentic_security.agents.agent2_registry import LookupOutcome, verify
from multi_agentic_security.agents.agent3_risk import assess
from multi_agentic_security.agents.agent4_recommendation import (
    LLMError, LLMOptions, LLMResponse, MemoryResponseStore, RecordedLLMClient, recommend,
)
from multi_agentic_security.agents.agent4_recommendation.packet import build_packets
from multi_agentic_security.agents.agent4_recommendation.prompt import build_request, prompt_input
from multi_agentic_security.agents.agent5_verification import verify_recommendations
from multi_agentic_security.contracts.evidence import LabelFamily as F, VersionScope as S

from test_agent3_review import T0, Client, found, rec, store_of
from test_agent4_rules import CUT, no_network, only, pkg_json, req, rule, run  # noqa: F401 (fixture)


# --------------------------------------------------------------------------- H1

def test_h1_no_usable_store_makes_no_absence_claim():
    adv = rec(F.VULNERABLE, "pypi", "libx", S.RANGE, rng="<1.0")
    _, rr, rs, vs = run(req("libx==2.0\n"), [adv], {("pypi", "libx"): found("libx", ["0.9", "2.0"])}, a4_store=None)
    r, v = only(rs, vs)
    assert [f.finding for f in rr.assessments[0].findings] == ["no_evidence"]
    assert r.action == "keep" and r.claims == [] and rule(r) == "a4.r0.no_evidence.keep_unverified"
    assert v.verdict == "accept"


# --------------------------------------------------------------------------- M1

def test_m1_unknown_registry_list_gives_no_upgrade_target():
    adv = rec(F.VULNERABLE, "pypi", "libz", S.RANGE, rng=">=1.0,<1.5")
    err = LookupOutcome(status="lookup_error", rule_id="a2.status.lookup_error", explanation="x", retrieved_at=T0,
                        source_url="u", error="timeout")
    _, _, rs, vs = run(req("libz==1.2\n"), [adv], {("pypi", "libz"): err})
    r, v = only(rs, vs)
    assert r.action == "abstain" and rule(r) == "a4.r0.version.no_target"
    assert "not available" in r.reasons[1].inputs["why"]


# --------------------------------------------------------------------------- M2

@pytest.mark.parametrize("flag", [
    lambda: rec(F.TYPOSQUAT, "pypi", "requestz", target="requests"),
    lambda: rec(F.MALICIOUS, "pypi", "requestz"),
])
def test_m2_flagged_imitated_package_is_not_a_replacement(flag):
    sq = rec(F.TYPOSQUAT, "pypi", "reqeusts", target="requestz")
    bad = flag()
    ans = {("pypi", "reqeusts"): found("reqeusts", ["1.0"]), ("pypi", "requestz"): found("requestz", ["1.0"])}
    _, _, rs, vs = run(req("reqeusts==1.0\n"), [sq, bad], ans)
    r, v = only(rs, vs)
    assert r.action == "remove" and rule(r) == "a4.r0.typosquat.target_flagged_remove"
    assert bad.evidence_id in r.reasons[0].evidence_ids and bad.evidence_id in r.reasons[1].evidence_ids
    assert v.verdict == "accept"


def test_m2_target_records_after_cutoff_are_not_given():
    sq = rec(F.TYPOSQUAT, "pypi", "reqeusts", target="requests", pub=date(2024, 1, 1))
    late = rec(F.MALICIOUS, "pypi", "requests", pub=date(2026, 1, 1))
    ans = {("pypi", "reqeusts"): found("reqeusts", ["1.0"]), ("pypi", "requests"): found("requests", ["2.0"])}
    _, _, rs, _ = run(req("reqeusts==1.0\n"), [sq, late], ans, cutoff=CUT)
    r = rs.recommendations[0]
    assert late.evidence_id not in r.reasons[0].evidence_ids and r.action == "replace"


# --------------------------------------------------------------------------- M3

def test_m3_grounded_prompt_without_usable_store_has_no_evidence_detail():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0", rid="PYSEC-1")
    store = store_of(adv)
    ex = extract_files("p", [UploadedFile("requirements.txt", b"web==1.0\n")], clock=lambda: T0)
    rg = verify(ex, mode="snapshot", client=Client({("pypi", "web"): found("web", ["1.0", "2.0"])}),
                evidence_store=store, clock=lambda: T0)
    rr = assess(ex, rg, evidence_store=store, clock=lambda: T0)
    p = build_packets(ex, rg, rr, evidence_store=None, variant="LLM-G", failures=[])[0]
    data = prompt_input(p, LLMOptions())
    assert data["findings"] == ["vulnerable"] and data["evidence"] == []
    text = build_request(p, LLMOptions()).messages[0][1]
    assert "PYSEC-1" not in text and "fixed_in" not in text


# --------------------------------------------------------------------------- M4, L1, L5, L6

def _llm(responses, store=None, text="web==1.0\n", risk_edit=None):
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0")
    s = store_of(adv)
    ex = extract_files("p", [UploadedFile("requirements.txt", text.encode())], clock=lambda: T0)
    rg = verify(ex, mode="snapshot", client=Client({("pypi", "web"): found("web", ["1.0", "2.0"])}), evidence_store=s,
                clock=lambda: T0)
    rr = assess(ex, rg, evidence_store=s, clock=lambda: T0)
    if risk_edit:
        rr = risk_edit(rr)
    client = RecordedLLMClient("prov", "m-1", responses)
    raw = store if store is not None else MemoryResponseStore()
    return recommend(ex, rg, rr, evidence_store=s, variant="LLM-G", llm=client, response_store=raw,
                     clock=lambda: T0), client, raw


def test_m4_llm_error_message_is_never_recorded_only_type_and_code():
    rs, _, raw = _llm([LLMError("upstream said key=sk-SECRET123", code="http_401")] * 3)
    r = rs.recommendations[0]
    dumped = rs.model_dump_json() + json.dumps(raw.records)
    assert "SECRET" not in dumped and "http_401" in r.failure.detail and r.generation_status == "llm_error"


def test_m4_invalid_codes_are_dropped():
    assert LLMError("x", code="sk-SECRET with spaces").code is None and LLMError("x", code="http_529").code == "http_529"


class _Broken:
    def put(self, record):
        raise OSError("disk full")


def test_l1_store_failure_is_llm_error_not_a_crash():
    ok = LLMResponse(text=json.dumps({"action": "keep"}))
    rs, _, _ = _llm([ok], store=_Broken())
    r = rs.recommendations[0]
    assert (r.action, r.generation_status) == ("abstain", "llm_error") and "could not be stored" in r.failure.detail


def test_l1_client_returning_wrong_type_is_llm_error():
    rs, _, _ = _llm(["not a response"] * 3)
    assert rs.recommendations[0].generation_status == "llm_error"


def test_l5_llm_is_not_called_without_assessment():
    rs, client, _ = _llm([LLMResponse(text='{"action": "keep"}')],
                         risk_edit=lambda rr: rr.model_copy(update={"assessments": []}))
    r = rs.recommendations[0]
    assert client.requests == [] and r.action == "abstain" and "a4.llm.no_assessment" in [x.rule_id for x in r.reasons]


def test_l6_versions_cap_is_bounded():
    with pytest.raises(ValueError):
        LLMOptions(max_versions_in_prompt=-1)


# --------------------------------------------------------------------------- L2, L3, L4

def test_l2_final_release_preferred_over_stated_npm_prerelease():
    adv = rec(F.VULNERABLE, "npm", "lib", S.RANGE, rng="<2.0.0-rc.1")
    ans = {("npm", "lib"): found("lib", ["1.0.0", "2.0.0-rc.1", "2.0.0"])}
    _, _, rs, vs = run(pkg_json("lib", "1.0.0"), [adv], ans)
    r, v = only(rs, vs)
    assert r.target.version == "2.0.0" and v.verdict == "accept"


def test_l2_stated_prerelease_used_when_no_final_release_clears():
    adv = rec(F.VULNERABLE, "npm", "lib", S.RANGE, rng="<2.0.0-rc.1")
    ans = {("npm", "lib"): found("lib", ["1.0.0", "2.0.0-rc.1"])}
    _, _, rs, _ = run(pkg_json("lib", "1.0.0"), [adv], ans)
    assert rs.recommendations[0].target.version == "2.0.0-rc.1"


def test_l3_local_versions_are_never_targets():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<1.5")
    _, _, rs, vs = run(req("web==1.0\n"), [adv], {("pypi", "web"): found("web", ["1.0", "1.5+cpu", "1.5.1"])})
    r, v = only(rs, vs)
    assert r.target.version == "1.5.1" and v.verdict == "accept"


def test_l4_stated_fix_listed_as_malicious_moves_to_next_clean_release():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<1.5")
    bad = rec(F.MALICIOUS, "pypi", "web", S.LISTED, version="1.5")
    _, _, rs, vs = run(req("web==1.0\n"), [adv, bad], {("pypi", "web"): found("web", ["1.0", "1.5", "1.5.1"])})
    r, v = only(rs, vs)
    assert r.target.version == "1.5.1" and r.reasons[1].inputs["next_release"] is True and v.verdict == "accept"


# --------------------------------------------------------------------------- L8: missing tests

def test_no_rule_abstains():
    def empty(rr):
        a = rr.assessments[0]
        return rr.model_copy(update={"assessments": [a.model_copy(update={"findings": []})]})
    _, _, rs, _ = run(req("plain==1.0\n"), answers={("pypi", "plain"): found("plain", ["1.0"])}, risk_edit=empty)
    assert rule(rs.recommendations[0]) == "a4.r0.no_rule" and rs.recommendations[0].action == "abstain"


def _stages():
    store = store_of()
    ex = extract_files("p", [UploadedFile("requirements.txt", b"plain==1.0\n")], clock=lambda: T0)
    rg = verify(ex, mode="snapshot", client=Client({("pypi", "plain"): found("plain", ["1.0"])}),
                evidence_store=store, clock=lambda: T0)
    rr = assess(ex, rg, evidence_store=store, clock=lambda: T0)
    return store, ex, rg, rr


def _codes(rs):
    return [f.code for f in rs.failures]


def test_input_failure_codes():
    store, ex, rg, rr = _stages()
    dup = recommend(ex, rg.model_copy(update={"results": rg.results * 2}),
                    rr.model_copy(update={"assessments": rr.assessments * 2}), evidence_store=store)
    assert "a4.input.duplicate_registry_result" in _codes(dup) and "a4.input.duplicate_assessment" in _codes(dup)
    stray = rr.assessments[0].model_copy(update={"dependency_id": "dep-0000000000000000"})
    unk = recommend(ex, rg, rr.model_copy(update={"assessments": rr.assessments + [stray]}), evidence_store=store)
    assert "a4.input.unknown_dependency" in _codes(unk) and len(unk.recommendations) == 1
    miss = recommend(ex, rg.model_copy(update={"results": []}), rr, evidence_store=store)
    assert "a4.input.missing_registry_result" in _codes(miss)


def test_evidence_failure_codes():
    store, ex, rg, rr = _stages()
    no_a2 = recommend(ex, rg.model_copy(update={"evidence_store": None}), rr, evidence_store=store)
    assert "a4.evidence.not_looked_up_by_agent2" in _codes(no_a2)
    bogus = rg.results[0].model_copy(update={"evidence_ids": ["ev-malicious-ffffffffffffffff"]})
    unk = recommend(ex, rg.model_copy(update={"results": [bogus]}), rr, evidence_store=store)
    assert "a4.evidence.unknown_id" in _codes(unk)
