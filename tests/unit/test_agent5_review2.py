"""Regression tests for the independent review of the D-060 corrections (D-061). Each test names its finding.

Hand-written recommendations, in-memory evidence stores and fake registry clients.
No network, no dataset files.
"""

import socket
from datetime import date, datetime, timezone

import pytest

from multi_agentic_security.agents.agent3_risk import assess
from multi_agentic_security.agents.agent5_verification import verify_recommendations
from multi_agentic_security.contracts.evidence import LabelFamily as F, VersionScope as S
from multi_agentic_security.versioning.evidence_ranges import above, in_range

from test_agent3_review import T0, found, rec, store_of  # same folder (pytest rootdir import mode)
from test_agent5_verify import CUT, Client, check, claim, one, pkg_json, recd, req, stage

D = lambda y, m, d: datetime(y, m, d, tzinfo=timezone.utc)  # noqa: E731


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


# --------------------------------------------------------------------------- 1: newer release without an upload time

def test_1_unversioned_npm_target_with_undated_reported_release_needs_review():
    s = store_of(rec(F.MALICIOUS, "npm", "newlib", S.LISTED, version="2.0.0", pub=date(2025, 3, 1)))
    ans = {("npm", "oldlib"): found("oldlib", ["1.0.0"]),
           ("npm", "newlib"): found("newlib", ["1.0.0", "2.0.0"], times={"1.0.0": D(2024, 1, 1), "2.0.0": None})}
    v, c = one(check(pkg_json("oldlib", "^1.0.0"), s, ans,
                     lambda d: [recd(d[0], "replace", target="newlib", eco="npm")], cutoff=CUT))
    assert c["target_not_malicious"] == "not_run" and v.verdict == "abstain"


# --------------------------------------------------------------------------- 2: an exposed pin missing from the registry is rejected

@pytest.mark.parametrize("files,eco,versions,reported", [
    (req("lib==1.1\n"), "pypi", ["1.0", "1.2"], "1.1"),
    (pkg_json("lib", "1.1.0"), "npm", ["1.0.0", "1.2.0"], "1.1.0"),
])
def test_2_keep_on_removed_malicious_pin_is_rejected(files, eco, versions, reported):
    s = store_of(rec(F.MALICIOUS, eco, "lib", S.LISTED, version=reported))
    v, c = one(check(files, s, {(eco, "lib"): found("lib", versions)}, lambda d: [recd(d[0], "keep")]))
    assert c["action_consistent"] == "fail" and v.verdict == "reject"


# --------------------------------------------------------------------------- 3: version-less claims on ranges

VULN = rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng=">=1.0,<2.0", rid="a")


@pytest.mark.parametrize("spec,expected", [("lib>=1.0\n", "pass"), ("lib>=1.0,<3\n", "pass"), ("lib>=2.0\n", "fail"),
                                           ("lib==1.5\n", "pass"), ("lib==2.0\n", "fail")])
def test_3_versionless_claim_applies_to_what_the_declaration_can_receive(spec, expected):
    ans = {("pypi", "lib"): found("lib", ["1.0", "1.5", "2.0"])}
    v, c = one(check(req(spec), store_of(VULN), ans,
                     lambda d: [recd(d[0], "investigate", claims=[claim("is_vulnerable", "pypi", "lib",
                                                                         VULN.evidence_id)])]))
    assert c["claims_supported"] == expected


# --------------------------------------------------------------------------- 4: npm "*" with a known final latest tag

def test_4_star_with_final_latest_excludes_other_prereleases_in_agent5():
    s = store_of(rec(F.MALICIOUS, "npm", "bar", S.LISTED, version="3.0.0-rc.1"))
    ans = {("npm", "bar"): found("bar", ["2.0.0", "3.0.0-rc.1"], latest="2.0.0")}
    v, c = one(check(pkg_json("bar", "*"), s, ans, lambda d: [recd(d[0], "keep")]))
    assert c["action_consistent"] == "pass" and v.verdict == "accept"


def test_4_star_with_final_latest_excludes_other_prereleases_in_agent3():
    s = store_of(rec(F.MALICIOUS, "npm", "bar", S.LISTED, version="3.0.0-rc.1"))
    ex, rg = stage(pkg_json("bar", "*"), s, {("npm", "bar"): found("bar", ["2.0.0", "3.0.0-rc.1"], latest="2.0.0")})
    a = assess(ex, rg, evidence_store=s, clock=lambda: T0).assessments[0]
    assert "compromised_version" not in [f.finding for f in a.findings]


# --------------------------------------------------------------------------- 5: not_yet does not trust Agent 2's list

def test_5_not_yet_uses_refiltered_versions():
    ans = {("pypi", "slopsq"): found("slopsq", ["0.1"], times={"0.1": D(2025, 9, 1)})}
    ex, rg = stage(req("slopsq\n"), store_of(), ans)            # Agent 2 without a cut-off: unfiltered
    rg = rg.model_copy(update={"evidence_cutoff": CUT})
    res = verify_recommendations(ex, rg, {"project_id": "p", "recommendations": [
        recd(ex.dependencies[0].dependency_id, "keep")]}, evidence_store=store_of(), target_client=Client(ans))
    _, c = one(res)
    assert c["action_consistent"] == "not_run"


# --------------------------------------------------------------------------- 6 and missing range tests

@pytest.mark.parametrize("eco,version,rng,expected", [
    ("pypi", "1.0", "=1.0", True), ("pypi", "1.0", "==1.0", True), ("pypi", "1.0.0", "==1.0", True),
    ("pypi", "1.0", ">=0,!=1.0", False), ("pypi", "1.1", " >= 1.0 , < 2.0 ", True),
    ("pypi", "1!0.5", ">=1.0", True), ("pypi", "1.0+cpu", "<=1.0", False),
    ("npm", "1.2.3", ">=1.0.0,<1.2.3", False), ("npm", "1.2.3-beta", ">=1.0.0,<1.2.3", True),
    ("npm", "v1.1.0", ">=1.0.0,<1.2.3", True), ("npm", "1.1.0+build", ">=1.0.0,<1.2.3", True),
    ("npm", "1.1.0", "<1.2", None), ("pypi", "1.0", "", None), ("pypi", "1.0", ">=1.0,", None),
])
def test_6_in_range_cases(eco, version, rng, expected):
    assert in_range(eco, version, rng) is expected


@pytest.mark.parametrize("version,rng,expected", [
    ("1.0.1", "<=1.0", True), ("1.0", "<=1.0", False), ("1.1", "==1.0", True), ("1.0", "==1.0", False),
    ("2.0", "<2.0", True), ("1.0+cpu", "<=1.0", False), ("3.0", ">=1.0,<2.0||>=2.5,<3.0", True),
    ("2.7", ">=1.0,<2.0||>=2.5,<3.0", False), ("9.0", ">=0,!=1.0", False),
])
def test_6_above_cases(version, rng, expected):
    assert above("pypi", version, rng) is expected
