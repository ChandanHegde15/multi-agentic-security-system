"""Regression tests for the independent review of Agent 5 (D-060). Each test names its finding.

Hand-written recommendations, in-memory evidence stores and fake registry clients.
No network, no dataset files.
"""

import socket
from datetime import date, datetime, timezone

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
from multi_agentic_security.agents.agent2_registry import verify
from multi_agentic_security.agents.agent3_risk import assess
from multi_agentic_security.agents.agent5_verification import ALL_CHECKS, verify_recommendations
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


# --------------------------------------------------------------------------- 1 (high): removed release of an unversioned target

@pytest.mark.parametrize("eco,files,old", [("pypi", req("oldlib\n"), "oldlib"),
                                           ("npm", pkg_json("oldlib", "^1.0.0"), "oldlib")])
def test_1_unversioned_target_with_later_removed_malicious_release_needs_review(eco, files, old):
    s = store_of(rec(F.MALICIOUS, eco, "newlib", S.LISTED, version="2.0.1", pub=date(2025, 3, 1)))
    ans = {(eco, old): found(old, ["1.0.0"]), (eco, "newlib"): found("newlib", ["2.0.0"])}
    v, c = one(check(files, s, ans, lambda ids: [recd(ids[0], "replace", target="newlib", eco=eco)], cutoff=CUT))
    assert c["target_not_malicious"] == "not_run" and v.verdict == "abstain"


def test_1_without_cutoff_a_removed_release_cannot_be_installed():
    s = store_of(rec(F.MALICIOUS, "pypi", "newlib", S.LISTED, version="2.0.1", pub=date(2025, 3, 1)))
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]), ("pypi", "newlib"): found("newlib", ["2.0.0"])}
    v, c = one(check(req("oldlib\n"), s, ans, lambda ids: [recd(ids[0], "replace", target="newlib")]))
    assert c["target_not_malicious"] == "pass"


# --------------------------------------------------------------------------- 2 (high): keep on a package with no release before the cut-off

def test_2_keep_on_package_registered_after_cutoff_needs_review():
    ans = {("pypi", "slopsq"): found("slopsq", ["0.1"], times={"0.1": D(2025, 9, 1)})}
    v, c = one(check(req("slopsq\n"), store_of(), ans, lambda ids: [recd(ids[0], "keep")], cutoff=CUT))
    assert c["action_consistent"] == "not_run" and v.verdict == "abstain"


def test_2_keep_on_pin_uploaded_after_cutoff_needs_review():
    ans = {("pypi", "lib"): found("lib", ["1.0", "2.0"], times={"1.0": D(2024, 1, 1), "2.0": D(2025, 9, 1)})}
    v, c = one(check(req("lib==2.0\n"), store_of(), ans, lambda ids: [recd(ids[0], "keep")], cutoff=CUT))
    assert c["action_consistent"] == "not_run"


def test_2_keep_on_pin_missing_from_registry_needs_review():
    v, c = one(check(req("lib==9.9\n"), store_of(), {("pypi", "lib"): found("lib", ["1.0"])},
                     lambda ids: [recd(ids[0], "keep")]))
    assert c["action_consistent"] == "not_run"


# --------------------------------------------------------------------------- 3 (high): PyPI ranges include pre-releases of the bound

@pytest.mark.parametrize("version,rng,expected", [
    ("2.0rc1", ">=1.0,<2.0", True), ("2.0a1", ">=1.0,<2.0", True), ("2.0.dev1", ">=1.0,<2.0", True),
    ("2.0", ">=1.0,<2.0", False), ("0.17.3", ">=0,<=0.17.3", True), ("5.0", ">=0", True),
    ("1.0", ">=1.0,<1.5||>=2.0,<2.5", True), ("1.7", ">=1.0,<1.5||>=2.0,<2.5", False),
    ("1.0", "~=1.0", None), ("1.0", ">=1.*", None), ("bad", ">=1.0", None),
])
def test_3_evidence_ranges_are_ordered_intervals(version, rng, expected):
    assert in_range("pypi", version, rng) is expected


def test_3_upgrade_to_prerelease_of_fixed_version_is_rejected():
    s = store_of(rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng=">=1.0,<2.0"))
    ans = {("pypi", "lib"): found("lib", ["1.0", "2.0rc1", "2.0"])}
    v, c = one(check(req("lib==1.0\n"), s, ans, lambda ids: [recd(ids[0], "upgrade", target="lib", version="2.0rc1")]))
    assert c["target_version_not_vulnerable"] == "fail" and v.verdict == "reject"


def test_3_agent3_pins_prerelease_of_fixed_version_as_affected():
    s = store_of(rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng=">=1.0,<2.0"))
    ex = extract_files("p", [UploadedFile("requirements.txt", b"lib==2.0rc1\n")], clock=lambda: T0)
    rg = verify(ex, mode="snapshot", client=Client({("pypi", "lib"): found("lib", ["1.0", "2.0rc1"])}),
                evidence_store=s, clock=lambda: T0)
    a = assess(ex, rg, evidence_store=s, clock=lambda: T0).assessments[0]
    assert next(f for f in a.findings if f.finding == "vulnerable").detail["applicability"] == "affected"


# --------------------------------------------------------------------------- 4: fixed_in must be a fix

def _fixed_in(obj, *ids):
    s = store_of(rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng=">=1.0,<2.0", rid="a"),
                 rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng=">=2.0,<3.0", rid="b"))
    v, c = one(check(req("lib==1.0\n"), s, {("pypi", "lib"): found("lib", ["1.0", "2.5", "3.0"])},
                     lambda d: [recd(d[0], "remove", claims=[claim("fixed_in", "pypi", "lib", *ids, obj=obj)])]))
    return c["claims_supported"]


A_ID = rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng=">=1.0,<2.0", rid="a").evidence_id


def test_4_fixed_in_inside_another_advisory_fails():
    assert _fixed_in("2.5", A_ID) == "fail"


def test_4_fixed_in_below_the_range_fails():
    assert _fixed_in("0.1", A_ID) == "fail"


def test_4_fixed_in_past_every_advisory_passes():
    assert _fixed_in("3.0", A_ID) == "pass"


def test_4_above_needs_an_upper_bound():
    assert above("pypi", "9.0", ">=0") is False and above("pypi", "2.0", ">=1.0,<2.0") is True


# --------------------------------------------------------------------------- 5: version-less claims about the dependency

def test_5_vulnerable_claim_on_a_version_not_in_use_fails():
    s = store_of(rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng=">=1.0,<2.0", rid="a"))
    v, c = one(check(req("lib==3.0\n"), s, {("pypi", "lib"): found("lib", ["1.0", "3.0"])},
                     lambda d: [recd(d[0], "keep", claims=[claim("is_vulnerable", "pypi", "lib", A_ID)])]))
    assert c["claims_supported"] == "fail" and v.verdict == "reject"


def test_5_listed_malicious_claim_on_excluded_version_fails():
    s = store_of(rec(F.MALICIOUS, "npm", "chalk", S.LISTED, version="5.6.1", rid="c"))
    cid = rec(F.MALICIOUS, "npm", "chalk", S.LISTED, version="5.6.1", rid="c").evidence_id
    v, c = one(check(pkg_json("chalk", "^2.1.0"), s, {("npm", "chalk"): found("chalk", ["2.4.2", "5.6.1"])},
                     lambda d: [recd(d[0], "remove", claims=[claim("is_reported_malicious", "npm", "chalk", cid)])]))
    assert c["claims_supported"] == "fail"


# --------------------------------------------------------------------------- 6: npm "*" and a pre-release under a cut-off

def _star(cutoff, action="keep", target=None):
    s = store_of(rec(F.MALICIOUS, "npm", "bar", S.LISTED, version="3.0.0-rc.1"))
    ans = {("npm", "bar"): found("bar", ["2.0.0", "3.0.0-rc.1"], latest="3.0.0-rc.1"),
           ("npm", "oldx"): found("oldx", ["1.0.0"])}
    files = pkg_json("bar" if target is None else "oldx", "*")
    return one(check(files, s, ans, lambda d: [recd(d[0], action, target=target, eco="npm")], cutoff=cutoff))


def test_6_keep_star_with_listed_prerelease_under_cutoff_needs_review():
    v, c = _star(CUT)
    assert c["action_consistent"] == "not_run"


def test_6_replace_with_unversioned_target_and_listed_prerelease_under_cutoff_needs_review():
    v, c = _star(CUT, "replace", "bar")
    assert c["target_not_malicious"] == "not_run"


def test_6_agent3_star_with_listed_prerelease_under_cutoff_is_undetermined():
    s = store_of(rec(F.MALICIOUS, "npm", "bar", S.LISTED, version="3.0.0-rc.1"))
    ex, rg = stage(pkg_json("bar", "*"), s, {("npm", "bar"): found("bar", ["2.0.0", "3.0.0-rc.1"],
                                                                   latest="3.0.0-rc.1")}, cutoff=CUT)
    a = assess(ex, rg, evidence_store=s, clock=lambda: T0).assessments[0]
    assert next(f for f in a.findings if f.finding == "compromised_version").detail["applicability"] == "undetermined"


# --------------------------------------------------------------------------- 7: incomplete store and upgrade

def test_7_upgrade_on_incomplete_store_needs_review_even_with_target_checks_off():
    partial = store_of(missing=("typosquat/yctt_pairs",))
    enabled = [c for c in ALL_CHECKS if not c.startswith("target_")]
    v, c = one(check(req("lib==1.0\n"), partial, {("pypi", "lib"): found("lib", ["1.0", "2.0"])},
                     lambda d: [recd(d[0], "upgrade", target="lib", version="2.0")], enabled=enabled))
    assert c["action_consistent"] == "not_run" and v.verdict == "abstain"


# --------------------------------------------------------------------------- 8: unknown upload times

def test_8_unknown_upload_times_are_not_a_missing_release():
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]), ("pypi", "newlib"): found("newlib", ["1.0"],
                                                                                 times={"1.0": None})}
    v, c = one(check(req("oldlib\n"), store_of(), ans, lambda d: [recd(d[0], "replace", target="newlib")], cutoff=CUT))
    assert c["target_exists"] == "not_run"


# --------------------------------------------------------------------------- 9: is_nonexistent for a later registration

def test_9_nonexistent_claim_for_package_registered_after_cutoff_needs_review():
    ans = {("pypi", "slopsq"): found("slopsq", ["0.1"], times={"0.1": D(2025, 9, 1)})}
    v, c = one(check(req("slopsq\n"), store_of(), ans,
                     lambda d: [recd(d[0], "remove", claims=[claim("is_nonexistent", "pypi", "slopsq")])], cutoff=CUT))
    assert c["claims_supported"] == "not_run" and v.verdict == "abstain"


# --------------------------------------------------------------------------- 10: missing and malformed recommendation lists

def test_10_empty_list_reports_every_missing_recommendation():
    ex, rg = stage(req("a\nb\n"), store_of(), {})
    res = verify_recommendations(ex, rg, {"project_id": "p", "recommendations": []}, evidence_store=store_of(),
                                 target_client=Client({}))
    assert [f.code for f in res.failures].count("a5.input.missing_recommendation") == 2


def test_10_non_list_is_a_failure():
    ex, rg = stage(req("a\n"), store_of(), {})
    res = verify_recommendations(ex, rg, {"project_id": "p", "recommendations": "oops"}, evidence_store=store_of(),
                                 target_client=Client({}))
    assert [f.code for f in res.failures] == ["a5.input.invalid_recommendations"]


# --------------------------------------------------------------------------- 11: npm "x" is a range, not the latest tag

def test_11_x_range_installs_highest_final_release_in_agent5():
    s = store_of(rec(F.MALICIOUS, "npm", "bar", S.LISTED, version="2.0.0"))
    ans = {("npm", "bar"): found("bar", ["2.0.0", "3.0.0-rc.1"], latest="3.0.0-rc.1")}
    v, c = one(check(pkg_json("bar", "x"), s, ans, lambda d: [recd(d[0], "keep")]))
    assert c["action_consistent"] == "fail"


def test_11_x_range_installs_highest_final_release_in_agent3():
    s = store_of(rec(F.MALICIOUS, "npm", "bar", S.LISTED, version="2.0.0"))
    ex, rg = stage(pkg_json("bar", "x"), s, {("npm", "bar"): found("bar", ["2.0.0", "3.0.0-rc.1"],
                                                                   latest="3.0.0-rc.1")})
    a = assess(ex, rg, evidence_store=s, clock=lambda: T0).assessments[0]
    assert next(f for f in a.findings if f.finding == "compromised_version").detail["applicability"] == \
        "likely_affected"


# --------------------------------------------------------------------------- 12, 13, 15 and untested codes

def test_12_client_supports_raising_is_a_failure_state():
    class Bad(Client):
        def supports(self, eco):
            raise RuntimeError("boom")
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"])}
    res = check(req("oldlib\n"), store_of(), ans, lambda d: [recd(d[0], "replace", target="newlib")],
                client=Bad({}))
    assert "a5.registry.client_error" in [f.code for f in res.failures] and res.verifications[0].verdict == "abstain"


def test_13_agent5_refilters_registry_versions_under_cutoff():
    s = store_of(rec(F.MALICIOUS, "pypi", "lib", S.LISTED, version="1.0"))
    ans = {("pypi", "lib"): found("lib", ["1.0", "2.0"], times={"1.0": D(2024, 1, 1), "2.0": D(2025, 9, 1)})}
    ex, rg = stage(req("lib\n"), s, ans)                              # Agent 2 without a cut-off: unfiltered
    rg = rg.model_copy(update={"evidence_cutoff": CUT})               # hand-built held-out input
    res = verify_recommendations(ex, rg, {"project_id": "p", "recommendations": [
        recd(ex.dependencies[0].dependency_id, "keep")]}, evidence_store=s, target_client=Client(ans))
    _, c = one(res)
    assert c["action_consistent"] == "fail"                          # at the cut-off a new install got 1.0


def test_15_replace_with_invalid_target_version_is_not_allowed():
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]), ("pypi", "newlib"): found("newlib", ["1.0"])}
    v, c = one(check(req("oldlib\n"), store_of(), ans,
                     lambda d: [recd(d[0], "replace", target="newlib", version=">=1.0")]))
    assert c["action_allowed"] == "fail"


def test_untested_codes_no_client_and_missing_registry_result():
    ex, rg = stage(req("a\n"), store_of(), {})
    rg = rg.model_copy(update={"results": []})
    res = verify_recommendations(ex, rg, {"project_id": "p", "recommendations": [
        recd(ex.dependencies[0].dependency_id, "keep")]}, evidence_store=store_of(), target_client=None)
    codes = {f.code for f in res.failures}
    assert {"a5.registry.no_client", "a5.input.missing_registry_result"} <= codes
    assert res.verifications[0].verdict == "abstain"


@pytest.mark.parametrize("store_kind", ["missing", "incomplete"])
@pytest.mark.parametrize("action,target,version", [("keep", None, None), ("upgrade", "lib", "2.0"),
                                                   ("downgrade", "lib", "0.5"), ("replace", "newlib", None)])
def test_store_missing_or_incomplete_never_gives_accept(store_kind, action, target, version):
    store = None if store_kind == "missing" else store_of(missing=("typosquat/yctt_pairs",))
    ans = {("pypi", "lib"): found("lib", ["0.5", "1.0", "2.0"]), ("pypi", "newlib"): found("newlib", ["1.0"])}
    ex, rg = stage(req("lib==1.0\n"), store_of(), ans)
    res = verify_recommendations(ex, rg, {"project_id": "p", "recommendations": [
        recd(ex.dependencies[0].dependency_id, action, target=target, version=version)]},
        evidence_store=store, target_client=Client(ans))
    assert res.verifications[0].verdict != "accept"
