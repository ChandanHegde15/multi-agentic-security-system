"""Regression tests for the second Agent 3 review and RUN-003 (D-057). Each test names its finding.

In-memory evidence stores from hand-written records; registry answers from fakes.
No network, no dataset files. The npm reference cases are taken from the range
include/exclude fixtures documented for node-semver (default options; loose-mode
cases left out).
"""

import socket
from datetime import datetime, timezone

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
from multi_agentic_security.agents.agent2_registry import verify
from multi_agentic_security.agents.agent3_risk import assess
from multi_agentic_security.agents.agent3_risk.npm_semver import satisfies, satisfies_evidence_range
from multi_agentic_security.contracts.evidence import LabelFamily as F, VersionScope as S
from multi_agentic_security.contracts.pipeline import RiskResult

from test_agent3_review import T0, found, nf, rec, run, store_of  # same folder (pytest rootdir import mode)

CUT = datetime(2025, 6, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def kinds(a):
    return [f.finding for f in a.findings]


def rules(a):
    return {r.rule_id for r in a.reasons} | {r.rule_id for f in a.findings for r in f.reasons}


def finding(a, kind):
    return next(f for f in a.findings if f.finding == kind)


def run_off(files, store):
    ex = extract_files("p", [UploadedFile(p, d.encode()) for p, d in files], clock=lambda: T0)
    rg = verify(ex, mode="off", client=None, evidence_store=store, clock=lambda: T0)
    rr = assess(ex, rg, evidence_store=store, clock=lambda: T0)
    RiskResult.model_validate_json(rr.model_dump_json())
    return rr


# --------------------------------------------------------------------------- finding 2 (high) + RUN-003

def test_r2_2_constraint_excluding_deleted_release_gives_no_finding_pypi():
    s = store_of(rec(F.MALICIOUS, "pypi", "lib", S.LISTED, version="9.0"))
    _, rr = run([("requirements.txt", "lib<2\n")], s, s, {("pypi", "lib"): found("lib", ["1.0", "1.5"])})
    a = rr.assessments[0]
    assert "compromised_version" not in kinds(a) and "a3.malicious.version.other_versions_only" in rules(a)


def test_r2_2_constraint_excluding_deleted_release_gives_no_finding_npm():
    s = store_of(rec(F.MALICIOUS, "npm", "chalk", S.LISTED, version="5.6.1"))
    _, rr = run([("package.json", '{"dependencies": {"chalk": "^4.1.2"}}')], s, s,
                {("npm", "chalk"): found("chalk", ["4.1.2", "5.6.0"])})
    assert "compromised_version" not in kinds(rr.assessments[0])


def test_run003_constraint_excluding_report_without_registry_gives_no_finding():
    # RUN-003: chalk ^2.1.0 in the react repository (registry off) was flagged for the 5.6.1 report.
    store = store_of(rec(F.MALICIOUS, "npm", "chalk", S.LISTED, version="5.6.1"))
    old = run_off([("package.json", '{"dependencies": {"chalk": "^2.1.0"}}')], store).assessments[0]
    new = run_off([("package.json", '{"dependencies": {"chalk": "^5.3.0"}}')], store).assessments[0]
    assert "compromised_version" not in kinds(old)
    assert finding(new, "compromised_version").detail["applicability"] == "undetermined"   # ^5.3.0 allows 5.6.1


def test_run003_deleted_release_allowed_without_cutoff_is_reason_only():
    # RUN-003: unpinned debug/ultralytics etc. were flagged only because the compromised release was deleted.
    s = store_of(rec(F.MALICIOUS, "npm", "debug", S.LISTED, version="4.4.2"))
    _, rr = run([("package.json", '{"dependencies": {"debug": "*"}}')], s, s,
                {("npm", "debug"): found("debug", ["4.4.1", "4.4.3"], latest="4.4.3")})
    a = rr.assessments[0]
    assert "compromised_version" not in kinds(a) and "no_evidence" in kinds(a)
    why = next(r for r in a.reasons if r.rule_id == "a3.malicious.version.reported_release_removed")
    assert why.evidence_ids and "4.4.3" in why.explanation and "lock" in why.explanation


def test_run003_deleted_release_allowed_under_cutoff_stays_undetermined():
    s = store_of(rec(F.MALICIOUS, "npm", "debug", S.LISTED, version="4.4.2"))
    _, rr = run([("package.json", '{"dependencies": {"debug": "*"}}')], s, s,
                {("npm", "debug"): found("debug", ["4.4.1", "4.4.3"])}, cutoff=CUT)
    assert finding(rr.assessments[0], "compromised_version").detail["applicability"] == "undetermined"


def test_run003_exact_pin_to_reported_release_still_affected():
    s = store_of(rec(F.MALICIOUS, "npm", "debug", S.LISTED, version="4.4.2"))
    _, rr = run([("package.json", '{"dependencies": {"debug": "4.4.2"}}')], s, s,
                {("npm", "debug"): found("debug", ["4.4.1", "4.4.3"])})
    assert finding(rr.assessments[0], "compromised_version").detail["applicability"] == "affected"


# --------------------------------------------------------------------------- finding 3 (npm evidence ranges)

def test_r2_3_npm_evidence_range_in_comma_form_is_read():
    assert satisfies_evidence_range("2.0.0", ">=0,<1.2.3") is False
    assert satisfies_evidence_range("1.0.0", ">=1.0.0,<1.2.3") is True
    s = store_of(rec(F.MALICIOUS, "npm", "foo", S.RANGE, rng=">=0,<1.2.3"))
    reg = {("npm", "foo"): found("foo", ["1.0.0", "2.0.0"])}
    _, outside = run([("package.json", '{"dependencies": {"foo": "2.0.0"}}')], s, s, reg)
    _, inside = run([("package.json", '{"dependencies": {"foo": "1.0.0"}}')], s, s, reg)
    assert "compromised_version" not in kinds(outside.assessments[0])
    assert finding(inside.assessments[0], "compromised_version").detail["applicability"] == "affected"


# --------------------------------------------------------------------------- finding 5 + node-semver cases

INCLUDE = [
    ("1.0.0 - 2.0.0", "1.2.3"), ("^1.2.3+build", "1.2.3"), ("^1.2.3+build", "1.3.0"),
    ("1.2.3-pre+asdf - 2.4.3-pre+asdf", "1.2.3"), ("1.2.3-pre+asdf - 2.4.3-pre+asdf", "1.2.3-pre.2"),
    ("1.2.3-pre+asdf - 2.4.3-pre+asdf", "2.4.3-alpha"), ("1.2.3+asdf - 2.4.3+asdf", "1.2.3"), ("1.0.0", "1.0.0"),
    (">=*", "0.2.4"), ("", "1.0.0"), ("*", "1.2.3"), (">=1.0.0", "1.0.0"), (">1.0.0", "1.0.1"), ("<=2.0.0", "2.0.0"),
    ("<2.0.0", "0.2.9"), (">= 1.0.0", "1.0.0"), (">  1.0.0", "1.1.0"), ("<\t2.0.0", "0.2.9"),
    ("0.1.20 || 1.2.4", "1.2.4"), (">=0.2.3 || <0.0.1", "0.0.0"), ("||", "1.3.4"), ("2.x.x", "2.1.3"),
    ("1.2.x || 2.x", "1.2.3"), ("x", "1.2.3"), ("2.*.*", "2.1.3"), ("2", "2.1.2"), ("2.3", "2.3.1"),
    ("~0.0.1", "0.0.2"), ("~x", "0.0.9"), ("~2", "2.0.9"), ("~2.4", "2.4.5"), ("~>3.2.1", "3.2.2"), ("~1", "1.2.3"),
    ("~> 1", "1.2.3"), ("~ 1.0", "1.0.2"), ("~ 1.0.3", "1.0.12"), (">= 1", "1.0.0"), ("< 1.2", "1.1.1"),
    ("~v0.5.4-pre", "0.5.5"), ("~v0.5.4-pre", "0.5.4"), ("=0.7.x", "0.7.2"), ("<=0.7.x", "0.7.2"),
    ("~1.2.1 >=1.2.3", "1.2.3"), ("~1.2.1 =1.2.3", "1.2.3"), ("~1.2.1 1.2.3", "1.2.3"), (">=1.2", "1.2.8"),
    ("^1.2.3", "1.8.1"), ("^0.1.2", "0.1.2"), ("^0.1", "0.1.2"), ("^0.0.1", "0.0.1"), ("^1.2 ^1", "1.4.2"),
    ("^1.2.3-alpha", "1.2.3-pre"), ("^0.0.1-alpha", "0.0.1-beta"), ("^0.0.1-alpha", "0.0.1"), ("^x", "1.2.3"),
    ("x - 1.0.0", "0.9.7"), ("x - 1.x", "0.9.7"), ("1.0.0 - x", "1.9.7"), ("1.x - x", "1.9.7"), ("<=7.x", "7.9.9"),
    ("1.2 - 2.3", "2.3.9"), (">1", "2.0.0"),
]
EXCLUDE = [
    ("1.0.0 - 2.0.0", "2.2.3"), ("1.2.3+asdf - 2.4.3+asdf", "1.2.3-pre.2"), ("^1.2.3+build", "2.0.0"),
    ("^1.2.3", "1.2.3-pre"), ("^1.2", "1.2.0-pre"), (">1.2", "1.3.0-beta"), ("<=1.2.3", "1.2.3-beta"),
    ("=0.7.x", "0.7.0-asdf"), (">=0.7.x", "0.7.0-asdf"), ("1.0.0", "1.0.1"), (">=1.0.0", "0.0.1"),
    ("<=2.0.0", "2.9999.9999"), ("<2.0.0", "2.2.9"), ("0.1.20 || 1.2.4", "1.2.3"), (">=0.2.3 || <0.0.1", "0.0.3"),
    ("2.x.x", "3.1.3"), ("1.2.x || 2.x", "1.1.3"), ("2", "1.1.2"), ("2.3", "2.4.1"), ("~0.0.1", "0.1.0-alpha"),
    ("~2.4", "2.5.0"), ("~>3.2.1", "3.2.0"), ("~1", "0.2.3"), ("~1.0", "1.1.0"), ("<1", "1.0.0"), (">=1.2", "1.1.1"),
    ("~v0.5.4-beta", "0.5.4-alpha"), ("<0.7.x", "0.7.2"), ("<1.2.3", "1.2.3-beta"), ("=1.2.3", "1.2.3-beta"),
    (">1.2", "1.2.8"), ("^0.0.1", "0.0.2-alpha"), ("^1.2.3", "2.0.0-alpha"), ("^1.2", "1.1.9"), ("*", "1.0.0-pre"),
    (">1", "2.0.0-beta"), ("1.2.x", "1.3.0-0"),
]


@pytest.mark.parametrize("rng,version", INCLUDE)
def test_npm_reference_include(rng, version):
    assert satisfies(version, rng) is True


@pytest.mark.parametrize("rng,version", EXCLUDE)
def test_npm_reference_exclude(rng, version):
    assert satisfies(version, rng) is False


@pytest.mark.parametrize("rng", ["blerg", "git+https://x/y", "npm:foo@1", "latest", "1.2.3 - ", "^1.2.3 || garbage"])
def test_npm_unreadable_range_is_undecided(rng):
    assert satisfies("1.2.3", rng) is None


# --------------------------------------------------------------------------- finding 4 (yanked under a cut-off)

def test_r2_4_yanked_list_ignored_under_cutoff():
    s = store_of(rec(F.MALICIOUS, "pypi", "yk", S.LISTED, version="1.1"))
    _, rr = run([("requirements.txt", "yk\n")], s, s,
                {("pypi", "yk"): found("yk", ["1.0", "1.1"], yanked=["1.1"])}, cutoff=CUT)
    assert finding(rr.assessments[0], "compromised_version").detail["applicability"] == "likely_affected"


def test_r2_4_yanked_list_used_without_cutoff():
    s = store_of(rec(F.MALICIOUS, "pypi", "yk", S.LISTED, version="1.1"))
    _, rr = run([("requirements.txt", "yk\n")], s, s, {("pypi", "yk"): found("yk", ["1.0", "1.1"], yanked=["1.1"])})
    assert "compromised_version" not in kinds(rr.assessments[0])


# --------------------------------------------------------------------------- finding 7 (pip pre-release and yanked rules)

def test_r2_7_specifier_naming_a_prerelease_allows_prereleases():
    s = store_of(rec(F.MALICIOUS, "pypi", "pre", S.LISTED, version="2.1rc1"))
    _, rr = run([("requirements.txt", "pre>=2.0b1\n")], s, s, {("pypi", "pre"): found("pre", ["2.0", "2.1rc1"])})
    f = finding(rr.assessments[0], "compromised_version")
    assert f.detail["applicability"] == "likely_affected" and f.detail["declared"]["resolved"] == "2.1rc1"


def test_r2_7_final_yanked_release_before_prerelease():
    s = store_of(rec(F.MALICIOUS, "pypi", "yb", S.LISTED, version="1.0"))
    _, rr = run([("requirements.txt", "yb\n")], s, s, {("pypi", "yb"): found("yb", ["1.0", "1.1b1"], yanked=["1.0"])})
    f = finding(rr.assessments[0], "compromised_version")
    assert f.detail["declared"]["resolved"] == "1.0" and f.detail["applicability"] == "likely_affected"


# --------------------------------------------------------------------------- finding 1 (no_evidence co-emission)

def test_r2_1_registered_after_cutoff_gives_unknown_without_no_evidence():
    s = store_of()
    _, rr = run([("requirements.txt", "slopname\n")], s, s,
                {("pypi", "slopname"): found("slopname", ["0.1"],
                                             times={"0.1": datetime(2025, 9, 1, tzinfo=timezone.utc)})}, cutoff=CUT)
    assert kinds(rr.assessments[0]) == ["unknown"]


def test_r2_1_nonexistent_without_no_evidence():
    s = store_of()
    _, rr = run([("requirements.txt", "madeupname\n")], s, s, {("pypi", "madeupname"): nf()})
    assert kinds(rr.assessments[0]) == ["nonexistent"]


def test_r2_1_post_cutoff_not_found_gives_unknown_only():
    s = store_of()
    _, rr = run([("requirements.txt", "madeupname\n")], s, s, {("pypi", "madeupname"): nf()}, cutoff=CUT)
    assert kinds(rr.assessments[0]) == ["unknown"]


def test_r2_1_registry_off_keeps_no_evidence_next_to_unknown():
    rr = run_off([("requirements.txt", "anything\n")], store_of())
    assert kinds(rr.assessments[0]) == ["unknown", "no_evidence"]


# --------------------------------------------------------------------------- finding 6 (missing cut-off flag)

def _assess_with_flag(flag, drop_rule):
    s = store_of()
    ex = extract_files("p", [UploadedFile("requirements.txt", b"madeupname\n")], clock=lambda: T0)

    class C:
        mode = "snapshot"

        def supports(self, eco):
            return True

        def lookup(self, eco, name):
            return nf()
    rg = verify(ex, mode="snapshot", client=C(), evidence_store=s, evidence_cutoff=CUT, clock=lambda: T0)
    res = rg.results[0]
    reasons = [r for r in res.reasons if not (drop_rule and r.rule_id == "a2.cutoff.snapshot_after_cutoff")]
    rg = rg.model_copy(update={"results": [res.model_copy(update={"retrieved_after_cutoff": flag, "reasons": reasons})]})
    return assess(ex, rg, evidence_store=s, clock=lambda: T0).assessments[0]


def test_r2_6_missing_flag_under_cutoff_is_derived_from_retrieval_time():
    assert kinds(_assess_with_flag(None, drop_rule=True)) == ["unknown"]


def test_r2_6_structured_flag_is_used_not_the_rule_text():
    # The rule text says "after the cut-off" was dropped; the flag alone decides.
    assert kinds(_assess_with_flag(True, drop_rule=True)) == ["unknown"]


# --------------------------------------------------------------------------- finding 8 (withdrawn is version-aware)

def test_r2_8_withdrawn_report_for_other_version_gives_no_finding():
    s = store_of(rec(F.WITHDRAWN, "pypi", "w", S.LISTED, version="0.1"))
    _, rr = run([("requirements.txt", "w==2.0\n")], s, s, {("pypi", "w"): found("w", ["0.1", "2.0"])})
    a = rr.assessments[0]
    assert "withdrawn_only" not in kinds(a) and "no_evidence" in kinds(a)
    assert "a3.withdrawn.other_versions_only" in rules(a)


def test_r2_8_withdrawn_report_for_declared_version_is_withdrawn_only():
    s = store_of(rec(F.WITHDRAWN, "pypi", "w", S.LISTED, version="0.1"))
    _, rr = run([("requirements.txt", "w==0.1\n")], s, s, {("pypi", "w"): found("w", ["0.1", "2.0"])})
    assert kinds(rr.assessments[0]) == ["withdrawn_only"]


# --------------------------------------------------------------------------- finding 9 (typosquat target is not nonexistent)

def test_r2_9_name_listed_only_as_typosquat_target_is_not_nonexistent():
    s = store_of(rec(F.TYPOSQUAT, "pypi", "reqestsss", target="reqestss"))
    _, rr = run([("requirements.txt", "reqestss\n")], s, s, {("pypi", "reqestss"): nf()})
    a = rr.assessments[0]
    assert "nonexistent" not in kinds(a) and "a3.nonexistent.named_as_target" in rules(a)


# --------------------------------------------------------------------------- findings 10, 12 (texts)

def test_r2_10_allowed_not_resolved_text_covers_npm_newer_than_latest():
    s = store_of(rec(F.MALICIOUS, "npm", "nl", S.LISTED, version="5.6.1"))
    _, rr = run([("package.json", '{"dependencies": {"nl": "^5.0.0"}}')], s, s,
                {("npm", "nl"): found("nl", ["5.0.0", "5.6.0", "5.6.1"], latest="5.6.0")})
    why = next(r for r in rr.assessments[0].reasons if r.rule_id == "a3.malicious.version.installed_version_not_affected")
    assert "latest" in why.explanation and "5.6.0" in why.explanation


def test_r2_12_pin_not_in_registry_text_mentions_cutoff():
    s = store_of()
    _, rr = run([("requirements.txt", "pp==3.0\n")], s, s, {("pypi", "pp"): found("pp", ["1.0"])}, cutoff=CUT)
    why = next(r for r in rr.assessments[0].reasons if r.rule_id == "a3.version.pin_not_in_registry")
    assert "after the cut-off" in why.explanation
