"""Regression tests for the third Agent 3 review (of the D-057 changes; D-058). Each test names its finding.

In-memory evidence stores from hand-written records; registry answers from fakes.
No network, no dataset files.
"""

import json
import socket
from datetime import datetime, timezone

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
from multi_agentic_security.agents.agent2_registry import LookupOutcome, verify
from multi_agentic_security.agents.agent3_risk import assess
from multi_agentic_security.contracts.evidence import LabelFamily as F, VersionScope as S
from multi_agentic_security.versioning.npm_semver import satisfies, satisfies_evidence_range

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


def pkg_json(name, spec):
    return [("package.json", json.dumps({"name": "app", "dependencies": {name: spec}}))]


def run_off(files, store):
    ex = extract_files("p", [UploadedFile(p, d.encode()) for p, d in files], clock=lambda: T0)
    rg = verify(ex, mode="off", client=None, evidence_store=store, clock=lambda: T0)
    return assess(ex, rg, evidence_store=store, clock=lambda: T0).assessments[0]


# --------------------------------------------------------------------------- finding 1 (high): pre-releases in evidence ranges

def test_r3_1_pinned_npm_prerelease_inside_malicious_range_is_affected():
    s = store_of(rec(F.MALICIOUS, "npm", "foo", S.RANGE, rng=">=0,<1.2.3"))
    _, rr = run(pkg_json("foo", "1.0.0-beta.1"), s, s, {("npm", "foo"): found("foo", ["1.0.0-beta.1", "1.2.3"])})
    assert finding(rr.assessments[0], "compromised_version").detail["applicability"] == "affected"


def test_r3_1_pinned_npm_prerelease_inside_vulnerable_range_is_affected():
    s = store_of(rec(F.VULNERABLE, "npm", "bar", S.RANGE, rng=">=1.0.0,<2.0.0"))
    _, rr = run(pkg_json("bar", "2.0.0-rc.1"), s, s, {("npm", "bar"): found("bar", ["1.0.0", "2.0.0-rc.1"])})
    assert finding(rr.assessments[0], "vulnerable").detail["applicability"] == "affected"


@pytest.mark.parametrize("version,rng,expected", [
    ("1.0.0-beta.1", ">=0", True),
    ("2.0.0-rc.1", ">=1.0.0,<2.0.0", True),     # 2.0.0-rc.1 sorts before 2.0.0
    ("1.0.0-alpha", ">=1.0.0", False),          # and 1.0.0-alpha before 1.0.0
    ("2.0.0", ">=1.0.0,<2.0.0", False),
])
def test_r3_1_evidence_ranges_include_prereleases(version, rng, expected):
    assert satisfies_evidence_range(version, rng) is expected


def test_r3_1_declared_ranges_still_exclude_prereleases():
    assert satisfies("2.0.0-rc.1", ">=1.0.0 <2.0.0") is False


# --------------------------------------------------------------------------- finding 5: "<1.2" is "<1.2.0-0"

@pytest.mark.parametrize("version,rng,expected", [
    ("1.2.0-beta", ">=1.2.0-alpha <1.2", False),
    ("1.1.9", "<1.2", True),
    ("1.2.0", "<1.2", False),
    ("0.9.0", "<1", True),
])
def test_r3_5_partial_less_than_bound(version, rng, expected):
    assert satisfies(version, rng) is expected


# --------------------------------------------------------------------------- finding 2: "*" and a pre-release

def test_r3_2_star_with_reported_prerelease_without_registry_stays_undetermined():
    s = store_of(rec(F.MALICIOUS, "npm", "bar", S.LISTED, version="3.0.0-rc.1"))
    a = run_off(pkg_json("bar", "*"), s)
    assert finding(a, "compromised_version").detail["applicability"] == "undetermined"


def test_r3_2_star_installs_prerelease_latest_tag():
    s = store_of(rec(F.MALICIOUS, "npm", "bar", S.LISTED, version="3.0.0-rc.1"))
    _, rr = run(pkg_json("bar", "*"), s, s,
                {("npm", "bar"): found("bar", ["2.0.0", "3.0.0-rc.1"], latest="3.0.0-rc.1")})
    assert finding(rr.assessments[0], "compromised_version").detail["applicability"] == "likely_affected"


def test_r3_2_caret_range_still_ignores_prerelease_latest():
    s = store_of(rec(F.MALICIOUS, "npm", "bar", S.LISTED, version="3.0.0-rc.1"))
    _, rr = run(pkg_json("bar", "^2.0.0"), s, s,
                {("npm", "bar"): found("bar", ["2.0.0", "3.0.0-rc.1"], latest="3.0.0-rc.1")})
    assert "compromised_version" not in kinds(rr.assessments[0])


# --------------------------------------------------------------------------- finding 3: yanked list under a cut-off

def test_r3_3_yank_that_changes_the_answer_gives_undetermined():
    s = store_of(rec(F.VULNERABLE, "pypi", "v", S.RANGE, rng=">=1.0,<1.9.1"))
    _, rr = run([("requirements.txt", "v\n")], s, s, {("pypi", "v"): found("v", ["1.9", "2.0"], yanked=["2.0"])},
                cutoff=CUT)
    assert finding(rr.assessments[0], "vulnerable").detail["applicability"] == "undetermined"


def test_r3_3_yank_that_does_not_change_the_answer_is_not_a_finding():
    s = store_of(rec(F.VULNERABLE, "pypi", "v", S.RANGE, rng=">=1.0,<1.5"))
    _, rr = run([("requirements.txt", "v\n")], s, s, {("pypi", "v"): found("v", ["1.9", "2.0"], yanked=["2.0"])},
                cutoff=CUT)
    assert "vulnerable" not in kinds(rr.assessments[0])


# --------------------------------------------------------------------------- finding 4: withdrawn reason texts

def test_r3_4_withdrawn_report_on_removed_release_uses_the_removed_rule():
    s = store_of(rec(F.WITHDRAWN, "npm", "wd", S.LISTED, version="1.2.0"))
    _, rr = run(pkg_json("wd", "^1.0.0"), s, s, {("npm", "wd"): found("wd", ["1.0.0", "1.3.0"])})
    a = rr.assessments[0]
    assert "withdrawn_only" not in kinds(a)
    assert "a3.withdrawn.reported_release_removed" in rules(a)
    assert "a3.withdrawn.other_versions_only" not in rules(a)


def test_r3_4_withdrawn_report_on_older_allowed_release_uses_the_older_rule():
    s = store_of(rec(F.WITHDRAWN, "npm", "wd", S.LISTED, version="1.0.0"))
    _, rr = run(pkg_json("wd", "^1.0.0"), s, s, {("npm", "wd"): found("wd", ["1.0.0", "1.3.0"])})
    assert "a3.withdrawn.installed_version_not_affected" in rules(rr.assessments[0])


# --------------------------------------------------------------------------- finding 8: security hold after the cut-off

def test_r3_8_security_hold_after_cutoff_is_unknown_without_no_evidence():
    hold = LookupOutcome(status="security_placeholder", rule_id="a2.status.security_placeholder", explanation="x",
                         retrieved_at=T0, source_url="u", metadata={"placeholder_published": "2025-09-01T00:00:00Z"})
    s = store_of()
    _, rr = run(pkg_json("held", "^1.0.0"), s, s, {("npm", "held"): hold}, cutoff=CUT)
    a = rr.assessments[0]
    assert kinds(a) == ["unknown"]
    assert "a3.registry.security_hold_not_historical" in rules(a)


# --------------------------------------------------------------------------- finding 9: both no-finding reasons kept

def test_r3_9_older_and_removed_releases_are_both_reported():
    s = store_of(rec(F.MALICIOUS, "pypi", "p", S.LISTED, version="1.0", rid="old"),
                 rec(F.MALICIOUS, "pypi", "p", S.LISTED, version="1.5", rid="gone"))
    _, rr = run([("requirements.txt", "p>=1.0\n")], s, s, {("pypi", "p"): found("p", ["1.0", "2.0"])})
    a = rr.assessments[0]
    why = next(r for r in a.reasons if r.rule_id == "a3.malicious.version.installed_version_not_affected")
    assert why.inputs["removed_releases_reported"] == 1 and "no longer in the registry" in why.explanation


# --------------------------------------------------------------------------- finding 6: item (g) when retrieval is before the cut-off

def test_r3_6_missing_flag_with_retrieval_before_cutoff_gives_nonexistent():
    later_cut = datetime(2026, 12, 1, tzinfo=timezone.utc)      # T0 (2026-11-16) is before it
    s = store_of()
    ex = extract_files("p", [UploadedFile("requirements.txt", b"madeupname\n")], clock=lambda: T0)

    class C:
        mode = "snapshot"

        def supports(self, eco):
            return True

        def lookup(self, eco, name):
            return nf()
    rg = verify(ex, mode="snapshot", client=C(), evidence_store=s, evidence_cutoff=later_cut, clock=lambda: T0)
    res = rg.results[0]
    rg = rg.model_copy(update={"results": [res.model_copy(update={"retrieved_after_cutoff": None})]})
    assert kinds(assess(ex, rg, evidence_store=s, clock=lambda: T0).assessments[0]) == ["nonexistent"]
