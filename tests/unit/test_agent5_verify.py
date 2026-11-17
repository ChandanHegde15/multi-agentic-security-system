"""Agent 5 (independent verifier) unit tests: one or more per check, rule and failure code.

Hand-written recommendations, in-memory evidence stores from hand-written records and
fake registry clients. No network, no dataset files, no Agent 4 code.
"""

import ast
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
from multi_agentic_security.agents.agent2_registry import LookupOutcome, verify
from multi_agentic_security.agents.agent5_verification import ALL_CHECKS, verify_recommendations
from multi_agentic_security.contracts.evidence import LabelFamily as F, VersionScope as S
from multi_agentic_security.contracts.pipeline import PackageRef, VerificationResult

from test_agent3_review import T0, found, nf, rec, store_of  # same folder (pytest rootdir import mode)

CUT = datetime(2025, 6, 1, tzinfo=timezone.utc)
AGENT5_DIR = Path(__file__).resolve().parents[2] / "src" / "multi_agentic_security" / "agents" / "agent5_verification"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


class Client:
    def __init__(self, answers, mode="snapshot", fail=False):
        self.answers, self.mode, self.fail, self.calls = answers, mode, fail, []

    def supports(self, eco):
        return True

    def lookup(self, eco, name):
        self.calls.append((eco, name))
        if self.fail:
            raise RuntimeError("boom")
        return self.answers.get((eco, name))


def outcome(status, *, retrieved=T0, error=None):
    return LookupOutcome(status=status, rule_id=f"a2.status.{status}", explanation="x", retrieved_at=retrieved,
                         source_url="u", error=error)


def ref(eco, name):
    return PackageRef.of(eco, name).model_dump()


def recd(dep_id, action, *, target=None, version=None, eco="pypi", claims=(), **extra):
    r = {"dependency_id": dep_id, "action": action, "backend": "rules", "claims": list(claims),
         "reasons": [{"rule_id": "a4.test", "outcome": action, "explanation": "hand-written"}]}
    if target is not None:
        r["target"] = {"package": ref(eco, target), "version": version}
    r.update(extra)
    return r


def claim(kind, eco, subject, *ids, obj=None):
    return {"type": kind, "subject": ref(eco, subject), "object": obj, "evidence_ids": list(ids)}


def stage(files, store, answers, *, cutoff=None, mode="snapshot"):
    ex = extract_files("p", [UploadedFile(p, d.encode()) for p, d in files], clock=lambda: T0)
    rg = verify(ex, mode=mode, client=Client(answers) if mode == "snapshot" else None, evidence_store=store,
                evidence_cutoff=cutoff, clock=lambda: T0)
    return ex, rg


def check(files, store, answers, make_recs, *, cutoff=None, client="same", mode="snapshot", enabled=None):
    ex, rg = stage(files, store, answers, cutoff=cutoff, mode=mode)
    recs = make_recs([d.dependency_id for d in ex.dependencies])
    tc = Client(answers) if client == "same" else client
    res = verify_recommendations(ex, rg, {"project_id": "p", "recommendations": recs}, evidence_store=store,
                                 target_client=tc, enabled_checks=enabled, clock=lambda: T0)
    VerificationResult.model_validate_json(res.model_dump_json())
    return res


def one(res):
    assert len(res.verifications) == 1, res.failures
    v = res.verifications[0]
    return v, {c.check: c.result for c in v.checks}


def req(text):
    return [("requirements.txt", text)]


def pkg_json(name, spec):
    return [("package.json", json.dumps({"name": "app", "dependencies": {name: spec}}))]


# --------------------------------------------------------------------------- isolation

def _imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            yield ("." * node.level) + (node.module or "")


# Allow-list: standard-library helpers, the validation and version libraries, and the project's
# own neutral packages. No LLM client, no HTTP or socket library, no other agent.
ALLOWED_TOP = {"__future__", "dataclasses", "datetime", "typing", "re", "pydantic", "packaging",
               "multi_agentic_security"}
ALLOWED_PROJECT = ("multi_agentic_security.contracts", "multi_agentic_security.evidence_store",
                   "multi_agentic_security.datasets.names", "multi_agentic_security.versioning")


def test_import_boundary_only_allowed_modules():
    # Agent 5 and the neutral version package it shares with Agent 3 ("semver" parses npm versions).
    files = sorted(AGENT5_DIR.glob("*.py")) + sorted((AGENT5_DIR.parents[1] / "versioning").glob("*.py"))
    allowed_top = ALLOWED_TOP | {"semver"}
    assert files
    for f in files:
        for name in _imports(f):
            if name.startswith("."):
                continue                                   # Agent 5's own modules
            assert name.split(".")[0] in allowed_top, (f.name, name)
            if name.startswith("multi_agentic_security"):
                assert name.startswith(ALLOWED_PROJECT), (f.name, name)
            assert "agent4_recommendation" not in name and "agent3_risk" not in name, (f.name, name)


# --------------------------------------------------------------------------- typosquat replacement (accept path)

def squat_store(extra=()):
    return store_of(rec(F.TYPOSQUAT, "pypi", "reqeusts", target="requests", rid="sq"), *extra)


def test_replace_typosquat_with_its_reference_is_accepted():
    s = squat_store()
    sq_id = rec(F.TYPOSQUAT, "pypi", "reqeusts", target="requests", rid="sq").evidence_id
    ans = {("pypi", "reqeusts"): found("reqeusts", ["0.1"]), ("pypi", "requests"): found("requests", ["2.31.0"])}
    v, c = one(check(req("reqeusts\n"), s, ans, lambda ids: [
        recd(ids[0], "replace", target="requests", claims=[claim("is_typosquat_of", "pypi", "reqeusts", sq_id,
                                                                 obj="requests")])]))
    assert v.verdict == "accept", v.reasons[-1].explanation
    assert c["replacement_matches_reference"] == "pass" and c["target_exists"] == "pass"
    assert v.reasons[-1].rule_id == "a5.verdict.accept"
    assert all(r.rule_id.startswith("a5.") for r in v.reasons)


def test_replace_with_a_different_package_than_the_reference_is_rejected():
    ans = {("pypi", "reqeusts"): found("reqeusts", ["0.1"]), ("pypi", "httpx"): found("httpx", ["0.27.0"])}
    v, c = one(check(req("reqeusts\n"), squat_store(), ans, lambda ids: [recd(ids[0], "replace", target="httpx")]))
    assert v.verdict == "reject" and c["replacement_matches_reference"] == "fail"


def test_replace_without_typosquat_record_does_not_need_a_reference():
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]), ("pypi", "newlib"): found("newlib", ["2.0"])}
    v, c = one(check(req("oldlib\n"), store_of(), ans, lambda ids: [recd(ids[0], "replace", target="newlib")]))
    assert c["replacement_matches_reference"] == "not_applicable" and v.verdict == "accept"


def test_replace_with_the_same_package_is_not_allowed():
    ans = {("pypi", "lib"): found("lib", ["1.0", "2.0"])}
    v, c = one(check(req("lib\n"), store_of(), ans, lambda ids: [recd(ids[0], "replace", target="lib")]))
    assert c["action_allowed"] == "fail" and v.verdict == "reject"


# --------------------------------------------------------------------------- target checks

def test_target_missing_from_registry_is_rejected():
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]), ("pypi", "hallucinated-lib"): nf()}
    v, c = one(check(req("oldlib\n"), store_of(), ans, lambda ids: [recd(ids[0], "replace", target="hallucinated-lib")]))
    assert c["target_exists"] == "fail" and v.verdict == "reject"


def test_target_security_placeholder_is_rejected():
    ans = {("npm", "left"): found("left", ["1.0.0"]), ("npm", "evil"): outcome("security_placeholder")}
    v, c = one(check(pkg_json("left", "^1.0.0"), store_of(), ans,
                     lambda ids: [recd(ids[0], "replace", target="evil", eco="npm")]))
    assert c["target_exists"] == "fail"


def test_target_version_not_in_registry_is_rejected():
    ans = {("pypi", "lib"): found("lib", ["1.0", "2.0"])}
    v, c = one(check(req("lib==1.0\n"), store_of(), ans,
                     lambda ids: [recd(ids[0], "upgrade", target="lib", version="9.9")]))
    assert c["target_exists"] == "fail"


def test_malicious_target_is_rejected():
    s = store_of(rec(F.MALICIOUS, "pypi", "evilpkg"))
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]), ("pypi", "evilpkg"): found("evilpkg", ["0.1"])}
    v, c = one(check(req("oldlib\n"), s, ans, lambda ids: [recd(ids[0], "replace", target="evilpkg")]))
    assert c["target_not_malicious"] == "fail" and v.verdict == "reject"
    assert rec(F.MALICIOUS, "pypi", "evilpkg").evidence_id in next(
        x for x in v.checks if x.check == "target_not_malicious").evidence_ids


def test_typosquat_target_is_rejected():
    s = store_of(rec(F.TYPOSQUAT, "pypi", "nunpy", target="numpy"))
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]), ("pypi", "nunpy"): found("nunpy", ["1.0"])}
    v, c = one(check(req("oldlib\n"), s, ans, lambda ids: [recd(ids[0], "replace", target="nunpy")]))
    assert c["target_not_typosquat"] == "fail"


def test_typosquat_target_role_is_not_a_typosquat():
    s = store_of(rec(F.TYPOSQUAT, "pypi", "nunpy", target="numpy"))
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]), ("pypi", "numpy"): found("numpy", ["2.0.0"])}
    v, c = one(check(req("oldlib\n"), s, ans, lambda ids: [recd(ids[0], "replace", target="numpy")]))
    assert c["target_not_typosquat"] == "pass"


def test_upgrade_into_a_vulnerable_range_is_rejected_and_past_it_is_accepted():
    s = store_of(rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng=">=1.0,<2.1"))
    ans = {("pypi", "lib"): found("lib", ["1.0", "2.0", "2.1"])}
    v, c = one(check(req("lib==1.0\n"), s, ans, lambda ids: [recd(ids[0], "upgrade", target="lib", version="2.0")]))
    assert c["target_version_not_vulnerable"] == "fail" and v.verdict == "reject"
    v, c = one(check(req("lib==1.0\n"), s, ans, lambda ids: [recd(ids[0], "upgrade", target="lib", version="2.1")]))
    assert c["target_version_not_vulnerable"] == "pass" and v.verdict == "accept"


def test_downgrade_away_from_compromised_release_is_accepted():
    s = store_of(rec(F.MALICIOUS, "npm", "debug", S.LISTED, version="4.4.2"))
    ans = {("npm", "debug"): found("debug", ["4.4.1", "4.4.2"])}
    v, c = one(check(pkg_json("debug", "4.4.2"), s, ans,
                     lambda ids: [recd(ids[0], "downgrade", target="debug", version="4.4.1", eco="npm")]))
    assert v.verdict == "accept", [(x.check, x.result, x.detail) for x in v.checks]
    allowed = next(r for r in v.reasons if r.rule_id.startswith("a5.check.action_allowed"))
    assert allowed.inputs["semver_distance"] == {"level": "patch", "delta": -1}
    assert allowed.inputs["constraint_admits_target"] is False


def test_target_without_version_uses_what_a_new_install_receives():
    s = store_of(rec(F.VULNERABLE, "pypi", "newlib", S.RANGE, rng="<3.0"))
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]), ("pypi", "newlib"): found("newlib", ["2.0", "3.0"])}
    v, c = one(check(req("oldlib\n"), s, ans, lambda ids: [recd(ids[0], "replace", target="newlib")]))
    assert c["target_version_not_vulnerable"] == "pass"
    ans[("pypi", "newlib")] = found("newlib", ["2.0", "3.0"], yanked=["3.0"])
    v, c = one(check(req("oldlib\n"), s, ans, lambda ids: [recd(ids[0], "replace", target="newlib")]))
    assert c["target_version_not_vulnerable"] == "fail"        # pip skips the yanked 3.0


def test_target_without_version_and_scoped_reports_cannot_be_decided_when_unresolvable():
    s = store_of(rec(F.MALICIOUS, "pypi", "newlib", S.LISTED, version="2.0"))
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]),
           ("pypi", "newlib"): found("newlib", ["2.0"], times={"2.0": datetime(2025, 9, 1, tzinfo=timezone.utc)})}
    v, c = one(check(req("oldlib\n"), s, ans, lambda ids: [recd(ids[0], "replace", target="newlib")], cutoff=CUT))
    assert c["target_exists"] == "fail"           # no release before the cut-off
    assert c["target_not_malicious"] == "not_run"


# --------------------------------------------------------------------------- action direction

@pytest.mark.parametrize("action,version,result", [
    ("upgrade", "2.0", "pass"), ("upgrade", "1.0", "fail"), ("upgrade", "0.9", "fail"),
    ("downgrade", "0.9", "pass"), ("downgrade", "2.0", "fail"), ("upgrade", "not a version", "fail"),
])
def test_action_direction(action, version, result):
    ans = {("pypi", "lib"): found("lib", ["0.9", "1.0", "2.0"])}
    v, c = one(check(req("lib==1.0\n"), store_of(), ans,
                     lambda ids: [recd(ids[0], action, target="lib", version=version)]))
    assert c["action_allowed"] == result


def test_upgrade_must_keep_the_package():
    ans = {("pypi", "lib"): found("lib", ["1.0"]), ("pypi", "other"): found("other", ["2.0"])}
    v, c = one(check(req("lib==1.0\n"), store_of(), ans,
                     lambda ids: [recd(ids[0], "upgrade", target="other", version="2.0")]))
    assert c["action_allowed"] == "fail"


def test_unpinned_upgrade_passes_without_direction_check():
    ans = {("pypi", "lib"): found("lib", ["1.0", "2.0"])}
    v, c = one(check(req("lib>=1.0\n"), store_of(), ans,
                     lambda ids: [recd(ids[0], "upgrade", target="lib", version="2.0")]))
    assert c["action_allowed"] == "pass"


# --------------------------------------------------------------------------- action consistency (re-derived, not Agent 3)

def test_keep_on_whole_package_malicious_is_rejected():
    s = store_of(rec(F.MALICIOUS, "pypi", "evilpkg"))
    v, c = one(check(req("evilpkg\n"), s, {("pypi", "evilpkg"): found("evilpkg", ["0.1"])},
                     lambda ids: [recd(ids[0], "keep")]))
    assert c["action_consistent"] == "fail" and v.verdict == "reject"


def test_upgrade_of_a_listed_typosquat_is_rejected():
    s = squat_store()
    ans = {("pypi", "reqeusts"): found("reqeusts", ["0.1", "0.2"])}
    v, c = one(check(req("reqeusts==0.1\n"), s, ans,
                     lambda ids: [recd(ids[0], "upgrade", target="reqeusts", version="0.2")]))
    assert c["action_consistent"] == "fail" and c["target_not_typosquat"] == "fail"


def test_keep_on_pinned_compromised_release_is_rejected_and_other_release_accepted():
    s = store_of(rec(F.MALICIOUS, "npm", "chalk", S.LISTED, version="5.6.1"))
    ans = {("npm", "chalk"): found("chalk", ["5.6.0", "5.6.1"])}
    v, c = one(check(pkg_json("chalk", "5.6.1"), s, ans, lambda ids: [recd(ids[0], "keep")]))
    assert c["action_consistent"] == "fail"
    v, c = one(check(pkg_json("chalk", "5.6.0"), s, ans, lambda ids: [recd(ids[0], "keep")]))
    assert c["action_consistent"] == "pass" and v.verdict == "accept"


def test_keep_on_range_that_excludes_the_reported_release_is_accepted():
    s = store_of(rec(F.MALICIOUS, "npm", "chalk", S.LISTED, version="5.6.1"))
    v, c = one(check(pkg_json("chalk", "^2.1.0"), s, {("npm", "chalk"): found("chalk", ["2.4.2", "5.6.1"])},
                     lambda ids: [recd(ids[0], "keep")]))
    assert c["action_consistent"] == "pass"


def test_keep_on_range_resolving_to_reported_release_is_rejected():
    s = store_of(rec(F.MALICIOUS, "npm", "chalk", S.LISTED, version="5.6.1"))
    v, c = one(check(pkg_json("chalk", "^5.0.0"), s, {("npm", "chalk"): found("chalk", ["5.6.0", "5.6.1"])},
                     lambda ids: [recd(ids[0], "keep")]))
    assert c["action_consistent"] == "fail"


def test_keep_with_removed_reported_release_is_accepted_and_reported():
    s = store_of(rec(F.MALICIOUS, "pypi", "p", S.LISTED, version="1.5"))
    v, c = one(check(req("p>=1.0\n"), s, {("pypi", "p"): found("p", ["1.0", "2.0"])},
                     lambda ids: [recd(ids[0], "keep")]))
    assert c["action_consistent"] == "pass"
    why = next(r for r in v.reasons if r.rule_id == "a5.check.action_consistent.pass")
    assert why.inputs["removed_release_ids"] and "lock files" in why.explanation


def test_keep_with_removed_reported_release_under_cutoff_needs_review():
    s = store_of(rec(F.MALICIOUS, "pypi", "p", S.LISTED, version="1.5"))
    v, c = one(check(req("p>=1.0\n"), s, {("pypi", "p"): found("p", ["1.0", "2.0"])},
                     lambda ids: [recd(ids[0], "keep")], cutoff=CUT))
    assert c["action_consistent"] == "not_run" and v.verdict == "abstain"


def test_keep_on_star_with_prerelease_latest_tag_is_rejected():
    s = store_of(rec(F.MALICIOUS, "npm", "bar", S.LISTED, version="3.0.0-rc.1"))
    ans = {("npm", "bar"): found("bar", ["2.0.0", "3.0.0-rc.1"], latest="3.0.0-rc.1")}
    v, c = one(check(pkg_json("bar", "*"), s, ans, lambda ids: [recd(ids[0], "keep")]))
    assert c["action_consistent"] == "fail"


def test_keep_when_yanked_state_decides_needs_review_under_cutoff():
    s = store_of(rec(F.VULNERABLE, "pypi", "v", S.RANGE, rng=">=1.0,<1.9.1"))
    ans = {("pypi", "v"): found("v", ["1.9", "2.0"], yanked=["2.0"])}
    v, c = one(check(req("v\n"), s, ans, lambda ids: [recd(ids[0], "keep")], cutoff=CUT))
    assert c["action_consistent"] == "not_run"


def test_keep_on_nonexistent_package_is_rejected():
    v, c = one(check(req("madeupname\n"), store_of(), {("pypi", "madeupname"): nf()},
                     lambda ids: [recd(ids[0], "keep")]))
    assert c["action_consistent"] == "fail"


def test_keep_on_not_found_after_cutoff_needs_review():
    v, c = one(check(req("madeupname\n"), store_of(), {("pypi", "madeupname"): nf()},
                     lambda ids: [recd(ids[0], "keep")], cutoff=CUT))
    assert c["action_consistent"] == "not_run" and v.verdict == "abstain"


def test_keep_with_registry_off_needs_review():
    v, c = one(check(req("anything\n"), store_of(), {}, lambda ids: [recd(ids[0], "keep")], mode="off", client=None))
    assert c["action_consistent"] == "not_run" and v.verdict == "abstain"


@pytest.mark.parametrize("action", ["remove", "investigate", "abstain"])
def test_actions_that_do_not_keep_the_package_are_consistent(action):
    s = store_of(rec(F.MALICIOUS, "pypi", "evilpkg"))
    v, c = one(check(req("evilpkg\n"), s, {("pypi", "evilpkg"): found("evilpkg", ["0.1"])},
                     lambda ids: [recd(ids[0], action)]))
    assert c["action_consistent"] == "pass" and v.verdict == "accept"
    assert all(c[t] == "not_applicable" for t in ("target_exists", "target_not_malicious", "target_not_typosquat",
                                                  "target_version_not_vulnerable"))


# --------------------------------------------------------------------------- claims

def mal_store():
    return store_of(rec(F.MALICIOUS, "pypi", "evilpkg", rid="m"), rec(F.VULNERABLE, "pypi", "lib", S.RANGE,
                                                                       rng=">=1.0,<2.0", rid="v"),
                    rec(F.WITHDRAWN, "pypi", "oops", rid="w"),
                    rec(F.MALICIOUS, "pypi", "late", pub=datetime(2025, 9, 1).date(), rid="late"))


def ev(name, fam=F.MALICIOUS, scope=S.ALL, **kw):
    return rec(fam, "pypi", name, scope, **kw).evidence_id


def claim_result(subject, c, *, cutoff=None, answers=None):
    ans = answers or {("pypi", subject): found(subject, ["1.0"])}
    v, checks = one(check(req(f"{subject}\n"), mal_store(), ans, lambda ids: [recd(ids[0], "remove", claims=[c])],
                          cutoff=cutoff))
    return checks["claims_supported"], v


M_ID = rec(F.MALICIOUS, "pypi", "evilpkg", rid="m").evidence_id
V_ID = rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng=">=1.0,<2.0", rid="v").evidence_id
W_ID = rec(F.WITHDRAWN, "pypi", "oops", rid="w").evidence_id
LATE_ID = rec(F.MALICIOUS, "pypi", "late", pub=datetime(2025, 9, 1).date(), rid="late").evidence_id


@pytest.mark.parametrize("subject,c,expected", [
    ("evilpkg", claim("is_reported_malicious", "pypi", "evilpkg", M_ID), "pass"),
    ("evilpkg", claim("is_reported_malicious", "pypi", "evilpkg"), "fail"),                 # no evidence cited
    ("evilpkg", claim("is_reported_malicious", "pypi", "evilpkg", "ev-doesnotexist"), "fail"),
    ("evilpkg", claim("is_vulnerable", "pypi", "evilpkg", M_ID), "fail"),                   # wrong family
    ("lib", claim("is_reported_malicious", "pypi", "lib", M_ID), "fail"),                   # about another package
    ("evilpkg", claim("is_compromised_version", "pypi", "evilpkg", M_ID, obj="0.1"), "fail"),  # whole-package record
    ("lib", claim("is_vulnerable", "pypi", "lib", V_ID, obj="1.5"), "pass"),
    ("lib", claim("is_vulnerable", "pypi", "lib", V_ID, obj="2.0"), "fail"),
    ("lib", claim("fixed_in", "pypi", "lib", V_ID, obj="2.0"), "pass"),
    ("lib", claim("fixed_in", "pypi", "lib", V_ID, obj="1.9"), "fail"),
    ("lib", claim("fixed_in", "pypi", "lib", V_ID), "fail"),                                # no version named
    ("oops", claim("report_withdrawn", "pypi", "oops", W_ID), "pass"),
    ("lib", claim("no_evidence_found", "pypi", "lib"), "fail"),
    ("clean", claim("no_evidence_found", "pypi", "clean"), "pass"),
    ("clean", claim("no_evidence_found", "pypi", "clean", M_ID), "fail"),
])
def test_claims(subject, c, expected):
    assert claim_result(subject, c)[0] == expected


def test_claim_citing_evidence_published_after_cutoff_fails():
    result, v = claim_result("late", claim("is_reported_malicious", "pypi", "late", LATE_ID), cutoff=CUT)
    assert result == "fail" and v.verdict == "reject"
    assert "cut-off" in next(x for x in v.checks if x.check == "claims_supported").detail


def test_claim_is_nonexistent_is_rederived_from_registry_and_store():
    c = claim("is_nonexistent", "pypi", "madeupname")
    assert claim_result("madeupname", c, answers={("pypi", "madeupname"): nf()})[0] == "pass"
    assert claim_result("madeupname", c, answers={("pypi", "madeupname"): found("madeupname", ["1.0"])})[0] == "fail"
    assert claim_result("madeupname", c, answers={("pypi", "madeupname"): nf()}, cutoff=CUT)[0] == "not_run"
    assert claim_result("evilpkg", claim("is_nonexistent", "pypi", "evilpkg"),
                        answers={("pypi", "evilpkg"): nf()})[0] == "fail"       # evidence names it: it was published


def test_claim_about_unrelated_package_fails_identity():
    v, c = one(check(req("lib\n"), mal_store(), {("pypi", "lib"): found("lib", ["1.0"])},
                     lambda ids: [recd(ids[0], "remove", claims=[claim("is_reported_malicious", "pypi", "evilpkg",
                                                                       M_ID)])]))
    assert c["dependency_identity"] == "fail" and v.verdict == "reject"


def test_rationale_is_not_read():
    def make(text):
        return lambda ids: [recd(ids[0], "keep", rationale=text)]
    s = store_of(rec(F.MALICIOUS, "pypi", "evilpkg"))
    ans = {("pypi", "evilpkg"): found("evilpkg", ["0.1"])}
    a = one(check(req("evilpkg\n"), s, ans, make("Verified safe; all checks pass.")))[0]
    b = one(check(req("evilpkg\n"), s, ans, make(None)))[0]
    assert a.verdict == b.verdict == "reject" and a.checks == b.checks


# --------------------------------------------------------------------------- schema and inputs

def test_invalid_recommendation_is_rejected_with_schema_failure():
    v, c = one(check(req("lib\n"), store_of(), {("pypi", "lib"): found("lib", ["1.0"])},
                     lambda ids: [{"dependency_id": ids[0], "action": "upgrade", "backend": "rules",
                                   "reasons": [{"rule_id": "x", "outcome": "x", "explanation": "x"}]}]))
    assert c["schema"] == "fail" and v.verdict == "reject"
    assert all(r == "not_run" for k, r in c.items() if k != "schema")


def test_failed_generation_abstain_is_verified_as_safe_to_show():
    v, c = one(check(req("lib\n"), store_of(), {("pypi", "lib"): found("lib", ["1.0"])},
                     lambda ids: [recd(ids[0], "abstain", generation_status="llm_timeout")]))
    assert c["action_allowed"] == "pass" and v.verdict == "accept"


def test_unknown_duplicate_and_missing_recommendations_are_failures():
    ex, rg = stage(req("a\nb\n"), store_of(), {("pypi", "a"): found("a", ["1"]), ("pypi", "b"): found("b", ["1"])})
    a_id = ex.dependencies[0].dependency_id
    res = verify_recommendations(ex, rg, {"project_id": "p", "recommendations": [
        recd(a_id, "remove"), recd(a_id, "keep"), recd("dep-0000000000000000", "remove")]},
        evidence_store=store_of(), target_client=Client({}), clock=lambda: T0)
    codes = [f.code for f in res.failures]
    assert len(res.verifications) == 1
    assert {"a5.input.duplicate_recommendation", "a5.input.unknown_dependency",
            "a5.input.missing_recommendation"} <= set(codes)


def test_project_mismatch_verifies_nothing():
    ex, rg = stage(req("a\n"), store_of(), {})
    res = verify_recommendations(ex, rg, {"project_id": "other", "recommendations": [
        recd(ex.dependencies[0].dependency_id, "remove")]}, evidence_store=store_of(), target_client=Client({}))
    assert not res.verifications and [f.code for f in res.failures] == ["a5.input.project_mismatch"]


def test_store_missing_and_incomplete():
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]), ("pypi", "newlib"): found("newlib", ["1.0"])}
    ex, rg = stage(req("oldlib\n"), store_of(), ans)
    recs = {"project_id": "p", "recommendations": [recd(ex.dependencies[0].dependency_id, "replace", target="newlib")]}
    res = verify_recommendations(ex, rg, recs, evidence_store=None, target_client=Client(ans))
    assert res.verifications[0].verdict == "abstain" and "a5.evidence.store_missing" in [f.code for f in res.failures]
    partial = store_of(missing=("typosquat/yctt_pairs",))
    res = verify_recommendations(ex, rg, recs, evidence_store=partial, target_client=Client(ans))
    _, c = one(res)
    assert c["target_not_typosquat"] == "not_run" and res.verifications[0].verdict == "abstain"
    assert {"a5.evidence.store_incomplete", "a5.evidence.store_differs_from_agent2"} <= {f.code for f in res.failures}


# --------------------------------------------------------------------------- cut-off and registry

def test_live_client_is_refused_under_cutoff():
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]), ("pypi", "newlib"): found("newlib", ["1.0"])}
    live = Client(ans, mode="live")
    res = check(req("oldlib\n"), store_of(), ans, lambda ids: [recd(ids[0], "replace", target="newlib")],
                cutoff=CUT, client=live)
    v, c = one(res)
    assert c["target_exists"] == "not_run" and v.verdict == "abstain" and live.calls == []
    assert "a5.registry.live_with_cutoff" in [f.code for f in res.failures]


def test_target_version_uploaded_after_cutoff_fails():
    times = {"1.0": datetime(2024, 1, 1, tzinfo=timezone.utc), "2.0": datetime(2025, 8, 1, tzinfo=timezone.utc)}
    ans = {("pypi", "lib"): found("lib", ["1.0", "2.0"], times=times)}
    v, c = one(check(req("lib==1.0\n"), store_of(), ans,
                     lambda ids: [recd(ids[0], "upgrade", target="lib", version="2.0")], cutoff=CUT))
    assert c["target_exists"] == "fail" and "after the cut-off" in next(
        x for x in v.checks if x.check == "target_exists").detail


def test_target_not_found_after_cutoff_is_not_used():
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]), ("pypi", "gone"): nf()}
    v, c = one(check(req("oldlib\n"), store_of(), ans, lambda ids: [recd(ids[0], "replace", target="gone")],
                     cutoff=CUT))
    assert c["target_exists"] == "not_run" and v.verdict == "abstain"


def test_evidence_after_cutoff_is_not_used_against_the_target():
    s = store_of(rec(F.MALICIOUS, "pypi", "late", pub=datetime(2025, 9, 1).date()))
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]), ("pypi", "late"): found("late", ["1.0"])}
    v, c = one(check(req("oldlib\n"), s, ans, lambda ids: [recd(ids[0], "replace", target="late")], cutoff=CUT))
    assert c["target_not_malicious"] == "pass"


FAILED_LOOKUPS = {
    "not_in_snapshot": dict(answer=None),
    "lookup_error": dict(answer=outcome("lookup_error", error="timeout")),
    "invalid_response": dict(answer=outcome("invalid_response", error="bad json")),
    "client_raises": dict(answer=None, fail=True),
    "no_client": dict(answer=None, no_client=True),
    "not_found_after_cutoff": dict(answer=nf(), cutoff=CUT),
    "placeholder_after_cutoff": dict(answer=outcome("security_placeholder"), cutoff=CUT),
}


@pytest.mark.parametrize("kind", sorted(FAILED_LOOKUPS))
@pytest.mark.parametrize("action,version", [("replace", None), ("replace", "1.0"), ("upgrade", "2.0"),
                                            ("downgrade", "0.5")])
def test_failed_target_lookup_never_gives_accept(kind, action, version):
    spec = FAILED_LOOKUPS[kind]
    target = "lib" if action != "replace" else "newlib"
    a2_answers = {("pypi", "lib"): found("lib", ["0.5", "1.0", "2.0"])}
    client = None if spec.get("no_client") else Client(
        {("pypi", target): spec["answer"]} if spec["answer"] is not None else {}, fail=spec.get("fail", False))
    res = check(req("lib==1.0\n"), store_of(), a2_answers,
                lambda ids: [recd(ids[0], action, target=target, version=version)], cutoff=spec.get("cutoff"),
                client=client)
    v, c = one(res)
    assert v.verdict != "accept"
    assert c["target_exists"] == "not_run"


def test_client_exception_is_a_failure_state():
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"])}
    res = check(req("oldlib\n"), store_of(), ans, lambda ids: [recd(ids[0], "replace", target="newlib")],
                client=Client({}, fail=True))
    assert "a5.registry.client_error" in [f.code for f in res.failures]


# --------------------------------------------------------------------------- ablation switches

def test_switched_off_check_is_not_required():
    ans = {("pypi", "oldlib"): found("oldlib", ["1.0"]), ("pypi", "newlib"): found("newlib", ["1.0"])}
    enabled = [c for c in ALL_CHECKS if c != "target_exists"]
    res = check(req("oldlib\n"), store_of(), ans, lambda ids: [recd(ids[0], "replace", target="newlib")],
                client=None, enabled=enabled)
    v, c = one(res)
    te = next(x for x in v.checks if x.check == "target_exists")
    assert te.result == "not_run" and te.required is False and v.verdict == "accept"
    assert "a5.check.target_exists.switched_off" in [r.rule_id for r in v.reasons]


def test_unknown_check_name_is_refused():
    ex, rg = stage(req("a\n"), store_of(), {})
    with pytest.raises(ValueError):
        verify_recommendations(ex, rg, {"project_id": "p", "recommendations": []}, evidence_store=store_of(),
                               enabled_checks=["schema", "nonsense"])


def test_every_verification_has_one_reason_per_check_and_a_verdict_reason():
    v, _ = one(check(req("lib\n"), store_of(), {("pypi", "lib"): found("lib", ["1.0"])},
                     lambda ids: [recd(ids[0], "keep")]))
    assert [c.check for c in v.checks] == list(ALL_CHECKS)
    assert len(v.reasons) == len(ALL_CHECKS) + 1 and v.reasons[-1].rule_id == f"a5.verdict.{v.verdict}"
