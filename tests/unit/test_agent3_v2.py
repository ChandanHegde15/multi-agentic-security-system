"""Agent 3: v1 adapter (frozen baseline unchanged), version applicability, name similarity and
v2 findings per family. Evidence stores are built in memory from hand-written records;
registry results come from Agent 2 on hand-written inputs. No network, no dataset files.
"""

import ast
import socket
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
from multi_agentic_security.agents.agent2_registry import LookupOutcome, verify
from multi_agentic_security.agents.agent3_risk import assess
from multi_agentic_security.agents.agent3_risk.similarity_v2 import PopularIndex, damerau_levenshtein
from multi_agentic_security.agents.agent3_risk.v1_adapter import v1_status
from multi_agentic_security.agents.agent3_risk.versions import applicability, declared_version, fixed_bounds
from multi_agentic_security.contracts.evidence import EvidenceRecord, LabelFamily as F, Provenance, VersionScope as S
from multi_agentic_security.contracts.pipeline import RiskResult
from multi_agentic_security.evidence_store import EvidenceStore

T0 = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def rec(fam, eco, name, scope=S.ALL, *, version=None, rng=None, pub=date(2025, 1, 1), target=None, rid=None, ds="src-a"):
    return EvidenceRecord(
        family=fam, ecosystem=eco, name_raw=name, name_normalized=name, version_scope=scope, version=version,
        version_range=rng, published=pub, target_name_raw=target, target_name_normalized=target,
        provenance=Provenance(source_dataset=ds, source_version="t1", source_record_id=rid or f"{fam.value}:{name}:{version or rng}",
                              source_file="t.json", source_file_sha256="0" * 64, license="test",
                              retrieved_at=T0))


def store_of(*records):
    return EvidenceStore(Path("mem"), [], [], [("mem/table", r) for r in records])


class Client:
    """Snapshot-mode fake answering from a dict of outcomes."""
    mode = "snapshot"

    def __init__(self, answers):
        self.answers = answers

    def supports(self, eco):
        return True

    def lookup(self, eco, name):
        return self.answers.get((eco, name))


def found(eco, name, versions, *, latest=None, yanked=None, times=None):
    times = times or {v: datetime(2024, 1, 1 + i, tzinfo=timezone.utc) for i, v in enumerate(versions)}
    return LookupOutcome(status="found", rule_id="a2.status.found", explanation="x", retrieved_at=T0,
                         source_url="u", canonical_name=name, versions=list(versions), upload_times=times,
                         latest_version=latest or versions[-1], metadata={"yanked_versions": yanked} if yanked else {})


def nf(eco, name):
    return LookupOutcome(status="not_found", rule_id="a2.status.not_found", explanation="x", retrieved_at=T0, source_url="u")


def pipeline(files, store, answers, cutoff=None):
    ex = extract_files("p3", [UploadedFile(p, d.encode()) for p, d in files], clock=lambda: T0)
    rg = verify(ex, mode="snapshot", client=Client(answers), evidence_store=store, evidence_cutoff=cutoff, clock=lambda: T0)
    rr = assess(ex, rg, evidence_store=store, clock=lambda: T0)
    RiskResult.model_validate_json(rr.model_dump_json())
    return ex, rg, rr


def kinds(a):
    return [f.finding for f in a.findings]


def finding(a, kind):
    return next(f for f in a.findings if f.finding == kind)


# --------------------------------------------------------------------------- frozen baseline

def test_baseline_v1_is_not_modified_by_agent3_code():
    """Agent 3 v2 modules only import baseline_v1; they never patch it."""
    for mod in ("assess.py", "v1_adapter.py", "versions.py", "similarity_v2.py"):
        src = (ROOT / "src/multi_agentic_security/agents/agent3_risk" / mod).read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    assert not (isinstance(t, ast.Attribute) and "baseline" in ast.unparse(t)), (mod, ast.unparse(t))


@pytest.mark.parametrize("status,reason,expected", [
    ("found", None, "verified"), ("security_placeholder", None, "verified"), ("not_found", None, "not_found"),
    ("lookup_error", None, "registry_error"), ("invalid_response", None, "registry_error"),
    ("not_checked", "a2.not_checked.unsupported_ecosystem", "unsupported_ecosystem"),
    ("not_checked", "a2.not_checked.mode_off", "registry_error"),
])
def test_v1_status_mapping(status, reason, expected):
    from multi_agentic_security.contracts.pipeline import Reason, RegistryVerification
    kw = {"retrieved_at": T0} if status not in ("not_checked",) else {}
    if status in ("lookup_error", "invalid_response"):
        kw["error"] = "e"
    reg = RegistryVerification(dependency_id="dep-0000000000000000", registry="pypi", status=status,
                               reasons=[Reason(rule_id=reason or "a2.x", outcome="o", explanation="e")], **kw)
    assert v1_status(reg) == expected


def test_v1_scores_registry_present_malicious_as_low_and_v2_reports_it():
    """RQ4 in miniature: a registry-present malicious package is low for v1, malicious for v2."""
    s = store_of(rec(F.MALICIOUS, "pypi", "bad-pkg"))
    _, _, rr = pipeline([("requirements.txt", "bad-pkg==1.0\n")], s, {("pypi", "bad-pkg"): found("pypi", "bad-pkg", ["1.0"])})
    a = rr.assessments[0]
    assert a.baseline_v1.risk_level == "low" and a.baseline_v1.policy_version == "agent3/v1"
    assert "malicious_reported" in kinds(a)


def test_v1_not_found_with_similarity_is_unchanged():
    _, _, rr = pipeline([("requirements.txt", "reqests\n")], store_of(), {("pypi", "reqests"): nf("pypi", "reqests")})
    v1 = rr.assessments[0].baseline_v1
    assert v1.risk_score == 70 and v1.risk_level == "high"          # 50 + 20 (similarity 0.875 to 'requests')


# --------------------------------------------------------------------------- versions

def dep_for(text, path="requirements.txt"):
    ex = extract_files("p", [UploadedFile(path, text.encode())], clock=lambda: T0)
    return ex.dependencies[0]


def reg_found(versions, latest=None, yanked=None):
    from multi_agentic_security.contracts.pipeline import Reason, RegistryVerification
    return RegistryVerification(dependency_id="dep-0000000000000000", registry="pypi", status="found", versions=versions,
                                latest_version=latest, retrieved_at=T0, metadata={"yanked_versions": yanked} if yanked else {},
                                reasons=[Reason(rule_id="a2.status.found", outcome="found", explanation="x")])


def test_declared_exact_constraint_and_resolution():
    assert declared_version(dep_for("a==1.0\n"), None).kind == "exact"
    d = declared_version(dep_for("a>=1,<3\n"), reg_found(["0.9", "1.0", "2.0", "2.1rc1", "3.0"]))
    assert d.kind == "constraint" and d.candidates == ("1.0", "2.0", "2.1rc1") and d.resolved == "2.0"
    d = declared_version(dep_for("a\n"), reg_found(["1.0", "2.0"], yanked=["2.0"]))
    assert d.kind == "any" and d.resolved == "1.0"                  # yanked versions are not chosen
    assert declared_version(dep_for('{"dependencies": {"x": "^1.2.0"}}', "package.json"), None).kind == "constraint"
    assert declared_version(dep_for('{"dependencies": {"x": "1.2.0"}}', "package.json"), None).exact == "1.2.0"


@pytest.mark.parametrize("declared,versions,record,expected", [
    ("a==1.2.0\n", None, dict(scope=S.LISTED, version="1.2.0"), "affected"),
    ("a==1.2\n", None, dict(scope=S.LISTED, version="1.2.0"), "affected"),          # PEP 440 equality
    ("a==1.3.0\n", None, dict(scope=S.LISTED, version="1.2.0"), "not_affected"),
    ("a\n", ["1.0", "1.2.0", "2.0"], dict(scope=S.LISTED, version="2.0"), "likely_affected"),
    ("a\n", ["1.0", "1.2.0", "2.0"], dict(scope=S.LISTED, version="1.2.0"), "allowed_not_resolved"),
    ("a>=2\n", ["1.0", "1.2.0", "2.0"], dict(scope=S.LISTED, version="1.2.0"), "not_affected"),
    ("a\n", None, dict(scope=S.LISTED, version="1.2.0"), "undetermined"),
    ("a==1.5\n", None, dict(scope=S.RANGE, rng=">=1.0,<2.0"), "affected"),
    ("a==2.0\n", None, dict(scope=S.RANGE, rng=">=1.0,<2.0"), "not_affected"),
    ("a==2.0rc1\n", None, dict(scope=S.RANGE, rng=">=1.0,<3.0"), "affected"),        # pre-releases count in ranges
    # Since D-060 evidence ranges are OSV intervals in version order, where 2.0rc1 < 2.0 (PEP 440
    # specifier semantics, used before, left 2.0 pre-releases out of "<2.0").
    ("a==2.0rc1\n", None, dict(scope=S.RANGE, rng="<2.0"), "affected"),
    ("a~=1.0\n", ["1.0", "1.9", "2.0"], dict(scope=S.RANGE, rng=">=1.5,<2.0"), "likely_affected"),
    ("a==1.0\n", None, dict(scope=S.ALL), "all_versions"),
])
def test_applicability(declared, versions, record, expected):
    d = declared_version(dep_for(declared), reg_found(versions) if versions else None)
    r = rec(F.VULNERABLE if record["scope"] is S.RANGE else F.MALICIOUS, "pypi", "a", record["scope"],
            version=record.get("version"), rng=record.get("rng"))
    assert applicability(r, d) == expected


def test_npm_ranges_are_undetermined_never_guessed():
    d = declared_version(dep_for('{"dependencies": {"x": "^1.0.0"}}', "package.json"), None)
    assert applicability(rec(F.MALICIOUS, "npm", "x", S.LISTED, version="1.0.1"), d) == "undetermined"


def test_fixed_bounds():
    assert fixed_bounds([">=2.0.0,<2.31.0", "<2.32.0", ">=1.0"]) == ["2.31.0", "2.32.0"]


# --------------------------------------------------------------------------- similarity

@pytest.mark.parametrize("a,b,d", [("requests", "requests", 0), ("reqeusts", "requests", 1), ("request", "requests", 1),
                                   ("requestz", "requests", 1), ("rqeuests", "requests", 1), ("reqsuets", "requests", 2)])
def test_damerau_levenshtein(a, b, d):
    assert damerau_levenshtein(a, b) == d


def test_popular_index():
    idx = PopularIndex([("requests", "e1"), ("numpy", "e2"), ("six", "e3")])
    assert idx.similar("reqeusts") == [("requests", "e1")]
    assert idx.similar("requests") == []               # a popular name is not similar to itself
    assert idx.similar("sx") == [] and "six" not in idx  # short names are skipped
    assert idx.similar("numpyy") == [("numpy", "e2")] and idx.similar("nmupyy") == []


# --------------------------------------------------------------------------- findings

def test_compromised_release_of_popular_package_only_for_that_version():
    s = store_of(rec(F.MALICIOUS, "pypi", "pop-lib", S.LISTED, version="1.2.0"),
                 rec(F.BENIGN_REFERENCE, "pypi", "pop-lib"))
    ans = {("pypi", "pop-lib"): found("pypi", "pop-lib", ["1.1.0", "1.2.0", "1.3.0"])}
    _, _, bad = pipeline([("requirements.txt", "pop-lib==1.2.0\n")], s, ans)
    assert finding(bad.assessments[0], "compromised_version").detail["applicability"] == "affected"
    _, _, ok = pipeline([("requirements.txt", "pop-lib==1.3.0\n")], s, ans)
    a = ok.assessments[0]
    assert "compromised_version" not in kinds(a) and "no_evidence" in kinds(a)
    assert any(r.rule_id == "a3.malicious.version.other_versions_only" for r in a.reasons)


def test_vulnerable_with_fixed_versions_and_advisories():
    s = store_of(rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng=">=1.0,<1.4", rid="GHSA-1"),
                 rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng="<1.2", rid="GHSA-2"),
                 rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng=">=3.0,<3.1", rid="GHSA-3"))
    _, _, rr = pipeline([("requirements.txt", "lib==1.3\n")], s, {("pypi", "lib"): found("pypi", "lib", ["1.3", "1.4"])})
    f = finding(rr.assessments[0], "vulnerable")
    assert f.detail["applicability"] == "affected" and f.detail["advisories"] == ["GHSA-1"] and f.detail["fixed_in_stated"] == ["1.4"]
    assert f.detail["fixed_in_released"] == ["1.4"]
    assert len(f.evidence_ids) == 1


def test_withdrawn_only_is_not_malicious():
    s = store_of(rec(F.WITHDRAWN, "npm", "react"))
    _, _, rr = pipeline([("package.json", '{"dependencies": {"react": "18.0.0"}}')], s,
                        {("npm", "react"): found("npm", "react", ["18.0.0"])})
    assert kinds(rr.assessments[0]) == ["withdrawn_only"]          # evidence-backed, so no 'no_evidence'


def test_typosquat_listed_sets_reference_package():
    s = store_of(rec(F.TYPOSQUAT, "pypi", "reqeusts", target="requests"), rec(F.BENIGN_REFERENCE, "pypi", "requests"))
    _, _, rr = pipeline([("requirements.txt", "reqeusts\n")], s, {("pypi", "reqeusts"): found("pypi", "reqeusts", ["0.1"])})
    a = rr.assessments[0]
    assert "typosquat_listed" in kinds(a) and a.reference_package.name_normalized == "requests"
    assert "name_similar_to_popular" not in kinds(a)    # the listed pair already explains the similarity


def test_typosquat_target_gets_no_typosquat_finding():
    s = store_of(rec(F.TYPOSQUAT, "pypi", "reqeusts", target="requests"))
    _, _, rr = pipeline([("requirements.txt", "requests\n")], s, {("pypi", "requests"): found("pypi", "requests", ["2.0"])})
    assert "typosquat_listed" not in kinds(rr.assessments[0])


def test_nonexistent_only_without_malicious_evidence():
    s = store_of(rec(F.MALICIOUS, "pypi", "removed-bad"))
    ans = {("pypi", "removed-bad"): nf("pypi", "removed-bad"), ("pypi", "made-up-pkg"): nf("pypi", "made-up-pkg")}
    ex, _, rr = pipeline([("requirements.txt", "removed-bad\nmade-up-pkg\n")], s, ans)
    removed, made_up = rr.assessments
    assert "nonexistent" not in kinds(removed) and "malicious_reported" in kinds(removed)
    assert any(r.rule_id == "a3.nonexistent.published_before" for r in removed.reasons)
    assert "nonexistent" in kinds(made_up)


def test_not_found_from_snapshot_after_cutoff_is_unknown_not_nonexistent():
    ans = {("pypi", "made-up-pkg"): nf("pypi", "made-up-pkg")}
    _, _, rr = pipeline([("requirements.txt", "made-up-pkg\n")], store_of(), ans,
                        cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc))
    a = rr.assessments[0]
    assert "nonexistent" not in kinds(a) and "unknown" in kinds(a)


def test_registry_security_hold_finding():
    hold = LookupOutcome(status="security_placeholder", rule_id="a2.status.security_placeholder", explanation="x",
                         retrieved_at=T0, source_url="u", canonical_name="gone",
                         metadata={"removed_versions": {"999.9.9": "2024-12-14T00:00:00+00:00"},
                                   "placeholder_published": "2025-01-14T00:00:00+00:00"})
    _, _, rr = pipeline([("package.json", '{"dependencies": {"gone": "999.9.9"}}')], store_of(), {("npm", "gone"): hold})
    a = rr.assessments[0]
    f = finding(a, "registry_security_hold")
    assert f.detail["removed_versions"] == {"999.9.9": "2024-12-14T00:00:00+00:00"}
    assert a.baseline_v1.risk_level == "low"


def test_name_similarity_to_popular():
    s = store_of(rec(F.BENIGN_REFERENCE, "pypi", "requests", pub=date(2026, 11, 1)))
    _, _, rr = pipeline([("requirements.txt", "requestz\n")], s, {("pypi", "requestz"): found("pypi", "requestz", ["1.0"])})
    a = rr.assessments[0]
    f = finding(a, "name_similar_to_popular")
    assert f.detail["similar_to"] == ["requests"] and a.reference_package.name_normalized == "requests"
    assert "not a malicious label" in f.reasons[0].explanation


def test_similarity_uses_only_lists_known_before_cutoff():
    s = store_of(rec(F.BENIGN_REFERENCE, "pypi", "requests", pub=date(2026, 11, 1)))
    _, _, rr = pipeline([("requirements.txt", "requestz\n")], s, {("pypi", "requestz"): found("pypi", "requestz", ["1.0"])},
                        cutoff=datetime(2026, 6, 1, tzinfo=timezone.utc))
    a = rr.assessments[0]
    assert "name_similar_to_popular" not in kinds(a) and any(r.rule_id == "a3.similarity.no_list" for r in a.reasons)


def test_unresolved_and_lookup_error_are_unknown():
    err = LookupOutcome(status="lookup_error", rule_id="a2.status.lookup_error", explanation="x", retrieved_at=T0,
                        source_url="u", error="timeout")
    _, _, rr = pipeline([("requirements.txt", "flaky\n"), ("app.py", "import made_up_zz\n")], store_of(),
                        {("pypi", "flaky"): err})
    flaky, unresolved = rr.assessments
    assert kinds(flaky) == ["unknown", "no_evidence"] and kinds(unresolved) == ["unknown"]
    assert unresolved.baseline_v1.risk_level == "unknown"


def test_every_assessment_has_reasons_and_cites_only_store_records():
    s = store_of(rec(F.MALICIOUS, "pypi", "bad"), rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng="<2"))
    _, _, rr = pipeline([("requirements.txt", "bad\nlib==1\nother\n")], s,
                        {("pypi", n): found("pypi", n, ["1"]) for n in ("bad", "lib", "other")})
    for a in rr.assessments:
        assert a.reasons[0].rule_id == "a3.v1.baseline" and a.reasons[-1].rule_id == "a3.summary"
        for f in a.findings:
            assert f.reasons and all(s.get(e) is not None for e in f.evidence_ids)


# --------------------------------------------------------------------------- failure states

def test_store_mismatch_disables_evidence_findings(tmp_path):
    import shutil
    fix = ROOT / "tests/fixtures/agent2/evidence/v1"
    a_store = EvidenceStore.load(fix)
    ex = extract_files("p", [UploadedFile("requirements.txt", b"compromised-lib==1.2.0\n")], clock=lambda: T0)
    rg = verify(ex, mode="off", client=None, evidence_store=a_store, clock=lambda: T0)
    other = tmp_path / "v1"
    shutil.copytree(fix, other)
    shutil.rmtree(other / "typosquat" / "yctt_pairs")
    rr = assess(ex, rg, evidence_store=EvidenceStore.load(other), clock=lambda: T0)
    assert [f.code for f in rr.failures] == ["a3.evidence.store_mismatch"]
    a = rr.assessments[0]
    assert "compromised_version" not in kinds(a) and any(r.rule_id == "a3.evidence.not_used" for r in a.reasons)


def test_project_mismatch_and_missing_store():
    ex = extract_files("p", [UploadedFile("requirements.txt", b"a\n")], clock=lambda: T0)
    rg = verify(ex, mode="off", client=None, evidence_store=None, clock=lambda: T0)
    other = extract_files("q", [UploadedFile("requirements.txt", b"a\n")], clock=lambda: T0)
    rr = assess(other, rg, evidence_store=None, clock=lambda: T0)
    assert {f.code for f in rr.failures} == {"a3.input.project_mismatch", "a3.evidence.store_missing",
                                             "a3.input.missing_registry_result"}
    assert kinds(rr.assessments[0]) == ["unknown"]


def test_unpinned_package_with_only_old_advisories_gets_no_vulnerable_finding():
    """RUN-002: popular packages have old advisories; only the version that would be installed counts."""
    s = store_of(rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng="<2.0", rid="GHSA-old"))
    _, _, rr = pipeline([("requirements.txt", "lib\nlib==1.5\n")], s,
                        {("pypi", "lib"): found("pypi", "lib", ["1.5", "2.0", "2.1"])})
    unpinned, pinned = rr.assessments
    assert "vulnerable" not in kinds(unpinned) and "no_evidence" in kinds(unpinned)
    why = next(r for r in unpinned.reasons if r.rule_id == "a3.vulnerable.installed_version_not_affected")
    assert why.inputs["older_versions_affected"] == 1 and "2.1" in why.explanation
    assert finding(pinned, "vulnerable").detail["applicability"] == "affected"


def test_possible_when_installed_version_is_unknown():
    # All allowed releases yanked: pip installs the highest yanked one (PEP 592, D-057).
    d = declared_version(dep_for("a\n"), reg_found(["1.0", "1.2.0"], yanked=["1.0", "1.2.0"]))
    assert d.resolved == "1.2.0"
    assert applicability(rec(F.MALICIOUS, "pypi", "a", S.LISTED, version="1.2.0"), d) == "likely_affected"
    # 'possible' remains for an allowed set whose installed version is unknown.
    from multi_agentic_security.agents.agent3_risk.versions import Declared
    d2 = Declared("any", "pypi", candidates=("1.0", "1.2.0"), resolved=None, allow_spec="")
    assert applicability(rec(F.MALICIOUS, "pypi", "a", S.LISTED, version="1.2.0"), d2) == "possible"
