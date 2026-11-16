"""Regression tests for the Agent 3 review (scorer review 1). Each test names its finding.

In-memory evidence stores from hand-written records; registry answers from fakes.
No network, no dataset files.
"""

import socket
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
from multi_agentic_security.agents.agent2_registry import LookupOutcome, verify
from multi_agentic_security.agents.agent3_risk import assess
from multi_agentic_security.agents.agent3_risk.npm_semver import satisfies
from multi_agentic_security.contracts.evidence import EvidenceRecord, LabelFamily as F, Provenance, VersionScope as S
from multi_agentic_security.contracts.pipeline import RiskResult
from multi_agentic_security.evidence_store import EvidenceStore, TableInfo

T0 = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def rec(fam, eco, name, scope=S.ALL, *, version=None, rng=None, pub=date(2025, 1, 1), target=None, rid=None):
    return EvidenceRecord(
        family=fam, ecosystem=eco, name_raw=name, name_normalized=name, version_scope=scope, version=version,
        version_range=rng, published=pub, target_name_raw=target, target_name_normalized=target,
        provenance=Provenance(source_dataset="src-a", source_version="t1", source_record_id=rid or f"{name}:{version}:{rng}",
                              source_file="t.json", source_file_sha256="0" * 64, license="test", retrieved_at=T0))


def store_of(*records, missing=()):
    tables = [TableInfo(key="mem/table", loaded=True, records=len(records), records_sha256="a" * 64)]
    tables += [TableInfo(key=m, loaded=False) for m in missing]
    return EvidenceStore(Path("mem"), tables, [], [("mem/table", r) for r in records])


class Client:
    mode = "snapshot"

    def __init__(self, answers):
        self.answers = answers

    def supports(self, eco):
        return True

    def lookup(self, eco, name):
        return self.answers.get((eco, name))


def found(name, versions, *, times=None, latest=None, retrieved=T0, yanked=None):
    times = times or {v: datetime(2024, 1, 1 + i, tzinfo=timezone.utc) for i, v in enumerate(versions)}
    return LookupOutcome(status="found", rule_id="a2.status.found", explanation="x", retrieved_at=retrieved,
                         source_url="u", canonical_name=name, versions=list(versions), upload_times=times,
                         latest_version=latest or (versions[-1] if versions else None),
                         metadata={"yanked_versions": yanked} if yanked else {})


def nf():
    return LookupOutcome(status="not_found", rule_id="a2.status.not_found", explanation="x", retrieved_at=T0, source_url="u")


def run(files, a2_store, a3_store, answers, cutoff=None):
    ex = extract_files("p", [UploadedFile(p, d.encode()) for p, d in files], clock=lambda: T0)
    rg = verify(ex, mode="snapshot", client=Client(answers), evidence_store=a2_store, evidence_cutoff=cutoff,
                clock=lambda: T0)
    rr = assess(ex, rg, evidence_store=a3_store, clock=lambda: T0)
    RiskResult.model_validate_json(rr.model_dump_json())
    return rg, rr


def kinds(a):
    return [f.finding for f in a.findings]


def rules(a):
    return [r.rule_id for r in a.reasons] + [r.rule_id for f in a.findings for r in f.reasons]


# --------------------------------------------------------------------------- H1

def test_h1_no_store_never_gives_nonexistent():
    _, rr = run([("requirements.txt", "evilpkg\n")], None, None, {("pypi", "evilpkg"): nf()})
    a = rr.assessments[0]
    assert "nonexistent" not in kinds(a) and "unknown" in kinds(a)


def test_h1_agent2_without_store_disables_evidence_in_agent3():
    s = store_of(rec(F.MALICIOUS, "pypi", "evilpkg"))
    _, rr = run([("requirements.txt", "evilpkg\n")], None, s, {("pypi", "evilpkg"): nf()})
    a = rr.assessments[0]
    assert "a3.evidence.not_looked_up_by_agent2" in [f.code for f in rr.failures]
    assert "nonexistent" not in kinds(a) and "no_evidence" not in kinds(a)


# --------------------------------------------------------------------------- H2

def test_h2_package_without_version_before_cutoff_is_unknown():
    ans = {("pypi", "slopname"): found("slopname", ["0.1"], times={"0.1": datetime(2025, 3, 1, tzinfo=timezone.utc)})}
    rg, rr = run([("requirements.txt", "slopname\n")], store_of(), store_of(), ans,
                 cutoff=datetime(2024, 6, 1, tzinfo=timezone.utc))
    assert rg.results[0].versions == [] and rg.results[0].retrieved_after_cutoff is True
    a = rr.assessments[0]
    assert "unknown" in kinds(a) and "a3.cutoff.no_version_before_cutoff" in rules(a)


# --------------------------------------------------------------------------- M1, M2

def test_m1_reported_release_missing_from_registry_is_undetermined():
    s = store_of(rec(F.MALICIOUS, "pypi", "ultra", S.LISTED, version="8.3.41"))
    _, rr = run([("requirements.txt", "ultra>=8.3\n")], s, s,
                {("pypi", "ultra"): found("ultra", ["8.3.0", "8.3.40", "8.3.42"])})
    f = next(f for f in rr.assessments[0].findings if f.finding == "compromised_version")
    assert f.detail["applicability"] == "undetermined"


def test_m2_empty_version_list_is_undetermined():
    s = store_of(rec(F.MALICIOUS, "pypi", "empt", S.LISTED, version="1.0"))
    _, rr = run([("requirements.txt", "empt\n")], s, s, {("pypi", "empt"): found("empt", [])})
    f = next(f for f in rr.assessments[0].findings if f.finding == "compromised_version")
    assert f.detail["applicability"] == "undetermined"


# --------------------------------------------------------------------------- M3

def test_m3_possible_text_does_not_claim_the_installed_version():
    s = store_of(rec(F.MALICIOUS, "pypi", "yk", S.LISTED, version="1.2.0"))
    _, rr = run([("requirements.txt", "yk\n")], s, s,
                {("pypi", "yk"): found("yk", ["1.0", "1.2.0"], yanked=["1.0", "1.2.0"])})
    f = next(f for f in rr.assessments[0].findings if f.finding == "compromised_version")
    assert f.detail["applicability"] == "possible"
    assert "unknown" in f.reasons[0].explanation and "not the one that would be installed" not in f.reasons[0].explanation


# --------------------------------------------------------------------------- M4 (npm ranges)

@pytest.mark.parametrize("version,rng,expected", [
    ("4.1.2", "^4.1.2", True), ("5.6.1", "^4.1.2", False), ("0.2.5", "^0.2.3", True), ("0.3.0", "^0.2.3", False),
    ("0.0.4", "^0.0.3", False), ("1.2.9", "~1.2.3", True), ("1.3.0", "~1.2.3", False), ("2.0.0", "1.x", False),
    ("1.0.0-beta", "*", False), ("1.2.4-beta.1", ">=1.2.4-beta.0", True), ("1.2.5-beta", ">=1.2.4-beta.0", False),
    ("2.3.9", "1.2.3 - 2.3", True), ("2.4.0", "1.2.3 - 2.3", False), ("1.3.0", "<1.2 || >=1.4", False),
    ("1.2.9", "<=1.2", True), ("1.2.9", ">1.2", False), ("1.0.0", ">= 1.0.0 < 2", True),
    ("1.0.0", "latest", None), ("1.0.0", "github:a/b", None),
])
def test_m4_npm_semver(version, rng, expected):
    assert satisfies(version, rng) is expected


def test_m4_npm_range_excludes_compromised_release_outside_it():
    s = store_of(rec(F.MALICIOUS, "npm", "chalk", S.LISTED, version="5.6.1"))
    ans = {("npm", "chalk"): found("chalk", ["4.1.2", "5.6.0", "5.6.1"], latest="5.6.1")}
    _, rr = run([("package.json", '{"dependencies": {"chalk": "^4.1.2"}}')], s, s, ans)
    a = rr.assessments[0]
    assert "compromised_version" not in kinds(a) and "no_evidence" in kinds(a)
    _, rr = run([("package.json", '{"dependencies": {"chalk": "^5.0.0"}}')], s, s, ans)
    f = next(f for f in rr.assessments[0].findings if f.finding == "compromised_version")
    assert f.detail["applicability"] == "likely_affected"        # npm installs the latest tag 5.6.1


# --------------------------------------------------------------------------- M5

def test_m5_incomplete_store_gives_no_no_evidence_and_no_nonexistent():
    s = store_of(missing=["vulnerable/osv_pypi_a2"])
    _, rr = run([("requirements.txt", "lib==1.0\nmadeup\n")], s, s,
                {("pypi", "lib"): found("lib", ["1.0"]), ("pypi", "madeup"): nf()})
    lib, madeup = rr.assessments
    assert "a3.evidence.store_incomplete" in [f.code for f in rr.failures]
    assert "no_evidence" not in kinds(lib) and "a3.evidence.incomplete" in rules(lib)
    assert "nonexistent" not in kinds(madeup) and "unknown" in kinds(madeup)


# --------------------------------------------------------------------------- M6

@pytest.mark.parametrize("record", [rec(F.TYPOSQUAT, "pypi", "reqeusts", target="requests"),
                                    rec(F.WITHDRAWN, "pypi", "reqeusts"),
                                    rec(F.VULNERABLE, "pypi", "reqeusts", S.RANGE, rng="<1")])
def test_m6_any_evidence_of_publication_blocks_nonexistent(record):
    s = store_of(record)
    _, rr = run([("requirements.txt", "reqeusts\n")], s, s, {("pypi", "reqeusts"): nf()})
    a = rr.assessments[0]
    assert "nonexistent" not in kinds(a) and "a3.nonexistent.published_before" in rules(a)


# --------------------------------------------------------------------------- M7

def test_m7_fixed_bound_not_released_at_cutoff_is_separated():
    s = store_of(rec(F.VULNERABLE, "pypi", "lib", S.RANGE, rng="<2.3", pub=date(2024, 1, 1)))
    times = {"2.2": datetime(2024, 1, 1, tzinfo=timezone.utc), "2.3": datetime(2024, 9, 1, tzinfo=timezone.utc)}
    _, rr = run([("requirements.txt", "lib==2.2\n")], s, s, {("pypi", "lib"): found("lib", ["2.2", "2.3"], times=times)},
                cutoff=datetime(2024, 6, 1, tzinfo=timezone.utc))
    f = next(f for f in rr.assessments[0].findings if f.finding == "vulnerable")
    assert f.detail["fixed_in_stated"] == ["2.3"] and f.detail["fixed_in_released"] == []
    assert "Not a safe target by itself" in f.detail["fixed_in_note"]


# --------------------------------------------------------------------------- L1, L2, L3, L4

def test_l1_l2_reason_texts():
    s = store_of(rec(F.MALICIOUS, "pypi", "pr", S.LISTED, version="2.0b1"),
                 rec(F.MALICIOUS, "pypi", "oth", S.LISTED, version="0.5"))
    _, rr = run([("requirements.txt", "pr>=1.0\noth>=1\n")], s, s,
                {("pypi", "pr"): found("pr", ["1.0", "2.0b1"]), ("pypi", "oth"): found("oth", ["0.5", "1.0"])})
    pr, oth = rr.assessments
    older = next(r for r in pr.reasons if r.rule_id.endswith("installed_version_not_affected"))
    assert "pre-release" in older.explanation
    other = next(r for r in oth.reasons if r.rule_id.endswith("other_versions_only"))
    assert "declared >=1" in other.explanation and "would install 1.0" in other.explanation


def test_l3_no_similarity_from_a_rejected_store():
    s2 = store_of(rec(F.BENIGN_REFERENCE, "pypi", "requests"))
    s3 = EvidenceStore(Path("mem"), [TableInfo(key="mem/table", loaded=True, records=1, records_sha256="b" * 64)], [],
                       [("mem/table", rec(F.BENIGN_REFERENCE, "pypi", "requests"))])
    _, rr = run([("requirements.txt", "requestz\n")], s2, s3, {("pypi", "requestz"): found("requestz", ["1"])})
    a = rr.assessments[0]
    assert "a3.evidence.store_mismatch" in [f.code for f in rr.failures]
    assert "name_similar_to_popular" not in kinds(a) and "a3.similarity.not_checked" in rules(a)


def test_l4_pin_not_in_registry_is_reported():
    _, rr = run([("requirements.txt", "lib==9.9\n")], store_of(), store_of(), {("pypi", "lib"): found("lib", ["1.0"])})
    assert "a3.version.pin_not_in_registry" in rules(rr.assessments[0])


# --------------------------------------------------------------------------- L7

def test_l7_structured_after_cutoff_flag_drives_the_guard():
    ans = {("pypi", "madeup"): nf()}
    rg, rr = run([("requirements.txt", "madeup\n")], store_of(), store_of(), ans,
                 cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert rg.results[0].retrieved_after_cutoff is True
    assert "a3.nonexistent.not_historical" in rules(rr.assessments[0])
    rg, rr = run([("requirements.txt", "madeup\n")], store_of(), store_of(), ans)
    assert rg.results[0].retrieved_after_cutoff is None and "nonexistent" in kinds(rr.assessments[0])
