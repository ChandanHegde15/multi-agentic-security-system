"""Tests for the pipeline contracts (pipeline/0.1). Inputs are hand-written fixtures."""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from multi_agentic_security.contracts import pipeline as c

T0 = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(seconds=2)


def reason(rule="r.test", outcome="ok"):
    return c.Reason(rule_id=rule, outcome=outcome, explanation="because", inputs={"x": 1})


def header(**kw):
    return dict(project_id="proj-1", stage_version="0.1", started_at=T0, finished_at=T1, **kw)


def dep(name="Flask_Cors", line=3, **kw):
    decl = f"{name}==4.0.0"
    values = dict(
        dependency_id=c.make_dependency_id("requirements.txt", line, "pypi", decl),
        ecosystem="pypi",
        package=c.PackageRef.of("pypi", name),
        original_declaration=decl,
        version_constraint_raw="==4.0.0",
        version_constraint_normalized="==4.0.0",
        dependency_type="runtime",
        source_kind="requirements_txt",
        source_path="requirements.txt",
        source_line=line,
        extraction_status="ok",
        reasons=[reason("a1.requirements.parsed")],
    )
    values.update(kw)
    return c.DependencyRecord(**values)


# ---- shared

def test_package_ref_normalization_enforced():
    assert c.PackageRef.of("pypi", "Flask_Cors").name_normalized == "flask-cors"
    with pytest.raises(ValidationError):
        c.PackageRef(ecosystem="pypi", name_raw="Flask_Cors", name_normalized="Flask_Cors")


def test_unknown_fields_rejected():
    with pytest.raises(ValidationError):
        c.Reason(rule_id="r", outcome="o", explanation="e", surprise=1)


def test_dependency_id_stable_and_path_separator_independent():
    a = c.make_dependency_id("sub\\requirements.txt", 3, "pypi", "x==1")
    b = c.make_dependency_id("sub/requirements.txt", 3, "pypi", " x==1 ")
    assert a == b and a.startswith("dep-") and len(a) == 20
    assert a != c.make_dependency_id("sub/requirements.txt", 4, "pypi", "x==1")


def test_header_requires_aware_ordered_times():
    with pytest.raises(ValidationError):
        c.ExtractionResult(**header(sources=[], dependencies=[]) | {"finished_at": T0 - timedelta(seconds=1)})
    with pytest.raises(ValidationError):
        c.ExtractionResult(**header(sources=[], dependencies=[]) | {"started_at": T0.replace(tzinfo=None)})


# ---- Agent 1

def test_dependency_record_requires_reason():
    with pytest.raises(ValidationError):
        dep(reasons=[])


def test_unresolved_import_without_package():
    d = c.DependencyRecord(
        dependency_id=c.make_dependency_id("gen.py", 1, None, "import cv2"),
        ecosystem=None, package=None, original_declaration="import cv2",
        dependency_type="import", source_kind="python_code", source_path="gen.py", source_line=1,
        extraction_status="unresolved", reasons=[reason("a1.import.unmapped", "unresolved")],
    )
    assert d.package is None
    with pytest.raises(ValidationError):
        c.DependencyRecord(**d.model_dump() | {"extraction_status": "ok"})


def test_warning_status_needs_warning_and_ecosystem_must_match():
    with pytest.raises(ValidationError):
        dep(extraction_status="warning")
    with pytest.raises(ValidationError):
        dep(ecosystem="npm")


def test_extraction_result_unique_ids():
    d = dep()
    with pytest.raises(ValidationError):
        c.ExtractionResult(**header(sources=[], dependencies=[d, d]))


# ---- Agent 2

def rv(**kw):
    values = dict(dependency_id="dep-0000000000000001", registry="pypi", status="found",
                  versions=["1.0"], retrieved_at=T0, reasons=[reason("a2.found")])
    values.update(kw)
    return c.RegistryVerification(**values)


def test_registry_lookup_error_never_without_message_or_time():
    with pytest.raises(ValidationError):
        rv(status="lookup_error", versions=None)
    with pytest.raises(ValidationError):
        rv(status="not_found", versions=None, retrieved_at=None)
    assert rv(status="lookup_error", versions=None, error="timeout").status == "lookup_error"


def test_versions_only_when_found_and_not_checked_needs_no_time():
    with pytest.raises(ValidationError):
        rv(status="not_found")
    assert rv(status="not_checked", versions=None, retrieved_at=None).status == "not_checked"


# ---- Agent 3

def test_evidence_backed_findings_need_evidence():
    with pytest.raises(ValidationError):
        c.Finding(finding="malicious_reported", reasons=[reason()])
    assert c.Finding(finding="nonexistent", reasons=[reason()]).finding == "nonexistent"
    assert c.Finding(finding="vulnerable", evidence_ids=["ev-vulnerable-1"], reasons=[reason()]).evidence_ids


def test_baseline_score_bounds():
    with pytest.raises(ValidationError):
        c.BaselineV1Score(registry_status_v1="not_found", risk_score=120, risk_level="critical", signals=[], catalogue_version="v1")


# ---- Agent 4

def rec(**kw):
    values = dict(dependency_id="dep-0000000000000001", action="keep", backend="rules", reasons=[reason("a4.rules.keep")])
    values.update(kw)
    return c.Recommendation(**values)


def test_target_rules():
    tgt = c.Target(package=c.PackageRef.of("pypi", "requests"), version="2.32.3")
    with pytest.raises(ValidationError):
        rec(action="replace")
    with pytest.raises(ValidationError):
        rec(action="keep", target=tgt)
    with pytest.raises(ValidationError):
        rec(action="upgrade", target=c.Target(package=tgt.package))
    assert rec(action="upgrade", target=tgt).target.version == "2.32.3"


def test_llm_needs_model_and_failed_generation_abstains():
    with pytest.raises(ValidationError):
        rec(backend="llm")
    with pytest.raises(ValidationError):
        rec(backend="llm", model="m", generation_status="llm_timeout", action="keep")
    assert rec(backend="llm", model="m", generation_status="llm_timeout", action="abstain").action == "abstain"


def test_action_set_is_closed():
    with pytest.raises(ValidationError):
        rec(action="monitor")


# ---- Agent 5

def chk(name, result, required=True):
    return c.CheckResult(check=name, result=result, required=required)


@pytest.mark.parametrize(
    "checks, expected",
    [
        ([chk("schema", "pass"), chk("target_exists", "not_applicable")], "accept"),
        ([chk("schema", "pass"), chk("target_exists", "fail")], "reject"),
        ([chk("schema", "pass"), chk("target_exists", "not_run")], "abstain"),
        ([chk("schema", "pass"), chk("target_exists", "not_run", required=False)], "accept"),
        ([chk("target_exists", "not_run"), chk("target_not_malicious", "fail")], "reject"),
        ([], "abstain"),
    ],
)
def test_verdict_rule(checks, expected):
    assert c.verdict_from_checks(checks) == expected


def test_verdict_must_match_checks_and_label():
    checks = [chk("schema", "pass"), chk("target_exists", "not_run")]
    with pytest.raises(ValidationError):
        c.RecommendationVerification(dependency_id="d", verdict="accept", checks=checks, verifier_version="0.1", reasons=[reason()])
    v = c.RecommendationVerification(dependency_id="d", verdict="abstain", checks=checks, verifier_version="0.1", reasons=[reason()])
    assert v.label == "needs review"


def test_duplicate_checks_rejected():
    with pytest.raises(ValidationError):
        c.RecommendationVerification(dependency_id="d", verdict="accept", checks=[chk("schema", "pass")] * 2,
                                     verifier_version="0.1", reasons=[reason()])


# ---- report

def summary():
    return c.PipelineSummary(total_dependencies=1, by_ecosystem={"pypi": 1}, registry_status_counts={},
                             finding_counts={}, baseline_level_counts={}, action_counts={}, verdict_counts={}, failures=0)


def test_report_trace_rejects_unknown_ids_and_foreign_projects():
    d = dep()
    ex = c.ExtractionResult(**header(sources=[], dependencies=[d]))
    good = c.RegistryResult(**header(registry_mode="off", results=[rv(dependency_id=d.dependency_id, status="not_checked", versions=None, retrieved_at=None)]))
    c.PipelineReport(project_id="proj-1", created_at=T1, extraction=ex, registry=good, summary=summary())
    bad = c.RegistryResult(**header(registry_mode="off", results=[rv(status="not_checked", versions=None, retrieved_at=None)]))
    with pytest.raises(ValidationError):
        c.PipelineReport(project_id="proj-1", created_at=T1, extraction=ex, registry=bad, summary=summary())
    with pytest.raises(ValidationError):
        c.PipelineReport(project_id="other", created_at=T1, extraction=ex, summary=summary())


def test_json_schemas_export():
    schemas = c.json_schemas()
    assert set(schemas) == set(c.ALL_CONTRACTS)
    assert "reasons" in schemas["ExtractionResult"]["$defs"]["DependencyRecord"]["properties"]
