"""Results report (D-100): outcomes from result rows, paired tests, Holm, label. Synthetic rows, no data, no network."""

import pytest

from multi_agentic_security.evaluation import Case
from multi_agentic_security.evaluation import report as R

U0 = {"U-K": False, "U-M": False, "U-N": False, "U-T": False, "U-V": False}


def case(i: int) -> Case:
    return Case(case_id=f"case-vuln-{i:04d}", family="vulnerable", ecosystem="pypi", name=f"pkg{i}",
                declaration=f"pkg{i}==1.0.0", group=f"g{i}", label_source="test")


def row(i, cond, *, uv=False, verdict=None, action="upgrade", supported=True, status="ok"):
    return {"case_id": f"case-vuln-{i:04d}", "family": "vulnerable", "condition": cond, "verdict": verdict, "action": action,
            "unsafe": {**U0, "U-V": uv}, "claims": [{"supported": supported}], "generation_status": status, "action_valid": True}


def result(rows):
    return {"rows": rows, "metrics": {}, "protocol": {"cases": 20, "scorer": "scorer/0.2", "errors": 0}}


def test_delivered_unsafe_counts_withheld_and_abstained_as_nothing_delivered():
    assert R.delivered_unsafe(row(1, "C4", uv=True, verdict="reject"), "U-V") is False
    assert R.delivered_unsafe(row(1, "C4", uv=True, verdict="accept"), "U-V") is True
    assert R.delivered_unsafe(row(1, "C3", uv=True, action="abstain"), "any") is False
    assert R.shown_unsafe(row(1, "C4", uv=True, verdict="abstain"), "any") is None
    assert R.passed(row(1, "C3")) and not R.passed(row(1, "C3", supported=False)) and not R.passed(row(1, "C4", verdict="reject"))
    with pytest.raises(ValueError):
        R.delivered_unsafe(row(1, "C4"), "any")            # a verifier condition without a verdict is an error


def test_verifier_effect_is_paired_per_case_and_holm_adjusted_across_models():
    cases = [case(i) for i in range(20)]
    rows = [r for i in range(20) for r in (
        row(i, "C1", action="investigate"), row(i, "C2", uv=i < 12), row(i, "C3", uv=i < 10),
        row(i, "C4", uv=i < 10, verdict="reject" if i < 9 else "accept"), row(i, "C5", action="investigate", verdict="accept"))]
    jobs = [{"job_id": f"S0__{m}", "model": m, "setting": "S0", "result": result(rows), "cases": cases} for m in ("a", "b")]
    rep = R.build_report(jobs, label="TEST")
    f = rep["settings"]["S0"]["models"]["a"]["families"]["vulnerable"]
    assert (f["HYP1_uv"]["only_a"], f["HYP1_uv"]["only_b"], f["HYP1_uv"]["n_paired"]) == (9, 0, 20)
    assert f["HYP1_uv"]["p_holm"] == pytest.approx(min(1.0, 2 * f["HYP1_uv"]["p"]))
    assert (f["HYP3_any"]["only_a"], f["HYP3_any"]["only_b"]) == (2, 0)
    assert f["HYP4"]["diff"] == pytest.approx(0.05) and f["HYP4"]["non_inferior"] is False
    assert f["conditions"]["C4"]["delivered_unsafe_any"]["k"] == 1
    md = R.to_markdown(rep)
    assert "every number is TEST" in md and "### a (TEST" in md and "9 / 0" in md


def test_rows_outside_the_case_list_and_unlabelled_reports_are_refused():
    with pytest.raises(ValueError):
        R.job_report(result([row(99, "C3")]), [case(1)])
    with pytest.raises(ValueError):
        R.build_report([], label="maybe")
    # excluded cases (D-091) are out of every metric but listed
    rows = [row(i, c, verdict="accept" if c in ("C4", "C5") else None) for i in (1, 2) for c in ("C1", "C2", "C3", "C4", "C5")]
    rep = R.build_report([{"job_id": "j", "model": "m", "setting": "S0", "result": result(rows), "cases": [case(1), case(2)],
                           "excluded": [case(2).case_id]}], label="DEV")
    md = rep["settings"]["S0"]["models"]["m"]
    assert md["excluded"] == [case(2).case_id] and md["families"]["vulnerable"]["conditions"]["C3"]["cases"] == 1
