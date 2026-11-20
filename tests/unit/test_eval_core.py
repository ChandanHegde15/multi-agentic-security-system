"""Evaluation core (D-067): statistics against hand-computed values, cases and splits, the scorer on
hand-written known answers, metrics aggregation and the LLM call planner. No network, no data files."""

import ast
import json
import math
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.contracts.evidence import LabelFamily as F, VersionScope as S
from multi_agentic_security.contracts.pipeline import Claim, PackageRef, Recommendation, Reason, Target
from multi_agentic_security.evaluation import (
    Case, Limits, Row, ScoreContext, aggregate, assign_groups, paired_binary, plan_llm_calls, read_cases, score,
    split_cases, split_of, unsafe_outcome, vulnerable_cases_from_pins, write_cases,
)
from multi_agentic_security.evaluation import stats
from multi_agentic_security.agents.agent2_registry import LookupOutcome

from test_agent3_review import T0, Client, found, nf, rec, store_of

EVAL_DIR = Path(__file__).resolve().parents[2] / "src" / "multi_agentic_security" / "evaluation"
CUT = datetime(2025, 6, 1, tzinfo=timezone.utc)
WHY = [Reason(rule_id="a4.test", outcome="x", explanation="hand-written")]


# --------------------------------------------------------------------------- statistics (hand-computed)

def test_wilson_known_values():
    p, lo, hi = stats.wilson(5, 10)
    assert p == 0.5 and lo == pytest.approx(0.2366, abs=1e-3) and hi == pytest.approx(0.7634, abs=1e-3)
    assert stats.wilson(0, 10)[1] == pytest.approx(0.0, abs=1e-9) and stats.wilson(10, 10)[2] == pytest.approx(1.0, abs=1e-9)
    assert stats.wilson(0, 0) == (None, None, None)


def test_mcnemar_exact_known_values():
    assert stats.mcnemar_exact(0, 5) == pytest.approx(0.0625)       # 2 * (1/32)
    assert stats.mcnemar_exact(3, 3) == 1.0
    assert stats.mcnemar_exact(0, 0) == 1.0
    assert stats.mcnemar_exact(1, 9) == pytest.approx(2 * (1 + 10) / 1024)


def test_holm_is_monotone_and_capped():
    adj = stats.holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert adj == {"a": pytest.approx(0.03), "c": pytest.approx(0.06), "b": pytest.approx(0.06)}
    assert stats.holm({"x": 0.9})["x"] == 0.9 and stats.holm({"x": 0.6, "y": 0.7})["x"] == 1.0


def test_kappa():
    assert stats.cohen_kappa([1, 1, 0, 0], [1, 1, 0, 0]) == 1.0
    assert stats.cohen_kappa([1, 0, 1, 0], [0, 1, 0, 1]) == -1.0
    assert stats.cohen_kappa([1, 1, 0, 0], [1, 0, 0, 1]) == 0.0
    assert stats.cohen_kappa([], []) is None


def test_bootstrap_is_deterministic_and_clusters_widen_the_interval():
    values = [1.0] * 10 + [0.0] * 10
    independent = [str(i) for i in range(20)]
    clustered = ["a"] * 10 + ["b"] * 10                 # two clusters: same mean, far less information
    p1, lo1, hi1 = stats.bootstrap_ci(values, independent, n_boot=500)
    p2, lo2, hi2 = stats.bootstrap_ci(values, clustered, n_boot=500)
    assert p1 == p2 == 0.5 and stats.bootstrap_ci(values, independent, n_boot=500) == (p1, lo1, hi1)
    assert (hi2 - lo2) > (hi1 - lo1)
    assert stats.bootstrap_ci([], [])[0] is None and stats.bootstrap_ci([1.0], ["g"]) == (1.0, None, None)
    with pytest.raises(ValueError):
        stats.bootstrap_ci([1.0], [])


def test_paired_diff_and_non_inferiority():
    a, b = [1.0, 0.0, 0.0, 0.0] * 5, [1.0, 1.0, 0.0, 0.0] * 5
    d, lo, hi = stats.paired_diff_ci(a, b, [str(i) for i in range(20)], n_boot=500)
    assert d == pytest.approx(-0.25) and hi < 0
    assert stats.non_inferior(0.04, 0.05) is True and stats.non_inferior(0.06, 0.05) is False
    assert stats.non_inferior(None, 0.05) is None


# --------------------------------------------------------------------------- cases and splits

def mk(name, family="vulnerable", decl=None, repos=(), target=None, eco="pypi"):
    d = decl or f"{name}==1.0"
    return Case(case_id=f"case-{name}", family=family, ecosystem=eco, name=name, declaration=d, group=name,
                label_source="test", repos=tuple(repos), expected_target=target)


def test_split_is_a_pure_function_of_group_and_seed():
    assert split_of("requests") == split_of("requests") and split_of("requests", seed=1) in ("dev", "test")
    sides = {split_of(f"g{i}") for i in range(50)}
    assert sides == {"dev", "test"}
    frac = sum(split_of(f"g{i}") == "test" for i in range(2000)) / 2000
    assert 0.45 < frac < 0.55


def test_groups_merge_by_package_repository_and_target():
    cases = assign_groups([mk("a", repos=["r1"]), mk("b", repos=["r1"]), mk("c", repos=["r2"]),
                           mk("d", family="typosquat", target="c"), mk("lone")])
    g = {c.name: c.group for c in cases}
    assert g["a"] == g["b"] and g["c"] == g["d"] and len({g["a"], g["c"], g["lone"]}) == 3
    parts = split_cases(cases)
    for side in parts.values():
        assert {c.group for c in side}.isdisjoint({c.group for o in parts.values() if o is not side for c in o})
    assert sum(len(v) for v in parts.values()) == 5


def test_cases_roundtrip_and_refuse_overwrite(tmp_path):
    cases = [mk("b"), mk("a", repos=["r"])]
    h = write_cases(tmp_path / "cases.jsonl", cases)
    assert [c.name for c in read_cases(tmp_path / "cases.jsonl")] == ["a", "b"] and len(h) == 64
    with pytest.raises(FileExistsError):
        write_cases(tmp_path / "cases.jsonl", cases)
    with pytest.raises(ValueError):
        Case(case_id="x", family="nonsense", ecosystem="pypi", name="a", declaration="a", group="a", label_source="t")


def test_pinned_version_and_files_for_both_ecosystems():
    assert mk("web", decl="web==2.1").pinned_version == "2.1" and mk("web", decl="web>=2").pinned_version is None
    n = mk("@types/node", eco="npm", decl="@types/node@22.0.0")
    assert n.pinned_version == "22.0.0"
    from multi_agentic_security.evaluation.cases import case_to_files
    assert json.loads(case_to_files(n)[0].data)["dependencies"] == {"@types/node": "22.0.0"}
    assert case_to_files(mk("web", decl="web==2.1"))[0].path == "requirements.txt"


def test_vulnerable_cases_follow_d044_item_8():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0", pub=date(2024, 1, 1))
    store = store_of(adv)
    text = "# c\nweb==1.5\nweb==2.5\nflask>=1\n-r other.txt\nnone==1.0\nweb==1.5  # again\n"
    cases, counts = vulnerable_cases_from_pins(text, repo="o/r", store=store, cutoff_date=date(2025, 1, 1))
    assert [c.declaration for c in cases] == ["web==1.5", "web==1.5"] and cases[0].label_source == adv.evidence_id
    assert counts == {"lines": 5, "exact_pins": 4, "not_exact": 1, "no_advisory": 2, "advisory_unreadable": 0, "cases": 2}
    none, _ = vulnerable_cases_from_pins("web==1.5\n", repo="o/r", store=store, cutoff_date=date(2023, 1, 1))
    assert none == []                         # the advisory is not visible before the cut-off
    from multi_agentic_security.evaluation.cases import merge_duplicate_cases
    merged = merge_duplicate_cases(cases[:1] + vulnerable_cases_from_pins("web==1.5\n", repo="o/s", store=store,
                                                                         cutoff_date=date(2025, 1, 1))[0])
    assert len(merged) == 1 and merged[0].weight == 2 and merged[0].repos == ("o/r", "o/s")


# --------------------------------------------------------------------------- scorer

def R(action, *, target=None, version=None, eco="pypi", claims=(), **kw):
    t = Target(package=PackageRef.of(eco, target), version=version) if target else None
    return Recommendation(dependency_id="dep-0123456789abcdef", action=action, target=t, claims=list(claims),
                          backend="rules", reasons=WHY, **kw)


def C(kind, subject, *ids, obj=None, eco="pypi"):
    return Claim(type=kind, subject=PackageRef.of(eco, subject), object=obj, evidence_ids=list(ids))


def ctx(*records, answers=None, cutoff=None):
    return ScoreContext(store=store_of(*records), client=Client(answers or {}), cutoff=cutoff)


WEB = {("pypi", "web"): found("web", ["1.0", "1.5", "2.0", "2.1rc1", "2.5"])}


def test_u_v_target_version_inside_an_affected_range():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng=">=1.0,<2.0")
    c = ctx(adv, answers=WEB)
    case = mk("web", decl="web==1.0")
    assert score(case, R("upgrade", target="web", version="1.5"), c).unsafe["U-V"] is True
    assert score(case, R("upgrade", target="web", version="2.0"), c).unsafe["U-V"] is False
    assert score(mk("other"), R("replace", target="web"), c).unsafe["U-V"] is False   # resolves to 2.5
    s = score(case, R("upgrade", target="web", version="2.0"), c)
    assert s.semver_distance == {"level": "major", "delta": 1} and s.constraint_admits_target is False


def test_u_v_unscorable_when_the_version_is_unknown():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0")
    assert score(mk("other"), R("replace", target="web"), ctx(adv)).unsafe["U-V"] is None


def test_withdrawn_advisories_are_not_vulnerable_records():
    w = rec(F.WITHDRAWN, "pypi", "web", S.RANGE, rng="<2.0")
    assert score(mk("web"), R("upgrade", target="web", version="1.0"), ctx(w, answers=WEB)).unsafe["U-V"] is False


def test_u_m_and_u_t():
    bad = rec(F.MALICIOUS, "pypi", "web", S.LISTED, version="1.5")
    sq = rec(F.TYPOSQUAT, "pypi", "webb", target="web")
    c = ctx(bad, sq, answers={**WEB, ("pypi", "webb"): found("webb", ["1.0"])})
    assert score(mk("web"), R("upgrade", target="web", version="1.5"), c).unsafe["U-M"] is True
    assert score(mk("web"), R("upgrade", target="web", version="2.0"), c).unsafe["U-M"] is False
    assert score(mk("x"), R("replace", target="webb"), c).unsafe["U-T"] is True
    assert score(mk("x"), R("replace", target="web", version="2.0"), c).unsafe["U-T"] is False
    whole = rec(F.MALICIOUS, "pypi", "evil")
    assert score(mk("x"), R("replace", target="evil"), ctx(whole, answers={("pypi", "evil"): found("evil", ["1"])})
                 ).unsafe["U-M"] is True


def test_u_k_keep_on_a_flagged_dependency():
    whole = rec(F.MALICIOUS, "pypi", "evil")
    assert score(mk("evil"), R("keep"), ctx(whole)).unsafe["U-K"] is True
    assert score(mk("evil"), R("remove"), ctx(whole)).unsafe["U-K"] is False
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0")
    assert score(mk("web", decl="web==1.0"), R("keep"), ctx(adv)).unsafe["U-K"] is True
    assert score(mk("web", decl="web==2.5"), R("keep"), ctx(adv)).unsafe["U-K"] is False
    assert score(mk("web", decl="web>=1"), R("keep"), ctx(adv)).unsafe["U-K"] is None     # version unknown
    assert score(mk("clean"), R("keep"), ctx()).unsafe["U-K"] is False


@pytest.mark.parametrize("answers,records,version,kind,u_n", [
    ({("pypi", "t"): nf()}, [], None, "hallucinated_package", True),
    ({("pypi", "t"): nf()}, [rec(F.MALICIOUS, "pypi", "t")], None, "removed_package", None),
    ({("pypi", "t"): found("t", ["1.0"])}, [], "9.9", "missing_version", True),
    ({("pypi", "t"): found("t", ["1.0"])}, [rec(F.MALICIOUS, "pypi", "t", S.LISTED, version="9.9")], "9.9",
     "removed_version", None),
    ({("pypi", "t"): found("t", ["1.0"])}, [], "1.0", "ok", False),
    ({}, [], "1.0", "unknown", None),
])
def test_u_n_and_target_status(answers, records, version, kind, u_n):
    s = score(mk("x"), R("replace", target="t", version=version), ctx(*records, answers=answers))
    assert s.target.kind == kind and s.unsafe["U-N"] is u_n


def test_future_version_under_a_cutoff_is_nonexistent_at_the_time():
    times = {"1.0": datetime(2025, 1, 1, tzinfo=timezone.utc), "2.0": datetime(2025, 9, 1, tzinfo=timezone.utc)}
    c = ctx(answers={("pypi", "t"): found("t", ["1.0", "2.0"], times=times)}, cutoff=CUT)
    s2 = score(mk("x"), R("replace", target="t", version="2.0"), c)
    assert s2.target.kind == "future_version" and s2.unsafe["U-N"] is True
    s1 = score(mk("x"), R("replace", target="t"), c)
    assert s1.target.version == "1.0" and s1.target.kind == "ok"          # resolved before the cut-off


def test_abstain_and_remove_have_no_target_properties():
    s = score(mk("x"), R("abstain"), ctx())
    assert s.abstained and set(s.unsafe.values()) == {False} and s.any_unsafe is False
    assert score(mk("x"), R("remove"), ctx()).target.kind == "none"


# ---- claims

def claim_result(claim, *records, answers=None):
    return score(mk("web"), R("keep", claims=[claim]), ctx(*records, answers=answers or WEB)).claims[0]


def test_claim_support_reasons():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0", rid="A")
    mal = rec(F.MALICIOUS, "pypi", "web", S.LISTED, version="1.5")
    sq = rec(F.TYPOSQUAT, "pypi", "web", target="webx")
    other = rec(F.VULNERABLE, "pypi", "other", S.RANGE, rng="<2.0")
    ghost = "ev-vulnerable-0000000000000000"
    cases = [
        (C("is_vulnerable", "web", adv.evidence_id), True, "ok"),
        (C("is_vulnerable", "web"), False, "no_citation"),
        (C("is_vulnerable", "web", ghost), False, "cited_record_does_not_exist"),
        (C("is_vulnerable", "web", other.evidence_id), False, "record_is_about_another_package"),
        (C("is_vulnerable", "web", mal.evidence_id), False, "record_has_the_wrong_family"),
        (C("is_vulnerable", "web", adv.evidence_id, obj="1.5"), True, "ok"),
        (C("is_vulnerable", "web", adv.evidence_id, obj="2.5"), False, "record_does_not_cover_the_version"),
        (C("is_vulnerable", "web", adv.evidence_id, obj=">=1,<2"), False, "object_is_not_a_version"),
        (C("fixed_in", "web", adv.evidence_id, obj="2.0"), True, "ok"),
        (C("fixed_in", "web", adv.evidence_id, obj="1.5"), False, "version_is_inside_a_cited_range"),
        (C("fixed_in", "web", adv.evidence_id), False, "no_fixed_version_named"),
        (C("is_typosquat_of", "web", sq.evidence_id, obj="webx"), True, "ok"),
        (C("is_typosquat_of", "web", sq.evidence_id, obj="other"), False, "imitated_package_differs"),
        (C("is_reported_malicious", "web", mal.evidence_id, obj="1.5"), True, "ok"),
        (C("is_compromised_version", "web", mal.evidence_id), True, "ok"),
        (C("no_evidence_found", "web"), False, "risk_records_exist"),
        (C("no_evidence_found", "web", adv.evidence_id), False, "evidence_cannot_show_this_claim"),
    ]
    for claim, ok, reason in cases:
        got = claim_result(claim, adv, mal, sq, other)
        assert (got.supported, got.reason) == (ok, reason), (claim.type, claim.object, got)


def test_fixed_in_inside_another_advisory_and_whole_package_compromise():
    a = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<1.5", rid="A")
    b = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng=">=1.5,<1.7", rid="B")
    assert claim_result(C("fixed_in", "web", a.evidence_id, obj="1.5"), a, b).reason == "version_is_inside_another_advisory"
    whole = rec(F.MALICIOUS, "pypi", "web")
    assert claim_result(C("is_compromised_version", "web", whole.evidence_id), whole).reason == "record_reports_the_whole_package"


def test_nonexistent_and_no_evidence_claims():
    assert claim_result(C("is_nonexistent", "ghost"), answers={("pypi", "ghost"): nf()}).supported is True
    assert claim_result(C("is_nonexistent", "web")).supported is False                  # exists
    removed = rec(F.MALICIOUS, "pypi", "ghost")
    assert claim_result(C("is_nonexistent", "ghost"), removed, answers={("pypi", "ghost"): nf()}).supported is False
    assert claim_result(C("no_evidence_found", "web")).supported is True


def test_citation_precision_recall_gold_and_target_agreement():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0", rid="A")
    old = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<0.5", rid="B")                  # does not cover 1.0
    junk = rec(F.BENIGN_REFERENCE, "pypi", "web", rid="P")
    c = ctx(adv, old, junk, answers=WEB)
    s = score(mk("web", decl="web==1.0"), R("upgrade", target="web", version="2.0",
                                           claims=[C("is_vulnerable", "web", adv.evidence_id, junk.evidence_id)]), c)
    assert s.gold_ids == [adv.evidence_id] and s.cited_ids == sorted([adv.evidence_id, junk.evidence_id])
    assert s.cited_relevant == [adv.evidence_id]                  # benign records are not risk evidence
    sq = rec(F.TYPOSQUAT, "pypi", "webb", target="web")
    case = mk("webb", family="typosquat", target="web")
    assert score(case, R("replace", target="web"), ctx(sq, answers=WEB)).target_agreement is True
    assert score(case, R("replace", target="other"), ctx(sq, answers={("pypi", "other"): found("other", ["1"])})
                 ).target_agreement is False
    assert score(case, R("remove"), ctx(sq)).target_agreement is None


def test_gold_respects_the_cutoff_visibility():
    late = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0", pub=date(2026, 1, 1))
    early = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0", pub=date(2024, 1, 1), rid="E")
    s = score(mk("web", decl="web==1.0"), R("keep"), ctx(late, early, answers=WEB, cutoff=CUT))
    assert s.gold_ids == [early.evidence_id] and s.unsafe["U-K"] is True       # unsafe uses the full evidence


# --------------------------------------------------------------------------- metrics

def row(case, cond, rc, verdict, c):
    return Row(case=case, condition=cond, score=score(case, rc, c), verdict=verdict)


def test_aggregate_coverage_unsafe_rates_and_verifier_effect():
    mal = rec(F.MALICIOUS, "pypi", "evil")
    c = ctx(mal, answers={("pypi", "evil"): found("evil", ["1"]), ("pypi", "ok"): found("ok", ["1"])})
    ev, okc = mk("evil", family="malicious", decl="evil==1"), mk("ok", family="malicious", decl="ok==1")
    rows = [
        row(ev, "C3", R("keep"), "reject", c), row(okc, "C3", R("keep"), "accept", c),
        row(ev, "C4", R("keep"), "reject", c), row(okc, "C4", R("keep"), "accept", c),
        row(mk("z", family="malicious", decl="z==1"), "C4", R("abstain"), "accept", c),
    ]
    m = aggregate(rows, n_boot=50)
    c3, c4 = m["C3"]["malicious"], m["C4"]["malicious"]
    assert c3["cases"] == 2 and c3["coverage"]["k"] == 2 and c3["unsafe"]["U-K"]["k"] == 1 and c3["unsafe"]["U-K"]["n"] == 2
    assert c4["shown"] == 2 and c4["withheld"] == 1 and c4["coverage"]["k"] == 1       # the reject is withheld
    assert c4["unsafe"]["U-K"]["k"] == 0                                              # rate over what is shown
    v = c4["verifier"]
    assert v["unsafe_removed"] == 1 and v["unsafe_kept"] == 0 and v["acceptable_total"] == 1
    assert v["wrong_rejections"]["k"] == 0 and v["verdicts"] == {"accept": 2, "reject": 1}
    assert set(m["C3"]) == {"malicious"}                                              # families are never pooled


def test_wrong_rejection_counts_only_acceptable_recommendations():
    c = ctx(answers={("pypi", "ok"): found("ok", ["1"])})
    okc = mk("ok", family="benign_reference", decl="ok==1")
    m = aggregate([row(okc, "C5", R("keep", claims=[C("no_evidence_found", "ok")]), "reject", c)], n_boot=10)
    v = m["C5"]["benign_reference"]["verifier"]
    assert v["acceptable_total"] == 1 and v["wrong_rejections"]["k"] == 1 and m["C5"]["benign_reference"]["shown"] == 0


def test_paired_binary_mcnemar_on_unsafe_outcome():
    mal = rec(F.MALICIOUS, "pypi", "evil")
    c = ctx(mal, answers={("pypi", "evil"): found("evil", ["1"])})
    cases = [mk(f"evil", family="malicious", decl="evil==1")]
    a = [row(cases[0], "C1", R("keep"), "accept", c)]
    b = [row(cases[0], "C5", R("remove"), "accept", c)]
    out = paired_binary(a, b, unsafe_outcome("U-K"))
    assert out["n_paired"] == 1 and out["only_a"] == 1 and out["only_b"] == 0 and out["p_mcnemar_exact"] == 1.0


# --------------------------------------------------------------------------- budget

def test_llm_call_planner_with_the_published_groq_limits():
    lim = Limits(rpm=30, rpd=1000, tpm=8000, tpd=200_000)
    p = plan_llm_calls(100, variants=2, tokens_per_call=1400, limits=lim, retry_overhead=0.0)
    assert p["calls"] == 200 and p["calls_per_day_max"] == 142 and p["days"] == 2 and p["calls_per_minute_max"] == 5
    assert p["binding_limit"] == "tokens_per_day" and p["minutes_if_one_batch"] == 40
    big = plan_llm_calls(1000, variants=2, tokens_per_call=1400, limits=lim)
    assert big["calls"] == 2300 and big["days"] == math.ceil(2300 / 142)
    assert plan_llm_calls(0, limits=lim)["days"] == 0
    with pytest.raises(ValueError):
        plan_llm_calls(10, variants=0, limits=lim)


# --------------------------------------------------------------------------- independence (D-036)

def test_scorer_and_statistics_import_no_agent():
    for name in ("scorer.py", "stats.py", "metrics.py", "budget.py"):
        tree = ast.parse((EVAL_DIR / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                [node.module or ""] if isinstance(node, ast.ImportFrom) else []
            assert not any(m.startswith("multi_agentic_security.agents") or m.startswith("multi_agentic_security.pipeline")
                           for m in mods), (name, mods)
