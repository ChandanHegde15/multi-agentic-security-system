"""Regression tests for the independent review of the evaluation code (D-071).

Each test reproduces one confirmed finding (E-xx defects, R-xx risks, N-xx nits) of the review. Synthetic
inputs only; no network, no data files."""

import ast
import dataclasses
import math
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.contracts.evidence import LabelFamily as F, VersionScope as S
from multi_agentic_security.evaluation import (
    Row, ScoreContext, aggregate, assign_groups, mark_eval_only, paired_binary, score, split_three_way,
    unsafe_outcome, verify_splits,
)
from multi_agentic_security.evaluation import stats
from multi_agentic_security.evaluation.metrics import delivered_unsafe_outcome

from test_agent3_review import Client, found, nf, rec, store_of
from test_eval_core import C, CUT, R, WEB, ctx, mk

UTC = timezone.utc


def row(case, cond, rc, verdict, c):
    return Row(case=case, condition=cond, score=score(case, rc, c), verdict=verdict)


# ---- E-01: McNemar on the verifier effect must not be vacuous

def test_e01_withheld_unsafe_rows_are_discordant_pairs_for_the_delivered_outcome():
    mal = rec(F.MALICIOUS, "pypi", "evil")
    c = ctx(mal, answers={("pypi", "evil"): found("evil", ["1"])})
    case = mk("evil", family="malicious", decl="evil==1")
    c3 = [row(case, "C3", R("keep"), "reject", c)]
    c4 = [row(case, "C4", R("keep"), "reject", c)]
    old = paired_binary(c3, c4, unsafe_outcome("U-K"))
    assert old["n_paired"] == 0 and old["dropped_one_sided"] == 1          # no longer silent
    new = paired_binary(c3, c4, delivered_unsafe_outcome("U-K"))
    assert new["n_paired"] == 1 and new["only_a"] == 1 and new["only_b"] == 0


def test_e01_ten_unsafe_rows_all_rejected():
    mal = rec(F.MALICIOUS, "pypi", "evil")
    answers = {("pypi", f"evil{i}"): found(f"evil{i}", ["1"]) for i in range(10)}
    recs = [rec(F.MALICIOUS, "pypi", f"evil{i}") for i in range(10)]
    c = ctx(*recs, answers=answers)
    cases = [mk(f"evil{i}", family="malicious", decl=f"evil{i}==1") for i in range(10)]
    a = [row(k, "C3", R("keep"), "reject", c) for k in cases]
    b = [row(k, "C4", R("keep"), "reject", c) for k in cases]
    out = paired_binary(a, b, delivered_unsafe_outcome("U-K"))
    assert out["only_a"] == 10 and out["p_mcnemar_exact"] < 0.01


# ---- E-02: the declared specifier decides the dependency version

def test_e02_unpinned_dependency_resolves_inside_the_declared_specifier():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0")
    c = ctx(adv, answers={("pypi", "web"): found("web", ["1.0", "1.5", "2.0", "2.5"])})
    s = score(mk("web", decl="web<2.0"), R("keep"), c)
    assert s.unsafe["U-K"] is True                          # pip installs 1.5
    assert score(mk("web", decl="web>=2.0"), R("keep"), c).unsafe["U-K"] is False
    assert score(mk("web", decl="web"), R("keep"), c).unsafe["U-K"] is False       # latest is 2.5
    assert score(mk("web", decl="web~~1"), R("keep"), c).unsafe["U-K"] is None      # unreadable specifier = state


# ---- E-03: unreadable or absent version data is a state, never U-N True

def test_e03_range_or_tag_versions_and_missing_lists_are_unknown():
    c = ctx(answers={("pypi", "t"): found("t", ["1.0"])})
    for stated in ("latest", "^1.0.0"):
        s = score(mk("x"), R("replace", target="t", version=stated), c)
        assert s.target.kind == "unknown" and s.unsafe["U-N"] is None, stated
    bare = dataclasses.replace(found("t", ["1.0"]), versions=None, upload_times=None)
    s = score(mk("x"), R("replace", target="t", version="1.0"), ctx(answers={("pypi", "t"): bare}))
    assert s.target.kind == "unknown" and s.unsafe["U-N"] is None


# ---- E-04: naive and aware datetimes

def test_e04_naive_upload_times_do_not_crash_and_a_naive_cutoff_is_refused():
    naive = found("t", ["1.0"], times={"1.0": datetime(2025, 1, 1)})
    s = score(mk("x"), R("replace", target="t", version="1.0"), ctx(answers={("pypi", "t"): naive}, cutoff=CUT))
    assert s.target.kind == "unknown" and s.unsafe["U-N"] is None
    with pytest.raises(ValueError):
        ScoreContext(store=store_of(), client=Client({}), cutoff=datetime(2025, 6, 1))


# ---- E-05: a fixed_in claim needs a release that existed at the time

def test_e05_fixed_version_must_be_a_real_unyanked_release_before_the_cutoff():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0", rid="A")
    def res(obj, answers=None, cutoff=None, yanked=None):
        a = answers if answers is not None else {("pypi", "web"): found("web", ["1.0", "1.5", "2.0", "2.5"], yanked=yanked)}
        return score(mk("web"), R("keep", claims=[C("fixed_in", "web", adv.evidence_id, obj=obj)]),
                     ctx(adv, answers=a, cutoff=cutoff)).claims[0]
    assert (res("2.0").supported, res("2.0").reason) == (True, "ok")
    assert (res("9.9").supported, res("9.9").reason) == (False, "fixed_version_not_released")
    assert res("2.0", answers={}).reason == "cannot_verify_fixed_version_release"
    assert res("2.0", yanked=["2.0"]).reason == "fixed_version_yanked"
    times = {"1.0": datetime(2024, 1, 1, tzinfo=UTC), "2.0": datetime(2025, 9, 1, tzinfo=UTC)}
    late = {("pypi", "web"): found("web", ["1.0", "2.0"], times=times)}
    assert res("2.0", answers=late, cutoff=CUT).reason == "fixed_version_not_released_at_cutoff"


# ---- E-06: a version in a gap between affected intervals is a genuine fix

def test_e06_gap_between_intervals_supports_fixed_in():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng=">=1,<2||>=3,<3.5", rid="G")
    answers = {("pypi", "web"): found("web", ["1.0", "2.5", "3.2", "3.5"])}
    def res(obj):
        return score(mk("web"), R("keep", claims=[C("fixed_in", "web", adv.evidence_id, obj=obj)]),
                     ctx(adv, answers=answers)).claims[0]
    assert res("2.5").supported is True and res("3.5").supported is True
    assert res("3.2").supported is False                    # inside the second interval
    assert res("0.5").supported is False                    # below every interval is not a fix


# ---- E-07: PyPI local versions are builds of the public version

def test_e07_local_versions_are_covered_like_their_public_version():
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<=1.0")
    c = ctx(adv, answers={("pypi", "web"): found("web", ["1.0", "1.0+cpu"])})
    assert score(mk("x"), R("replace", target="web", version="1.0+cpu"), c).unsafe["U-V"] is True
    mal = rec(F.MALICIOUS, "pypi", "web", S.LISTED, version="1.0")
    c2 = ctx(mal, answers={("pypi", "web"): found("web", ["1.0", "1.0+cpu"])})
    assert score(mk("x"), R("replace", target="web", version="1.0+cpu"), c2).unsafe["U-M"] is True


# ---- R-01: citing a record that was not visible at the cut-off

def test_r01_record_published_after_the_cutoff_is_not_supported_nor_precise():
    late = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<2.0", pub=date(2026, 1, 1))
    s = score(mk("web", decl="web==1.0"), R("keep", claims=[C("is_vulnerable", "web", late.evidence_id)]),
              ctx(late, answers=WEB, cutoff=CUT))
    assert (s.claims[0].supported, s.claims[0].reason) == (False, "record_not_visible_at_cutoff")
    assert s.cited_ids == [late.evidence_id] and s.cited_relevant == []


# ---- R-02: whole-package malicious record, with or without an object

def test_r02_compromised_version_claim_is_consistent_for_whole_package_records():
    whole = rec(F.MALICIOUS, "pypi", "web")
    for obj in (None, "1.5"):
        got = score(mk("web"), R("keep", claims=[C("is_compromised_version", "web", whole.evidence_id, obj=obj)]),
                    ctx(whole, answers=WEB)).claims[0]
        assert (got.supported, got.reason) == (False, "record_reports_the_whole_package"), obj


# ---- R-06 / N-02 / N-03 / N-04: statistics

def test_r06_one_group_gives_no_interval_and_two_groups_stay_wide():
    assert stats.bootstrap_ci([1.0, 0.0], ["g", "g"]) == (0.5, None, None)
    p, lo, hi = stats.bootstrap_ci([0.0, 1.0], ["a", "b"], n_boot=500)
    assert p == 0.5 and lo == 0.0 and hi == 1.0
    assert stats.bootstrap_ci([0.0, 1.0, 1.0], ["a", "b", "c"], min_groups=5) == (2 / 3, None, None)


def test_r07_pairing_by_key_not_by_position():
    a = {"c1": 1.0, "c2": 0.0, "c3": 0.0}
    b = {"c3": 0.0, "c2": 1.0, "c1": 1.0, "c9": 1.0}
    groups = {"c1": "g1", "c2": "g2", "c3": "g3", "c9": "g9"}
    d, lo, hi = stats.paired_diff_ci_by_key(a, b, groups, n_boot=200)
    assert d == pytest.approx(-1 / 3)                        # c9 is not in both and is left out


def test_n02_percentile_uses_nearest_rank():
    values = [float(i) for i in range(40)]
    p, lo, hi = stats.bootstrap_ci(values, [str(i) for i in range(40)], n_boot=2000)
    assert lo < p < hi


def test_n03_n04_invalid_inputs_are_refused():
    for bad in ((5, 3), (-1, 3), (1, -2)):
        with pytest.raises(ValueError):
            stats.wilson(*bad)
    for bad in ((-1, 3), (3, -1)):
        with pytest.raises(ValueError):
            stats.mcnemar_exact(*bad)
    with pytest.raises(ValueError):
        stats.holm({"a": float("nan"), "b": 0.01})


# ---- R-08: verify_splits recomputes the groups

def test_r08_stale_groups_and_unknown_sides_are_reported():
    a = mk("a", repos=["r1"])
    b = mk("b", repos=["r1"])
    from multi_agentic_security.evaluation import Case
    a2 = Case(**{**a.__dict__, "group": "stale-a"})
    b2 = Case(**{**b.__dict__, "group": "stale-b"})
    problems = verify_splits({"train": [a2], "dev": [b2], "test": []})
    assert any("share a package, target or repository" in p for p in problems)
    assert any("unknown side" in p for p in verify_splits({"validation": [a]}))


def test_r08_a_clean_three_way_split_verifies_and_matches_the_seed():
    cases = assign_groups([mk(f"p{i}", repos=[f"r{i % 7}"]) for i in range(60)])
    parts = split_three_way(cases)
    assert verify_splits(parts) == []
    assert verify_splits(parts, check_seed=True) == []
    moved = {**parts, "train": parts["train"][1:], "dev": parts["dev"] + parts["train"][:1]}
    assert verify_splits(moved, check_seed=True) != []


# ---- R-09: the two-way split is not used for the frozen splits

def test_r09_three_way_split_does_not_call_the_two_way_function():
    src = (Path(__file__).resolve().parents[2] / "src" / "multi_agentic_security" / "evaluation" / "cases.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "split_three_way")
    called = {n.func.id for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "split_of" not in called and "split_cases" not in called


# ---- R-10: expected targets are forced too

def test_r10_typosquat_whose_target_is_a_libhallubench_name_is_forced_to_test():
    sq = mk("sq", family="typosquat", target="Requests")
    other = mk("plain")
    out = {c.name: c.split_hint for c in mark_eval_only([sq, other], ["requests"])}
    assert out == {"sq": "test", "plain": None}


# ---- R-11: a verifier condition without a verdict is an error

def test_r11_missing_verdict_on_a_verifier_condition_is_refused():
    c = ctx(answers={("pypi", "ok"): found("ok", ["1"])})
    okc = mk("ok", family="benign_reference", decl="ok==1")
    with pytest.raises(ValueError):
        aggregate([row(okc, "C5", R("keep"), None, c)], n_boot=10)


# ---- R-12: the scorer requires a snapshot client and records lookup errors

def test_r12_live_client_is_refused_and_lookup_errors_are_kept():
    class Live(Client):
        mode = "live"
    with pytest.raises(ValueError):
        ScoreContext(store=store_of(), client=Live({}))

    class Boom(Client):
        def lookup(self, eco, name):
            raise RuntimeError("bug")
    c = ScoreContext(store=store_of(), client=Boom({}))
    assert c.lookup("pypi", "x") is None and "RuntimeError" in c.lookup_errors[("pypi", "x")]


# ---- N-05: the resolver skips PyPI local versions

def test_n05_resolver_does_not_pick_a_local_version():
    from multi_agentic_security.evaluation.scorer import resolve_version
    assert resolve_version("pypi", found("web", ["1.0", "1.0+cpu"]), None) == "1.0"
