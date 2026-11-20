"""Train / dev (validation) / test splits and the fine-tuning pool (D-070). Hand-written cases; no data files."""

import random
from datetime import date

import pytest

from multi_agentic_security.contracts.evidence import LabelFamily as F, VersionScope as S
from multi_agentic_security.evaluation import (
    SPLITS, THREE_WAY, Case, fine_tuning_pool, mark_eval_only, split_of3, split_three_way, verify_splits,
)

from test_agent3_review import rec, store_of


def mk(name, family="malicious", repos=(), hint=None, target=None, source="test", eco="pypi"):
    return Case(case_id=f"case-{name}-{family[:3]}", family=family, ecosystem=eco, name=name, declaration=f"{name}==1.0",
                group=name, label_source=source, repos=tuple(repos), split_hint=hint, expected_target=target)


def test_split_of3_is_pure_and_follows_the_fractions():
    assert split_of3("requests") == split_of3("requests") and split_of3("requests") in SPLITS
    counts = {s: 0 for s in SPLITS}
    for i in range(6000):
        counts[split_of3(f"g{i}")] += 1
    assert abs(counts["train"] / 6000 - 0.70) < 0.03 and abs(counts["dev"] / 6000 - 0.15) < 0.03
    assert abs(counts["test"] / 6000 - 0.15) < 0.03
    assert THREE_WAY["train"] > THREE_WAY["dev"] and THREE_WAY["train"] > THREE_WAY["test"]     # D-072
    assert {split_of3(f"g{i}", {"train": 0.0, "dev": 0.5, "test": 0.5}) for i in range(500)} == {"dev", "test"}
    assert {split_of3(f"g{i}", {"train": 0.0, "dev": 0.0, "test": 1.0}) for i in range(100)} == {"test"}
    assert split_of3("x", seed=1) in SPLITS


@pytest.mark.parametrize("bad", [{"train": 0.5, "dev": 0.5}, {"train": 0.5, "dev": 0.4, "test": 0.4},
                                 {"train": -0.1, "dev": 0.6, "test": 0.5}])
def test_bad_fractions_are_refused(bad):
    with pytest.raises(ValueError):
        split_of3("g", bad)


def test_three_way_split_is_disjoint_grouped_and_order_independent():
    cases = [mk(f"p{i}", repos=[f"r{i // 3}"]) for i in range(60)] + \
            [mk("web", family="typosquat", target="p1"), mk("web2", family="typosquat", target="p1")]
    parts = split_three_way(cases)
    assert set(parts) == set(SPLITS) and sum(len(v) for v in parts.values()) == 62
    assert verify_splits(parts) == []
    g = {c.name: side for side, cs in parts.items() for c in cs}
    assert g["p0"] == g["p1"] == g["p2"]                       # one repository: one side
    assert g["web"] == g["web2"] == g["p1"]                    # same imitated package: one side
    shuffled = cases[:]
    random.Random(3).shuffle(shuffled)
    again = split_three_way(shuffled)
    assert {s: [c.case_id for c in v] for s, v in parts.items()} == {s: [c.case_id for c in v] for s, v in again.items()}


def test_a_package_stays_on_one_side_across_families():
    cases = [mk("shared", family="malicious"), mk("shared", family="vulnerable"), mk("shared", family="typosquat", target="x")]
    parts = split_three_way(cases)
    assert len({side for side, cs in parts.items() for c in cs if c.name == "shared"}) == 1


def test_forced_sides_and_precedence():
    only_dev = mk("a", hint="dev", repos=["dev-repo"])
    pulled = mk("b", hint="test", repos=["dev-repo"])           # shares a repository with a dev-hinted case
    train_hint = mk("c", hint="train", repos=["t"])
    parts = split_three_way([only_dev, pulled, train_hint, mk("d", hint="test")])
    where = {c.name: side for side, cs in parts.items() for c in cs}
    assert where["b"] == "test" and where["a"] == "test", "a group with a test case goes to test; dev never receives it"
    assert where["c"] == "train" and where["d"] == "test"
    assert verify_splits(parts) == []


def test_eval_only_names_are_forced_to_test_in_every_family():
    cases = [mk("evilpkg", family="malicious"), mk("evilpkg", family="typosquat", target="y"), mk("other")]
    marked = mark_eval_only(cases, ["EvilPkg"])
    assert [c.split_hint for c in marked] == ["test", "test", None]
    parts = split_three_way(marked, {"train": 0.5, "dev": 0.5, "test": 0.0})
    assert {c.name for c in parts["test"]} == {"evilpkg"} and parts["train"] + parts["dev"] != []
    assert all(c.name == "other" for c in parts["train"] + parts["dev"])


def test_verify_splits_detects_every_kind_of_leak():
    a, b = mk("a"), mk("b", hint="test")
    leak = verify_splits({"train": [a], "dev": [a], "test": []})
    assert leak == [f"case {a.case_id} is in both train and dev", "group a is in both train and dev"]
    two = Case(**{**mk("a", family="vulnerable").__dict__})
    assert any("group a is in both" in p for p in verify_splits({"train": [a], "dev": [two], "test": []}))
    assert any("test-only case" in p for p in verify_splits({"train": [b], "dev": [], "test": []}))
    assert any("dev-only case" in p for p in verify_splits({"train": [mk("c", hint="dev")], "dev": [], "test": []}))
    assert verify_splits({"train": [], "dev": [mk("c", hint="dev")], "test": [b]}) == []


def test_randomised_no_held_out_case_ever_reaches_dev_or_train():
    rng = random.Random(20261114)
    for trial in range(30):
        cases = []
        for i in range(120):
            cases.append(mk(f"p{rng.randrange(60)}", family=rng.choice(["malicious", "vulnerable", "typosquat"]),
                            repos=[f"r{rng.randrange(25)}"] * rng.randrange(2), hint=rng.choice([None, None, None, "test", "dev", "train"]),
                            target=None))
        cases = list({c.case_id: c for c in cases}.values())
        fractions = {"train": 0.3, "dev": 0.2, "test": 0.5}
        parts = split_three_way(cases, fractions, seed=trial)
        assert verify_splits(parts) == []
        assert sum(len(v) for v in parts.values()) == len(cases)
        assert all(c.split_hint != "test" for c in parts["train"] + parts["dev"])


# --------------------------------------------------------------------------- fine-tuning pool

def test_fine_tuning_pool_requires_dated_evidence_backed_labels_before_the_cutoff():
    early = rec(F.MALICIOUS, "pypi", "early", pub=date(2024, 1, 1))
    late = rec(F.MALICIOUS, "pypi", "late", pub=date(2026, 1, 1))
    undated = rec(F.MALICIOUS, "pypi", "undated", pub=None)
    store = store_of(early, late, undated)
    cases = [mk("early", source=early.evidence_id), mk("late", source=late.evidence_id),
             mk("undated", source=undated.evidence_id), mk("free", source="some dataset name"),
             mk("ghost", source="ev-malicious-0000000000000000"), mk("held", source=early.evidence_id, hint="test"),
             mk("multi", source=f"{early.evidence_id},{late.evidence_id}"), mk("none", source="")]
    ok, rejected = fine_tuning_pool(cases, store, date(2025, 1, 1))
    assert [c.name for c in ok] == ["early"]
    assert rejected == {"label_not_from_evidence_records": ["case-free-mal", "case-none-mal"],
                        "label_record_missing": ["case-ghost-mal"], "label_record_not_before_cutoff": ["case-late-mal", "case-multi-mal"],
                        "label_record_undated": ["case-undated-mal"], "test_only_case": ["case-held-mal"]}
    assert len(ok) + sum(len(v) for v in rejected.values()) == len(cases), "nothing is dropped silently"


def test_the_default_fractions_name_exactly_the_three_sides():
    assert set(THREE_WAY) == set(SPLITS) == {"train", "dev", "test"} and abs(sum(THREE_WAY.values()) - 1) < 1e-12
