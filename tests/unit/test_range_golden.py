"""Golden vectors for the shared version-range reader (`versioning.evidence_ranges`, `npm_semver`).

Why: the evaluation scorer and Agent 5 share this reader, so a defect in it would make them agree by
construction (D-036, D-071). These expected values are written by hand from the ordering rules, not produced
by running the code: PEP 440 (1.0.dev1 < 1.0a1 < 1.0rc1 < 1.0 < 1.0.post1, a local version "1.0+x" sorts above
"1.0") and the semver rules (a pre-release is lower than its release, numeric identifiers compare as numbers,
numeric identifiers are lower than alphanumeric ones, a shorter identifier list is lower, build metadata is
ignored). Range semantics are those of OSV evidence ranges: a pre-release of an exclusive upper bound is inside
(``<2.0`` contains ``2.0rc1``); this differs from pip's specifier rule on purpose and is documented."""

import pytest

from multi_agentic_security.versioning import evidence_ranges as er

PYPI_IN_RANGE = [
    # (version, range, expected)
    ("1.0", "<2.0", True), ("1.9.9", "<2.0", True), ("2.0", "<2.0", False), ("2.0.post1", "<2.0", False),
    ("2.0rc1", "<2.0", True), ("2.0.dev1", "<2.0", True), ("2.0a1", "<2.0", True),
    ("1.0", ">=1.0,<2.0", True), ("0.9", ">=1.0,<2.0", False), ("1.0rc1", ">=1.0,<2.0", False),
    ("1.0.post1", ">=1.0,<2.0", True), ("2.0", ">=1.0,<2.0", False),
    ("1.0", "<=1.0", True), ("1.0.post1", "<=1.0", False), ("0.0.1", "<=1.0", True),
    ("1.0", ">1.0", False), ("1.0.post1", ">1.0", True),
    ("1.0", "==1.0", True), ("1.0.0", "==1.0", True), ("1.0.1", "==1.0", False), ("1.0", "!=1.0", False),
    # '||' alternatives
    ("0.5", ">=1,<2||>=3,<3.5", False), ("1", ">=1,<2||>=3,<3.5", True), ("1.9", ">=1,<2||>=3,<3.5", True),
    ("2", ">=1,<2||>=3,<3.5", False), ("2.5", ">=1,<2||>=3,<3.5", False), ("3", ">=1,<2||>=3,<3.5", True),
    ("3.4", ">=1,<2||>=3,<3.5", True), ("3.5", ">=1,<2||>=3,<3.5", False), ("4", ">=1,<2||>=3,<3.5", False),
    # an affected range starting at 0
    ("0", ">=0,<1.5", True), ("1.5", ">=0,<1.5", False),
]


@pytest.mark.parametrize("version,rng,expected", PYPI_IN_RANGE)
def test_pypi_in_range_golden(version, rng, expected):
    assert er.in_range("pypi", version, rng) is expected


NPM_IN_RANGE = [
    ("1.5.0", ">=1.0.0,<2.0.0", True), ("2.0.0", ">=1.0.0,<2.0.0", False), ("0.9.9", ">=1.0.0,<2.0.0", False),
    ("2.0.0-rc.1", "<2.0.0", True), ("2.0.0", "<2.0.0", False),
    ("1.2.3+build", "<=1.2.3", True), ("1.2.3+build", "<1.2.3", False),
    ("1.2.3-alpha.10", "<1.2.3-alpha.2", False), ("1.2.3-alpha.2", "<1.2.3-alpha.10", True),
    ("1.2.3-alpha", "<1.2.3-alpha.1", True), ("1.2.3-alpha.1", "<1.2.3-alpha.beta", True),
    ("1.2.3-alpha.beta", "<1.2.3-beta", True), ("1.2.3-beta", "<1.2.3", True),
    ("1.0.0", ">=1.0.0,<1.0.1||>=2.0.0,<2.0.1", True), ("1.5.0", ">=1.0.0,<1.0.1||>=2.0.0,<2.0.1", False),
    ("2.0.0", ">=1.0.0,<1.0.1||>=2.0.0,<2.0.1", True), ("2.0.1", ">=1.0.0,<1.0.1||>=2.0.0,<2.0.1", False),
]


@pytest.mark.parametrize("version,rng,expected", NPM_IN_RANGE)
def test_npm_in_range_golden(version, rng, expected):
    assert er.in_range("npm", version, rng) is expected


ABOVE = [
    # (ecosystem, version, range, expected): True only when the version is past every upper bound
    ("pypi", "2.0", "<2.0", True), ("pypi", "1.9", "<2.0", False), ("pypi", "2.0", "<=2.0", False),
    ("pypi", "2.0.post1", "<=2.0", True), ("pypi", "5", ">=1", False),            # no upper bound: nothing is past it
    ("pypi", "3.5", ">=1,<2||>=3,<3.5", True), ("pypi", "2.5", ">=1,<2||>=3,<3.5", False),   # a gap is not "past every interval"
    ("pypi", "3.2", ">=1,<2||>=3,<3.5", False), ("pypi", "1.1", "==1.0", True), ("pypi", "1.0", "==1.0", False),
    ("pypi", "2.0+cpu", "<=2.0", False),       # a local build of 2.0 is not a fix past it (D-061)
    ("npm", "2.0.0", "<2.0.0", True), ("npm", "1.9.9", "<2.0.0", False), ("npm", "2.0.0-rc.1", "<2.0.0", False),
    ("npm", "3.5.0", ">=1.0.0,<2.0.0||>=3.0.0,<3.5.0", True),
]


@pytest.mark.parametrize("eco,version,rng,expected", ABOVE)
def test_above_golden(eco, version, rng, expected):
    assert er.above(eco, version, rng) is expected


@pytest.mark.parametrize("eco,version,rng", [
    ("pypi", "not-a-version", "<2.0"), ("pypi", "1.0", ""), ("pypi", "1.0", "<banana"), ("pypi", "1.0", ">=1.*"),
    ("npm", "banana", "<2.0.0"), ("npm", "1.0.0", ""), ("pypi", None, "<2.0"),
])
def test_unreadable_input_is_a_state_not_a_default(eco, version, rng):
    assert er.in_range(eco, version, rng) is None and er.above(eco, version, rng) is None


def test_known_divergence_local_versions_scorer_strips_but_the_shared_reader_does_not():
    """PEP 440 sorts "1.0+cpu" above "1.0", so the shared reader says "<=1.0" does not contain it. The scorer
    (D-071 E-07) treats a local version as a build of its public version, so it says it does. Both behaviours
    are pinned here: a change on either side must be a recorded decision, because Agent 3 and Agent 5 use the
    shared reader and the scorer must not agree with them by construction."""
    from datetime import date
    from multi_agentic_security.contracts.evidence import LabelFamily as F, VersionScope as S
    from multi_agentic_security.evaluation.scorer import covers
    from test_agent3_review import rec
    assert er.in_range("pypi", "1.0+cpu", "<=1.0") is False
    adv = rec(F.VULNERABLE, "pypi", "web", S.RANGE, rng="<=1.0", pub=date(2025, 1, 1))
    assert covers(adv, "1.0+cpu") is True


def test_scorer_gap_rule_differs_from_the_shared_above_on_purpose():
    """`above` demands "past every interval"; the scorer accepts a fix that is past at least one interval and
    outside all of them (D-071 E-06), so a backported fix in a gap is a real fix."""
    from multi_agentic_security.evaluation.scorer import _past_an_interval
    rng = ">=1,<2||>=3,<3.5"
    assert er.above("pypi", "2.5", rng) is False and _past_an_interval("pypi", "2.5", rng) is True
    assert _past_an_interval("pypi", "0.5", rng) is False              # below every interval is not a fix
    assert _past_an_interval("pypi", "9", ">=1") is False              # no upper bound at all
