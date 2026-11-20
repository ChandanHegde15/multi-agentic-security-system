"""Statistics for the evaluation (RESEARCH_QUESTIONS.md section 10, D-067). Pure Python, seeded,
no extra dependencies.

* Wilson interval for a proportion;
* bootstrap intervals resampled by group (target package / repository), so that near-duplicate
  cases do not make the interval too narrow (D-036);
* exact McNemar test for paired binary outcomes;
* Holm correction across families and models;
* Cohen's kappa;
* non-inferiority decision from a paired grouped-bootstrap interval and a margin fixed beforehand.
"""

from __future__ import annotations

import math
import random
from collections import defaultdict
from typing import Optional, Sequence


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[Optional[float], Optional[float], Optional[float]]:
    """(proportion, low, high); all None when n == 0."""
    if n < 0 or k < 0 or k > n:
        raise ValueError("wilson needs 0 <= k <= n")
    if n == 0:
        return None, None, None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, centre - half), min(1.0, centre + half)


def _by_group(values: Sequence[float], groups: Sequence[str]) -> list[tuple[float, int]]:
    acc: dict[str, list[float]] = defaultdict(list)
    for v, g in zip(values, groups):
        acc[g].append(v)
    return [(sum(vs), len(vs)) for _, vs in sorted(acc.items())]


def bootstrap_ci(values: Sequence[float], groups: Sequence[str], *, n_boot: int = 2000, seed: int = 20261114,
                 alpha: float = 0.05, min_groups: int = 2) -> tuple[Optional[float], Optional[float], Optional[float]]:
    """Mean with a percentile interval, resampling whole groups with replacement. With fewer than
    ``min_groups`` groups there is no interval (None bounds, never a zero-width one); the protocol fixes
    the minimum (D-071 R-06)."""
    if len(values) != len(groups):
        raise ValueError("values and groups must have the same length")
    if not values:
        return None, None, None
    cells = _by_group(values, groups)
    rng = random.Random(seed)
    total_n = sum(n for _, n in cells)
    point = sum(s for s, _ in cells) / total_n
    if len(cells) < max(2, min_groups):
        return point, None, None
    means = []
    for _ in range(n_boot):
        pick = [cells[rng.randrange(len(cells))] for _ in cells]
        n = sum(c[1] for c in pick)
        means.append(sum(c[0] for c in pick) / n)
    means.sort()
    lo = means[max(0, math.floor((alpha / 2) * n_boot))]                     # nearest rank (D-071 N-02)
    hi = means[min(n_boot - 1, math.ceil((1 - alpha / 2) * n_boot) - 1)]
    return point, lo, hi


def paired_diff_ci_by_key(a: dict, b: dict, groups: dict, *, n_boot: int = 2000, seed: int = 20261114,
                          alpha: float = 0.05, min_groups: int = 2):
    """Mean of (a - b) over the keys present in both mappings, with a grouped bootstrap interval. Pairs by
    case ID, never by position (D-071 R-07); keys missing from either side or from ``groups`` are left out."""
    keys = sorted(k for k in a.keys() & b.keys() if k in groups)
    return bootstrap_ci([a[k] - b[k] for k in keys], [groups[k] for k in keys], n_boot=n_boot, seed=seed,
                        alpha=alpha, min_groups=min_groups)


def paired_diff_ci(a: Sequence[float], b: Sequence[float], groups: Sequence[str], *, n_boot: int = 2000,
                   seed: int = 20261114, alpha: float = 0.05) -> tuple[Optional[float], Optional[float], Optional[float]]:
    """Mean of (a - b) over the same cases, with a grouped bootstrap interval."""
    if not (len(a) == len(b) == len(groups)):
        raise ValueError("a, b and groups must have the same length")
    return bootstrap_ci([x - y for x, y in zip(a, b)], groups, n_boot=n_boot, seed=seed, alpha=alpha)


def mcnemar_exact(only_a: int, only_b: int) -> float:
    """Two-sided exact McNemar p-value from the two discordant counts (binomial, p = 0.5)."""
    if only_a < 0 or only_b < 0:
        raise ValueError("discordant counts must be >= 0")
    n = only_a + only_b
    if n == 0:
        return 1.0
    k = min(only_a, only_b)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def holm(pvalues: dict[str, float]) -> dict[str, float]:
    """Holm-adjusted p-values (monotone, capped at 1)."""
    if any(isinstance(p, float) and math.isnan(p) for p in pvalues.values()):
        raise ValueError("holm cannot adjust a NaN p-value")
    items = sorted(pvalues.items(), key=lambda kv: kv[1])
    m = len(items)
    out, running = {}, 0.0
    for i, (key, p) in enumerate(items):
        running = max(running, min(1.0, (m - i) * p))
        out[key] = running
    return out


def cohen_kappa(r1: Sequence, r2: Sequence) -> Optional[float]:
    if len(r1) != len(r2):
        raise ValueError("ratings must have the same length")
    n = len(r1)
    if n == 0:
        return None
    labels = sorted(set(r1) | set(r2), key=str)
    po = sum(1 for a, b in zip(r1, r2) if a == b) / n
    pe = sum((sum(1 for a in r1 if a == l) / n) * (sum(1 for b in r2 if b == l) / n) for l in labels)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def non_inferior(diff_upper: Optional[float], margin: float) -> Optional[bool]:
    """HYP4: the candidate is non-inferior if the upper bound of (candidate - reference) in the
    unsafe rate is below ``margin`` (fixed in the protocol before any run). None if undetermined."""
    if diff_upper is None:
        return None
    return diff_upper < margin
