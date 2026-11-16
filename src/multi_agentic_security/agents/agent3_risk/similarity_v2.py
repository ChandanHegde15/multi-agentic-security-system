"""Name similarity to popular packages for Agent 3 v2 (D-055).

A name is *similar* to a popular name when their Damerau-Levenshtein distance
is exactly 1 (one inserted, deleted, substituted or swapped character) on the
normalized names. This is the edit model most typosquatting studies use for
single-character variants; it is a signal for review, never a malicious label.

Candidates are found with a symmetric-delete index (every name and every
one-character deletion of it), so a lookup does not scan the whole list; each
candidate is confirmed with the exact distance. Names shorter than
``MIN_LENGTH`` are skipped, because very short names are within distance 1 of
many others. The frozen v1 similarity (normalized Levenshtein against a
7-package catalogue) is not used or changed here.
"""

from __future__ import annotations

from typing import Iterable

MIN_LENGTH = 4


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance (adjacent transpositions count 1)."""
    la, lb = len(a), len(b)
    prev2: list[int] = []
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[lb]


def _keys(name: str) -> set[str]:
    return {name} | {name[:i] + name[i + 1:] for i in range(len(name))}


class PopularIndex:
    """Popular names of one ecosystem -> lookups of names at distance 1."""

    def __init__(self, names: Iterable[tuple[str, str]]):
        """``names``: (normalized name, evidence ID of the list record)."""
        self._ids: dict[str, str] = {}
        self._index: dict[str, set[str]] = {}
        for name, eid in names:
            if len(name) < MIN_LENGTH or name in self._ids:
                continue
            self._ids[name] = eid
            for k in _keys(name):
                self._index.setdefault(k, set()).add(name)

    def __contains__(self, name: str) -> bool:
        return name in self._ids

    def __len__(self) -> int:
        return len(self._ids)

    def similar(self, name: str) -> list[tuple[str, str]]:
        """Popular names at distance exactly 1 from ``name``: [(popular name, evidence ID)], sorted."""
        if len(name) < MIN_LENGTH or name in self._ids:
            return []
        cands = set()
        for k in _keys(name):
            cands |= self._index.get(k, set())
        hits = sorted(c for c in cands if c != name and damerau_levenshtein(name, c) == 1)
        return [(c, self._ids[c]) for c in hits]
