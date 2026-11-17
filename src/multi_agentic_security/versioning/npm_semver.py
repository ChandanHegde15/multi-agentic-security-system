"""npm version ranges (shared by Agents 3 and 5; first written for Agent 3, D-056).

A small, read-only implementation of the range grammar npm documents for
``node-semver`` (default options: no loose parsing, pre-releases excluded
unless a comparator in the same set names the same ``major.minor.patch`` with a
pre-release tag). Supported: exact versions (with an optional ``v`` or ``=``),
comparators ``< <= > >= =``, X-ranges (``*``, ``x``, ``1``, ``1.2``, ``1.2.x``),
tilde, caret, hyphen ranges and ``||``. Anything else returns ``None``
("cannot decide"), never a guess.

Only used to decide whether a version is allowed by a declared range; nothing is
installed or resolved against a registry.
"""

from __future__ import annotations

import re
from typing import Optional

from semver import Version

_X = {"x", "X", "*"}
_PART = r"(?:0|[1-9]\d*|[xX*])"
_PARTIAL = re.compile(rf"^[v=]?\s*(?P<maj>{_PART})(?:\.(?P<min>{_PART})(?:\.(?P<pat>{_PART})"
                      r"(?:-(?P<pre>[0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]+)?)?)?$")
_COMP = re.compile(r"^(?P<op><=|>=|<|>|=)?\s*(?P<ver>.+)$")

Comparator = tuple[str, Version]


def parse_version(text: str) -> Optional[Version]:
    t = text.strip().lstrip("v=").strip()
    try:
        return Version.parse(t)
    except (ValueError, TypeError):
        return None


def _partial(text: str):
    m = _PARTIAL.match(text.strip())
    if not m:
        return None
    parts = [m.group("maj"), m.group("min"), m.group("pat")]
    nums: list[Optional[int]] = []
    for p in parts:
        if p is None or p in _X:
            nums.append(None)
        else:
            nums.append(int(p))
    for i in range(1, 3):          # once a part is wild, the rest are wild
        if nums[i - 1] is None:
            nums[i] = None
    return nums, m.group("pre")


def _v(maj: int, mi: int, pa: int, pre: Optional[str] = None) -> Version:
    return Version(maj, mi, pa, prerelease=pre)


def _xrange(op: str, nums, pre) -> Optional[list[Comparator]]:
    maj, mi, pa = nums
    if maj is None:
        return [] if op in ("", "=", ">=", "<=") else ([("<", _v(0, 0, 0, "0"))] if op in ("<", ">") else None)
    if mi is None:
        lo, hi = _v(maj, 0, 0), _v(maj + 1, 0, 0, "0")
    elif pa is None:
        lo, hi = _v(maj, mi, 0), _v(maj, mi + 1, 0, "0")
    else:
        v = _v(maj, mi, pa, pre)
        return [({"": "=", "=": "="}.get(op, op), v)]
    # node-semver adds the "-0" pre-release only to "<" bounds: ">1.2" is ">=1.3.0", so 1.3.0-beta stays out (D-057);
    # "<1.2" is "<1.2.0-0", so 1.2.0-beta is below it (D-058).
    nxt = _v(hi.major, hi.minor, hi.patch)
    return {"": [(">=", lo), ("<", hi)], "=": [(">=", lo), ("<", hi)], ">=": [(">=", lo)], "<": [("<", _v(lo.major, lo.minor, lo.patch, "0"))],
            ">": [(">=", nxt)], "<=": [("<", hi)]}.get(op)


def _tilde(nums, pre) -> list[Comparator]:
    maj, mi, pa = nums
    if maj is None:
        return []
    if mi is None:
        return [(">=", _v(maj, 0, 0)), ("<", _v(maj + 1, 0, 0, "0"))]
    return [(">=", _v(maj, mi, pa or 0, pre if pa is not None else None)), ("<", _v(maj, mi + 1, 0, "0"))]


def _caret(nums, pre) -> list[Comparator]:
    maj, mi, pa = nums
    if maj is None:
        return []
    lo = _v(maj, mi or 0, pa or 0, pre if pa is not None else None)
    if maj > 0 or mi is None:
        hi = _v(maj + 1, 0, 0, "0")
    elif mi > 0 or pa is None:
        hi = _v(0, mi + 1, 0, "0")
    else:
        hi = _v(0, 0, pa + 1, "0")
    return [(">=", lo), ("<", hi)]


def _hyphen(a: str, b: str) -> Optional[list[Comparator]]:
    pa, pb = _partial(a), _partial(b)
    if pa is None or pb is None:
        return None
    lo = _xrange(">=", *pa)
    (bmaj, bmi, bpa), bpre = pb
    if bmaj is None:
        hi: list[Comparator] = []
    elif bmi is None:
        hi = [("<", _v(bmaj + 1, 0, 0, "0"))]
    elif bpa is None:
        hi = [("<", _v(bmaj, bmi + 1, 0, "0"))]
    else:
        hi = [("<=", _v(bmaj, bmi, bpa, bpre))]
    return None if lo is None else lo + hi


def _comparator_set(text: str) -> Optional[list[Comparator]]:
    text = text.strip()
    if not text:
        return []
    h = re.match(r"^(\S+)\s+-\s+(\S+)$", text)
    if h:
        return _hyphen(h.group(1), h.group(2))
    text = re.sub(r"(<=|>=|<|>|=|~>?|\^)\s+", r"\1", text)   # ">= 1.2" -> ">=1.2"
    out: list[Comparator] = []
    for tok in text.split():
        if tok.startswith("~"):
            p = _partial(tok.lstrip("~>"))
            if p is None:
                return None
            out += _tilde(*p)
            continue
        if tok.startswith("^"):
            p = _partial(tok[1:])
            if p is None:
                return None
            out += _caret(*p)
            continue
        m = _COMP.match(tok)
        p = _partial(m.group("ver")) if m else None
        if p is None:
            return None
        part = _xrange(m.group("op") or "", *p)
        if part is None:
            return None
        out += part
    return out


def satisfies_evidence_range(version: str, rng: str) -> Optional[bool]:
    """An affected range from an evidence record. The adapters write OSV intervals in the comma
    form (``>=1.0.0,<1.2.3``, D-046), which means AND; read it as the space-separated npm form.
    Pre-releases inside the interval are covered (node-semver ``includePrerelease``)."""
    if not isinstance(rng, str):
        return None
    # OSV intervals order versions by SemVer precedence and include pre-releases, so the
    # node-semver rule for declared ranges (pre-releases left out) does not apply (D-058).
    return satisfies(version, " || ".join(" ".join(p.strip() for p in part.split(",")) for part in rng.split("||")),
                     include_prerelease=True)


def _ok(v: Version, op: str, c: Version) -> bool:
    cmp = v.compare(c)
    return {"<": cmp < 0, "<=": cmp <= 0, ">": cmp > 0, ">=": cmp >= 0, "=": cmp == 0}[op]


def satisfies(version: str, rng: str, *, include_prerelease: bool = False) -> Optional[bool]:
    """True/False if ``version`` is allowed by the npm range ``rng``; None if either cannot be read.
    ``include_prerelease`` drops node-semver's pre-release rule (used for evidence ranges)."""
    v = parse_version(version)
    if v is None or not isinstance(rng, str):
        return None
    sets = [_comparator_set(part) for part in rng.split("||")]
    if any(s is None for s in sets):
        return None
    for s in sets:
        if not all(_ok(v, op, c) for op, c in s):
            continue
        if v.prerelease and not include_prerelease and not any(c.prerelease and (c.major, c.minor, c.patch) == (v.major, v.minor, v.patch)
                                    for _, c in s):
            continue
        return True
    return False
