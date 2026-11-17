"""Affected-version ranges from evidence records, read as ordered intervals (D-060).

The adapters write OSV intervals in a comma form (``>=1.0,<2.0``; ``||`` separates
alternatives). OSV orders versions by the ecosystem's precedence and includes
pre-releases, so a range is a plain interval check: ``2.0rc1`` is inside
``>=1.0,<2.0`` (PEP 440 specifier semantics would leave it out, because an
exclusive ``<`` drops pre-releases of its own bound). Shared by Agents 3 and 5.

Anything that cannot be read (an unknown operator, a wildcard, an invalid
version) gives ``None``, never a guess.
"""

from __future__ import annotations

import re
from typing import Callable, Optional

from packaging.version import InvalidVersion, Version

from . import npm_semver

_COMP = re.compile(r"^(<=|>=|==|!=|<|>|=)?\s*(\S+)$")


def _pypi(text: str):
    try:
        return Version(text)
    except InvalidVersion:
        return None


def parser(ecosystem: str) -> Optional[Callable[[str], object]]:
    return {"pypi": _pypi, "npm": npm_semver.parse_version}.get(ecosystem)


def comparators(ecosystem: str, rng: str) -> Optional[list[list[tuple[str, object]]]]:
    """``[[(op, version), ...], ...]``: alternatives of AND-ed comparators, or None."""
    parse = parser(ecosystem)
    if parse is None or not isinstance(rng, str) or not rng.strip():
        return None
    out = []
    for alt in rng.split("||"):
        part = []
        for tok in alt.split(","):
            tok = tok.strip()
            m = _COMP.match(tok)
            if not m or "*" in m.group(2):
                return None
            v = parse(m.group(2))
            if v is None:
                return None
            part.append(({None: "==", "=": "=="}.get(m.group(1), m.group(1)), v))
        if not part:
            return None
        out.append(part)
    return out


def _ok(v, op: str, b) -> bool:
    return {"<": v < b, "<=": v <= b, ">": v > b, ">=": v >= b, "==": v == b, "!=": v != b}[op]


def in_range(ecosystem: str, version: str, rng: str) -> Optional[bool]:
    parse = parser(ecosystem)
    comps = comparators(ecosystem, rng)
    v = parse(version) if parse is not None and isinstance(version, str) else None
    if comps is None or v is None:
        return None
    return any(all(_ok(v, op, b) for op, b in alt) for alt in comps)


def above(ecosystem: str, version: str, rng: str) -> Optional[bool]:
    """True when ``version`` is past every upper bound of the range (a fix, not merely outside it).
    False when it is inside, below, or the range has an alternative without an upper bound."""
    parse = parser(ecosystem)
    comps = comparators(ecosystem, rng)
    v = parse(version) if parse is not None and isinstance(version, str) else None
    if comps is None or v is None:
        return None
    if ecosystem == "pypi" and v.local is not None:
        v = Version(v.public)        # "1.0+cpu" is a build of 1.0, not a fix past it (D-061)
    for alt in comps:
        uppers = [(op, b) for op, b in alt if op in ("<", "<=", "==")]
        if not uppers:
            return False
        if not all((v >= b) if op == "<" else (v > b) for op, b in uppers):
            return False
    return True
