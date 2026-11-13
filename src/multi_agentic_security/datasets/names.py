"""Package-name normalization (RESEARCH_METHODOLOGY.md section 3, item 1).

PyPI names follow PEP 503: runs of ``-``, ``_`` and ``.`` become a single ``-``
and the result is lower-cased. npm names are lower-cased; a scope
(``@scope/name``) is kept.

Normalization is used only to build join keys. The raw name is always stored
next to the normalized one.
"""

from __future__ import annotations

import re

PYPI = "pypi"
NPM = "npm"
SUPPORTED_ECOSYSTEMS = (PYPI, NPM)

_PEP503_RUN = re.compile(r"[-_.]+")


def normalize_ecosystem(ecosystem: str) -> str:
    """Return the canonical ecosystem key, or raise ``ValueError``."""
    if not isinstance(ecosystem, str):
        raise ValueError(f"ecosystem must be a string, got {type(ecosystem).__name__}")
    key = ecosystem.strip().lower()
    if key not in SUPPORTED_ECOSYSTEMS:
        raise ValueError(f"unsupported ecosystem: {ecosystem!r}")
    return key


def normalize_name(ecosystem: str, raw_name: str) -> str:
    """Return the normalized package name used as a join key."""
    eco = normalize_ecosystem(ecosystem)
    if not isinstance(raw_name, str):
        raise ValueError(f"package name must be a string, got {type(raw_name).__name__}")
    name = raw_name.strip()
    if not name:
        raise ValueError("package name is empty")
    if eco == PYPI:
        return _PEP503_RUN.sub("-", name).lower()
    return name.lower()
