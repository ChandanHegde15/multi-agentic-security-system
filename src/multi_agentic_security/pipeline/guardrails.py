"""Guardrails of the pipeline (D-066).

* input: project ID format, a cap on the number of dependencies when an LLM is used;
* output: no secret-shaped string may appear in anything the pipeline writes;
* every stage output is re-validated against its contract at the stage boundary
  (done in ``graph.py`` with the contract models).
"""

from __future__ import annotations

import re
from typing import Any, Optional

PROJECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# Shapes of API keys and tokens (Groq, Google, OpenAI-style, GitHub, AWS access keys, private key blocks).
SECRET_PATTERNS = (
    re.compile(r"gsk_[A-Za-z0-9]{20,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{24,}"),
)


def check_project_id(project_id: Any) -> Optional[str]:
    if not isinstance(project_id, str) or not PROJECT_ID.match(project_id):
        return "project_id must be 1-64 characters: letters, digits, '.', '_' or '-', starting with a letter or digit"
    return None


def check_dependency_count(n: int, *, llm_used: bool, max_dependencies_llm: int) -> Optional[str]:
    if llm_used and n > max_dependencies_llm:
        return (f"{n} dependencies exceed the limit of {max_dependencies_llm} for a run that calls an LLM; "
                "split the project or use the rule-based variant")
    return None


def find_secret(text: str) -> Optional[str]:
    """Name of the first secret pattern found in ``text`` (never the matched value), or None."""
    for pat in SECRET_PATTERNS:
        if pat.search(text):
            return pat.pattern[:24]
    return None
