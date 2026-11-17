"""Parsing an LLM answer into a ``Recommendation`` (D-062).

The answer must be one JSON object (optionally inside a single ```json fence) with the
fields of the output schema in ``prompt.SYSTEM``; unknown fields, wrong types, an invalid
package name or a combination the contract forbids (an upgrade without a version, a
target on ``keep``) are a schema violation. ``{"refusal": "..."}`` is a refusal.

Cited evidence IDs are kept exactly as given, even when they were not in the input:
removing them would hide the unsupported-claim rate that RQ1a measures. Agent 4 flags
them (``a4.llm.cited_not_given``); Agent 5 and the scorer judge them.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from multi_agentic_security.contracts.pipeline import Action, Claim, ClaimType, PackageRef, Target

MAX_ANSWER_CHARS = 32_000
_FENCE = re.compile(r"^```(?:json)?\s*\n(.*)\n```$", re.DOTALL)


class SchemaViolation(Exception):
    pass


class Refusal(Exception):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _Target(_Strict):
    package: str = Field(min_length=1, max_length=214)
    version: Optional[str] = Field(default=None, min_length=1, max_length=128)


class _Claim(_Strict):
    type: ClaimType
    subject: str = Field(min_length=1, max_length=214)
    object: Optional[str] = Field(default=None, min_length=1, max_length=214)
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)


class _Answer(_Strict):
    action: Action
    target: Optional[_Target] = None
    claims: list[_Claim] = Field(default_factory=list, max_length=20)
    rationale: Optional[str] = Field(default=None, max_length=2000)
    uncertainty: Optional[str] = Field(default=None, max_length=1000)


def _first_error(exc: ValidationError) -> str:
    e = exc.errors()[0] if exc.errors() else {}
    return f"{'.'.join(str(p) for p in e.get('loc', ())) or 'answer'}: {e.get('msg', 'invalid')}"


def parse_answer(text: str, ecosystem: str) -> dict:
    """Fields for ``Recommendation`` (action, target, claims, rationale, uncertainty).
    Raises ``SchemaViolation`` or ``Refusal``."""
    if not isinstance(text, str) or not text.strip():
        raise SchemaViolation("empty answer")
    if len(text) > MAX_ANSWER_CHARS:
        raise SchemaViolation(f"answer longer than {MAX_ANSWER_CHARS} characters")
    body = text.strip()
    m = _FENCE.match(body)
    if m:
        body = m.group(1).strip()
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise SchemaViolation(f"not a JSON object ({type(exc).__name__})")
    if not isinstance(obj, dict):
        raise SchemaViolation("the answer is not a JSON object")
    if set(obj) == {"refusal"}:
        raise Refusal(str(obj["refusal"])[:300])
    try:
        ans = _Answer.model_validate(obj)
    except ValidationError as exc:
        raise SchemaViolation(_first_error(exc))
    try:
        target = (Target(package=PackageRef.of(ecosystem, ans.target.package), version=ans.target.version)
                  if ans.target is not None else None)
        claims = [Claim(type=c.type, subject=PackageRef.of(ecosystem, c.subject), object=c.object,
                        evidence_ids=list(c.evidence_ids)) for c in ans.claims]
    except (ValueError, ValidationError) as exc:
        raise SchemaViolation(f"invalid package name ({str(exc)[:120]})")
    return {"action": ans.action, "target": target, "claims": claims, "rationale": ans.rationale,
            "uncertainty": ans.uncertainty}
