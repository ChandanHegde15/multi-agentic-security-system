"""Planning LLM calls against free-tier limits (D-067). A pure calculation; makes no call.

Example from TRIAL-001 (Groq ``openai/gpt-oss-20b``, one grounded prompt): about 880 input and
460 output tokens, i.e. about 1,400 tokens per call. With a tokens-per-day limit of 200,000 that is
about 140 calls per day; with 8,000 tokens per minute, about 5 calls per minute.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Limits:
    rpm: Optional[int] = None
    rpd: Optional[int] = None
    tpm: Optional[int] = None
    tpd: Optional[int] = None

    def __post_init__(self) -> None:
        for name in ("rpm", "rpd", "tpm", "tpd"):
            v = getattr(self, name)
            if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 1):
                raise ValueError(f"{name} must be a positive integer or None (D-071 B-3)")


def plan_llm_calls(n_cases: int, *, variants: int = 2, tokens_per_call: int = 1400, limits: Limits,
                   retry_overhead: float = 0.15) -> dict:
    """How many calls, tokens and days a run needs under ``limits``. ``retry_overhead`` is the share of
    extra calls expected from schema repairs and transient errors (an assumption, measured in the pilot)."""
    if n_cases < 0 or variants < 1 or tokens_per_call < 1:
        raise ValueError("n_cases >= 0, variants >= 1 and tokens_per_call >= 1 are required")
    if not (isinstance(retry_overhead, (int, float)) and math.isfinite(retry_overhead) and retry_overhead >= 0):
        raise ValueError("retry_overhead must be a finite number >= 0 (D-071 B-4)")
    calls = math.ceil(n_cases * variants * (1 + retry_overhead))
    tokens = calls * tokens_per_call
    per_day = [calls_ for calls_ in (
        limits.rpd,
        (limits.tpd // tokens_per_call) if limits.tpd else None) if calls_ is not None]
    per_minute = [x for x in (limits.rpm, (limits.tpm // tokens_per_call) if limits.tpm else None) if x is not None]
    calls_per_day = min(per_day) if per_day else None
    calls_per_minute = min(per_minute) if per_minute else None
    # a single call larger than a per-minute or per-day token limit can never be made (D-071 B-1, B-2)
    too_big = [name for name, cap in (("tokens_per_minute", calls_per_minute), ("tokens_per_day", calls_per_day))
               if cap == 0]
    feasible = not too_big
    return {"calls": calls, "tokens": tokens, "feasible": feasible,
            "infeasible_because_one_call_exceeds": too_big,
            "calls_per_day_max": calls_per_day, "calls_per_minute_max": calls_per_minute,
            "days": (math.ceil(calls / calls_per_day) if calls_per_day else None) if feasible else None,
            "minutes_if_one_batch": (math.ceil(calls / calls_per_minute) if calls_per_minute else None) if feasible else None,
            "binding_limit": (None if not feasible else
                              "tokens_per_day" if limits.tpd and calls_per_day == limits.tpd // tokens_per_call
                              else "requests_per_day" if calls_per_day else None)}
