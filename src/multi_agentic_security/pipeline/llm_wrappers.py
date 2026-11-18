"""Cost control for LLM calls (D-066): a response cache and a hard budget.

``BudgetedLLMClient`` counts real calls and output-token requests and refuses further
calls with ``LLMError(code="budget_exhausted")``; Agent 4 turns that into ``llm_error``
-> ``abstain`` (a state, never a default action). ``CachingLLMClient`` replays an
earlier successful answer for the exact same request (provider, model, prompt,
temperature, seed, token limit), so repeating a run costs no calls. Only successful
answers are cached. Order: ``CachingLLMClient(BudgetedLLMClient(real))``, so cache
hits do not use up the budget.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Union

from multi_agentic_security.agents.agent4_recommendation.llm import LLMClient, LLMError, LLMRequest, LLMResponse


class BudgetedLLMClient:
    def __init__(self, inner: LLMClient, *, max_calls: int, max_total_output_tokens: Optional[int] = None):
        if max_calls < 0:
            raise ValueError("max_calls must be >= 0")
        self.inner, self.provider, self.model = inner, inner.provider, inner.model
        self.max_calls, self.max_tokens = max_calls, max_total_output_tokens
        self.calls = 0
        self.tokens_requested = 0

    def generate(self, request: LLMRequest) -> LLMResponse:
        if self.calls >= self.max_calls or (
                self.max_tokens is not None and self.tokens_requested + request.max_output_tokens > self.max_tokens):
            raise LLMError("budget exhausted", code="budget_exhausted")
        self.calls += 1
        self.tokens_requested += request.max_output_tokens
        return self.inner.generate(request)


class CachingLLMClient:
    def __init__(self, inner: LLMClient, folder: Union[str, Path]):
        self.inner, self.provider, self.model = inner, inner.provider, inner.model
        self.folder = Path(folder)
        self.hits = 0
        self.misses = 0

    def _path(self, request: LLMRequest) -> Path:
        return self.folder / (request.key(self.provider, self.model) + ".json")

    def generate(self, request: LLMRequest) -> LLMResponse:
        path = self._path(request)
        if path.is_file():
            try:
                d = json.loads(path.read_text(encoding="utf-8"))
                resp = LLMResponse(text=d["text"], stop_reason=d["stop_reason"],
                                   provider_response_id=d.get("provider_response_id"), usage=d.get("usage") or {})
                self.hits += 1
                return resp
            except (OSError, ValueError, KeyError, TypeError):
                pass   # an unreadable cache entry is a miss, never an answer
        self.misses += 1
        resp = self.inner.generate(request)
        if resp.stop_reason == "end" and resp.text.strip():
            self.folder.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"text": resp.text, "stop_reason": resp.stop_reason,
                                        "provider_response_id": resp.provider_response_id,
                                        "usage": dict(resp.usage)}, ensure_ascii=False), encoding="utf-8")
        return resp
