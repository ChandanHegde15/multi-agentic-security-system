"""Provider-independent LLM interface for Agent 4 (D-022, D-038, D-062).

Agent 4 talks to every model through ``LLMClient.generate(LLMRequest) -> LLMResponse``.
Provider adapters (``providers.py``: Groq, D-064, D-068) map this to their own API,
enforce ``request.timeout_s`` and raise ``LLMTimeout`` or ``LLMError``; they read their
API key from the environment at call time and never record it.

``RecordedLLMClient`` replays recorded responses (tests, and re-running a finished
experiment without calling the provider again). ``ResponseStore`` keeps every raw
response; a recommendation refers to it by ``raw_response_ref``.

Environment variable names (values only in the git-ignored local secrets file; no
template is kept in the repository, D-064): ``AGENT4_GROQ_API_KEY1`` and ``AGENT4_GROQ_MODEL`` (or the single ``AGENT4_GROQ_API_KEY``), optionally
``AGENT4_GROQ_API_KEY2`` with ``AGENT4_GROQ_MODEL_2`` for a second model, and optionally
``AGENT4_LLM_TIMEOUT_SECONDS``, ``AGENT4_LLM_MAX_OUTPUT_TOKENS``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Protocol, Union, runtime_checkable

ENV_VARS = ("AGENT4_GROQ_API_KEY", "AGENT4_GROQ_API_KEY1", "AGENT4_GROQ_API_KEY2", "AGENT4_GROQ_MODEL", "AGENT4_GROQ_MODEL_2", "AGENT4_LLM_TIMEOUT_SECONDS",
            "AGENT4_LLM_MAX_OUTPUT_TOKENS")
STOP_REASONS = ("end", "length", "refusal", "other")
RAW_FORMAT = "a4_raw_response/1"


_CODE = re.compile(r"^[a-z0-9_.-]{1,40}$")


class LLMError(Exception):
    """The provider call failed (connection, HTTP error, quota, malformed provider answer).

    Only the exception type and ``code`` (a short machine code such as ``http_529``) are ever
    recorded; the message is not, because provider messages may echo keys or request data (D-063)."""

    def __init__(self, message: str = "", code: Optional[str] = None):
        super().__init__(message)
        self.code = code if isinstance(code, str) and _CODE.match(code) else None


class LLMTimeout(LLMError):
    """The provider did not answer within ``request.timeout_s``."""


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


@dataclass(frozen=True)
class LLMRequest:
    system: str
    messages: tuple[tuple[str, str], ...]        # (role, text); role 'user' or 'assistant'
    temperature: float = 0.0
    seed: Optional[int] = None
    max_output_tokens: int = 1024
    timeout_s: float = 60.0

    def key(self, provider: str, model: str) -> str:
        """Identifies the exact request to one model (used to replay recorded responses)."""
        body = {"provider": provider, "model": model, "system": self.system, "messages": [list(m) for m in self.messages],
                "temperature": self.temperature, "seed": self.seed, "max_output_tokens": self.max_output_tokens}
        return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()

    def followed_by(self, assistant_text: str, user_text: str) -> "LLMRequest":
        return replace(self, messages=self.messages + (("assistant", assistant_text), ("user", user_text)))


@dataclass(frozen=True)
class LLMResponse:
    text: str
    stop_reason: str = "end"                     # one of STOP_REASONS, mapped by the adapter
    provider_response_id: Optional[str] = None
    usage: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.stop_reason not in STOP_REASONS:
            raise ValueError(f"stop_reason must be one of {STOP_REASONS}")
        if not isinstance(self.text, str):
            raise ValueError("text must be a string")


@runtime_checkable
class LLMClient(Protocol):
    provider: str
    model: str                                   # the exact pinned model identifier

    def generate(self, request: LLMRequest) -> LLMResponse: ...


@dataclass(frozen=True)
class LLMOptions:
    temperature: float = 0.0
    seed: Optional[int] = None
    max_output_tokens: int = 1024
    timeout_s: float = 60.0
    max_schema_retries: int = 2                  # repair requests after a schema violation
    max_transport_retries: int = 2               # repeats after llm_error / llm_timeout
    max_versions_in_prompt: int = 200

    def __post_init__(self) -> None:
        for name in ("max_schema_retries", "max_transport_retries"):
            v = getattr(self, name)
            if not isinstance(v, int) or not 0 <= v <= 5:
                raise ValueError(f"{name} must be an integer between 0 and 5 (bounded retries)")
        if not isinstance(self.max_versions_in_prompt, int) or not 0 <= self.max_versions_in_prompt <= 1000:
            raise ValueError("max_versions_in_prompt must be an integer between 0 and 1000")


Recorded = Union[LLMResponse, Exception]


class RecordedLLMClient:
    """Replays recorded responses; never touches the network.

    ``responses`` is either a mapping ``request key -> response`` (replay of a recorded run)
    or a sequence returned in order (tests). An exception instance is raised instead of
    answering. A request with no recording raises ``LLMError``.
    """

    def __init__(self, provider: str, model: str, responses: Union[Mapping[str, Recorded], Iterable[Recorded]]):
        self.provider, self.model = provider, model
        self._by_key = dict(responses) if isinstance(responses, Mapping) else None
        self._queue = None if self._by_key is not None else list(responses)
        self.requests: list[LLMRequest] = []

    def generate(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        if self._by_key is not None:
            item = self._by_key.get(request.key(self.provider, self.model))
        else:
            item = self._queue.pop(0) if self._queue else None
        if item is None:
            raise LLMError("no recorded response for this request")
        if isinstance(item, Exception):
            raise item
        return item


# --------------------------------------------------------------------------- raw responses

class ResponseStore(Protocol):
    def put(self, record: Mapping[str, Any]) -> str: ...


def _ref(record: Mapping[str, Any]) -> tuple[str, bytes]:
    data = _canonical(dict(record)).encode("utf-8")
    return "a4raw:sha256:" + hashlib.sha256(data).hexdigest(), data


class MemoryResponseStore:
    def __init__(self) -> None:
        self.records: dict[str, dict] = {}

    def put(self, record: Mapping[str, Any]) -> str:
        ref, _ = _ref(record)
        self.records.setdefault(ref, dict(record))
        return ref

    def get(self, ref: str) -> Optional[dict]:
        return self.records.get(ref)


class FileResponseStore:
    """One JSON file per raw response, named by its SHA-256; never overwrites."""

    def __init__(self, folder: Union[str, Path]):
        self.folder = Path(folder)

    def put(self, record: Mapping[str, Any]) -> str:
        ref, data = _ref(record)
        self.folder.mkdir(parents=True, exist_ok=True)
        path = self.folder / (ref.rsplit(":", 1)[1] + ".json")
        if path.exists():
            if path.read_bytes() != data:
                raise LLMError(f"raw response file {path.name} exists with different content")
            return ref
        path.write_bytes(data)
        return ref

    def get(self, ref: str) -> Optional[dict]:
        path = self.folder / (ref.rsplit(":", 1)[1] + ".json")
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def raw_record(request: LLMRequest, client: LLMClient, attempt: int, received_at: datetime,
               response: Optional[LLMResponse] = None, error: Optional[str] = None) -> dict:
    return {"format": RAW_FORMAT, "provider": client.provider, "model": client.model, "attempt": attempt,
            "request_key": request.key(client.provider, client.model),
            "received_at": received_at.astimezone(timezone.utc).isoformat(),
            "stop_reason": response.stop_reason if response is not None else None,
            "provider_response_id": response.provider_response_id if response is not None else None,
            "usage": dict(response.usage) if response is not None else {},
            "text": response.text if response is not None else None, "error": error}
