"""Hosted LLM adapter for Agent 4: Groq (D-064, D-068).

This is the only Agent 4 module that touches the network. The adapter implements
``LLMClient`` (``llm.py``):

* the API key is read from the environment **at each call** and sent only in a request
  header (never in the URL); it is never stored on the object, never put in an exception
  message and never written to a raw-response record;
* the model is an exact identifier from the constructor or the environment; aliases that
  move (``latest``) are refused, because results must be tied to one model version;
* HTTP errors, timeouts and malformed provider answers raise ``LLMError`` / ``LLMTimeout``
  with a short machine code only (``http_429``, ``timeout``, ``invalid_provider_response``);
* calls are spaced by ``min_interval_s`` to stay inside free-tier rate limits.

No output-format constraint (JSON mode) is requested, so every model is measured on the
same prompt-only instruction (D-064).

``load_secrets(path)`` reads ``KEY=VALUE`` lines from the local, git-ignored secrets file
into the process environment, only for the names in ``llm.ENV_VARS``; it returns the
names it set, never the values.

The request and response shapes follow Groq's public documentation (OpenAI-compatible chat
completions endpoint); they are tested against recorded shapes and the first live calls
(TRIAL-001).
"""

from __future__ import annotations

import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Mapping, Optional, Union

from .llm import ENV_VARS, LLMError, LLMRequest, LLMResponse, LLMTimeout

Transport = Callable[[str, Mapping[str, str], bytes, float], tuple[int, bytes]]
MAX_RESPONSE_BYTES = 2_000_000
USER_AGENT = "multi-agentic-security-research/0.1"
_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]{0,127}$")


def urllib_transport(url: str, headers: Mapping[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
    """POST ``body`` and return (HTTP status, response bytes). Errors become LLMError/LLMTimeout."""
    # A generic client name: providers' web firewalls block Python's default user-agent
    # (Groq answered HTTP 403, "error code: 1010", in TRIAL-001; D-064).
    merged = {"User-Agent": USER_AGENT, **dict(headers)}
    req = urllib.request.Request(url, data=body, headers=merged, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        try:
            data = exc.read(MAX_RESPONSE_BYTES) if exc.fp is not None else b""
        except OSError:
            data = b""
        return exc.code, data
    except (socket.timeout, TimeoutError):
        raise LLMTimeout(code="timeout") from None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            raise LLMTimeout(code="timeout") from None
        raise LLMError(code="connection_error") from None
    except OSError:
        raise LLMError(code="connection_error") from None


def load_secrets(path: Union[str, Path], *, environ: Optional[dict] = None) -> list[str]:
    """Set the Agent 4 variables from a ``KEY=VALUE`` file; existing values win. Returns names only."""
    env = os.environ if environ is None else environ
    loaded = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip().removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if name in ENV_VARS and value and name not in env:
            env[name] = value
            loaded.append(name)
    return loaded


def _pinned(model: Optional[str], var: str, pattern: re.Pattern) -> str:
    model = (model if model is not None else os.environ.get(var, "")).strip()
    if not model:
        raise ValueError(f"no model given and {var} is not set")
    if not pattern.match(model) or "latest" in model.lower():
        raise ValueError(f"model {model!r} is not an exact, pinned model identifier")
    return model


def _status_error(status: int) -> LLMError:
    return LLMError(code=f"http_{status}")


def _json(data: bytes) -> dict:
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise LLMError(code="invalid_provider_response") from None
    if not isinstance(obj, dict):
        raise LLMError(code="invalid_provider_response")
    return obj


class _Hosted:
    provider = ""
    key_vars: tuple[str, ...] = ()

    def __init__(self, model: str, *, key_vars: Optional[tuple[str, ...]] = None,
                 transport: Optional[Transport] = None, min_interval_s: float = 0.0,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        if key_vars is not None:
            self.key_vars = key_vars
        if not any(os.environ.get(v) for v in self.key_vars):
            raise ValueError(f"none of {', '.join(self.key_vars)} is set")   # names only, never a value
        self.model = model
        self._transport = transport or urllib_transport
        self._min_interval = float(min_interval_s)
        self._clock, self._sleep = clock, sleep
        self._last: Optional[float] = None
        self._cooldown_until = 0.0
        self._failures = 0

    def __repr__(self) -> str:
        return f"{type(self).__name__}(model={self.model!r})"

    def _key(self) -> str:
        """The first of this client's key variables that is set, read now and never stored."""
        for var in self.key_vars:
            key = os.environ.get(var, "")
            if key:
                return key
        raise LLMError(code="missing_api_key")

    def _throttle(self) -> None:
        wait = max(self._cooldown_until - self._clock(), 0.0)
        if self._last is not None and self._min_interval > 0:
            wait = max(wait, self._min_interval - (self._clock() - self._last))
        if wait > 0:
            self._sleep(wait)
        self._last = self._clock()

    def _back_off(self) -> None:
        """After a 429, 5xx or timeout wait progressively longer before the next call (D-065):
        10 s, 20 s, 40 s, ... at most 120 s. A success resets it."""
        self._failures += 1
        self._cooldown_until = self._clock() + min(10.0 * 2 ** (self._failures - 1), 120.0)

    def _post(self, url: str, headers: dict, payload: dict, timeout: float) -> dict:
        self._throttle()
        try:
            status, data = self._transport(url, headers, json.dumps(payload).encode("utf-8"), timeout)
        except LLMError:        # timeout or connection error
            self._back_off()
            raise
        if status in (429, 500, 502, 503, 504):
            self._back_off()
        if status != 200:
            raise _status_error(status)
        self._failures, self._cooldown_until = 0, 0.0
        return _json(data)


class GroqClient(_Hosted):
    """Groq's OpenAI-compatible chat completions API (hosted open-weight models)."""

    provider = "groq"
    # Each model slot has its own key variable, with the single-key name as a fallback; slot 2 never
    # falls back to slot 1's key, and keys are never rotated across requests or models (D-069).
    SLOT_KEYS = {"AGENT4_GROQ_MODEL": ("AGENT4_GROQ_API_KEY1", "AGENT4_GROQ_API_KEY"),
                 "AGENT4_GROQ_MODEL_2": ("AGENT4_GROQ_API_KEY2", "AGENT4_GROQ_API_KEY")}
    URL = "https://api.groq.com/openai/v1/chat/completions"
    FINISH = {"stop": "end", "length": "length", "content_filter": "refusal"}

    def __init__(self, model: Optional[str] = None, *, model_var: str = "AGENT4_GROQ_MODEL",
                 min_interval_s: float = 2.5, **kw):
        """``model`` is an exact identifier, or it is read from the variable ``model_var``
        (``AGENT4_GROQ_MODEL`` or ``AGENT4_GROQ_MODEL_2``): Groq limits apply per model, so a second
        model of another family on the same account is a second client with its own variable."""
        if model_var not in self.SLOT_KEYS:
            raise ValueError("model_var must be AGENT4_GROQ_MODEL or AGENT4_GROQ_MODEL_2")
        super().__init__(_pinned(model, model_var, _MODEL_ID), key_vars=self.SLOT_KEYS[model_var],
                         min_interval_s=min_interval_s, **kw)

    def generate(self, request: LLMRequest) -> LLMResponse:
        payload = {"model": self.model, "stream": False, "temperature": request.temperature,
                   "max_tokens": request.max_output_tokens,
                   "messages": [{"role": "system", "content": request.system}] +
                               [{"role": role, "content": text} for role, text in request.messages]}
        if request.seed is not None:
            payload["seed"] = request.seed
        obj = self._post(self.URL, {"Authorization": f"Bearer {self._key()}", "Content-Type": "application/json"},
                         payload, request.timeout_s)
        try:
            choice = obj["choices"][0]
            message = choice.get("message") or {}
            text = message.get("content") or ""
            finish = choice.get("finish_reason")
        except (KeyError, IndexError, TypeError, AttributeError):
            raise LLMError(code="invalid_provider_response") from None
        if not isinstance(text, str):
            raise LLMError(code="invalid_provider_response")
        stop = "refusal" if message.get("refusal") else self.FINISH.get(finish, "other")
        usage = obj.get("usage") if isinstance(obj.get("usage"), dict) else {}
        return LLMResponse(text=text, stop_reason=stop, provider_response_id=_str(obj.get("id")),
                           usage=_ints({"input_tokens": usage.get("prompt_tokens"),
                                        "output_tokens": usage.get("completion_tokens")}))


def _str(v) -> Optional[str]:
    return v[:200] if isinstance(v, str) else None


def _ints(d: dict) -> dict:
    return {k: v for k, v in d.items() if isinstance(v, int) and not isinstance(v, bool)}
