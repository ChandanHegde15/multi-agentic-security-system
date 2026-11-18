"""Hosted LLM adapters for Agent 4: Groq and Google Gemini (D-064).

This is the only Agent 4 module that touches the network. Each adapter implements
``LLMClient`` (``llm.py``):

* the API key is read from the environment **at each call** and sent only in a request
  header (never in the URL); it is never stored on the object, never put in an exception
  message and never written to a raw-response record;
* the model is an exact identifier from the constructor or the environment; aliases that
  move (``latest``) are refused, because results must be tied to one model version;
* HTTP errors, timeouts and malformed provider answers raise ``LLMError`` / ``LLMTimeout``
  with a short machine code only (``http_429``, ``timeout``, ``invalid_provider_response``);
* calls are spaced by ``min_interval_s`` to stay inside free-tier rate limits.

No output-format constraint (JSON mode) is requested from either provider, so both are
measured on the same prompt-only instruction (D-064).

``load_secrets(path)`` reads ``KEY=VALUE`` lines from the local, git-ignored secrets file
into the process environment, only for the names in ``llm.ENV_VARS``; it returns the
names it set, never the values.

The request and response shapes follow the providers' public documentation (Groq's
OpenAI-compatible chat completions endpoint, Gemini's ``generateContent``); they are
tested against recorded shapes only, not yet against the live services.
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
_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]{0,127}$")
_GEMINI_MODEL = re.compile(r"^(?:models/)?[a-z0-9][a-z0-9.\-]{0,99}$")


def urllib_transport(url: str, headers: Mapping[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
    """POST ``body`` and return (HTTP status, response bytes). Errors become LLMError/LLMTimeout."""
    req = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
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
    key_var = ""

    def __init__(self, model: str, *, transport: Optional[Transport] = None, min_interval_s: float = 0.0,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        if not os.environ.get(self.key_var):
            raise ValueError(f"{self.key_var} is not set")   # the name only, never a value
        self.model = model
        self._transport = transport or urllib_transport
        self._min_interval = float(min_interval_s)
        self._clock, self._sleep = clock, sleep
        self._last: Optional[float] = None

    def __repr__(self) -> str:
        return f"{type(self).__name__}(model={self.model!r})"

    def _key(self) -> str:
        key = os.environ.get(self.key_var, "")
        if not key:
            raise LLMError(code="missing_api_key")
        return key

    def _throttle(self) -> None:
        if self._last is not None and self._min_interval > 0:
            wait = self._min_interval - (self._clock() - self._last)
            if wait > 0:
                self._sleep(wait)
        self._last = self._clock()

    def _post(self, url: str, headers: dict, payload: dict, timeout: float) -> dict:
        self._throttle()
        status, data = self._transport(url, headers, json.dumps(payload).encode("utf-8"), timeout)
        if status != 200:
            raise _status_error(status)
        return _json(data)


class GroqClient(_Hosted):
    """Groq's OpenAI-compatible chat completions API (hosted open-weight models)."""

    provider = "groq"
    key_var = "AGENT4_GROQ_API_KEY"
    URL = "https://api.groq.com/openai/v1/chat/completions"
    FINISH = {"stop": "end", "length": "length", "content_filter": "refusal"}

    def __init__(self, model: Optional[str] = None, *, min_interval_s: float = 2.5, **kw):
        super().__init__(_pinned(model, "AGENT4_GROQ_MODEL", _MODEL_ID), min_interval_s=min_interval_s, **kw)

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


class GeminiClient(_Hosted):
    """Google Gemini ``generateContent`` API. The key goes in the ``x-goog-api-key`` header."""

    provider = "gemini"
    key_var = "AGENT4_GEMINI_API_KEY"
    URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    FINISH = {"STOP": "end", "MAX_TOKENS": "length", "SAFETY": "refusal", "RECITATION": "refusal",
              "BLOCKLIST": "refusal", "PROHIBITED_CONTENT": "refusal", "SPII": "refusal"}

    def __init__(self, model: Optional[str] = None, *, min_interval_s: float = 6.5, **kw):
        m = _pinned(model, "AGENT4_GEMINI_MODEL", _GEMINI_MODEL)
        super().__init__(m.removeprefix("models/"), min_interval_s=min_interval_s, **kw)

    def generate(self, request: LLMRequest) -> LLMResponse:
        config = {"temperature": request.temperature, "maxOutputTokens": request.max_output_tokens}
        if request.seed is not None:
            config["seed"] = request.seed
        payload = {"systemInstruction": {"parts": [{"text": request.system}]},
                   "contents": [{"role": "user" if role == "user" else "model", "parts": [{"text": text}]}
                                for role, text in request.messages],
                   "generationConfig": config}
        obj = self._post(self.URL.format(model=self.model),
                         {"x-goog-api-key": self._key(), "Content-Type": "application/json"}, payload,
                         request.timeout_s)
        usage = obj.get("usageMetadata") if isinstance(obj.get("usageMetadata"), dict) else {}
        counts = _ints({"input_tokens": usage.get("promptTokenCount"),
                        "output_tokens": usage.get("candidatesTokenCount"),
                        "thinking_tokens": usage.get("thoughtsTokenCount")})
        rid = _str(obj.get("responseId"))
        feedback = obj.get("promptFeedback") if isinstance(obj.get("promptFeedback"), dict) else {}
        candidates = obj.get("candidates")
        if feedback.get("blockReason") and not candidates:
            return LLMResponse(text="", stop_reason="refusal", provider_response_id=rid, usage=counts)
        try:
            cand = candidates[0]
            parts = (cand.get("content") or {}).get("parts") or []
            text = "".join(p.get("text", "") for p in parts if isinstance(p, dict) and not p.get("thought"))
            finish = cand.get("finishReason")
        except (KeyError, IndexError, TypeError, AttributeError):
            raise LLMError(code="invalid_provider_response") from None
        return LLMResponse(text=text, stop_reason=self.FINISH.get(finish, "other"), provider_response_id=rid,
                           usage=counts)


def _str(v) -> Optional[str]:
    return v[:200] if isinstance(v, str) else None


def _ints(d: dict) -> dict:
    return {k: v for k, v in d.items() if isinstance(v, int) and not isinstance(v, bool)}
