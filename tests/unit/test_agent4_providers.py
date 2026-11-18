"""Groq and Gemini adapters (D-064): request shape, response parsing, failure codes, key
handling, model pinning, throttling and the secrets loader. A fake transport replaces the
network; the keys are fake test values. No network, no real secrets file.
"""

import json
import socket
import urllib.error
import urllib.request

import pytest

from multi_agentic_security.agents.agent4_recommendation import (
    LLMError, LLMOptions, LLMRequest, LLMTimeout, MemoryResponseStore, recommend,
)
from multi_agentic_security.agents.agent4_recommendation.providers import (
    GeminiClient, GroqClient, load_secrets, urllib_transport,
)

FAKE_GROQ = "test-groq-key-not-real"
FAKE_GEMINI = "test-gemini-key-not-real"
REQ = LLMRequest(system="SYS", messages=(("user", "U1"), ("assistant", "A1"), ("user", "U2")), temperature=0.0,
                 seed=7, max_output_tokens=300, timeout_s=12.0)


@pytest.fixture(autouse=True)
def env(monkeypatch):
    import socket as s

    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(s, "socket", refuse)
    monkeypatch.setattr(s, "create_connection", refuse)
    monkeypatch.setattr(s, "getaddrinfo", refuse)
    for name in ("AGENT4_GROQ_MODEL", "AGENT4_GEMINI_MODEL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AGENT4_GROQ_API_KEY", FAKE_GROQ)
    monkeypatch.setenv("AGENT4_GEMINI_API_KEY", FAKE_GEMINI)


class Fake:
    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def __call__(self, url, headers, body, timeout):
        self.calls.append((url, dict(headers), json.loads(body), timeout))
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        status, obj = a
        return status, (obj if isinstance(obj, bytes) else json.dumps(obj).encode())


def groq_ok(text='{"action": "keep"}', finish="stop", **msg):
    return 200, {"id": "chatcmpl-1", "choices": [{"message": {"content": text, **msg}, "finish_reason": finish}],
                 "usage": {"prompt_tokens": 11, "completion_tokens": 5}}


def gemini_ok(parts=None, finish="STOP"):
    return 200, {"responseId": "r-1", "candidates": [{"content": {"parts": parts or [{"text": '{"action": "keep"}'}]},
                                                     "finishReason": finish}],
                 "usageMetadata": {"promptTokenCount": 20, "candidatesTokenCount": 4, "thoughtsTokenCount": 9}}


# --------------------------------------------------------------------------- Groq

def test_groq_request_shape_and_parsing():
    t = Fake(groq_ok())
    c = GroqClient("openai/gpt-oss-20b", transport=t, min_interval_s=0)
    r = c.generate(REQ)
    url, headers, body, timeout = t.calls[0]
    assert url == "https://api.groq.com/openai/v1/chat/completions" and timeout == 12.0
    assert headers["Authorization"] == f"Bearer {FAKE_GROQ}"
    assert body["model"] == "openai/gpt-oss-20b" and body["seed"] == 7 and body["max_tokens"] == 300
    assert [m["role"] for m in body["messages"]] == ["system", "user", "assistant", "user"]
    assert "response_format" not in body           # no JSON mode (D-064)
    assert (r.text, r.stop_reason, r.provider_response_id) == ('{"action": "keep"}', "end", "chatcmpl-1")
    assert dict(r.usage) == {"input_tokens": 11, "output_tokens": 5}


@pytest.mark.parametrize("answer,stop", [(groq_ok(finish="length"), "length"),
                                         (groq_ok(finish="content_filter"), "refusal"),
                                         (groq_ok(refusal="no"), "refusal"),
                                         (groq_ok(finish="tool_calls"), "other")])
def test_groq_stop_reasons(answer, stop):
    assert GroqClient("m-1", transport=Fake(answer), min_interval_s=0).generate(REQ).stop_reason == stop


# --------------------------------------------------------------------------- Gemini

def test_gemini_request_shape_and_parsing_key_only_in_header():
    t = Fake(gemini_ok(parts=[{"text": "thinking...", "thought": True}, {"text": '{"action": '}, {"text": '"keep"}'}]))
    c = GeminiClient("gemini-2.5-flash", transport=t, min_interval_s=0)
    r = c.generate(REQ)
    url, headers, body, _ = t.calls[0]
    assert url == "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    assert FAKE_GEMINI not in url and headers["x-goog-api-key"] == FAKE_GEMINI
    assert body["systemInstruction"] == {"parts": [{"text": "SYS"}]}
    assert [c["role"] for c in body["contents"]] == ["user", "model", "user"]
    assert body["generationConfig"] == {"temperature": 0.0, "maxOutputTokens": 300, "seed": 7}
    assert "responseMimeType" not in body["generationConfig"]
    assert r.text == '{"action": "keep"}' and r.stop_reason == "end"     # thought parts are not the answer
    assert dict(r.usage) == {"input_tokens": 20, "output_tokens": 4, "thinking_tokens": 9}


@pytest.mark.parametrize("answer,stop", [
    (gemini_ok(finish="MAX_TOKENS"), "length"),
    (gemini_ok(finish="SAFETY"), "refusal"),
    ((200, {"promptFeedback": {"blockReason": "SAFETY"}}), "refusal"),
    (gemini_ok(finish="OTHER"), "other"),
])
def test_gemini_stop_reasons(answer, stop):
    assert GeminiClient("gemini-2.5-flash", transport=Fake(answer), min_interval_s=0).generate(REQ).stop_reason == stop


def test_gemini_accepts_models_prefix():
    assert GeminiClient("models/gemini-2.5-flash", transport=Fake(), min_interval_s=0).model == "gemini-2.5-flash"


# --------------------------------------------------------------------------- failures

@pytest.mark.parametrize("cls,model", [(GroqClient, "m-1"), (GeminiClient, "gemini-2.5-flash")])
@pytest.mark.parametrize("answer,code", [((429, {"error": {"message": FAKE_GROQ}}), "http_429"),
                                         ((500, b"oops"), "http_500"), ((401, b""), "http_401"),
                                         ((200, b"not json"), "invalid_provider_response"),
                                         ((200, {"choices": []}), "invalid_provider_response")])
def test_http_and_shape_errors_are_llm_errors_with_codes_only(cls, model, answer, code):
    with pytest.raises(LLMError) as e:
        cls(model, transport=Fake(answer), min_interval_s=0).generate(REQ)
    assert e.value.code == code and FAKE_GROQ not in str(e.value) and FAKE_GEMINI not in str(e.value)


def test_missing_key_is_a_configuration_error_naming_the_variable_only(monkeypatch):
    monkeypatch.delenv("AGENT4_GROQ_API_KEY")
    with pytest.raises(ValueError, match="AGENT4_GROQ_API_KEY is not set"):
        GroqClient("m-1")


def test_key_removed_after_construction_is_llm_error(monkeypatch):
    c = GroqClient("m-1", transport=Fake(groq_ok()), min_interval_s=0)
    monkeypatch.delenv("AGENT4_GROQ_API_KEY")
    with pytest.raises(LLMError) as e:
        c.generate(REQ)
    assert e.value.code == "missing_api_key"


@pytest.mark.parametrize("cls,bad", [(GroqClient, ""), (GroqClient, "llama-latest"), (GroqClient, "a b"),
                                     (GeminiClient, "gemini-flash-latest"), (GeminiClient, "../x"),
                                     (GeminiClient, "Gemini Flash")])
def test_only_exact_model_ids_are_accepted(cls, bad):
    with pytest.raises(ValueError):
        cls(bad)


def test_model_from_environment(monkeypatch):
    monkeypatch.setenv("AGENT4_GROQ_MODEL", "openai/gpt-oss-20b")
    assert GroqClient(transport=Fake()).model == "openai/gpt-oss-20b"


def test_key_is_never_stored_or_shown():
    c = GroqClient("m-1", transport=Fake())
    assert FAKE_GROQ not in repr(c) and FAKE_GROQ not in json.dumps(vars(c), default=str)


def test_throttle_spaces_calls():
    now = [100.0]
    slept = []
    c = GroqClient("m-1", transport=Fake(groq_ok(), groq_ok()), min_interval_s=2.5, clock=lambda: now[0],
                   sleep=lambda s: slept.append(s))
    c.generate(REQ)
    now[0] += 1.0
    c.generate(REQ)
    assert slept == [pytest.approx(1.5)]


# --------------------------------------------------------------------------- transport

def test_urllib_transport_maps_failures(monkeypatch):
    def timeout(*a, **k):
        raise socket.timeout()
    monkeypatch.setattr(urllib.request, "urlopen", timeout)
    with pytest.raises(LLMTimeout):
        urllib_transport("https://x", {}, b"{}", 1.0)

    def refused(*a, **k):
        raise urllib.error.URLError(ConnectionRefusedError())
    monkeypatch.setattr(urllib.request, "urlopen", refused)
    with pytest.raises(LLMError) as e:
        urllib_transport("https://x", {}, b"{}", 1.0)
    assert e.value.code == "connection_error" and e.value.__cause__ is None

    def http(*a, **k):
        raise urllib.error.HTTPError("https://x", 429, "Too Many", {}, None)
    monkeypatch.setattr(urllib.request, "urlopen", http)
    assert urllib_transport("https://x", {}, b"{}", 1.0) == (429, b"")


# --------------------------------------------------------------------------- secrets loader

def test_load_secrets_sets_known_names_only_and_never_overwrites(tmp_path):
    f = tmp_path / "secrets.txt"
    f.write_text("# comment\nAGENT4_GROQ_API_KEY='abc'\nexport AGENT4_GEMINI_MODEL=gemini-2.5-flash\n"
                 "OTHER_SECRET=zzz\nAGENT4_GEMINI_API_KEY=\nAGENT4_GROQ_MODEL=keep-me\n", encoding="utf-8")
    env = {"AGENT4_GROQ_MODEL": "already-set"}
    names = load_secrets(f, environ=env)
    assert names == ["AGENT4_GROQ_API_KEY", "AGENT4_GEMINI_MODEL"]
    assert env == {"AGENT4_GROQ_MODEL": "already-set", "AGENT4_GROQ_API_KEY": "abc",
                   "AGENT4_GEMINI_MODEL": "gemini-2.5-flash"}


# --------------------------------------------------------------------------- end to end, no key in any record

def test_recommend_with_adapter_records_no_key():
    from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files
    from multi_agentic_security.agents.agent2_registry import verify
    from multi_agentic_security.agents.agent3_risk import assess
    from test_agent3_review import T0, Client, found, store_of

    store = store_of()
    ex = extract_files("p", [UploadedFile("requirements.txt", b"plain==1.0\n")], clock=lambda: T0)
    rg = verify(ex, mode="snapshot", client=Client({("pypi", "plain"): found("plain", ["1.0"])}),
                evidence_store=store, clock=lambda: T0)
    rr = assess(ex, rg, evidence_store=store, clock=lambda: T0)
    t = Fake(groq_ok('{"action": "keep", "claims": [{"type": "no_evidence_found", "subject": "plain"}]}'),
             (429, {"error": FAKE_GROQ}), (429, b""), (429, b""))
    raw = MemoryResponseStore()
    rs = recommend(ex, rg, rr, evidence_store=store, variant="LLM-G", llm=GroqClient("m-1", transport=t,
                   min_interval_s=0), response_store=raw, options=LLMOptions(), clock=lambda: T0)
    assert rs.recommendations[0].action == "keep" and rs.recommendations[0].model == "groq/m-1"
    everything = rs.model_dump_json() + json.dumps(raw.records)
    assert FAKE_GROQ not in everything
