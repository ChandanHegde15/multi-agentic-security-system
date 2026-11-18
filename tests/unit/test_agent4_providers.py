"""Groq adapter (D-064, D-068): request shape, response parsing, failure codes, key
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
    GroqClient, load_secrets, urllib_transport,
)

FAKE_GROQ = "test-groq-key-not-real"
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
    monkeypatch.delenv("AGENT4_GROQ_MODEL", raising=False)
    monkeypatch.delenv("AGENT4_GROQ_MODEL_2", raising=False)
    monkeypatch.setenv("AGENT4_GROQ_API_KEY", FAKE_GROQ)


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


# --------------------------------------------------------------------------- failures

@pytest.mark.parametrize("answer,code", [((429, {"error": {"message": FAKE_GROQ}}), "http_429"),
                                         ((500, b"oops"), "http_500"), ((401, b""), "http_401"),
                                         ((200, b"not json"), "invalid_provider_response"),
                                         ((200, {"choices": []}), "invalid_provider_response")])
def test_http_and_shape_errors_are_llm_errors_with_codes_only(answer, code):
    with pytest.raises(LLMError) as e:
        GroqClient("m-1", transport=Fake(answer), min_interval_s=0).generate(REQ)
    assert e.value.code == code and FAKE_GROQ not in str(e.value)


def test_missing_key_is_a_configuration_error_naming_the_variable_only(monkeypatch):
    monkeypatch.delenv("AGENT4_GROQ_API_KEY")
    with pytest.raises(ValueError, match="none of AGENT4_GROQ_API_KEY1, AGENT4_GROQ_API_KEY is set"):
        GroqClient("m-1")


def test_key_removed_after_construction_is_llm_error(monkeypatch):
    c = GroqClient("m-1", transport=Fake(groq_ok()), min_interval_s=0)
    monkeypatch.delenv("AGENT4_GROQ_API_KEY")
    with pytest.raises(LLMError) as e:
        c.generate(REQ)
    assert e.value.code == "missing_api_key"


@pytest.mark.parametrize("bad", ["", "llama-latest", "a b", "../x", "Groq Model"])
def test_only_exact_model_ids_are_accepted(bad):
    with pytest.raises(ValueError):
        GroqClient(bad)


def test_each_model_slot_uses_its_own_key_and_never_the_others(monkeypatch):
    k1, k2 = "test-key-one-not-real", "test-key-two-not-real"
    monkeypatch.delenv("AGENT4_GROQ_API_KEY")
    monkeypatch.setenv("AGENT4_GROQ_API_KEY1", k1)
    monkeypatch.setenv("AGENT4_GROQ_API_KEY2", k2)
    monkeypatch.setenv("AGENT4_GROQ_MODEL", "openai/gpt-oss-20b")
    monkeypatch.setenv("AGENT4_GROQ_MODEL_2", "qwen/qwen3.8-27b")
    t1, t2 = Fake(groq_ok()), Fake(groq_ok())
    GroqClient(transport=t1, min_interval_s=0).generate(REQ)
    GroqClient(model_var="AGENT4_GROQ_MODEL_2", transport=t2, min_interval_s=0).generate(REQ)
    assert t1.calls[0][1]["Authorization"] == f"Bearer {k1}" and t1.calls[0][2]["model"] == "openai/gpt-oss-20b"
    assert t2.calls[0][1]["Authorization"] == f"Bearer {k2}" and t2.calls[0][2]["model"] == "qwen/qwen3.8-27b"
    # no rotation: repeated calls on one client keep using that client's key
    t3 = Fake(groq_ok(), groq_ok())
    c = GroqClient(transport=t3, min_interval_s=0)
    c.generate(REQ), c.generate(REQ)
    assert {x[1]["Authorization"] for x in t3.calls} == {f"Bearer {k1}"}
    assert k1 not in repr(c) and k2 not in repr(c) and k1 not in json.dumps(vars(c), default=str)


def test_slot_two_does_not_borrow_slot_ones_key_but_the_single_key_name_is_a_fallback(monkeypatch):
    monkeypatch.delenv("AGENT4_GROQ_API_KEY")
    monkeypatch.setenv("AGENT4_GROQ_API_KEY1", "test-key-one-not-real")
    monkeypatch.setenv("AGENT4_GROQ_MODEL_2", "qwen/qwen3.8-27b")
    with pytest.raises(ValueError, match="none of AGENT4_GROQ_API_KEY2, AGENT4_GROQ_API_KEY is set"):
        GroqClient(model_var="AGENT4_GROQ_MODEL_2")
    monkeypatch.setenv("AGENT4_GROQ_API_KEY", "test-single-key-not-real")
    t = Fake(groq_ok())
    GroqClient(model_var="AGENT4_GROQ_MODEL_2", transport=t, min_interval_s=0).generate(REQ)
    assert t.calls[0][1]["Authorization"] == "Bearer test-single-key-not-real"


def test_second_model_variable_and_no_other_variable_names(monkeypatch):
    monkeypatch.setenv("AGENT4_GROQ_MODEL", "openai/gpt-oss-20b")
    monkeypatch.setenv("AGENT4_GROQ_MODEL_2", "qwen/qwen3.8-27b")
    assert GroqClient(model_var="AGENT4_GROQ_MODEL_2", transport=Fake()).model == "qwen/qwen3.8-27b"
    assert GroqClient(transport=Fake()).model == "openai/gpt-oss-20b"
    with pytest.raises(ValueError):
        GroqClient(model_var="PATH")


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

def test_backoff_after_429_grows_and_success_resets_it():
    now = [0.0]
    slept = []

    def sleep(s):
        slept.append(round(s, 1))
        now[0] += s
    t = Fake((429, b""), (429, b""), (503, b""), groq_ok(), (429, b""), groq_ok())
    c = GroqClient("m-1", transport=t, min_interval_s=0, clock=lambda: now[0], sleep=sleep)
    for expect_ok in (False, False, False, True, False, True):
        if expect_ok:
            c.generate(REQ)
        else:
            with pytest.raises(LLMError):
                c.generate(REQ)
    # waits before calls 2..6: 10 s, 20 s, 40 s after the three failures; none after the success's own
    # reset except the one failure that followed it (10 s again, not 80 s)
    assert slept == [10.0, 20.0, 40.0, 10.0]


def test_backoff_after_transport_timeout():
    now = [0.0]
    slept = []
    c = GroqClient("m-1", transport=Fake(LLMTimeout(code="timeout"), groq_ok()), min_interval_s=0,
                   clock=lambda: now[0], sleep=lambda s: (slept.append(s), now.__setitem__(0, now[0] + s)))
    with pytest.raises(LLMTimeout):
        c.generate(REQ)
    c.generate(REQ)
    assert slept == [10.0]


def test_transport_sends_a_generic_user_agent_and_keeps_caller_headers(monkeypatch):
    """TRIAL-001: Groq's firewall answered 403 (error code 1010) to Python's default user-agent."""
    seen = {}

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            return b"{}"

    def fake_urlopen(req, timeout=None):
        seen.update({k.lower(): v for k, v in req.header_items()})
        return Resp()
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert urllib_transport("https://x", {"Authorization": "Bearer t"}, b"{}", 1.0) == (200, b"{}")
    assert seen["user-agent"] == "multi-agentic-security-research/0.1" and "python" not in seen["user-agent"].lower()
    assert seen["authorization"] == "Bearer t"


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
    f.write_text("# comment\nAGENT4_GROQ_API_KEY='abc'\nexport AGENT4_LLM_TIMEOUT_SECONDS=30\n"
                 "OTHER_SECRET=zzz\nAGENT4_LLM_MAX_OUTPUT_TOKENS=\nAGENT4_GROQ_MODEL=keep-me\n", encoding="utf-8")
    env = {"AGENT4_GROQ_MODEL": "already-set"}
    names = load_secrets(f, environ=env)
    assert names == ["AGENT4_GROQ_API_KEY", "AGENT4_LLM_TIMEOUT_SECONDS"]
    assert env == {"AGENT4_GROQ_MODEL": "already-set", "AGENT4_GROQ_API_KEY": "abc",
                   "AGENT4_LLM_TIMEOUT_SECONDS": "30"}


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
