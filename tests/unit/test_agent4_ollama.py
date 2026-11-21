"""Ollama adapter (D-074): a local model behind the provider-independent interface. Request shape, response
parsing, failure codes, model pinning, loopback-only URL, no key, no silent truncation, and use through the
caching wrapper and the pipeline's LLM path. A fake transport replaces the network; no network, no secrets."""

import json

import pytest

from multi_agentic_security.agents.agent4_recommendation import LLMClient, LLMError, LLMRequest, LLMTimeout
from multi_agentic_security.agents.agent4_recommendation.providers import OllamaClient
from multi_agentic_security.pipeline import CachingLLMClient

REQ = LLMRequest(system="SYS", messages=(("user", "U1"), ("assistant", "A1"), ("user", "U2")), temperature=0.0,
                 seed=7, max_output_tokens=300, timeout_s=12.0)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    import socket as s

    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(s, "socket", refuse)
    monkeypatch.setattr(s, "create_connection", refuse)
    monkeypatch.setattr(s, "getaddrinfo", refuse)


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


def ok(text='{"action": "keep"}', reason="stop", **extra):
    return 200, {"model": "llama3.2:3b", "created_at": "2026-11-21T00:00:00Z", "message": {"role": "assistant", "content": text},
                 "done": True, "done_reason": reason, "prompt_eval_count": 21, "eval_count": 9, **extra}


def test_request_shape_and_parsing():
    t = Fake(ok())
    c = OllamaClient("llama3.2:3b", transport=t)
    r = c.generate(REQ)
    url, headers, body, timeout = t.calls[0]
    assert url == "http://127.0.0.1:11434/api/chat" and timeout == 12.0
    assert body["model"] == "llama3.2:3b" and body["stream"] is False
    assert body["options"] == {"temperature": 0.0, "num_predict": 300, "num_ctx": 8192, "seed": 7}
    assert body["messages"] == [{"role": "system", "content": "SYS"}, {"role": "user", "content": "U1"},
                                {"role": "assistant", "content": "A1"}, {"role": "user", "content": "U2"}]
    assert "Authorization" not in headers and "authorization" not in {k.lower() for k in headers}     # no key at all
    assert (r.text, r.stop_reason, r.provider_response_id) == ('{"action": "keep"}', "end", None)
    assert dict(r.usage) == {"input_tokens": 21, "output_tokens": 9}
    assert c.provider == "ollama" and isinstance(c, LLMClient) and "llama3.2:3b" in repr(c)


def test_seed_is_omitted_when_not_given_and_stop_reasons_are_mapped():
    t = Fake(ok(reason="length"), ok(reason="load"), ok(reason="stop"))
    c = OllamaClient("llama3.2:3b", transport=t)
    no_seed = LLMRequest(system="S", messages=(("user", "U"),))
    assert c.generate(no_seed).stop_reason == "length" and "seed" not in t.calls[0][2]["options"]
    assert c.generate(no_seed).stop_reason == "other" and c.generate(no_seed).stop_reason == "end"


@pytest.mark.parametrize("model", ["llama3.2", "llama3.2:latest", "llama3.2:LATEST", "", "llama 3.2:3b", "llama3.2:3b;rm",
                                   "../x:3b", "llama3.2:"])
def test_only_exact_name_tag_models_are_accepted(model):
    with pytest.raises(ValueError):
        OllamaClient(model, transport=Fake())


@pytest.mark.parametrize("model", ["llama3.2:3b", "llama3.2:3b-instruct-q4_K_M", "library/llama3.2:3b", "qwen2.5:7b"])
def test_exact_models_are_accepted(model):
    assert OllamaClient(model, transport=Fake()).model == model


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434", "http://localhost:11434", "http://localhost", "http://[::1]:11434/",
                                 "http://127.0.0.1:8080"])
def test_loopback_urls_are_accepted(url):
    OllamaClient("llama3.2:3b", base_url=url, transport=Fake())


@pytest.mark.parametrize("url", ["http://example.com:11434", "http://192.168.1.5:11434", "https://127.0.0.1:11434",
                                 "http://user:pw@127.0.0.1:11434", "http://127.0.0.1.evil.com:11434",
                                 "http://127.0.0.1:11434/api", "http://0.0.0.0:11434", "ftp://127.0.0.1", "", "http://127.0.0.1:99999"])
def test_prompts_never_leave_the_machine_non_loopback_urls_are_refused(url):
    with pytest.raises(ValueError):
        OllamaClient("llama3.2:3b", base_url=url, transport=Fake())


def test_a_prompt_that_does_not_fit_is_refused_not_truncated():
    t = Fake(ok())
    c = OllamaClient("llama3.2:3b", transport=t, num_ctx=1024)
    long = LLMRequest(system="S" * 3000, messages=(("user", "U"),), max_output_tokens=200)
    with pytest.raises(LLMError) as e:
        c.generate(long)
    assert e.value.code == "prompt_too_long" and t.calls == []             # nothing was sent
    short = LLMRequest(system="S" * 300, messages=(("user", "U"),), max_output_tokens=200)
    assert c.generate(short).stop_reason == "end" and len(t.calls) == 1


def test_num_ctx_is_bounded():
    for bad in (100, 10_000_000, True, "8192"):
        with pytest.raises(ValueError):
            OllamaClient("llama3.2:3b", transport=Fake(), num_ctx=bad)


@pytest.mark.parametrize("answer,code", [
    ((404, {"error": "model 'llama3.2:3b' not found"}), "model_not_found"),
    ((500, {"error": "boom"}), "http_500"), ((503, b""), "http_503"), ((400, {"error": "bad"}), "http_400"),
    ((200, b"not json"), "invalid_provider_response"), ((200, b"[1, 2]"), "invalid_provider_response"),
    ((200, {"done": True, "done_reason": "stop"}), "invalid_provider_response"),                      # no message
    ((200, {"message": {"content": "x"}, "done": False}), "invalid_provider_response"),                # not finished
    ((200, {"message": {"content": 5}, "done": True}), "invalid_provider_response"),
    ((200, {"message": "oops", "done": True}), "invalid_provider_response"),
])
def test_failures_are_states_with_machine_codes(answer, code):
    with pytest.raises(LLMError) as e:
        OllamaClient("llama3.2:3b", transport=Fake(answer)).generate(REQ)
    assert e.value.code == code


def test_connection_errors_and_timeouts_propagate_with_their_codes():
    with pytest.raises(LLMError) as e:
        OllamaClient("llama3.2:3b", transport=Fake(LLMError(code="connection_error"))).generate(REQ)
    assert e.value.code == "connection_error"
    with pytest.raises(LLMTimeout):
        OllamaClient("llama3.2:3b", transport=Fake(LLMTimeout(code="timeout"))).generate(REQ)


def test_no_environment_variable_is_read(monkeypatch):
    import os
    reads = []
    real = os.environ.get
    monkeypatch.setattr(os.environ.__class__, "get", lambda self, k, d=None: (reads.append(k), real(k, d))[1])
    OllamaClient("llama3.2:3b", transport=Fake(ok())).generate(REQ)
    assert not [k for k in reads if "KEY" in str(k).upper() or "AGENT4" in str(k).upper()]


def test_the_caching_wrapper_replays_an_answer_without_a_second_call(tmp_path):
    t = Fake(ok())
    c = CachingLLMClient(OllamaClient("llama3.2:3b", transport=t), tmp_path / "cache")
    first, second = c.generate(REQ), c.generate(REQ)
    assert first.text == second.text and len(t.calls) == 1 and (c.hits, c.misses) == (1, 1)
    assert c.provider == "ollama" and c.model == "llama3.2:3b"


@pytest.mark.parametrize("model", ["gpt-oss:120b-cloud", "deepseek-v3.1:671b-cloud", "qwen3-coder:cloud", "llama3.2:3b-CLOUD"])
def test_cloud_models_are_refused_because_a_signed_in_app_would_forward_them(model):
    with pytest.raises(ValueError):
        OllamaClient(model, transport=Fake())
