"""Agent 2 registry clients: URL building, response parsing, status mapping, retries,
the HTTPS transport's safety settings and the snapshot client.

Only hand-written recordings (tests/fixtures/agent2/registry_snapshot/) and fake
transports are used. Sockets are blocked in every test.
"""

import json
import socket
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent2_registry.client import (
    USER_AGENT, HttpRegistryClient, HttpResponse, SnapshotRegistryClient, TransportError, UrllibTransport,
    _AllowListRedirects, check_url, outcome_from_response, parse_npm, parse_pypi, registry_url,
    valid_registry_name,
)

SNAP = Path(__file__).resolve().parents[1] / "fixtures" / "agent2" / "registry_snapshot"
T0 = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def body_of(name):
    return json.loads((SNAP / name).read_text(encoding="utf-8"))["body"]


# --------------------------------------------------------------------------- names and URLs

def test_registry_urls():
    assert registry_url("pypi", "requests") == "https://pypi.org/pypi/requests/json"
    assert registry_url("npm", "lodash") == "https://registry.npmjs.org/lodash"
    assert registry_url("npm", "@types/node") == "https://registry.npmjs.org/@types%2Fnode"


@pytest.mark.parametrize("eco,name", [
    ("pypi", "../etc"), ("pypi", "a b"), ("pypi", "x/y"), ("pypi", "-x"), ("pypi", ""), ("pypi", "a?b"),
    ("npm", "../x"), ("npm", "@a/../b"), ("npm", "A"), ("npm", "a b"), ("npm", "@a/b/c"), ("npm", "x" * 215),
    ("maven", "x"),
])
def test_invalid_names_never_become_urls(eco, name):
    assert not valid_registry_name(eco, name)
    with pytest.raises(ValueError):
        registry_url(eco, name)


# --------------------------------------------------------------------------- parsing

def test_parse_pypi_found():
    o = parse_pypi(body_of("pypi_requests.json"), retrieved_at=T0, url="u")
    assert o.status == "found" and o.rule_id == "a2.status.found"
    assert o.canonical_name == "requests" and o.latest_version == "2.32.3"
    assert o.versions == ["2.31.0", "2.32.0", "2.32.3", "0.0.1"]  # upload order, unknown last
    assert o.upload_times["2.32.3"] == datetime(2024, 5, 29, 15, 37, 47, tzinfo=timezone.utc)  # earliest file
    assert o.upload_times["0.0.1"] is None
    assert o.metadata["yanked_versions"] == ["2.32.0"]
    assert o.metadata["versions_without_files"] == ["0.0.1"]


def test_canonical_name_comes_from_registry():
    o = parse_pypi(body_of("pypi_pyyaml.json"), retrieved_at=T0, url="u")
    assert o.canonical_name == "PyYAML"


def test_parse_npm_found_and_scoped():
    o = parse_npm(body_of("npm_lodash.json"), retrieved_at=T0, url="u")
    assert o.status == "found" and o.versions == ["4.17.20", "4.17.21"] and o.latest_version == "4.17.21"
    assert o.upload_times["4.17.21"] == datetime(2021, 2, 20, 15, 42, 16, 891000, tzinfo=timezone.utc)
    assert parse_npm(body_of("npm_types-node.json"), retrieved_at=T0, url="u").canonical_name == "@types/node"


def test_npm_security_placeholder_keeps_removed_versions_and_dates():
    # Fixture shaped after recorded real holder responses (live check 2026-11-16, D-054).
    o = parse_npm(body_of("npm_evil-pkg.json"), retrieved_at=T0, url="u")
    assert o.status == "security_placeholder" and o.versions is None
    assert o.metadata["removed_versions"] == {"99.9.9": "2025-12-18T10:00:00+00:00"}
    assert o.metadata["placeholder_published"] == "2026-01-05T00:00:00.500000+00:00"
    assert o.metadata["repository"] == "npm/security-holder" and "removed version" in o.explanation


def test_npm_placeholder_needs_every_version_to_be_a_holder():
    doc = body_of("npm_lodash.json")
    doc["versions"]["0.0.1-security"] = {}
    doc["dist-tags"]["latest"] = "0.0.1-security"
    assert parse_npm(doc, retrieved_at=T0, url="u").status == "found"


def test_npm_unpublished_is_not_found():
    o = parse_npm(body_of("npm_gone-pkg.json"), retrieved_at=T0, url="u")
    assert o.status == "not_found" and o.rule_id == "a2.status.npm_unpublished"


@pytest.mark.parametrize("status,expected", [
    (404, "not_found"), (500, "lookup_error"), (503, "lookup_error"), (429, "lookup_error"),
    (403, "lookup_error"), (None, "lookup_error"),
])
def test_status_mapping(status, expected):
    o = outcome_from_response("pypi", "u", status, b"{}", T0, error="x")
    assert o.status == expected and o.retrieved_at == T0
    if expected == "lookup_error":
        assert o.error and "not the same as not found" in o.explanation


@pytest.mark.parametrize("body", [b'{"info": ', b"\xff\xfe", b"[]", b'{"info": {"name": "x"}, "releases": []}',
                                  b'{"info": {"name": "x"}, "releases": {"1": "notalist"}}', b"[" * 100000],
                         ids=["truncated", "not_utf8", "list", "releases_list", "files_not_list", "deep_nesting"])
def test_malformed_or_unexpected_body_is_invalid_response(body):
    o = outcome_from_response("pypi", "u", 200, body, T0)
    assert o.status == "invalid_response" and o.error


def test_npm_without_versions_and_not_unpublished_is_invalid():
    o = outcome_from_response("npm", "u", 200, b'{"name": "x", "versions": {}}', T0)
    assert o.status == "invalid_response"


def test_metadata_text_is_cleaned_and_capped():
    doc = body_of("pypi_requests.json")
    doc["info"]["summary"] = "a\x00b\x1b" + "x" * 1000
    o = parse_pypi(doc, retrieved_at=T0, url="u")
    assert "\x00" not in o.metadata["summary"] and len(o.metadata["summary"]) == 300


# --------------------------------------------------------------------------- live client with fake transports

class FakeTransport:
    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def get(self, url, *, timeout, max_bytes, deadline_s):
        self.calls.append(url)
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a


def ok(body, status=200, headers=None):
    return HttpResponse(status, "https://pypi.org/x", headers or {}, json.dumps(body).encode() if body is not None else b"")


def client(transport, sleeps=None):
    return HttpRegistryClient(transport=transport, clock=lambda: T0, sleep=(sleeps.append if sleeps is not None else lambda s: None))


def test_live_found_after_server_error_retry():
    sleeps = []
    t = FakeTransport(ok(None, 503), ok(body_of("pypi_requests.json")))
    o = client(t, sleeps).lookup("pypi", "requests")
    assert o.status == "found" and o.inputs["attempts"] == 2 and len(t.calls) == 2 and sleeps == [1.0]
    assert o.retrieved_at == T0 and o.source_url == "https://pypi.org/pypi/requests/json"


def test_timeouts_exhaust_retries_and_are_never_not_found():
    sleeps = []
    t = FakeTransport(*[TransportError("timeout", "connection timed out")] * 3)
    o = client(t, sleeps).lookup("pypi", "requests")
    assert o.status == "lookup_error" and "timeout" in o.error and len(t.calls) == 3 and sleeps == [1.0, 2.0]


def test_rate_limit_respects_retry_after_with_a_cap():
    sleeps = []
    t = FakeTransport(ok(None, 429, {"retry-after": "120"}), ok(None, 429, {"retry-after": "3"}), ok(None, 429))
    o = client(t, sleeps).lookup("npm", "lodash")
    assert o.status == "lookup_error" and "HTTP 429" in o.error and sleeps == [10.0, 3.0]


def test_404_is_not_retried():
    t = FakeTransport(ok({"message": "Not Found"}, 404))
    assert client(t).lookup("pypi", "nope").status == "not_found" and len(t.calls) == 1


@pytest.mark.parametrize("kind", ["too_large", "redirect_refused"])
def test_non_retryable_transport_errors(kind):
    t = FakeTransport(TransportError(kind, "x"))
    o = client(t).lookup("pypi", "requests")
    assert o.status == "lookup_error" and kind in o.error and len(t.calls) == 1


def test_broken_transport_is_a_state_not_a_crash():
    o = client(FakeTransport(RuntimeError("boom"))).lookup("pypi", "requests")
    assert o.status == "lookup_error" and "RuntimeError" in o.error


def test_invalid_name_raises_before_any_request():
    t = FakeTransport()
    with pytest.raises(ValueError):
        client(t).lookup("pypi", "../x")
    assert t.calls == []


# --------------------------------------------------------------------------- HTTPS transport settings

@pytest.mark.parametrize("url", [
    "http://pypi.org/pypi/x/json", "https://evil.example/pypi/x/json", "https://u:p@pypi.org/x",
    "https://pypi.org:8443/x", "https://registry.npmjs.org.evil.example/x", "file:///etc/passwd",
])
def test_url_allow_list(url):
    with pytest.raises(TransportError):
        check_url(url)


def test_allowed_urls_pass():
    check_url("https://pypi.org/pypi/requests/json")
    check_url("https://registry.npmjs.org/@types%2Fnode")


def test_redirect_outside_allow_list_is_refused():
    handler = _AllowListRedirects()
    req = urllib.request.Request("https://pypi.org/pypi/x/json")
    with pytest.raises(TransportError):
        handler.redirect_request(req, None, 302, "Found", {}, "https://evil.example/x")


def test_transport_sends_no_cookies_no_env_proxy_and_a_generic_user_agent():
    t = UrllibTransport()
    handlers = t._opener.handlers
    assert not any(isinstance(h, urllib.request.HTTPCookieProcessor) for h in handlers)
    # ProxyHandler({}) registers no proxy methods, so no environment proxy is ever used.
    assert all(not getattr(h, "proxies", None) for h in handlers)
    assert not any(hasattr(h, "https_open") and isinstance(h, urllib.request.ProxyHandler) for h in handlers)
    assert dict(t._opener.addheaders)["User-Agent"] == USER_AGENT
    assert "@" not in USER_AGENT and "Authorization" not in dict(t._opener.addheaders)


def test_real_transport_with_network_blocked_gives_lookup_error(monkeypatch):
    def refuse(*a, **k):
        raise OSError("network blocked in test")
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    sleeps = []
    o = HttpRegistryClient(clock=lambda: T0, sleep=sleeps.append).lookup("pypi", "requests")
    assert o.status == "lookup_error" and o.error.startswith("connection") and len(sleeps) == 2


# --------------------------------------------------------------------------- snapshot client

def test_snapshot_client_reads_recordings():
    c = SnapshotRegistryClient(SNAP)
    assert c.load_failures == []
    o = c.lookup("pypi", "requests")
    assert o.status == "found" and o.retrieved_at == datetime(2026, 11, 15, 10, tzinfo=timezone.utc)
    assert o.inputs["snapshot_file"] == "pypi_requests.json"
    assert c.lookup("pypi", "pyyaml").canonical_name == "PyYAML"
    assert c.lookup("pypi", "reqeusts-hallucinated").status == "not_found"
    assert c.lookup("pypi", "numpy").status == "lookup_error"
    assert c.lookup("pypi", "timeoutpkg").status == "lookup_error"
    assert c.lookup("pypi", "brokenpkg").status == "invalid_response"
    assert c.lookup("pypi", "oddshape").status == "invalid_response"
    assert c.lookup("npm", "@types/node").status == "found"
    assert c.lookup("pypi", "not-recorded") is None


def write_rec(folder, fname, **doc):
    base = {"format": "registry_snapshot/1", "ecosystem": "pypi", "name": "x",
            "retrieved_at": "2026-11-15T10:00:00+00:00", "http_status": 404}
    (folder / fname).write_text(json.dumps({**base, **doc}), encoding="utf-8")


def test_snapshot_conflict_and_bad_files(tmp_path):
    write_rec(tmp_path, "a.json", name="Dup_Pkg")
    write_rec(tmp_path, "b.json", name="dup.pkg", retrieved_at="2026-11-15T11:00:00+00:00")
    write_rec(tmp_path, "c.json", name="naive", retrieved_at="2026-11-15T10:00:00")
    write_rec(tmp_path, "d.json", format="other")
    write_rec(tmp_path, "e.json", name="noerr", http_status=None)
    (tmp_path / "f.json").write_text("{not json", encoding="utf-8")
    c = SnapshotRegistryClient(tmp_path)
    o = c.lookup("pypi", "dup-pkg")
    assert o.status == "lookup_error" and o.rule_id == "a2.status.snapshot_conflict"
    assert o.retrieved_at == datetime(2026, 11, 15, 11, tzinfo=timezone.utc)
    assert sorted(f for f, _ in c.load_failures) == ["c.json", "d.json", "e.json", "f.json"]
    assert c.lookup("pypi", "naive") is None


def test_snapshot_missing_folder_is_a_load_failure(tmp_path):
    c = SnapshotRegistryClient(tmp_path / "missing")
    assert c.load_failures and c.lookup("pypi", "requests") is None


def test_snapshot_run_record_is_not_a_recording(tmp_path):
    (tmp_path / "RUN_RECORD.json").write_text('{"format": "registry_live_check/1"}', encoding="utf-8")
    write_rec(tmp_path, "a.json", name="x")
    c = SnapshotRegistryClient(tmp_path)
    assert c.load_failures == [] and c.lookup("pypi", "x").status == "not_found"
