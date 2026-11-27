"""Offline API tests using FastAPI TestClient and the Agent 2 test fixtures (no network)."""

from __future__ import annotations

import io
import json
import socket
import time
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="web extras not installed: pip install -e .[dev,web]")
pytest.importorskip("httpx", reason="web extras not installed: pip install -e .[dev,web]")

from fastapi.testclient import TestClient  # noqa: E402

from multi_agentic_security.agents.agent1_ingestion import FetchResponse  # noqa: E402
from multi_agentic_security.agents.agent4_recommendation import LLMResponse # noqa: E402
from multi_agentic_security.api import ScanService, create_app # noqa: E402
from multi_agentic_security.evidence_store import EvidenceStore # noqa: E402


FIX = Path(__file__).resolve().parents[1] / "fixtures" / "agent2"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    import http.client
    import urllib.request

    def refuse(*a, **k):
        raise AssertionError("network access attempted in an offline API test")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", refuse)
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", refuse)


@pytest.fixture
def client(tmp_path: Path):
    store = EvidenceStore.load(FIX / "evidence" / "v1")
    svc = ScanService(
        runtime_dir=tmp_path / "runtime",
        evidence_store=store,
        evidence_source="fixture",
        snapshot_dir=FIX / "registry_snapshot",
    )
    return TestClient(create_app(svc))


def _poll_done(client: TestClient, scan_id: str, timeout_s: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        res = client.get(f"/api/scans/{scan_id}")
        assert res.status_code == 200
        body = res.json()
        if body["status"] in ("done", "failed"):
            return body
        time.sleep(0.05)
    raise AssertionError(f"scan {scan_id} did not finish within {timeout_s}s")


def test_health_endpoint(client: TestClient):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["evidence_store"]["complete"] is True
    assert data["snapshot_available"] is True
    assert data["llm"]["rules_available"] is True


def test_file_upload_full_pipeline_and_dashboard_stats(client: TestClient):
    pkg_json = json.dumps({
        "dependencies": {
            "lodash": "^4.17.21",
            "strign-width": "1.0.0",
            "evil-pkg": "1.0.0",
        }
    }).encode("utf-8")
    reqs = b"requests==2.32.3\nreqeusts-hallucinated==1.0.0\ntimeoutpkg==1.0.0\n"

    res = client.post(
        "/api/scans",
        data={"project_name": "demo-app", "variant": "R0", "registry_mode": "snapshot", "wait": "true"},
        files=[
            ("files", ("requirements.txt", reqs, "text/plain")),
            ("files", ("package.json", pkg_json, "application/json")),
        ],
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "done"
    assert body["stages"] == {
        "extract": "done",
        "registry": "done",
        "risk": "done",
        "recommend": "done",
        "verify": "done",
        "report": "done",
    }
    report = body["report"]
    assert report is not None
    assert report["summary"]["total_dependencies"] == 6

    # Check export endpoint
    exp = client.get(f"/api/scans/{body['scan_id']}/export")
    assert exp.status_code == 200
    assert "attachment;" in exp.headers["content-disposition"]
    exported = exp.json()
    assert exported["project_id"] == report["project_id"]

    # Check dashboard stats aggregation
    hist = client.get("/api/scans")
    assert hist.status_code == 200
    stats = hist.json()["stats"]
    assert stats["total_scans"] == 1
    assert stats["completed_scans"] == 1
    assert stats["packages_analyzed"] == 6
    assert stats["verified"] == 6
    assert stats["suspicious"] >= 2
    assert stats["not_found"] >= 2


def test_async_scan_completes_via_polling(client: TestClient):
    res = client.post(
        "/api/scans",
        data={"project_name": "async-demo", "variant": "R0", "registry_mode": "snapshot"},
        files=[("files", ("requirements.txt", b"requests==2.32.3\n", "text/plain"))],
    )
    assert res.status_code == 200
    scan_id = res.json()["scan_id"]
    final = _poll_done(client, scan_id)
    assert final["status"] == "done"
    assert final["report"]["summary"]["total_dependencies"] == 1


def test_zip_upload_and_pasted_text(client: TestClient):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("proj/requirements.txt", "requests==2.32.3\n")
    res_zip = client.post(
        "/api/scans",
        data={"variant": "R0", "registry_mode": "snapshot", "wait": "true"},
        files=[("files", ("sample.zip", buf.getvalue(), "application/zip"))],
    )
    assert res_zip.status_code == 200
    assert res_zip.json()["status"] == "done"
    assert res_zip.json()["report"]["summary"]["total_dependencies"] == 1

    res_txt = client.post(
        "/api/scans",
        data={"text": "$ pip install reqeusts-hallucinated\n", "variant": "R0", "registry_mode": "snapshot", "wait": "true"},
    )
    assert res_txt.status_code == 200
    assert res_txt.json()["status"] == "done"
    assert res_txt.json()["report"]["summary"]["total_dependencies"] == 1


def test_git_url_scan_with_recorded_fetcher(tmp_path: Path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("repo-main/requirements.txt", "requests==2.32.3\n")

    class FakeFetcher:
        def fetch(self, url: str, *, max_bytes: int, timeout: float) -> FetchResponse:
            return FetchResponse(final_url="https://codeload.github.com/org/repo/zip/HEAD", status=200, data=buf.getvalue())

    svc = ScanService(
        runtime_dir=tmp_path / "runtime",
        evidence_store=EvidenceStore.load(FIX / "evidence" / "v1"),
        snapshot_dir=FIX / "registry_snapshot",
        git_fetcher_factory=FakeFetcher,
    )
    c = TestClient(create_app(svc))
    res = c.post(
        "/api/scans",
        data={"git_url": "https://github.com/org/repo", "variant": "R0", "registry_mode": "snapshot", "wait": "true"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "done"
    assert res.json()["report"]["summary"]["total_dependencies"] == 1


def test_llm_variant_with_fake_client_and_verifier_rejection(tmp_path: Path):
    class UnsafeFakeLLM:
        provider, model = "fake", "unsafe-test-1"

        def generate(self, request):
            # Recommends keeping an explicitly malicious/typosquat package -> Agent 5 must reject
            return LLMResponse(text='{"action": "keep", "rationale": "Looks fine"}')

    svc = ScanService(
        runtime_dir=tmp_path / "runtime",
        evidence_store=EvidenceStore.load(FIX / "evidence" / "v1"),
        snapshot_dir=FIX / "registry_snapshot",
        llm_client_factory=lambda _v: UnsafeFakeLLM(),
    )
    c = TestClient(create_app(svc))
    pkg_json = json.dumps({"dependencies": {"strign-width": "1.0.0"}}).encode("utf-8")
    res = c.post(
        "/api/scans",
        data={"variant": "LLM-G", "registry_mode": "snapshot", "wait": "true"},
        files=[("files", ("package.json", pkg_json, "application/json"))],
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "done"
    assert body["metrics"]["rejected"] == 1
    assert body["report"]["verification"]["verifications"][0]["verdict"] == "reject"


def test_invalid_inputs_and_errors(client: TestClient):
    # Empty submission
    r0 = client.post("/api/scans", data={"variant": "R0"})
    assert r0.status_code == 400

    # Unsupported file type
    r1 = client.post(
        "/api/scans",
        data={"variant": "R0"},
        files=[("files", ("malware.exe", b"MZ", "application/octet-stream"))],
    )
    assert r1.status_code == 400
    assert "Unsupported file type" in r1.json()["detail"]

    # Path traversal filename
    r2 = client.post(
        "/api/scans",
        data={"variant": "R0"},
        files=[("files", ("../requirements.txt", b"requests==2.32.3", "text/plain"))],
    )
    assert r2.status_code == 400

    # Invalid GitHub URL
    r3 = client.post("/api/scans", data={"git_url": "http://evil.example.com/a/b", "variant": "R0"})
    assert r3.status_code == 400

    # Live + cutoff refused
    r4 = client.post(
        "/api/scans",
        data={"text": "pip install requests", "registry_mode": "live", "evidence_cutoff": "2025-01-01"},
    )
    assert r4.status_code == 400

    # Missing LLM config
    r5 = client.post(
        "/api/scans",
        data={"text": "pip install requests", "variant": "LLM-G"},
    )
    assert r5.status_code == 400

    # Unknown scan ID
    assert client.get("/api/scans/does-not-exist").status_code == 404
    assert client.get("/api/scans/does-not-exist/export").status_code == 404

    # Empty dependency list finishes cleanly with 0 dependencies
    r6 = client.post(
        "/api/scans",
        data={"variant": "R0", "registry_mode": "snapshot", "wait": "true"},
        files=[("files", ("requirements.txt", b"# only comments\n", "text/plain"))],
    )
    assert r6.status_code == 200
    assert r6.json()["status"] == "done"
    assert r6.json()["report"]["summary"]["total_dependencies"] == 0


# --------------------------------------------------------------------------- review fixes


def test_importing_the_api_creates_no_server(tmp_path: Path):
    """Importing the package must not build a ScanService (evidence store, runtime/scans.db, settings)."""
    import subprocess
    import sys

    code = (
        "import multi_agentic_security.api as api, multi_agentic_security.api.app as m; "
        "assert m._default_app is None, 'app was created on import'; print('ok')"
    )
    env = {**__import__("os").environ, "PYTHONPATH": __import__("os").pathsep.join(sys.path)}
    out = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "ok"


def test_no_secrets_file_is_read_and_api_keys_are_ignored(tmp_path: Path, monkeypatch):
    """The web layer never opens a secrets file and never uses hosted-model keys, even when they are set."""
    monkeypatch.delenv("AGENT4_OLLAMA_MODEL", raising=False)
    monkeypatch.setenv("AGENT4_GROQ_API_KEY1", "dummy-not-a-key")
    monkeypatch.setenv("AGENT4_GROQ_MODEL", "llama-3.1-8b-instant")
    opened: list[str] = []
    real_read_text, real_open = Path.read_text, Path.open

    def spy_read_text(self, *a, **k):
        opened.append(self.name)
        return real_read_text(self, *a, **k)

    def spy_open(self, *a, **k):
        opened.append(self.name)
        return real_open(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", spy_read_text)
    monkeypatch.setattr(Path, "open", spy_open)
    svc = ScanService(
        runtime_dir=tmp_path / "runtime",
        evidence_store=EvidenceStore.load(FIX / "evidence" / "v1"),
        snapshot_dir=FIX / "registry_snapshot",
        ollama_probe=lambda: None,
    )
    c = TestClient(create_app(svc))
    llm = c.get("/api/health").json()["llm"]
    res = c.post("/api/scans", data={"text": "pip install requests", "variant": "LLM-G"})
    assert not any(".env" in name for name in opened), opened
    assert not any("groq" in key.lower() for key in llm)
    assert res.status_code == 400


def _local_service(tmp_path: Path, installed):
    return ScanService(
        runtime_dir=tmp_path / "runtime",
        evidence_store=EvidenceStore.load(FIX / "evidence" / "v1"),
        snapshot_dir=FIX / "registry_snapshot",
        ollama_probe=lambda: installed,
    )


def test_llm_modes_use_the_built_in_local_model_without_any_setting(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("AGENT4_OLLAMA_MODEL", raising=False)
    llm = TestClient(create_app(_local_service(tmp_path, ["qwen2.5:7b", "llama3.2:3b"]))).get("/api/health").json()["llm"]
    assert llm == {"rules_available": True, "local_model": "qwen2.5:7b", "ollama_running": True,
                   "local_model_installed": True, "local_model_ready": True}
    llm_client, _ = _local_service(tmp_path, ["qwen2.5:7b"])._build_llm("LLM-U")
    assert llm_client is not None   # built without calling the model; no key, no file


@pytest.mark.parametrize("installed, expected", [(None, "Ollama is not running"), ([], "ollama pull qwen2.5:7b")])
def test_llm_modes_explain_what_to_do_when_the_local_model_is_missing(tmp_path: Path, monkeypatch, installed, expected):
    monkeypatch.delenv("AGENT4_OLLAMA_MODEL", raising=False)
    c = TestClient(create_app(_local_service(tmp_path, installed)))
    assert c.get("/api/health").json()["llm"]["local_model_ready"] is False
    for variant in ("LLM-G", "LLM-U"):
        res = c.post("/api/scans", data={"text": "$ pip install requests", "variant": variant})
        assert res.status_code == 400
        assert expected in res.json()["detail"]
    r0 = c.post("/api/scans", data={"text": "$ pip install requests", "variant": "R0", "registry_mode": "off", "wait": "true"})
    assert r0.status_code == 200 and r0.json()["status"] == "done"   # R0 never needs the model


def test_another_local_model_can_be_chosen_with_an_environment_variable(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AGENT4_OLLAMA_MODEL", "llama3.2:3b")
    llm = TestClient(create_app(_local_service(tmp_path, ["llama3.2:3b"]))).get("/api/health").json()["llm"]
    assert llm["local_model"] == "llama3.2:3b" and llm["local_model_ready"] is True


def test_local_probe_only_contacts_this_computer():
    from multi_agentic_security.api.service import OLLAMA_LOCAL_URL, probe_local_ollama

    assert OLLAMA_LOCAL_URL.startswith("http://127.0.0.1:")
    assert probe_local_ollama() is None   # the offline fixture refuses every connection: reported as not running


@pytest.mark.parametrize("name", ["pyproject.toml", "Pipfile"])
def test_unparsed_manifest_is_reported_not_refused(client: TestClient, name: str):
    res = client.post(
        "/api/scans",
        data={"variant": "R0", "registry_mode": "snapshot", "wait": "true"},
        files=[("files", (name, b"[project]\ndependencies = []\n", "text/plain"))],
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "done"
    codes = [f["code"] for f in body["report"]["extraction"]["failures"]]
    assert "a1.source.unsupported_manifest" in codes
