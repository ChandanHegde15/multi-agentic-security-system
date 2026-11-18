"""Pipeline orchestrator (LangGraph) on tests/fixtures/agent2 (D-066): full runs with R0 and a fake
LLM, caching, budget, guardrails, resume, stage failures and the secret scan. No network."""

import ast
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile
from multi_agentic_security.agents.agent2_registry import SnapshotRegistryClient
from multi_agentic_security.agents.agent4_recommendation import LLMError, LLMResponse, MemoryResponseStore
from multi_agentic_security.evidence_store import EvidenceStore
from multi_agentic_security.pipeline import (
    BudgetedLLMClient, CachingLLMClient, MultiSnapshotClient, PipelineConfig, build_graph, run_pipeline,
)
from multi_agentic_security.pipeline.guardrails import find_secret

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "agent2"
PIPE = Path(__file__).resolve().parents[2] / "src" / "multi_agentic_security" / "pipeline"
T0 = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
CUT = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


class FixedLLM:
    provider, model = "fake", "fixed-1"

    def __init__(self, text='{"action": "keep"}'):
        self.text, self.calls = text, 0

    def generate(self, request):
        self.calls += 1
        return LLMResponse(text=self.text)


def cfg(tmp_path=None, **kw):
    files = [UploadedFile(p.name, p.read_bytes()) for p in sorted((FIX / "upload").iterdir())]
    base = dict(project_id="proj-graph", files=files, registry_mode="snapshot",
                registry_client=SnapshotRegistryClient(FIX / "registry_snapshot"),
                evidence_store=EvidenceStore.load(FIX / "evidence" / "v1"), clock=lambda: T0,
                run_dir=(tmp_path / "run") if tmp_path is not None else None)
    base.update(kw)
    return PipelineConfig(**base)


# --------------------------------------------------------------------------- full runs

def test_r0_run_produces_a_valid_report_and_run_record(tmp_path):
    res = run_pipeline(cfg(tmp_path))
    assert res.status == "done" and res.failures == [] and res.report is not None
    s = res.report.summary
    assert s.total_dependencies == 19 and s.verdict_counts == {"accept": 19}
    assert s.action_counts == {"abstain": 6, "keep": 7, "remove": 4, "replace": 1, "upgrade": 1}
    assert s.by_ecosystem == {"npm": 7, "pypi": 12}
    files = {p.name for p in (tmp_path / "run").glob("*.json")}
    assert files == {"extract.json", "registry.json", "risk.json", "recommend.json", "verify.json", "report.json",
                     "RUN_RECORD.json"}
    rec = json.loads((tmp_path / "run" / "RUN_RECORD.json").read_text())
    assert rec["status"] == "done" and rec["langgraph_version"] and rec["contract_version"] == "pipeline/0.2"
    assert rec["stage_versions"]["recommend"].startswith("agent4/0.1+r0") and rec["evidence_store"]["complete"]
    assert set(rec["files"]) == files - {"RUN_RECORD.json"} and all(len(h) == 64 for h in rec["files"].values())
    assert rec["config"]["llm"] is None


def test_run_with_cutoff_sends_one_recommendation_to_review(tmp_path):
    res = run_pipeline(cfg(tmp_path, evidence_cutoff=CUT))
    assert res.status == "done"
    assert res.report.summary.verdict_counts == {"abstain": 1, "accept": 18}


def test_graph_uses_langgraph_with_the_documented_stages():
    nodes = set(build_graph(cfg()).get_graph().nodes)
    assert {"guard_input", "extract", "registry", "risk", "recommend", "verify", "report"} <= nodes


def test_llm_variant_caches_and_counts_cost(tmp_path):
    inner = FixedLLM()
    llm = CachingLLMClient(BudgetedLLMClient(inner, max_calls=100), tmp_path / "cache")
    c1 = cfg(tmp_path / "a", variant="LLM-G", llm=llm, response_store=MemoryResponseStore())
    r1 = run_pipeline(c1)
    assert r1.status == "done" and inner.calls == 18 and llm.misses == 18 and llm.hits == 0
    assert r1.record["cost"]["BudgetedLLMClient.calls"] == 18
    llm2 = CachingLLMClient(BudgetedLLMClient(FixedLLM(), max_calls=0), tmp_path / "cache")   # zero budget
    r2 = run_pipeline(cfg(tmp_path / "b", variant="LLM-G", llm=llm2, response_store=MemoryResponseStore()))
    assert r2.status == "done" and llm2.hits == 18 and llm2.inner.calls == 0, "a repeated run must cost no calls"
    assert r2.record["config"]["llm"] == "fake/fixed-1"
    assert {r.generation_status for r in r2.report.recommendations.recommendations} == {"ok"}


def test_budget_exhaustion_is_llm_error_and_abstain_not_a_default(tmp_path):
    llm = BudgetedLLMClient(FixedLLM(), max_calls=5)
    res = run_pipeline(cfg(tmp_path, variant="LLM-U", llm=llm, response_store=MemoryResponseStore()))
    recs = res.report.recommendations.recommendations
    failed = [r for r in recs if r.generation_status == "llm_error"]
    assert res.status == "done" and llm.calls == 5 and len(failed) == 13   # 18 callable dependencies, 5 within budget
    assert all(r.action == "abstain" and r.failure.code == "a4.llm.llm_error" for r in failed)
    assert any("budget_exhausted" in x.explanation for r in failed for x in r.reasons)


def test_cache_ignores_failures_and_unreadable_entries(tmp_path):
    class Flaky:
        provider, model = "fake", "m"

        def __init__(self):
            self.n = 0

        def generate(self, request):
            self.n += 1
            if self.n == 1:
                raise LLMError(code="http_503")
            return LLMResponse(text="ok")
    from multi_agentic_security.agents.agent4_recommendation import LLMRequest
    req = LLMRequest(system="s", messages=(("user", "u"),))
    c = CachingLLMClient(Flaky(), tmp_path / "c")
    with pytest.raises(LLMError):
        c.generate(req)
    assert list((tmp_path / "c").glob("*.json")) == []        # nothing cached for a failure
    assert c.generate(req).text == "ok" and c.generate(req).text == "ok" and (c.hits, c.misses) == (1, 2)
    path = next((tmp_path / "c").glob("*.json"))
    path.write_text("{broken", encoding="utf-8")
    assert c.generate(req).text == "ok" and c.inner.n == 3    # unreadable entry is a miss


# --------------------------------------------------------------------------- guardrails

@pytest.mark.parametrize("kw,code", [
    ({"project_id": "../etc"}, "pipeline.guard.project_id"),
    ({"project_id": ""}, "pipeline.guard.project_id"),
    ({"variant": "LLM-G"}, "pipeline.guard.llm_missing"),
    ({"variant": "X"}, "pipeline.guard.variant"),
    ({"registry_mode": "snapshot", "registry_client": None}, "pipeline.guard.client_missing"),
    ({"registry_mode": "bogus"}, "pipeline.guard.registry_mode"),
])
def test_input_guards_stop_the_run_with_a_recorded_failure(tmp_path, kw, code):
    res = run_pipeline(cfg(tmp_path, **kw))
    assert res.status == "failed" and res.report is None and [f.code for f in res.failures] == [code]
    assert not (tmp_path / "run" / "extract.json").exists()           # nothing ran


def test_live_registry_with_cutoff_is_refused(tmp_path):
    res = run_pipeline(cfg(tmp_path, registry_mode="live", evidence_cutoff=CUT))
    assert [f.code for f in res.failures] == ["pipeline.guard.live_with_cutoff"]


def test_too_many_dependencies_for_an_llm_run_stops_before_any_call(tmp_path):
    llm = FixedLLM()
    res = run_pipeline(cfg(tmp_path, variant="LLM-U", llm=llm, response_store=MemoryResponseStore(),
                           max_dependencies_llm=5))
    assert res.status == "failed" and [f.code for f in res.failures] == ["pipeline.guard.too_many_dependencies"]
    assert llm.calls == 0 and not (tmp_path / "run" / "registry.json").exists()


def test_secret_shaped_output_blocks_the_report_and_is_never_written(tmp_path):
    secret = "gsk_" + "A" * 30
    llm = FixedLLM(json.dumps({"action": "keep", "rationale": f"my key is {secret}"}))
    res = run_pipeline(cfg(tmp_path, variant="LLM-G", llm=llm, response_store=MemoryResponseStore()))
    assert res.status == "failed" and res.report is None
    assert [f.code for f in res.failures] == ["pipeline.guard.secret_in_output"]
    written = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "run").glob("*.json"))
    assert secret not in written and "recommend.json" not in {p.name for p in (tmp_path / "run").glob("*.json")}


def test_find_secret_patterns_and_no_false_positive_on_ids():
    assert find_secret("x gsk_" + "b" * 25) and find_secret("AIza" + "c" * 35) and find_secret("-----BEGIN PRIVATE KEY-----")
    assert find_secret("ev-vulnerable-0a68c5f5febb2d61 and sha 33e409abbfb17ab8840a0cadb73ee44ce963b5d80bf1ccd8") is None


# --------------------------------------------------------------------------- failures and resume

def test_a_crashing_stage_is_a_recorded_failure_not_a_default(tmp_path):
    def boom(project_id, clock):
        raise RuntimeError("intake exploded")
    res = run_pipeline(cfg(tmp_path, extract_fn=boom))
    assert res.status == "failed" and res.report is None
    assert [f.code for f in res.failures] == ["pipeline.stage_error.extract"]


def test_resume_reuses_saved_stages_and_recomputes_invalid_ones(tmp_path):
    first = run_pipeline(cfg(tmp_path))

    def must_not_run(project_id, clock):
        raise AssertionError("extract ran again")
    second = run_pipeline(cfg(tmp_path, extract_fn=must_not_run, resume=True))
    assert second.status == "done" and second.resumed_stages == ["extract", "registry", "risk", "recommend", "verify"]
    assert second.report.summary == first.report.summary
    (tmp_path / "run" / "risk.json").write_text("{not valid", encoding="utf-8")
    third = run_pipeline(cfg(tmp_path, extract_fn=must_not_run, resume=True))
    assert "risk" not in third.resumed_stages and third.status == "done"


# --------------------------------------------------------------------------- snapshots

def test_multi_snapshot_client_reads_several_folders_and_flags_conflicts(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    src = FIX / "registry_snapshot"
    (a / "npm_lodash.json").write_bytes((src / "npm_lodash.json").read_bytes())
    (b / "npm_lodash.json").write_bytes((src / "npm_lodash.json").read_bytes())          # same answer twice
    (b / "pypi_requests.json").write_bytes((src / "pypi_requests.json").read_bytes())
    d = json.loads((src / "pypi_numpy.json").read_text())
    d["name"] = "requests"
    (a / "pypi_requests.json").write_text(json.dumps(d), encoding="utf-8")                  # a different answer
    m = MultiSnapshotClient([a, b])
    assert m.mode == "snapshot" and m.lookup("npm", "lodash").status == "found"
    assert m.lookup("pypi", "nothing-here") is None
    conflict = m.lookup("pypi", "requests")
    assert conflict.status == "lookup_error" and conflict.rule_id == "a2.status.snapshot_conflict"
    with pytest.raises(ValueError):
        MultiSnapshotClient([])


# --------------------------------------------------------------------------- boundaries

def _imports(path):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            yield from (a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            yield ("." * node.level) + (node.module or "")


def test_pipeline_package_uses_no_network_library_and_no_provider_module():
    for f in sorted(PIPE.glob("*.py")):
        for name in _imports(f):
            assert not any(name == b or name.startswith(b + ".") for b in
                           ("socket", "http", "urllib", "requests", "httpx", "subprocess")), (f.name, name)
            assert "providers" not in name, (f.name, name)
