"""Pipeline orchestrator: Agents 1 -> 5 as a LangGraph state graph (D-047, D-066).

``guard_input -> extract -> registry -> risk -> recommend -> verify -> report``

* **State management.** The graph state holds each stage's output as validated JSON; every
  stage boundary re-validates it against the contract model, so a stage can never hand the
  next one a malformed object. A failed guard or a crashing stage ends the run with a
  recorded failure (stage ``pipeline``); nothing falls back to a default.
* **Memory management.** With ``run_dir`` set, every stage output is written to
  ``run_dir/<stage>.json`` and a ``RUN_RECORD.json`` (versions, evidence-store fingerprint,
  cost counters, SHA-256 of each file) is written at the end. ``resume=True`` reuses stage
  files that already exist. Raw LLM answers stay in the response store, by reference.
* **Guardrails.** ``guardrails.py``: input checks, and a secret scan of every output before
  anything is written. LLM cost: ``llm_wrappers.py`` (cache and budget).
* No stage is skipped or reordered; Agent 5 receives only the ``RecommendationResult``.
* LangSmith tracing is disabled explicitly: nothing leaves the machine.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, TypedDict

os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"

from langgraph.checkpoint.memory import InMemorySaver  # noqa: E402
from langgraph.graph import END, START, StateGraph  # noqa: E402
from pydantic import BaseModel, ValidationError  # noqa: E402

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, extract_files  # noqa: E402
from multi_agentic_security.agents.agent2_registry import verify as registry_verify  # noqa: E402
from multi_agentic_security.agents.agent3_risk import assess  # noqa: E402
from multi_agentic_security.agents.agent4_recommendation import LLMOptions, recommend  # noqa: E402
from multi_agentic_security.agents.agent5_verification import verify_recommendations  # noqa: E402
from multi_agentic_security.contracts.pipeline import (  # noqa: E402
    CONTRACT_VERSION, ExtractionResult, Failure, PipelineReport, PipelineSummary, RecommendationResult, RegistryResult,
    RiskResult, VerificationResult,
)
from multi_agentic_security.evidence_store import EvidenceStore  # noqa: E402

from . import guardrails  # noqa: E402

PIPELINE_VERSION = "pipeline_run/0.1"
STAGES = ("extract", "registry", "risk", "recommend", "verify")
MODELS: dict[str, type[BaseModel]] = {"extract": ExtractionResult, "registry": RegistryResult, "risk": RiskResult,
                                      "recommend": RecommendationResult, "verify": VerificationResult}
Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class PipelineConfig:
    project_id: str
    files: list[UploadedFile] = field(default_factory=list)
    extract_fn: Optional[Callable[[str, Clock], ExtractionResult]] = None   # e.g. a ZIP or Git intake
    registry_mode: str = "off"
    registry_client: Any = None
    target_client: Any = None                    # Agent 5's client for targets; defaults to registry_client
    evidence_store: Optional[EvidenceStore] = None
    evidence_cutoff: Optional[datetime] = None
    variant: str = "R0"
    llm: Any = None                              # an LLMClient (wrap with llm_wrappers for cache and budget)
    response_store: Any = None
    llm_options: LLMOptions = field(default_factory=LLMOptions)
    max_dependencies_llm: int = 200
    run_dir: Optional[Path] = None
    resume: bool = False
    clock: Clock = _utc_now


class State(TypedDict, total=False):
    status: str                      # running | failed | done
    failures: list[dict]
    extract: dict
    registry: dict
    risk: dict
    recommend: dict
    verify: dict
    report: dict
    resumed: list[str]


@dataclass
class RunResult:
    status: str
    report: Optional[PipelineReport]
    failures: list[Failure]
    run_dir: Optional[Path]
    record: dict
    resumed_stages: list[str]


def _fail(state: State, code: str, detail: str) -> State:
    f = Failure(stage="pipeline", code=code, detail=detail[:300]).model_dump(mode="json")
    return {"status": "failed", "failures": list(state.get("failures", [])) + [f]}


def _dump(model: BaseModel) -> dict:
    return model.model_dump(mode="json")


def _load(stage: str, state: State) -> BaseModel:
    """Validate a stage output at the boundary; a malformed one raises ValidationError."""
    return MODELS[stage].model_validate(state[stage])


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_graph(cfg: PipelineConfig):
    """The compiled LangGraph for ``cfg`` (stateful objects such as clients are closed over, not in the state)."""
    run_dir = Path(cfg.run_dir) if cfg.run_dir is not None else None

    def persist(stage: str, data: dict) -> Optional[str]:
        text = json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True, default=str)
        hit = guardrails.find_secret(text)
        if hit:
            return hit
        if run_dir is not None:
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / f"{stage}.json").write_text(text, encoding="utf-8")
        return None

    def reuse(stage: str, state: State) -> Optional[State]:
        if cfg.resume and run_dir is not None and (run_dir / f"{stage}.json").is_file():
            try:
                data = json.loads((run_dir / f"{stage}.json").read_text(encoding="utf-8"))
                MODELS[stage].model_validate(data)
            except (OSError, ValueError, ValidationError):
                return None            # an unreadable or invalid saved stage is recomputed, never trusted
            return {stage: data, "resumed": list(state.get("resumed", [])) + [stage]}
        return None

    def stage_node(stage: str, work: Callable[[State], BaseModel]):
        def node(state: State) -> State:
            saved = reuse(stage, state)
            if saved is not None:
                return saved
            try:
                out = work(state)
                data = _dump(out)
                MODELS[stage].model_validate(data)                       # structured output at the boundary
            except Exception as exc:                                      # a crash is a recorded failure
                return _fail(state, f"pipeline.stage_error.{stage}", f"{type(exc).__name__}: {str(exc)[:200]}")
            hit = persist(stage, data)
            if hit:
                return _fail(state, "pipeline.guard.secret_in_output",
                             f"stage {stage}: a secret-shaped string ({hit}) was found; output not written")
            return {stage: data}
        return node

    def guard_input(state: State) -> State:
        problem = guardrails.check_project_id(cfg.project_id)
        if problem:
            return _fail(state, "pipeline.guard.project_id", problem)
        if cfg.variant not in ("R0", "LLM-U", "LLM-G"):
            return _fail(state, "pipeline.guard.variant", f"unknown variant {cfg.variant!r}")
        if cfg.variant != "R0" and (cfg.llm is None or cfg.response_store is None):
            return _fail(state, "pipeline.guard.llm_missing", f"variant {cfg.variant} needs an LLM client and a response store")
        if cfg.registry_mode not in ("off", "snapshot", "live"):
            return _fail(state, "pipeline.guard.registry_mode", f"unknown registry mode {cfg.registry_mode!r}")
        if cfg.registry_mode == "live" and cfg.evidence_cutoff is not None:
            return _fail(state, "pipeline.guard.live_with_cutoff", "live lookups are refused in a run with a cut-off")
        if cfg.registry_mode != "off" and cfg.registry_client is None:
            return _fail(state, "pipeline.guard.client_missing", f"registry mode {cfg.registry_mode} needs a client")
        return {"status": "running", "failures": [], "resumed": []}

    def do_extract(state: State) -> ExtractionResult:
        if cfg.extract_fn is not None:
            return cfg.extract_fn(cfg.project_id, cfg.clock)
        return extract_files(cfg.project_id, cfg.files, clock=cfg.clock)

    def after_extract_guard(state: State) -> State:
        n = len(_load("extract", state).dependencies)
        problem = guardrails.check_dependency_count(n, llm_used=cfg.variant != "R0",
                                                    max_dependencies_llm=cfg.max_dependencies_llm)
        return _fail(state, "pipeline.guard.too_many_dependencies", problem) if problem else {}

    def do_registry(state: State) -> RegistryResult:
        return registry_verify(_load("extract", state), mode=cfg.registry_mode, client=cfg.registry_client,
                               evidence_store=cfg.evidence_store, evidence_cutoff=cfg.evidence_cutoff, clock=cfg.clock)

    def do_risk(state: State) -> RiskResult:
        return assess(_load("extract", state), _load("registry", state), evidence_store=cfg.evidence_store,
                      clock=cfg.clock)

    def do_recommend(state: State) -> RecommendationResult:
        return recommend(_load("extract", state), _load("registry", state), _load("risk", state),
                         evidence_store=cfg.evidence_store, variant=cfg.variant, llm=cfg.llm,
                         response_store=cfg.response_store, options=cfg.llm_options, clock=cfg.clock)

    def do_verify(state: State) -> VerificationResult:
        # Agent 5 gets only the structured RecommendationResult, never Agent 4's internals.
        return verify_recommendations(_load("extract", state), _load("registry", state), _load("recommend", state),
                                      evidence_store=cfg.evidence_store,
                                      target_client=cfg.target_client or cfg.registry_client, clock=cfg.clock)

    def report(state: State) -> State:
        try:
            ex, rg, rk = _load("extract", state), _load("registry", state), _load("risk", state)
            rc, vf = _load("recommend", state), _load("verify", state)
            count = lambda items: dict(sorted(_counter(items).items()))
            summary = PipelineSummary(
                total_dependencies=len(ex.dependencies),
                by_ecosystem=count(d.ecosystem or "unresolved" for d in ex.dependencies),
                registry_status_counts=count(r.status for r in rg.results),
                finding_counts=count(f.finding for a in rk.assessments for f in a.findings),
                baseline_level_counts=count((a.baseline_v1.risk_level if a.baseline_v1 else "none") for a in rk.assessments),
                action_counts=count(r.action for r in rc.recommendations),
                verdict_counts=count(v.verdict for v in vf.verifications),
                failures=sum(len(s.failures) for s in (ex, rg, rk, rc, vf)) + len(state.get("failures", [])))
            rep = PipelineReport(project_id=cfg.project_id, created_at=cfg.clock(), extraction=ex, registry=rg,
                                 risk=rk, recommendations=rc, verification=vf, summary=summary)
        except Exception as exc:
            return _fail(state, "pipeline.stage_error.report", f"{type(exc).__name__}: {str(exc)[:200]}")
        data = _dump(rep)
        hit = persist("report", data)
        if hit:
            return _fail(state, "pipeline.guard.secret_in_output", f"report: secret-shaped string ({hit}); not written")
        return {"report": data, "status": "done"}

    def route(next_node: str):
        return lambda state: END if state.get("status") == "failed" else next_node

    g = StateGraph(State)
    g.add_node("guard_input", guard_input)
    g.add_node("extract", stage_node("extract", do_extract))
    g.add_node("extract_guard", after_extract_guard)
    g.add_node("registry", stage_node("registry", do_registry))
    g.add_node("risk", stage_node("risk", do_risk))
    g.add_node("recommend", stage_node("recommend", do_recommend))
    g.add_node("verify", stage_node("verify", do_verify))
    g.add_node("report", report)
    g.add_edge(START, "guard_input")
    for a, b in (("guard_input", "extract"), ("extract", "extract_guard"), ("extract_guard", "registry"),
                 ("registry", "risk"), ("risk", "recommend"), ("recommend", "verify"), ("verify", "report")):
        g.add_conditional_edges(a, route(b), [b, END])
    g.add_edge("report", END)
    return g.compile(checkpointer=InMemorySaver())


def _counter(items) -> dict:
    out: dict = {}
    for i in items:
        out[i] = out.get(i, 0) + 1
    return out


def _cost(cfg: PipelineConfig) -> dict:
    out: dict[str, Any] = {}
    node = cfg.llm
    while node is not None:
        for attr in ("calls", "tokens_requested", "hits", "misses"):
            if hasattr(node, attr):
                out[f"{type(node).__name__}.{attr}"] = getattr(node, attr)
        node = getattr(node, "inner", None)
    return out


def run_pipeline(cfg: PipelineConfig) -> RunResult:
    """Run the graph once and return the report (or the recorded failure)."""
    started = cfg.clock()
    graph = build_graph(cfg)
    thread = {"configurable": {"thread_id": cfg.project_id if isinstance(cfg.project_id, str) else "invalid"}}
    state: State = graph.invoke({"status": "running", "failures": []}, thread)
    failures = [Failure.model_validate(f) for f in state.get("failures", [])]
    report = PipelineReport.model_validate(state["report"]) if state.get("report") else None
    run_dir = Path(cfg.run_dir) if cfg.run_dir is not None else None
    try:
        import langgraph  # noqa: F401
        from importlib.metadata import version as _v
        lg = _v("langgraph")
    except Exception:
        lg = None
    store = cfg.evidence_store.run_record() if cfg.evidence_store is not None else None
    record = {
        "format": PIPELINE_VERSION, "contract_version": CONTRACT_VERSION, "project_id": cfg.project_id,
        "status": state.get("status", "failed"), "started_at": started.isoformat(),
        "finished_at": max(cfg.clock(), started).isoformat(), "langgraph_version": lg,
        "config": {"variant": cfg.variant, "registry_mode": cfg.registry_mode,
                   "evidence_cutoff": cfg.evidence_cutoff.isoformat() if cfg.evidence_cutoff else None,
                   "llm": f"{cfg.llm.provider}/{cfg.llm.model}" if cfg.llm is not None else None,
                   "llm_options": {k: getattr(cfg.llm_options, k) for k in
                                   ("temperature", "seed", "max_output_tokens", "max_schema_retries",
                                    "max_transport_retries", "prompt_version")} if cfg.llm is not None else None},
        "stage_versions": {s: state[s].get("stage_version") for s in STAGES if s in state},
        "resumed_stages": state.get("resumed", []), "cost": _cost(cfg),
        "evidence_store": store, "pipeline_failures": [f.model_dump(mode="json") for f in failures]}
    if run_dir is not None:
        run_dir.mkdir(parents=True, exist_ok=True)
        record["files"] = {p.name: _digest(p) for p in sorted(run_dir.glob("*.json")) if p.name != "RUN_RECORD.json"}
        text = json.dumps(record, indent=1, sort_keys=True, default=str)
        if guardrails.find_secret(text) is None:
            (run_dir / "RUN_RECORD.json").write_text(text, encoding="utf-8")
    return RunResult(status=state.get("status", "failed"), report=report, failures=failures, run_dir=run_dir,
                     record=record, resumed_stages=list(state.get("resumed", [])))
