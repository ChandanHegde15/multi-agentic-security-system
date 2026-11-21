"""Evaluation harness (D-067): cases -> pipeline -> scorer -> metrics for conditions C1-C5.

Each case is a one-dependency project run through the real pipeline (Agents 1-5). Agent 5 always
runs, so the verifier-on and verifier-off conditions are two *readings* of the same run: C1 and C5
share one R0 run, C3 and C4 share one LLM-G run. This is both the cost saving (C4 needs no extra
LLM call) and the paired design the comparisons need. A case that the pipeline cannot process is
reported in ``errors``, never dropped silently.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from multi_agentic_security.agents.agent4_recommendation import LLMOptions
from multi_agentic_security.evidence_store import EvidenceStore
from multi_agentic_security.pipeline import PipelineConfig, run_pipeline

from .cases import Case, case_to_files
from .metrics import CONDITIONS, Row, aggregate
from .scorer import ScoreContext, score

HARNESS_VERSION = "eval_harness/0.1"
VARIANT_CONDITIONS = {"R0": ("C1", "C5"), "LLM-U": ("C2",), "LLM-G": ("C3", "C4")}


@dataclass
class EvalEnv:
    evidence_store: EvidenceStore
    registry_client: Any                       # a snapshot client (experiments never use live lookups, D-021)
    cutoff: Optional[datetime] = None
    llms: dict = field(default_factory=dict)   # variant -> LLMClient (wrapped for cache and budget)
    response_store: Any = None
    llm_options: LLMOptions = field(default_factory=LLMOptions)
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)


@dataclass
class EvaluationResult:
    rows: list[Row]
    errors: list[dict]
    metrics: dict
    protocol: dict


def run_variant(cases: Iterable[Case], env: EvalEnv, variant: str) -> tuple[list[Row], list[dict]]:
    """Run one recommender variant over the cases; returns (rows for its conditions, errors)."""
    if variant not in VARIANT_CONDITIONS:
        raise ValueError(f"unknown variant {variant!r}")
    if variant != "R0" and (variant not in env.llms or env.response_store is None):
        raise ValueError(f"variant {variant} needs an LLM client in env.llms and a response store")
    ctx = ScoreContext(store=env.evidence_store, client=env.registry_client, cutoff=env.cutoff)
    rows: list[Row] = []
    errors: list[dict] = []
    for case in cases:
        cfg = PipelineConfig(project_id=f"eval-{case.case_id}", files=case_to_files(case), registry_mode="snapshot",
                             registry_client=env.registry_client, evidence_store=env.evidence_store,
                             evidence_cutoff=env.cutoff, variant=variant, llm=env.llms.get(variant),
                             response_store=env.response_store, llm_options=env.llm_options, clock=env.clock)
        res = run_pipeline(cfg)
        if res.status != "done" or res.report is None:
            errors.append({"case_id": case.case_id, "variant": variant, "stage": "pipeline",
                           "failures": [f.code for f in res.failures]})
            continue
        recs = res.report.recommendations.recommendations
        vers = res.report.verification.verifications
        if len(recs) != 1 or len(vers) != 1:
            errors.append({"case_id": case.case_id, "variant": variant, "stage": "extraction",
                           "detail": f"{len(recs)} recommendations for one case (declaration not read as one dependency)"})
            continue
        sc = score(case, recs[0], ctx)
        for cond in VARIANT_CONDITIONS[variant]:
            rows.append(Row(case=case, condition=cond, score=sc, verdict=vers[0].verdict))
    return rows, errors


def run_evaluation(cases: list[Case], env: EvalEnv, variants: Iterable[str] = ("R0",), *, n_boot: int = 2000) -> EvaluationResult:
    cases = sorted(cases, key=lambda c: c.case_id)
    rows: list[Row] = []
    errors: list[dict] = []
    for v in variants:
        r, e = run_variant(cases, env, v)
        rows += r
        errors += e
    protocol = {"harness": HARNESS_VERSION, "cases": len(cases),
                "case_list_sha256": hashlib.sha256("\n".join(c.case_id for c in cases).encode()).hexdigest(),
                "variants": list(variants), "conditions": sorted({r.condition for r in rows}),
                "cutoff": env.cutoff.isoformat() if env.cutoff else None, "store": env.evidence_store.run_record(),
                "errors": len(errors)}
    return EvaluationResult(rows=rows, errors=errors, metrics=aggregate(rows, n_boot=n_boot), protocol=protocol)


def write_result(folder: Path, result: EvaluationResult) -> dict:
    """Write rows, errors, metrics and protocol once (never overwrites); returns file hashes."""
    folder = Path(folder)
    if folder.exists() and any(folder.iterdir()):
        raise FileExistsError(f"{folder} is not empty; results are written once")
    folder.mkdir(parents=True, exist_ok=True)
    rows_text = "".join(json.dumps({
        "case_id": r.case.case_id, "family": r.case.family, "condition": r.condition, "verdict": r.verdict,
        "action": r.score.action, "unsafe": r.score.unsafe, "target": r.score.target.__dict__,
        "claims": [c.__dict__ for c in r.score.claims], "cited": r.score.cited_ids,
        "gold": r.score.gold_ids, "generation_status": r.score.generation_status,
        "action_valid": r.score.action_valid}, sort_keys=True) + "\n"
        for r in sorted(result.rows, key=lambda r: (r.condition, r.case.case_id)))
    files = {"rows.jsonl": rows_text,
             "errors.json": json.dumps(result.errors, indent=1, sort_keys=True),
             "metrics.json": json.dumps(result.metrics, indent=1, sort_keys=True),
             "protocol.json": json.dumps(result.protocol, indent=1, sort_keys=True, default=str)}
    hashes = {}
    for name, text in files.items():
        (folder / name).write_text(text, encoding="utf-8", newline="\n")
        hashes[name] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return hashes
