"""Held-out runner (D-095): runs the frozen evaluation plan on the test side, resumably and within the free limits.

Three steps per job, each a separate command so that nothing is scored before generation is complete:

``generate``  every (case, variant) through the real pipeline with the job's model; answers go to a response cache
              and a raw-response store; one line per generation is appended to ``generations.jsonl``. A rerun skips
              pairs already ``ok`` and retries failed ones. Hosted models: a shared per-model daily ledger caps real
              calls (150 per UTC day), it is written after every generation, and the run stops at the cap or when
              the UTC day changes; spacing of at least 12 s is required. Local models: the Ollama image ID must match
              the plan before any call. One local (GPU) job at a time, one job per hosted model at a time (lock files).
``targets``   recommended targets with no recorded snapshot (offline), for the metadata-only lookups of D-089.
``score``     a cache-only replay (a stub raises on any miss, no call is possible) through the harness; results are
              written once and only if every replayed generation status equals the one in the generation log.

Gates: nothing runs unless the freeze record names the SHA-256 of the protocol and of the plan and both still match;
each case file must match the hash in the plan; the registry client is a snapshot client (no live lookups). Errors
are states: a failed generation stays ``llm_error``/``abstain`` and is counted, never replaced by a default.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from multi_agentic_security.agents.agent4_recommendation import LLMOptions
from multi_agentic_security.agents.agent4_recommendation.llm import FileResponseStore, LLMError, LLMTimeout, MemoryResponseStore

from multi_agentic_security.pipeline import CachingLLMClient, PipelineConfig, run_pipeline

from .cases import Case, case_to_files, read_cases
from .harness import EvalEnv, run_evaluation, write_result

RUNNER_VERSION = "heldout_runner/0.2"     # 0.2: redo of named pairs (D-102); recorded timeouts replay as timeouts (D-103)
PLAN_FORMAT = "heldout_plan/1"
FREEZE_FORMAT = "protocol_freeze/1"
SETTINGS = ("S0", "S1", "S2")
PROVIDERS = ("ollama", "groq")
VARIANTS = ("LLM-U", "LLM-G")
DAILY_CAP = 150                      # real calls per hosted model per UTC day (free-tier limit)
MIN_SPACING_S = 12.0
CALLS_PER_GENERATION = 5             # worst case: 1 + 2 schema repairs + 2 transport retries


class RunnerError(RuntimeError):
    """A gate refused the run; the message says which one."""


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sha256_text(path: Path) -> str:
    """SHA-256 of a text file with CRLF read as LF, so that git's line-ending conversion on checkout does not change the
    hash of a frozen document (used for the protocol and the plan)."""
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def model_tag(model: str) -> str:
    return model.replace("/", "_").replace(":", "_")


# --------------------------------------------------------------------------- plan and freeze

@dataclass(frozen=True)
class Job:
    job_id: str
    setting: str
    provider: str
    model: str
    prompt_version: str
    cases_file: str
    cases_sha256: str
    cutoff: Optional[str] = None          # ISO date (UTC midnight) or None for S0
    image_id: Optional[str] = None        # local models: digest prefix recorded at selection

    def __post_init__(self) -> None:
        if self.setting not in SETTINGS or self.provider not in PROVIDERS:
            raise RunnerError(f"job {self.job_id}: unknown setting or provider")
        if (self.setting == "S0") != (self.cutoff is None):
            raise RunnerError(f"job {self.job_id}: S0 has no cut-off and S1/S2 have one")
        if self.provider == "ollama" and not self.image_id:
            raise RunnerError(f"job {self.job_id}: a local model needs its image ID")

    @property
    def cutoff_dt(self) -> Optional[datetime]:
        return None if self.cutoff is None else datetime.fromisoformat(self.cutoff).replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Plan:
    root: Path
    protocol: str
    evidence_store: str
    snapshot_folders: tuple[str, ...]
    out_root: str
    cache_root: str
    results_root: str
    ledger_dir: str
    max_output_tokens: int
    jobs: tuple[Job, ...]
    excluded_case_ids: tuple[str, ...] = ()
    score_gate: Optional[str] = None      # D-097: a result record that must exist (status "done") before any scoring

    def path(self, rel: str) -> Path:
        return self.root / rel

    def job(self, job_id: str) -> Job:
        for j in self.jobs:
            if j.job_id == job_id:
                return j
        raise RunnerError(f"no job {job_id!r} in the plan")


def load_plan(path: Path, root: Path) -> Plan:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    if d.get("format") != PLAN_FORMAT:
        raise RunnerError(f"plan format must be {PLAN_FORMAT}")
    jobs = tuple(Job(**j) for j in d["jobs"])
    if len({j.job_id for j in jobs}) != len(jobs):
        raise RunnerError("job IDs must be unique")
    return Plan(root=Path(root), protocol=d["protocol"], evidence_store=d["evidence_store"],
                snapshot_folders=tuple(d["snapshot_folders"]), out_root=d["out_root"], cache_root=d["cache_root"],
                results_root=d["results_root"], ledger_dir=d["ledger_dir"], max_output_tokens=int(d["max_output_tokens"]),
                jobs=jobs, excluded_case_ids=tuple(d.get("excluded_case_ids", ())), score_gate=d.get("score_gate"))


def check_frozen(plan_path: Path, plan: Plan, freeze_path: Path) -> dict:
    """The run gate: the freeze record must exist and name the current hashes of the protocol and the plan."""
    freeze_path = Path(freeze_path)
    if not freeze_path.is_file():
        raise RunnerError("the protocol is not frozen (no freeze record): held-out runs are refused")
    rec = json.loads(freeze_path.read_text(encoding="utf-8"))
    if rec.get("format") != FREEZE_FORMAT or rec.get("status") != "frozen":
        raise RunnerError("the freeze record is not a valid frozen record")
    proto = plan.path(plan.protocol)
    if not proto.is_file() or sha256_text(proto) != rec.get("protocol_sha256"):
        raise RunnerError("the protocol differs from the frozen one")
    if sha256_text(plan_path) != rec.get("plan_sha256"):
        raise RunnerError("the plan differs from the frozen one")
    return rec


def job_cases(plan: Plan, job: Job) -> list[Case]:
    path = plan.path(job.cases_file)
    if sha256_file(path) != job.cases_sha256:
        raise RunnerError(f"job {job.job_id}: case file hash differs from the plan")
    return sorted(read_cases(path), key=lambda c: c.case_id)


# --------------------------------------------------------------------------- locks and ledger

class Lock:
    """An exclusive lock file. A lock left by a dead process is not removed automatically: that is a state the
    owner checks (it can mean that a job is still running)."""

    def __init__(self, path: Path, holder: str):
        self.path, self.holder = Path(path), holder

    def __enter__(self) -> "Lock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            held = self.path.read_text(encoding="utf-8", errors="replace").strip()
            raise RunnerError(f"lock {self.path.name} is held ({held}); one job at a time") from None
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(f"{self.holder} pid {os.getpid()} since {datetime.now(timezone.utc).isoformat()}")
        return self

    def __exit__(self, *exc) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def lock_for(plan: Plan, job: Job) -> Lock:
    name = "gpu.lock" if job.provider == "ollama" else f"hosted_{model_tag(job.model)}.lock"
    return Lock(plan.path(plan.out_root) / "locks" / name, job.job_id)


class Ledger:
    """Real calls per model and UTC day, in the format of the development ledgers (shared across all runs)."""

    def __init__(self, folder: Path, model: str, cap: int = DAILY_CAP):
        self.path = Path(folder) / f"ledger_{model.replace('/', '_')}.json"
        self.model, self.cap = model, cap

    def _read(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}

    def used(self, day: str) -> int:
        return int(self._read().get(self.model, {}).get(day, 0))

    def add(self, day: str, n: int) -> None:
        if n <= 0:
            return
        d = self._read()
        d.setdefault(self.model, {})[day] = int(d.get(self.model, {}).get(day, 0)) + n
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(d, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)


class _Counted:
    """Counts the calls that reach the real client and refuses any beyond the allowance."""

    def __init__(self, inner, allowance: int):
        self.inner, self.provider, self.model = inner, inner.provider, inner.model
        self.allowance, self.calls = allowance, 0

    def generate(self, request):
        if self.calls >= self.allowance:
            raise LLMError("daily call budget reached", code="budget_exhausted")
        self.calls += 1
        return self.inner.generate(request)


# --------------------------------------------------------------------------- generate

def _options(plan: Plan, job: Job) -> LLMOptions:
    return LLMOptions(temperature=0.0, max_output_tokens=plan.max_output_tokens, prompt_version=job.prompt_version,
                      timeout_s=300.0 if job.provider == "ollama" else 60.0)


def _require_snapshot(client) -> None:
    if getattr(client, "mode", None) != "snapshot":
        raise RunnerError("the registry client must be a snapshot client: no live lookups in held-out runs")


def _done(gen_path: Path) -> dict:
    last: dict = {}
    if gen_path.exists():
        for line in gen_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                d = json.loads(line)
                last[(d["case_id"], d["variant"])] = d
    return last


def generate(plan: Plan, job: Job, *, llm, store, registry_client, utc_now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
             image_id: Optional[str] = None, ledger: Optional[Ledger] = None, log: Callable[[str], None] = print,
             redo: Iterable[tuple[str, str]] = (), redo_reason: Optional[str] = None) -> dict:
    """Generate the job's answers (resumable). ``llm`` is the real client; it is wrapped here in the call counter
    and the response cache, in that order, so cache hits cost nothing.

    ``redo`` (D-102): regenerate exactly these (case, variant) pairs, even if they are ``ok``, and nothing else; each
    new line carries ``redo_reason``. The earlier lines stay in the log (the last line of a pair counts)."""
    _require_snapshot(registry_client)
    if llm.provider != job.provider or llm.model != job.model:
        raise RunnerError(f"client {llm.provider}/{llm.model} is not the job's model {job.provider}/{job.model}")
    if job.provider == "ollama":
        if not image_id or not image_id.startswith(job.image_id):
            raise RunnerError(f"local image {image_id!r} is not the planned image {job.image_id}")
    else:
        spacing = getattr(llm, "_min_interval", None)
        if spacing is None or spacing < MIN_SPACING_S:
            raise RunnerError(f"hosted calls need at least {MIN_SPACING_S:.0f} s spacing")
        if ledger is None:
            raise RunnerError("hosted jobs need the daily ledger")
    cases = job_cases(plan, job)
    run_dir = plan.path(plan.out_root) / job.job_id
    run_dir.mkdir(parents=True, exist_ok=True)
    gen_path = run_dir / "generations.jsonl"
    day = utc_now().date().isoformat()
    allowance = 10 ** 9 if ledger is None else max(0, min(DAILY_CAP, ledger.cap) - ledger.used(day))
    counted = _Counted(llm, allowance)
    cache = CachingLLMClient(counted, plan.path(plan.cache_root) / f"{job.provider}_{model_tag(job.model)}")
    raw = FileResponseStore(run_dir / "raw")
    opts = _options(plan, job)
    done = {k for k, v in _done(gen_path).items() if v.get("generation_status") == "ok"}
    redo = set(redo)
    if redo:
        if not redo_reason:
            raise RunnerError("a redo needs a recorded reason")
        unknown = redo - {(c.case_id, v) for c in cases for v in VARIANTS}
        if unknown:
            raise RunnerError(f"redo pairs are not in job {job.job_id}: {sorted(unknown)}")
        done = {(c.case_id, v) for c in cases for v in VARIANTS} - redo
    stats = {"job": job.job_id, "cases": len(cases), "already_ok": len(done), "generated": 0, "stopped": None}
    log(f"{job.job_id}: {len(cases)} cases, {len(done)} pairs already ok, call allowance today {allowance if ledger else 'none'}")
    with lock_for(plan, job):
        for case in cases:
            for variant in VARIANTS:
                if (case.case_id, variant) in done:
                    continue
                if ledger is not None:
                    if utc_now().date().isoformat() != day:
                        stats["stopped"] = "utc_day_changed"
                        break
                    if counted.calls + CALLS_PER_GENERATION > allowance:
                        stats["stopped"] = "daily_cap"
                        break
                before = counted.calls
                cfg = PipelineConfig(project_id=f"heldout-{case.case_id}-{variant}", files=case_to_files(case),
                                     registry_mode="snapshot", registry_client=registry_client,
                                     evidence_store=store, evidence_cutoff=job.cutoff_dt, variant=variant, llm=cache,
                                     response_store=raw, llm_options=opts, clock=utc_now)
                try:
                    res = run_pipeline(cfg)
                finally:
                    if ledger is not None:
                        ledger.add(day, counted.calls - before)
                if res.report is None or len(res.report.recommendations.recommendations) != 1:
                    line = {"case_id": case.case_id, "variant": variant, "status": res.status,
                            "failures": [f.code for f in res.failures], "generation_status": None}
                else:
                    r = res.report.recommendations.recommendations[0]
                    line = {"case_id": case.case_id, "variant": variant, "status": "ok", "action": r.action,
                            "generation_status": r.generation_status,
                            "target": r.target.model_dump(mode="json") if r.target else None,
                            "model": r.model, "prompt_version": r.prompt_version, "raw_ref": r.raw_response_ref}
                line["at"] = utc_now().isoformat()
                if redo:
                    line["redo_reason"] = redo_reason
                with open(gen_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(line, sort_keys=True) + "\n")
                stats["generated"] += 1
                log(f"{case.case_id} {variant} {line.get('action')} {line.get('generation_status')} calls {counted.calls}")
            if stats["stopped"]:
                break
    last = _done(gen_path)
    stats.update(real_calls=counted.calls, cache_hits=cache.hits,
                 complete=all((c.case_id, v) in last for c in cases for v in VARIANTS),
                 ok_pairs=sum(1 for v in last.values() if v.get("generation_status") == "ok"),
                 failed_pairs=sum(1 for v in last.values() if v.get("generation_status") not in (None, "ok")))
    log(json.dumps(stats, sort_keys=True))
    return stats


# --------------------------------------------------------------------------- targets

def missing_targets(plan: Plan, job: Job, registry_client) -> dict:
    """Recommended targets in the generation log that no snapshot folder records (offline)."""
    from multi_agentic_security.agents.agent2_registry.client import registry_url

    _require_snapshot(registry_client)
    last = _done(plan.path(plan.out_root) / job.job_id / "generations.jsonl")
    names: dict = {}
    for d in last.values():
        t = d.get("target")
        if t:
            k = (t["package"]["ecosystem"], t["package"]["name_normalized"])
            names[k] = names.get(k, 0) + 1
    missing, invalid = [], []
    for (eco, name), n in sorted(names.items()):
        try:
            registry_url(eco, name)
        except ValueError:
            invalid.append(f"{eco}:{name}")
            continue
        if registry_client.lookup(eco, name) is None:
            missing.append({"ecosystem": eco, "name": name, "recommendations": n})
    return {"job": job.job_id, "distinct_targets": len(names), "missing": missing, "invalid_names": invalid}


# --------------------------------------------------------------------------- score

class _CacheOnly:
    """Scoring makes no calls. Errors are never cached (D-094), so a miss replays the error the run recorded for that
    exact request (D-103): a request whose latest raw record is a timeout raises ``LLMTimeout`` again, any other miss
    raises ``LLMError`` (``llm_error``), as before."""

    def __init__(self, provider: str, model: str, timed_out: frozenset = frozenset()):
        self.provider, self.model, self._timed_out = provider, model, timed_out

    def generate(self, request):
        if request.key(self.provider, self.model) in self._timed_out:
            raise LLMTimeout("recorded timeout replayed", code="timeout")
        raise LLMError("cache miss: scoring makes no calls", code="cache_miss")


def recorded_timeouts(raw_dir: Path) -> frozenset:
    """Request keys whose latest raw record (by time received) is a timeout (D-103)."""
    latest: dict = {}
    for f in sorted(raw_dir.glob("*.json")) if raw_dir.is_dir() else ():
        d = json.loads(f.read_text(encoding="utf-8"))
        k, t = d.get("request_key"), d.get("received_at") or ""
        if k and (k not in latest or t >= latest[k][0]):
            latest[k] = (t, str(d.get("error") or "").startswith("LLMTimeout"))
    return frozenset(k for k, (_, timeout) in latest.items() if timeout)


COND_VARIANT = {"C2": "LLM-U", "C3": "LLM-G", "C4": "LLM-G"}


def check_score_gate(plan: Plan) -> Optional[dict]:
    """D-097: scoring waits for the claim-matcher audit (annotation Task C). Generation does not."""
    if plan.score_gate is None:
        return None
    gate = plan.path(plan.score_gate)
    if not gate.is_file():
        raise RunnerError(f"scoring is closed until {plan.score_gate} exists (annotation Task C, D-097)")
    rec = json.loads(gate.read_text(encoding="utf-8"))
    if rec.get("status") != "done":
        raise RunnerError(f"{plan.score_gate} does not say status 'done'; scoring stays closed")
    return rec


def score(plan: Plan, job: Job, *, store, registry_client, n_boot: int = 2000) -> dict:
    """Replay the job from the cache only and write the results once. Refuses an incomplete generation log and any
    replay whose generation status differs from the log (a replay that is not the run)."""
    gate = check_score_gate(plan)
    _require_snapshot(registry_client)
    failures = list(getattr(registry_client, "load_failures", []))
    missing_folders = [f for f, why in failures if why == "snapshot folder does not exist"]
    if missing_folders:
        raise RunnerError(f"snapshot folders missing: {missing_folders}; record the target lookups first (an empty "
                          "folder with its run record when no target needs one)")
    cases = job_cases(plan, job)
    last = _done(plan.path(plan.out_root) / job.job_id / "generations.jsonl")
    absent = [(c.case_id, v) for c in cases for v in VARIANTS if (c.case_id, v) not in last]
    if absent:
        raise RunnerError(f"job {job.job_id}: {len(absent)} (case, variant) pairs have no generation yet; generate first")
    timed_out = recorded_timeouts(plan.path(plan.out_root) / job.job_id / "raw")
    llm = CachingLLMClient(_CacheOnly(job.provider, job.model, timed_out), plan.path(plan.cache_root) / f"{job.provider}_{model_tag(job.model)}")
    env = EvalEnv(evidence_store=store, registry_client=registry_client, cutoff=job.cutoff_dt,
                  llms={"LLM-U": llm, "LLM-G": llm}, response_store=MemoryResponseStore(), llm_options=_options(plan, job))
    res = run_evaluation(cases, env, ("R0",) + VARIANTS, n_boot=n_boot)
    mismatches = []
    for r in res.rows:
        v = COND_VARIANT.get(r.condition)
        if v and r.score.generation_status != last[(r.case.case_id, v)]["generation_status"]:
            mismatches.append({"case_id": r.case.case_id, "variant": v, "logged": last[(r.case.case_id, v)]["generation_status"],
                               "replayed": r.score.generation_status})
    # A pipeline failure is a state when the log recorded it for that pair (R0 has no log: its errors are deterministic
    # and reported in errors.json). Any other error means the replay is not the run.
    unexplained = [e for e in res.errors if e.get("variant") != "R0"
                   and last[(e["case_id"], e["variant"])].get("generation_status") is not None]
    if mismatches or unexplained:
        raise RunnerError(f"job {job.job_id}: replay differs from the run ({len(mismatches)} status mismatches, "
                          f"{len(unexplained)} unexplained pipeline errors); nothing written. "
                          f"First: {(mismatches or unexplained)[:3]}")
    res.protocol.update({"runner": RUNNER_VERSION, "recorded_timeouts_replayed": len(timed_out), "job": job.__dict__, "cache_hits": llm.hits, "cache_misses": llm.misses,
                         "replay_check": "every replayed generation status equals the generation log",
                         "excluded_case_ids_in_job": sorted(set(plan.excluded_case_ids) & {c.case_id for c in cases}),
                         "snapshot_folders": list(plan.snapshot_folders),
                         "snapshot_load_failures": [list(f) for f in failures],
                         "score_gate": None if gate is None else {"file": plan.score_gate, "sha256": sha256_file(plan.path(plan.score_gate))}})
    hashes = write_result(plan.path(plan.results_root) / job.job_id, res)
    return {"job": job.job_id, "rows": len(res.rows), "cache_hits": llm.hits, "cache_misses": llm.misses, "files": hashes}


# --------------------------------------------------------------------------- command line (the only place that builds real clients)

def ollama_image_id(model: str, base_url: str = "http://127.0.0.1:11434", fetch: Optional[Callable[[str], bytes]] = None) -> Optional[str]:
    """The digest of a pulled local model, read from the loopback Ollama server (``/api/tags``)."""
    from multi_agentic_security.agents.agent4_recommendation.providers import _loopback_url
    import urllib.request

    url = _loopback_url(base_url) + "/api/tags"
    if fetch is None:
        def fetch(u: str) -> bytes:
            with urllib.request.urlopen(u, timeout=10) as resp:       # loopback only (checked above)
                return resp.read(1_000_000)
    data = json.loads(fetch(url))
    for m in data.get("models", []):
        if m.get("name") == model or m.get("model") == model:
            return m.get("digest")
    return None


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Held-out runner (D-095)")
    ap.add_argument("step", choices=("generate", "targets", "score"))
    ap.add_argument("job_id")
    ap.add_argument("--plan", required=True)
    ap.add_argument("--freeze", required=True)
    ap.add_argument("--root", default=".")
    ap.add_argument("--secrets", default=None, help="path of the local secrets file (hosted jobs only)")
    ap.add_argument("--redo", action="append", default=[], metavar="CASE_ID:VARIANT",
                    help="generate: regenerate exactly these pairs (D-102); needs --redo-reason")
    ap.add_argument("--redo-reason", default=None)
    a = ap.parse_args(argv)
    from multi_agentic_security.evidence_store import EvidenceStore
    from multi_agentic_security.pipeline import MultiSnapshotClient

    root = Path(a.root).resolve()
    plan = load_plan(Path(a.plan), root)
    check_frozen(Path(a.plan), plan, Path(a.freeze))
    job = plan.job(a.job_id)
    client = MultiSnapshotClient([plan.path(f) for f in plan.snapshot_folders])
    if a.step == "targets":
        print(json.dumps(missing_targets(plan, job, client), indent=1))
        return 0
    store = EvidenceStore.load(plan.path(plan.evidence_store))
    if a.step == "score":
        print(json.dumps(score(plan, job, store=store, registry_client=client), indent=1, default=str))
        return 0
    from multi_agentic_security.agents.agent4_recommendation import providers
    if job.provider == "ollama":
        llm = providers.OllamaClient(job.model, num_ctx=8192)
        redo = [tuple(x.rsplit(":", 1)) for x in a.redo]
        generate(plan, job, llm=llm, store=store, registry_client=client, image_id=ollama_image_id(job.model),
                 redo=redo, redo_reason=a.redo_reason)
    else:
        if not a.secrets:
            raise RunnerError("hosted jobs need --secrets")
        providers.load_secrets(Path(a.secrets))          # values are never printed
        slot = {"openai/gpt-oss-20b": "AGENT4_GROQ_MODEL", "qwen/qwen3.8-27b": "AGENT4_GROQ_MODEL_2"}.get(job.model)
        if slot is None:
            raise RunnerError(f"no Groq slot for {job.model}")
        llm = providers.GroqClient(model_var=slot, min_interval_s=MIN_SPACING_S)
        generate(plan, job, llm=llm, store=store, registry_client=client,
                 ledger=Ledger(plan.path(plan.ledger_dir), job.model))
    return 0


if __name__ == "__main__":
    sys.exit(main())
