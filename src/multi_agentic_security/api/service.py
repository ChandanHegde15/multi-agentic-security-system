"""Orchestration service connecting FastAPI endpoints to the 5-agent LangGraph pipeline."""

from __future__ import annotations

import json
import os
import re
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from multi_agentic_security.agents.agent1_ingestion import (
    DEFAULT_LIMITS,
    Fetcher,
    HttpsFetcher,
    UploadedFile,
    extract_git,
    extract_text,
    extract_zip,
    parse_repo_url,
)
from multi_agentic_security.agents.agent1_ingestion.git_fetch import GitLinkError
from multi_agentic_security.agents.agent2_registry import HttpRegistryClient, SnapshotRegistryClient
from multi_agentic_security.agents.agent4_recommendation import FileResponseStore, LLMOptions
from multi_agentic_security.agents.agent1_ingestion.extract import UNSUPPORTED_MANIFESTS
from multi_agentic_security.agents.agent4_recommendation.providers import OllamaClient
from multi_agentic_security.contracts.pipeline import Failure, PipelineReport
from multi_agentic_security.evidence_store import EvidenceStore
from multi_agentic_security.pipeline import BudgetedLLMClient, CachingLLMClient, PipelineConfig, build_graph, guardrails
from multi_agentic_security.pipeline.graph import PIPELINE_VERSION, STAGES

from .storage import ScanStore

PIPELINE_STAGES = ("extract", "registry", "risk", "recommend", "verify", "report")

SUPPORTED_EXTENSIONS = frozenset({
    ".txt", ".in", ".json", ".py", ".pyw",
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts",
    ".sh", ".md", ".zip",
})
SUPPORTED_BASENAMES = frozenset({"dockerfile", "requirements.txt", "requirements.in", "package.json", "package-lock.json", "npm-shrinkwrap.json"})
MAX_REQUEST_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_SINGLE_MANIFEST_BYTES = 10 * 1024 * 1024

_SUSPICIOUS_FINDINGS = frozenset({
    "malicious_reported",
    "compromised_version",
    "typosquat_listed",
    "vulnerable",
    "registry_security_hold",
    "name_similar_to_popular",
})


class InputValidationError(ValueError):
    """Raised when user-supplied scan parameters or files fail validation."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _default_evidence_dir(root: Path) -> tuple[Path, str]:
    full = root / "research" / "datasets" / "verified" / "normalized" / "v1"
    if full.is_dir():
        return full, "full"
    return root / "tests" / "fixtures" / "agent2" / "evidence" / "v1", "fixture"


def _sanitize_filename(name: str) -> str:
    if not name or "\x00" in name:
        raise InputValidationError("Uploaded file name is missing or invalid.")
    norm = name.replace("\\", "/").strip()
    if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm):
        raise InputValidationError(f"Absolute file path is not permitted: {name!r}")
    parts = [p for p in norm.split("/") if p]
    if not parts or any(p in (".", "..") for p in parts):
        raise InputValidationError(f"Invalid relative file path: {name!r}")
    return "/".join(parts)


def _is_supported_upload(path: str) -> bool:
    base = path.rsplit("/", 1)[-1].lower()
    # Manifests Agent 1 does not parse yet (pyproject.toml, Pipfile, ...) are let through so that Agent 1
    # reports them as ``a1.source.unsupported_manifest`` instead of the upload being refused.
    if base in SUPPORTED_BASENAMES or base in UNSUPPORTED_MANIFESTS or base.startswith("dockerfile"):
        return True
    suffix = Path(base).suffix.lower()
    return suffix in SUPPORTED_EXTENSIONS


def _parse_cutoff(raw: Optional[str]) -> Optional[datetime]:
    if raw is None or not raw.strip():
        return None
    text = raw.strip()
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            dt = datetime.fromisoformat(text + "T00:00:00+00:00")
        else:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError as exc:
        raise InputValidationError("Invalid evidence_cutoff date; use YYYY-MM-DD or ISO-8601 format.") from exc


# LLM-U and LLM-G run on a local Ollama model on this computer, as in the evaluation. Nothing is sent
# outside the computer, no API key is used and no secrets file (such as ``.env``) is ever read.
# The model works without any setting; an environment variable may pick another local model.
DEFAULT_LOCAL_MODEL = "qwen2.5:7b"   # the best of the three local models in the held-out evaluation
DEFAULT_LLM_TIMEOUT_SECONDS = "300"  # local models on a laptop GPU can be slow; same limit as the evaluation
WEB_SETTINGS = ("AGENT4_OLLAMA_MODEL", "AGENT4_LLM_TIMEOUT_SECONDS", "AGENT4_LLM_MAX_OUTPUT_TOKENS")
OLLAMA_LOCAL_URL = "http://127.0.0.1:11434"


def _read_settings() -> dict[str, str]:
    """Return the optional WEB_SETTINGS overrides that are set (non-empty) in the process environment."""
    values: dict[str, str] = {}
    for name in WEB_SETTINGS:
        value = os.environ.get(name, "").strip()
        if value:
            values[name] = value
    return values


def probe_local_ollama(base_url: str = OLLAMA_LOCAL_URL, timeout_s: float = 1.0) -> Optional[list[str]]:
    """Names of the models installed in the local Ollama server, or None if it is not running.

    Only the loopback address is contacted, and any proxy setting is ignored, so nothing leaves the computer.
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(base_url + "/api/tags", timeout=timeout_s) as resp:
            data = json.loads(resp.read(1_000_000))
    except Exception:  # not running, refused, timed out or not JSON: all mean "not available"
        return None
    models = data.get("models", []) if isinstance(data, dict) else []
    return [m["name"] for m in models if isinstance(m, dict) and isinstance(m.get("name"), str)]


def _make_project_id(project_name: str, scan_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", project_name.strip()).strip(".-")
    prefix = (cleaned[:40] if cleaned else "project")
    if not prefix[0].isalnum():
        prefix = "p-" + prefix
    candidate = f"{prefix}-{scan_id[:8]}"[:64]
    if guardrails.check_project_id(candidate) is None:
        return candidate
    return f"scan-{scan_id[:12]}"


def _summarize_metrics(report: PipelineReport) -> dict[str, int]:
    deps = report.extraction.dependencies
    reg_by = {r.dependency_id: r for r in report.registry.results} if report.registry else {}
    risk_by = {a.dependency_id: a for a in report.risk.assessments} if report.risk else {}
    ver_by = {v.dependency_id: v for v in report.verification.verifications} if report.verification else {}

    verified = rejected = needs_review = suspicious = not_found = 0
    for dep in deps:
        did = dep.dependency_id
        v = ver_by.get(did)
        if v is not None:
            if v.verdict == "accept":
                verified += 1
            elif v.verdict == "reject":
                rejected += 1
            else:
                needs_review += 1
        r = reg_by.get(did)
        rk = risk_by.get(did)
        findings = {f.finding for f in rk.findings} if rk else set()
        if findings & _SUSPICIOUS_FINDINGS:
            suspicious += 1
        if (r is not None and r.status == "not_found") or "nonexistent" in findings:
            not_found += 1

    return {
        "packages_analyzed": len(deps),
        "verified": verified,
        "suspicious": suspicious,
        "not_found": not_found,
        "needs_review": needs_review,
        "rejected": rejected,
    }


class ScanService:
    """Runs multi-agent dependency scans safely and tracks live stage progress."""

    def __init__(
        self,
        *,
        runtime_dir: Optional[Path] = None,
        evidence_store: Optional[EvidenceStore] = None,
        evidence_source: Optional[str] = None,
        snapshot_dir: Optional[Path] = None,
        live_client_factory: Optional[Callable[[], Any]] = None,
        git_fetcher_factory: Optional[Callable[[], Fetcher]] = None,
        llm_client_factory: Optional[Callable[[str], Any]] = None,
        ollama_probe: Optional[Callable[[], Optional[list[str]]]] = None,
        max_workers: int = 2,
    ):
        root = _repo_root()
        self.runtime_dir = Path(runtime_dir) if runtime_dir is not None else (root / "runtime")
        self.runs_dir = self.runtime_dir / "runs"
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.store = ScanStore(self.runtime_dir / "scans.db")

        self._settings = _read_settings()
        self._ollama_probe = ollama_probe or probe_local_ollama

        if evidence_store is not None:
            self.evidence_store = evidence_store
            self.evidence_source = evidence_source or "custom"
        else:
            ev_path, ev_src = _default_evidence_dir(root)
            self.evidence_store = EvidenceStore.load(ev_path)
            self.evidence_source = evidence_source or ev_src

        self.snapshot_dir = (
            Path(snapshot_dir)
            if snapshot_dir is not None
            else (root / "tests" / "fixtures" / "agent2" / "registry_snapshot")
        )
        self._live_client_factory = live_client_factory or HttpRegistryClient
        self._git_fetcher_factory = git_fetcher_factory or HttpsFetcher
        self._llm_client_factory = llm_client_factory
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scan-worker")

    def _local_model_status(self) -> dict[str, Any]:
        model = self._settings.get("AGENT4_OLLAMA_MODEL") or DEFAULT_LOCAL_MODEL
        installed = self._ollama_probe()
        return {"model": model, "running": installed is not None,
                "installed": installed is not None and model in installed}

    def health_info(self) -> dict[str, Any]:
        local = self._local_model_status()
        ev = self.evidence_store.run_record() if self.evidence_store is not None else None
        return {
            "status": "ok",
            "pipeline_version": PIPELINE_VERSION,
            "evidence_store": {
                "source": self.evidence_source,
                "complete": ev["complete"] if ev else False,
                "records_indexed": ev["records_indexed"] if ev else 0,
            },
            "snapshot_available": self.snapshot_dir.is_dir(),
            "llm": {
                "rules_available": True,
                "local_model": local["model"],
                "ollama_running": local["running"],
                "local_model_installed": local["installed"],
                "local_model_ready": local["running"] and local["installed"],
            },
            "supported_inputs": sorted(SUPPORTED_BASENAMES | {"*.py", "*.js", "*.ts", "*.sh", "*.md", "*.zip"}),
        }

    def _build_llm(self, variant: str) -> tuple[Any, Optional[FileResponseStore]]:
        if variant == "R0":
            return None, None
        resp_store = FileResponseStore(self.runtime_dir / "responses")
        if self._llm_client_factory is not None:
            inner = self._llm_client_factory(variant)
            wrapped = CachingLLMClient(BudgetedLLMClient(inner, max_calls=200), self.runtime_dir / "llm_cache")
            return wrapped, resp_store

        local = self._local_model_status()
        ollama_model = local["model"]
        if not local["running"]:
            raise InputValidationError(
                f"Variant {variant} runs a local model, but Ollama is not running on this computer. "
                f"Start Ollama and run 'ollama pull {ollama_model}' once, or use R0 (deterministic rules)."
            )
        if not local["installed"]:
            raise InputValidationError(
                f"Variant {variant} needs the local model {ollama_model}. "
                f"Run 'ollama pull {ollama_model}' once, or use R0 (deterministic rules)."
            )
        if ollama_model:
            try:
                client = OllamaClient(ollama_model)
            except ValueError as exc:
                raise InputValidationError(f"Ollama configuration error: {exc}") from exc
            wrapped = CachingLLMClient(BudgetedLLMClient(client, max_calls=200), self.runtime_dir / "llm_cache")
            return wrapped, resp_store

        raise InputValidationError(
            f"Variant {variant} has no local model name. Use R0 (deterministic rules)."
        )

    def submit_scan(
        self,
        *,
        project_name: Optional[str] = None,
        uploaded_files: Optional[list[tuple[str, bytes]]] = None,
        pasted_text: Optional[str] = None,
        git_url: Optional[str] = None,
        variant: str = "R0",
        registry_mode: str = "snapshot",
        evidence_cutoff: Optional[str] = None,
        verifier_enabled: bool = True,
        wait: bool = False,
    ) -> dict[str, Any]:
        if variant not in ("R0", "LLM-G", "LLM-U"):
            raise InputValidationError(f"Unsupported recommender variant {variant!r}; choose R0, LLM-G, or LLM-U.")
        if registry_mode not in ("snapshot", "off", "live"):
            raise InputValidationError(f"Unsupported registry_mode {registry_mode!r}; choose snapshot, off, or live.")

        cutoff_dt = _parse_cutoff(evidence_cutoff)
        if registry_mode == "live" and cutoff_dt is not None:
            raise InputValidationError("Live registry lookups cannot be combined with an evidence cut-off date.")

        has_files = bool(uploaded_files)
        has_text = bool(pasted_text and pasted_text.strip())
        has_git = bool(git_url and git_url.strip())
        if sum([has_files, has_text, has_git]) == 0:
            raise InputValidationError("Provide at least one manifest/code file, a ZIP archive, pasted text, or a public GitHub URL.")
        if sum([has_files, has_text, has_git]) > 1:
            raise InputValidationError("Submit one input source per scan: uploaded files/ZIP, pasted text, OR a GitHub URL.")

        llm_client, response_store = self._build_llm(variant)

        scan_id = uuid.uuid4().hex[:16]
        run_dir = self.runs_dir / scan_id
        run_dir.mkdir(parents=True, exist_ok=True)

        extract_fn = None
        mem_files: list[UploadedFile] = []
        input_kind = "files"
        input_summary = ""
        inferred_name = "Uploaded Project"

        if has_files:
            total_bytes = 0
            cleaned_files: list[tuple[str, bytes]] = []
            for raw_name, data in uploaded_files or []:
                safe_name = _sanitize_filename(raw_name)
                if not _is_supported_upload(safe_name):
                    raise InputValidationError(
                        f"Unsupported file type: {safe_name!r}. Supported: requirements.txt, package.json, "
                        "package-lock.json, .py, .js/.ts, .sh, Dockerfile, .md, or .zip."
                    )
                total_bytes += len(data)
                if total_bytes > MAX_REQUEST_UPLOAD_BYTES:
                    raise InputValidationError(f"Total upload size exceeds the {MAX_REQUEST_UPLOAD_BYTES // (1024 * 1024)} MB limit.")
                cleaned_files.append((safe_name, data))

            zips = [f for f in cleaned_files if f[0].lower().endswith(".zip")]
            if zips:
                if len(cleaned_files) > 1:
                    raise InputValidationError("Upload a single .zip archive on its own, without additional files.")
                zip_name, zip_bytes = zips[0]
                if not zip_bytes:
                    raise InputValidationError("The uploaded ZIP archive is empty.")
                input_kind = "zip"
                input_summary = zip_name
                inferred_name = Path(zip_name).stem
                extract_fn = lambda pid, clk, zname=zip_name, zbytes=zip_bytes: extract_zip(
                    pid, zbytes, zname, limits=DEFAULT_LIMITS, clock=clk
                )
            else:
                for fname, fbytes in cleaned_files:
                    if len(fbytes) > MAX_SINGLE_MANIFEST_BYTES:
                        raise InputValidationError(
                            f"File {fname!r} exceeds the {MAX_SINGLE_MANIFEST_BYTES // (1024 * 1024)} MB single-file limit."
                        )
                    mem_files.append(UploadedFile(fname, fbytes))
                input_kind = "files"
                names = [f.path for f in mem_files]
                input_summary = ", ".join(names[:4]) + (f" (+{len(names) - 4} more)" if len(names) > 4 else "")
                inferred_name = names[0]

        elif has_git:
            assert git_url is not None
            try:
                ref = parse_repo_url(git_url.strip())
            except GitLinkError as exc:
                raise InputValidationError(exc.detail) from exc
            input_kind = "git_repository"
            input_summary = ref.canonical_url
            inferred_name = f"{ref.owner}/{ref.repo}"
            fetcher = self._git_fetcher_factory()
            extract_fn = lambda pid, clk, u=ref.canonical_url, ft=fetcher: extract_git(
                pid, u, ft, limits=DEFAULT_LIMITS, clock=clk
            )

        else:
            assert pasted_text is not None
            if len(pasted_text.encode("utf-8")) > MAX_SINGLE_MANIFEST_BYTES:
                raise InputValidationError("Pasted text exceeds the size limit.")
            input_kind = "text"
            input_summary = "pasted-snippet.md"
            inferred_name = "Pasted Snippet"
            extract_fn = lambda pid, clk, txt=pasted_text: extract_text(pid, txt, clock=clk)

        display_name = (project_name or "").strip() or inferred_name
        project_id = _make_project_id(display_name, scan_id)

        registry_client = None
        if registry_mode == "snapshot":
            registry_client = SnapshotRegistryClient(self.snapshot_dir)
        elif registry_mode == "live":
            registry_client = self._live_client_factory()

        try:
            timeout_s = float(self._settings.get("AGENT4_LLM_TIMEOUT_SECONDS", DEFAULT_LLM_TIMEOUT_SECONDS))
            max_tokens = int(self._settings.get("AGENT4_LLM_MAX_OUTPUT_TOKENS", "1024"))
        except ValueError as exc:
            raise InputValidationError("AGENT4_LLM_TIMEOUT_SECONDS and AGENT4_LLM_MAX_OUTPUT_TOKENS must be numbers.") from exc
        llm_options = LLMOptions(timeout_s=min(max(timeout_s, 5.0), 300.0), max_output_tokens=min(max(max_tokens, 128), 4096))

        cfg = PipelineConfig(
            project_id=project_id,
            files=mem_files,
            extract_fn=extract_fn,
            registry_mode=registry_mode,
            registry_client=registry_client,
            evidence_store=self.evidence_store,
            evidence_cutoff=cutoff_dt,
            variant=variant,
            llm=llm_client,
            response_store=response_store,
            llm_options=llm_options,
            run_dir=run_dir,
        )

        initial_stages = {s: "pending" for s in PIPELINE_STAGES}
        initial_stages["extract"] = "running"
        created_at = _utc_now().isoformat()
        self.store.create_scan({
            "scan_id": scan_id,
            "project_id": project_id,
            "project_name": display_name,
            "input_kind": input_kind,
            "input_summary": input_summary,
            "variant": variant,
            "registry_mode": registry_mode,
            "evidence_cutoff": cutoff_dt.isoformat() if cutoff_dt else None,
            "verifier_enabled": verifier_enabled,
            "status": "running",
            "current_stage": "extract",
            "stages": initial_stages,
            "summary": None,
            "metrics": None,
            "failures": [],
            "error_message": None,
            "run_dir": str(run_dir),
            "created_at": created_at,
            "finished_at": None,
        })

        if wait:
            self._execute_scan(scan_id, cfg)
        else:
            self._executor.submit(self._execute_scan, scan_id, cfg)

        return self.get_scan_detail(scan_id)

    def _execute_scan(self, scan_id: str, cfg: PipelineConfig) -> None:
        stages = {s: "pending" for s in PIPELINE_STAGES}
        stages["extract"] = "running"
        next_after = {
            "extract": "registry",
            "registry": "risk",
            "risk": "recommend",
            "recommend": "verify",
            "verify": "report",
            "report": None,
        }
        try:
            graph = build_graph(cfg)
            thread = {"configurable": {"thread_id": cfg.project_id}}
            for chunk in graph.stream({"status": "running", "failures": []}, thread, stream_mode="updates"):
                for node_name, delta in chunk.items():
                    if not isinstance(delta, dict):
                        continue
                    failed = delta.get("status") == "failed"
                    if node_name in stages:
                        stages[node_name] = "failed" if failed else "done"
                        nxt = next_after[node_name]
                        if not failed and nxt:
                            stages[nxt] = "running"
                            self.store.update_scan(scan_id, current_stage=nxt, stages=stages)
                        else:
                            self.store.update_scan(scan_id, current_stage=node_name, stages=stages)
                    elif failed:
                        for k, v in stages.items():
                            if v in ("pending", "running"):
                                stages[k] = "skipped"
                        self.store.update_scan(scan_id, current_stage=node_name, stages=stages)

            state = graph.get_state(thread).values
            status = state.get("status", "failed")
            failures = [Failure.model_validate(f).model_dump(mode="json") for f in state.get("failures", [])]
            report_data = state.get("report")
            summary_data = None
            metrics_data = None
            if report_data is not None:
                report_obj = PipelineReport.model_validate(report_data)
                summary_data = report_obj.summary.model_dump(mode="json")
                metrics_data = _summarize_metrics(report_obj)
            else:
                for k, v in stages.items():
                    if v in ("pending", "running"):
                        stages[k] = "skipped"

            error_msg = None
            if status == "failed" and failures:
                error_msg = failures[0].get("detail") or failures[0].get("code")

            self._write_run_record(cfg, status, state, failures)
            self.store.update_scan(
                scan_id,
                status="done" if status == "done" else "failed",
                current_stage="done" if status == "done" else "failed",
                stages=stages,
                summary=summary_data,
                metrics=metrics_data,
                failures=failures,
                error_message=error_msg,
                finished_at=_utc_now().isoformat(),
            )
        except Exception as exc:
            for k, v in stages.items():
                if v in ("pending", "running"):
                    stages[k] = "skipped"
            safe_err = f"Scan execution stopped unexpectedly ({type(exc).__name__})."
            self.store.update_scan(
                scan_id,
                status="failed",
                current_stage="failed",
                stages=stages,
                failures=[{"stage": "pipeline", "code": "api.execution_error", "detail": safe_err}],
                error_message=safe_err,
                finished_at=_utc_now().isoformat(),
            )

    def _write_run_record(self, cfg: PipelineConfig, status: str, state: dict, failures: list[dict]) -> None:
        if cfg.run_dir is None:
            return
        run_dir = Path(cfg.run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "format": PIPELINE_VERSION,
            "project_id": cfg.project_id,
            "status": status,
            "config": {
                "variant": cfg.variant,
                "registry_mode": cfg.registry_mode,
                "evidence_cutoff": cfg.evidence_cutoff.isoformat() if cfg.evidence_cutoff else None,
            },
            "stage_versions": {s: state[s].get("stage_version") for s in STAGES if isinstance(state.get(s), dict)},
            "evidence_store": self.evidence_store.run_record() if self.evidence_store is not None else None,
            "pipeline_failures": failures,
        }
        text = json.dumps(record, indent=1, sort_keys=True, default=str)
        if guardrails.find_secret(text) is None:
            (run_dir / "RUN_RECORD.json").write_text(text, encoding="utf-8")

    def get_scan_detail(self, scan_id: str) -> Optional[dict[str, Any]]:
        rec = self.store.get_scan(scan_id)
        if rec is None:
            return None
        rec.pop("_run_dir", None)
        if rec["status"] == "done":
            rec["report"] = self.store.get_report(scan_id)
        else:
            rec["report"] = None
        return rec

    def list_scans_and_stats(self, limit: int = 25) -> dict[str, Any]:
        return {
            "stats": self.store.dashboard_stats(),
            "scans": self.store.list_scans(limit=limit),
        }

    def export_report(self, scan_id: str) -> Optional[dict[str, Any]]:
        return self.store.get_report(scan_id)
