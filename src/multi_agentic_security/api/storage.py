"""SQLite scan-history index and runtime report reader (stored strictly under ``runtime/``).

The evidence store is NEVER placed in SQLite (WEB_HANDOVER.md). This module
indexes scan runs and reads ``PipelineReport`` JSON artifacts from ``run_dir``.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    project_name TEXT NOT NULL,
    input_kind TEXT NOT NULL,
    input_summary TEXT NOT NULL,
    variant TEXT NOT NULL,
    registry_mode TEXT NOT NULL,
    evidence_cutoff TEXT,
    verifier_enabled INTEGER NOT NULL,
    status TEXT NOT NULL,
    current_stage TEXT,
    stages_json TEXT NOT NULL,
    summary_json TEXT,
    metrics_json TEXT,
    failures_json TEXT NOT NULL,
    error_message TEXT,
    run_dir TEXT NOT NULL,
    created_at TEXT NOT NULL,
    finished_at TEXT
);
"""


class ScanStore:
    """Thread-safe SQLite store for scan records and dashboard aggregates."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.execute(_SCHEMA)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def create_scan(self, record: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, project_id, project_name, input_kind, input_summary,
                    variant, registry_mode, evidence_cutoff, verifier_enabled,
                    status, current_stage, stages_json, summary_json, metrics_json,
                    failures_json, error_message, run_dir, created_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["scan_id"],
                    record["project_id"],
                    record["project_name"],
                    record["input_kind"],
                    record["input_summary"],
                    record["variant"],
                    record["registry_mode"],
                    record.get("evidence_cutoff"),
                    1 if record.get("verifier_enabled", True) else 0,
                    record["status"],
                    record.get("current_stage"),
                    json.dumps(record["stages"]),
                    json.dumps(record["summary"]) if record.get("summary") is not None else None,
                    json.dumps(record["metrics"]) if record.get("metrics") is not None else None,
                    json.dumps(record.get("failures", [])),
                    record.get("error_message"),
                    record["run_dir"],
                    record["created_at"],
                    record.get("finished_at"),
                ),
            )
            conn.commit()

    def update_scan(
        self,
        scan_id: str,
        *,
        status: Optional[str] = None,
        current_stage: Optional[str] = None,
        stages: Optional[dict[str, str]] = None,
        summary: Optional[dict[str, Any]] = None,
        metrics: Optional[dict[str, Any]] = None,
        failures: Optional[list[dict[str, Any]]] = None,
        error_message: Optional[str] = None,
        finished_at: Optional[str] = None,
    ) -> None:
        fields: list[str] = []
        values: list[Any] = []
        if status is not None:
            fields.append("status = ?")
            values.append(status)
        if current_stage is not None:
            fields.append("current_stage = ?")
            values.append(current_stage)
        if stages is not None:
            fields.append("stages_json = ?")
            values.append(json.dumps(stages))
        if summary is not None:
            fields.append("summary_json = ?")
            values.append(json.dumps(summary))
        if metrics is not None:
            fields.append("metrics_json = ?")
            values.append(json.dumps(metrics))
        if failures is not None:
            fields.append("failures_json = ?")
            values.append(json.dumps(failures))
        if error_message is not None:
            fields.append("error_message = ?")
            values.append(error_message)
        if finished_at is not None:
            fields.append("finished_at = ?")
            values.append(finished_at)
        if not fields:
            return
        values.append(scan_id)
        with self._lock, self._connect() as conn:
            conn.execute(f"UPDATE scans SET {', '.join(fields)} WHERE scan_id = ?", values)
            conn.commit()

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "scan_id": row["scan_id"],
            "project_id": row["project_id"],
            "project_name": row["project_name"],
            "input_kind": row["input_kind"],
            "input_summary": row["input_summary"],
            "variant": row["variant"],
            "registry_mode": row["registry_mode"],
            "evidence_cutoff": row["evidence_cutoff"],
            "verifier_enabled": bool(row["verifier_enabled"]),
            "status": row["status"],
            "current_stage": row["current_stage"],
            "stages": json.loads(row["stages_json"]),
            "summary": json.loads(row["summary_json"]) if row["summary_json"] else None,
            "metrics": json.loads(row["metrics_json"]) if row["metrics_json"] else None,
            "failures": json.loads(row["failures_json"]),
            "error_message": row["error_message"],
            "created_at": row["created_at"],
            "finished_at": row["finished_at"],
            "_run_dir": row["run_dir"],
        }

    def get_scan(self, scan_id: str) -> Optional[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return self._row_to_dict(row) if row is not None else None

    def list_scans(self, limit: int = 25) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
        out = []
        for r in rows:
            item = self._row_to_dict(r)
            item.pop("_run_dir", None)
            out.append(item)
        return out

    def get_report(self, scan_id: str) -> Optional[dict[str, Any]]:
        rec = self.get_scan(scan_id)
        if rec is None:
            return None
        report_path = Path(rec["_run_dir"]) / "report.json"
        if not report_path.is_file():
            return None
        try:
            return json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def dashboard_stats(self) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT status, metrics_json FROM scans").fetchall()
        totals = {
            "total_scans": len(rows),
            "completed_scans": 0,
            "failed_scans": 0,
            "packages_analyzed": 0,
            "verified": 0,
            "suspicious": 0,
            "not_found": 0,
            "needs_review": 0,
            "rejected": 0,
        }
        for row in rows:
            if row["status"] == "done":
                totals["completed_scans"] += 1
            elif row["status"] == "failed":
                totals["failed_scans"] += 1
            if row["metrics_json"]:
                m = json.loads(row["metrics_json"])
                for key in ("packages_analyzed", "verified", "suspicious", "not_found", "needs_review", "rejected"):
                    totals[key] += int(m.get(key, 0))
        return totals
