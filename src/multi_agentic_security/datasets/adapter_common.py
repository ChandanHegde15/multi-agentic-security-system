"""Shared pieces for source adapters (RESEARCH_METHODOLOGY.md section 3, D-024).

Adapters read text files only. They never extract archives, run code or
contact the network. Every input that is not mapped is reported as a ``Skip``
with a reason; mapped inputs with a caveat get a ``note``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Optional

from multi_agentic_security.contracts.evidence import EvidenceRecord


@dataclass(frozen=True)
class Snapshot:
    """Identifies the acquired copy of a source (from the download log)."""

    source_version: str
    retrieved_at: datetime
    license: str


@dataclass(frozen=True)
class Skip:
    record_id: str
    reason: str
    detail: str = ""


@dataclass
class AdapterResult:
    records: list[EvidenceRecord] = field(default_factory=list)
    skips: list[Skip] = field(default_factory=list)   # input not mapped, with the reason
    notes: list[Skip] = field(default_factory=list)   # mapped, but with a caveat
    duplicates_dropped: int = 0
    files_read: int = 0

    def extend(self, other: "AdapterResult") -> None:
        self.records.extend(other.records)
        self.skips.extend(other.skips)
        self.notes.extend(other.notes)
        self.duplicates_dropped += other.duplicates_dropped
        self.files_read += other.files_read

    def add_unique(self, record: EvidenceRecord, seen: set[str]) -> None:
        if record.evidence_id in seen:
            self.duplicates_dropped += 1
            return
        seen.add(record.evidence_id)
        self.records.append(record)


def file_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def relative(path: Path, root: Path) -> str:
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return Path(path).name


def parse_utc_date(value: Any) -> Optional[date]:
    """ISO timestamp or date -> UTC date; None when absent or unparseable."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).date()


ECOSYSTEM_MAP = {"pypi": "pypi", "npm": "npm"}


def map_ecosystem(value: Any) -> Optional[str]:
    """Source ecosystem label -> canonical key, or None when unsupported."""
    if not isinstance(value, str):
        return None
    return ECOSYSTEM_MAP.get(value.strip().lower())
