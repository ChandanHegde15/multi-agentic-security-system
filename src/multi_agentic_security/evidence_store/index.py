"""Evidence-store index (D-053).

* Tables are loaded from an explicit allow-list of folders, never from a glob, so
  superseded builds lying next to the current ones are never read.
* Each ``records.jsonl`` is read once into memory; its SHA-256 and size are
  checked against ``MANIFEST.json`` before any record is used. A mismatch, a
  missing table or any record that does not re-validate as an evidence/1.1
  record (including its recomputed ``evidence_id``) rejects that table, and the
  rejection is a failure state that every caller must report.
* The index maps (ecosystem, normalized name) to evidence records. Label families
  stay separate. Typosquat records are indexed twice: by the squatting name
  (role ``name``) and by the imitated target (role ``target``); the role is kept
  so a target is never mistaken for a typosquat.
* Cut-off rule: with a cut-off date, only records published strictly before it
  are returned (``EvidenceRecord.known_before``); later and undated records are
  excluded and counted. Without a cut-off every record is returned and undated
  ones are listed so callers can flag them.
* The store never writes anything.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable, Optional, Union

from multi_agentic_security.contracts.evidence import EvidenceRecord, LabelFamily, Provenance, VersionScope

STORE_VERSION = "evidence_store/1"


@dataclass(frozen=True)
class TableSpec:
    folder: str          # family folder under the root, e.g. "malicious_withdrawn"
    table: str           # table folder, e.g. "openssf_a2"
    families: tuple[str, ...]

    @property
    def key(self) -> str:
        return f"{self.folder}/{self.table}"


# Current tables (docs/datasets/DATASET_EVALUATION.md, 2026-11-14). Superseded builds
# (vulnerable/osv_pypi, malicious_withdrawn/openssf) are deliberately absent.
CURRENT_TABLES: tuple[TableSpec, ...] = (
    TableSpec("vulnerable", "osv_pypi_a2", ("vulnerable",)),
    TableSpec("malicious_withdrawn", "openssf_a2", ("malicious", "withdrawn")),
    TableSpec("malicious", "datadog_manifests", ("malicious",)),
    TableSpec("malicious", "malregistry_listing", ("malicious",)),
    TableSpec("typosquat", "ecosystems_typosquats", ("typosquat",)),
    TableSpec("typosquat", "yctt_pairs", ("typosquat",)),
    TableSpec("benign_reference", "pypi_popular", ("benign_reference",)),
    TableSpec("benign_reference", "yctt_targets", ("benign_reference",)),
)


@dataclass(frozen=True)
class TableInfo:
    key: str
    loaded: bool
    records: int = 0
    records_sha256: Optional[str] = None
    records_bytes: Optional[int] = None
    schema_version: Optional[str] = None
    adapter_version: Optional[str] = None
    source_versions: tuple[str, ...] = ()
    licenses: tuple[str, ...] = ()
    undated_records: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"table": self.key, "loaded": self.loaded, "records": self.records,
                "records_sha256": self.records_sha256, "records_bytes": self.records_bytes,
                "schema_version": self.schema_version, "adapter_version": self.adapter_version,
                "source_versions": list(self.source_versions), "licenses": list(self.licenses),
                "undated_records": self.undated_records}


@dataclass(frozen=True)
class StoreFailure:
    table: str
    code: str
    detail: str


@dataclass(frozen=True)
class EvidenceMatch:
    record: EvidenceRecord
    role: str            # "name" or "target" (typosquat target)
    table: str

    @property
    def evidence_id(self) -> str:
        return self.record.evidence_id


@dataclass(frozen=True)
class QueryResult:
    matches: tuple[EvidenceMatch, ...]
    excluded_after_cutoff: tuple[str, ...] = ()
    excluded_undated: tuple[str, ...] = ()
    undated_included: tuple[str, ...] = ()

    def by_family(self, family: str, role: str = "name") -> list[EvidenceMatch]:
        return [m for m in self.matches if m.record.family.value == family and m.role == role]


class _TableError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code, self.detail = code, detail


def _record_from_dict(d: dict, families: tuple[str, ...]) -> EvidenceRecord:
    if not isinstance(d, dict):
        raise ValueError("record is not an object")
    if d.get("family") not in families:
        raise ValueError(f"family {d.get('family')!r} does not belong in this table")
    p = d["provenance"]
    retrieved = datetime.fromisoformat(p["retrieved_at"])
    prov = Provenance(source_dataset=p["source_dataset"], source_version=p["source_version"],
                      source_record_id=p["source_record_id"], source_file=p["source_file"],
                      source_file_sha256=p["source_file_sha256"], license=p["license"], retrieved_at=retrieved,
                      human_reviewed=bool(p.get("human_reviewed", False)))
    published = d.get("published")
    rec = EvidenceRecord(
        family=LabelFamily(d["family"]), ecosystem=d["ecosystem"], name_raw=d["name_raw"],
        name_normalized=d["name_normalized"], version_scope=VersionScope(d["version_scope"]), provenance=prov,
        version=d.get("version"), version_range=d.get("version_range"),
        published=date.fromisoformat(published) if published else None,
        corroborating_sources=tuple(d.get("corroborating_sources") or ()),
        target_name_raw=d.get("target_name_raw"), target_name_normalized=d.get("target_name_normalized"))
    if rec.evidence_id != d.get("evidence_id"):
        raise ValueError(f"evidence_id {d.get('evidence_id')!r} does not match the record ({rec.evidence_id})")
    return rec


def _load_table(root: Path, spec: TableSpec) -> tuple[TableInfo, list[EvidenceRecord]]:
    folder = root / spec.folder / spec.table
    manifest_path, records_path = folder / "MANIFEST.json", folder / "records.jsonl"
    if not folder.is_dir() or not manifest_path.is_file() or not records_path.is_file():
        raise _TableError("evidence_store.table_missing", f"{spec.key}: folder, MANIFEST.json or records.jsonl missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest["files"]["records.jsonl"]
        expected_sha, expected_bytes = expected["sha256"], int(expected["bytes"])
        expected_count = int(manifest["counts"]["records"])
        schema = manifest.get("schema_version")
        if not isinstance(schema, str) or not schema.startswith("evidence/1"):
            raise ValueError(f"schema_version {schema!r} is not evidence/1.x")
        if manifest.get("table") not in (None, spec.table):
            raise ValueError(f"manifest names table {manifest.get('table')!r}, expected {spec.table!r}")
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise _TableError("evidence_store.manifest_invalid",
                          f"{spec.key}: MANIFEST.json unusable ({type(exc).__name__}: {str(exc)[:120]})")
    data = records_path.read_bytes()  # read once: the hash and the parse see the same bytes
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != expected_sha:
        raise _TableError("evidence_store.hash_mismatch",
                          f"{spec.key}: records.jsonl SHA-256 {actual_sha[:12]}... != manifest {str(expected_sha)[:12]}...")
    if len(data) != expected_bytes:
        raise _TableError("evidence_store.size_mismatch", f"{spec.key}: {len(data)} bytes != manifest {expected_bytes}")
    records: list[EvidenceRecord] = []
    for line_no, line in enumerate(data.decode("utf-8").split("\n"), start=1):
        if not line.strip():
            continue
        try:
            records.append(_record_from_dict(json.loads(line), spec.families))
        except (ValueError, KeyError, TypeError, OverflowError, RecursionError) as exc:
            raise _TableError("evidence_store.invalid_record", f"{spec.key} line {line_no}: {str(exc)[:200]}")
    if len(records) != expected_count:
        raise _TableError("evidence_store.count_mismatch",
                          f"{spec.key}: {len(records)} records != manifest count {expected_count}")
    source_versions = manifest.get("source_versions") or ([manifest["source_version"]] if manifest.get("source_version") else [])
    licenses = manifest.get("licenses") or ([manifest["license"]] if manifest.get("license") else [])
    info = TableInfo(key=spec.key, loaded=True, records=len(records), records_sha256=actual_sha,
                     records_bytes=len(data), schema_version=manifest.get("schema_version"),
                     adapter_version=manifest.get("adapter_version"), source_versions=tuple(source_versions),
                     licenses=tuple(licenses), undated_records=sum(1 for r in records if r.published is None))
    return info, records


class EvidenceStore:
    """Load with ``EvidenceStore.load(root)``; ``root`` is the folder that holds the
    family folders (``.../verified/normalized/v1``)."""

    def __init__(self, root: Path, tables: list[TableInfo], failures: list[StoreFailure],
                 records: Iterable[tuple[str, EvidenceRecord]]):
        self.root = root
        self.tables = tables
        self.failures = failures
        self._by_id: dict[str, EvidenceRecord] = {}
        self._table_of: dict[str, str] = {}
        self._index: dict[tuple[str, str], list[tuple[EvidenceRecord, str]]] = {}
        for table, rec in records:
            eid = rec.evidence_id
            if eid in self._by_id:
                self.failures.append(StoreFailure(table, "evidence_store.duplicate_evidence_id",
                                                  f"{eid} already loaded from {self._table_of[eid]}; second copy ignored"))
                continue
            self._by_id[eid], self._table_of[eid] = rec, table
            self._index.setdefault((rec.ecosystem, rec.name_normalized), []).append((rec, "name"))
            if rec.family is LabelFamily.TYPOSQUAT and rec.target_name_normalized:
                self._index.setdefault((rec.ecosystem, rec.target_name_normalized), []).append((rec, "target"))

    @classmethod
    def load(cls, root: Union[str, Path], tables: Iterable[TableSpec] = CURRENT_TABLES) -> "EvidenceStore":
        root = Path(root)
        infos: list[TableInfo] = []
        failures: list[StoreFailure] = []
        loaded: list[tuple[str, EvidenceRecord]] = []
        for spec in tables:
            try:
                info, records = _load_table(root, spec)
            except _TableError as exc:
                infos.append(TableInfo(key=spec.key, loaded=False))
                failures.append(StoreFailure(spec.key, exc.code, exc.detail))
                continue
            except (OSError, UnicodeDecodeError) as exc:
                infos.append(TableInfo(key=spec.key, loaded=False))
                failures.append(StoreFailure(spec.key, "evidence_store.unreadable", f"{spec.key}: {type(exc).__name__}"))
                continue
            infos.append(info)
            loaded.extend((spec.key, r) for r in records)
        return cls(root, infos, failures, loaded)

    @property
    def complete(self) -> bool:
        """True when every allow-listed table loaded and verified."""
        return all(t.loaded for t in self.tables) and not any(
            f.code != "evidence_store.duplicate_evidence_id" for f in self.failures)

    @property
    def missing_tables(self) -> list[str]:
        return [t.key for t in self.tables if not t.loaded]

    def get(self, evidence_id: str) -> Optional[EvidenceRecord]:
        return self._by_id.get(evidence_id)

    def table_of(self, evidence_id: str) -> Optional[str]:
        return self._table_of.get(evidence_id)

    def __len__(self) -> int:
        return len(self._by_id)

    def records(self, *, family: Optional[str] = None, ecosystem: Optional[str] = None,
                cutoff: Optional[date] = None) -> list[EvidenceRecord]:
        """All records of a family/ecosystem, with the same cut-off rule as ``query``
        (published strictly before; undated excluded when a cut-off is given)."""
        out = []
        for rec in self._by_id.values():
            if family is not None and rec.family.value != family:
                continue
            if ecosystem is not None and rec.ecosystem != ecosystem:
                continue
            if cutoff is not None and not rec.known_before(cutoff):
                continue
            out.append(rec)
        return out

    def tables_fingerprint(self) -> dict[str, Optional[str]]:
        """table -> records SHA-256 (None when not loaded); used to check that two stages saw the same store."""
        return {t.key: t.records_sha256 for t in self.tables}

    def query(self, ecosystem: str, name_normalized: str, *, cutoff: Optional[date] = None) -> QueryResult:
        """Evidence about this name, with the cut-off rule applied. Deterministic order."""
        if isinstance(cutoff, datetime):
            raise TypeError("cutoff must be a date; convert the run's cut-off to a UTC date first")
        kept, after, undated_out, undated_in = [], [], [], []
        for rec, role in self._index.get((ecosystem, name_normalized), []):
            eid = rec.evidence_id
            if cutoff is not None:
                if rec.published is None:
                    undated_out.append(eid)
                    continue
                if not rec.known_before(cutoff):
                    after.append(eid)
                    continue
            elif rec.published is None:
                undated_in.append(eid)
            kept.append(EvidenceMatch(rec, role, self._table_of[eid]))
        kept.sort(key=lambda m: (m.record.family.value, m.role, m.evidence_id))
        return QueryResult(tuple(kept), tuple(sorted(after)), tuple(sorted(undated_out)), tuple(sorted(undated_in)))

    def run_record(self) -> dict[str, Any]:
        """What was loaded: for the run record (and, if approved, the contract)."""
        return {"store_version": STORE_VERSION, "root_name": self.root.name, "complete": self.complete,
                "tables": [t.to_dict() for t in self.tables],
                "failures": [{"table": f.table, "code": f.code, "detail": f.detail} for f in self.failures],
                "records_indexed": len(self._by_id)}
