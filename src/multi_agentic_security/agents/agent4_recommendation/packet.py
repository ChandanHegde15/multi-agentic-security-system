"""Per-dependency input packets for Agent 4 (D-062).

A packet is everything one recommender variant may see for one dependency:

* the Agent 1 dependency record, Agent 2's registry facts and Agent 3's assessment;
* the evidence records given to the variant:
  - ``R0`` and ``LLM-G``: the records Agent 2 cited for the dependency, the records Agent 3's
    findings cite and, for a typosquat finding, the imitated packages' own malicious and
    typosquat records (D-063), each read from the store and filtered again by the cut-off;
  - ``LLM-U``: none (it sees finding names only).

The packet's evidence IDs are recorded in the first reason of every recommendation
(``a4.input.packet``), so it can be checked afterwards which IDs a variant was given.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Optional

from multi_agentic_security.contracts.evidence import EvidenceRecord
from multi_agentic_security.contracts.pipeline import (
    DependencyRecord, ExtractionResult, Failure, RegistryResult, RegistryVerification, RiskAssessment, RiskResult,
)
from multi_agentic_security.evidence_store import EvidenceStore

VARIANTS = ("R0", "LLM-U", "LLM-G")
GROUNDED = frozenset({"R0", "LLM-G"})


@dataclass(frozen=True)
class Packet:
    variant: str
    dependency: DependencyRecord
    registry: Optional[RegistryVerification]
    assessment: Optional[RiskAssessment]
    evidence: tuple[EvidenceRecord, ...]
    cutoff: Optional[datetime]
    evidence_usable: bool          # False: no store, or not the store Agent 2 used

    @property
    def cutoff_date(self) -> Optional[date]:
        return self.cutoff.astimezone(timezone.utc).date() if self.cutoff is not None else None

    @property
    def evidence_ids(self) -> list[str]:
        return [r.evidence_id for r in self.evidence]

    def given(self) -> dict[str, EvidenceRecord]:
        return {r.evidence_id: r for r in self.evidence}

    def finding_names(self) -> list[str]:
        return [f.finding for f in self.assessment.findings] if self.assessment is not None else []


def build_packets(extraction: ExtractionResult, registry: RegistryResult, risk: RiskResult, *,
                  evidence_store: Optional[EvidenceStore], variant: str,
                  failures: list[Failure]) -> list[Packet]:
    """One packet per Agent 1 dependency, in Agent 1's order. Problems are appended to ``failures``."""
    if variant not in VARIANTS:
        raise ValueError(f"unknown variant {variant!r}; expected one of {VARIANTS}")
    cutoff = registry.evidence_cutoff
    cutoff_date = cutoff.astimezone(timezone.utc).date() if cutoff is not None else None
    known = {d.dependency_id for d in extraction.dependencies}

    regs: dict[str, RegistryVerification] = {}
    if registry.project_id != extraction.project_id:
        failures.append(Failure(stage="agent4", code="a4.input.project_mismatch",
                                detail="the registry result belongs to another project; registry data not used"))
    else:
        for r in registry.results:
            if r.dependency_id in regs:
                failures.append(Failure(stage="agent4", code="a4.input.duplicate_registry_result",
                                        detail="two registry results for one dependency; the first is used",
                                        dependency_id=r.dependency_id))
                continue
            regs[r.dependency_id] = r

    assessments: dict[str, RiskAssessment] = {}
    if risk.project_id != extraction.project_id:
        failures.append(Failure(stage="agent4", code="a4.input.project_mismatch",
                                detail="the risk result belongs to another project; findings not used"))
    else:
        for a in risk.assessments:
            if a.dependency_id in assessments:
                failures.append(Failure(stage="agent4", code="a4.input.duplicate_assessment",
                                        detail="two assessments for one dependency; the first is used",
                                        dependency_id=a.dependency_id))
                continue
            assessments[a.dependency_id] = a
    for dep_id in sorted((set(regs) | set(assessments)) - known):
        failures.append(Failure(stage="agent4", code="a4.input.unknown_dependency",
                                detail="registry result or assessment for a dependency Agent 1 did not produce; "
                                       "ignored", dependency_id=dep_id))

    usable = evidence_store is not None
    if evidence_store is None:
        failures.append(Failure(stage="agent4", code="a4.evidence.store_missing",
                                detail="no evidence store; no evidence records can be given to any variant"))
    elif registry.evidence_store is None:
        usable = False
        failures.append(Failure(stage="agent4", code="a4.evidence.not_looked_up_by_agent2",
                                detail="Agent 2 ran without an evidence store; no evidence records are given"))
    else:
        used = {t.table: t.records_sha256 for t in registry.evidence_store.tables}
        if used != evidence_store.tables_fingerprint():
            usable = False
            failures.append(Failure(stage="agent4", code="a4.evidence.store_mismatch",
                                    detail="the evidence store differs from the one Agent 2 used (table hashes); "
                                           "no evidence records are given"))

    packets: list[Packet] = []
    for dep in extraction.dependencies:
        reg = regs.get(dep.dependency_id)
        a = assessments.get(dep.dependency_id)
        if reg is None:
            failures.append(Failure(stage="agent4", code="a4.input.missing_registry_result",
                                    detail="no registry result for this dependency", dependency_id=dep.dependency_id))
        if a is None:
            failures.append(Failure(stage="agent4", code="a4.input.missing_assessment",
                                    detail="no Agent 3 assessment for this dependency; the recommendation abstains",
                                    dependency_id=dep.dependency_id))
        records: list[EvidenceRecord] = []
        if usable and variant in GROUNDED:
            ids: list[str] = []
            for eid in list(reg.evidence_ids if reg is not None else []) + [
                    e for f in (a.findings if a is not None else []) for e in f.evidence_ids]:
                if eid not in ids:
                    ids.append(eid)
            # The imitated packages of a typosquat finding: their own malicious and typosquat records,
            # so that a replacement is never a package that is itself flagged (D-063).
            for f in (a.findings if a is not None else []):
                if f.finding != "typosquat_listed" or dep.package is None:
                    continue
                for target in f.detail.get("targets") or []:
                    q = evidence_store.query(dep.package.ecosystem, target, cutoff=cutoff_date)
                    for m in q.matches:
                        if m.role == "name" and m.record.family.value in ("malicious", "typosquat") \
                                and m.evidence_id not in ids:
                            ids.append(m.evidence_id)
            for eid in ids:
                rec = evidence_store.get(eid)
                if rec is None:
                    failures.append(Failure(stage="agent4", code="a4.evidence.unknown_id",
                                            detail=f"{eid} is not in the evidence store; not given",
                                            dependency_id=dep.dependency_id))
                    continue
                if cutoff_date is not None and not rec.known_before(cutoff_date):
                    failures.append(Failure(stage="agent4", code="a4.evidence.after_cutoff",
                                            detail=f"{eid} is not known before the cut-off; not given",
                                            dependency_id=dep.dependency_id))
                    continue
                records.append(rec)
        packets.append(Packet(variant=variant, dependency=dep, registry=reg, assessment=a, evidence=tuple(records),
                              cutoff=cutoff, evidence_usable=usable))
    return packets
