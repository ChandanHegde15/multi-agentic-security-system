"""Agent 3 entry point: ``ExtractionResult`` + ``RegistryResult`` -> ``RiskResult`` (pipeline/0.2, D-020, D-055).

Per dependency, side by side:

* ``baseline_v1`` - the frozen v1 score, unchanged (``v1_adapter``);
* ``findings``    - v2: one finding per label family, never a combined score.

v2 findings and their rules (rule IDs ``a3.*``):

* ``malicious_reported``  - a malicious report covering the whole package.
* ``compromised_version`` - malicious reports for listed versions or ranges that
  cover (or may cover) the declared version. Reports naming only other versions
  give no finding (popular packages with compromised releases stay usable).
* ``withdrawn_only``      - only withdrawn (retracted) reports, covering the declared
  version; never malicious.
* ``vulnerable``          - advisories whose affected range covers (or may cover)
  the declared version, with the fixed boundaries the advisories state.
* ``typosquat_listed``    - a typosquat list names this package as imitating
  another; the imitated package becomes ``reference_package`` when unique.
* ``nonexistent``         - the registry has no such package **and** no malicious
  evidence names it (PyPI answers 404 for removed malicious packages too,
  RUN-001) **and** the registry status is not a post-cut-off snapshot in a
  held-out run.
* ``registry_security_hold`` - npm replaced the package with a security holding
  package (registry fact; removed versions in ``detail``).
* ``name_similar_to_popular`` - one edit away from a popular-list name; a signal
  for review, never a malicious label.
* ``unknown``             - existence or applicability could not be decided.
* ``no_evidence``         - none of the above; explicitly not a safety statement.

Every applicability decision is version-aware (``versions.py``). Evidence is
read from the store by the IDs Agent 2 reported; the store must be the one
Agent 2 used (same table hashes), otherwise that is a failure state.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Optional

from multi_agentic_security.contracts.evidence import EvidenceRecord, VersionScope
from multi_agentic_security.contracts.pipeline import (
    DependencyRecord, ExtractionResult, Failure, Finding, PackageRef, Reason, RegistryResult, RegistryVerification,
    RiskAssessment, RiskResult,
)
from multi_agentic_security.evidence_store import EvidenceStore

from .similarity_v2 import PopularIndex
from .v1_adapter import run_v1
from .versions import APPLIES, Declared, RecordView, applicability, declared_version, fixed_bounds, strongest
from .versions import _same as _same_version

STAGE_VERSION = "agent3/0.1"
FINDINGS_VERSION = "agent3_v2/0.1"
Clock = Callable[[], datetime]

_APPLICABILITY_TEXT = {
    "all_versions": "the reports cover every version of the package",
    "affected": "the declared version is covered",
    "likely_affected": "the version that would be installed (highest allowed) is covered",
    "possible": "some version the constraint allows is covered; which version would be installed is unknown",
    "undetermined": "whether the installed version is covered cannot be decided",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _r(rule_id: str, outcome: str, explanation: str, evidence_ids=None, **inputs: Any) -> Reason:
    return Reason(rule_id=rule_id, outcome=outcome, explanation=explanation, inputs=inputs,
                  evidence_ids=list(evidence_ids or []))


def _views(records: list[EvidenceRecord], d: Declared) -> list[RecordView]:
    return [RecordView(r, applicability(r, d)) for r in records]


def _family_finding(kind: str, views: list[RecordView], d: Declared, rule: str, text: str,
                    extra: Optional[dict] = None) -> tuple[Optional[Finding], Optional[Reason]]:
    """A finding from the records that apply, or a reason saying they all name other versions."""
    applying = [v for v in views if v.applicability in APPLIES]
    if not applying:
        ids = sorted(v.record.evidence_id for v in views)
        older = sorted(v.record.evidence_id for v in views if v.applicability == "allowed_not_resolved")
        removed = sorted(v.record.evidence_id for v in views if v.applicability == "removed_from_registry")
        if older:
            return None, _r(f"{rule}.installed_version_not_affected", "no_finding",
                            f"{len(older)} {text} record(s) cover other versions that the constraint still allows "
                            "(older, pre-release or yanked, or for npm newer than the 'latest' tag), but not the version "
                            f"that would be installed ({d.resolved}). Pinning or a lock file would prevent an affected "
                            "version from being installed."
                            + (f" {len(removed)} further record(s) name release(s) that are no longer in the "
                               "registry; an environment or lock file created earlier may still contain them."
                               if removed else ""), ids,
                            declared=d.to_dict(), older_versions_affected=len(older),
                            removed_releases_reported=len(removed))
        if removed:
            return None, _r(f"{rule}.reported_release_removed", "no_finding",
                            f"{len(removed)} {text} record(s) name release(s) that the constraint allows but that are no "
                            "longer in the registry, so a new install cannot receive them"
                            + (f" (it would install {d.resolved})" if d.resolved else "") + ". An environment or lock "
                            "file created while they were available may still contain them; check the installed "
                            "version.", ids, declared=d.to_dict(), removed_releases_reported=len(removed))
        return None, _r(f"{rule}.other_versions_only", "no_finding",
                        f"{len(ids)} {text} record(s) name this package, but none covers the declared version "
                        f"(declared {d.exact or d.spec or 'without a constraint'}"
                        + (f", would install {d.resolved}" if d.resolved and not d.exact else "") + ").", ids,
                        declared=d.to_dict())
    best = strongest(v.applicability for v in applying)
    ids = sorted({v.record.evidence_id for v in applying})
    sources = sorted({v.record.provenance.source_dataset for v in applying})
    detail = {"applicability": best, "declared": d.to_dict(), "records": [v.to_dict() for v in applying],
              "sources": sources, **(extra or {})}
    explanation = (f"{len(ids)} {text} record(s) from {', '.join(sources)} apply: {_APPLICABILITY_TEXT[best]}.")
    if len(sources) > 1:
        explanation += " Agreement between these sources is not independent confirmation."
    reason = _r(f"{rule}.{best}", kind, explanation, ids, applicability=best, declared=d.to_dict(),
                records=len(ids), not_applying=len(views) - len(applying))
    return Finding(finding=kind, evidence_ids=ids, detail=detail, reasons=[reason]), None


def _cutoff_violation(rec: EvidenceRecord, cutoff_date) -> bool:
    return cutoff_date is not None and not rec.known_before(cutoff_date)


def assess(extraction: ExtractionResult, registry: RegistryResult, *, evidence_store: Optional[EvidenceStore],
           clock: Clock = _utc_now) -> RiskResult:
    started = clock()
    failures: list[Failure] = []
    cutoff = registry.evidence_cutoff
    cutoff_date = cutoff.astimezone(timezone.utc).date() if cutoff else None

    if registry.project_id != extraction.project_id:
        failures.append(Failure(stage="agent3", code="a3.input.project_mismatch",
                                detail="the registry result belongs to another project; registry data not used"))
        reg_by_id: dict[str, RegistryVerification] = {}
    else:
        reg_by_id = {}
        for r in registry.results:
            if r.dependency_id in reg_by_id:
                failures.append(Failure(stage="agent3", code="a3.input.duplicate_registry_result",
                                        detail="two registry results for one dependency; the first is used",
                                        dependency_id=r.dependency_id))
                continue
            reg_by_id[r.dependency_id] = r
        known = {d.dependency_id for d in extraction.dependencies}
        for dep_id in sorted(set(reg_by_id) - known):
            failures.append(Failure(stage="agent3", code="a3.input.unknown_dependency",
                                    detail="registry result for a dependency Agent 1 did not produce; ignored",
                                    dependency_id=dep_id))

    # store_ok: evidence IDs from Agent 2 can be read and trusted; complete: every family was searched.
    store_ok = evidence_store is not None
    if evidence_store is None:
        failures.append(Failure(stage="agent3", code="a3.evidence.store_missing",
                                detail="no evidence store; evidence-backed findings cannot be made"))
    elif registry.evidence_store is None:
        store_ok = False
        failures.append(Failure(stage="agent3", code="a3.evidence.not_looked_up_by_agent2",
                                detail="Agent 2 ran without an evidence store, so no evidence was looked up for any "
                                       "dependency; evidence-backed findings are not made"))
    else:
        used = {t.table: t.records_sha256 for t in registry.evidence_store.tables}
        if used != evidence_store.tables_fingerprint():
            store_ok = False
            failures.append(Failure(stage="agent3", code="a3.evidence.store_mismatch",
                                    detail="the evidence store differs from the one Agent 2 used (table hashes); "
                                           "evidence-backed findings are not made"))
    complete = store_ok and registry.evidence_store.complete and evidence_store.complete
    if store_ok and not complete:
        failures.append(Failure(stage="agent3", code="a3.evidence.store_incomplete",
                                detail="some evidence tables were not loaded: "
                                       + ", ".join(evidence_store.missing_tables or ["see Agent 2 failures"])
                                       + "; absence of evidence is not reported as no_evidence or nonexistent"))

    popular: dict[str, PopularIndex] = {}
    if store_ok:
        for eco in ("pypi", "npm"):
            recs = evidence_store.records(family="benign_reference", ecosystem=eco, cutoff=cutoff_date)
            popular[eco] = PopularIndex((r.name_normalized, r.evidence_id) for r in recs)

    pairs = [(d, reg_by_id.get(d.dependency_id)) for d in extraction.dependencies]
    baseline = run_v1(extraction.project_id, pairs)

    assessments: list[RiskAssessment] = []
    for (dep, reg), v1 in zip(pairs, baseline):
        findings, reasons, reference = _assess_one(dep, reg, evidence_store if store_ok else None, popular,
                                                  cutoff_date, failures, store_ok, complete,
                                                  evidence_store.missing_tables if evidence_store is not None else [],
                                                  cutoff)
        reasons.insert(0, _r("a3.v1.baseline", v1.risk_level,
                             f"Frozen v1 baseline: score {v1.risk_score}, level {v1.risk_level} (registry status for v1: "
                             f"{v1.registry_status_v1}). Shown for comparison only.",
                             risk_score=v1.risk_score, registry_status_v1=v1.registry_status_v1))
        assessments.append(RiskAssessment(dependency_id=dep.dependency_id, baseline_v1=v1, findings=findings,
                                          reference_package=reference, findings_version=FINDINGS_VERSION,
                                          reasons=reasons))
    return RiskResult(project_id=extraction.project_id, stage_version=STAGE_VERSION, started_at=started,
                      finished_at=max(clock(), started), assessments=assessments, failures=failures)


def _assess_one(dep: DependencyRecord, reg: Optional[RegistryVerification], store: Optional[EvidenceStore],
                popular: dict[str, PopularIndex], cutoff_date, failures: list[Failure], store_ok: bool,
                complete: bool, missing_tables: list[str], cutoff: Optional[datetime] = None):
    findings: list[Finding] = []
    reasons: list[Reason] = []
    reference: Optional[PackageRef] = None

    if dep.package is None:
        f = Finding(finding="unknown", detail={"why": "no package determined"},
                    reasons=[_r("a3.unknown.unresolved", "unknown",
                                "Agent 1 could not determine a package, so no finding can be made about it.")])
        return [f], [_r("a3.summary", "unknown", "No package was determined for this declaration.")], None

    eco, name = dep.package.ecosystem, dep.package.name_normalized
    if reg is None:
        failures.append(Failure(stage="agent3", code="a3.input.missing_registry_result",
                                detail="no registry result for this dependency", dependency_id=dep.dependency_id))
    d = declared_version(dep, reg, cutoff_set=cutoff_date is not None)
    if d.kind == "exact" and d.registry_versions is not None and not any(
            _same_version(eco, d.exact, v) for v in d.registry_versions):
        reasons.append(_r("a3.version.pin_not_in_registry", "context",
                          f"The pinned version {d.exact} is not in the registry's version list"
                          + (" before the cut-off" if cutoff_date else "") + "; it may have been deleted"
                          + (", uploaded after the cut-off" if cutoff_date else "") + " or never published.",
                          pinned=d.exact))

    # ---- evidence by family
    records: list[EvidenceRecord] = []
    if store is not None and reg is not None:
        for eid in reg.evidence_ids:
            rec = store.get(eid)
            if rec is None:
                failures.append(Failure(stage="agent3", code="a3.evidence.unknown_id",
                                        detail=f"{eid} is not in the evidence store", dependency_id=dep.dependency_id))
                continue
            if rec.ecosystem != eco or rec.name_normalized != name:
                failures.append(Failure(stage="agent3", code="a3.evidence.wrong_package",
                                        detail=f"{eid} is about another package; ignored", dependency_id=dep.dependency_id))
                continue
            if _cutoff_violation(rec, cutoff_date):
                failures.append(Failure(stage="agent3", code="a3.evidence.after_cutoff",
                                        detail=f"{eid} is not known before the cut-off; ignored",
                                        dependency_id=dep.dependency_id))
                continue
            records.append(rec)
    by_family: dict[str, list[EvidenceRecord]] = {}
    for rec in records:
        by_family.setdefault(rec.family.value, []).append(rec)

    malicious = by_family.get("malicious", [])
    whole = [r for r in malicious if r.version_scope is VersionScope.ALL]
    scoped = [r for r in malicious if r.version_scope is not VersionScope.ALL]
    if whole:
        f, _ = _family_finding("malicious_reported", _views(whole, d), d, "a3.malicious.whole_package",
                               "whole-package malicious")
        findings.append(f)
    if scoped:
        f, why = _family_finding("compromised_version", _views(scoped, d), d, "a3.malicious.version",
                                 "version-specific malicious")
        findings.append(f) if f else reasons.append(why)

    withdrawn = by_family.get("withdrawn", [])
    if withdrawn and not malicious:
        # Version-aware like the other families (D-057): a retracted report about version 1.0.0
        # says nothing about a dependency on 19.x.
        wviews = _views(withdrawn, d)
        wapply = [v for v in wviews if v.applicability in APPLIES]
        if wapply:
            ids = sorted(v.record.evidence_id for v in wapply)
            findings.append(Finding(finding="withdrawn_only", evidence_ids=ids,
                                    detail={"applicability": strongest(v.applicability for v in wapply),
                                            "records": [v.to_dict() for v in wapply]},
                                    reasons=[_r("a3.withdrawn.only", "withdrawn_only",
                                                f"Only withdrawn (retracted) malicious reports name this package and "
                                                f"version ({len(ids)}). A withdrawn report is not a malicious finding.",
                                                ids)]))
        else:
            # Same reason rules and texts as the other families (D-058: the text must match the rule).
            _, why = _family_finding("withdrawn_only", wviews, d, "a3.withdrawn", "withdrawn (retracted) malicious")
            reasons.append(why)
    elif withdrawn:
        reasons.append(_r("a3.withdrawn.with_malicious", "context",
                          "Withdrawn reports exist next to malicious reports; the malicious reports are judged on "
                          "their own.", sorted(r.evidence_id for r in withdrawn)))

    vulnerable = by_family.get("vulnerable", [])
    if vulnerable:
        views = _views(vulnerable, d)
        applying_ranges = [v.record.version_range for v in views
                           if v.applicability in APPLIES and v.record.version_range]
        stated = fixed_bounds(applying_ranges)
        released = ([b for b in stated if any(_same_version(eco, b, v) for v in d.registry_versions)]
                    if d.registry_versions is not None else None)
        f, why = _family_finding("vulnerable", views, d, "a3.vulnerable", "vulnerability advisory",
                                 extra={"fixed_in_stated": stated, "fixed_in_released": released,
                                        "fixed_in_note": "Upper bounds named by the advisories (current advisory text). "
                                                         "Not a safe target by itself: a bound may fall inside another "
                                                         "advisory's range, and only versions in the registry list (at "
                                                         "the cut-off, if any) were available.",
                                        "advisories": sorted({v.record.provenance.source_record_id for v in views
                                                              if v.applicability in APPLIES})})
        findings.append(f) if f else reasons.append(why)

    squats = by_family.get("typosquat", [])
    if squats:
        targets = sorted({r.target_name_normalized for r in squats})
        ids = sorted(r.evidence_id for r in squats)
        findings.append(Finding(finding="typosquat_listed", evidence_ids=ids,
                                detail={"targets": targets, "sources": sorted({r.provenance.source_dataset for r in squats})},
                                reasons=[_r("a3.typosquat.listed", "typosquat_listed",
                                            f"Typosquat list(s) name this package as imitating {', '.join(targets)}. "
                                            "A listed typosquat is not by itself proof of malware.", ids, targets=targets)]))
        if len(targets) == 1:
            raw = next(r.target_name_raw for r in squats if r.target_name_normalized == targets[0])
            reference = PackageRef.of(eco, raw)

    # ---- registry facts
    status = reg.status if reg is not None else None
    after_cutoff = False
    if reg is not None and reg.retrieved_after_cutoff is not None:
        after_cutoff = reg.retrieved_after_cutoff is True
    elif reg is not None and cutoff is not None:
        # Flag missing under a cut-off (e.g. older input): derive it, and fail closed without a time (D-057).
        after_cutoff = reg.retrieved_at is None or reg.retrieved_at >= cutoff
    retrieved = reg.retrieved_at.isoformat() if reg is not None and reg.retrieved_at is not None else None
    target_ids: list[str] = []
    if status == "not_found" and store is not None and not records:
        # Agent 2 cites only records about this name; a typosquat record naming it as the TARGET
        # also shows the name was published (review 2, finding 9).
        q = store.query(eco, name, cutoff=cutoff_date)
        target_ids = sorted(m.evidence_id for m in q.matches if m.role != "name")
    if status == "not_found":
        if target_ids:
            reasons.append(_r("a3.nonexistent.named_as_target", "not_nonexistent",
                              "The registry has no such package now, but typosquat records name it as the imitated "
                              "package: it was published and later removed, which is not the same as never existing.",
                              target_ids))
        elif records:
            reasons.append(_r("a3.nonexistent.published_before", "not_nonexistent",
                              "The registry has no such package now, but evidence records name it "
                              f"({', '.join(sorted({r.family.value for r in records}))}): it was published and later "
                              "removed, which is not the same as never existing.",
                              sorted(r.evidence_id for r in records)))
        elif not complete:
            findings.append(Finding(finding="unknown", detail={"why": "evidence not fully checked"},
                                    reasons=[_r("a3.nonexistent.evidence_not_checked", "unknown",
                                                "The registry has no such package, but the evidence store was missing "
                                                "or incomplete, so a removed malicious or reported package cannot be "
                                                "ruled out.", missing_tables=missing_tables)]))
        elif after_cutoff:
            findings.append(Finding(finding="unknown", detail={"why": "registry status is from after the cut-off"},
                                    reasons=[_r("a3.nonexistent.not_historical", "unknown",
                                                "The registry has no such package now, but the data was retrieved "
                                                "after the cut-off, so it cannot show whether the package existed then.")]))
        else:
            findings.append(Finding(finding="nonexistent", detail={"registry_retrieved_at": retrieved},
                                    reasons=[_r("a3.nonexistent.registry_not_found", "nonexistent",
                                                f"The {eco} registry has no package with this name (retrieved "
                                                f"{retrieved or 'at an unrecorded time'}) and no evidence record names it.",
                                                retrieved_at=retrieved)]))
    elif status == "security_placeholder":
        if after_cutoff:
            # Like a not_found retrieved after the cut-off (D-058): the state at the cut-off is unknown.
            findings.append(Finding(finding="unknown", detail={"why": "registry status is from after the cut-off"},
                                    reasons=[_r("a3.registry.security_hold_not_historical", "unknown",
                                                "npm shows a security holding package now, but the data was "
                                                "retrieved after the cut-off, so it cannot show the state then.")]))
        else:
            findings.append(Finding(finding="registry_security_hold",
                                    detail={k: (reg.metadata or {}).get(k) for k in
                                            ("removed_versions", "placeholder_published", "placeholder_versions")},
                                    reasons=[_r("a3.registry.security_hold", "registry_security_hold",
                                                "npm removed this package for security reasons and replaced it with a "
                                                "holding package; the original cannot be installed from npm.",
                                                removed_versions=(reg.metadata or {}).get("removed_versions"))]))
    elif status == "found" and cutoff_date is not None and reg.versions == []:
        findings.append(Finding(finding="unknown", detail={"why": "no version uploaded before the cut-off",
                                                           "registry_retrieved_at": retrieved},
                                reasons=[_r("a3.cutoff.no_version_before_cutoff", "unknown",
                                            "The package exists in the registry now, but none of its listed versions was "
                                            "uploaded before the cut-off: it may not have existed then (for example a name "
                                            "registered later). Deleted earlier releases cannot be ruled out.")]))
    elif status in ("lookup_error", "invalid_response", "not_checked") or status is None:
        findings.append(Finding(finding="unknown", detail={"registry_status": status},
                                reasons=[_r("a3.unknown.registry", "unknown",
                                            f"Whether the package exists was not established (registry status "
                                            f"{status or 'missing'}).", registry_status=status)]))

    # ---- name similarity
    idx = popular.get(eco)
    if idx is not None and len(idx) and not squats:
        hits = idx.similar(name)
        if hits:
            names = [h[0] for h in hits]
            findings.append(Finding(finding="name_similar_to_popular", evidence_ids=[h[1] for h in hits],
                                    detail={"similar_to": names, "distance": 1},
                                    reasons=[_r("a3.similarity.edit_distance_1", "name_similar_to_popular",
                                                f"The name is one edit away from popular package(s) {', '.join(names[:5])}. "
                                                "This is a signal for review, not a malicious label.",
                                                [h[1] for h in hits], similar_to=names[:5])]))
            if reference is None and len(names) == 1:
                reference = PackageRef.of(eco, names[0])
    elif idx is None:
        reasons.append(_r("a3.similarity.not_checked", "not_checked",
                          "Name similarity was not checked because the evidence store (with the popular lists) was not "
                          "usable."))
    elif not len(idx):
        reasons.append(_r("a3.similarity.no_list", "not_checked",
                          "No popular-package list record is available for this ecosystem ("
                          + ("none is known before the cut-off" if cutoff_date else "the list table holds no records")
                          + "), so name similarity was not checked."))

    if not store_ok:
        reasons.append(_r("a3.evidence.not_used", "not_checked",
                          "Evidence-backed findings were not made because the evidence store is missing or differs "
                          "from the one Agent 2 used."))
    evidence_backed = {"malicious_reported", "compromised_version", "withdrawn_only", "vulnerable", "typosquat_listed"}
    if store_ok and not complete:
        reasons.append(_r("a3.evidence.incomplete", "partial",
                          "Some evidence tables were not loaded (" + ", ".join(missing_tables or ["unknown"]) + "), so the "
                          "absence of a finding is not reported as no_evidence.", missing_tables=missing_tables))
    # no_evidence is not added when the package's existence is itself the finding or is unknown because
    # of the cut-off (D-056 b, D-057); it is kept next to an 'unknown' registry status (mode off, lookup
    # error), where the evidence was still searched and found nothing.
    blocking = {"nonexistent", "registry_security_hold"}
    cutoff_unknown = any(r.rule_id in ("a3.cutoff.no_version_before_cutoff", "a3.nonexistent.not_historical",
                                       "a3.registry.security_hold_not_historical")
                         for f in findings for r in f.reasons)
    if complete and not cutoff_unknown and not any(f.finding in evidence_backed | blocking for f in findings):
        findings.append(Finding(finding="no_evidence",
                                reasons=[_r("a3.no_evidence", "no_evidence",
                                            "No evidence record applies to this package and version. This is not a "
                                            "statement that it is safe.")]))
    kinds = [f.finding for f in findings]
    reasons.append(_r("a3.summary", ",".join(kinds) or "none",
                      "Findings (one per family, no combined score): " + (", ".join(kinds) or "none") + ".",
                      findings=kinds, declared=d.to_dict()))
    return findings, reasons, reference
