"""Agent 2 entry point: ``ExtractionResult`` -> ``RegistryResult`` (pipeline/0.2, D-053, D-054).

Agent 2 reports facts; it does not judge:

* registry facts per package (status, canonical name, versions, upload times),
  each lookup time-stamped;
* the IDs of evidence records whose package NAME matches, per label family,
  with the cut-off rule applied. Whether a record applies to the declared
  version (compromised releases, vulnerable ranges, fixed versions) is decided
  by Agent 3, never here.

Exactly one ``RegistryVerification`` per Agent 1 ``dependency_id``, in Agent 1's
order; no identifier is invented or dropped. Every result carries reasons
(rule IDs ``a2.*``). Every problem is a state (``lookup_error``,
``invalid_response``, ``not_checked`` with a reason, or a run-level failure),
never a default.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Callable, Optional

from multi_agentic_security.contracts.pipeline import (
    DependencyRecord, EvidenceStoreInfo, EvidenceTableInfo, ExtractionResult, Failure, Reason, RegistryResult,
    RegistryVerification,
)
from multi_agentic_security.evidence_store import EvidenceStore, QueryResult

from .client import LookupOutcome, RegistryClient, SnapshotRegistryClient, valid_registry_name

STAGE_VERSION = "agent2/0.1"
Clock = Callable[[], datetime]

# Agent 1 writes these phrases into the warnings of every registry name that a file or
# command sends to another index or registry (D-049 d, D-051). Guarded by an
# integration test so a wording change in Agent 1 cannot silently disable the rule.
PRIVATE_INDEX_MARKERS = (
    "may resolve outside the public PyPI index",
    "may not refer to the public npm package",
)

_FAMILY_TEXT = {
    ("malicious", "name"): ("a2.evidence.malicious",
                            "{n} report(s) in the evidence store name this package as malicious. Agent 3 decides whether "
                            "the reported versions include the declared one."),
    ("withdrawn", "name"): ("a2.evidence.withdrawn",
                            "{n} withdrawn (retracted) malicious report(s) name this package. A withdrawn report never "
                            "counts as malicious."),
    ("vulnerable", "name"): ("a2.evidence.vulnerable",
                             "{n} vulnerability advisory record(s) name this package. Agent 3 decides whether the "
                             "declared version is in an affected range."),
    ("typosquat", "name"): ("a2.evidence.typosquat_name",
                            "{n} typosquat record(s) name this package as imitating another package."),
    ("typosquat", "target"): ("a2.evidence.typosquat_target",
                              "This package is the imitated target in {n} typosquat record(s). That is context about "
                              "other packages, not a finding against this one; these records are cited here only and "
                              "are not in this result's evidence_ids."),
    ("benign_reference", "name"): ("a2.evidence.benign_reference",
                                   "This name is on {n} reference-list record(s) of popular or target packages. That is "
                                   "context only, never proof that the package is safe."),
}
_FAMILY_ORDER = [("malicious", "name"), ("withdrawn", "name"), ("vulnerable", "name"), ("typosquat", "name"),
                 ("typosquat", "target"), ("benign_reference", "name")]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _r(rule_id: str, outcome: str, explanation: str, evidence_ids: Optional[list[str]] = None, **inputs: Any) -> Reason:
    return Reason(rule_id=rule_id, outcome=outcome, explanation=explanation, inputs=inputs,
                  evidence_ids=list(evidence_ids or []))


# --------------------------------------------------------------------------- evidence

def _evidence_reasons(q: QueryResult, cutoff: Optional[date], origin_note: Optional[str]) -> tuple[list[Reason], list[str]]:
    reasons: list[Reason] = []
    undated = set(q.undated_included)
    for family, role in _FAMILY_ORDER:
        matches = [m for m in q.matches if m.record.family.value == family and m.role == role]
        if not matches:
            continue
        rule_id, text = _FAMILY_TEXT[(family, role)]
        ids = [m.evidence_id for m in matches]
        scopes: dict[str, int] = {}
        for m in matches:
            scopes[m.record.version_scope.value] = scopes.get(m.record.version_scope.value, 0) + 1
        explanation = text.format(n=len(matches))
        if origin_note:
            explanation += " " + origin_note
        reasons.append(_r(rule_id, "matched_by_name", explanation, ids, family=family, role=role, records=len(ids),
                          tables=sorted({m.table for m in matches}), version_scopes=scopes,
                          undated=sorted(set(ids) & undated)))
    if q.undated_included:
        reasons.append(_r("a2.evidence.undated_included", "flagged_undated",
                          f"{len(q.undated_included)} matching record(s) have no publication date. They are shown "
                          "because no cut-off is set; they cannot be placed in time and are excluded from held-out "
                          "experiments.",
                          list(q.undated_included), undated=len(q.undated_included)))
    if q.excluded_after_cutoff:
        reasons.append(_r("a2.evidence.excluded_after_cutoff", "excluded",
                          f"{len(q.excluded_after_cutoff)} matching record(s) were published on or after the cut-off "
                          f"{cutoff.isoformat()} (UTC date) and are not used.", excluded=len(q.excluded_after_cutoff),
                          excluded_ids=list(q.excluded_after_cutoff), cutoff=cutoff.isoformat()))
    if q.excluded_undated:
        reasons.append(_r("a2.evidence.excluded_undated", "excluded",
                          f"{len(q.excluded_undated)} matching record(s) have no publication date and are not used, "
                          f"because a cut-off ({cutoff.isoformat()}, UTC date) is set.",
                          excluded=len(q.excluded_undated), excluded_ids=list(q.excluded_undated),
                          cutoff=cutoff.isoformat()))
    # Only records about THIS name go into evidence_ids. A typosquat record matched because this
    # package is its target is about another package and is cited in its reason only.
    ids = sorted({m.evidence_id for m in q.matches if m.role == "name"})
    if not q.matches:
        reasons.append(_r("a2.evidence.no_match", "no_record",
                          "No record in the loaded evidence tables names this package"
                          + (" before the cut-off" if cutoff else "")
                          + ". This is not a statement that the package is safe."))
    return reasons, ids


# --------------------------------------------------------------------------- registry

def _not_checked(dep: DependencyRecord, rule_id: str, explanation: str, **inputs: Any) -> Reason:
    return _r(rule_id, "not_checked", explanation, **inputs)


def _apply_cutoff(outcome: LookupOutcome, cutoff_dt: Optional[datetime]) -> tuple[dict[str, Any], list[Reason]]:
    """Registry fields for the result, with versions limited to those uploaded before the cut-off."""
    fields: dict[str, Any] = dict(canonical_name=outcome.canonical_name, versions=outcome.versions,
                                  latest_version=outcome.latest_version, version_upload_times=outcome.upload_times)
    reasons: list[Reason] = []
    if cutoff_dt is None:
        return fields, reasons
    if outcome.retrieved_at >= cutoff_dt:
        reasons.append(_r("a2.cutoff.snapshot_after_cutoff", "current_not_historical",
                          f"The registry data was retrieved on {outcome.retrieved_at.date().isoformat()}, after the cut-off "
                          f"{cutoff_dt.date().isoformat()}. It shows the state at retrieval time; packages or versions "
                          "removed in between are not visible.", retrieved_at=outcome.retrieved_at.isoformat(),
                          cutoff=cutoff_dt.isoformat()))
    if outcome.status == "found" and outcome.versions is not None:
        times = outcome.upload_times or {}
        kept = [v for v in outcome.versions if times.get(v) is not None and times[v] < cutoff_dt]
        dropped_late = sum(1 for v in outcome.versions if times.get(v) is not None and times[v] >= cutoff_dt)
        dropped_unknown = sum(1 for v in outcome.versions if times.get(v) is None)
        fields.update(versions=kept, version_upload_times={v: times[v] for v in kept}, latest_version=None)
        reasons.append(_r("a2.cutoff.versions_filtered", "versions_before_cutoff",
                          f"{len(kept)} version(s) were uploaded before the cut-off; {dropped_late} later and "
                          f"{dropped_unknown} without an upload time are left out. The registry's current 'latest' "
                          "tag is withheld because it reflects today, not the cut-off.",
                          kept=len(kept), after_cutoff=dropped_late, no_upload_time=dropped_unknown,
                          cutoff=cutoff_dt.isoformat()))
        if not kept:
            reasons.append(_r("a2.cutoff.no_version_before_cutoff", "no_version_at_cutoff",
                              "No version of this package was uploaded before the cut-off according to the registry data.",
                              cutoff=cutoff_dt.isoformat()))
    return fields, reasons


def verify(extraction: ExtractionResult, *, mode: str, client: Optional[RegistryClient],
           evidence_store: Optional[EvidenceStore], evidence_cutoff: Optional[datetime] = None,
           clock: Clock = _utc_now) -> RegistryResult:
    """Verify every dependency of ``extraction``.

    ``mode`` is ``off``, ``snapshot`` or ``live``. Live lookups happen only when the
    caller passes ``mode="live"`` together with an explicitly constructed
    ``HttpRegistryClient``; there is no default client. ``evidence_cutoff``
    (timezone-aware) switches on held-out rules: evidence published on or after it
    and undated evidence are excluded, and live lookups are refused.
    """
    if mode not in ("off", "snapshot", "live"):
        raise ValueError(f"unknown registry mode {mode!r}")
    if evidence_cutoff is not None and evidence_cutoff.tzinfo is None:
        raise ValueError("evidence_cutoff must be timezone-aware")
    started = clock()
    cutoff_dt = evidence_cutoff.astimezone(timezone.utc) if evidence_cutoff else None
    cutoff_date = cutoff_dt.date() if cutoff_dt else None
    failures: list[Failure] = []

    # ---- run-level registry decision
    registry_block: Optional[Reason] = None
    if mode == "off":
        registry_block = _r("a2.not_checked.mode_off", "not_checked",
                            "Registry lookups are switched off for this run (mode 'off').", mode=mode)
    elif client is None:
        failures.append(Failure(stage="agent2", code="a2.mode.client_missing",
                                detail=f"mode '{mode}' needs a registry client; none was given, nothing was looked up"))
        registry_block = _r("a2.not_checked.no_client", "not_checked",
                            f"Mode '{mode}' was requested without a registry client, so nothing was looked up.", mode=mode)
    elif getattr(client, "mode", None) != mode:
        failures.append(Failure(stage="agent2", code="a2.mode.client_mismatch",
                                detail=f"mode '{mode}' requested with a '{getattr(client, 'mode', None)}' client; "
                                       "nothing was looked up"))
        registry_block = _r("a2.not_checked.client_mismatch", "not_checked",
                            f"The registry client does not match mode '{mode}', so nothing was looked up.", mode=mode)
    elif mode == "live" and cutoff_dt is not None:
        failures.append(Failure(stage="agent2", code="a2.mode.live_with_cutoff",
                                detail="live registry lookups are refused when an evidence cut-off is set (held-out "
                                       "runs use a dated snapshot, D-021)"))
        registry_block = _r("a2.not_checked.live_refused_held_out", "not_checked",
                            "A cut-off is set (held-out run), and today's registry state would leak later takedowns, "
                            "so no live lookup was made.", mode=mode, cutoff=cutoff_dt.isoformat())
    if isinstance(client, SnapshotRegistryClient) and registry_block is None:
        for fname, detail in client.load_failures:
            failures.append(Failure(stage="agent2", code="a2.snapshot.unusable_file", detail=f"{fname}: {detail}"))

    # ---- evidence store state
    store_reason: Optional[Reason] = None
    if evidence_store is None:
        failures.append(Failure(stage="agent2", code="a2.evidence.store_missing",
                                detail="no evidence store was given; no evidence was looked up"))
        store_reason = _r("a2.evidence.not_available", "not_looked_up",
                          "No evidence store was available for this run, so no evidence was looked up.")
    else:
        for f in evidence_store.failures:
            failures.append(Failure(stage="agent2", code=f.code, detail=f.detail))
        if not evidence_store.complete:
            store_reason = _r("a2.evidence.store_incomplete", "partial",
                              "Some evidence tables could not be loaded or verified; evidence from them is missing: "
                              + ", ".join(evidence_store.missing_tables or ["see run failures"]) + ".",
                              missing_tables=evidence_store.missing_tables)

    cache: dict[tuple[str, str], Optional[LookupOutcome]] = {}
    users: dict[tuple[str, str], int] = {}
    for dep in extraction.dependencies:
        if dep.package is not None:
            k = (dep.package.ecosystem, dep.package.name_normalized)
            users[k] = users.get(k, 0) + 1

    results: list[RegistryVerification] = []
    for dep in extraction.dependencies:
        reasons: list[Reason] = []
        fields: dict[str, Any] = {}
        status = "not_checked"
        pkg = dep.package
        origin_note: Optional[str] = None

        # ---- registry
        if pkg is None:
            reasons.append(_not_checked(
                dep, "a2.not_checked.unresolved",
                "Agent 1 could not determine a package for this declaration, so there is nothing to look up. An import "
                "name is not treated as a package name.", declaration=dep.original_declaration[:200]))
        elif registry_block is not None:
            reasons.append(registry_block)
        elif dep.origin != "registry":
            origin_note = (f"The dependency is installed from a {dep.origin} reference, so evidence about the registry "
                           "package of the same name may not apply to it.")
            reasons.append(_not_checked(
                dep, "a2.not_checked.non_registry_origin",
                f"Installed from a {dep.origin} reference, not from the public registry, so the registry entry of this "
                "name says nothing about what is installed.", origin=dep.origin))
        elif not client.supports(pkg.ecosystem):
            reasons.append(_not_checked(dep, "a2.not_checked.unsupported_ecosystem",
                                        f"The registry client cannot look up '{pkg.ecosystem}' packages.",
                                        ecosystem=pkg.ecosystem))
        elif not valid_registry_name(pkg.ecosystem, pkg.name_normalized):
            reasons.append(_not_checked(dep, "a2.not_checked.invalid_name",
                                        f"'{pkg.name_raw[:100]}' is not a valid {pkg.ecosystem} package name, so no "
                                        "request was built from it.", name=pkg.name_raw[:100]))
        else:
            key = (pkg.ecosystem, pkg.name_normalized)
            if key not in cache:
                try:
                    cache[key] = client.lookup(*key)
                except Exception as exc:  # a broken client is a state, never a crash
                    cache[key] = LookupOutcome(
                        status="lookup_error", rule_id="a2.status.lookup_error",
                        explanation="The registry client failed; existence is unknown, which is not the same as not found.",
                        retrieved_at=clock(), source_url="", error=f"client failed ({type(exc).__name__})")
            outcome = cache[key]
            if outcome is None:
                reasons.append(_not_checked(dep, "a2.not_checked.not_in_snapshot",
                                            "The registry snapshot has no recording for this package.",
                                            ecosystem=pkg.ecosystem, name=pkg.name_normalized))
            else:
                status = outcome.status
                reasons.append(_r(outcome.rule_id, outcome.status, outcome.explanation,
                                  **{**outcome.inputs, "lookup_key": f"{key[0]}:{key[1]}",
                                     "dependencies_sharing_lookup": users.get(key, 1),
                                     "retrieved_at": outcome.retrieved_at.isoformat()}))
                cut_fields, cut_reasons = _apply_cutoff(outcome, cutoff_dt)
                fields.update(cut_fields, metadata=dict(outcome.metadata), source_url=outcome.source_url or None,
                              retrieved_at=outcome.retrieved_at, error=outcome.error,
                              retrieved_after_cutoff=(outcome.retrieved_at >= cutoff_dt) if cutoff_dt else None)
                reasons.extend(cut_reasons)
                hits = [w for w in dep.warnings if any(m in w for m in PRIVATE_INDEX_MARKERS)]
                if hits:
                    reasons.append(_r("a2.registry.private_index", "public_registry_may_differ",
                                      "The declaration points to another package index or registry. The public registry "
                                      "was looked up, but it may not be the one that installs this package.",
                                      warnings=hits[:3]))

        # ---- evidence (independent of the registry mode)
        evidence_ids: list[str] = []
        if pkg is None:
            reasons.append(_r("a2.evidence.not_looked_up", "not_looked_up",
                              "No package was determined, so no evidence was looked up."))
        elif evidence_store is not None:
            q = evidence_store.query(pkg.ecosystem, pkg.name_normalized, cutoff=cutoff_date)
            ev_reasons, evidence_ids = _evidence_reasons(q, cutoff_date, origin_note)
            reasons.extend(ev_reasons)
        if store_reason is not None and pkg is not None:
            reasons.append(store_reason)

        results.append(RegistryVerification(
            dependency_id=dep.dependency_id, registry=pkg.ecosystem if pkg else None, status=status,
            evidence_ids=evidence_ids, reasons=reasons, **fields))

    store_info = None
    if evidence_store is not None:
        rec = evidence_store.run_record()
        store_info = EvidenceStoreInfo(
            store_version=rec["store_version"], complete=rec["complete"], records_indexed=rec["records_indexed"],
            tables=[EvidenceTableInfo(**t) for t in rec["tables"]])
    return RegistryResult(project_id=extraction.project_id, stage_version=STAGE_VERSION, started_at=started,
                          finished_at=max(clock(), started), registry_mode=mode, evidence_cutoff=evidence_cutoff,
                          evidence_store=store_info, results=results, failures=failures)
