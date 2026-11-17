"""Agent 5: independent deterministic verification of recommendations (D-047 e, D-059).

Agent 5 decides whether a recommendation may be shown. It reads only the
structured fields of each recommendation (action, target, claims and their
evidence IDs; never the rationale), the Agent 1 dependency record, Agent 2's
registry facts for that dependency, the evidence store and a read-only registry
client for the recommended target. It has no LLM, imports nothing from Agent 4
and does not trust Agent 3: every check is re-derived here.

Verdict (``contracts.pipeline.verdict_from_checks``): any ``fail`` gives
``reject``; any required ``not_run`` gives ``abstain``; otherwise ``accept``.
A check that cannot be run (no registry data, a lookup error, an incomplete
evidence store, a version that cannot be read) is ``not_run``, never ``pass``,
so a failed lookup can never lead to ``accept``.

Cut-off (held-out runs): evidence published on or after the cut-off and undated
evidence are not used; a citation of such a record is a failed claim. Live
registry lookups are refused; snapshot versions count only when uploaded before
the cut-off; a ``not_found`` or security hold recorded after the cut-off says
nothing about the cut-off and leaves the check ``not_run``.

Checks other than ``schema`` can be switched off for the verifier ablation
(D-030); a switched-off check is recorded as ``not_run`` with ``required=False``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Optional, Union

from pydantic import ValidationError

from multi_agentic_security.contracts.evidence import EvidenceRecord, LabelFamily, VersionScope
from multi_agentic_security.contracts.pipeline import (
    TARGET_ACTIONS, CheckResult, DependencyRecord, ExtractionResult, Failure, PackageRef, Reason, Recommendation,
    RecommendationResult, RecommendationVerification, RegistryResult, RegistryVerification, VerificationResult,
    verdict_from_checks,
)
from multi_agentic_security.datasets.names import normalize_name
from multi_agentic_security.evidence_store import EvidenceStore, QueryResult

from . import versions as V

STAGE_VERSION = "agent5/0.1"

ALL_CHECKS = ("schema", "dependency_identity", "action_allowed", "claims_supported", "target_exists",
              "target_not_malicious", "target_not_typosquat", "target_version_not_vulnerable",
              "replacement_matches_reference", "action_consistent")
SWITCHABLE = frozenset(ALL_CHECKS[1:])
TARGET_CHECKS = ("target_exists", "target_not_malicious", "target_not_typosquat", "target_version_not_vulnerable")
KEEPS_PACKAGE = frozenset({"keep", "upgrade", "downgrade"})
EVIDENCE_CLAIMS = {
    "is_reported_malicious": LabelFamily.MALICIOUS,
    "is_compromised_version": LabelFamily.MALICIOUS,
    "is_typosquat_of": LabelFamily.TYPOSQUAT,
    "is_vulnerable": LabelFamily.VULNERABLE,
    "fixed_in": LabelFamily.VULNERABLE,
    "report_withdrawn": LabelFamily.WITHDRAWN,
}
VERSIONED_CLAIMS = frozenset({"is_reported_malicious", "is_compromised_version", "is_vulnerable"})
RISK_FAMILIES = (LabelFamily.MALICIOUS, LabelFamily.WITHDRAWN, LabelFamily.TYPOSQUAT, LabelFamily.VULNERABLE)

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- helpers

@dataclass
class _Out:
    result: str
    detail: str
    evidence_ids: list[str] = field(default_factory=list)
    inputs: dict[str, Any] = field(default_factory=dict)


def _same_pkg(a: Optional[PackageRef], b: Optional[PackageRef]) -> bool:
    return a is not None and b is not None and (a.ecosystem, a.name_normalized) == (b.ecosystem, b.name_normalized)


def _merge(outs: list[_Out]) -> str:
    if any(o.result == "fail" for o in outs):
        return "fail"
    if any(o.result == "not_run" for o in outs):
        return "not_run"
    return "pass"


@dataclass
class _Ctx:
    store: Optional[EvidenceStore]
    complete: bool
    cutoff_dt: Optional[datetime]
    cutoff_date: Optional[date]
    client: Any
    client_refused: Optional[str]
    failures: list[Failure]
    _lookups: dict = field(default_factory=dict)
    _queries: dict = field(default_factory=dict)

    def query(self, pkg: PackageRef) -> Optional[QueryResult]:
        if self.store is None:
            return None
        key = (pkg.ecosystem, pkg.name_normalized)
        if key not in self._queries:
            self._queries[key] = self.store.query(pkg.ecosystem, pkg.name_normalized, cutoff=self.cutoff_date)
        return self._queries[key]

    def lookup(self, pkg: PackageRef) -> V.TargetFacts:
        key = (pkg.ecosystem, pkg.name_normalized)
        if key in self._lookups:
            return self._lookups[key]
        if self.client_refused:
            facts = V.TargetFacts("unavailable", note=self.client_refused)
        else:
            try:
                supported = self.client.supports(pkg.ecosystem)
                outcome = self.client.lookup(pkg.ecosystem, pkg.name_normalized) if supported else None
            except Exception as exc:  # a client failure is a state, never a default answer
                self.failures.append(Failure(stage="agent5", code="a5.registry.client_error",
                                             detail=f"{pkg.ecosystem}/{pkg.name_normalized}: {type(exc).__name__}"))
                facts = V.TargetFacts("unavailable", note=f"the registry client failed ({type(exc).__name__})")
            else:
                facts = (V.target_facts(outcome, self.cutoff_dt) if supported else
                         V.TargetFacts("unavailable", note=f"the registry client does not support {pkg.ecosystem}"))
        self._lookups[key] = facts
        return facts


# --------------------------------------------------------------------------- checks

def _check_identity(rec: Recommendation, dep: DependencyRecord) -> _Out:
    subjects = [c.subject for c in rec.claims]
    if dep.package is None:
        if rec.action in ("abstain", "investigate", "remove") and not rec.claims:
            return _Out("pass", "The dependency's package is unknown; the action names no package.")
        return _Out("fail", "The dependency's package could not be determined, so a recommendation that names a "
                            "package or makes claims cannot be tied to it.", inputs={"action": rec.action})
    if rec.target is not None and rec.target.package.ecosystem != dep.ecosystem:
        return _Out("fail", f"The target is a {rec.target.package.ecosystem} package but the dependency is "
                            f"{dep.ecosystem}.", inputs={"target": rec.target.package.name_normalized})
    allowed = [dep.package] + ([rec.target.package] if rec.target is not None else [])
    stray = [s.name_normalized for s in subjects if not any(_same_pkg(s, a) for a in allowed)]
    if stray:
        return _Out("fail", "Claims are made about packages that are neither the dependency nor the target: "
                            + ", ".join(sorted(set(stray))) + ".", inputs={"subjects": sorted(set(stray))})
    return _Out("pass", "The recommendation refers to this dependency, and its claims are about the dependency "
                        "or the target.", inputs={"package": dep.package.name_normalized})


def _check_action(rec: Recommendation, dep: DependencyRecord, inst: Optional[V.Installed]) -> _Out:
    if rec.generation_status != "ok":
        return _Out("pass", f"Generation ended with {rec.generation_status!r}; the only action allowed is "
                            "'abstain', which this is.", inputs={"generation_status": rec.generation_status})
    if rec.action not in TARGET_ACTIONS:
        return _Out("pass", f"Action {rec.action!r} takes no target.")
    if dep.package is None:
        return _Out("fail", "A target action needs a known dependency package.")
    t = rec.target
    if rec.action == "replace":
        if _same_pkg(t.package, dep.package):
            return _Out("fail", "'replace' names the same package; changing only the version is an upgrade or "
                                "downgrade.", inputs={"target": t.package.name_normalized})
        if t.version and V.parse(t.package.ecosystem, t.version) is None:
            return _Out("fail", f"The target version {t.version!r} is not a valid {t.package.ecosystem} version.",
                        inputs={"target_version": t.version})
        return _Out("pass", f"Replace {dep.package.name_normalized} with {t.package.name_normalized}.",
                    inputs={"target": t.package.name_normalized, "target_version": t.version})
    if not _same_pkg(t.package, dep.package):
        return _Out("fail", f"'{rec.action}' must keep the package; the target is a different package "
                            f"({t.package.name_normalized}).", inputs={"target": t.package.name_normalized})
    eco = dep.ecosystem
    tv = V.parse(eco, t.version)
    if tv is None:
        return _Out("fail", f"The target version {t.version!r} is not a valid {eco} version.",
                    inputs={"target_version": t.version})
    current = inst.version if inst is not None and inst.kind == "exact" else None
    cv = V.parse(eco, current)
    indicators: dict[str, Any] = {"target_version": t.version, "current_version": current,
                                  "constraint_admits_target": inst.allows(t.version) if inst is not None else None,
                                  "semver_distance": _distance(eco, cv, tv)}
    if cv is None:
        return _Out("pass", f"The current version is not pinned, so the direction of the {rec.action} cannot be "
                            "checked; the target version is valid.", inputs=indicators)
    if (rec.action == "upgrade" and not tv > cv) or (rec.action == "downgrade" and not tv < cv):
        return _Out("fail", f"'{rec.action}' from {current} to {t.version} goes the wrong way or does not change "
                            "the version.", inputs=indicators)
    return _Out("pass", f"{rec.action.capitalize()} from {current} to {t.version}.", inputs=indicators)


def _distance(eco: str, a, b) -> Optional[dict]:
    """Reported indicator (D-036), never used to reject."""
    if a is None or b is None:
        return None
    if eco == "pypi":
        ra, rb = (list(a.release) + [0, 0, 0])[:3], (list(b.release) + [0, 0, 0])[:3]
    else:
        ra, rb = [a.major, a.minor, a.patch], [b.major, b.minor, b.patch]
    for i, part in enumerate(("major", "minor", "patch")):
        if ra[i] != rb[i]:
            return {"level": part, "delta": rb[i] - ra[i]}
    return {"level": "none", "delta": 0}


def _subject_registry(ctx: _Ctx, subject: PackageRef, dep: DependencyRecord,
                      reg: Optional[RegistryVerification]) -> tuple[str, bool]:
    """(status, after_cutoff) for a claim subject: Agent 2's facts for the dependency, a lookup for others."""
    if _same_pkg(subject, dep.package):
        if reg is None:
            return "unavailable", False
        after = bool(reg.retrieved_after_cutoff) if ctx.cutoff_dt is not None else False
        if ctx.cutoff_dt is not None and reg.retrieved_after_cutoff is None and reg.retrieved_at is not None:
            after = reg.retrieved_at >= ctx.cutoff_dt
        if reg.status == "found" and ctx.cutoff_dt is not None:
            known = list(reg.versions or [])
            if reg.version_upload_times is not None:     # filter again, do not trust Agent 2 (D-061)
                times = reg.version_upload_times
                known = [v for v in known if times.get(v) is not None and times[v] < ctx.cutoff_dt]
            if not known:
                return "not_yet", after      # registered, but no release before the cut-off (D-060)
        if reg.status in ("found", "not_found", "security_placeholder"):
            return reg.status, after
        return "unavailable", False
    facts = ctx.lookup(subject)
    if facts.state == "found" and ctx.cutoff_dt is not None and not facts.versions:
        return "not_yet", facts.after_cutoff
    return facts.state, facts.after_cutoff


def _claim(ctx: _Ctx, claim, dep: DependencyRecord, reg: Optional[RegistryVerification],
           inst: Optional[V.Installed] = None) -> _Out:
    kind, subj, ids = claim.type, claim.subject, list(claim.evidence_ids)
    label = f"{kind}({subj.name_normalized}{', ' + claim.object if claim.object else ''})"
    if kind in EVIDENCE_CLAIMS:
        if not ids:
            return _Out("fail", f"{label}: the claim cites no evidence.")
        if ctx.store is None:
            return _Out("not_run", f"{label}: no evidence store, so the citations cannot be checked.", ids)
        family = EVIDENCE_CLAIMS[kind]
        records: list[EvidenceRecord] = []
        for eid in ids:
            r = ctx.store.get(eid)
            if r is None:
                return _Out("fail", f"{label}: evidence {eid} does not exist in the store.", ids)
            if ctx.cutoff_date is not None and not r.known_before(ctx.cutoff_date):
                return _Out("fail", f"{label}: evidence {eid} was not published before the cut-off "
                                    f"{ctx.cutoff_date.isoformat()} (or has no date), so it was not available.", ids)
            if (r.ecosystem, r.name_normalized) != (subj.ecosystem, subj.name_normalized):
                return _Out("fail", f"{label}: evidence {eid} is about {r.ecosystem}/{r.name_normalized}, "
                                    "not the claim's subject.", ids)
            if r.family is not family:
                return _Out("fail", f"{label}: evidence {eid} is a {r.family.value} record; the claim needs "
                                    f"{family.value}.", ids)
            records.append(r)
        out = _claim_content(ctx, kind, label, claim.object, subj, records, ids)
        if (out.result == "pass" and not claim.object and kind in VERSIONED_CLAIMS and _same_pkg(subj, dep.package)
                and inst is not None and any(r.version_scope is not VersionScope.ALL for r in records)):
            states = [V.applies(r, inst) for r in records]
            if all(s is False for s in states):
                return _Out("fail", f"{label}: every cited record covers only versions that the declaration of "
                                    f"{subj.name_normalized} cannot receive.", ids, {"applies": states})
        return out
    if ids:
        return _Out("fail", f"{label}: evidence records cannot show this claim; it must cite none.", ids)
    q = ctx.query(subj)
    if q is None or not ctx.complete:
        return _Out("not_run", f"{label}: the evidence store is missing or incomplete, so absence of evidence "
                               "cannot be shown.")
    if kind == "no_evidence_found":
        hits = [m.evidence_id for m in q.matches if m.role == "name" and m.record.family in RISK_FAMILIES]
        if hits:
            return _Out("fail", f"{label}: the store holds {len(hits)} risk record(s) about this package.", hits)
        return _Out("pass", f"{label}: no malicious, withdrawn, typosquat or vulnerable record names this package"
                            + (" before the cut-off." if ctx.cutoff_date else "."))
    # is_nonexistent
    named = [m.evidence_id for m in q.matches]
    if named:
        return _Out("fail", f"{label}: evidence records name this package, so it was published.", named)
    status, after = _subject_registry(ctx, subj, dep, reg)
    if status == "not_yet":
        return _Out("not_run", f"{label}: the package has no release before the cut-off; whether the name was "
                               "taken then is not known.")
    if status in ("found",):
        return _Out("fail", f"{label}: the registry lists this package.")
    if status == "security_placeholder" and not after:
        return _Out("fail", f"{label}: the registry holds a security placeholder, so the package was published.")
    if status == "not_found" and not after:
        return _Out("pass", f"{label}: the registry does not know this package and no evidence names it.")
    if after:
        return _Out("not_run", f"{label}: the registry answer was recorded after the cut-off and says nothing "
                               "about the cut-off.")
    return _Out("not_run", f"{label}: no registry answer for this package.")


def _claim_content(ctx: _Ctx, kind: str, label: str, obj: Optional[str], subj: PackageRef,
                   records: list[EvidenceRecord], ids: list[str]) -> _Out:
    eco = subj.ecosystem
    if kind in ("is_reported_malicious", "report_withdrawn", "is_vulnerable") and not obj:
        return _Out("pass", f"{label}: every cited record is a matching report about this package.", ids)
    if kind == "is_typosquat_of":
        if not obj:
            return _Out("fail", f"{label}: the claim does not name the imitated package.", ids)
        target = normalize_name(eco, obj)
        wrong = [r.evidence_id for r in records if r.target_name_normalized != target]
        if wrong:
            return _Out("fail", f"{label}: cited record(s) name a different imitated package.", ids)
        return _Out("pass", f"{label}: every cited record lists this package as a typosquat of {target}.", ids)
    if kind == "fixed_in" and not obj:
        return _Out("fail", f"{label}: the claim does not name the fixed version.", ids)
    if kind == "is_compromised_version":
        if any(r.version_scope is VersionScope.ALL for r in records):
            return _Out("fail", f"{label}: a cited record reports the whole package, not a version.", ids)
    if not obj:
        return _Out("pass", f"{label}: every cited record reports specific versions of this package.", ids)
    if V.parse(eco, obj) is None:
        return _Out("fail", f"{label}: {obj!r} is not a valid {eco} version.", ids)
    cov = [V.covers(r, obj) for r in records]
    if any(c is None for c in cov):
        return _Out("not_run", f"{label}: a cited record's version scope cannot be read.", ids)
    if kind == "fixed_in":
        if any(cov):
            return _Out("fail", f"{label}: {obj} is still inside the affected range of a cited record.", ids)
        past = [V.fixed_by(r, obj) for r in records]
        if any(x is None for x in past):
            return _Out("not_run", f"{label}: a cited record's range cannot be read.", ids)
        if not all(past):
            return _Out("fail", f"{label}: {obj} is not past the affected versions of every cited record (it is "
                                "below them, or a range has no upper bound).", ids)
        q = ctx.query(subj)
        others = [m for m in (q.by_family("vulnerable") if q is not None else [])]
        still = [m.evidence_id for m in others if V.covers(m.record, obj)]
        if still:
            return _Out("fail", f"{label}: {obj} is inside {len(still)} other vulnerable record(s) for this package.",
                        sorted(set(ids) | set(still)))
        if any(V.covers(m.record, obj) is None for m in others):
            return _Out("not_run", f"{label}: another vulnerable record's range cannot be read.", ids)
        if q is None or not ctx.complete:
            return _Out("not_run", f"{label}: the evidence store is incomplete, so other advisories cannot be ruled "
                                   "out.", ids)
        return _Out("pass", f"{label}: {obj} is past every cited affected range and outside every known "
                            "vulnerable record.", ids)
    if not all(cov):
        return _Out("fail", f"{label}: a cited record does not cover version {obj}.", ids)
    return _Out("pass", f"{label}: every cited record covers version {obj}.", ids)


def _check_claims(ctx: _Ctx, rec: Recommendation, dep: DependencyRecord,
                  reg: Optional[RegistryVerification], inst: Optional[V.Installed] = None) -> _Out:
    if not rec.claims:
        return _Out("not_applicable", "The recommendation makes no claims.")
    outs = [_claim(ctx, c, dep, reg, inst) for c in rec.claims]
    ids = sorted({e for o in outs for e in o.evidence_ids})
    result = _merge(outs)
    return _Out(result, " ".join(o.detail for o in outs), ids,
                {"claims": [{"type": c.type, "result": o.result} for c, o in zip(rec.claims, outs)]})


def _target(ctx: _Ctx, rec: Recommendation) -> tuple[V.TargetFacts, Optional[str], str]:
    t = rec.target
    facts = ctx.lookup(t.package)
    if t.version:
        return facts, t.version, "stated"
    v = V.target_version(t.package.ecosystem, facts)
    return facts, v, "resolved" if v else "unknown"


def _check_target_exists(ctx: _Ctx, rec: Recommendation, facts: V.TargetFacts) -> _Out:
    t = rec.target
    name = t.package.name_normalized
    cut = f" {ctx.cutoff_date.isoformat()}" if ctx.cutoff_date else ""
    if facts.state == "unavailable":
        return _Out("not_run", f"Existence of {name} could not be checked: {facts.note}")
    if facts.state in ("not_found", "security_placeholder"):
        what = "does not list" if facts.state == "not_found" else "holds only a security placeholder for"
        if facts.after_cutoff:
            return _Out("not_run", f"The registry {what} {name}, but this was recorded after the cut-off{cut} and "
                                   "says nothing about the cut-off.", inputs={"status": facts.state})
        return _Out("fail", f"The registry {what} {name}.", inputs={"status": facts.state})
    inputs = {"status": "found", "versions_known": len(facts.versions), "after_cutoff": facts.after_cutoff}
    if not t.version:
        if not facts.versions:
            if any(facts.upload_times.get(v) is None for v in facts.all_versions):
                return _Out("not_run", f"Some releases of {name} have no upload time, so they cannot be placed "
                                       f"before the cut-off{cut}.", inputs=inputs)
            return _Out("fail", f"{name} has no release uploaded before the cut-off{cut}.", inputs=inputs)
        return _Out("pass", f"{name} exists in the registry" + (f" before the cut-off{cut}." if cut else "."),
                    inputs=inputs)
    eco = t.package.ecosystem
    if any(V.same(eco, v, t.version) for v in facts.versions):
        note = " (the release is yanked)" if t.version in facts.yanked else ""
        return _Out("pass", f"{name} {t.version} exists in the registry{note}.", inputs=inputs)
    listed = [v for v in facts.all_versions if V.same(eco, v, t.version)]
    if listed and ctx.cutoff_dt is not None:
        up = facts.upload_times.get(listed[0])
        if up is None:
            return _Out("not_run", f"{name} {t.version} has no upload time, so it cannot be placed before the "
                                   f"cut-off{cut}.", inputs=inputs)
        return _Out("fail", f"{name} {t.version} was uploaded on {up.date().isoformat()}, after the cut-off{cut}.",
                    inputs=inputs)
    if ctx.cutoff_dt is not None and facts.after_cutoff:
        return _Out("not_run", f"{name} {t.version} is not in a registry list recorded after the cut-off{cut}; it may "
                               "have been removed later.", inputs=inputs)
    return _Out("fail", f"{name} has no release {t.version} in the registry.", inputs=inputs)


def _scoped_check(ctx: _Ctx, pkg: PackageRef, version: Optional[str], how: str, family: LabelFamily,
                  what: str, facts: Optional[V.TargetFacts] = None) -> _Out:
    q = ctx.query(pkg)
    name = pkg.name_normalized
    if q is None:
        return _Out("not_run", f"No evidence store, so {name} cannot be checked for {what} reports.")
    recs = q.by_family(family.value)
    hits, unknown, other = [], [], []
    for m in recs:
        c = V.covers(m.record, version)
        if c is False and how == "resolved" and ctx.cutoff_dt is not None and facts is not None \
                and m.record.version_scope is VersionScope.LISTED and V.newer(pkg.ecosystem, m.record.version, version):
            listed = [v for v in facts.all_versions if V.same(pkg.ecosystem, v, m.record.version)]
            gone = not listed or any(facts.upload_times.get(v) is None for v in listed)   # removed, or undated (D-061)
            pre = pkg.ecosystem == "npm" and V.parse("npm", m.record.version) is not None \
                and bool(V.parse("npm", m.record.version).prerelease)
            if gone or pre:
                # Under a cut-off the release may have been the newest (or the 'latest' tag) then and
                # removed later; the version a new install received at the cut-off is unknown (D-060).
                c = None
        (hits if c else unknown if c is None else other).append(m.evidence_id)
    vtext = f"{name} {version}" if version else name
    inputs = {"version": version, "version_source": how, "other_versions": other}
    if hits:
        return _Out("fail", f"{vtext} is covered by {len(hits)} {what} report(s).", hits, inputs)
    if unknown:
        why = ("the version to install is unknown" if version is None else
               "a reported release may have been the one installed at the cut-off" if how == "resolved" and
               ctx.cutoff_dt is not None else "a record's version scope cannot be read")
        return _Out("not_run", f"{name} has {what} reports and {why}.", unknown, inputs)
    if not ctx.complete:
        return _Out("not_run", "The evidence store is incomplete, so the absence of a report cannot be shown.",
                    inputs=inputs)
    tail = f" ({len(other)} report(s) cover other versions only)" if other else ""
    return _Out("pass", f"No {what} report covers {vtext}{tail}.", other, inputs)


def _check_typosquat(ctx: _Ctx, pkg: PackageRef) -> _Out:
    q = ctx.query(pkg)
    if q is None:
        return _Out("not_run", "No evidence store, so the target cannot be checked against typosquat lists.")
    hits = [m.evidence_id for m in q.by_family("typosquat", role="name")]
    if hits:
        targets = sorted({m.record.target_name_normalized for m in q.by_family("typosquat", role="name")
                          if m.record.target_name_normalized})
        return _Out("fail", f"{pkg.name_normalized} is listed as a typosquat of {', '.join(targets) or 'a package'}.",
                    hits, {"imitates": targets})
    if not ctx.complete:
        return _Out("not_run", "The evidence store is incomplete, so the absence of a typosquat listing cannot be "
                               "shown.")
    return _Out("pass", f"{pkg.name_normalized} is not listed as a typosquat (name similarity is not checked).")


def _check_reference(ctx: _Ctx, rec: Recommendation, dep: DependencyRecord) -> _Out:
    if rec.action != "replace":
        return _Out("not_applicable", f"Action {rec.action!r} is not a replacement.")
    if dep.package is None:
        return _Out("not_applicable", "The dependency's package is unknown.")
    q = ctx.query(dep.package)
    if q is None:
        return _Out("not_run", "No evidence store, so the reference package cannot be looked up.")
    squats = q.by_family("typosquat", role="name")
    refs = sorted({m.record.target_name_normalized for m in squats if m.record.target_name_normalized})
    ids = [m.evidence_id for m in squats]
    if refs:
        if rec.target.package.name_normalized in refs:
            return _Out("pass", f"{dep.package.name_normalized} is listed as a typosquat of "
                                f"{rec.target.package.name_normalized}, the recommended replacement.", ids,
                        {"references": refs})
        return _Out("fail", f"{dep.package.name_normalized} is listed as a typosquat of {', '.join(refs)}, but the "
                            f"replacement is {rec.target.package.name_normalized}.", ids, {"references": refs})
    if not ctx.complete:
        return _Out("not_run", "The evidence store is incomplete, so a reference package may be missing.")
    return _Out("not_applicable", "No typosquat record names a reference package for this dependency.")


def _check_consistent(ctx: _Ctx, rec: Recommendation, dep: DependencyRecord, reg: Optional[RegistryVerification],
                      inst: Optional[V.Installed]) -> _Out:
    if rec.action not in KEEPS_PACKAGE:
        return _Out("pass", f"Action {rec.action!r} does not keep the package in the project.")
    if dep.package is None:
        return _Out("not_run", "The dependency's package is unknown.")
    q = ctx.query(dep.package)
    if q is None:
        return _Out("not_run", "No evidence store, so the dependency's risk cannot be re-derived.")
    name = dep.package.name_normalized
    whole = [m.evidence_id for m in q.by_family("malicious") if m.record.version_scope is VersionScope.ALL]
    if whole:
        return _Out("fail", f"'{rec.action}' keeps {name}, which is reported malicious as a whole package.", whole)
    squat = [m.evidence_id for m in q.by_family("typosquat", role="name")]
    if squat:
        return _Out("fail", f"'{rec.action}' keeps {name}, which is listed as a typosquat.", squat)
    status, after = _subject_registry(ctx, dep.package, dep, reg)
    if status == "not_yet":
        return _Out("not_run", f"{name} has no release before the cut-off, so it could not have been installed "
                               "then; the recommendation needs review.")
    if status in ("not_found", "security_placeholder"):
        if after:
            return _Out("not_run", f"The registry answer for {name} ({status}) was recorded after the cut-off.")
        what = "does not list it" if status == "not_found" else "replaced it with a security placeholder"
        return _Out("fail", f"'{rec.action}' keeps {name}, but the registry {what}.", inputs={"status": status})
    if status != "found":
        return _Out("not_run", f"No registry answer for {name}, so its existence cannot be confirmed.")
    if not ctx.complete:
        return _Out("not_run", "The evidence store is incomplete, so the absence of a whole-package report cannot be "
                               "shown.")
    if rec.action != "keep":
        return _Out("pass", f"{name} is not reported as a whole package; the target version is checked separately.")
    scoped = [m for m in q.matches if m.role == "name" and m.record.family in (LabelFamily.MALICIOUS,
                                                                                LabelFamily.VULNERABLE)]
    states = {m.evidence_id: V.exposure(m.record, inst) for m in scoped}
    exposed = sorted(e for e, s in states.items() if s == "exposed")
    unknown = sorted(e for e, s in states.items() if s == "unknown")
    removed = sorted(e for e, s in states.items() if s == "removed")
    inputs = {"installed": inst.to_dict() if inst else None, "removed_release_ids": removed}
    if exposed:
        return _Out("fail", f"'keep' leaves {name} at a version covered by {len(exposed)} malicious or "
                            "vulnerable report(s).", exposed, inputs)
    if inst is not None and inst.kind == "exact" and inst.registry_versions is not None and not any(
            V.same(dep.ecosystem, v, inst.version) for v in inst.registry_versions):
        # Checked after 'exposed' so that a pin the evidence covers is still rejected (D-061).
        return _Out("not_run", f"The pinned version {inst.version} of {name} is not among the registry's releases"
                               + (" before the cut-off" if ctx.cutoff_dt else "") + "; it cannot be checked.",
                    inputs=inputs)
    if unknown:
        return _Out("not_run", f"{name} has version-specific reports and the installed version cannot be decided.",
                    unknown, inputs)
    if not ctx.complete:
        return _Out("not_run", "The evidence store is incomplete, so the absence of a report cannot be shown.",
                    inputs=inputs)
    tail = (f" {len(removed)} reported release(s) are no longer in the registry, so a new install cannot receive "
            "them; check lock files and installed copies." if removed else "")
    return _Out("pass", f"No report covers the version of {name} that a new install receives.{tail}",
                sorted(states), inputs)


# --------------------------------------------------------------------------- one recommendation

def _reason(check: str, out: _Out) -> Reason:
    return Reason(rule_id=f"a5.check.{check}.{out.result}", outcome=out.result, explanation=out.detail,
                  inputs=out.inputs, evidence_ids=out.evidence_ids)


def _verify_one(ctx: _Ctx, raw: Mapping, dep: DependencyRecord, reg: Optional[RegistryVerification],
                enabled: frozenset) -> RecommendationVerification:
    outs: dict[str, _Out] = {}
    try:
        rec = Recommendation.model_validate(dict(raw))
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        outs["schema"] = _Out("fail", "The recommendation does not match the contract: "
                                      f"{'.'.join(str(p) for p in first.get('loc', ()))} {first.get('msg', '')}".strip(),
                              inputs={"errors": len(exc.errors())})
        rec = None
    else:
        outs["schema"] = _Out("pass", "The recommendation matches the contract.")

    if rec is not None:
        inst = (V.installed(dep, reg, cutoff_set=ctx.cutoff_dt is not None, cutoff_dt=ctx.cutoff_dt)
                if dep.package is not None else None)
        outs["dependency_identity"] = _check_identity(rec, dep)
        outs["action_allowed"] = _check_action(rec, dep, inst)
        outs["claims_supported"] = _check_claims(ctx, rec, dep, reg, inst)
        if rec.target is None:
            for c in TARGET_CHECKS:
                outs[c] = _Out("not_applicable", f"Action {rec.action!r} has no target.")
        else:
            facts, version, how = _target(ctx, rec)
            pkg = rec.target.package
            outs["target_exists"] = _check_target_exists(ctx, rec, facts)
            outs["target_not_malicious"] = _scoped_check(ctx, pkg, version, how, LabelFamily.MALICIOUS, "malicious",
                                                         facts)
            outs["target_not_typosquat"] = _check_typosquat(ctx, pkg)
            outs["target_version_not_vulnerable"] = _scoped_check(ctx, pkg, version, how, LabelFamily.VULNERABLE,
                                                                  "vulnerability", facts)
        outs["replacement_matches_reference"] = _check_reference(ctx, rec, dep)
        outs["action_consistent"] = _check_consistent(ctx, rec, dep, reg, inst)
    else:
        for c in ALL_CHECKS[1:]:
            outs[c] = _Out("not_run", "Not run: the recommendation does not match the contract.")

    checks, reasons = [], []
    for name in ALL_CHECKS:
        out = outs[name]
        if name in SWITCHABLE and name not in enabled:
            out = _Out("not_run", "Switched off for this run (verifier ablation).")
            checks.append(CheckResult(check=name, result="not_run", required=False, detail=out.detail))
            reasons.append(Reason(rule_id=f"a5.check.{name}.switched_off", outcome="not_run",
                                  explanation=out.detail))
            continue
        checks.append(CheckResult(check=name, result=out.result, evidence_ids=out.evidence_ids, detail=out.detail))
        reasons.append(_reason(name, out))
    verdict = verdict_from_checks(checks)
    failed = [c.check for c in checks if c.result == "fail"]
    open_ = [c.check for c in checks if c.required and c.result == "not_run"]
    text = {"reject": "Rejected: failed " + ", ".join(failed) + ".",
            "abstain": "Needs review: could not run " + ", ".join(open_) + ".",
            "accept": "Verified: every required check passed or does not apply."}[verdict]
    reasons.append(Reason(rule_id=f"a5.verdict.{verdict}", outcome=verdict, explanation=text,
                          inputs={"failed": failed, "not_run": open_,
                                  "cutoff": ctx.cutoff_date.isoformat() if ctx.cutoff_date else None,
                                  "store_complete": ctx.complete if ctx.store is not None else None,
                                  "registry_client": getattr(ctx.client, "mode", None) if ctx.client else None}))
    return RecommendationVerification(dependency_id=dep.dependency_id, verdict=verdict, checks=checks,
                                      verifier_version=STAGE_VERSION, reasons=reasons)


# --------------------------------------------------------------------------- entry point

def _raw_recommendations(recommendations: Union[RecommendationResult, Mapping]) -> tuple[Optional[str], list]:
    if isinstance(recommendations, RecommendationResult):
        return recommendations.project_id, [r.model_dump(mode="python") for r in recommendations.recommendations]
    if isinstance(recommendations, Mapping):
        recs = recommendations.get("recommendations")
        pid = recommendations.get("project_id")
        return (pid if isinstance(pid, str) else None), (list(recs) if isinstance(recs, list) else None)
    raise TypeError("recommendations must be a RecommendationResult or a mapping of the same shape")


def verify_recommendations(extraction: ExtractionResult, registry: RegistryResult,
                           recommendations: Union[RecommendationResult, Mapping], *,
                           evidence_store: Optional[EvidenceStore], target_client: Any = None,
                           enabled_checks: Optional[Iterable[str]] = None,
                           clock: Clock = _utc_now) -> VerificationResult:
    """Verify every recommendation; one ``RecommendationVerification`` each, in input order.

    ``target_client`` is a registry client (``SnapshotRegistryClient`` for experiments) used only
    for recommended targets and for claim subjects other than the dependency. The cut-off is
    ``registry.evidence_cutoff``. ``enabled_checks`` (default: all) switches checks off for the
    verifier ablation; ``schema`` is always run."""
    started = clock()
    failures: list[Failure] = []
    enabled = frozenset(ALL_CHECKS if enabled_checks is None else enabled_checks)
    unknown_checks = sorted(enabled - set(ALL_CHECKS))
    if unknown_checks:
        raise ValueError(f"unknown checks: {unknown_checks}")

    cutoff = registry.evidence_cutoff
    cutoff_dt = cutoff.astimezone(timezone.utc) if cutoff is not None else None
    cutoff_date = cutoff_dt.date() if cutoff_dt is not None else None

    refused = None
    if target_client is None:
        refused = "no registry client was given (registry mode off)"
        failures.append(Failure(stage="agent5", code="a5.registry.no_client",
                                detail="target existence and target version checks are not run"))
    elif cutoff_dt is not None and getattr(target_client, "mode", None) != "snapshot":
        refused = "a live registry lookup is refused in a run with a cut-off (it would show later takedowns)"
        failures.append(Failure(stage="agent5", code="a5.registry.live_with_cutoff",
                                detail="use a snapshot client for held-out runs; target lookups are not run"))

    complete = False
    if evidence_store is None:
        failures.append(Failure(stage="agent5", code="a5.evidence.store_missing",
                                detail="no evidence store: evidence checks are not run and nothing can be accepted "
                                       "that depends on them"))
    else:
        complete = evidence_store.complete
        if not complete:
            failures.append(Failure(stage="agent5", code="a5.evidence.store_incomplete",
                                    detail="tables not loaded: " + ", ".join(evidence_store.missing_tables or ["?"])
                                           + "; absence of evidence is never treated as a pass"))
        if registry.evidence_store is not None:
            used = {t.table: t.records_sha256 for t in registry.evidence_store.tables}
            if used != evidence_store.tables_fingerprint():
                failures.append(Failure(stage="agent5", code="a5.evidence.store_differs_from_agent2",
                                        detail="Agent 5 re-derives its checks from its own store, which differs "
                                               "from the one Agent 2 used (table hashes)"))

    ctx = _Ctx(evidence_store, complete, cutoff_dt, cutoff_date, target_client, refused, failures)
    deps = {d.dependency_id: d for d in extraction.dependencies}
    regs: dict[str, RegistryVerification] = {}
    for r in registry.results:
        regs.setdefault(r.dependency_id, r)

    pid, raws = _raw_recommendations(recommendations)
    check_missing = True
    if raws is None:
        failures.append(Failure(stage="agent5", code="a5.input.invalid_recommendations",
                                detail="'recommendations' is not a list; nothing was verified"))
        raws, check_missing = [], False
    if registry.project_id != extraction.project_id or (pid is not None and pid != extraction.project_id):
        failures.append(Failure(stage="agent5", code="a5.input.project_mismatch",
                                detail="the extraction, registry and recommendation results belong to different "
                                       "projects; nothing was verified"))
        raws, check_missing = [], False

    out: list[RecommendationVerification] = []
    seen: set[str] = set()
    for i, raw in enumerate(raws):
        dep_id = raw.get("dependency_id") if isinstance(raw, Mapping) else None
        if not isinstance(dep_id, str) or dep_id not in deps:
            failures.append(Failure(stage="agent5", code="a5.input.unknown_dependency",
                                    detail=f"recommendation {i} refers to no Agent 1 dependency; not verified",
                                    dependency_id=dep_id if isinstance(dep_id, str) else None))
            continue
        if dep_id in seen:
            failures.append(Failure(stage="agent5", code="a5.input.duplicate_recommendation",
                                    detail=f"recommendation {i} repeats a dependency; only the first is verified",
                                    dependency_id=dep_id))
            continue
        seen.add(dep_id)
        if dep_id not in regs:
            failures.append(Failure(stage="agent5", code="a5.input.missing_registry_result",
                                    detail="no Agent 2 result for this dependency; its registry state is unknown",
                                    dependency_id=dep_id))
        out.append(_verify_one(ctx, raw, deps[dep_id], regs.get(dep_id), enabled))

    for dep_id in deps:
        if dep_id not in seen and check_missing:
            failures.append(Failure(stage="agent5", code="a5.input.missing_recommendation",
                                    detail="Agent 4 gave no recommendation for this dependency", dependency_id=dep_id))

    return VerificationResult(project_id=extraction.project_id, stage_version=STAGE_VERSION, started_at=started,
                              finished_at=max(clock(), started), verifications=out, failures=failures)
