"""R0: the deterministic rule recommender (RESEARCH_QUESTIONS.md section 7, D-062).

R0 reads Agent 3's findings and the evidence records in the packet; it never looks
anything up. The first rule that matches decides (order in ``decide``):

1.  no package, or no assessment                      -> abstain
2.  typosquat listed with one imitated package         -> replace with it (remove when the imitated
                                                          package is itself reported malicious or
                                                          listed as a typosquat, D-063)
    typosquat listed with several imitated packages    -> remove
3.  reported malicious (whole package)                 -> remove
4.  registry security hold                             -> remove
5.  nonexistent                                        -> remove
6.  compromised version or vulnerable, applicability affected / likely_affected / possible
                                                       -> upgrade to the lowest registry release at or
                                                          above a stated fix (``<X``) that is past
                                                          every applying record and covered by no given
                                                          malicious or vulnerable record (final releases
                                                          first, D-063); otherwise abstain
    the same families, only undetermined               -> investigate
7.  name similar to a popular package                  -> investigate
8.  unknown                                            -> abstain
9.  withdrawn report only                              -> keep
10. no evidence                                        -> keep
11. anything else                                      -> abstain

Every action carries the structured claims Agent 5 can check, citing only evidence IDs
from the packet. The nonexistent "replace if a pair source names a target" branch is not
active: no approved table names a target for a name that no record mentions (D-062).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from multi_agentic_security.contracts.evidence import EvidenceRecord, LabelFamily, VersionScope
from multi_agentic_security.contracts.pipeline import Claim, Finding, PackageRef, Reason, Target
from multi_agentic_security.versioning import evidence_ranges

from .packet import Packet

RULES_VERSION = "r0/0.1"
ACT_ON = frozenset({"all_versions", "affected", "likely_affected", "possible"})
RISK_FAMILIES = (LabelFamily.MALICIOUS, LabelFamily.WITHDRAWN, LabelFamily.TYPOSQUAT, LabelFamily.VULNERABLE)


@dataclass
class Decision:
    action: str
    target: Optional[Target] = None
    claims: list[Claim] = field(default_factory=list)
    reasons: list[Reason] = field(default_factory=list)
    rationale: Optional[str] = None
    uncertainty: Optional[str] = None


def _r(rule_id: str, outcome: str, explanation: str, evidence_ids=None, **inputs: Any) -> Reason:
    return Reason(rule_id=rule_id, outcome=outcome, explanation=explanation, inputs=inputs,
                  evidence_ids=list(evidence_ids or []))


def _by_kind(p: Packet) -> dict[str, Finding]:
    out: dict[str, Finding] = {}
    for f in p.assessment.findings:
        out.setdefault(f.finding, f)
    return out


def _cited(f: Finding, given: dict[str, EvidenceRecord]) -> tuple[list[str], list[str]]:
    """(IDs of the finding that are in the packet, IDs that are not)."""
    have = [e for e in f.evidence_ids if e in given]
    return have, [e for e in f.evidence_ids if e not in given]


def _missing(kind: str, missing: list[str]) -> Decision:
    return Decision("abstain", reasons=[_r(f"a4.r0.{kind}.evidence_not_given", "abstain",
                                           f"Agent 3 reports {kind}, but {len(missing)} of the records it cites were "
                                           "not given to the recommender (store missing, different or after the "
                                           "cut-off), so no supported claim can be made.", missing)],
                    rationale=f"{kind} reported, but the evidence could not be given; no recommendation.")


def decide(p: Packet) -> Decision:
    dep = p.dependency
    if dep.package is None:
        return Decision("abstain", reasons=[_r("a4.r0.no_package", "abstain",
                                               "Agent 1 could not determine a package, so there is nothing to "
                                               "recommend about.")],
                        rationale="The package could not be determined.")
    if p.assessment is None:
        return Decision("abstain", reasons=[_r("a4.r0.no_assessment", "abstain",
                                               "Agent 3 produced no assessment for this dependency.")],
                        rationale="No risk assessment is available.")
    pkg = dep.package
    F = _by_kind(p)
    given = p.given()

    # 2. typosquat
    if "typosquat_listed" in F:
        f = F["typosquat_listed"]
        have, missing = _cited(f, given)
        if missing:
            return _missing("typosquat_listed", missing)
        targets = sorted({given[e].target_name_normalized for e in have})
        claims = [Claim(type="is_typosquat_of", subject=pkg, object=t,
                        evidence_ids=sorted(e for e in have if given[e].target_name_normalized == t))
                  for t in targets]
        mal = F.get("malicious_reported")
        if mal is not None:
            mhave, mmissing = _cited(mal, given)
            if not mmissing:
                claims.append(Claim(type="is_reported_malicious", subject=pkg, evidence_ids=mhave))
        if len(targets) == 1:
            raw = next(given[e].target_name_raw for e in have if given[e].target_name_normalized == targets[0])
            target = PackageRef.of(pkg.ecosystem, raw)
            # The imitated package's own records are in the packet (D-063): never replace with a package
            # that is itself reported malicious as a whole or listed as a typosquat.
            flagged = sorted(r.evidence_id for r in p.evidence
                             if (r.ecosystem, r.name_normalized) == (target.ecosystem, target.name_normalized)
                             and ((r.family is LabelFamily.MALICIOUS and r.version_scope is VersionScope.ALL)
                                  or r.family is LabelFamily.TYPOSQUAT))
            if flagged:
                return Decision("remove", claims=claims,
                                reasons=[_r("a4.r0.typosquat.target_flagged_remove", "remove",
                                            f"{pkg.name_normalized} is listed as imitating {target.name_normalized}, "
                                            "but that package is itself reported malicious or listed as a typosquat; "
                                            "R0 removes instead of replacing.", have + flagged,
                                            imitated=target.name_normalized, target_records=flagged)],
                                rationale=f"{pkg.name_normalized} is a listed typosquat; the imitated package is "
                                          "itself flagged.")
            return Decision("replace", target=Target(package=target), claims=claims,
                            reasons=[_r("a4.r0.typosquat.replace", "replace",
                                        f"Typosquat list(s) name {pkg.name_normalized} as imitating "
                                        f"{target.name_normalized}; R0 replaces it with the imitated package.",
                                        have, imitated=target.name_normalized)],
                            rationale=f"{pkg.name_normalized} is listed as a typosquat of {target.name_normalized}.",
                            uncertainty="No target version is stated; the version a fresh install receives is "
                                        "checked by the verifier.")
        return Decision("remove", claims=claims,
                        reasons=[_r("a4.r0.typosquat.several_targets_remove", "remove",
                                    f"Typosquat lists name {pkg.name_normalized} as imitating several packages "
                                    f"({', '.join(targets)}); the intended package is not clear, so R0 removes it.",
                                    have, imitated=targets)],
                        rationale=f"{pkg.name_normalized} is listed as a typosquat of {', '.join(targets)}.")

    # 3. reported malicious (whole package)
    if "malicious_reported" in F:
        f = F["malicious_reported"]
        have, missing = _cited(f, given)
        if missing:
            return _missing("malicious_reported", missing)
        return Decision("remove", claims=[Claim(type="is_reported_malicious", subject=pkg, evidence_ids=have)],
                        reasons=[_r("a4.r0.malicious.remove", "remove",
                                    f"{len(have)} report(s) name the whole package {pkg.name_normalized} as "
                                    "malicious; R0 removes it.", have)],
                        rationale=f"{pkg.name_normalized} is reported malicious.")

    # 4. registry security hold
    if "registry_security_hold" in F:
        return Decision("remove", reasons=[_r("a4.r0.security_hold.remove", "remove",
                                              "npm replaced this package with a security holding package; the "
                                              "original cannot be installed, so R0 removes it. No claim type "
                                              "exists for a security hold; the verifier re-reads the registry.")],
                        rationale=f"npm removed {pkg.name_normalized} for security reasons.")

    # 5. nonexistent
    if "nonexistent" in F:
        return Decision("remove", claims=[Claim(type="is_nonexistent", subject=pkg)],
                        reasons=[_r("a4.r0.nonexistent.remove", "remove",
                                    f"The registry has no package {pkg.name_normalized} and no evidence record names "
                                    "it; R0 removes it. No pair source names a replacement for such a name.")],
                        rationale=f"{pkg.name_normalized} does not exist in the registry.")

    # 6. version-scoped families
    scoped = [F[k] for k in ("compromised_version", "vulnerable") if k in F]
    if scoped:
        return _version_rule(p, scoped, given)

    # 7. similarity
    if "name_similar_to_popular" in F:
        f = F["name_similar_to_popular"]
        similar = list(f.detail.get("similar_to") or [])
        return Decision("investigate", reasons=[_r("a4.r0.similar_name.investigate", "investigate",
                                                   f"The name is one edit away from popular package(s) "
                                                   f"{', '.join(similar[:5])}. This is a signal, not evidence of "
                                                   "a risk; R0 asks for a check that the intended package is used.",
                                                   f.evidence_ids, similar_to=similar[:5])],
                        rationale=f"Check that {pkg.name_normalized} is the intended package "
                                  f"(similar to {', '.join(similar[:3])}).")

    # 8. unknown
    if "unknown" in F:
        why = F["unknown"].detail
        return Decision("abstain", reasons=[_r("a4.r0.unknown.abstain", "abstain",
                                               "Agent 3 could not establish the package's state (" +
                                               ", ".join(f"{k}: {v}" for k, v in why.items()) + "); R0 does not "
                                               "recommend without it.", **{"unknown": why})],
                        rationale="The package's state could not be established.")

    # 9. withdrawn only
    if "withdrawn_only" in F:
        f = F["withdrawn_only"]
        have, missing = _cited(f, given)
        if missing:
            return _missing("withdrawn_only", missing)
        return Decision("keep", claims=[Claim(type="report_withdrawn", subject=pkg, evidence_ids=have)],
                        reasons=[_r("a4.r0.withdrawn.keep", "keep",
                                    "Only withdrawn (retracted) reports name this package; a withdrawn report is not "
                                    "a finding against it, so R0 keeps it.", have)],
                        rationale="The only reports about this package were withdrawn.")

    # 10. no evidence
    if "no_evidence" in F:
        if not p.evidence_usable:
            # Without the store Agent 2 used, R0 cannot show that no record names the package (D-063).
            return Decision("keep", reasons=[_r("a4.r0.no_evidence.keep_unverified", "keep",
                                                "Agent 3 found no applying evidence, but the recommender was given no "
                                                "usable evidence store, so it makes no claim about the absence of "
                                                "records; R0 keeps the package.")],
                            rationale="No applying evidence was reported; this is not a safety statement.")
        # Agent 3's no_evidence means "no record covers this version"; the claim no_evidence_found means
        # "no risk record names the package". The claim is made only when both hold (D-062).
        other = sorted(r.evidence_id for r in p.evidence if r.family in RISK_FAMILIES and
                       (r.ecosystem, r.name_normalized) == (pkg.ecosystem, pkg.name_normalized))
        if other:
            return Decision("keep", reasons=[_r("a4.r0.no_evidence.keep_other_versions", "keep",
                                                f"{len(other)} risk record(s) name this package, but none covers the "
                                                "version that would be installed; R0 keeps it. No claim is made, "
                                                "because records about the package exist.", other)],
                            rationale="Reports exist for other versions only; this is not a safety statement.",
                            uncertainty="An older or locked installation may still hold a reported version.")
        return Decision("keep", claims=[Claim(type="no_evidence_found", subject=pkg)],
                        reasons=[_r("a4.r0.no_evidence.keep", "keep",
                                    "No evidence record applies to this package and version; R0 keeps it. This is "
                                    "not a statement that it is safe.")],
                        rationale="No evidence applies; this is not a safety statement.")

    return Decision("abstain", reasons=[_r("a4.r0.no_rule", "abstain",
                                           "No R0 rule applies to the findings ("
                                           + (", ".join(p.finding_names()) or "none") + ").",
                                           findings=p.finding_names())],
                    rationale="No rule applies.")


# --------------------------------------------------------------------------- version rule

def _version_claims(pkg: PackageRef, f: Finding, have: list[str]) -> Claim:
    kind = "is_compromised_version" if f.finding == "compromised_version" else "is_vulnerable"
    declared = f.detail.get("declared") or {}
    obj = declared.get("exact") if f.detail.get("applicability") == "affected" else None
    return Claim(type=kind, subject=pkg, object=obj, evidence_ids=have)


def _version_rule(p: Packet, scoped: list[Finding], given: dict[str, EvidenceRecord]) -> Decision:
    pkg = p.dependency.package
    for f in scoped:
        _, missing = _cited(f, given)
        if missing:
            return _missing(f.finding, missing)
    acting = [f for f in scoped if f.detail.get("applicability") in ACT_ON]
    all_ids = sorted({e for f in scoped for e in f.evidence_ids})
    if not acting:
        return Decision("investigate", reasons=[_r("a4.r0.version.undetermined_investigate", "investigate",
                                                   "Records of " + " and ".join(f.finding for f in scoped) +
                                                   " exist, but whether they cover the installed version could not "
                                                   "be decided; R0 asks for a check of the installed version.",
                                                   all_ids, findings=[f.finding for f in scoped])],
                        rationale="Reports exist; whether they cover the installed version is undetermined.",
                        uncertainty="The installed version could not be determined.")
    claims = [_version_claims(pkg, f, list(f.evidence_ids)) for f in acting]
    applying_ids = sorted({e for f in acting for e in f.evidence_ids})
    version, info = pick_version(p, [given[e] for e in applying_ids])
    if version is None:
        return Decision("abstain", claims=claims,
                        reasons=[_r("a4.r0.version.no_target", "abstain",
                                    "The applying records do not name a version that is past every one of them, "
                                    f"covered by no known record and released: {info['why']}", applying_ids,
                                    **info)],
                        rationale="Affected, but the evidence names no usable fixed version.")
    vul = next((f for f in acting if f.finding == "vulnerable"), None)
    if vul is not None:
        claims.append(Claim(type="fixed_in", subject=pkg, object=version, evidence_ids=list(vul.evidence_ids)))
    current = next((f.detail.get("declared", {}).get("exact") for f in acting
                    if (f.detail.get("declared") or {}).get("kind") == "exact"), None)
    applic = sorted({f.detail.get("applicability") for f in acting})
    # Always an upgrade: the target is past every applying record, which covers the installed version
    # (D-063; no source names an earlier safe version, so R0 never downgrades).
    return Decision("upgrade", target=Target(package=pkg, version=version), claims=claims,
                    reasons=[_r("a4.r0.version.upgrade", "upgrade",
                                f"{' and '.join(f.finding for f in acting)} ({', '.join(applic)}): R0 recommends "
                                f"{version}, " + (f"the lowest final release above the stated fix {info['stated_fix']} "
                                                  "that clears every record (the stated fix is not released, yanked "
                                                  "or itself covered)" if info.get("next_release")
                                                  else "the lowest version a record states as fixed") +
                                ", past every applying record, covered by no known record and listed in the "
                                "registry.", applying_ids, target_version=version, current_version=current, **info)],
                    rationale=f"Move to {version}, the lowest released fixed version clear of every known record.",
                    uncertainty=None if applic == ["affected"] else
                    "The installed version is inferred from the constraint, not pinned.")


def _is_pre(eco: str, v) -> bool:
    return bool(v.is_prerelease) if eco == "pypi" else bool(getattr(v, "prerelease", None))


def _is_local(eco: str, v) -> bool:
    """PyPI local versions (``1.5+cpu``) are builds, not releases to recommend (D-063)."""
    return eco == "pypi" and v.local is not None


def pick_version(p: Packet, applying: list[EvidenceRecord]) -> tuple[Optional[str], dict]:
    """The lowest registry release at or above a stated fixed version (``<X`` of any given range
    record) that is past every applying record and covered by no given malicious or vulnerable record.
    Final releases are preferred; local versions and (without a cut-off) yanked releases are skipped.
    Without a registry version list there is no target (D-063)."""
    eco = p.dependency.package.ecosystem
    parse = evidence_ranges.parser(eco)
    bad = [r for r in p.evidence if r.family in (LabelFamily.MALICIOUS, LabelFamily.VULNERABLE)
           and r.version_scope is not VersionScope.ALL]
    candidates: set[str] = set()
    for r in bad:
        if r.version_scope is VersionScope.RANGE and evidence_ranges.comparators(eco, r.version_range) is not None:
            for tok in r.version_range.replace("||", ",").split(","):
                tok = tok.strip()
                if tok.startswith("<") and not tok.startswith("<="):
                    v = tok[1:].strip()
                    if parse(v) is not None:
                        candidates.add(v)
    info: dict[str, Any] = {"candidates": sorted(candidates, key=parse), "registry_checked": False}
    if not candidates:
        info["why"] = "no record states a fixed version (only listed versions or open ranges)."
        return None, info

    def not_past(v: str) -> Optional[str]:
        pv = parse(v)
        for r in applying:
            if r.version_scope is VersionScope.LISTED:
                pl = parse(r.version)
                if pl is None:
                    return f"listed version {r.version!r} cannot be read"
                if not pv > pl:
                    return f"not newer than the listed version {r.version}"
            elif evidence_ranges.above(eco, v, r.version_range) is not True:
                return f"not past the range {r.version_range}"
        return None

    def covered(v: str) -> Optional[str]:
        pv = parse(v)
        for r in bad:
            if r.version_scope is VersionScope.LISTED:
                pl = parse(r.version)
                cov = None if pl is None else pl == pv
            else:
                cov = evidence_ranges.in_range(eco, v, r.version_range)
            if cov is None:
                return f"record {r.evidence_id} cannot be read"
            if cov:
                return f"covered by {r.evidence_id}"
        return None

    reg = p.registry
    if reg is None or reg.status != "found" or reg.versions is None:
        # A target R0 cannot confirm as a release is not recommended (D-063).
        info["why"] = "the registry version list is not available, so no release can be confirmed."
        return None, info
    yanked = set() if p.cutoff is not None else set((reg.metadata or {}).get("yanked_versions") or [])
    releases = sorted(((pv, v) for pv, v in ((parse(v), v) for v in reg.versions)
                       if pv is not None and v not in yanked and not _is_local(eco, pv)), key=lambda x: x[0])
    info["registry_checked"] = True
    rejected: dict[str, str] = {}
    for c in sorted(candidates, key=parse):
        pc = parse(c)
        why = not_past(c)
        if why is not None:
            rejected[c] = why
            continue
        # Final releases at or above the stated fix first; the stated pre-release itself only when no
        # final release clears every record (D-063).
        pool = [(pv, v) for pv, v in releases if pv >= pc and not _is_pre(eco, pv)]
        if _is_pre(eco, pc):
            pool += [(pv, v) for pv, v in releases if pv == pc]
        for pv, v in pool:
            if not_past(v) is None and covered(v) is None:
                info.update(rejected=rejected, stated_fix=c, next_release=pv != pc)
                return v, info
        rejected[c] = (covered(c) or "not released") + "; no final release at or above it clears every record" +             (" before the cut-off" if p.cutoff is not None else " (yanked releases skipped)")
    info["rejected"] = rejected
    info["why"] = "every stated fixed version was rejected (" + "; ".join(f"{k}: {v}" for k, v in rejected.items()) + ")."
    return None, info
