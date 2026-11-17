"""Version applicability for Agent 3 v2 (D-055).

Decides, for one dependency and one evidence record, whether the record's claim
covers the version that would be installed. Nothing is installed or resolved
against a live index: the decision uses the declared constraint (Agent 1) and
the version list the registry reported (Agent 2, already limited to the
cut-off).

Declared version:
* ``exact``  - PyPI ``==X`` (no wildcard) or ``===X``; npm exact semantic version
  (package.json pin, lockfile entry, ``npm i x@1.2.3``).
* ``constraint`` - any other PyPI specifier set; the candidates are the
  registry versions it allows, and the *resolved* version is the highest
  non-yanked final release among them (pip's default choice, ignoring other
  constraints of the environment). npm ranges are read with ``npm_semver``
  (D-056); the resolved version is the ``latest`` tag when the range allows it,
  otherwise the highest allowed final release (npm's default choice).
* ``any`` - no constraint (PyPI); resolved like a constraint that allows all.
* ``unknown`` - nothing usable.

Applicability of one record (ordered from strongest to weakest):
``all_versions`` (claim covers the whole package), ``affected`` (exact version
covered), ``likely_affected`` (resolved version covered), ``possible`` (some
allowed version covered and the resolved version unknown), ``undetermined``
(cannot be decided), ``allowed_not_resolved`` (only other allowed versions are
covered; the version that would be installed is not), ``removed_from_registry``
(the reported release is allowed but no longer in the registry, so a new install
cannot receive it; only without a cut-off, D-057), ``not_affected`` (exact or
every allowed version outside the claim, or the constraint excludes the reported
version). The last three give no finding, only a reason.

Under a cut-off the registry's yanked list is ignored: it is the state at
retrieval time, and a release yanked later was installable at the cut-off (D-057).
"""

from __future__ import annotations

import dataclasses

import re
from dataclasses import dataclass, field
from typing import Optional

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from multi_agentic_security.contracts.evidence import EvidenceRecord, VersionScope
from multi_agentic_security.contracts.pipeline import DependencyRecord, RegistryVerification

from multi_agentic_security.versioning import evidence_ranges, npm_semver

APPLICABILITY_ORDER = ("all_versions", "affected", "likely_affected", "possible", "undetermined",
                       "allowed_not_resolved", "removed_from_registry", "not_affected")
APPLIES = frozenset(APPLICABILITY_ORDER[:5])          # the last three yield no finding, only a reason
_NPM_EXACT = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$")
_NPM_LATEST = frozenset({"", "*", "latest", "x"})


def strongest(values) -> Optional[str]:
    vals = [v for v in values if v in APPLICABILITY_ORDER]
    return min(vals, key=APPLICABILITY_ORDER.index) if vals else None


def _pv(text: str) -> Optional[Version]:
    try:
        return Version(text)
    except (InvalidVersion, TypeError):
        return None


@dataclass(frozen=True)
class Declared:
    kind: str                                   # exact | constraint | any | unknown
    ecosystem: Optional[str]
    exact: Optional[str] = None
    candidates: Optional[tuple[str, ...]] = None  # registry versions the declaration allows
    resolved: Optional[str] = None
    note: str = ""
    spec: Optional[str] = None
    registry_versions: Optional[tuple[str, ...]] = None   # every version the registry reported (after the cut-off filter)
    allow_spec: Optional[str] = None    # the constraint as read (PEP 440 set or npm range); None when not readable
    cutoff_set: bool = False
    resolved_if_yanked: Optional[str] = None  # under a cut-off: the choice if today's yanked list applied (D-058)
    npm_latest: Optional[str] = None    # npm dist-tags.latest, when known
    latest_tag_rule: bool = False       # npm "*", "" or "latest": the latest tag is installed (D-058, D-060)

    def allows(self, version: str) -> Optional[bool]:
        """Whether the declared constraint itself admits ``version`` (None: cannot be decided)."""
        if self.kind == "exact" and self.exact:
            return _same(self.ecosystem, self.exact, version)
        if self.kind not in ("constraint", "any") or self.allow_spec is None:
            return None
        if self.ecosystem == "npm":
            if self.latest_tag_rule:
                # npm installs dist-tags.latest for "*", "" and "latest" even when it is a pre-release
                # (D-058); other pre-releases are not chosen, so they are left undecided. "x" is an
                # ordinary range (D-060).
                pv = npm_semver.parse_version(version)
                if pv is not None and pv.prerelease:
                    # A known final 'latest' tag excludes every other pre-release (D-061).
                    return (version == self.npm_latest) if self.npm_latest is not None else None
            return npm_semver.satisfies(version, self.allow_spec)
        p = _pv(version)
        if p is None:
            return None
        try:
            return SpecifierSet(self.allow_spec).contains(p, prereleases=True)
        except InvalidSpecifier:
            return None

    def to_dict(self) -> dict:
        return {"kind": self.kind, "exact": self.exact, "resolved": self.resolved, "constraint": self.spec,
                "allowed_versions": len(self.candidates) if self.candidates is not None else None,
                "note": self.note or None}


def _resolve_pypi(candidates: list[str], yanked: set[str], spec: SpecifierSet) -> Optional[str]:
    """pip's default choice (D-057): pre-releases only when the specifier names one or no final
    release is allowed (packaging's filter rule); a non-yanked release before a yanked one, but a
    yanked release when it is the only one allowed (PEP 592; pip installs it with a warning)."""
    parsed = [(p, v) for p, v in ((_pv(v), v) for v in candidates) if p is not None]
    finals = [(p, v) for p, v in parsed if not p.is_prerelease]
    pool = parsed if spec.prereleases else (finals or parsed)
    kept = [(p, v) for p, v in pool if v not in yanked]
    pick = kept or pool
    return max(pick)[1] if pick else None


def declared_version(dep: DependencyRecord, reg: Optional[RegistryVerification], *,
                     cutoff_set: bool = False) -> Declared:
    d = _declared(dep, reg, cutoff_set)
    versions = tuple(reg.versions) if reg is not None and reg.status == "found" and reg.versions is not None else None
    return dataclasses.replace(d, registry_versions=versions, cutoff_set=cutoff_set)


def _resolve_npm(candidates: list[str], latest: Optional[str]) -> Optional[str]:
    if latest is not None and latest in candidates:
        return latest
    parsed = [(npm_semver.parse_version(v), v) for v in candidates]
    finals = [(p, v) for p, v in parsed if p is not None and not p.prerelease]
    pool = finals or [(p, v) for p, v in parsed if p is not None]
    return max(pool, key=lambda pv: pv[0])[1] if pool else None


def _declared(dep: DependencyRecord, reg: Optional[RegistryVerification], cutoff_set: bool = False) -> Declared:
    eco = dep.ecosystem
    raw = (dep.version_constraint_normalized or "").strip()
    versions = list(reg.versions) if reg is not None and reg.status == "found" and reg.versions is not None else None
    # Yanked state is from retrieval time; under a cut-off it says nothing about the cut-off (D-057).
    yanked_now = set((reg.metadata or {}).get("yanked_versions") or []) if reg is not None else set()
    yanked = yanked_now if not cutoff_set else set()
    if eco == "pypi":
        if raw.startswith("===") and "," not in raw:
            return Declared("exact", eco, exact=raw[3:].strip(), spec=raw)
        if raw:
            try:
                spec = SpecifierSet(raw)
            except InvalidSpecifier:
                return Declared("unknown", eco, note="constraint is not a valid PEP 440 specifier", spec=raw)
            specs = list(spec)
            if len(specs) == 1 and specs[0].operator == "==" and "*" not in specs[0].version:
                return Declared("exact", eco, exact=specs[0].version, spec=raw)
        else:
            spec = SpecifierSet("")
        if versions is None:
            return Declared("constraint" if raw else "any", eco, spec=raw or None, allow_spec=str(spec),
                            note="no registry version list, so the allowed versions are unknown")
        allowed = [v for v in versions if _pv(v) is not None and spec.contains(_pv(v), prereleases=True)]
        resolved = _resolve_pypi(allowed, yanked, spec)
        # Under a cut-off the yanked list is today's; a yank before the cut-off would change the
        # choice. Both choices are kept, and applicability is undetermined when they disagree (D-058).
        alt = _resolve_pypi(allowed, yanked_now, spec) if cutoff_set and yanked_now else None
        return Declared("constraint" if raw else "any", eco, candidates=tuple(allowed), resolved=resolved,
                        spec=raw or None, allow_spec=str(spec), resolved_if_yanked=alt if alt != resolved else None)
    if eco == "npm":
        if _NPM_EXACT.match(raw):
            return Declared("exact", eco, exact=raw, spec=raw)
        latest = reg.latest_version if reg is not None and reg.status == "found" else None
        rng = "*" if raw.lower() in _NPM_LATEST else raw
        star = raw.lower() in ("", "*", "latest")
        if npm_semver.satisfies("0.0.0", rng) is None:
            return Declared("unknown", eco, spec=raw or None,
                            note="npm specifier is not a version range (tag, URL or alias); installed version undetermined")
        kind = "any" if rng == "*" else "constraint"
        if versions is None:
            return Declared(kind, eco, spec=raw or None, allow_spec=rng, npm_latest=latest, latest_tag_rule=star,
                            note="no registry version list, so the allowed versions are unknown")
        allowed = [v for v in versions if npm_semver.satisfies(v, rng)]
        latest_pv = npm_semver.parse_version(latest) if latest is not None else None
        if star and latest_pv is not None and latest_pv.prerelease and latest in versions \
                and latest not in allowed:
            allowed.append(latest)   # npm picks a pre-release 'latest' tag for "*" (D-058)
        return Declared(kind, eco, candidates=tuple(allowed), resolved=_resolve_npm(allowed, latest), spec=raw or None,
                        allow_spec=rng, npm_latest=latest, latest_tag_rule=star)
    return Declared("unknown", eco, note="no ecosystem")


def _same(eco: str, a: str, b: str) -> bool:
    if eco == "pypi":
        pa, pb = _pv(a), _pv(b)
        return pa == pb if pa is not None and pb is not None else a == b
    return a.lstrip("v=") == b.lstrip("v=")


def _in_range(eco: str, version: str, rng: str) -> Optional[bool]:
    if eco == "npm":
        return npm_semver.satisfies_evidence_range(version, rng)
    if eco != "pypi":
        return None
    # An ordered interval, not a PEP 440 specifier: "<2.0" covers 2.0rc1 in OSV order (D-060).
    return evidence_ranges.in_range("pypi", version, rng)


def applicability(rec: EvidenceRecord, d: Declared) -> str:
    if rec.version_scope is VersionScope.ALL:
        return "all_versions"
    eco = rec.ecosystem

    def covers(v: str) -> Optional[bool]:
        if rec.version_scope is VersionScope.LISTED:
            return _same(eco, v, rec.version)
        return _in_range(eco, v, rec.version_range)

    if d.kind == "exact" and d.exact:
        c = covers(d.exact)
        return "undetermined" if c is None else ("affected" if c else "not_affected")
    if rec.version_scope is VersionScope.LISTED and d.allows(rec.version) is False:
        return "not_affected"            # the constraint itself excludes the reported version (D-057)
    if rec.version_scope is VersionScope.LISTED and d.allows(rec.version) is None and \
            d.registry_versions is not None and any(_same(eco, v, rec.version) for v in d.registry_versions):
        return "undetermined"            # listed and installable, but whether it is chosen is unknown (D-060)
    if d.candidates is not None and not d.candidates:
        return "undetermined"            # no allowed version known (none listed, or none before the cut-off)
    if rec.version_scope is VersionScope.LISTED and d.registry_versions is not None and not any(
            _same(eco, v, rec.version) for v in d.registry_versions):
        # The reported version is allowed but not in the registry list: registries delete malicious
        # releases. Under a cut-off it may have been installable (and the newest) then (review M1);
        # without one, a new install cannot receive it (D-057). Unreadable: undetermined.
        if d.cutoff_set or d.allows(rec.version) is None:
            return "undetermined"
        return "removed_from_registry"
    resolved_covered = covers(d.resolved) if d.resolved is not None else None
    if d.resolved_if_yanked is not None and covers(d.resolved_if_yanked) != resolved_covered:
        return "undetermined"            # the answer depends on when releases were yanked (D-058)
    if resolved_covered:
        return "likely_affected"
    if d.candidates is not None:
        hits = [covers(v) for v in d.candidates]
        if any(h is None for h in hits):
            return "undetermined"
        if any(hits):
            # The installed (highest allowed) version is known and not covered: only older allowed
            # versions are. No finding, but the reason keeps this visible (RUN-002).
            return "allowed_not_resolved" if resolved_covered is False else "possible"
        return "not_affected"
    return "undetermined"


@dataclass
class RecordView:
    record: EvidenceRecord
    applicability: str
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        r = self.record
        return {"evidence_id": r.evidence_id, "source": r.provenance.source_dataset,
                "source_record_id": r.provenance.source_record_id, "scope": r.version_scope.value,
                "version": r.version, "version_range": r.version_range,
                "published": r.published.isoformat() if r.published else None,
                "applicability": self.applicability, **self.extra}


def fixed_bounds(ranges: list[str]) -> list[str]:
    """Upper bounds ``<X`` of affected PyPI ranges: the versions an advisory names as fixed."""
    out = set()
    for rng in ranges:
        try:
            for s in SpecifierSet(rng):
                if s.operator == "<" and _pv(s.version) is not None:
                    out.add(s.version)
        except InvalidSpecifier:
            continue
    return sorted(out, key=lambda v: _pv(v))
