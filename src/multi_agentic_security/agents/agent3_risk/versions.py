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
(cannot be decided), ``allowed_not_resolved`` (only older allowed versions are
covered; the version that would be installed is not), ``not_affected`` (exact or
every allowed version outside the claim). The last two give no finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from multi_agentic_security.contracts.evidence import EvidenceRecord, VersionScope
from multi_agentic_security.contracts.pipeline import DependencyRecord, RegistryVerification

from . import npm_semver

APPLICABILITY_ORDER = ("all_versions", "affected", "likely_affected", "possible", "undetermined",
                       "allowed_not_resolved", "not_affected")
APPLIES = frozenset(APPLICABILITY_ORDER[:5])          # the last two yield no finding, only a reason
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

    def to_dict(self) -> dict:
        return {"kind": self.kind, "exact": self.exact, "resolved": self.resolved, "constraint": self.spec,
                "allowed_versions": len(self.candidates) if self.candidates is not None else None,
                "note": self.note or None}


def _resolve_pypi(candidates: list[str], yanked: set[str]) -> Optional[str]:
    finals = [(_pv(v), v) for v in candidates if v not in yanked]
    finals = [(p, v) for p, v in finals if p is not None]
    stable = [(p, v) for p, v in finals if not p.is_prerelease]
    pool = stable or finals
    return max(pool)[1] if pool else None


def declared_version(dep: DependencyRecord, reg: Optional[RegistryVerification]) -> Declared:
    d = _declared(dep, reg)
    versions = tuple(reg.versions) if reg is not None and reg.status == "found" and reg.versions is not None else None
    return Declared(d.kind, d.ecosystem, d.exact, d.candidates, d.resolved, d.note, d.spec, versions)


def _resolve_npm(candidates: list[str], latest: Optional[str]) -> Optional[str]:
    if latest is not None and latest in candidates:
        return latest
    parsed = [(npm_semver.parse_version(v), v) for v in candidates]
    finals = [(p, v) for p, v in parsed if p is not None and not p.prerelease]
    pool = finals or [(p, v) for p, v in parsed if p is not None]
    return max(pool, key=lambda pv: pv[0])[1] if pool else None


def _declared(dep: DependencyRecord, reg: Optional[RegistryVerification]) -> Declared:
    eco = dep.ecosystem
    raw = (dep.version_constraint_normalized or "").strip()
    versions = list(reg.versions) if reg is not None and reg.status == "found" and reg.versions is not None else None
    yanked = set((reg.metadata or {}).get("yanked_versions") or []) if reg is not None else set()
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
            return Declared("constraint" if raw else "any", eco, spec=raw or None,
                            note="no registry version list, so the allowed versions are unknown")
        allowed = [v for v in versions if _pv(v) is not None and spec.contains(_pv(v), prereleases=True)]
        return Declared("constraint" if raw else "any", eco, candidates=tuple(allowed),
                        resolved=_resolve_pypi(allowed, yanked), spec=raw or None)
    if eco == "npm":
        if _NPM_EXACT.match(raw):
            return Declared("exact", eco, exact=raw, spec=raw)
        latest = reg.latest_version if reg is not None and reg.status == "found" else None
        rng = "*" if raw.lower() in _NPM_LATEST else raw
        if npm_semver.satisfies("0.0.0", rng) is None:
            return Declared("unknown", eco, spec=raw or None,
                            note="npm specifier is not a version range (tag, URL or alias); installed version undetermined")
        kind = "any" if rng == "*" else "constraint"
        if versions is None:
            return Declared(kind, eco, spec=raw or None, note="no registry version list, so the allowed versions are unknown")
        allowed = [v for v in versions if npm_semver.satisfies(v, rng)]
        return Declared(kind, eco, candidates=tuple(allowed), resolved=_resolve_npm(allowed, latest), spec=raw or None)
    return Declared("unknown", eco, note="no ecosystem")


def _same(eco: str, a: str, b: str) -> bool:
    if eco == "pypi":
        pa, pb = _pv(a), _pv(b)
        return pa == pb if pa is not None and pb is not None else a == b
    return a.lstrip("v=") == b.lstrip("v=")


def _in_range(eco: str, version: str, rng: str) -> Optional[bool]:
    if eco == "npm":
        return npm_semver.satisfies(version, rng)
    if eco != "pypi":
        return None
    p = _pv(version)
    try:
        spec = SpecifierSet(rng)
    except InvalidSpecifier:
        return None
    return None if p is None else spec.contains(p, prereleases=True)


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
    if d.candidates is not None and not d.candidates:
        return "undetermined"            # no allowed version known (none listed, or none before the cut-off)
    if rec.version_scope is VersionScope.LISTED and d.registry_versions is not None and not any(
            _same(eco, v, rec.version) for v in d.registry_versions):
        # The reported version is not in the registry list: registries delete malicious releases,
        # so its absence says nothing about whether it was installable (review M1).
        return "undetermined"
    resolved_covered = covers(d.resolved) if d.resolved is not None else None
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
