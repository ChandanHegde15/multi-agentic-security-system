"""Version logic of Agent 5, written for the verifier and not taken from Agent 3 (D-059).

Agent 5 must not trust Agent 3's applicability, so it decides version questions
itself from the evidence records and the registry facts. Only the npm range
grammar is shared, through the neutral ``multi_agentic_security.versioning``
package; every decision rule here is Agent 5's own:

* ``covers(record, version)``: whether an evidence record covers one version
  (whole package, the listed version, or the affected range). ``None`` means
  "cannot be decided" and is never read as "not covered".
* ``TargetFacts``: one registry lookup of a recommended target, with the cut-off
  applied (only versions uploaded before the cut-off; ``latest`` and the yanked
  list are withheld under a cut-off because they describe the retrieval time).
* ``installed(dep, reg)``: the version a fresh install of a declared dependency
  receives (pip and npm default choice), from Agent 2's registry facts.
* ``exposure(record, inst)``: whether that install is covered by a record, with
  the rules of D-057 and D-058: a constraint that excludes a listed version is
  not exposed; a listed version missing from the registry is ``removed`` without
  a cut-off and ``unknown`` with one; otherwise the resolved version decides,
  and it is ``unknown`` when today's yanked list would change the choice under a
  cut-off. npm ``*`` (and ``""``, ``latest``) installs the ``latest`` tag even
  when it is a pre-release.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from multi_agentic_security.contracts.evidence import EvidenceRecord, VersionScope
from multi_agentic_security.contracts.pipeline import DependencyRecord, RegistryVerification
from multi_agentic_security.versioning import evidence_ranges, npm_semver

_NPM_EXACT = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$")
_NPM_ANY = frozenset({"", "*", "latest", "x", "X"})
_NPM_LATEST_TAG = frozenset({"", "*", "latest"})   # npm installs the 'latest' tag for these ("x" is a range)


def parse(eco: str, text: Optional[str]):
    """A comparable version, or None when the text is not a valid version of the ecosystem."""
    if not isinstance(text, str) or not text.strip():
        return None
    if eco == "pypi":
        try:
            return Version(text.strip())
        except InvalidVersion:
            return None
    if eco == "npm":
        return npm_semver.parse_version(text.strip())
    return None


def is_prerelease(eco: str, v) -> bool:
    return bool(v.is_prerelease) if eco == "pypi" else bool(v.prerelease)


def same(eco: str, a: str, b: str) -> bool:
    pa, pb = parse(eco, a), parse(eco, b)
    if pa is not None and pb is not None:
        return pa == pb
    return a.strip() == b.strip()


def covers(rec: EvidenceRecord, version: Optional[str]) -> Optional[bool]:
    """True/False when decidable; None when the version or the range cannot be read."""
    if rec.version_scope is VersionScope.ALL:
        return True
    if version is None:
        return None
    if rec.version_scope is VersionScope.LISTED:
        if parse(rec.ecosystem, version) is None:
            return None
        return same(rec.ecosystem, version, rec.version or "")
    rng = rec.version_range
    if not isinstance(rng, str):
        return None
    # OSV intervals in version order, pre-releases included (D-058, D-060).
    return evidence_ranges.in_range(rec.ecosystem, version, rng)


def fixed_by(rec: EvidenceRecord, version: str) -> Optional[bool]:
    """Whether ``version`` is past the versions a record covers (a fix, not merely outside them)."""
    if rec.version_scope is VersionScope.ALL:
        return False
    if rec.version_scope is VersionScope.LISTED:
        a, b = parse(rec.ecosystem, version), parse(rec.ecosystem, rec.version)
        return None if a is None or b is None else a > b
    if not isinstance(rec.version_range, str):
        return None
    return evidence_ranges.above(rec.ecosystem, version, rec.version_range)


def newer(eco: str, a: Optional[str], b: Optional[str]) -> Optional[bool]:
    pa, pb = parse(eco, a), parse(eco, b)
    return None if pa is None or pb is None else pa > pb


# --------------------------------------------------------------------------- targets

@dataclass(frozen=True)
class TargetFacts:
    state: str                       # found | not_found | security_placeholder | unavailable
    after_cutoff: bool = False       # the lookup describes a time after the cut-off
    versions: tuple[str, ...] = ()   # versions known at the cut-off (all versions without one)
    all_versions: tuple[str, ...] = ()
    upload_times: dict = field(default_factory=dict)
    latest: Optional[str] = None     # withheld under a cut-off
    yanked: frozenset = frozenset()  # withheld under a cut-off
    yanked_at_retrieval: frozenset = frozenset()   # always kept, to detect an ambiguous choice
    retrieved_at: Optional[datetime] = None
    note: str = ""


def target_facts(outcome, cutoff_dt: Optional[datetime]) -> TargetFacts:
    """``outcome`` is a registry ``LookupOutcome`` (or None: no data)."""
    if outcome is None:
        return TargetFacts("unavailable", note="the registry data has no record of this package")
    status = outcome.status
    after = cutoff_dt is not None and outcome.retrieved_at >= cutoff_dt
    if status in ("not_found", "security_placeholder"):
        return TargetFacts(status, after_cutoff=after, retrieved_at=outcome.retrieved_at)
    if status != "found":
        return TargetFacts("unavailable", retrieved_at=outcome.retrieved_at,
                           note=f"registry lookup ended with {status!r}: {outcome.error or ''}".strip())
    raw = tuple(outcome.versions or ())
    times = dict(outcome.upload_times or {})
    yanked_now = frozenset((outcome.metadata or {}).get("yanked_versions") or ())
    if cutoff_dt is None:
        known = raw
        latest = outcome.latest_version
        yanked = yanked_now
    else:
        known = tuple(v for v in raw if times.get(v) is not None and times[v] < cutoff_dt)
        latest, yanked = None, frozenset()
    return TargetFacts("found", after_cutoff=after, versions=known, all_versions=raw, upload_times=times,
                       latest=latest, yanked=yanked, yanked_at_retrieval=yanked_now,
                       retrieved_at=outcome.retrieved_at)


def default_choice(eco: str, candidates, *, latest: Optional[str] = None, yanked=frozenset(),
                   prereleases_named: bool = False) -> Optional[str]:
    """What a fresh install picks among ``candidates``.

    pip: the highest release; pre-releases only when the specifier names one or no
    final release is allowed; a yanked release only when nothing else is allowed
    (PEP 592). npm: the ``latest`` dist-tag when it is allowed, else the highest
    final release, else the highest pre-release."""
    parsed = [(p, v) for p, v in ((parse(eco, v), v) for v in candidates) if p is not None]
    if not parsed:
        return None
    if eco == "npm" and latest is not None and any(v == latest for _, v in parsed):
        return latest
    finals = [(p, v) for p, v in parsed if not is_prerelease(eco, p)]
    pool = parsed if (eco == "pypi" and prereleases_named) else (finals or parsed)
    if eco == "pypi":
        kept = [(p, v) for p, v in pool if v not in yanked]
        pool = kept or pool
    return max(pool, key=lambda pv: pv[0])[1]


def target_version(eco: str, facts: TargetFacts) -> Optional[str]:
    """The version a recommendation without a version would install."""
    if facts.state != "found":
        return None
    pick = default_choice(eco, facts.versions, latest=facts.latest, yanked=facts.yanked)
    if eco == "pypi" and facts.yanked_at_retrieval and facts.yanked != facts.yanked_at_retrieval:
        alt = default_choice(eco, facts.versions, yanked=facts.yanked_at_retrieval)
        if alt != pick:
            return None       # the choice depends on when releases were yanked (D-058)
    return pick


# --------------------------------------------------------------------------- the input dependency

@dataclass(frozen=True)
class Installed:
    kind: str                                   # exact | range | unknown
    ecosystem: Optional[str]
    version: Optional[str] = None               # the pin, or the resolved version of a range
    candidates: Optional[tuple[str, ...]] = None  # registry versions the constraint allows
    registry_versions: Optional[tuple[str, ...]] = None
    spec: Optional[str] = None                  # PEP 440 specifier set or npm range, as read
    cutoff_set: bool = False
    note: str = ""
    any_version: bool = False                   # npm "*", "" or "latest"
    npm_latest: Optional[str] = None
    version_if_yanked: Optional[str] = None     # under a cut-off: the choice with today's yanked list

    def allows(self, version: str) -> Optional[bool]:
        if self.kind == "exact" and self.version is not None:
            return same(self.ecosystem, self.version, version)
        if self.kind != "range" or self.spec is None:
            return None
        if self.ecosystem == "npm":
            pv = npm_semver.parse_version(version)
            if self.any_version and pv is not None and pv.prerelease:
                # A known 'latest' tag decides; without it (cut-off, no registry) it is undecided (D-061).
                return (version == self.npm_latest) if self.npm_latest is not None else None
            return npm_semver.satisfies(version, self.spec)
        p = parse("pypi", version)
        if p is None:
            return None
        try:
            return SpecifierSet(self.spec).contains(p, prereleases=True)
        except InvalidSpecifier:
            return None

    def to_dict(self) -> dict:
        return {"kind": self.kind, "version": self.version, "constraint": self.spec,
                "allowed_versions": None if self.candidates is None else len(self.candidates),
                "note": self.note or None}


def installed(dep: DependencyRecord, reg: Optional[RegistryVerification], *, cutoff_set: bool,
              cutoff_dt: Optional[datetime] = None) -> Installed:
    eco = dep.ecosystem
    raw = (dep.version_constraint_normalized or "").strip()
    reg_versions = (tuple(reg.versions) if reg is not None and reg.status == "found" and reg.versions is not None
                    else None)
    if reg_versions is not None and cutoff_dt is not None and reg.version_upload_times is not None:
        # Agent 2 already filters by upload time; filtering again keeps Agent 5 from trusting it (D-060).
        times = reg.version_upload_times
        reg_versions = tuple(v for v in reg_versions if times.get(v) is not None and times[v] < cutoff_dt)
    yanked_now = frozenset((reg.metadata or {}).get("yanked_versions") or ()) if reg is not None else frozenset()
    yanked = frozenset() if cutoff_set else yanked_now
    if eco == "pypi":
        if raw.startswith("===") and "," not in raw:
            return Installed("exact", eco, version=raw[3:].strip(), spec=raw, cutoff_set=cutoff_set,
                             registry_versions=reg_versions)
        try:
            spec = SpecifierSet(raw)
        except InvalidSpecifier:
            return Installed("unknown", eco, note="the constraint is not a valid PEP 440 specifier",
                             cutoff_set=cutoff_set)
        items = list(spec)
        if len(items) == 1 and items[0].operator == "==" and "*" not in items[0].version:
            return Installed("exact", eco, version=items[0].version, spec=str(spec), cutoff_set=cutoff_set,
                             registry_versions=reg_versions)
        if reg_versions is None:
            return Installed("range", eco, spec=str(spec), cutoff_set=cutoff_set,
                             note="no registry version list, so the installed version is unknown")
        allowed = tuple(v for v in reg_versions
                        if parse("pypi", v) is not None and spec.contains(parse("pypi", v), prereleases=True))
        named_pre = any(parse("pypi", s.version) is not None and parse("pypi", s.version).is_prerelease
                        for s in items if "*" not in s.version)
        pick = default_choice("pypi", allowed, yanked=yanked, prereleases_named=named_pre)
        alt = (default_choice("pypi", allowed, yanked=yanked_now, prereleases_named=named_pre)
               if cutoff_set and yanked_now else None)
        return Installed("range", eco, version=pick, candidates=allowed, registry_versions=reg_versions,
                         spec=str(spec), cutoff_set=cutoff_set, version_if_yanked=alt if alt != pick else None)
    if eco == "npm":
        if _NPM_EXACT.match(raw):
            return Installed("exact", eco, version=raw.lstrip("v"), spec=raw, cutoff_set=cutoff_set,
                             registry_versions=reg_versions)
        rng = "*" if raw in _NPM_ANY else raw
        any_version = raw in _NPM_LATEST_TAG
        latest = (reg.latest_version if reg is not None and reg.status == "found" and not cutoff_set else None)
        if npm_semver.satisfies("0.0.0", rng) is None:
            return Installed("unknown", eco, spec=raw or None, cutoff_set=cutoff_set,
                             note="the npm specifier is not a version range (tag, URL or alias)")
        if reg_versions is None:
            return Installed("range", eco, spec=rng, cutoff_set=cutoff_set, any_version=any_version,
                             npm_latest=latest, note="no registry version list, so the installed version is unknown")
        allowed = tuple(v for v in reg_versions if npm_semver.satisfies(v, rng))
        lp = npm_semver.parse_version(latest) if latest else None
        if any_version and lp is not None and lp.prerelease and latest in reg_versions:
            allowed = allowed + (latest,)      # npm installs a pre-release 'latest' tag for "*"
        return Installed("range", eco, version=default_choice("npm", allowed, latest=latest),
                         candidates=allowed, registry_versions=reg_versions, spec=rng, cutoff_set=cutoff_set,
                         any_version=any_version, npm_latest=latest)
    return Installed("unknown", eco, note="no ecosystem")


def applies(rec: EvidenceRecord, inst: Installed) -> Optional[bool]:
    """Whether the declaration can receive a version the record covers at all (D-061): False only
    when the pin is not covered, the constraint excludes the listed version, or no allowed
    registry version is covered. Broader than ``exposure``, which looks at a fresh install."""
    if rec.version_scope is VersionScope.ALL:
        return True
    if inst.kind == "exact":
        return covers(rec, inst.version)
    if inst.kind != "range":
        return None
    if rec.version_scope is VersionScope.LISTED and rec.version and inst.allows(rec.version) is False:
        return False
    if inst.candidates is None:
        return None
    hits = [covers(rec, v) for v in inst.candidates]
    if any(hits):
        return True
    return None if any(h is None for h in hits) else (None if rec.version_scope is VersionScope.LISTED else False)


def exposure(rec: EvidenceRecord, inst: Installed) -> str:
    """``exposed``, ``not_exposed``, ``removed`` (a listed release no longer installable,
    no cut-off) or ``unknown``."""
    if rec.version_scope is VersionScope.ALL:
        return "exposed"
    if inst.kind == "exact":
        c = covers(rec, inst.version)
        return "unknown" if c is None else ("exposed" if c else "not_exposed")
    if inst.kind != "range":
        return "unknown"
    if rec.version_scope is VersionScope.LISTED and rec.version and inst.allows(rec.version) is False:
        return "not_exposed"
    if rec.version_scope is VersionScope.LISTED and rec.version and inst.allows(rec.version) is None and             inst.registry_versions is not None and any(same(rec.ecosystem, v, rec.version)
                                                       for v in inst.registry_versions):
        return "unknown"        # installable, but whether it is chosen cannot be decided (D-060)
    if inst.candidates is None or not inst.candidates:
        return "unknown"
    if rec.version_scope is VersionScope.LISTED and rec.version and inst.registry_versions is not None and not any(
            same(rec.ecosystem, v, rec.version) for v in inst.registry_versions):
        if inst.cutoff_set or inst.allows(rec.version) is None:
            return "unknown"
        return "removed"
    if inst.version is None:
        return "unknown"
    c = covers(rec, inst.version)
    if inst.version_if_yanked is not None and covers(rec, inst.version_if_yanked) != c:
        return "unknown"
    return "unknown" if c is None else ("exposed" if c else "not_exposed")
