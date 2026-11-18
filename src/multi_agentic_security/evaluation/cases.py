"""Evaluation cases and splits (RESEARCH_METHODOLOGY.md section 7.1, D-044, D-067).

A ``Case`` is one dependency declaration with the family it belongs to and where its label
came from. Cases are built from real data only (evidence records, real manifests); this
module never invents a label. Splits are decided before any model is run and never change:

* the development/test side of a case is a pure function of its group key and a fixed seed
  (SHA-256, no random state), so it cannot depend on results;
* groups are connected components: all cases of one package, and all cases pinned by one
  repository, share a group and therefore a side (D-036, D-044 item 9).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Union

from multi_agentic_security.agents.agent1_ingestion import UploadedFile
from multi_agentic_security.datasets.names import normalize_name
from multi_agentic_security.evidence_store import EvidenceStore
from multi_agentic_security.versioning import evidence_ranges

FAMILIES = ("vulnerable", "typosquat", "malicious", "nonexistent", "benign_reference")
SPLIT_SEED = 20261114            # the seed of D-044
_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)\s*(?:;.*)?(?:#.*)?$")


@dataclass(frozen=True)
class Case:
    case_id: str
    family: str
    ecosystem: str
    name: str                        # normalized package name of the dependency
    declaration: str                 # as written in the manifest, e.g. "requests==2.31.0"
    group: str                       # split group key (set by ``assign_groups``)
    label_source: str                # provenance of the label: evidence IDs or a source name
    weight: int = 1                  # number of repositories that pin this case (D-044 item 9)
    expected_target: Optional[str] = None   # the source-stated imitated package (typosquat pairs)
    repos: tuple[str, ...] = ()
    split_hint: Optional[str] = None        # a forced side from the case's provenance (D-070), e.g. 'test'

    def __post_init__(self) -> None:
        if self.family not in FAMILIES:
            raise ValueError(f"unknown family {self.family!r}")
        if self.ecosystem not in ("pypi", "npm"):
            raise ValueError(f"unknown ecosystem {self.ecosystem!r}")
        if self.split_hint not in (None, "train", "dev", "test"):
            raise ValueError(f"unknown split_hint {self.split_hint!r}")

    @property
    def pinned_version(self) -> Optional[str]:
        if self.ecosystem == "pypi":
            m = _PIN.match(self.declaration)
            return m.group(2) if m else None
        name, sep, spec = self.declaration.strip().rpartition("@")
        if not sep or not name or not re.match(r"^v?\d+\.\d+\.\d+(?:-[\w.]+)?$", spec.strip()):
            return None
        return spec.strip().lstrip("v")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["repos"] = list(self.repos)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Case":
        return cls(**{**d, "repos": tuple(d.get("repos") or ())})


def case_id(family: str, ecosystem: str, name: str, declaration: str) -> str:
    h = hashlib.sha256("\x1f".join((family, ecosystem, name, declaration.strip())).encode()).hexdigest()[:12]
    return f"case-{family[:4]}-{h}"


def case_to_files(case: Case) -> list[UploadedFile]:
    """The smallest manifest that declares the case's dependency, for the pipeline."""
    if case.ecosystem == "pypi":
        return [UploadedFile("requirements.txt", (case.declaration.strip() + "\n").encode("utf-8"))]
    name, sep, spec = case.declaration.strip().rpartition("@")
    version = spec.strip() if sep and name else None
    pkg = {"name": "case", "dependencies": {case.name: version or "*"}}
    return [UploadedFile("package.json", json.dumps(pkg).encode("utf-8"))]


# --------------------------------------------------------------------------- splits

def split_of(group: str, *, test_fraction: float = 0.5, seed: int = SPLIT_SEED) -> str:
    """'dev' or 'test', a pure function of the group key and the seed."""
    h = int(hashlib.sha256(f"{seed}\x1f{group}".encode("utf-8")).hexdigest()[:12], 16) / float(16 ** 12)
    return "test" if h < test_fraction else "dev"


def assign_groups(cases: Iterable[Case]) -> list[Case]:
    """Give every case the group key of its connected component: cases that share a package, a
    typosquat target or a repository end up in one group (union-find)."""
    cases = list(cases)
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    for c in cases:
        keys = [f"pkg:{c.ecosystem}:{c.name}"]
        if c.expected_target:
            keys.append(f"pkg:{c.ecosystem}:{normalize_name(c.ecosystem, c.expected_target)}")
        keys += [f"repo:{r}" for r in c.repos]
        find(keys[0])
        for k in keys[1:]:
            union(keys[0], k)
    return [Case(**{**c.__dict__, "group": find(f"pkg:{c.ecosystem}:{c.name}")}) for c in cases]


def split_cases(cases: Iterable[Case], *, test_fraction: float = 0.5, seed: int = SPLIT_SEED) -> dict[str, list[Case]]:
    out: dict[str, list[Case]] = {"dev": [], "test": []}
    for c in sorted(assign_groups(cases), key=lambda c: c.case_id):
        out[split_of(c.group, test_fraction=test_fraction, seed=seed)].append(c)
    return out


# --------------------------------------------------------------------------- three-way split (D-070)

SPLITS = ("train", "dev", "test")           # dev is the validation set
THREE_WAY = {"train": 0.30, "dev": 0.20, "test": 0.50}
_PRECEDENCE = ("test", "dev", "train")      # when forced hints inside one group disagree, the earlier wins


def split_of3(group: str, fractions: dict = THREE_WAY, seed: int = SPLIT_SEED) -> str:
    """'train', 'dev' or 'test': a pure function of the group key, the fractions and the seed."""
    if set(fractions) != set(SPLITS) or any(v < 0 for v in fractions.values()) or abs(sum(fractions.values()) - 1) > 1e-9:
        raise ValueError("fractions must name train, dev and test, be >= 0 and sum to 1")
    u = int(hashlib.sha256(f"{seed}3{group}".encode("utf-8")).hexdigest()[:12], 16) / float(16 ** 12)
    acc = 0.0
    for name in SPLITS:
        acc += fractions[name]
        if u < acc and fractions[name] > 0:
            return name
    return max((n for n in SPLITS if fractions[n] > 0), key=lambda n: SPLITS.index(n))


def split_three_way(cases: Iterable[Case], fractions: dict = THREE_WAY, seed: int = SPLIT_SEED) -> dict[str, list[Case]]:
    """Disjoint train / dev / test, grouped (D-036, D-044 item 9). A case with a ``split_hint`` forces its
    whole group to that side; when hints in one group disagree the order test > dev > train applies, so a
    held-out case can never be pulled into a development or training side."""
    grouped = assign_groups(cases)
    forced: dict[str, str] = {}
    for c in grouped:
        if c.split_hint is not None:
            cur = forced.get(c.group)
            if cur is None or _PRECEDENCE.index(c.split_hint) < _PRECEDENCE.index(cur):
                forced[c.group] = c.split_hint
    out: dict[str, list[Case]] = {s: [] for s in SPLITS}
    for c in sorted(grouped, key=lambda c: c.case_id):
        out[forced.get(c.group) or split_of3(c.group, fractions, seed)].append(c)
    return out


def mark_eval_only(cases: Iterable[Case], names: Iterable[str]) -> list[Case]:
    """Force the test side for every case whose package name is in ``names`` (LibHalluBench-derived names and
    the names it shares with the malicious and typosquat lists, FOUNDATION_REVIEW section 3)."""
    wanted = {(e, normalize_name(e, n)) for e in ("pypi", "npm") for n in names}
    return [Case(**{**c.__dict__, "split_hint": "test"}) if (c.ecosystem, c.name) in wanted else c for c in cases]


def verify_splits(splits: dict[str, list[Case]]) -> list[str]:
    """Problems found in a split (empty list = clean): shared cases, shared groups, broken forced sides."""
    problems: list[str] = []
    seen_id: dict[str, str] = {}
    seen_group: dict[str, str] = {}
    for side in SPLITS:
        for c in splits.get(side, []):
            if c.case_id in seen_id:
                problems.append(f"case {c.case_id} is in both {seen_id[c.case_id]} and {side}")
            seen_id[c.case_id] = side
            if seen_group.setdefault(c.group, side) != side:
                problems.append(f"group {c.group} is in both {seen_group[c.group]} and {side}")
            if c.split_hint == "test" and side != "test":
                problems.append(f"test-only case {c.case_id} is in {side}")
            if c.split_hint == "dev" and side == "train":
                problems.append(f"dev-only case {c.case_id} is in train")
    return problems


def fine_tuning_pool(train_cases: Iterable[Case], store: EvidenceStore, cutoff_date) -> tuple[list[Case], dict]:
    """The training cases that may be used to fine-tune a model for evaluation at ``cutoff_date`` (D-070):
    every label must come from evidence records that exist and were published before the earliest cut-off
    (a model must not learn from evidence that a held-out run treats as unknown). Others are rejected with
    a reason; nothing is silently dropped."""
    ok: list[Case] = []
    rejected: dict[str, list[str]] = {}
    for c in train_cases:
        reason = None
        if c.split_hint == "test":
            reason = "test_only_case"
        else:
            ids = [i for i in c.label_source.split(",") if i]
            if not ids or not all(i.startswith("ev-") for i in ids):
                reason = "label_not_from_evidence_records"
            else:
                for i in ids:
                    rec = store.get(i)
                    if rec is None:
                        reason = "label_record_missing"
                    elif rec.published is None:
                        reason = "label_record_undated"
                    elif not rec.known_before(cutoff_date):
                        reason = "label_record_not_before_cutoff"
                    if reason:
                        break
        if reason:
            rejected.setdefault(reason, []).append(c.case_id)
        else:
            ok.append(c)
    return ok, {k: sorted(v) for k, v in sorted(rejected.items())}


# --------------------------------------------------------------------------- reading and writing

def write_cases(path: Union[str, Path], cases: Iterable[Case]) -> str:
    """One JSON object per line, sorted by ``case_id``; returns the file's SHA-256."""
    p = Path(path)
    if p.exists():
        raise FileExistsError(f"{p} exists; case lists are written once (build a new file)")
    text = "".join(json.dumps(c.to_dict(), sort_keys=True, ensure_ascii=False) + "\n"
                   for c in sorted(cases, key=lambda c: c.case_id))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_cases(path: Union[str, Path]) -> list[Case]:
    return [Case.from_dict(json.loads(line)) for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip()]


# --------------------------------------------------------------------------- D-044 item 8

def vulnerable_cases_from_pins(requirements_text: str, *, repo: str, store: EvidenceStore, cutoff_date,
                               label_source: str = "osv_pypi_a2") -> tuple[list[Case], dict]:
    """A pin ``name==version`` becomes a vulnerable-family case if the version lies in the affected
    range of a vulnerable record published before ``cutoff_date`` (the system can see the finding).
    Returns (cases, counts of every line kind and of rejected pins)."""
    cases: list[Case] = []
    counts = {"lines": 0, "exact_pins": 0, "not_exact": 0, "no_advisory": 0, "advisory_unreadable": 0, "cases": 0}
    for line in requirements_text.splitlines():
        s = line.strip()
        if not s or s.startswith(("#", "-")):
            continue
        counts["lines"] += 1
        m = _PIN.match(s)
        if not m:
            counts["not_exact"] += 1
            continue
        counts["exact_pins"] += 1
        name, version = normalize_name("pypi", m.group(1)), m.group(2)
        ids, unreadable = [], False
        for match in store.query("pypi", name, cutoff=cutoff_date).by_family("vulnerable"):
            cov = evidence_ranges.in_range("pypi", version, match.record.version_range or "") \
                if match.record.version_range else None
            if cov is None:
                unreadable = True
            elif cov:
                ids.append(match.evidence_id)
        if ids:
            cases.append(Case(case_id=case_id("vulnerable", "pypi", name, f"{name}=={version}"), family="vulnerable", ecosystem="pypi",
                              name=name, declaration=f"{name}=={version}", group=name,
                              label_source=",".join(sorted(ids)), repos=(repo,)))
            counts["cases"] += 1
        elif unreadable:
            counts["advisory_unreadable"] += 1
        else:
            counts["no_advisory"] += 1
    return cases, counts


def merge_duplicate_cases(cases: Iterable[Case]) -> list[Case]:
    """One case per (package, version); ``weight`` counts the repositories that pin it (D-044 item 9)."""
    by_id: dict[str, Case] = {}
    for c in cases:
        if c.case_id in by_id:
            prev = by_id[c.case_id]
            repos = tuple(sorted(set(prev.repos) | set(c.repos)))
            by_id[c.case_id] = Case(**{**prev.__dict__, "repos": repos, "weight": len(repos) or prev.weight + 1})
        else:
            by_id[c.case_id] = c
    return list(by_id.values())
