# Research methodology

Status 2026-11-14 (sampling rule fixed, D-044; supplementary data placed, D-045). Earlier status 2026-11-13:
- The research questions, metrics and experiment design are **approved in the narrowed form** (D-030; evaluation additions D-032 to D-041); see sections 4 and 6 to 8.
- This document records the approved data-handling principles and the approved normalization strategy (D-024).

## 1. Approved principles

| Principle | Decision |
|---|---|
| Ground truth comes only from public research sources with recorded provenance. No synthetic ground truth. Legacy synthetic data is not used. | D-002 |
| Label families stay separate: malicious, withdrawn, typosquat, vulnerable, nonexistent, benign-reference. | D-012 |
| LibHalluBench is used for evaluation only. | D-013 |
| Normalized data is rebuilt from raw sources; submitter-normalized files are cross-checks only. | D-011 |
| Raw data is immutable and outside the repository; package samples are never executed. | D-008, D-009 |
| The Agent 3 v1 baseline stays reproducible for comparison; new versions are explicit. | D-004, D-005 |

## 2. Constraints that follow from the verified data

These are facts, not design choices.

**Overlapping sources.** OpenSSF, OSV MAL, DataDog and MalRegistry overlap heavily, so agreement between them is not independent evidence.

**Registry lookups change over time.** A current registry lookup does not show historical status: removed npm malware often returns a `0.0.1-security` placeholder. Any registry-based signal must be time-stamped and kept apart from historical labels.

**"Benign" means "candidate".** Benign references (popular packages, YCTT benign sets) are candidates, not proven safe.

**Version scope matters.**
- Some labels apply to specific versions only: DataDog version lists, OSV affected ranges.
- These must not be widened into whole-package labels.

**Coverage is uneven.** Malicious-report coverage is PyPI-heavy:
- OpenSSF and OSV are PyPI-only in the current data.
- npm malicious coverage comes from DataDog names and the 394 YCTT packages.

## 3. Normalization strategy (approved, D-024)

From the Phase 3 report, section 8. Approval of the strategy does not approve any source for evaluation or training; those gates stay per source (item 7).

1. **One evidence row per source claim**, never one merged row per package.
   - Keys:
     - `ecosystem`
     - normalized name (PEP 503 for PyPI, lower-case for npm)
     - raw name
     - version or null
     - `version_scope` (all / listed / range)
   - Provenance:
     - source dataset
     - source version
     - source record ID
     - source file and its SHA-256
     - license
     - retrieval time
     - `human_reviewed`
2. **One table per label family.**
3. **Cross-source links** (e.g. OSV MAL ↔ OpenSSF by MAL ID), recorded as `corroborating_sources`, not as independent votes.
4. **A conflict table** for contradictory labels, for human review.
5. **Splits fixed before modelling**, grouped by target or package family and assigned by hash.
6. **Versioned JSON Schema and validation.**
   - Output to `research/datasets/verified/normalized/v1/` (git-ignored) with a manifest of counts and hashes.
   - The repo holds only code, the schema and a small dataset registry.
7. **Human approval gates** per source for evaluation and training use.

## 4. Research design (approved, D-018 to D-025)

Research questions, hypotheses, variables, baselines, metrics, the temporal hold-out against circular evaluation, statistics and threats to validity are in `docs/research/RESEARCH_QUESTIONS.md`. Per-agent tasks and metrics are in `docs/architecture/SYSTEM_ARCHITECTURE.md`. Known weaknesses are in `docs/research/FOUNDATION_REVIEW.md`.

## 5. Still to be defined

- Benchmark construction: the exact case lists, splits and cut-off date.
- The non-inferiority margin and significance level.
- The pilot design (D-023) and the Agent 4 model (D-022).
- Paper structure (`docs/paper/`, not yet created).

## 6. Evaluation additions (approved, D-030 to D-041)

The narrowed research questions and the full evaluation design are in `RESEARCH_QUESTIONS.md`. The methodological commitments are:

| Commitment | Decision |
|---|---|
| Development set and test set; the test set is frozen before any LLM run and used once | D-030, D-036 |
| Splits and resampling group cases by target package and by near-duplicate name | D-036 |
| The scorer is implemented independently of the verifier | D-036 |
| Three pinned LLMs from different families, one open-weight and local; no fine-tuning | D-022, D-038 |
| One existing audit tool, version-pinned, as an external baseline; never run on dataset manifests; no package downloaded or installed | D-039 |
| Human-judged validation sample and three smaller annotation tasks, under `ANNOTATION_GUIDELINES.md` | D-033, D-037 |
| The whole protocol (cases, splits, cut-offs, prompts, model and tool versions, metrics, non-inferiority margin) is written to one file, hashed and dated before the main runs | D-030 |
| Logged systematic literature search before any gap is claimed in the paper | D-035 |

## 7. Acquisition plan (D-041)

Everything acquired goes under `research/datasets/`, stays out of git, and gets a provenance record (source URL, retrieval time in UTC, tool and version, file hash, licence evidence). Nothing is downloaded as a package, installed or executed.

| Item | What is retrieved | Status |
|---|---|---|
| PyPI version lists and upload times | Registry JSON metadata for sampled package names only | Approved (D-034). Acquired 2026-11-14 for 125 names (top-100 popular + Ecosyste.ms targets; D-045). Vulnerable-family PyPI targets: not yet acquired |
| PyPI popular-package list | One dated public list of most-downloaded packages | Acquired 2026-11-14: hugovk/top-pypi-packages 30-day list, 15,000 names, list dated 2026-11-01; licence unverified (D-045) |
| LibHalluBench dataset card | The card text and the revision identifier | Acquired 2026-11-14, revision `6882a8a4` (D-045) |
| Real-project dependency pins | Text of requirement files only (rule below) | Rule fixed (D-044); test-set sample not yet acquired. Five development repositories acquired 2026-11-14, development and pilot use only (D-045) |
| OSV npm advisories | The npm export | Approved (D-027); not yet acquired |

### 7.1 Sampling rule for real-project dependency pins (fixed, D-044)

**Goal.** Realistic `package==version` inputs for the vulnerable family, as they stood before each cut-off date T, drawn so that the test set is not hand-picked.

1. **Sampling frame.** GitHub repository search, `language:Python fork:false archived:false stars:>=10`, run over consecutive creation-month windows from 2015-01 to the last full month before the earliest cut-off. Monthly windows keep every query under the search API's 1,000-result limit, so the frame is the full list, not the first page. The queries, run date and the complete candidate list (with its SHA-256) are stored; the stored list, not a re-run search, is the frame.
2. **Exclusions.** The five development repositories already acquired (home-assistant/core, apache/superset, pallets/flask, pandas-dev/pandas, psf/requests); repositories that are themselves a source dataset of this project; forks and archived repositories.
3. **Strata.** Three star bands, 100 repositories each: 10–99, 100–999, ≥1,000 (stars as at retrieval; this is recorded as a limitation).
4. **Order.** Candidates in each band are shuffled once with the fixed seed `20261114` (Python `random.Random(seed).shuffle` over the sorted `owner/repo` list). Repositories are checked in that order until the band has 100 eligible repositories. Every checked repository and the reason it was accepted or rejected are logged.
5. **Snapshot.** For each cut-off T, the last commit on the default branch dated before T. Eligible only if that commit is no older than 24 months before T (the project was active at T). One snapshot per repository per cut-off; commit hash and date are recorded.
6. **Files.** Only `requirements*.txt` at the repository root or `requirements/*.txt`, at most three files per repository (root files first, then alphabetical), fetched as text through the hosting API. Nothing is cloned, and nothing else is fetched except the repository's licence identifier.
7. **Eligibility.** At least five exact pins (`name==version`) of PyPI packages across the repository's retrieved files. Unpinned, range, URL, editable, local-path and hash-only lines are counted and discarded. Names are normalised (PEP 503).
8. **Case construction.** A pin becomes a vulnerable-family case if the pinned version lies in an affected range of a non-withdrawn advisory published before T (the system can see the finding). The same pin is scored against advisories published at any time.
9. **Duplicates and splits.** One case per (package, version, T); the number of repositories that pin it is kept as a weight. All cases for one package stay on the same side of the development/test split, and all pins from one repository stay together.
10. **Size check.** After retrieval, if fewer than 300 vulnerable-family cases result, each band is extended by continuing the same shuffled order in steps of 50 repositories until 300 cases are reached or the frame is exhausted. This extension rule is fixed now, before any result is seen.
11. **Licences and publication.** The repository licence identifier is recorded for each file. Raw files are not redistributed; only (package, version, count) tuples and repository identifiers are release candidates, after a licence check.
12. **Never.** `pip install`, dependency resolution that downloads packages, or execution of anything from the sampled repositories.

**Why this rule.**
- *Random within a recorded frame* removes selection by the researcher, which is the main weakness of the five development repositories.
- *Star bands* stop very popular, well-maintained projects (which pin few vulnerable versions) from dominating, while keeping them represented; results can be reported per band.
- *At least 10 stars* removes most empty, personal and coursework repositories, which are not projects a remediation recommender would realistically serve.
- *Activity within 24 months of T* ensures the pins describe a project in use at T, so a recommendation made at T is meaningful.
- *At least five exact pins* is the minimum for a repository to contribute version-level cases; looser pins cannot be checked against affected ranges.
- *At most three files per repository and grouping by repository* stop large monorepos from contributing most of the cases.
- *300 repositories* is expected (unverified estimate: about 20 exact pins per repository, a few per cent vulnerable) to give several hundred vulnerable-family cases, enough for proportions with roughly ±5 percentage-point 95% intervals. The pilot checks this, and the size check (item 10) is fixed in advance.

**Known limits.** Repositories with pinned requirement files over-represent applications compared with libraries; star counts are measured at retrieval, not at T; declared pins are not necessarily deployed; GitHub search coverage is not guaranteed complete. All are stated as threats.

## 8. Reading order for the evaluation

1. `RESEARCH_QUESTIONS.md`: questions, conditions, metrics, threats.
2. `ANNOTATION_GUIDELINES.md`: human annotation tasks.
3. `literature/`: the evidence behind the narrowed direction.
