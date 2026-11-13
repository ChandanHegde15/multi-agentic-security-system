# Research methodology

Status 2026-11-13:
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
| PyPI version lists and upload times | Registry JSON metadata for sampled package names only | Approved (D-034); not started |
| PyPI popular-package list | One dated public list of most-downloaded packages | Approved (D-027); source and date to be recorded |
| LibHalluBench dataset card | The card text and the revision identifier | Approved (D-041); not started |
| Real-project dependency pins | Text of requirement files only (rule below) | Approved in principle (D-040); **the rule below must be confirmed by the owner before retrieval** |
| OSV npm advisories | The npm export | Approved (D-027); optional, low priority |

### 7.1 Sampling rule for real-project dependency pins (proposed)

**Goal.** Realistic `package==version` inputs for the vulnerable family, as they stood before the cut-off date T.

1. **Population.** Public GitHub repositories whose primary language is Python, that are not forks or archives, and that have a `requirements.txt` (or `requirements/*.txt`) at the repository root level.
2. **Sample.** A fixed-size random sample (proposed: 300 repositories) drawn with a recorded seed from a recorded search query, stratified into three star bands so that the sample is not only very popular projects. The query, seed, date and the full list of sampled repositories are stored.
3. **Version of the file.** The last commit to the default branch dated before T. The commit hash and date are recorded.
4. **What is retrieved.** Only the text of the requirement files at that commit, through the hosting API. No repository is cloned in full, and no other file is fetched except the repository's licence identifier.
5. **What is kept.** Only exact pins (`name==version`) of packages on PyPI. Unpinned, range-pinned, URL, editable and local-path entries are counted and discarded. Names are normalised (PEP 503).
6. **Case construction.** A pin becomes a vulnerable-family case if the pinned version lies in an affected range of a non-withdrawn advisory published **before** T (the system can see the finding). The same pin is scored against advisories published at any time.
7. **Duplicates.** One case per (package, version); the number of repositories that pin it is kept as a weight. All cases for one package stay on the same side of the development and test split.
8. **Licences and publication.** Requirement files are short factual lists; the repository licence identifier is recorded for each. Raw files are not redistributed. Only (package, version, count) tuples and repository identifiers are candidates for release, after a licence check.
9. **Never.** `pip install`, dependency resolution that downloads packages, or execution of anything from the sampled repositories.

**Known limits.** Repositories with pinned requirement files are not representative of all Python projects; applications are over-represented compared with libraries. Pins in a requirement file are declared, not necessarily deployed. Both are stated as threats.

## 8. Reading order for the evaluation

1. `RESEARCH_QUESTIONS.md`: questions, conditions, metrics, threats.
2. `ANNOTATION_GUIDELINES.md`: human annotation tasks.
3. `literature/`: the evidence behind the narrowed direction.
