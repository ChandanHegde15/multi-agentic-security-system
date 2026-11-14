# Project brief: Multi-Agentic Security System

- **Owner:** Chandan Hegde
- **Repository:** `https://github.com/ChandanHegde15/multi-agentic-security-system`
- **Status:** research foundation approved on 2026-11-13 (decisions D-017 to D-028); research direction narrowed and evaluation design extended the same day (D-029 to D-043). Only the Agent 3 v1 baseline is implemented. See `DECISIONS.md`.

## 1. Research aim

Build and evaluate a five-agent system that analyses a software project's dependencies and identifies packages that are:
- **nonexistent** (for example names invented by an LLM)
- **typosquatted** (names imitating popular packages)
- **reported malicious**
- **known vulnerable**

The system then produces evidence-grounded remediation recommendations and verifies them independently.

The project is grounded in public research datasets (section 4), not in synthetic labels.
Planned deliverables:
- the five-agent pipeline
- dataset ingestion with provenance
- independent benchmarks and a research evaluation
- reproducible experiments
- a backend API with frontend integration
- automated tests
- a research paper

### Research direction (approved, D-030; narrowed from D-018)

The project is an **evaluation study** of the reliability of remediation recommendations (D-031). It is not a detection contribution and not a system contribution.

> **RQ1.** How reliable are remediation recommendations for flagged dependencies, and what do evidence grounding and deterministic verification change?

RQ1 is answered by three measurements:
- **Claim support:** how often the structured claims in a recommendation are unsupported by the evidence records they cite.
- **Rules versus LLM:** whether a grounded, verified LLM recommender is non-inferior to deterministic recommenders (project rules and an existing audit tool) and adds coverage.
- **Verifier, vulnerable family, PyPI:** how much a deterministic verifier reduces upgrade targets that fall in an advisory published after the cut-off, and what it wrongly rejects.

Supporting questions RQ2–RQ4 cover grounding (a replication), per-family differences (descriptive) and what the frozen Agent 3 v1 misses.

- No component is claimed as novel: multi-agent design, retrieval, LLM use, registry lookup and deterministic verification all have published precedents (`docs/research/literature/NOVELTY_ASSESSMENT.md`).
- Detection is done by evidence lookup and is reported as a component.
- Scope (D-019): PyPI for all four families; npm for typosquat and malicious only. The headline safety result is the vulnerable family on PyPI; other families are reported descriptively.
- A negative result (deterministic recommenders are as good as the LLM) is an acceptable headline (D-032).
- Evaluation strength: three pinned LLMs (D-038), an external audit-tool baseline (D-039), real-project inputs (D-040), a human-judged validation sample (D-037), a frozen and hashed protocol.
- The data does **not** support a "hallucinated packages become malware" claim; see the foundation review.

| Document | Content |
|---|---|
| `docs/research/PROBLEM_DEFINITION.md` | What each dataset can and cannot establish; scope |
| `docs/research/LITERATURE_REVIEW.md` | 28 sources with verification status |
| `docs/research/RESEARCH_GAP_MATRIX.md` | Comparison matrix and the research gap (a hypothesis about the literature) |
| `docs/research/RESEARCH_QUESTIONS.md` | Questions, hypotheses, variables, baselines, metrics, threats |
| `docs/research/ANNOTATION_GUIDELINES.md` | Rules for the human annotation tasks |
| `docs/research/literature/` | Paper inventory, comparison matrix, gap register, novelty assessment, contribution candidates, dataset feasibility |
| `docs/research/FOUNDATION_REVIEW.md` | Review of the foundation: claim audit, known weaknesses, what the data cannot answer |
| `docs/architecture/SYSTEM_ARCHITECTURE.md` | Five-agent design and evaluation harness |
| `docs/architecture/AGENT_CONTRACTS.md` | Agent 3 v1 contract and draft contracts for the new agents |
| `docs/datasets/DATASET_CATALOG.md` | Data sources, location, licences, known issues |
| `docs/datasets/DATASET_MIGRATION_PLAN.md` | The executed move of the dataset into `research/datasets/` |

## 2. Five-agent architecture (design approved, D-025; system specification D-047; contracts implemented, agents in progress)

| # | Legacy role | New role |
|---|---|---|
| 1 | Dependency extraction (root `requirements.txt` / `package.json`) | Deterministic extraction from uploaded files, ZIP or folder, a public Git repository link, or generated Python/JavaScript code (imports read statically, never executed) (D-047) |
| 2 | Registry verification (PyPI/npm existence check) | Registry verification and evidence collection: live, time-stamped PyPI/npm lookups for user uploads, a dated snapshot for experiments, lookups in separate label families; no judgement |
| 3 | Deterministic risk scoring (not-found weight + Levenshtein similarity to 7 reference packages) | **v1 preserved unchanged as a baseline.** v2 (allowed, D-020): one finding per label family, no combined score |
| 4 | LLM recommendation (Groq / local Qwen LoRA) | Structured recommendation with evidence-cited claims; rule-based, ungrounded-LLM and grounded-LLM variants plus an adapter for an existing audit tool (D-039); provider-agnostic, three pinned models (D-038); no fine-tuning |
| 5 | Recommendation verification (git worktree, pip install, tests, merge gate) | Isolated deterministic verification of every recommendation before acceptance (separate from Agent 4, no LLM); verified / rejected / needs review; nothing installed or executed |

## 3. Why the project was reset

A read-only audit of the legacy implementation (2026-11-13) found the following.

**Agent 3 blind spot.** Agent 3 scored only packages *not found* in the registry. A malicious package that still exists in the registry scored 0 / "low", and the similarity signal covered only 7 hard-coded reference packages. A probe recorded in the dataset submission (`data/manifests/eval_run_2026-11-12T182055+0000.json`) is consistent with this: on 132 typosquat cases, the 88 flagged cases were exactly the 88 not-found cases, and every typosquat still in the registry scored low. That run used current registry lookups.

**Circular benchmark.** The legacy 65-case benchmark's ground truth was generated by running the legacy agents on stubbed registries, so it measured self-consistency, not detection accuracy.

**Agent 4 results:**
- The Groq baseline reached 19.3% action accuracy on that benchmark.
- The fine-tuned Qwen2.5-0.5B LoRA adapter scored 95% on its own synthetic internal test, but only 3 of 42 scorable benchmark cases.
- Its local integration was never validated (schema-violating outputs).

**Agent 5 limits:**
- Only handled `requirements.txt` replacements at a repo root.
- Ran `pip install` on unvetted candidates.
- Left branches behind.

**Repository hygiene.** There was no dependency manifest.

Legacy benchmarks, training data, the model and results are archived outside the repository (`D:\RESEARCH_DATA\legacy_archive\agentic-security-system_v1\`, permanent archive, D-029), and the old git history is backed up outside the repository.

## 4. Research data (summary; details in `docs/datasets/DATASET_CATALOG.md`)

A dataset submission (`dataset_submission.zip`, SHA-256 `33e409ab…0d00`) was inspected and extracted text-only on 2026-11-13. Since the same day it lives in `research/datasets/` on the owner's machine, **git-ignored** (D-017).

| Status | Sources |
|---|---|
| Complete | LibHalluBench, Package Hallucination (Zenodo v1.0), Ecosyste.ms Typosquatting, You Can't Touch This (Zenodo v1.1.0), real-world manifests (12 GitHub repos) |
| Partial | OpenSSF Malicious Packages (PyPI only), DataDog (package-name manifests only, no samples), OSV.dev (PyPI only) |
| Listing only | PyPI MalRegistry |
| Absent | deps.dev |

- The archive contains 394 real malicious npm packages. They were never extracted.
- None of the data is normalized or approved for evaluation or training yet. The normalization strategy is approved (D-024).
- Limits on the research (details in `docs/research/PROBLEM_DEFINITION.md`):
  - Only 34 package names are human-confirmed hallucinations (Package Hallucination).
  - Ecosyste.ms pairs are name pairs of mixed intent, not confirmed malware.
  - Vulnerability data is PyPI-only; there is no registry history and no gold set of correct recommendations.

## 5. Constraints

- No data, archives, malware or model weights in git. `research/datasets/` is git-ignored and never committed.
- Only the owner commits and pushes; automated tools never do.
- Microsoft Defender stays fully enabled: no exclusions, no restoring quarantined files.
- No synthetic ground truth. Legacy data is not migrated.
- LibHalluBench is evaluation-only.

## 6. Repository structure (approved, D-026)

The package skeleton exists and the Agent 3 v1 baseline lives at `src/multi_agentic_security/agents/agent3_risk/baseline_v1/` (D-042). Other directories are created as they are needed.

```
MAJORPROJECT/
├── README.md, PROJECT_BRIEF.md, DECISIONS.md
├── pyproject.toml                  project metadata and dependencies
├── src/multi_agentic_security/
│   ├── contracts/                  versioned schemas shared between agents
│   ├── agents/
│   │   ├── agent1_ingestion/
│   │   ├── agent2_registry/
│   │   ├── agent3_risk/            baseline_v1/ (frozen) + v2
│   │   ├── agent4_recommendation/
│   │   └── agent5_verification/
│   ├── pipeline/                   orchestration of the five agents
│   ├── datasets/                   source adapters, normalization, dataset registry
│   │                               (code only; reads research/datasets/)
│   └── evaluation/                 scorer, metrics and benchmark runners
├── research/datasets/              primary data, local only, git-ignored
├── benchmarks/                     benchmark definitions and manifests (hashes, splits; no raw data)
├── experiments/                    experiment configs and small result records
├── backend/                        API service (FastAPI)
├── frontend/                       web client (React + Vite + TypeScript)
├── tests/                          unit/, contract/, integration/, fixtures/ (small fixtures only)
├── scripts/                        command-line entry points
└── docs/
    ├── architecture/
    ├── datasets/
    ├── research/
    └── paper/
```
