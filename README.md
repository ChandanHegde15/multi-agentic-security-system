# Multi-Agentic Security System

Research project on detecting nonexistent (for example LLM-hallucinated), typosquatted, reported-malicious and known-vulnerable software dependencies, and on producing **evidence-grounded, independently verified remediation recommendations** with a five-agent pipeline.

## Status

- The research foundation and the narrowed research direction are approved (see `DECISIONS.md`, D-017 to D-056). The user-facing system is specified in D-047: upload (files, ZIP, Git link or generated code) → Agents 1 to 5 → per-agent dashboards with an explanation for every decision.
- Implemented: the frozen **Agent 3 v1 baseline** (`src/multi_agentic_security/agents/agent3_risk/baseline_v1/`), the evidence record contract, the pipeline contracts between all five agents (`src/multi_agentic_security/contracts/`), source adapters that build the normalized evidence tables (`src/multi_agentic_security/datasets/`; results in `docs/datasets/DATASET_EVALUATION.md`), and **Agent 1** (`src/multi_agentic_security/agents/agent1_ingestion/`): dependencies from `requirements*.txt`, `package.json` and `package-lock.json`, imports in Python and JavaScript/TypeScript code, install commands in scripts, Dockerfiles and text, with safe in-memory intake of ZIP archives, folders and public GitHub links (D-049 to D-052); and **Agent 2** (`src/multi_agentic_security/agents/agent2_registry/`, with the read-only evidence index in `src/multi_agentic_security/evidence_store/`): PyPI and npm registry metadata in `off`, `snapshot` or `live` mode, and the evidence records that name each package, per label family, with an evidence cut-off (D-053, D-054). Runs on real data or the network are recorded in `docs/research/RUN_LOG.md`. **Agent 3** (`src/multi_agentic_security/agents/agent3_risk/`) reports the frozen v1 score next to version-aware findings per label family, with evidence IDs and reasons (D-055, D-056).
- Also implemented: **Agent 5**, an isolated deterministic verifier (`src/multi_agentic_security/agents/agent5_verification/`, D-059 to D-061); **Agent 4**, with the rule baseline R0 and a provider-independent LLM interface and Groq adapter (`src/multi_agentic_security/agents/agent4_recommendation/`, D-062 to D-069); the **pipeline orchestrator**, a LangGraph state graph with guardrails, run records and LLM cost control (`src/multi_agentic_security/pipeline/`, D-066); and the **evaluation machinery**: an independent scorer, per-family metrics, statistics, cases and train/dev/test splits (`src/multi_agentic_security/evaluation/`, D-067, D-070; split design in `docs/research/EVALUATION_SPLITS.md`).
- Not done: no scored evaluation has been run on real cases and the evaluation protocol is not frozen (`docs/research/RUN_LOG.md`, PLAN-002); the dashboards and the backend API are not planned. Only fixture-based trials of the LLM back end have been made (TRIAL-001, TRIAL-002).

## Research question

> How reliable are remediation recommendations for flagged dependencies, and what do evidence grounding and deterministic verification change?

It is answered by three measurements: how often the claims in a recommendation are unsupported by the evidence they cite; whether an LLM recommender is non-inferior to deterministic recommenders; and how much a deterministic verifier reduces risky upgrade targets for vulnerable PyPI packages. The project is an evaluation study; its pipeline is not claimed as novel.

Details: `docs/research/RESEARCH_QUESTIONS.md`.

## Documentation

| Document | Content |
|---|---|
| `PROJECT_BRIEF.md` | Aim, history, scope, repository structure |
| `DECISIONS.md` | Approved decisions and their reasons |
| `docs/research/` | Problem definition, literature review, gap matrix, research questions, methodology, foundation review |
| `docs/architecture/` | System architecture and agent contracts |
| `docs/datasets/` | Dataset catalog, dataset evaluation and the dataset migration record |

## Running the tests

Python 3.13:

```
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider
```

## Data

The research data is **not** in this repository. It consists of public research datasets (LibHalluBench, Package Hallucination, Ecosyste.ms Typosquatting, You Can't Touch This, OpenSSF Malicious Packages, DataDog manifests, OSV.dev, PyPI MalRegistry listing, real-world manifests), described with sources and licences in `docs/datasets/DATASET_CATALOG.md`.

On the owner's machine it lives in `research/datasets/`, which is git-ignored. It includes live malware inside an archive and data without redistribution rights, so it must never be committed. Do not run `pip install` or `npm install` against any manifest from the datasets.

## Licence

Not yet chosen.
