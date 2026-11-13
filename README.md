# Multi-Agentic Security System

Research project on detecting nonexistent (for example LLM-hallucinated), typosquatted, reported-malicious and known-vulnerable software dependencies, and on producing **evidence-grounded, independently verified remediation recommendations** with a five-agent pipeline.

## Status

- The research foundation and the narrowed research direction are approved (see `DECISIONS.md`, D-017 to D-043).
- Only the **Agent 3 v1 baseline** (`src/multi_agentic_security/agents/agent3_risk/baseline_v1/`) is implemented. It is frozen as a deterministic comparison point.
- Agents 1, 2, 4 and 5, Agent 3 v2, the evidence store, the evaluation harness, the backend and the frontend are designed but not yet implemented.

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
| `docs/datasets/` | Dataset catalog and the dataset migration record |

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
