# Agentic Defense Against AI-Hallucinated Package Poisoning

An evaluation study of how language models fix risky software dependencies. When a scanner flags a package as malicious, typosquatted, vulnerable or nonexistent, and a model is asked what to do about it, two things can go wrong: the recommended fix can itself be unsafe, and the reasons the model gives can be unsupported by the evidence it cites. This project measures both, and measures what an independent, deterministic verifier changes.

## How it works

A five-agent pipeline turns a manifest into a report. Only the Recommendation and Remediation Agent (Agent 4) can use a language model.

```mermaid
flowchart LR
    M["Input"] --> A1
    subgraph G["LangGraph state graph"]
        A1["Agent 1<br/>Dependency Extraction"] --> A2["Agent 2<br/>Evidence Collection"]
        A2 --> A3["Agent 3<br/>Risk Assessment"]
        A3 --> A4["Agent 4<br/>Recommendation and Remediation"]
        A4 --> A5["Agent 5<br/>Verification"]
    end
    A5 --> R["Report"]
    LM["Language model<br/>local, no tools"] --> A4
    D[("Recorded data<br/>evidence store and registry recordings")] -.-> A2
    D -.-> A5
```

| Agent | Role | Language model | Code |
|---|---|---|---|
| 1 Dependency Extraction | Parses `requirements.txt`, `pyproject.toml`, `Pipfile`, `package.json`, code imports and install commands | no | `agent1_ingestion` |
| 2 Evidence Collection | Checks each package against recorded PyPI and npm metadata and looks up its evidence records, filtered by a cut-off date | no | `agent2_registry` |
| 3 Risk Assessment | One finding per label family, version-aware, with evidence IDs | no | `agent3_risk` |
| 4 Recommendation and Remediation | Rules (R0), or a model given only the finding names (LLM-U) or the evidence records too (LLM-G) | LLM-U, LLM-G | `agent4_recommendation` |
| 5 Verification | Ten deterministic checks: accept, reject or abstain. Shares no code or model with Agent 4 | no | `agent5_verification` |

Every decision carries its reasons. Failures are explicit states, never defaults. Uploaded files are never installed, imported or executed.

## Main results (held-out test cases)

Three local models (Llama 3.2 3B, Qwen 2.5 3B, Qwen 2.5 7B) on 298 test cases, five label families, and two evidence cut-off settings for vulnerable packages:

- **Unsupported reasons.** With the evidence in the prompt, every model still made unsupported claims (for vulnerable packages: 8 of 24, 25 of 38 and 50 of 95 claims).
- **Unsafe fixes.** The two 3B models often kept a malicious or typosquatted package, or proposed a replacement that was itself malicious or a typosquat.
- **Verifier.** It delivered no unsafe recommendation without a cut-off: 100 unsafe recommendations removed, 5 of 396 acceptable ones wrongly rejected. The cost is coverage.
- **Rules.** The rule-based recommender was never unsafe without a cut-off and covered more cases.
- **Time.** Under cut-offs, every vulnerable target that was still delivered had its advisory published after the cut-off. The verifier removed every target whose advisory was already known.

Details: [`docs/research/RESULTS.md`](docs/research/RESULTS.md).

## Repository

| Path | Content |
|---|---|
| `src/multi_agentic_security/agents/` | The five agents |
| `src/multi_agentic_security/pipeline/` | LangGraph orchestration, guardrails, response cache |
| `src/multi_agentic_security/contracts/` | Typed contracts between the agents and for evidence records |
| `src/multi_agentic_security/datasets/`, `evidence_store/` | Source adapters and the evidence store |
| `src/multi_agentic_security/evaluation/` | Cases, scorer, metrics, statistics, held-out runner and report |
| `tests/` | Unit and integration tests (no network) |
| `docs/architecture/` | System architecture and agent contracts |
| `docs/datasets/DATASET_CATALOG.md` | Data sources, versions and licenses |
| `docs/research/` | Frozen evaluation protocol, amendments, splits, held-out plans and freeze records, results |
| `docs/paper/` | The paper and the literature review (IEEE format, LaTeX) |
| `docs/WEB_HANDOVER.md` | Guide for building the web interface (planned) |
| `docs/INTEGRATIONS_PLAN.md` | Plan for developer integrations: MCP server, CLI, GitHub Action (planned) |

## Running the tests

Python 3.13:

```
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider
```

1,321 tests pass without network access.

## Data

The research data is **not** in this repository. It comes from public research datasets (LibHalluBench, Package Hallucination, Ecosyste.ms Typosquatting, You Can't Touch This, OpenSSF Malicious Packages, DataDog manifests, OSV.dev, PyPI MalRegistry listing, PyPI popular packages and real-world manifests), described with sources and licenses in `docs/datasets/DATASET_CATALOG.md`. Some of these sources contain live malware or have no redistribution rights. Do not install or run anything from them.

## Authors

Chandan Prakash Hegde, Gaargi L, Disha T P, Chethan Magudilu Shivanna, and Spoorthi M (Assistant Professor). Department of Information Science and Engineering, Dayananda Sagar College of Engineering, Bangalore, India.

## License

Not yet chosen.
