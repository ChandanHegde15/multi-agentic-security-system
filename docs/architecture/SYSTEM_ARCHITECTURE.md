# System architecture

Status 2026-11-13: **approved as the design baseline (D-025), with the adjustments in section 8 (D-030 to D-042).** No code exists for any of this except the frozen Agent 3 v1 baseline and the package skeleton. Schemas are in `AGENT_CONTRACTS.md`.

The architecture is derived from the research questions (`docs/research/RESEARCH_QUESTIONS.md`), not the other way round. Each agent exists because an experiment needs to switch it, replace it or measure it.

## 1. Design principles

1. **Label families never merge** (D-012). Evidence and findings are carried as separate families from Agent 2 to the final report. There is no single risk flag in the new design.
2. **Only one agent uses an LLM.** Agents 1, 2, 3 and 5 are deterministic. This keeps the experiment's independent variable (the recommender) isolated and makes every other stage reproducible.
3. **Evidence is a record with an ID.** Anything an agent asserts about a package must point to an evidence record with provenance. This is what makes "unsupported claim" measurable.
4. **The verifier does not trust the recommender.** Agent 5 receives the recommendation and re-derives every check from the evidence store. It never reads the LLM's reasoning as fact.
5. **Nothing is installed or executed.** No `pip install`, no `npm install`, no package archives opened, no fixes applied. Output is a report.
6. **Time is explicit.** Every registry lookup has a timestamp. Every run has an evidence cut-off date, which is what enables the temporal hold-out.
7. **Failures are states.** A lookup error or an unparseable LLM answer is a recorded outcome, never a default value.
8. **No infrastructure beyond need.** One Python package, local files, standard-library data structures or SQLite. No vector database, no fine-tuning, no microservices, no message queue.

On "RAG": Agent 4 receives evidence records retrieved by exact key (ecosystem, normalized name, version). This is evidence grounding by lookup. Embedding search is unnecessary because the keys are exact, and a vector index would add a component with no experimental purpose.

## 2. Data flow

```
manifest files
     │
     ▼
Agent 1  Dependency extraction ──────────────► dependency records
     │
     ▼
Agent 2  Evidence collection ────────────────► evidence records per dependency
     │      registry state (time-stamped)        (registry, malicious, withdrawn,
     │      + local evidence store                typosquat pair, advisory)
     ▼
Agent 3  Risk analysis ──────────────────────► findings per family
     │      v1 baseline (frozen) │ v2 (proposed)
     ▼
Agent 4  Recommendation ─────────────────────► recommendation with cited claims
     │      R0 rules │ LLM without evidence │ LLM with evidence
     ▼
Agent 5  Independent verification ───────────► verdict: accept / reject / abstain
     │      deterministic; re-queries the evidence store for the *target*
     ▼
report (per dependency: findings, recommendation, verdict, evidence trail)
```

The evidence store is built offline from the normalized sources with a recorded cut-off date. It is read by Agents 2 and 5 through the same lookup interface but in separate calls: Agent 2 asks about the **input** dependency, Agent 5 asks about the **recommended target**.

## 3. The agents

### Agent 1: dependency extraction

| Item | Proposal |
|---|---|
| Responsibility | Parse manifest files into dependency records. No network, no judgement. |
| Inputs | Paths to `requirements.txt`, `pyproject.toml`, `Pipfile`, `package.json`. Lockfiles are a later extension. |
| Outputs | One record per declared dependency: ecosystem, raw name, normalized name (PEP 503 for PyPI, lower-case for npm), version constraint, source file and line, dependency group. |
| Evidence sources | None. |
| Failure conditions | Unreadable file, unsupported format, malformed entry. Each is reported per file or per entry; other entries are still returned. Non-registry sources (git URLs, local paths) are marked, not dropped. |
| Dependencies | None. |
| Tests | Unit tests per format; real-manifest cases after human review of their gold lists; malformed-input cases. Tests never run an installer. |
| Research metrics | Precision and recall of extracted (name, constraint) pairs against reviewed gold. Supporting only; not tied to an RQ. |

### Agent 2: evidence collection

| Item | Proposal |
|---|---|
| Responsibility | For each dependency, gather evidence records. It reports what sources say and makes no risk judgement. |
| Inputs | Dependency records; evidence cut-off date; registry mode (`live`, `snapshot`, `off`). |
| Outputs | Evidence records grouped by family: `registry_state`, `malicious_report`, `compromised_version`, `withdrawn_report`, `typosquat_pair`, `vulnerability_advisory`. Each has an ID, source, source version, source record ID, version scope, publication date and retrieval time. |
| Evidence sources | Local store built from OpenSSF, DataDog manifests, OSV (GHSA, PYSEC), Ecosyste.ms and YCTT pairs. Registry metadata from PyPI and npm when the owner approves lookups. OSV MAL records are linked to OpenSSF as the same report, not counted twice. |
| Failure conditions | `registry_error`, `registry_rate_limited`, `store_unavailable`, `unsupported_ecosystem`. A failed lookup yields an explicit error record, never "not found". An npm security placeholder (`0.0.1-security`) is recorded as its own state, not as "exists". |
| Dependencies | Agent 1 output; the evidence store. |
| Tests | Lookup tests on a small fixture store; name normalization; version-range matching (PEP 440, semver); the cut-off filter; registry responses mocked from recorded fixtures. |
| Research metrics | Evidence recall per family against the source lists; lookup error rate. Feeds RQ4. |

### Agent 3: risk analysis

| Item | Proposal |
|---|---|
| Responsibility | Turn evidence into findings. |
| v1 baseline | **Frozen** (`src/multi_agentic_security/agents/agent3_risk/baseline_v1/`, D-004): weights 50/20/40, thresholds 0.80/0.90, cut-offs 19/49/74, normalized Levenshtein, 7-name catalogue. Used unchanged as condition C0. An adapter maps Agent 2's registry state to v1's `status` values; the adapter lives outside the v1 package. |
| v2 (proposed) | A separately versioned implementation, to be recorded in `DECISIONS.md` before any code is written. It outputs one finding per family present (`nonexistent`, `typosquat_listed`, `name_similar_to_popular`, `malicious_reported`, `compromised_version`, `vulnerable`, `withdrawn_only`, `no_evidence`), each with its evidence IDs. No combined score. Name similarity against a documented popular-package list is a separate, weaker finding than a listed typosquat pair. |
| Inputs | Agent 2 evidence records. |
| Outputs | v1: its existing `RiskResult`. v2: findings per dependency. |
| Failure conditions | Missing or errored evidence yields `unknown`, never `no_evidence`. |
| Dependencies | Agent 2. |
| Tests | v1: the existing 13 tests, untouched. v2: one test per finding rule; label-separation tests (a malicious report never produces a vulnerable finding, and so on). |
| Research metrics | RQ4: recall and false-positive rate per family, v1 against v2, on dated positives and benign-reference candidates. |

### Agent 4: recommendation

| Item | Proposal |
|---|---|
| Responsibility | Produce one structured recommendation per flagged dependency. |
| Variants | **R0** deterministic rules (baseline). **LLM-U** without evidence in the prompt. **LLM-G** with the dependency's evidence records in the prompt. The variant is a run parameter. |
| Inputs | Dependency, findings, evidence records (R0, LLM-G). |
| Outputs | Action (`remove`, `replace`, `upgrade`, `keep`, `abstain`), optional target package and version, and structured claims that each cite evidence IDs. The raw LLM response is stored. |
| Evidence sources | Only what Agent 2 supplied. The LLM has no tools and no network. |
| Failure conditions | `llm_error`, `llm_timeout`, `schema_violation` (after a bounded number of retries, recorded), `refusal`. None is converted to a default action. |
| Dependencies | Agents 2 and 3; an LLM provider chosen by the owner, with the model version pinned. No fine-tuning. |
| Tests | R0 rule tests; schema validation; prompt-construction tests; LLM calls replaced by recorded responses in tests. |
| Research metrics | Unsafe recommendation rate, unsupported claim rate, citation precision and recall, coverage, target agreement, cost (RQ1–RQ3). |

### Agent 5: independent verification

| Item | Proposal |
|---|---|
| Responsibility | Decide whether a recommendation may be shown. Deterministic; no LLM; does not execute or install anything. |
| Inputs | The recommendation, the original dependency, the evidence store, registry mode. |
| Checks | (1) Schema and action validity. (2) Every cited evidence ID exists and states the claim. (3) Target exists in the registry at lookup time. (4) Target is not reported malicious and not a compromised version. (5) Target is not a listed typosquat variant. (6) Target version is outside every affected range of non-withdrawn advisories. (7) Action is consistent with the findings (for example not `keep` on a reported-malicious package). |
| Outputs | Verdict `accept`, `reject` or `abstain`, with the result of each check and the evidence IDs used. `abstain` is used when a check could not be run (for example a registry error). |
| Evidence sources | The same store as Agent 2, queried for the target. Registry lookup for the target. |
| Failure conditions | Any check that cannot run produces `abstain`, never `accept`. |
| Dependencies | The evidence store. It does not depend on Agent 4's internals. |
| Tests | One test per check, with accept and reject cases; property test that a failed lookup can never yield `accept`. |
| Research metrics | Reduction in unsafe rate (C4 vs C3), false-rejection rate, coverage loss, in-snapshot versus held-out results (RQ1). |

**Limit of "independent".** Agent 5 is independent of the LLM. It is not independent of the evidence: it knows only what the store and the registry know at the cut-off. It cannot detect a malicious package nobody has reported. This must be stated in every description of the system.

## 4. Evaluation harness (not an agent)

The research questions need a component that the five agents must not contain: the **scorer** that decides whether a recommendation was unsafe or unsupported.

| Item | Proposal |
|---|---|
| Responsibility | Score recommendations and verdicts against the **full** evidence, including records published after the run's cut-off. Compute the metrics in `RESEARCH_QUESTIONS.md` §10. |
| Separation | The agents never see post-cut-off evidence; the scorer does. The scorer is not called by any agent. |
| Independence | Its checks must not reuse Agent 5's code path untested: a shared bug would hide itself. Either a separate implementation or a shared one covered by independent hand-checked fixtures. |
| Registry | In held-out experiments the scorer and Agent 5 must not use a live existence check for the target (it leaks later takedowns; `RESEARCH_QUESTIONS.md` §6). |
| Outputs | Per-case scores, per-family tables, raw run records with model version, seed, cut-off and store version. |

## 5. How the architecture maps to the research questions

| Research need | Where it is met | Gap found in the review |
|---|---|---|
| RQ1: verifier on / off | Agent 5 is a separate stage that can be skipped | None |
| RQ1: unsafe properties U-N, U-M, U-T, U-V | Agent 5 checks `target_exists`, `target_not_malicious`, `target_not_typosquat`, `target_version_not_vulnerable` | U-N has no data source until lookups are approved; with `registry_mode: off` the check is `not_run` and every `replace` or `upgrade` becomes `abstain` |
| RQ1: U-K | Agent 5 check `action_consistent` | None |
| RQ1: unsupported claims | Agent 4 structured `claims` with `evidence_ids`; Agent 5 check `claims_supported` | The claim list had no type for a withdrawn report; added to the draft |
| RQ1: held-out scoring | Evidence `published_at` and the run's `evidence_cutoff` | The scorer was missing from the design (now §4); records with no publication date need a rule (added to the draft contract) |
| RQ2: grounded vs ungrounded | Agent 4 `variant` | What the ungrounded variant receives was undefined; now stated, still an open choice |
| RQ3: per family | `family` on evidence, `finding` on Agent 3 v2 output | None; depends on Agent 3 v2 being approved |
| RQ4: v1 vs evidence lookup | Agent 3 v1 through an adapter; Agent 2 lookup | Rules for condition C0 were undefined; now stated in `RESEARCH_QUESTIONS.md` §7. A PyPI popular-package list for name similarity does not exist in the data |
| Actions without a target (`remove`, `keep`, `abstain`) | Agent 5 | Target checks had no "not applicable" result; added to the draft |

## 6. What is deliberately not in the architecture

| Not included | Reason |
|---|---|
| Vector database or embedding retrieval | Evidence is found by exact key |
| Fine-tuned model | Forbidden training data sources; the legacy attempt failed; not needed for the research question |
| Sandboxed install or test execution (legacy Agent 5) | Unsafe on this host and outside the scope |
| Code or metadata malware analysis | No samples may be opened; well covered by prior work |
| Automatic pull requests or merges | D-015; out of scope |
| Microservices, queues, containers | One process is enough |
| Agent-to-agent free-text chat | Agents exchange typed records only, which keeps runs reproducible |

Backend API and frontend remain in the project plan (`PROJECT_BRIEF.md`) but are not part of the research design and are not specified here.

## 7. Decisions

| Topic | Decision |
|---|---|
| Research direction and questions | D-018 |
| Agent 3 v2 | Allowed as a new versioned implementation, D-020 |
| Registry metadata lookups | Allowed, time-stamped, never live for held-out target checks, D-021 |
| Agent 4 LLM | Provider-agnostic; model chosen and pinned before the pilot, D-022 |
| Normalization strategy | D-024 |
| Repository structure, backend and frontend stack | D-026 |

Still open: the Agent 4 model, the pilot design, and the scorer's independence strategy (§4).

## 8. Adjustments after the literature investigation (D-030 to D-041)

The five-agent design of sections 1–7 stands. These adjustments are applied during implementation; where they conflict with earlier text in this document or in `AGENT_CONTRACTS.md`, this section takes precedence until those sections are revised.

| Adjustment | Affects | Reason | Decision |
|---|---|---|---|
| The architecture is not a research claim. The paper is an evaluation study; the agents are the apparatus | Whole document | Multi-agent LLM pipelines with deterministic tools and verifier stages are published | D-031 |
| The evaluation scorer is a separate implementation from Agent 5, with its own tests. They share only the contracts | Section 4 | A shared bug would hide itself | D-036 |
| A `downgrade` action is added for compromised-version cases; Agent 5 checks the target against the listed versions in either direction | Agents 4, 5; contracts | Real incident responses rolled back to earlier versions | D-036 |
| Every `upgrade` or `downgrade` recommendation carries two reported indicators: semver distance from the input version, and whether the declared constraint admits the target. They are reported, not used to reject | Agent 5, scorer | A version outside all affected ranges is not shown to be applicable | D-036 |
| The structured claim schema is a versioned contract in `contracts/`. Agent 4 variants, Agent 5 and the scorer all read the same version | Contracts | Claim support is a headline measurement | D-030, D-036 |
| Agent 4 has four recommender back ends behind one interface: project rules, ungrounded LLM, grounded LLM, and an adapter for an existing audit tool (vulnerable family only) | Agent 4 | External deterministic baseline | D-039 |
| Agent 4's LLM back ends are provider-agnostic and run with three pinned models, one local and open-weight | Agent 4 | Reproducibility | D-038 |
| Agent 5's checks are individually switchable | Agent 5 | Verifier ablation | D-030 |
| The evidence store is time-aware: every record carries its publication date and every query takes a cut-off date. No agent performs a live lookup during an experiment | Agent 2, store | Temporal hold-out; live lookups leak later takedowns | D-021, D-034 |
| Case manifests carry a group key (target package, name cluster) used by the splitter and by resampling | Evaluation harness | Near-duplicate names and copy-cat clusters | D-036 |
| Agent 3 v1 lives at `src/multi_agentic_security/agents/agent3_risk/baseline_v1/`, unchanged | Agent 3 | Repository structure | D-042 |

## 9. System specification (D-047)

The user-facing system follows the specification adopted in D-047: an upload (files, ZIP, folder, public Git repository link, or generated code) passes through Agents 1 to 5 and ends in per-agent dashboard views and a per-dependency trace from the original declaration to the final verdict. Section 8 and the research rules still apply: nothing is installed or executed, Agent 4 is not fine-tuned, live lookups serve user uploads only, and experiments run on the dated evidence snapshot. Contract changes are listed in `AGENT_CONTRACTS.md` (System specification adjustments).
