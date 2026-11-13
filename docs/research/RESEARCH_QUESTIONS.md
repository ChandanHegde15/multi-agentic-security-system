# Research questions and evaluation design

Status 2026-11-13: **approved in the narrowed form** (D-030), replacing the broad form of D-018. Evaluation additions approved in D-032, D-033 and D-037 to D-041. The study is framed as an **evaluation study** (D-031).

Why it was narrowed: `literature/NOVELTY_ASSESSMENT.md`, `literature/CONTRIBUTION_CANDIDATES.md` and `literature/DATASET_FEASIBILITY_MAPPING.md`. In short, no component of the system is new, the broad four-family question is not supported by the data, and three measurements were not found in the inspected literature.

Background: `PROBLEM_DEFINITION.md` (data and scope), `LITERATURE_REVIEW.md` and `literature/PAPER_INVENTORY.md` (sources), `FOUNDATION_REVIEW.md` (known weaknesses).

## 1. What changed from the D-018 version

| D-018 version | Now |
|---|---|
| One primary question about the verifier across four families | Three headline measurements; families other than vulnerable are reported descriptively |
| The pilot decides whether to narrow | Narrowing adopted; the pilot estimates rates and power (D-023) |
| One LLM, to be chosen | Three pinned LLMs from different families, one open-weight and local (D-038) |
| Project-written rule baseline only | Plus one existing audit tool as an external baseline (D-039) |
| Vulnerable inputs built from advisory ranges | Dependency pins from real public projects dated before the cut-off (D-040, D-041) |
| Automatic property metrics only | Plus a human-judged validation sample (D-037) |
| Scorer independence listed as open | Scorer implemented independently of Agent 5 (D-036) |

## 2. Research questions

**RQ1 (primary). How reliable are remediation recommendations for flagged dependencies, and what do evidence grounding and deterministic verification change?** It is answered by three measurements:

- **RQ1a (claim support).** How often are the structured claims in a remediation recommendation unsupported by the evidence records they cite, for a rule-based recommender, an LLM without evidence, an LLM with evidence, and the latter with a verifier? All four families; PyPI and npm where data exist.
- **RQ1b (rules versus LLM).** Is an evidence-grounded, verified LLM recommender non-inferior to deterministic recommenders (the project's rules and an existing audit tool) on unsafe and unsupported rates, and does it add coverage where the deterministic recommenders abstain? A negative answer is an acceptable result (D-032).
- **RQ1c (verifier, vulnerable family, PyPI).** How much does a deterministic verifier reduce recommendations whose target version lies in an affected range of an advisory published after the system's cut-off date, and how many acceptable recommendations does it reject?

**Supporting**

- **RQ2 (grounding).** How do unsafe and unsupported rates change when the LLM is given evidence records? A replication-style check; grounding is already known to help (`LITERATURE_REVIEW.md` H1, H2, R3; `literature/NOVELTY_ASSESSMENT.md` X1).
- **RQ3 (families).** How do actions, rates and the verifier's effect differ across the four families? Descriptive, with event counts; no inferential claim for the nonexistent, typosquat and malicious families unless the pilot shows enough events.
- **RQ4 (detection precondition).** How many registry-present typosquats and reported-malicious packages does an existence-and-similarity detector (Agent 3 v1) miss compared with evidence lookup, at what false-positive rate on benign-reference candidates? Corroboration of known results, not a contribution.

## 3. Definitions

A **recommendation** is a structured record: an action from a closed set, an optional target package and version, and a list of claims, each citing evidence record IDs.

| Action | Meaning |
|---|---|
| `remove` | Delete the dependency |
| `replace` | Use a different named package |
| `upgrade` | Use a later version of the same package |
| `downgrade` | Use an earlier version of the same package (compromised-version cases, D-036) |
| `keep` | No change needed |
| `abstain` | Evidence is insufficient to recommend |

A recommendation is **unsafe** if it has any of these properties when scored against the full evidence, including evidence the system did not see (§6). Each is reported separately.

| Code | Property | Role |
|---|---|---|
| U-V | Target version lies in an affected range of a non-withdrawn advisory | **Headline (RQ1c)** |
| U-M | Target package or version is reported malicious or a compromised version | Descriptive |
| U-T | Target is a listed typosquat variant | Descriptive |
| U-K | Action is `keep` for a dependency whose flag is supported by evidence | Descriptive |
| U-N | Target package or version does not exist at the recorded time | Scored only where a dated version list exists; not scored for removed packages |

A claim is **unsupported** if it cites no evidence record, cites a record that does not exist, or cites a record that does not state what is claimed. Only structured claims are scored (package X is reported malicious in record R; version V is the first fixed version in record R; X is a variant of Y in record R). The share of each output that is free text outside the claim schema is reported, and a sample of it is audited by hand.

These definitions are a **project-defined evaluation policy**, not ground truth about what a developer should do. The human-judged sample (§9) measures how well the policy agrees with human judgement.

Limits of the policy that are stated with every result: a version outside all affected ranges may not be installable under the project's constraints, advisory ranges often lack a lower bound, and "not listed" is not "safe" (`literature/RESEARCH_GAP_EVIDENCE_REGISTER.md` GAP-06, GAP-07).

## 4. Hypotheses

IDs `HYP1`–`HYP4` and `HYP6` are kept from the earlier version; HYP5 was dropped by D-018 and is not reused. HYP7 is new.

| ID | Hypothesis | Question | Falsified if |
|---|---|---|---|
| HYP1 | The verifier lowers the held-out U-V rate of the grounded LLM (C4 < C3) | RQ1c | The paired difference is not below zero at the chosen level |
| HYP2 | The verifier removes more unsafe recommendations than it wrongly rejects, counted on the same cases | RQ1c | Wrong rejections are at least as many as removed unsafe recommendations |
| HYP3 | Grounding lowers the unsupported-claim rate and the unsafe rate (C3 < C2) | RQ1a, RQ2 | No reduction |
| HYP4 | The grounded, verified LLM is non-inferior to the deterministic recommenders on the unsafe rate (margin fixed before any run) and has higher coverage where they abstain | RQ1b | It is worse beyond the margin, or adds no coverage |
| HYP6 | Evidence lookup detects registry-present typosquats and reported-malicious packages that Agent 3 v1 scores low | RQ4 | Agent 3 v1 recall on registry-present positives is not lower |
| HYP7 | The grounded LLM has a non-zero unsupported-claim rate that the claim check in the verifier removes | RQ1a | The grounded rate is already indistinguishable from zero |

HYP4 and HYP7 may well be false. If the deterministic recommenders are as safe and as complete, or if a grounded model with structured output makes no unsupported claims, those are the findings.

## 5. Variables

**Independent**

| Variable | Levels |
|---|---|
| Recommender | Project rules (R0); external audit tool (vulnerable family only); LLM without evidence; LLM with evidence |
| Verifier | Off; on; and each check alone (ablation) |
| LLM | Three pinned models from different families, one open-weight and run locally (D-038) |
| Risk family of the input | Vulnerable; typosquat; malicious (and compromised version); nonexistent; benign reference |
| Ecosystem | PyPI (all families); npm (typosquat, malicious) |
| Cut-off date | Several dates, fixed in the protocol |

**Dependent.** Unsupported-claim rate; citation precision and recall; unsafe rate by code; coverage; verifier wrong-rejection rate; target agreement where a source states the answer; semver distance and declared-constraint compatibility of each upgrade target; detection recall and false-positive rate (RQ4); tokens and latency.

**Controlled.** Evidence snapshot and cut-off; prompts; temperature and seeds; lookup times; the case list and its split.

## 6. Avoiding circular evaluation

If Agent 5 rejects anything on list L and "unsafe" means "on list L", the verifier scores perfectly by construction. Controls:

1. **Temporal hold-out.** Agents 2–5 see only evidence published before the cut-off T. Unsafe properties are scored with evidence published at any time. Advisory publication dates are in the records, so this is valid for U-V.
2. **In-snapshot and held-out results are reported separately.** In-snapshot results only show that the verifier is implemented correctly.
3. **Several cut-off dates.** Advisory dates skew to 2026, so a single cut-off could drive the result.
4. **Independent scorer.** The scorer is written separately from Agent 5 and has its own tests (D-036).
5. **No live lookups in held-out runs.** A package reported after T has usually been removed since; a live existence check would read the takedown. Existence is checked only against dated version lists retrieved once and time-stamped (D-021, D-034).
6. **Benign-reference controls** in every experiment, to measure false rejections.
7. **Development and test sets.** Prompts, rules and the claim schema are developed on a development set. The test set is frozen before any LLM run and used once. Cases sharing a target package or a near-duplicate name stay on the same side (D-036). LibHalluBench is evaluation-only and never in the development set.
8. **Protocol frozen and hashed** before the main runs: cases, splits, cut-offs, prompts, model versions, metrics and the non-inferiority margin.

Remaining weakness: an LLM may have seen the public lists during training. It cannot be excluded; cut-offs after each model's stated training date reduce it, and the dates are reported.

## 7. Experimental conditions

| ID | Detection | Recommender | Verifier | Purpose |
|---|---|---|---|---|
| C0 | Agent 3 v1 (frozen) | Rules on v1 signals only | Off | Legacy-style baseline (RQ4) |
| C1 | Evidence lookup | Project rules (R0) | Off | Deterministic baseline |
| C2 | Evidence lookup | LLM, no evidence records | Off | Ungrounded LLM |
| C3 | Evidence lookup | LLM with evidence | Off | Grounded LLM |
| C4 | Evidence lookup | LLM with evidence | On | Grounded and verified LLM |
| C5 | Evidence lookup | Project rules (R0) | On | Does the verifier matter without an LLM? |
| C6 | Tool's own advisory data, pinned | Existing audit tool (`pip-audit` or OSV-Scanner, version-pinned) | Off | External deterministic baseline, vulnerable family only (D-039) |

C2–C4 are run for each of the three LLMs.

Comparisons: C2, C3, C4 against C1 on claim support (RQ1a); C4 against C1 and C6 (RQ1b, HYP4); C4 against C3 (RQ1c, HYP1, HYP2); C3 against C2 (RQ2, HYP3); per-family breakdown (RQ3); C0 against C1 detection (RQ4, HYP6). Verifier ablation: each check alone on C3 outputs.

**R0 rules.** Nonexistent: `remove`, or `replace` if a pair source names a target. Typosquat with a stated target: `replace` with the target. Reported malicious: `remove`. Compromised version: `downgrade` or `upgrade` to a version outside the listed versions if the evidence names one, otherwise `abstain`. Vulnerable: `upgrade` to the lowest fixed version stated in the advisory. No evidence: `keep`.

**External tool.** Run only on pinned requirement lists built for the evaluation, in a mode that does not download or install the audited packages, and never on manifests from the datasets (D-039). Its advisory database is pinned to the cut-off where the tool allows it; if it does not, the tool is compared in-snapshot only and this is stated.

## 8. Evaluation sets

All counts are upper bounds before review, de-duplication and splitting. No source is approved for evaluation yet; each is approved individually after normalization.

| Family | Cases | Source | Status |
|---|---|---|---|
| Vulnerable (headline) | Dependency pins from real public projects dated before the cut-off that fall in an advisory range; advisories with a fixed version | Real-project pins (to acquire, D-041); OSV PyPI | Sampling rule in `RESEARCH_METHODOLOGY.md` §7, to be confirmed before retrieval |
| Typosquat | 406 npm pairs; Ecosyste.ms PyPI and npm pairs after per-row review | YCTT, Ecosyste.ms | Review task approved (D-033) |
| Malicious | Sample of 11,992 PyPI reports and the DataDog manifests, stratified by publication year | OpenSSF, DataDog | Held |
| Nonexistent | 34 human-confirmed hallucinated names | Package Hallucination | Held; intervals will be wide |
| Induced hallucination, end to end | LibHalluBench prompts run through an LLM; evaluation only | LibHalluBench | Held; template artefact to resolve or exclude |
| Benign reference | Popular packages; dependencies in real manifests | Popular-package list (to acquire), real manifests | Candidates only, not verified safe |

Prerequisites: normalization (D-024); the acquisitions in D-041; pinned models and tool; the annotation tasks in §9.

## 9. Human annotation

| Task | Size | Purpose | Decision |
|---|---|---|---|
| Ratings of recommendations as acceptable or not | About 150–200, stratified by family and condition | Validate the automatic metrics | D-037 |
| Audit of the automatic claim matcher | About 200 claims | Show the unsupported-claim check is correct | D-033 |
| Per-row review of Ecosyste.ms pairs | 132 rows | Use as typosquat cases | D-033 |
| Imitated package for overlapping LibHalluBench names | 34 names | Descriptive analysis of wrong names that resolve to risky packages | D-033 |

Rules: `ANNOTATION_GUIDELINES.md`. Two annotators where possible, guidelines fixed first, agreement reported, labels stored as project-created annotations separate from source labels. Raters do not see which condition produced a recommendation.

## 10. Metrics and statistics

| Metric | Definition | Used for |
|---|---|---|
| Unsupported-claim rate | Unsupported structured claims / all structured claims | RQ1a, RQ2 |
| Citation precision, recall | As in ALCE (G2), adapted to evidence record IDs | RQ1a |
| Unsafe rate | Unsafe recommendations / non-abstain recommendations, per code and family; held-out and in-snapshot separately | RQ1b, RQ1c, RQ3 |
| Coverage | Non-abstain recommendations / cases | RQ1b |
| Verifier wrong-rejection rate | Rejected recommendations with no unsafe property under full evidence / all such recommendations; reported with the count of removed unsafe recommendations | RQ1c |
| Target agreement | Share of typosquat cases where `replace` names the source-stated target (LLM conditions only; the rules copy the source) | RQ3 |
| Upgrade applicability indicators | Semver distance from the input version; whether the declared constraint admits the target | Disclosure (GAP-06) |
| Agreement with human ratings | Cohen's kappa between annotators; agreement between automatic "unsafe or unsupported" and "not acceptable" | Validity |
| Detection recall, false-positive rate | Per family, on dated positives and benign-reference candidates | RQ4 |
| Cost | Tokens, latency | Reporting |

Statistics: paired comparisons on the same cases (McNemar for binary outcomes); non-inferiority test for HYP4 with a pre-set margin; bootstrap 95% confidence intervals resampled by target-package group; Holm correction across families and models; effect sizes with every p-value; repeated runs over fixed seeds with variance reported; power estimated from the pilot. Families are never pooled into one headline number. An error analysis categorises a sample of failures by hand.

## 11. Threats to validity

| Threat | Mitigation or disclosure |
|---|---|
| Circular labels | §6 |
| Self-defined evaluation policy | Human-judged sample; stated as a policy |
| "Not listed" treated as safe | Unsafe rates are lower bounds |
| Advisory ranges imprecise; upgrade may not be applicable | Applicability indicators reported; no claim of compatibility |
| Rare events outside the vulnerable family | Descriptive reporting with counts; no inferential claim |
| 34 nonexistent positives | Intervals reported; no generalisation |
| Non-independent malicious sources | No cross-source voting; de-duplication by normalised name |
| LLM nondeterminism and drift | Pinned versions, fixed seeds, stored raw outputs, one local open-weight model |
| LLM training-data leakage of public lists | Cannot be excluded; cut-offs after training dates |
| Structured claims hide free-text errors | Free-text share reported and audited |
| Removed packages have no history | Existence not scored for them |
| PyPI-centric | Ecosystem limits stated per family |
| Benign references are candidates | Reported as "candidate" false rejections |
| Literature gap rests on a limited search | Logged systematic search before the paper (D-035) |

## 12. What the data can answer

| Question | Answerable? | Missing |
|---|---|---|
| RQ1a claim support | Yes, after normalization | Claim schema; pinned models |
| RQ1b rules versus LLM | Yes for typosquat and vulnerable; trivial for malicious; weak for nonexistent | Margin fixed in the protocol |
| RQ1c verifier, vulnerable, PyPI | Yes after acquisition | Version lists with upload times; real-project pins; effect size unknown until the pilot |
| RQ2 grounding | Yes | — |
| RQ3 families | Descriptively | Events may be too few for inference |
| RQ4 detection precondition | Yes for typosquat and malicious | Popular-package list; dated existence for PyPI names |

Ground truth that does not exist in the data and will not be invented: the intended package for a wrong name; a safe label for any package; a correct recommendation for any case; a structured attack type; registry state at a past date for removed packages.
