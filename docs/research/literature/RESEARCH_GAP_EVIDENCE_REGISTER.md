# Research gap evidence register

Status 2026-11-13. One record per proposed gap, with its evidence. Nothing here is an approved claim.

**Evidence levels**

- **A, explicit:** stated by paper authors (statement IDs `EA-nn` are in `EXPLICIT_RESEARCH_GAPS.md`).
- **B, comparative:** visible when papers are compared (`PAPER_COMPARISON_MATRIX.md`).
- **C, potential:** inferred opportunity; not shown to be unexplored.

**Source IDs**

- `Pnnn`: papers in the three archives (`PAPER_INVENTORY.md`).
- `H`, `T`, `M`, `R`, `G` with a number: externally verified sources in `../LITERATURE_REVIEW.md`.
- `X1`–`X4`: sources verified externally in this investigation (`NOVELTY_ASSESSMENT.md` §4).

**Confidence** is confidence that the gap is real in the wider literature, not only in the archives: High, Medium, Low.

A gap marked "not found" was not found in three archives plus two limited web search sessions. That does not establish that no such work exists.

---

## GAP-01. Remediation recommendations for flagged dependencies are not evaluated outside the vulnerable family

| Field | Record |
|---|---|
| Level | **B** (comparative), supported by A statements on neighbouring problems |
| Description | Work on risky dependencies ends at a verdict. Where remediation is evaluated, it is the choice of a non-vulnerable version. No study was found that evaluates a recommended fix (remove, replace, upgrade) for a dependency flagged as nonexistent, typosquatted or reported malicious |
| Supporting sources | P004, P005, P022, P023, P025, P027 (stop at a verdict); P007 (mitigation ends at validation); R1, R3, X1 (version choice only); X3 (code-level mitigation for vulnerable libraries); H5 (regenerate on detection) |
| Pages / sections | P004 p7 (recommendations judged unclear, EA-09); P007 p5–p6 and Table I; P020 p6–p7 (general advice only); `PAPER_COMPARISON_MATRIX.md` §2 |
| What prior work accomplishes | Accurate detection of malicious packages from code; measurement of vulnerable version choices by LLMs and agents (R1, X1); validated code mitigations for vulnerable libraries (X3) |
| What remains unresolved | Whether a recommended replacement or version for a flagged dependency is itself safe and supported, for the N, T and M families |
| Why it matters | A fix is a new dependency decision. H2 and H5 show wrong names can resolve to existing packages; X2 reports hallucinated names that previously hosted malware |
| Explicit or inferred | Inferred from comparison |
| Confidence | **Medium.** Two search sessions found nothing; industry tools and unpublished work are plausible; R1's benchmark may expand |
| Validating experiment | A systematic search (fixed query strings, three databases, snowballing from H1, R1, X1) recorded with dates and counts. Then the pilot: do recommenders ever produce a risky target for N, T, M inputs? |

## GAP-02. Unsupported claims in LLM dependency advice are not measured

| Field | Record |
|---|---|
| Level | **B**, with A support |
| Description | No study was found that measures, per claim, whether statements in an LLM's dependency-security recommendation are supported by identifiable evidence records |
| Supporting sources | P004 (report quality by a three-person Likert survey); P005 (hallucination noted, not measured per claim); P001 (evidence-citation rule, unevaluated); M8 (LLM-reported indicators that were absent); G2 (citation metrics exist in NLP) |
| Pages / sections | P004 p6–p7, Tables IV–VI; P005 p10–p11 (EA-11); P001 p4; P003 p16 (EA-05, EA-06) |
| What prior work accomplishes | Citation precision and recall metrics for open-domain QA (G2); qualitative judgement of security reports (P004); indicator-level accuracy for malware explanations (M8) |
| What remains unresolved | A deterministic, per-claim support rate for dependency recommendations with structured evidence |
| Why it matters | Developers act on stated reasons (a version number, a "this package is malicious" statement). R3 reports about 27.8% nonexistent versions in ungrounded upgrade advice |
| Explicit or inferred | Inferred; the need for automated fact checking is explicit (EA-05, EA-06) |
| Confidence | **Medium.** The metric is borrowed, so novelty is in the application; RAG-faithfulness work in security was not searched systematically |
| Validating experiment | Run the three recommender variants on a fixed case list; score structured claims against the evidence store; report unsupported-claim rate with intervals. Feasible for every family, including those where unsafe targets are rare |

## GAP-03. Independent verification is applied to detections, not to recommendations

| Field | Record |
|---|---|
| Level | **B** |
| Description | "Generate, then verify" exists for detector output (deterministic in P025, LLM-judged in P027) and for hallucinated libraries (H4, H5). No archive paper verifies a remediation; X3 validates code mitigations and R1 proposes validation by tests for version choices |
| Supporting sources | P025, P027, P022, P004, P005; H4, H5, R1, X3 |
| Pages / sections | P025 p1–p2, p5; P027 p7 §3.6 and p8 (ablation); P004 p4 §IV.B; `PAPER_COMPARISON_MATRIX.md` §2 |
| What prior work accomplishes | Verifiers that reduce detector false positives; tools that supply reliable facts to an LLM; validated patches for vulnerable code |
| What remains unresolved | A deterministic check of the *target* of a dependency recommendation across risk families, with its removal and wrong-rejection counts |
| Why it matters | Without it, the last LLM output reaches the user unchecked (as in P004) |
| Explicit or inferred | Inferred |
| Confidence | **Medium-low for novelty of the idea** (the pattern is established and the check is a list and range lookup); **Medium for the measurement** |
| Validating experiment | The planned C3 versus C4 comparison with a temporal hold-out; report removed unsafe recommendations next to wrong rejections and coverage |

## GAP-04. No evaluation spans the four risk families with separate labels

| Field | Record |
|---|---|
| Level | **B**, with A support |
| Description | Each archive paper studies one family. No paper evaluates a method across nonexistent, typosquatted, malicious and vulnerable dependencies while keeping the labels separate |
| Supporting sources | All of T2, T3, T7 in `THEMATIC_ANALYSIS.md`; P010 (EA-31); P004 (EA-10); H7 (several supply-chain threats in LLM output; abstract only) |
| Pages / sections | `PAPER_COMPARISON_MATRIX.md` §4 items 1–2; P010 p3; P004 p7 |
| What prior work accomplishes | Deep single-family results; conceptual argument that the families differ |
| What remains unresolved | Per-family comparison of the same pipeline on the same ecosystem |
| Why it matters | The correct action differs by family; a merged score cannot recommend correctly |
| Explicit or inferred | Inferred; the need for distinct categories is explicit (EA-31) |
| Confidence | **Medium.** H7 must be read in full before this is claimed |
| Validating experiment | Read H7 in full. Build the per-family evidence tables and report case counts per family; the nonexistent family has 34 positives, so this gap is only weakly testable there |

## GAP-05. A wrong package name can resolve to an existing risky package, and existence checks do not address it

| Field | Record |
|---|---|
| Level | **B**, partly A outside the archives |
| Description | The archive literature treats package hallucination as a nonexistence problem solved by an existence check (P007). It does not consider names that exist and are risky |
| Supporting sources | P007 (existence validation as "first-line defense"); H1 (registry lists may contain malicious names); H2 (existence tool insufficient); H5 (about half of flagged names already registered); X2 (at least 23 suggested names previously hosted malware); this project's own count (25 of 1,049 planted LibHalluBench names are reported-malicious PyPI names) |
| Pages / sections | P007 p5 §IV.E.c and Table I p6; `../PROBLEM_DEFINITION.md` §2 |
| What prior work accomplishes | H5 adds a classifier for registered lookalikes; X2 quantifies prior malware under hallucinated names |
| What remains unresolved | A labelled evaluation of the distinction between "nonexistent" and "exists and is reported malicious or a typosquat variant" |
| Why it matters | An existence-only check passes exactly the dangerous case |
| Explicit or inferred | Explicit in H2, H5, X2; inferred for the archives |
| Confidence | **Low as a novelty claim** (already shown by H2, H5, X2). **High as a real problem** |
| Validating experiment | RQ4 as planned: recall of an existence-and-similarity detector against evidence lookup on registry-present positives. Report as corroboration, not as a finding |

## GAP-06. Applicability of an upgrade recommendation is not established by an advisory-range check

| Field | Record |
|---|---|
| Level | **A** |
| Description | A version outside all affected ranges may not be installable under existing constraints, may be a major-version step, and the range itself may be imprecise |
| Supporting sources | P024, P018, P026; R1 (36.8% of agent cases needed a major upgrade); X1 (95.11% of vulnerable pairs have the whole same-major branch affected) |
| Pages / sections | P024 p8 (EA-26), p10 (EA-25); P018 p10–p11 (EA-28); P026 p2 (EA-29) |
| What prior work accomplishes | Measures propagation and constraint effects on npm; time-aware resolution |
| What remains unresolved | For this project: a deterministic verifier that checks ranges says nothing about applicability |
| Why it matters | "Safe" by the project's policy can be unusable in practice; reviewers will ask |
| Explicit or inferred | Explicit |
| Confidence | **High** that the limitation is real; it is a **limitation to disclose**, not a contribution |
| Validating experiment | Report, for each upgrade recommendation, the semver distance from the input version and whether the manifest's declared constraint admits the target. Both are computable without installing anything |

## GAP-07. Benign and malicious ground truth are weak, and historical registry state is not recoverable

| Field | Record |
|---|---|
| Level | **A** |
| Description | Benign labels are assumed from popularity; malicious labels are reporter assertions with overlap and possible errors; removed packages lose their history |
| Supporting sources | P004, P022, P023 (assumed benign); P005, P020 (label quality); P017, P018, P025 (removal) |
| Pages / sections | EA-12, EA-17 to EA-21 |
| What prior work accomplishes | Manual two-person confirmation in P023; takedown as confirmation in P025 and P027 |
| What remains unresolved | No verified-benign set; no registry snapshot for past dates covering removed packages |
| Why it matters | Bounds every unsafe-rate estimate (lower bounds) and blocks existence checks in held-out experiments |
| Explicit or inferred | Explicit |
| Confidence | **High** |
| Validating experiment | None needed; state as threats. A dated upload-time table for surviving packages can be built from registry metadata |

## GAP-08. LLM security analysis merges "insecure" with "malicious"

| Field | Record |
|---|---|
| Level | **A** (single paper) |
| Description | An LLM analyst classified insecure but benign code as malicious |
| Supporting sources | P004; P005 (prompt design to separate malware from vulnerabilities) |
| Pages / sections | P004 p7 (EA-10); P005 p4 |
| What prior work accomplishes | Notes the confusion; scores malware intent and security risk separately (P005) |
| What remains unresolved | Whether an LLM recommender keeps the families apart when given per-family evidence |
| Why it matters | A vulnerable package needs an upgrade; a malicious one needs removal. Confusing them yields the wrong action |
| Explicit or inferred | Explicit observation in two cases (P004) |
| Confidence | **Medium** (small evidence base) |
| Validating experiment | Per-family action confusion matrix: for each input family, the distribution of recommended actions under each recommender variant |

## GAP-09. Whether an LLM adds anything over a rule-based recommender for dependency remediation

| Field | Record |
|---|---|
| Level | **C** (potential), with partial outside evidence |
| Description | Where the evidence states the answer (a typosquat's target, an advisory's fixed version), a rule may be as good as an LLM. Archive papers compare LLMs with deterministic baselines only for detection |
| Supporting sources | P005 (CodeQL baseline; EA-13); P004 (GuardDog baseline); R3 (vendor: deterministic strategies beat an LLM for upgrade versions); a vendor blog found by search reports a no-AI baseline passing 46.9% of dependency-fix tasks (**unverified**, not a paper) |
| Pages / sections | P005 p6–p7, p10; P004 p6 |
| What prior work accomplishes | LLM beats static rules for malware detection (P005, P004); vendor evidence that rules win for versions |
| What remains unresolved | A peer-reviewable comparison for remediation across families |
| Why it matters | If rules suffice, the LLM stage is unnecessary cost and risk; this is a publishable negative result |
| Explicit or inferred | Inferred |
| Confidence | **Medium** that the comparison is unpublished; the likely outcome (rules match the LLM where evidence gives the answer) weakens the "LLM system" story |
| Validating experiment | C1 versus C3 and C4 with a pre-registered non-inferiority margin; coverage on cases where rules abstain |

## GAP-10. Compromised versions need a different remediation direction

| Field | Record |
|---|---|
| Level | **C** |
| Description | For a legitimate package with malicious versions, the correct fix may be a downgrade or pin, not an upgrade |
| Supporting sources | P011 (XZ Utils response was rollback); P020 (`aiocpa` versions 0.1.13 and 0.1.14); P004 (ultralytics compromise) |
| Pages / sections | P011 p3; P020 p3; P004 p2 |
| What prior work accomplishes | Incident descriptions |
| What remains unresolved | Whether recommenders choose a clean version in the right direction |
| Why it matters | An "upgrade" rule or LLM habit is wrong here |
| Explicit or inferred | Inferred from incident reports |
| Confidence | **Low** as a research gap; the project holds only 18 PyPI and 2,074 npm version-scoped records with no independent confirmation |
| Validating experiment | Descriptive only: the action and version direction chosen by each recommender on version-scoped cases |

---

## Summary table

| Gap | Level | Confidence | Testable with data held | Role |
|---|---|---|---|---|
| GAP-01 remediation beyond vulnerable versions | B | Medium | Partly (rare events for M, T; N lacks registry data) | Candidate core gap |
| GAP-02 unsupported claims | B | Medium | **Yes, all families** | Candidate core gap |
| GAP-03 verifying recommendations | B | Medium-low (idea), Medium (measurement) | Partly | Supporting |
| GAP-04 cross-family evaluation | B | Medium | Partly (34 nonexistent positives) | Framing; needs H7 read |
| GAP-05 wrong name resolves to risky package | B | Low as novelty | Yes | Corroboration only |
| GAP-06 applicability of upgrades | A | High | Partly (semver distance, declared constraints) | Limitation to disclose |
| GAP-07 ground truth and history | A | High | — | Threat to validity |
| GAP-08 family confusion by LLMs | A | Medium | Yes | Secondary measurement |
| GAP-09 LLM versus rules for remediation | C | Medium | Yes | Possible negative result |
| GAP-10 compromised-version direction | C | Low | Weakly | Descriptive only |
