# Novelty assessment

Status 2026-11-13. A critical test of the project's proposed direction against the literature. **Nothing here finalises the research question.** The aim was to disprove novelty, not to confirm it.

Direction under test:

> Evaluating whether an independent deterministic verifier reduces unsafe and unsupported remediation recommendations produced by an evidence-grounded LLM, compared with ungrounded LLM and deterministic rule-based recommendation baselines.

## 1. Evidence base and its limits

| Source set | Size | Read depth |
|---|---|---|
| Three archives (`PAPER_INVENTORY.md`) | 26 distinct papers | 5 full, 11 partial, 10 skim or abbreviated |
| Earlier external review (`../LITERATURE_REVIEW.md`) | 28 sources | 3 full text, most abstract only, 3 bibliographic only |
| External check in this investigation (§4) | 4 new sources verified on arXiv records; several more seen only in search results | Abstract or metadata only |

Limits that apply to every verdict below:

- "Not found" means not found in these sources. The archives were assembled around supply-chain security and LLM hallucination in general and contain no paper on remediation, typosquatting or package hallucination measurement.
- Two web search sessions are not a systematic review. No database query log with counts exists yet.
- Abstract-level reads cannot rule out that a paper does something its abstract omits.
- Industry tools (dependency bots, vendor "AI fix" features) do some of this in practice without publishing evaluations.

## 2. The eight elements

Classification scale: **Directly addressed**, **Partially addressed**, **Related but different**, **Not found in the inspected literature**, **Insufficient evidence**.

### E1. Registry-backed package evidence collection

| | Classification | Evidence |
|---|---|---|
| Archives | Partially addressed | P004 queries VirusTotal and the web through tools (p4). P018 reconstructs registry state over time (p1). P007 reports package-existence validation as "a first-line defense" (p5). P020 collects the same malicious-package lists this project holds (p3) |
| With external sources | **Directly addressed** | H1 compares names with dated registry lists; H2 gives the model a PyPI tool; H5 runs a deterministic PyPI check; R3 grounds versions in registry data; T5 uses registry metadata; X2 revalidates names against live registries |

Verdict: **not novel.** Collecting registry and advisory evidence is standard practice.

### E2. Evidence-grounded LLM recommendations

| | Classification | Evidence |
|---|---|---|
| Archives | Related but different | P003 grounds code generation in retrieved repository code (p14–p16). P004 grounds a malware analysis report in tool results. P001 requires each hypothesis to cite evidence, in robotics, without evaluation (p4) |
| With external sources | **Partially addressed** | R3 (vendor) compares ungrounded with registry-grounded upgrade recommendations. X1 reports that "externally anchored version constraints" reduce vulnerable and incompatible versions. H1 and H2 measure grounding at generation time. M7 uses RAG for detection |

Verdict: grounding an LLM's dependency advice is **already shown to help for versions**. What was not found is grounding with per-claim citations to evidence records in a remediation setting. The effect of grounding can be reported only as a replication.

### E3. Deterministic recommendation verification

| | Classification | Evidence |
|---|---|---|
| Archives | Related but different | P025 deterministically verifies *detections* (reproducer, clone detector). P027 verifies detections with sandbox execution and an LLM (p7). P004 uses deterministic tools for intermediate facts only |
| With external sources | **Partially addressed** | H4 applies static analysis to LLM code and measures its ceiling. H5 checks LLM-suggested packages with a deterministic existence check and a classifier. R1 proposes checking agent version choices against advisories and tests. X3 generates mitigation patches that are validated |

Verdict: the **idea is established**. Applying it to the target of a remediation recommendation across risk families was not found, but that is an extension of a known pattern, and the check itself (list and range lookup) is technically simple. Not defensible as a method contribution; defensible only as a measured component.

### E4. Independent validation of recommended replacement packages

| | Classification | Evidence |
|---|---|---|
| Archives | **Not found** | No archive paper recommends or validates a replacement package |
| With external sources | Partially addressed, with **insufficient evidence** on details | H5 validates packages an LLM proposes in generated code, including registered lookalikes, and regenerates on failure (abstract only). T2 (SpellBound) and typosquat detectors identify the likely intended package for a typo, which is a deterministic replacement suggestion (not read; bibliographic record only) |

Verdict: **closest threat to novelty is H5** and typosquat-correction tooling. Both must be read in full before any claim. The difference that may survive: validating a *remediation's* replacement against malicious, typosquat and advisory records together, with a hold-out.

### E5. Comparison of rule-based and LLM-based remediation

| | Classification | Evidence |
|---|---|---|
| Archives | Related but different | P005 compares LLMs with CodeQL rules, and P004 with GuardDog heuristics, for *detection* |
| With external sources | **Partially addressed** | R3 (vendor, not peer-reviewed) compares an LLM with deterministic strategies for upgrade versions and reports the deterministic strategies ahead. A vendor blog seen only in search results reports a no-AI baseline for dependency fixes (**unverified**) |

Verdict: a peer-reviewed comparison for remediation was not found; vendor evidence already suggests the likely answer for versions. A negative result for the LLM is plausible and should be planned for.

### E6. Measurement of unsupported recommendation claims

| | Classification | Evidence |
|---|---|---|
| Archives | **Not found** | P004 rates report accuracy with three practitioners on a Likert scale (p7). P005 notes hallucination without per-claim measurement (p10–p11). P006 uses LLM judges for faithfulness in another task |
| With external sources | Related but different | G2 defines citation precision and recall for question answering. M8 reports that LLMs named malware indicators that were absent. R3 counts nonexistent versions |

Verdict: **the least covered element.** The metric is borrowed from G2; its application to dependency remediation with structured, record-level evidence was not found. Faithfulness of RAG output in security settings was **not searched systematically**, so confidence is medium.

### E7. Measurement of unsafe replacement recommendations

| | Classification | Evidence |
|---|---|---|
| Archives | **Not found** | — |
| With external sources | **Partially addressed** (versions); not found (packages) | R1: agents chose known-vulnerable versions in 2.46% of changes. X1: 36.70%–55.70% of tasks contained an LLM-specified version with a known CVE (abstract). R3: about 27.8% nonexistent versions. X4: coding agents can be steered toward an attacker-controlled package (an attack study). H2, X2: wrong or hallucinated names that exist or previously hosted malware |

Verdict: **for vulnerable and nonexistent versions this is already measured, at larger scale than this project can reach.** X1 in particular overlaps the U-V metric. What was not found is the measurement in a *remediation* setting (the input is a flagged dependency and the output is a fix) and for targets that are reported malicious or typosquat variants. Whether such targets occur often enough to measure is unknown; the pilot decides.

### E8. Evaluation across hallucinated, typosquatted, malicious and vulnerable categories

| | Classification | Evidence |
|---|---|---|
| Archives | **Not found** | Every archive paper is single-family; P020 only counts two families side by side; P010 argues conceptually |
| With external sources | **Insufficient evidence** | H7 studies eleven supply-chain threats in LLM-generated code with a prompt defence and a warning middleware (abstract only). It may cover several families |

Verdict: cannot be claimed until H7 is read in full.

## 3. Summary of the test

| Element | Archives | With external sources | Can it be claimed as new? |
|---|---|---|---|
| E1 registry-backed evidence | Partially | Directly addressed | **No** |
| E2 evidence-grounded LLM recommendations | Related | Partially addressed | No; replication only |
| E3 deterministic verification | Related | Partially addressed | Not as an idea; as a measured component |
| E4 validation of replacement packages | Not found | Partial; insufficient evidence | Not yet; read H5 and T2 first |
| E5 rules versus LLM for remediation | Related | Partially (vendor) | Possibly, as a comparison; expect a negative result |
| E6 unsupported claims | Not found | Related but different | **Most defensible** |
| E7 unsafe replacement recommendations | Not found | Partially (versions) | Only for the remediation setting and non-vulnerable families |
| E8 cross-family evaluation | Not found | Insufficient evidence | Not yet; read H7 first |

**Overall.** No component of the direction is new. Multi-agent design, LLM use, retrieval, registry lookup, a deterministic tool beside an LLM, a verifier stage and a deterministic baseline all have published precedents, several of them inside the archives (P004, P005, P025, P027). The direction is defensible only as an **evaluation**: a measurement of recommendation properties that prior work does not report. Two of those properties were not found measured anywhere in the sources inspected: per-claim evidence support (E6), and risky targets of remediation outside the vulnerable family (E7, part). The remainder would be replication or framing.

## 4. External literature verification

### 4.1 Verified in this investigation (arXiv record read on 2026-11-13; abstract or metadata only)

| ID | Work | Record | Verified | Relevance |
|---|---|---|---|---|
| X1 | Wang, Wu, Ling, Luo, Zhao. "Correct Code, Vulnerable Dependencies: A Large Scale Measurement Study of LLM-Specified Library Versions" | arXiv:2605.06279, submitted 7 May 2026; no venue in the comments field | Title, authors, date; abstract in summary | **Narrows E7 and E2.** 10 LLMs, 1,000 Stack Overflow tasks (PinTrace); many LLM-specified versions carry known CVEs; external anchoring of version constraints reduces vulnerabilities and compatibility failures. Figures quoted in §2 come from a search summary of the abstract and need a direct read |
| X2 | Churilov. "The Range Shrinks, the Threat Remains: Re-evaluating LLM Package Hallucinations on the 2026 Frontier-Model Cohort" | arXiv:2605.17062, v1 16 May 2026, v4 9 November 2026; comments mention an earlier SCORED '26 version | Title, author, dates; abstract in summary | Replication of H1 on five models, 199,840 generations; hallucination rate 3.6–5.0% of package mentions; at least 23 suggested names had previously hosted malware later removed; one hallucinated name was registered with malware after the runs. **Narrows GAP-05** and weakens "hallucinated names never become malware" as much as it weakens the opposite |
| X3 | Chen, Hu, Sun, Xia, Yang. "Generating Mitigations for Downstream Projects to Neutralize Upstream Library Vulnerability" (LUMEN) | arXiv:2503.24273, v1 31 March 2025, v2 21 October 2026; comments field: "TOSEM" | Title, authors, dates; abstract in summary | **LLM remediation with validation already exists for vulnerable libraries**, at code level: 474 impacted functions, 94 vulnerabilities, 82.91% mitigated. Different from dependency-level recommendation, but it removes any claim that "validated LLM remediation" is new |
| X4 | Liu, Hsu, Huang, Backes, Wen, Yu. "Trust Me, Import This: Dependency Steering Attacks via Malicious Agent Skills" | arXiv:2605.09594, submitted 10 May 2026; no venue listed | Title, authors, date; abstract in summary | Treats an agent's package recommendation as a supply-chain decision that can be attacked. Related threat model; not remediation |

### 4.2 Seen only in search results (not verified; do not cite)

- A vendor blog on agents fixing vulnerable dependencies, with a no-AI baseline.
- arXiv:2508.21417 (vulnerable dependencies in LLM project repositories), arXiv:2501.16191 (LLMs fixing Python dependency conflicts), arXiv:2506.17798 (reachability analysis of vulnerable dependencies), arXiv:2607.13965 (a multi-agent npm malware detector, known only from a blog).
- Vendor white papers on grounding AI dependency upgrades.

### 4.3 Most important literature still to obtain and read in full

Ranked by how likely each is to change the verdicts above.

| Priority | Work | Why |
|---|---|---|
| 1 | H5, Raj and Sahu (arXiv:2608.23897) | Closest to E4: checks LLM-suggested packages, including registered lookalikes |
| 2 | X1, Wang et al. (arXiv:2605.06279) | Closest to E7 and E2 for versions; need its definitions, anchoring conditions and data |
| 3 | R1, Singla et al. (arXiv:2601.00205) | Closest remediation benchmark; check whether it has been extended or released |
| 4 | H7, Li and Gao (arXiv:2509.20277) | Decides E8 |
| 5 | T2 SpellBound and T3 Neupane et al. | Whether typosquat tools already output the intended package (E4) |
| 6 | Work on faithfulness and attribution of RAG output in security advice; FActScore and SelfCheckGPT style metrics | Decides E6; not searched yet |
| 7 | Studies of automated dependency update tools and "AI fix" features | E5; grey literature likely |
| 8 | X3 LUMEN full text | How validation is done; whether dependency-level remediation is a baseline |

### 4.4 Separation of sources

| Category | Sources |
|---|---|
| In the three archives, full text reviewed | P002, P004, P007, P017, P020 |
| In the three archives, partially reviewed | P001, P003, P005, P006, P010, P011, P012, P018, P022–P027 |
| In the three archives, skimmed | P008, P009, P013–P016, P019 |
| External, full text reviewed (earlier review) | H1, H2, R1 |
| External, abstract or metadata only | All other entries of `../LITERATURE_REVIEW.md`; X1–X4 |
| External, search result only | §4.2 |

## 5. Strongest arguments against the project's novelty

A reviewer could reasonably say each of the following. None is refuted yet.

1. **"The verifier is a lookup."** Rejecting a target that appears on a list the system already holds is trivial, and in-snapshot results are circular. Only a temporal or source hold-out says anything, and for malicious and typosquat targets hold-out events may be too rare to measure.
2. **"Grounding is known to help."** H1, H2, R3, X1 and P003 show it. The grounded-versus-ungrounded comparison is a replication.
3. **"Vulnerable-version choice is already measured at scale."** R1 (117,062 dependency changes) and X1 (10 models, 1,000 tasks) exceed what this project can do.
4. **"For malicious packages the remediation is 'remove'."** There is little for an LLM to get wrong, so the families beyond vulnerable may show no effect.
5. **"A rule-based recommender suffices."** Where a source states the target or the fixed version, rules are exact. R3 points this way.
6. **"The evaluation policy is self-defined."** No gold recommendations exist; "unsafe" and "unsupported" are project definitions, and P024 shows a range-safe upgrade is often not applicable.
7. **"34 nonexistent positives."** The family that motivates the LLM connection has almost no data.
8. **"External safeguards are the wrong layer."** P007 asks for mitigation inside models and tooling (EA-04).
9. **"Multi-agent is decoration."** P004 already shows the pattern, with an ablation against a single agent, which this project does not plan.

## 6. What survives

1. **Per-claim evidence support in dependency remediation advice** (E6, GAP-02): not found measured; deterministic; feasible in every family; does not depend on rare events.
2. **Remediation framed as a new dependency decision, scored by properties, with the cost of verification reported** (E7 in the remediation setting, GAP-01, GAP-03): the framing and the paired removal versus wrong-rejection accounting were not found. Strength depends on the pilot.
3. **A comparison of rule-based and LLM recommenders for remediation in which a negative result is acceptable** (E5, GAP-09).
4. **Separate treatment of four families on one ecosystem** as the organising design (E8), pending a full read of H7.

These are candidates for review. `CONTRIBUTION_CANDIDATES.md` assesses them, and `DATASET_FEASIBILITY_MAPPING.md` checks them against the data.

## Sources consulted for §4

- https://arxiv.org/abs/2605.06279
- https://arxiv.org/abs/2605.17062
- https://arxiv.org/abs/2503.24273
- https://arxiv.org/abs/2605.09594
- https://arxiv.org/abs/2601.00205
- https://arxiv.org/abs/2608.23897
- https://www.sonatype.com/state-of-the-software-supply-chain/2026/ai-agents
