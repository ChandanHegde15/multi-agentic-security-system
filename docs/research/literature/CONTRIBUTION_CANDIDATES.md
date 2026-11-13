# Contribution candidates

Status 2026-11-13. Six candidate contributions, assessed and ranked by **defensibility and feasibility**, not by how impressive they sound. None is selected; the choice is the owner's.

Inputs: `NOVELTY_ASSESSMENT.md` (what survives the novelty test), `RESEARCH_GAP_EVIDENCE_REGISTER.md` (gap IDs), `DATASET_FEASIBILITY_MAPPING.md` (data support), `../RESEARCH_QUESTIONS.md` (current RQ1–RQ4, conditions C0–C5).

Multi-agent architecture, retrieval and the use of an LLM are not offered as contributions anywhere below. Each has a published precedent (P004, P003, P005, M6, M7).

## Ranking

| Rank | Candidate | Defensibility | Feasibility with data held | Main dependency |
|---|---|---|---|---|
| 1 | CC-1 Evidence support of claims in dependency remediation advice | Medium-high | **High** | A fixed structured-claim schema |
| 2 | CC-3 Rule-based versus LLM recommender, negative result allowed | Medium-high | **High** | Pre-registered margin |
| 3 | CC-2 Risky remediation targets and the cost of deterministic verification (vulnerable family, PyPI) | Medium | Medium | Pilot; hold-out design; registry data |
| 4 | CC-5 Wrong names that resolve to reported-risky packages | Medium (corroboration) | High | None; data analysis |
| 5 | CC-6 Provenance-preserving multi-family evidence set | Low-medium | Medium | Licences; cannot redistribute all sources |
| 6 | CC-4 Full four-family verifier evaluation (current RQ1, broad form) | Low | **Low** | Rare events; no registry history; 34 positives |

CC-1, CC-2 and CC-3 come from the **same experiment** (conditions C1–C5) and differ in which measurement carries the paper. CC-5 needs no LLM.

---

## CC-1. Evidence support of claims in dependency remediation advice

**Statement.** Measure, per structured claim, how often an LLM's remediation recommendation cites an evidence record that exists and states what is claimed; compare ungrounded, grounded and verified variants and a rule-based recommender.

| Aspect | Assessment |
|---|---|
| Difference from previous research | No inspected source measures per-claim evidence support for dependency advice. P004 judges report quality with a three-person survey; P005 notes hallucination without measuring it per claim; M8 measures absent indicators for malware explanations; R3 counts nonexistent versions; G2 defines the metric for question answering |
| Supporting literature | GAP-02; EA-05, EA-06 (P003), EA-09 (P004), EA-11 (P005); G2, M8, R3 |
| Feasibility | High. Deterministic scoring against record IDs; no rare-event problem; works in all four families and both ecosystems |
| Dataset requirements | The normalised evidence store with stable record IDs (OpenSSF, OSV, DataDog, typosquat pairs). All held |
| Ground-truth requirements | **None beyond the source records.** A claim is supported if the cited record says it. No human labels of "correct advice" are needed. A small human audit of the claim parser (for example 200 claims, two annotators) is advisable to show the automatic check is right |
| Implementation complexity | Medium. Closed claim schema, structured output from the LLM, deterministic matcher, independent scorer |
| Evaluation methodology | Unsupported-claim rate; citation precision and recall; paired comparison across variants on the same cases; bootstrap intervals grouped by target package; per-family reporting |
| Expected measurable outcome | Rates per variant and family, for example grounded lower than ungrounded, and what remains after verification. Any outcome is reportable |
| Main risks | (a) With structured output and exact-key evidence, a strong model may be near zero unsupported, leaving little to show. (b) Free-text claims are excluded, so real unsupported statements may hide in prose. (c) Faithfulness literature in security was not searched systematically |
| Likely reviewer objection | "The metric is ALCE applied to a new domain." Answer: yes; the contribution is the measurement and the released protocol, not the metric. "Structured claims are an artificial setting." Answer: disclose, and report the share of output that is free text |

## CC-3. Rule-based versus LLM recommender, with a negative result allowed

**Statement.** For flagged dependencies, test whether a grounded LLM recommender is non-inferior to a deterministic rule-based recommender on unsafe and unsupported rates, and whether it adds coverage where rules abstain.

| Aspect | Assessment |
|---|---|
| Difference from previous research | Archive papers compare LLMs with deterministic baselines for detection only (P005, P004). For remediation only vendor evidence exists (R3) |
| Supporting literature | GAP-09; EA-13 (P005); R3; P024 and P018 on what "upgrade" involves |
| Feasibility | High. The rule recommender is fully determined by the evidence; the same cases serve both |
| Dataset requirements | Typosquat pairs with stated targets; advisories with fixed versions; malicious lists. All held |
| Ground-truth requirements | Source-stated targets and fixed versions as reference points for agreement. No gold recommendations |
| Implementation complexity | Low for the rules; medium overall |
| Evaluation methodology | Non-inferiority test with a margin fixed before any run; coverage on rule-abstain cases; per family |
| Expected measurable outcome | Either "the LLM adds coverage at no safety cost" or "rules are as good and cheaper". Both are publishable; the second is the more likely for families where the evidence states the answer |
| Main risks | The honest result may be that the LLM is unnecessary, which undercuts a system built around one. Rule-abstain cases may be few |
| Likely reviewer objection | "The rules win by construction because the metrics are defined on the same evidence." Answer: hold-out scoring, and target agreement reported separately from safety |

## CC-2. Risky remediation targets and the cost of deterministic verification

**Statement.** Treat a remediation as a new dependency decision. Measure how often a recommended target version lies in an affected range of an advisory published after the system's cut-off, and how many such recommendations a deterministic verifier removes against how many acceptable ones it rejects. Scope: vulnerable family on PyPI; other families reported descriptively.

| Aspect | Assessment |
|---|---|
| Difference from previous research | R1 and X1 measure vulnerable version choices in code generation and pull requests, at larger scale. Not found: the remediation setting (input is a flagged dependency), and paired accounting of removed unsafe recommendations against wrong rejections and coverage. P003 shows a mitigation can damage correct outputs, which motivates the accounting |
| Supporting literature | GAP-01, GAP-03, GAP-06; EA-01, EA-02 (P007), EA-25, EA-26 (P024); R1, R3, X1 |
| Feasibility | Medium. Needs a cut-off date, dated advisories (held: 6,853 non-withdrawn GHSA and PYSEC records published in 2026) and version lists per package (**not held**; approved metadata lookups can supply them for surviving packages) |
| Dataset requirements | OSV PyPI advisories with publication dates and ranges; per-package version lists with upload times; a decision on how input versions are chosen from advisory ranges |
| Ground-truth requirements | Advisory ranges as the reference, with their known imprecision (EA-26). The input-version choice is a derived test input and needs explicit approval so that it is not mistaken for synthetic ground truth |
| Implementation complexity | Medium-high: time-aware evidence store, version parsing and range evaluation, independent scorer |
| Evaluation methodology | Held-out unsafe-version rate with and without the verifier; McNemar on paired cases; counts of removed versus wrongly rejected; semver distance and declared-constraint compatibility of each target (GAP-06) |
| Expected measurable outcome | A held-out U-V rate and its reduction. If the pilot shows the rate is near zero, the result is "verification is unnecessary for this family", reportable but thin |
| Main risks | (a) X1 or R1 may already cover it more convincingly. (b) Held-out events may be rare. (c) Advisory dates skew to 2026, so the cut-off choice drives the result. (d) A range-safe target may not be installable (P024) |
| Likely reviewer objection | "This is a list lookup evaluated on its own list." Answer: only the held-out result is the claim; in-snapshot results are reported as an implementation check |

## CC-5. Wrong names that resolve to reported-risky packages

**Statement.** Quantify, from the data alone, how often names from the error space (planted typos and invented names in a hallucination benchmark, human-confirmed hallucinated names, typosquat variants) coincide with reported-malicious or typosquat-listed packages, and show what an existence-only check does with them.

| Aspect | Assessment |
|---|---|
| Difference from previous research | H2 and H5 show an existence check is insufficient; X2 reports hallucinated names that previously hosted malware. This project's counts (25 of 1,049 planted LibHalluBench names are reported-malicious PyPI names; none of the 29 observed hallucinated names is) are a new data point on a different dataset, not a new finding in kind |
| Supporting literature | GAP-05; P007 (existence validation as the stated defence); H1, H2, H5, X2 |
| Feasibility | High. Counts already recomputed from raw files; the Agent 3 v1 comparison (RQ4) needs normalisation and dated existence only |
| Dataset requirements | LibHalluBench (evaluation only), Package Hallucination, OpenSSF, DataDog, typosquat pairs |
| Ground-truth requirements | None new. The "imitated package" for each overlapping name is a reading of the spelling and must be labelled as such or annotated by two people |
| Implementation complexity | Low |
| Evaluation methodology | Overlap counts with exact matching rules; detector recall on registry-present positives; false positives on benign-reference candidates |
| Expected measurable outcome | A small, exact table |
| Main risks | Small numbers (25 names); planted names are constructed, not observed model output; overlap depends on name normalisation |
| Likely reviewer objection | "Already known." Answer: present as corroboration and motivation, in one section, not as a headline |

## CC-6. Provenance-preserving multi-family evidence set

**Statement.** Release the normalisation schema, per-family evidence tables, conflict table and case manifests (hashes and identifiers, not raw data) so that others can evaluate dependency advice across families.

| Aspect | Assessment |
|---|---|
| Difference from previous research | P023 argues for benchmark-quality criteria in malware datasets; P005 uses a benchmark with neutral packages; none spans four families with separate labels and documented overlaps |
| Supporting literature | GAP-04, GAP-07; EA-03 (P007), EA-12, EA-20, EA-21 |
| Feasibility | Medium. Schema and manifests can be released; raw data cannot for several sources (LibHalluBench gated and no-training; MalRegistry without licence; OSV and manifest licences unverified) |
| Dataset requirements | All held sources, normalised |
| Ground-truth requirements | Per-row review of Ecosyste.ms pairs (attack, research demonstration, synthetic, legitimate fork) by two annotators; resolution of the documented label conflicts |
| Implementation complexity | Medium |
| Evaluation methodology | Descriptive statistics, overlap and conflict tables, reproducibility by hash |
| Expected measurable outcome | A reusable artefact |
| Main risks | A resource built from other people's lists is a modest contribution; licence limits reduce its usefulness; maintenance |
| Likely reviewer objection | "Aggregation of existing lists." Answer: only claim it as a supporting artefact |

## CC-4. Full four-family verifier evaluation (the current RQ1 in its broad form)

**Statement.** As approved in D-018: the verifier's effect on unsafe and unsupported recommendations across all four families, with unsafe codes for nonexistent, malicious, typosquat and vulnerable targets.

| Aspect | Assessment |
|---|---|
| Difference from previous research | No inspected source evaluates all four families together (E8 pending a full read of H7) |
| Supporting literature | GAP-01, GAP-04; EA-31 (P010) |
| Feasibility | **Low.** Nonexistent targets cannot be scored without registry data, and a live lookup leaks later takedowns in held-out runs. Malicious and typosquat targets are expected to be rare. The nonexistent family has 34 positives |
| Dataset requirements | A registry state for the cut-off date, including removed packages: not obtainable from data held (EA-17 to EA-19 confirm this is a general limit) |
| Ground-truth requirements | Intended package for wrong names (absent); verified-benign set (absent) |
| Implementation complexity | High |
| Evaluation methodology | As in `../RESEARCH_QUESTIONS.md` §7–§10 |
| Expected measurable outcome | Uncertain; several cells may have zero events |
| Main risks | A headline claim resting on empty or circular cells |
| Likely reviewer objection | Arguments 1, 4 and 7 in `NOVELTY_ASSESSMENT.md` §5 |

---

## A combination to consider (for review, not a decision)

The candidates are not exclusive. The most defensible paper the evidence supports is narrower than the current RQ1:

1. **Headline measurements: CC-1 and CC-3.** Both are deterministic, feasible in every family, do not depend on rare events, and were not found in the inspected literature.
2. **CC-2 restricted to the vulnerable family on PyPI**, as the one place where a held-out safety effect can be tested, positioned explicitly after R1 and X1.
3. **CC-5 as a short motivating analysis** and RQ4 as the baseline record.
4. **CC-4's broad claims dropped** from the headline; other families reported descriptively with their event counts.

This matches the narrowing that D-018 and D-023 already anticipate ("unsupported-claim rate and vulnerable-version targets on PyPI"). The difference is that the literature evidence now argues for adopting that narrowing as the plan, and for adding the rule-versus-LLM comparison as a first-class result, without waiting for the pilot to force it. The pilot remains useful to estimate rates and power.

## Decisions this raises for the owner

1. Whether to adopt the narrowed form now or keep the broad RQ1 until the pilot.
2. Whether the paper is framed as an evaluation study or as a system paper. The evidence supports only the former.
3. Whether a negative result for the LLM (rules suffice) is an acceptable headline.
4. Whether to approve a small two-annotator audit (claim parser; Ecosyste.ms row review; imitated-package reading). Human annotation of source records is not synthetic ground truth, but it must be recorded as project-created labels.
5. Whether to approve registry metadata lookups for version lists, which CC-2 needs.
6. Whether to run a systematic search with a logged protocol before any gap is written into a paper.
