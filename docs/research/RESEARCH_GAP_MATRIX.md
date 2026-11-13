# Research gap matrix

Status 2026-11-13: analysis accepted with the research direction (D-018). The gap in §4 remains **a hypothesis about the literature**, based on one search session; it must be re-checked before the paper is written.

Paper IDs refer to `LITERATURE_REVIEW.md`. Cell values come from what was verified there; for papers read at abstract level only, a "No" means "not stated in the abstract", which is weaker than "the paper does not do it".

## 1. Comparison matrix

Columns:

- **Families**: risk categories the work evaluates. N = nonexistent or hallucinated, T = typosquat or confusion, M = malicious, V = vulnerable.
- **Detect**: detects or measures the risk.
- **Remediate**: produces a recommendation for a specific flagged dependency (replace, remove, upgrade).
- **Evidence cited**: output links claims to identifiable source records.
- **Independent check**: output is validated by a mechanism that does not share the generating model.
- **Deterministic baseline**: compared against a non-LLM method.

| ID | Work | Families | Detect | Remediate | Evidence cited | Independent check | Deterministic baseline | Read depth |
|---|---|---|---|---|---|---|---|---|
| H1 | Spracklen 2025 | N | Yes | No (prevention at generation) | No | Registry list as oracle; self-detection studied | — | Full |
| H2 | Twist 2026 | N | Yes | No | No | PyPI tool given to the model | — | Full |
| H3 | Krishna 2025 | N | Yes | No | No | No | — | Abstract |
| H4 | Miranda-Pena 2026 | N (library features) | Yes | Mitigation by static analysis | No | **Yes, static analysis** | The checker is deterministic | Abstract |
| H5 | Raj & Sahu 2026 | N, lookalikes | Yes | Regenerate / fall back | No | **Yes, existence check + classifier** | — | Abstract |
| H7 | Li & Gao 2025 | Several supply-chain threats | Yes | Warnings | No | Middleware (details unverified) | — | Abstract |
| T3 | Neupane 2023 | T | Yes | No | — | — | Is deterministic | Abstract |
| T4 | Truong 2025 | T | Yes | No | — | — | String metrics | Abstract |
| T5 | Jiang 2026 | T | Yes | No | Metadata | Analyst triage | — | Abstract |
| M5 | Zahan 2025 | M | Yes | No | No | No | **Yes, CodeQL** | Abstract |
| M6 | Zeshan 2026 | M | Yes (multi-agent) | No | No | No | Prior tool | Abstract |
| M7 | Guo 2026 | M | Yes (RAG) | No | Retrieved reports | No | — | Abstract |
| M8 | Ryan 2026 | M | Yes | No | Indicator lines | No | — | Abstract |
| R1 | Singla 2026 | V | Measures agent choices | **Yes (version choice)** | No | **Proposed: advisory snapshot + tests** | Human PRs as context | Full |
| R2 | He 2023 | V, outdated | — | **Yes (Dependabot)** | Changelogs | — | Is deterministic | Abstract |
| R3 | Sonatype 2026 (vendor) | V | — | **Yes (upgrade version)** | Vendor data | Registry grounding | **Yes** | Web page |
| — | **This project (proposed)** | N, T, M, V kept separate | Evidence lookup | **Yes** | **Yes, per claim** | **Yes, deterministic** | **Yes** | — |

## 2. Candidate gaps, tested against the literature and the data

Each row is a hypothesis about a gap, not an established gap.

| # | Candidate gap | What the literature shows | What our data allows | Verdict |
|---|---|---|---|---|
| G1 | Detection is studied far more than remediation | Supported in this sample: 10 of the 16 rows above detect or measure only, and 3 more (H4, H5, H7) mitigate by checking, regenerating or warning without recommending a remediation. Remediation appears in R1 (preprint), R2 and R3 (vendor), all for vulnerable or outdated versions. | Typosquat targets and advisory fixed versions give partial remediation evidence | **Plausible**, but "remediation is unstudied" is false: R1–R3 exist |
| G2 | Recommendations lack evidence traceability | No reviewed package-security work reports a per-claim citation metric. M8 shows LLM explanations are far weaker than verdicts. Citation metrics exist in NLP (G2). | Every source record has an ID, so claim-to-record checks are feasible | **Plausible and measurable** |
| G3 | LLM recommendations contain unsupported or false claims | R3 (vendor): about 27.8% nonexistent versions. H2: models accept invented libraries. M8: reported indicators that were absent. | Version and name claims can be checked against records | **Supported as a problem.** Not new as an observation |
| G4 | Unsafe replacement decisions: the recommended package is itself risky | R1 measures vulnerable version choices by agents. No reviewed work measures recommendations that land on malicious, typosquatted or nonexistent packages. | Malicious lists, typosquat lists, advisories; 25 LibHalluBench typo names are reported-malicious packages | **Plausible; the least covered area in this sample** |
| G5 | Independent verification of recommendations | Deterministic checks of LLM output exist for hallucinated libraries (H4, H5) and are proposed for vulnerable versions (R1). None in this sample covers M and T. | Feasible without executing anything | **Partly open.** The idea is not new; its extension across families is |
| G6 | Distinguishing malicious from nonexistent packages | H5 reports that about half of flagged names were registered lookalikes. H1 notes its registry lists may contain malicious names. No reviewed work evaluates the distinction as a labelled task. | Separate label families exist; nonexistent positives are few (34) | **Real but hard to evaluate strongly** with 34 positives |
| G7 | End-to-end evaluation across several risk categories | H7 covers several threats in LLM output (abstract only). Detection papers are single-family. | Four families on PyPI, two on npm | **Plausible.** H7 must be read in full before claiming it |
| G8 | "Five agents", "RAG" or "uses an LLM" | M6 is a peer-reviewed multi-agent system; M7 is RAG-based; many works use LLMs. | — | **Not a gap. Must not be claimed as novelty** |
| G9 | Grounding reduces hallucinated recommendations | H1 (RAG), H2 (tool use) and R3 (registry grounding) already show it. | — | **Not a gap.** Usable as a replication check only |

## 3. What is not defensible, and why

1. **Novel detection of malicious packages or typosquats.** Published detectors use code and metadata (M5–M7, T5) that we do not have and may not open. Our detection is a lookup in known lists. It can be reported as a component, not as a contribution.
2. **Measuring hallucination rates.** H1 used 576,000 samples; our data has 34 confirmed hallucinated names.
3. **Any accuracy claim about "correct" recommendations.** There is no gold set of correct recommendations, and making one would be synthetic ground truth.
4. **Claims about npm vulnerabilities, dependency confusion or impersonation.** No data.
5. **Claims that an existence check is insufficient, as a new finding.** H2 and H5 already indicate it. Our Agent 3 v1 probe and the 25 overlapping names are corroboration.

## 4. The defensible gap [P]

> Prior work on package risk in LLM-assisted development measures or detects one risk family at a time, and the work on remediation (R1, R3) concerns the choice of a non-vulnerable version. In the literature reviewed, **no study evaluates remediation recommendations across nonexistent, typosquatted, malicious and vulnerable dependencies, with the families kept separate, and measures (a) how often a recommendation itself introduces a risky dependency, (b) how often its claims are unsupported by citable evidence, and (c) how much an independent deterministic verifier reduces both and at what cost in coverage.**

Why this one:

- It combines G4 (primary), G2 and G5, which are the least covered and are all measurable with records we hold.
- It needs no gold recommendations: (a) and (b) are property checks against source records.
- It uses the one thing our data is unusually good at: four separately sourced label families for the same ecosystem (PyPI).
- It turns the legacy system's verified failure (existence-only reasoning) into a baseline instead of hiding it.

**Limits on this claim, to be stated wherever it is used**

1. It rests on one session's search with abstract-level reads for most papers (`LITERATURE_REVIEW.md` §6). H7 and R1 are the works most likely to narrow it, and R1's benchmark may be released before we finish.
2. The contribution is an **evaluation and a measured design**, not a new detection algorithm or a new architecture.
3. The verifier and the unsafe-recommendation metric would both rely on the same lists unless separated. Without a time-based or source-based hold-out the evaluation is circular, which is the flaw that invalidated the legacy benchmark (`RESEARCH_QUESTIONS.md` §6).
4. A negative result is possible and publishable: a deterministic recommender may match or beat the LLM (R3 suggests so for versions). The research question is worded so that this outcome answers it.
