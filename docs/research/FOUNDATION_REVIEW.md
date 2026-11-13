# Foundation review

Date 2026-11-13. A review of the research foundation (problem definition, literature review, gap matrix, research questions, architecture), requested by the owner before approval.

At the time of the review nothing was approved. **The owner has since approved the foundation (D-017 to D-028)**, with a pilot gate on RQ1 and HYP5 dropped. The weaknesses recorded here still apply and must be addressed during implementation. No implementation, normalization, fine-tuning, experiment or registry query was done as part of this review.

## 1. Deliverables: existence and consistency

All eight exist.

| # | File | Exists | State |
|---|---|---|---|
| 1 | `docs/research/PROBLEM_DEFINITION.md` | Yes | Proposal; 2 statements tightened in the review |
| 2 | `docs/research/LITERATURE_REVIEW.md` | Yes | 28 sources; 6 entries corrected or upgraded in the review |
| 3 | `docs/research/RESEARCH_GAP_MATRIX.md` | Yes | Proposal; consistent with the corrected review |
| 4 | `docs/research/RESEARCH_QUESTIONS.md` | Yes | Proposal; 8 corrections and a new §11 |
| 5 | `docs/architecture/SYSTEM_ARCHITECTURE.md` | Yes | Proposal; new §4 and §5 |
| 6 | `docs/architecture/AGENT_CONTRACTS.md` | Yes | Agent 3 v1 section unchanged; drafts corrected |
| 7 | `PROJECT_BRIEF.md` | Yes | Direction recorded |
| 8 | Project status notes | Yes | Updated at the end of the review |

Inconsistencies found and fixed:

| Problem | Fix |
|---|---|
| Hypothesis IDs H1–H6 clashed with paper IDs H1–H8 | Hypotheses renamed HYP1–HYP6 |
| Gap matrix said "12 of 15 rows detect only"; the table has 16 rows | Corrected to 10 of 16, plus 3 that mitigate without recommending |
| "Unsafe" was defined on the target, but U-K is about the input dependency | Definition reworded |
| "False-rejection rate" was defined with the wrong denominator (it was a share of rejections) | Redefined as a rate over recommendations with no unsafe property; renamed wrong-rejection rate |
| HYP2 compared two rates with different denominators | Now compares counts on the same cases |
| Condition C0 said "rule-based" without saying how rules read Agent 3 v1 output | Rules stated |
| The ungrounded LLM variant's input was undefined | Stated, and flagged as an open choice |
| Citation recall had no definition | Defined |
| The architecture had no component that scores results | Evaluation harness added (`SYSTEM_ARCHITECTURE.md` §4) |
| Agent 5 had no result for target checks when the action has no target | `not_applicable` added to the draft |
| No claim type for a withdrawn report | `report_withdrawn` added to the draft |
| `DATASET_CATALOG.md` and `RESEARCH_METHODOLOGY.md` were edited although not in the deliverable list | Disclosed; kept because they contained inaccurate statements |

Checked and consistent: scope (PROBLEM_DEFINITION §4) against evaluation sets (RESEARCH_QUESTIONS §8); the five actions across RESEARCH_QUESTIONS §3, the R0 rules and the Agent 4 contract; the six evidence families across SYSTEM_ARCHITECTURE and the contracts; Agent 3 v1 values against `agents/risk_analysis/` (untouched; 13 tests pass).

## 2. Claim audit: how each statement was verified

### 2.1 Evidence classes

| Class | Meaning | Trust |
|---|---|---|
| **D** | Read directly from local files, by hand or by a read-only script (counts, READMEs, licence files) | High; reproducible |
| **P** | Bibliographic fact on a publisher or proceedings page, the ACL Anthology, or a Crossref DOI record | High for title, authors, venue, pages |
| **X** | Bibliographic fact on the arXiv record only; the venue is the authors' own comment | Medium |
| **A** | Content from the abstract, read through an automated page reader | Medium; abstracts omit limits and details |
| **A2** | As A, read twice from two different pages (arXiv abstract page and raw arXiv API record) with the same result | Medium-high for what the abstract says |
| **F1** | Content from the paper's full text through **one** automated summary | Low-medium; needs a human check before quoting |
| **F2** | As F1, read twice with agreeing numbers | Medium |
| **G** | Grey literature (vendor page), one automated read | Low; not peer-reviewed |
| **N** | Not verified; bibliographic record only | Do not cite content |
| **H** / **Pr** | Project hypothesis / project proposal | Not facts |

Every web page was read by an automated fetch-and-summarize tool. No paper PDF was read in full by a person. Springer and IEEE full texts were not accessible.

### 2.2 Per source

| ID | Source | Bibliographic | Content | Changed in the review |
|---|---|---|---|---|
| H1 | Spracklen et al. 2025 | P (USENIX page) | Abstract numbers (16 models, 576,000 samples, 5.2% / 21.7%, 205,474 names): A. Everything else (19.7% overall, 43% repetition, 13.4% within 1–2 edits, all mitigation numbers, the 2024-01-10 list date): **F1**; a second read failed | Entry now states which numbers are single-read |
| H2 | Twist et al. 2026 | **P** (Crossref; was X) | 26% / 99% / 85%: A. 79%, tool-use numbers, pipeline precision and recall: F1 | Venue, pages and DOI confirmed |
| H3 | Krishna et al. 2025 | X, no venue | A2 | — |
| H4 | Miranda-Pena et al. 2026 | X (TMLR per authors) | A2 | — |
| H5 | Raj and Sahu 2026 | X, no venue | A2 | **Corrected.** The abstract says about half of flagged hallucinations are packages already registered on PyPI; the first entry said "lookalikes of real PyPI packages", which lost the point |
| H6 | Öz 2026 (dataset) | D (Zenodo metadata file) | D | — |
| H7 | Li and Gao 2025 | X, no venue | A2 | — |
| H8 | Latendresse et al. 2024 | X ("Submitted") | A | — |
| T1 | Vu et al. 2020 | P (Crossref) | **N** | — |
| T2 | Taylor et al. 2020 | P (Crossref) | **N** | — |
| T3 | Neupane et al. 2023 | P (USENIX page) | A | — |
| T4 | Truong et al. 2025 | P (Crossref) | D (abstract in the dataset README, read directly) | — |
| T5 | Jiang et al. 2026 | **Conference programme page** (ICSE 2026 Research Track; was unconfirmed). No proceedings DOI | A2 | Venue confirmed; numbers confirmed |
| M1 | Ohm et al. 2020 | P (Crossref) | **N** | — |
| M2 | Duan et al. 2021 | X (NDSS per authors) | A | — |
| M3 | Guo et al. 2023 | X (ASE per authors) | A | — |
| M4 | Ladisa et al. 2023 | X with journal reference and DOI on the arXiv record; DOI not resolved | A | — |
| M5 | Zahan et al. 2025 | P (Crossref) | A | — |
| M6 | Zeshan et al. 2026 | X (JSS per authors) | A2 | Second dataset size added |
| M7 | Guo et al. 2026 | **P** (Crossref: ACM Web Conference 2026; was unconfirmed) | A2 | Venue confirmed |
| M8 | Ryan et al. 2026 | X, no venue | A2 | — |
| R1 | Singla et al. 2026 | X ("Under review at JAWS 2026"); the paper itself names no venue | **F2** (counts, 2.46% / 1.64%, −98 / +1,316, 36.8% / 12.9% agreed) | Second read done |
| R2 | He et al. 2023 | X (TSE per authors) | A | — |
| R3 | Sonatype 2026 | Vendor page | **G** | — |
| R4 | Pearce et al. 2023 | X (S&P per authors) | A | — |
| G1 | Lewis et al. 2020 | X (NeurIPS per authors) | A | — |
| G2 | Gao et al. 2023 | X (EMNLP per authors) | A | — |
| G3 | Dhuliawala et al. 2024 | **P** (ACL Anthology: Findings of ACL 2024; was unconfirmed) | A | Venue confirmed; year is 2024 |

Summary: 10 sources have publisher-level bibliographic confirmation, 1 a conference programme, 15 arXiv-only, 1 is a dataset record held locally, 1 a vendor page. Content: 3 full-text (2 single-read, 1 double-read), 19 abstract-level, 2 read directly from local files, 3 not verified, 1 grey. **No "Findings" cell has been checked by a human against a PDF.**

### 2.3 Claims in our own documents

| Claim | Class | Note |
|---|---|---|
| All dataset counts in `PROBLEM_DEFINITION.md` §1–§2 | D | Recomputed from raw files |
| Agent 3 v1 probe: 88 of 132 flagged, all not-found; 44 present, all low | D | Re-read from the run file in the review. The run used a foreign commit and current lookups |
| 9,480 of 10,790 MalRegistry names are in OpenSSF | From the Phase 3 report | Not recomputed in Session 01 |
| LibHalluBench licence and no-training condition | One automated read of the Hugging Face card | Not archived locally; the card can change |
| "A peer-reviewed multi-agent system and a RAG system for package security exist" | M6: X + A2 (accepted at JSS per the authors). M7: P + A2 | Sound enough to rule out novelty claims |
| "No reviewed study evaluates remediation across the four families with an independent verifier" | **H** | An absence claim from one search session, mostly abstract-level. It is a hypothesis about the literature, not a verified fact. H7 (abstract only) and R1 are the likeliest to narrow it |
| "Grounding is already known to reduce hallucinated packages and versions" | H1: F1; H2: F1; R3: G | Reasonable, but rests on single-read and vendor sources |
| RQ1–RQ4, HYP1–HYP6, metrics, conditions, architecture, contracts, scope | **Pr** | Proposals only |

## 3. The LibHalluBench / OpenSSF overlap

### 3.1 Facts (class D)

| Measure | Value |
|---|---|
| Distinct `mistake` names in the specify split | 1,049 (154 one-character typos, 272 multi-character typos, 623 fake libraries) |
| Names that are also OpenSSF malicious reports (PyPI, PEP 503-normalized) | **25** (2.4%) |
| By type | 18 of 154 one-character typos (11.7%); 7 of 272 multi-character typos (2.6%); **0 of 623 fake libraries** |
| Names in any of OpenSSF, DataDog PyPI, MalRegistry listing, Ecosyste.ms PyPI | **34** (9 more: `matplotib`, `matplotllib`, `mumpy`, `numoy`, `pyteseract`, `request`, `requets`, `statmodels`, `statsmodel`) |
| Specify prompts that contain one of the 25 | **192 of 1,926** (10.0%) |
| Seeds touched by those prompts | 172 of 321 (53.6%) |
| Concentration | `numberpy` 49 prompts, `pndas` 41, `sklern` 40: 130 of the 192 |
| OpenSSF publication dates of the 25 | 16 on 2023-02-10/11 (one reporter's batch), 8 between 2024-05-31 and 2024-07-26, 1 on 2026-05-22 (`sklern`) |
| Withdrawn reports among them | 0 |
| Package Hallucination absent names in OpenSSF | 0 of 29 |

The 25: `bs3`, `bs5`, `cryptographylib`, `easyrequests`, `maplotlib`, `matlibplot`, `matlotlib`, `matplolib`, `matplotlb`, `matpltlib`, `mattplotlib`, `mtplotlib`, `numberpy`, `openpyx`, `openyxl`, `panas`, `pandaas`, `pndas`, `ppandas`, `psutill`, `requestlib`, `scikit-earn`, `scikit-lean`, `sklearns`, `sklern`.

What is **not** known:

- Whether any of the 25 exists on PyPI today. The submitter's lookup file records `registry_error` for 21 of them (and for 859 of all 1,049 names), so it is useless here. No lookup was made in this session.
- How the benchmark authors generated the typo names, and whether the benchmark revision we hold contained `sklern` before its report date. The revision was not recorded.

### 3.2 Consequences for label validity

1. **`mistake` is a prompt-construction field, not a nonexistence label.** Treating the 1,049 names as "nonexistent" would mislabel at least 25 (and up to 34) as nonexistent when a source reports them as malicious. The benchmark itself is not wrong: its oracle is a live PyPI lookup of what the model imports. The error would be ours.
2. **One name can belong to several families at different times.** `pndas` was reported malicious in 2023, is a spelling variant of `pandas`, and may be absent from PyPI now. A case with a single label cannot represent that. Each family claim needs its own record with its own date, which is the per-family evidence design already proposed; the review confirms it is necessary, not optional.
3. **No typosquat pair can be taken from LibHalluBench.** The benchmark has no field for the intended library. Inferring `pndas → pandas` would be a label we created. Only 3 of the names have a source-stated target (Ecosyste.ms).
4. **The existing submitter draft is invalid on this point.** `benchmarks/agent2/libhallubench_specify_lookup.jsonl` treats all 1,049 as lookup cases with `historical_registry_status: null`; it must not be reused.

### 3.3 Consequences for leakage

1. **Evidence-to-label leakage.** If a LibHalluBench-derived case is scored as "nonexistent" while the evidence store holds an OpenSSF report for the same name, the system returns "reported malicious". Scoring that as an error punishes a correct answer; scoring it by OpenSSF makes the label come from the system's own evidence. Either way the number is meaningless. These cases need to be scored per family against dated evidence, or excluded.
2. **Development-to-evaluation leakage.** LibHalluBench is evaluation-only (D-013). The malicious and typosquat lists would be used during development (rules, popular-name lists, few-shot examples, error analysis). The 34 shared names would then be seen in development and met again in evaluation. No fine-tuning is planned, but prompt examples and tuned rules leak in the same way.
3. **Pre-training leakage.** The OpenSSF reports have been public since 2023–2024. Any LLM used as Agent 4 may know these names as malicious. LibHalluBench is gated and carries a canary string on its card; the canary is not present in our exported rows (Session 0 inspection), so we cannot show our copy is protected.
4. **Temporal leakage.** `sklern` was reported on 2026-05-22. With an evidence cut-off before that date it is "unreported" to the system and "malicious" to the scorer, which is the intended held-out case. But a live registry check would see its removal and leak the answer (`RESEARCH_QUESTIONS.md` §6).

### 3.4 Consequences for evaluation splits

1. **All LibHalluBench-derived cases belong to the held-out side only.** This already follows from D-013; the overlap adds that the 34 shared names must also be removed from every development split of the malicious and typosquat families. The cost is 34 names out of thousands.
2. **Splits must be grouped by the imitated package, not by name.** The 25 cluster on a few packages (by reading the spellings, which is not a label: matplotlib 8, pandas 4, scikit-learn 4). Hashing individual names would put `matplolib` in development and `matpltlib` in held-out. The grouping key (the imitated package) is not labelled for most names; assigning it is a derived label and needs an explicit owner decision.
3. **Excluding by seed is not viable.** The 192 prompts touch 172 of 321 seeds.
4. **Report with and without.** Any LibHalluBench-based result should be reported for all specify prompts and again without the 192, because three names account for 130 of them and could dominate a rate.
5. **Fix the family of each shared name before any run**, in a conflict table, as the normalization proposal already requires.

### 3.5 Consequences for research claims

Supported by this finding:

- The set of plausible typos of popular PyPI names intersects the set of names used by reported malware. In this benchmark's name set, 11.7% of one-character typos are reported-malicious names.
- An existence check cannot be the only defence: a mistyped name can resolve to a registered package. This agrees with H2 and H5.
- The four families cannot be assigned from a name alone.

**Not** supported, and must not be written:

- That LLM-hallucinated names are being squatted. The overlap is zero for the 623 invented library names and zero for the 29 names that LLMs actually hallucinated in the Package Hallucination data. On our data, the hallucination-to-malware link is unobserved. This is consistent with H1's finding that most hallucinated names are not near-typos.
- Any rate for real developer typos. The names were constructed by the benchmark authors by a method we have not verified.
- That these 25 packages are installable today.
- That the benchmark caused or preceded any registration. 24 of 25 reports predate the benchmark's first preprint (2025-09-26); for `sklern` the order is unknown.
- That the overlap affects the results reported in H2. We have not checked how their oracle handled these names.

Effect on the proposed direction: it strengthens the case for per-family, dated evidence and weakens any framing built on "hallucinated packages become malware". The project brief's first aim ("hallucinated or nonexistent, e.g. invented by an LLM") should be described as a nonexistence problem, with the malware link stated as unobserved in our data.

## 4. Can the research questions be answered?

The full table is in `RESEARCH_QUESTIONS.md` §12. The main points:

| Question | Verdict | Why |
|---|---|---|
| RQ4 (Agent 3 v1 against evidence lookup) | **Answerable** after normalization | Dated positives exist for npm typosquats and PyPI malicious reports |
| RQ2 (grounding) | Partly | Needs an LLM; unsafe events may be few |
| RQ3 (per family) | Partly | 34 nonexistent cases against thousands elsewhere; npm lacks the vulnerable family |
| RQ1 in-snapshot | Answerable but uninformative | The verifier and the score use the same records; it shows only that the code is right |
| RQ1 held-out (the headline) | **At risk** | Two problems below |
| RQ1 for nonexistent targets (U-N) | **Not answerable** | No registry data at all |

Two problems with the headline question that Session 01 did not state clearly enough:

1. **The live-lookup leak.** A package reported after the cut-off has usually been taken down since. Checking existence today rejects it for the wrong reason and credits the verifier with foresight it does not have. There is no registry history in the data to replace the live lookup.
2. **Unknown event rate.** The held-out design measures something only if recommenders actually propose targets that are later reported bad. For vulnerable versions this is plausible (6,853 advisories published in 2026). For malicious and typosquat targets it is probably rare: a recommender that suggests `pandas` for `pndas` never hits it. If events are rare, RQ1 has no statistical power for those families and HYP5 is untestable (HYP5 was later dropped, D-018). No pilot has been run, and running one would be an experiment, which is out of bounds for this session.

Missing ground truth (none of it exists in the data): the intended package for a mistyped or hallucinated name; a "safe" label; a correct recommendation; the attack type of a report; past registry state and version lists; npm advisories; realistic versions for vulnerable input cases.

Missing evidence that could be acquired with approval: registry metadata with upload times (PyPI, npm); OSV npm advisories; a popular-package list for PyPI; the LibHalluBench card and revision; a human check of the Ecosyste.ms rows.

Honest reading: **the direction is sound, but RQ1 as worded may be only partly answerable.** A narrower fallback is answerable with what we hold: the unsupported-claim rate of recommendations, and vulnerable-version targets on PyPI under a temporal hold-out. Whether to keep the broader wording should be decided after a small approved pilot.

## 5. Do the architecture and contracts match the research questions?

Mostly yes after the corrections; the mapping is in `SYSTEM_ARCHITECTURE.md` §5.

Gaps found and corrected in the drafts: the missing scorer; `not_applicable` results; the `report_withdrawn` claim type; the rule for undated evidence; the ban on live target lookups in held-out runs; the definition of the ungrounded variant; the C0 rules.

Gaps that remain open because they need a decision or data:

1. Agent 5's `target_exists` check has no data source without registry lookups (since allowed, D-021; not yet run). With lookups off, every `replace` and `upgrade` ends in `abstain`, so condition C4 would have near-zero coverage.
2. Agent 3 v2 is assumed by RQ3 and RQ4 (since approved, D-020).
3. `name_similar_to_popular` needs a popular-package list. One exists for npm (YCTT, 1,000 names); none for PyPI.
4. The evidence store depends on normalization (strategy since approved, D-024; not yet implemented).
5. Agent 1 serves no research question. It is needed for a working system and for the end-to-end demonstration only; that should be said plainly in the paper.
6. Version-level checks need PEP 440 and semver range matching against OSV ranges; 6,411 OpenSSF reports use ranges without listed versions.

## 6. What was not done

- No proposal was marked approved during the review; approvals came afterwards from the owner (D-017 to D-028).
- No code, normalization, training, experiment, registry lookup or download.
- No data was moved during the review. The migration was executed afterwards under D-017: `docs/datasets/DATASET_MIGRATION_PLAN.md`.
