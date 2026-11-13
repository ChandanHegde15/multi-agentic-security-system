# Dataset feasibility mapping

Status 2026-11-13. Checks whether the data the project holds can support each candidate contribution in `CONTRIBUTION_CANDIDATES.md`.

**Basis.** `../../datasets/DATASET_CATALOG.md`, `../PROBLEM_DEFINITION.md`, `../RESEARCH_QUESTIONS.md` §12, `../FOUNDATION_REVIEW.md`, and the two inspection reports kept with the data. All counts below are the verified counts recorded in those documents; **no dataset was opened, normalised, split or modified for this mapping, and no new count was computed.** No registry was queried. Statements from the literature are cited by paper ID (`PAPER_INVENTORY.md`).

No source is approved for evaluation or training yet. This mapping does not change that.

## 1. What each source can supply

| Source | Usable label | Scope | Label quality | Literature note |
|---|---|---|---|---|
| OSV PyPI (GHSA, PYSEC) | `vulnerable` at version-range scope; fixed version in most records; publication date | PyPI, 1,697 package names with a non-withdrawn advisory | Curated advisories; ranges can be imprecise; GHSA and PYSEC alias each other | P024 p8: most ranges give only an upper bound |
| OpenSSF Malicious Packages | `malicious_reported`, `withdrawn`; publication date | PyPI, 11,992 readable reports | Reporter assertion; concentrated origins; includes typosquats, research activity, borderline squats | P005 p1 and P020 p4: reports are rarely confirmed and may be wrong |
| DataDog manifests | `malicious_reported` (name), `compromised_version` (version list) | npm 48,600; PyPI 1,835 | Human-triaged, one main detection tool; absence is "inconclusive" | P020 p5: 812 packages shared with other lists |
| PyPI MalRegistry listing | Corroborating name list only | PyPI, 10,790 names | No licence; largely duplicates OpenSSF | Used as the malicious set in P004 |
| You Can't Touch This | `typosquat` pair with target; registry dates | npm, 406 pairs | Vendor-listed, to early 2023 | — |
| Ecosyste.ms typosquats | Name-pair relation only | PyPI 95, npm 37 | Mixed intent; needs per-row review | — |
| Package Hallucination | `nonexistent_at_collection`, human-confirmed, dated | PyPI, 34 names | Best label in the collection; very small | — |
| LibHalluBench | Prompts; planted wrong names (not nonexistence labels) | Python | Evaluation only; 963 rows with a template artefact | — |
| Real manifests | Benign-reference input | 12 repositories | Not verified benign; gold lists unreviewed | P004, P022, P023 also assume benign from popularity or recency |

## 2. Cross-cutting data conditions

| Condition | State in the data | Consequence |
|---|---|---|
| **Label quality** | Only 65 rows in the whole submission are human-reviewed. Malicious labels are assertions by reporters | Unsafe rates are lower bounds; "not listed" must never be scored as safe |
| **Provenance** | Source, version or commit, record ID and file hash exist for every source except the LibHalluBench revision | Adequate for record-level citation (CC-1). Record the missing revision as a limitation |
| **Duplicate package identities** | OSV MAL republishes OpenSSF; 9,480 of 10,790 MalRegistry names are in OpenSSF; 1,371 of 1,835 DataDog PyPI names are in OpenSSF; GHSA and PYSEC alias each other | De-duplicate by normalised ecosystem and name (PEP 503 for PyPI) before counting cases. One package, one case |
| **Overlapping labels** | `axios`, `pytorch`, `detectron2` are both typosquat targets and on malicious lists; 37 of 94 Ecosyste.ms PyPI variants are OpenSSF reports; 12 of 35 Ecosyste.ms PyPI targets have an advisory | Keep a conflict table; a case can carry several family findings; never collapse them |
| **Package identity leakage** | The same or near-identical names recur across sources and within campaigns | Group by target package and by name cluster in any split or bootstrap. P025 p8 reports copy-cat clusters; P023 p12 reports train/test dependence from this cause |
| **LLM pre-training leakage** | All sources are public lists an LLM may have seen | Cannot be excluded. A cut-off after the model's training date reduces it for recent reports |
| **Missing ground truth** | No intended package for wrong names (4 names only); no verified-benign set; no correct-recommendation set; no structured attack type; no npm advisories yet | Evaluation by properties only; target agreement only where a source states the target |
| **Registry snapshots and temporal validity** | None held. YCTT has dated history for 406 npm names; Package Hallucination has dated absence for 34 names | Existence cannot be scored in held-out runs. P017 p3, P018 p11 and P025 p5 confirm removed packages cannot be reconstructed by anyone |
| **Verified replacement packages** | None. Typosquat targets are source-stated, not verified safe; 12 of 35 PyPI targets carry an advisory | "Replace with the target" can be checked for agreement with the source and against the lists, not for correctness |
| **Objective evaluation of remediation** | Possible for properties: target not on malicious or typosquat lists; version outside affected ranges; claim supported by a cited record; action consistent with the finding | Not possible for "the right fix". P024 p10 shows a range-safe upgrade is often not installable |

## 3. Candidate by candidate

### CC-1. Evidence support of claims

| Question | Answer |
|---|---|
| Supported by the data? | **Yes.** Every evidence record has a stable ID and machine-readable content (OSV JSON, manifests, CSV pairs) |
| Families and ecosystems | All four on PyPI; typosquat and malicious on npm |
| Positive cases available | Thousands for malicious and vulnerable; 406 plus reviewed Ecosyste.ms pairs for typosquat; 34 for nonexistent |
| Labels needed that do not exist | None for scoring. The claim is checked against the record it cites |
| Human annotation required | (a) Audit of the automatic claim matcher on a sample, two annotators, agreement reported. (b) Optional: classify free-text statements outside the schema on a sample, to show how much escapes the structured check |
| Leakage or circularity | Low. The check is against the cited record, not against a held-out list |
| Blocking items | Normalisation (D-024); the claim schema; an LLM choice |
| Verdict | **Feasible now**, after normalisation |

### CC-3. Rules versus LLM

| Question | Answer |
|---|---|
| Supported by the data? | **Yes** for typosquat (source-stated targets) and vulnerable (fixed versions in 6,008 GHSA and 6,858 PYSEC records). Trivial for malicious (the rule is `remove`). Weak for nonexistent (34 cases; target known for 4) |
| Labels needed that do not exist | None; the reference points are source-stated |
| Human annotation required | Per-row review of the 132 Ecosyste.ms PyPI and npm pairs before they are used as typosquat cases |
| Leakage or circularity | Target agreement is circular for the rule recommender (it copies the source). Report agreement for the LLM only, and compare safety on held-out evidence |
| Blocking items | Lowest fixed version needs version ordering per package; some advisories have several ranges |
| Verdict | **Feasible.** Expect little difference in families where the evidence states the answer |

### CC-2. Risky targets and verifier cost (vulnerable, PyPI)

| Question | Answer |
|---|---|
| Supported by the data? | **Partly.** Dated advisories exist (6,853 non-withdrawn GHSA and PYSEC records published in 2026, enough for a cut-off inside 2026). Version lists and upload dates per package are **not held** |
| Labels needed that do not exist | Which versions existed at the cut-off; which input version a project would realistically use |
| Human annotation required | None, but an approved rule for choosing input versions from advisory ranges (a derived test input, to be recorded as such) |
| Leakage or circularity | In-snapshot results are circular by design. The hold-out is valid for U-V because advisory publication dates are in the records. The 2026 skew makes the result sensitive to the cut-off; report several cut-offs |
| Blocking items | Approved metadata lookups (D-021) for version lists of the sampled packages, time-stamped; surviving packages only |
| Verdict | **Feasible after one acquisition step.** Effect size unknown until the pilot |

### CC-5. Wrong names resolving to risky packages

| Question | Answer |
|---|---|
| Supported by the data? | **Yes**, at small scale: 25 of 1,049 planted LibHalluBench names are OpenSSF-reported PyPI names (34 in any list); none of the 29 observed hallucinated names is |
| Labels needed that do not exist | The package each overlapping name imitates. Currently a reading of the spelling |
| Human annotation required | Two-annotator labelling of the imitated package for the 34 names, or present the names without that label |
| Leakage or circularity | LibHalluBench is evaluation-only and its overlapping names must stay out of every development split |
| Blocking items | Resolve the LibHalluBench template artefact for the describe rows, or exclude them |
| Verdict | **Feasible now** as a descriptive analysis; too small for inference |

### CC-6. Evidence set as an artefact

| Question | Answer |
|---|---|
| Supported by the data? | Schema, manifests and hashes: yes. Raw redistribution: **no** for LibHalluBench (gated, no training use), MalRegistry (no licence), OSV and manifests (licence unverified) |
| Human annotation required | Ecosyste.ms row review; conflict resolution notes |
| Verdict | Feasible as a manifest-and-code release only |

### CC-4. Full four-family evaluation

| Question | Answer |
|---|---|
| Supported by the data? | **No** for nonexistent targets (no registry state; live lookup leaks takedowns). **Unknown, probably too sparse** for malicious and typosquat targets in a hold-out. Yes for vulnerable versions |
| Labels needed that do not exist | Past registry existence including removed packages; intended package; verified-benign set |
| Verdict | **Not supported as a headline.** Descriptive reporting per family is possible |

## 4. Where human annotation is required

| Task | Size | Purpose | Status |
|---|---|---|---|
| Per-row review of Ecosyste.ms pairs (attack, research demonstration, synthetic, legitimate fork) | 132 PyPI and npm rows | Use as typosquat cases | Not started; needs approval |
| Imitated package for overlapping LibHalluBench names | 34 names | CC-5 | Not started |
| Audit of the automatic claim matcher | About 200 claims | CC-1 validity | Not started |
| Review of the 29-versus-45 discrepancy in Package Hallucination | 45 rows | Correct count of nonexistent positives | Open |
| Sample audit of benign-reference candidates | To be sized | State how "candidate" false rejections are bounded | Optional |

Rules for all of them: two annotators where possible, written guidelines fixed first, agreement reported, labels stored with provenance as **project-created annotations** and kept separate from source labels. They are annotations of existing records, not synthetic ground truth, and must be described that way.

## 5. What the data cannot support, whatever the design

1. Any statement about the **correctness** of a recommendation.
2. Any statement that a package is **safe**.
3. Existence of a recommended package or version **at a past date**, for removed packages.
4. **npm vulnerability** results until the approved OSV npm acquisition is done.
5. Rates for the **nonexistent** family with useful precision (34 positives).
6. **Applicability** of an upgrade in a real project (no installation, no tests). Only semver distance and declared-constraint compatibility can be reported.
7. **Dependency confusion, impersonation, slopsquatting as an observed attack.**

## 6. Summary

| Candidate | Data support | Extra acquisition | Human annotation | Verdict |
|---|---|---|---|---|
| CC-1 claim support | Full | None | Small audit | Feasible |
| CC-3 rules versus LLM | Full for T and V | None | Ecosyste.ms review | Feasible |
| CC-2 risky targets, vulnerable PyPI | Partial | Version lists (approved type of lookup) | None | Feasible after acquisition; effect unknown |
| CC-5 wrong names | Full, small | None | 34 names | Feasible, descriptive |
| CC-6 artefact | Manifests only | None | Row review | Limited by licences |
| CC-4 four-family headline | Insufficient | Not obtainable for removed packages | Several | Not supported |
