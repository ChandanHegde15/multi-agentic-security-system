# Data splits, validation and the fine-tuning plan

Status: design fixed by D-070 (2026-11-19). **No case list exists yet, no split has been built and nothing has been trained.** This document says what each set is for, what may never cross between sets, and what a later fine-tuning run may use. It extends `RESEARCH_METHODOLOGY.md` (splits fixed before modelling, grouped, assigned by hash) and `FOUNDATION_REVIEW.md` §3 (LibHalluBench).

## 1. The three sets

| Set | Also called | Purpose | May be used for |
|---|---|---|---|
| **train** | fine-tuning pool | Examples a model may learn from | Fine-tuning only (a later, separate condition). Never used to choose prompts, rules or thresholds, and never reported as a result |
| **dev** | validation set | Everything that is *chosen*: prompts, R0 rules, verifier ablations, sample sizes, hyper-parameters and early stopping of a fine-tune, error analysis | Repeated use; its numbers are development numbers and are reported as such |
| **test** | held-out set | The headline results and nothing else | Frozen before any model run; each model or condition is scored on it **once**; its results are never fed back into prompts, rules or training |

A **pilot** is a fixed subset of dev (the first N cases by `case_id`, N set in the protocol, about 100) used when free-tier call limits make the full dev set too slow. It is not a fourth set.

## 2. Rules that hold for every set

1. **Fixed before modelling.** Fractions, seed and forced assignments are recorded in the protocol and hashed before any model run. A split is never changed after a result has been seen.
2. **Assigned by hash, grouped.** A case's side is a pure function of its group key and the seed `20261114` (no random state). A group is a connected component over the package, the package a typosquat imitates, and the repository that pins it, so all cases of one package, and all pins of one repository, share a side (D-036, D-044 item 9). Default fractions: **train 30 %, dev 20 %, test 50 %**.
3. **Held-out wins.** Where a source forces a side and the cases of one group disagree, the order is test, then dev, then train. A test case can therefore never be pulled into dev or train; the reverse (a dev case ending up in test) only shrinks dev.
4. **LibHalluBench is evaluation-only** (D-013): every case derived from it is forced to test. The 34 names it shares with the malicious and typosquat lists are forced to test in every family, so they appear in no dev or train example, prompt example or rule tuning (`FOUNDATION_REVIEW.md` §3).
5. **Evidence dates.** A training example may use only evidence records published before the *earliest* cut-off of the held-out runs; an undated or later record disqualifies the example. A model must not learn from what a held-out run treats as unknown.
6. **Overlapping sources are not independent** (OpenSSF, OSV malware, DataDog, MalRegistry): one package seen in several sources is one group.
7. **No legacy material.** The earlier project's benchmarks and training data are never used in any set (D-029).
8. **Machine-checked.** `verify_splits` reports shared cases, shared groups and broken forced sides; `fine_tuning_pool` lists every training case it rejects with the reason. Both run before any protocol is hashed.

## 3. Where each family's cases go

| Family | Source | dev | test | train |
|---|---|---|---|---|
| Vulnerable (headline, PyPI) | Real-project pins (D-044) | The five development repositories already acquired (D-045) | The sampled repositories of D-044 | Further repositories from the same stored frame, beyond those already checked; **needs the owner's approval to acquire** |
| Typosquat | Pair sources (YCTT npm pairs, Ecosyste.ms pairs after review) | Hash side, grouped by imitated package | Hash side; plus forced names (rule 4) | Hash side |
| Malicious / compromised version | OpenSSF, DataDog (stratified sample by year) | Hash side | Hash side; plus forced names (rule 4) | Hash side; version-specific reports are undated in most sources, so few qualify under rule 5 |
| Nonexistent | The 34 human-confirmed names; LibHalluBench | None | All (too few to split; evaluation-only) | None |
| Benign reference | Popular lists, real-manifest dependencies | Hash side | Hash side | Hash side |

Cases for one repository are all in one set, so a repository pinned by both a development and a sampled repository goes to test (rule 3).

## 4. What each set is used for

| Activity | Set |
|---|---|
| Writing and changing prompts, R0 rules, claim schema | dev (pilot subset for LLM calls) |
| Choosing a model, temperature, output limit | dev |
| Verifier ablation (each check alone) | dev first; test once for the reported ablation |
| Error analysis by hand | dev; for test only after its results are final, never to change them |
| Fine-tuning: updates to weights | train only |
| Fine-tuning: choosing the checkpoint, stopping early | dev |
| Headline results for C1 to C5 and for a fine-tuned condition | test, once each |
| Human ratings and the claim-matcher audit | a sample of the test outputs, raters blind to the condition |

## 5. Fine-tuning plan (after the evaluation is complete)

The project's decisions so far say **no fine-tuning** (D-022, D-038, D-047); the owner plans to try it **after** the evaluation, on a free local open-weight model. That is a separate, later step with its own decision. This section fixes what it may use so that the evaluation stays valid.

1. **What is trained.** One open-weight model served locally. On the owner's 4 GB laptop GPU only a small model with 4-bit adapters is likely to fit (unverified; to be measured first). No paid service.
2. **Training examples.** The same prompt and structured input that the untuned model gets, with a target answer in the Agent 4 output schema, built from **train cases only**.
3. **Where the target comes from.** Targets must come from what a source states about the case (for example a typosquat pair's imitated package, a whole-package malicious report, an advisory's stated fixed version), never from R0's output and never from any LLM's answer. Reason: if the model is trained on R0 and then compared with R0 under the same policy, the comparison is circular. Because targets are derived by a policy, not given by a human, they are *training supervision*, not ground truth, and are never used to score anything. **Building the target rules is a decision for the owner before any training file exists.**
4. **Eligibility.** `fine_tuning_pool` against the earliest cut-off (rule 5); nothing forced to test; the list of rejected cases and reasons is stored.
5. **Selection and stopping** use dev. The chosen checkpoint, its training data hash, hyper-parameters and seeds go into the protocol before the test run.
6. **Evaluation.** The tuned model is a new condition (for example C7) on the same test cases as C1 to C5, with the **untuned base model** as its paired comparison and the verifier on and off as before. The test set is touched once for it.
7. **Leakage that cannot be removed** (stated, not hidden): the base model may have seen public advisories and malicious-package reports in pre-training (`FOUNDATION_REVIEW.md` §3, item 3); cut-offs after the model's stated training date reduce, not remove, this.
8. **Not allowed:** training on test or dev cases; on LibHalluBench; on the legacy data; on outputs of the models being evaluated; changing the split after seeing a result.

## 6. Checks to run before the protocol is hashed

- `verify_splits` returns no problem on the final split.
- Group counts per family and side are reported; a side with too few groups for a family is stated, not hidden.
- `fine_tuning_pool` is run on train and its rejected cases are listed.
- The case-list hash, the seed, the fractions and the forced-side lists are written into the protocol file.
