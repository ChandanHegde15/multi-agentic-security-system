# Dataset evaluation

Status 2026-11-14. One-pass evaluation of the normalized evidence tables (`DATASET_CATALOG.md` §2.2, D-046, D-048) and the benchmark sources, produced by `src/multi_agentic_security/datasets/evaluate.py`. All numbers below are read from the evaluation output (`research/datasets/inspected/evaluation_2026-11-14/evaluation.json`, SHA-256 `a54a11b4…5010be`, git-ignored). Overlap between sources is overlap, not confirmation; conflicts are facts for review, not errors.

## 1. Evidence tables

| Family | Tables | Distinct names | Dated share | Use in held-out experiments |
|---|---|---:|---|---|
| vulnerable | OSV PyPI | 1,696 (PyPI) | 100% | Yes |
| malicious | OpenSSF, DataDog manifests, MalRegistry listing | 61,970 | OpenSSF 99.95%; DataDog and MalRegistry none | OpenSSF only; undated sources only in ordinary (non-held-out) runs |
| withdrawn | OpenSSF | 362 | 100% | Yes |
| typosquat | Ecosyste.ms, YCTT | 536 | YCTT 100% (release date); Ecosyste.ms none | YCTT only |
| benign_reference | PyPI popular list, YCTT targets | 15,232 | popular list 100% (list date) | As candidates only |
| nonexistent | not an evidence table: comes from benchmarks (§4) | — | — | — |

Publication years. Vulnerable advisories: 2021 5,042; 2022 3,852; 2023 1,006; 2024 1,241; 2025 1,120; 2026 8,852 records. OpenSSF malicious and withdrawn: 2022 20; 2023 6,492; 2024 4,838; 2025 2,955; 2026 4,033 records. The 2026 skew confirms the need for several cut-off dates (`RESEARCH_QUESTIONS.md` §6).

Licences as evidenced: OSV unverified (per upstream database); OpenSSF Apache-2.0; DataDog Apache-2.0 with NOTICE; MalRegistry none stated (do not redistribute); Ecosyste.ms CC0-1.0; YCTT MIT; popular list unverified.

## 2. Overlap between malicious sources (PyPI names)

| OpenSSF | DataDog | MalRegistry | OpenSSF ∩ DataDog | OpenSSF ∩ MalRegistry | DataDog ∩ MalRegistry | All three | Union | In one source only |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 11,992 | 1,834 | 10,790 | 1,371 | 9,478 | 1,388 | 991 | 13,370 | 3,115 |

npm malicious names come from DataDog only (48,600); OpenSSF npm reports were not acquired (D-041). Agreement between these sources is not independent evidence.

Other relations:
- 90 typosquat variants are also reported malicious; 446 are not (a listed typosquat is not proof of malware).
- 53 packages have both a vulnerability advisory and a malicious report (compromised versions of legitimate packages).
- 17 withdrawn-report names also have a malicious report; 345 are withdrawn only.
- 780 of the 1,696 vulnerable packages are in the PyPI popular list.

## 3. Label conflicts (29, `conflicts.csv`)

| Conflict | Count | Examples |
|---|---:|---|
| Benign reference and malicious | 16 | npm `debug`, `strip-ansi`, `ansi-regex`; PyPI `litellm`, `lightning`, `ultralytics`, `pytorch` |
| Benign reference and typosquat variant | 1 | PyPI `pillow-simd` |
| Benign reference and withdrawn report | 5 | npm `react`; PyPI `fastapi`, `strawberry-graphql` |
| Typosquat target that is itself reported malicious | 7 | npm `axios`, `debug`; PyPI `pytorch`, `detectron2` |

Consequences for the agents:
- All 16 "benign and malicious" pairs are **version-scoped**: every malicious record for these names lists specific versions, none claims the whole package (verified on the tables). They are compromised releases of otherwise legitimate packages. Agents 3 and 5 must match evidence by version, never by name alone, and must not flag the whole package.
- Popularity of a name is not identity: for example PyPI `pytorch` is both popular-listed and a typosquat target with malicious reports; what the name resolves to needs registry evidence.
- Withdrawn reports on popular packages (`react`, `fastapi`) are retracted false reports: `withdrawn` must never count as malicious.

## 4. Benchmarks and agent inputs

**LibHalluBench** (evaluation only, D-013): 1,926 `specify` tasks with 1,049 distinct injected names. 34 of them are real reported-malicious (33) or listed typosquat (3) packages, e.g. `matplotlib`, `pandas` and `scikit-learn` misspellings, `requets`, `request`. These 34 must stay out of every development split (`FOUNDATION_REVIEW.md` §3); list in `libhallubench_exclusions.csv`. One injected name is in the popular list, so "injected" does not always mean nonexistent.

**Package Hallucination** (CC-BY-4.0): 4,630 mentions, 224 distinct names from three models; 29 names absent at generation time, none of them in a malicious or typosquat table. 185 import-name → package pairs, 9 with a different name (for example `telegram` → `python-telegram-bot`), and 2,725 code generations.

**Real manifests**: 326 files from 12 repositories (package.json 146, pyproject.toml 116, yarn.lock 46, package-lock.json 8, requirements.txt 5, Pipfile 4, pnpm-lock.yaml 1). Five-repository requirements pins (14 files) are development and pilot only (D-045).

**PyPI version lists**: 123 packages, of which only 49 are vulnerable-family targets (of 1,696).

## 5. Readiness per agent

| Agent | Ready | Gaps |
|---|---|---|
| 1 Extraction | Real manifests (326) for format coverage; 2,725 LLM generations for generated-code extraction; import-name pairs (185) | No human-reviewed gold lists for real manifests; using Package Hallucination pairs to build the import table **and** to evaluate it would leak, so split them or use a separate mapping source |
| 2 Registry verification | Dated evidence store (8 tables); 123 version lists | Version lists for 1,647 vulnerable targets; registry snapshot for experiments; OSV npm advisories |
| 3 Risk analysis | Per-family evidence with version scope; typosquat pairs with targets; popular list for name similarity | Undated malicious and typosquat sources unusable in held-out runs; version-aware matching needed for compromised packages |
| 4 Recommendation | Evidence records with IDs for grounding; claim types defined | Cases and splits not yet built; model choice pending benchmark |
| 5 Verification | Evidence for every target check (exists, malicious, typosquat, vulnerable) | Target existence at a past cut-off needs version lists with upload times |
| Evaluation | 34 LibHalluBench exclusions identified; conflicts listed | GHSA/PYSEC alias groups; case lists and splits; second annotator |

## 6. Open checks

1. 1,696 vs 1,697 vulnerable names and 607 vs 606 withdrawn advisories against `PROBLEM_DEFINITION.md` (unverified causes).
2. Dates for DataDog and MalRegistry records: a dated DataDog index exists in a later version of the submission archive (proposed, not adopted).
3. GHSA/PYSEC alias grouping (double counting in the vulnerable family).
4. Rebuild determinism of each table (not yet checked by a second run).
