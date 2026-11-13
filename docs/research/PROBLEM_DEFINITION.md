# Problem definition

Status 2026-11-13: **approved** as the project's problem definition and scope (D-018, D-019).

Every statement is marked:

- **[V]** verified on 2026-11-13 against the files in `research/datasets/extracted/v1/` (then at `D:\RESEARCH_DATA\extracted\v1\`) or a cited paper.
- **[H]** hypothesis, to be tested.
- **[P]** proposal at the time of writing; approved where `DECISIONS.md` says so (D-017 to D-028).

All counts below were recomputed from the raw extracted files with read-only scripts. No dataset was normalized, modified, downloaded or executed, and no registry was queried.

---

## 1. What each dataset actually is

Counts differ slightly from `DATASET_CATALOG.md` where 7 advisory files are quarantined (D-009): 11,992 of 11,995 OpenSSF reports and 26,859 of 26,863 OSV records are readable on disk. [V]

### 1.1 LibHalluBench

| Aspect | Finding |
|---|---|
| Problem investigated | Whether prompt wording makes a code LLM import a library that does not exist (Twist et al., EMNLP 2026; `LITERATURE_REVIEW.md` H2). [V] |
| Records | 4,173 **prompts**, not packages: 321 control, 1,926 describe (6 types × 321), 1,926 specify (3 types × 642). All derive from 321 BigCodeBench seed tasks. Python only. [V] |
| Original labels | `split` and `type` describe how the prompt was built. `mistake` (specify split only) is the wrong library name planted in the prompt: 1,926 rows, 1,049 distinct names. [V] |
| Nature | **Generated** benchmark prompts. The `mistake` names are constructed typos and invented names, not observations of LLM output. [V] |
| Legitimate ground truth | None about packages by itself. The benchmark's oracle is a live PyPI lookup of what a model imports (paper). A `mistake` name is **not** labelled nonexistent: 25 of the 1,049 names are names of reported-malicious PyPI packages in OpenSSF (e.g. `maplotlib`, `pandaas`, `sklearns`, `requestlib`), and 34 are in at least one of our malicious or typosquat lists. They sit in 192 of the 1,926 specify prompts. Full analysis: `FOUNDATION_REVIEW.md` §3. [V] |
| Supports | Evaluation input for the end-to-end hallucination scenario (an LLM is run on the prompts; its imports go through the pipeline). Evaluation only (D-013). |
| Cannot establish | That a name is nonexistent, benign or malicious; the intended correct library for a typo (no such field); anything about npm. |
| Limitations | 963 describe rows (types "lesser known", "not widely used", "hidden gem") contain an unrendered template string, `{<HallucinationLevel.LIBRARY: 'library'>: '...'}`, inside the prompt. [V] Whether this is in the upstream release or an export artifact is **unverified**. HF revision not recorded. |
| License | CC-BY-4.0; the card forbids training, fine-tuning and inclusion in training corpora, and the dataset is gated. Verified on the Hugging Face dataset card on 2026-11-13 through an automated page read; the card is **not archived locally**. [V] |
| Attribution | Twist, Harman, Yannakoudakis, Zhang (EMNLP 2026). |

### 1.2 Package Hallucination (Zenodo 23962898, v1.0)

| Aspect | Finding |
|---|---|
| Problem investigated | How often three open-weight LLMs name PyPI packages that do not exist, by prompt language (English, Turkish) and task region. [V] |
| Records | 243 tasks; 2,725 raw generations; 2,605 deduplicated responses; 4,630 package mentions; 45 manual-review rows. [V] |
| Original labels | Per mention: `exists` (61 False), `absent_at_generation` (63 True; 29 distinct normalized names), `registered_after` (2 True), `first_upload`. Manual review per absent name: `hallucination` 34, `real` 4 (an import name of a real distribution, e.g. `RPi` → `RPi.GPIO`), `other` 7 (parser artifacts, placeholders). [V] |
| Nature | **Real-world observations** of LLM output, with a registry check dated to each answer and a human review of every absent name. |
| Legitimate ground truth | `nonexistent_at_collection` for the 34 human-confirmed hallucinated names, with the answer timestamp. This is the only human-reviewed, historically dated nonexistence label in the whole submission. |
| Supports | Agent 2 (nonexistence), Agent 1 (import-name vs distribution-name confusion), end-to-end hallucination cases. |
| Cannot establish | Malicious intent (none of the absent names is in OpenSSF [V]); hallucination rates for other models or languages; anything about npm. |
| Limitations | Very small positive set (34 names). `generations.jsonl` contains six model names; the README names three (the other three account for 31 generations). [V] `manual_review.csv` has 45 rows but `packages.csv` yields 29 distinct absent names; the relationship is **unresolved**. No peer-reviewed paper was located for this dataset (**unverified** whether one exists). |
| License | Data CC-BY-4.0, code MIT (`record_metadata.json`, README). [V] |
| Attribution | Erin Su Öz, DOI 10.5281/zenodo.23962898. |

### 1.3 Ecosyste.ms Typosquatting (commit `ccda8797`)

| Aspect | Finding |
|---|---|
| Problem investigated | Name pairs for testing typosquat detectors. |
| Records | 167 variant → target pairs: PyPI 95, npm 37, RubyGems 15, Go 10, GitHub Actions 8, crates.io 2. [V] |
| Original labels | `classification` is the spelling transformation only (62 are "other"). `source` attributes the pair. |
| Nature | **Curated and mixed.** The README states that the set includes reported attacks, research demonstrations and synthetic examples, and that "inclusion does not establish that a package is malicious". The column is named `malicious_package` for historical reasons. [V] |
| Legitimate ground truth | The **name-pair relation** (variant, target). Not maliciousness. |
| Supports | Agent 3 (name-similarity detection), Agent 4/5 (the source-stated target as the intended package). |
| Cannot establish | That a variant is malware, exists or ever existed. Examples in the file: `pillow-simd` is a legitimate fork; `torchtriton` was dependency confusion; 4 GitHub Actions rows are synthetic test fixtures; 2 rows illustrate PEP 503 normalization and are not separately registrable. [V] |
| Limitations | Small. Not independent of the malicious lists: 82 of 167 rows are attributed to OpenSSF or DataDog, and 37 of 94 PyPI variants are also OpenSSF reports. [V] |
| License | CC0 1.0 (LICENSE file). [V] |

**Correction.** `DATASET_CATALOG.md` described these as "167 malicious→target pairs". They are name pairs; the catalog has been corrected.

### 1.4 You Can't Touch This (Zenodo 23520699, v1.1.0)

| Aspect | Finding |
|---|---|
| Problem investigated | Detecting npm typosquats with string metrics and with ML on package features (Truong et al., NSS 2024). [V] |
| Records | 406 typosquat → target mappings (234 distinct targets); feature rows for 394 own-malware packages, 1,610 Backstabber's, 390 MalOSS, 980 most-downloaded and 232 target packages. [V] |
| Original labels | Typosquat listing by Sonatype, Phylum and Snyk, with a stated target; per-package registry history (`published`, `removed`, `unpublished`). All 406 have `exists=True` ("has existed"); 134 were unpublished. [V] |
| Nature | **Real-world observations**, curated by the authors from vendor listings up to early 2023. |
| Legitimate ground truth | `typosquat` pairs with targets for npm; `malicious` for the authors' 394 packages (vendor-listed); historical existence dates. |
| Supports | Agent 3 (similarity detection on registry-present names), Agent 4/5 (target as intended package), benign-reference candidates. |
| Cannot establish | Labels for Backstabber's and MalOSS rows beyond "in that collection" (no source, own licenses). "Benign" sets are popular packages, i.e. candidates, not proven safe. |
| Limitations | npm only; ends early 2023. None of the 406 names is in the DataDog npm manifest and none is in Ecosyste.ms, so it is disjoint from the other npm sources. [V] Package tarballs are live malware and are never extracted (D-008). |
| License | MIT for the authors' code and own dataset; Backstabber's and MalOSS terms **unverified**. [V] |

### 1.5 OpenSSF Malicious Packages (commit `b6d4ae95`, PyPI slice)

| Aspect | Finding |
|---|---|
| Problem investigated | A public database of reports of malicious packages. |
| Records | 11,992 readable PyPI reports, one package each, plus 362 withdrawn reports (337 npm, 25 PyPI). [V] |
| Original labels | A `MAL-` report means a reporter asserted the package meets the repository's definition of malicious. The definition includes typosquatting, account takeover, dependency confusion and security-researcher activity; empty or trivial squats are "borderline" but allowed. `withdrawn` means the report was retracted. [V] |
| Nature | **Real-world reports**, aggregated from other reporters. |
| Legitimate ground truth | `malicious_reported` at package or version scope; `withdrawn` as a separate family. |
| Supports | Agent 2 (evidence), Agent 3 (risk), Agent 5 (rejecting a recommended package that is reported malicious). |
| Cannot establish | The attack type (typosquat vs other) in structured form; that an unlisted package is safe; npm coverage (absent from this slice). |
| Limitations | 10,033 of 11,992 reports have a single origin source; origins are concentrated (`kam193` 7,987 entries, `checkmarx` 6,374, `reversing-labs` 5,753). 5,620 reports list explicit versions; 6,411 use ranges. Published dates: 2022: 20, 2023: 6,467, 2024: 2,645, 2025: 1,246, 2026: 1,613. [V] |
| License | Apache-2.0. [V] |

### 1.6 DataDog malicious software packages (commit `72c723be`, manifests only)

| Aspect | Finding |
|---|---|
| Records | Name manifests: npm 48,600 (46,526 whole-package, 2,074 version-scoped), PyPI 1,835 (1,817 / 18), AI skills 204, IDE extensions 103. [V] |
| Original labels | `null` = "malicious intent", all versions. A version list = a legitimate package that was compromised in those versions. Absence from the manifest is "inconclusive" (README). [V] |
| Nature | **Real-world**, human-triaged per the README, mostly found by one tool (GuardDog); the README warns of selection bias. [V] |
| Legitimate ground truth | `malicious_reported` (name scope) and `compromised_version` (version scope). The two must stay distinct. |
| Supports | Agents 2, 3 and 5, and the only large npm malicious list available. |
| Cannot establish | Anything about code or behaviour (no samples); independence from OpenSSF (1,371 of 1,835 PyPI names are also OpenSSF reports [V]). |
| License | Apache-2.0, attribution requested. [V] |

### 1.7 OSV.dev (PyPI export, 2026-11-12)

| Aspect | Finding |
|---|---|
| Records | 26,859 readable: MAL 12,017, PYSEC 7,986, GHSA 6,844, OSV 12. [V] |
| Original labels | GHSA and PYSEC are **vulnerability advisories** for legitimate packages, with affected ranges. MAL records republish OpenSSF. |
| Nature | **Real-world advisories.** |
| Legitimate ground truth | `vulnerable` at version-range scope; a `fixed` event exists in 6,008 GHSA and 6,858 PYSEC records. Withdrawn: 251 GHSA, 355 PYSEC. 1,697 distinct PyPI package names have a non-withdrawn advisory. [V] |
| Supports | Agent 2 (advisory evidence), Agent 4 (fixed version as the evidence for an upgrade), Agent 5 (checking that a recommended version is outside every affected range). |
| Cannot establish | Reachability or exploitability in a project; that an upgrade is compatible; npm vulnerabilities (absent). |
| Limitations | GHSA and PYSEC alias each other (double counting). GHSA records include 487 affected entries for other ecosystems. Publication dates are heavily skewed to 2026 (6,853 of the non-withdrawn GHSA+PYSEC records). [V] |
| License | **Unverified** (terms vary per upstream source). |

### 1.8 PyPI MalRegistry (listing only), deps.dev (absent), real manifests

- **MalRegistry:** a path listing (12,600 version paths, 10,790 names), no archives, no license. It adds names that largely duplicate OpenSSF (9,480 of 10,790, per the Phase 3 report). Usable only as a corroborating name list; never redistributed.
- **deps.dev:** absent. No dependency-graph, popularity or version-history data is available.
- **Real manifests:** 326 manifests from 12 popular repositories (109 project, 217 test fixtures; React contributes most). Real-world input for Agent 1. The gold dependency lists were drafted by the submitter and are not human-reviewed. They contain **no** labelled risky dependencies, so they can only serve as benign-reference input and parser tests. Licenses unverified.

---

## 2. The problem categories and how they relate

| Category | Definition used here | Does the package exist? | Is someone acting maliciously? |
|---|---|---|---|
| Package hallucination | An LLM names a package that was not registered when the answer was produced | No, at that time | No (the model is wrong, nobody attacked) |
| Nonexistent dependency | A manifest names a package absent from the registry at lookup time (any cause: hallucination, typo, private or removed package) | No, at lookup time | Unknown |
| Typosquat / package confusion | A registered name chosen to be confused with a legitimate one | Yes (or it did) | Usually, not always (forks, research, placeholders) |
| Malicious package | A registered package reported to deliver harm | Yes (or it did) | Yes, as reported |
| Compromised version | Specific versions of a legitimate package that were malicious | Yes | Yes, for those versions only |
| Vulnerable package | A legitimate package with a known flaw in some versions | Yes | No |
| Dependency confusion | A public package shadows a private name | Yes | Yes |
| Slopsquatting | An attacker registers a name that LLMs hallucinate | Yes, afterwards | Yes |

Relationships that the data supports:

1. **Nonexistence is a moment, not a property.** A hallucinated name is harmless until someone registers it. The Package Hallucination data records 2 mentions whose name was registered after the answer. [V]
2. **Name-error space and attack space overlap.** 25 of the 1,049 typo and fake names planted in LibHalluBench prompts are names of reported-malicious PyPI packages. [V] A user typo or model typo can therefore resolve to real malware.
3. **Existence does not imply safety, and it is what an existence-only check cannot see.** All 406 YCTT typosquats existed on npm. The recorded Agent 3 v1 probe (`eval_run_2026-11-12T182055+0000.json`, re-read in the review) flagged 88 of 132 typosquat cases; all 88 were not-found lookups scored "high", and all 44 registry-present cases scored low. That run used current lookups and a foreign repository commit, so it is an indication, not a result of this project. [V]
4. **Typosquat and malicious are different claims.** Ecosyste.ms explicitly includes non-malicious pairs. OpenSSF explicitly includes non-typosquat malware. Only 37 of 94 Ecosyste.ms PyPI variants are OpenSSF reports. [V]
5. **Vulnerable is not malicious, and popular packages are both targets and vulnerable.** 12 of the 35 Ecosyste.ms PyPI typosquat targets have at least one vulnerability advisory; none is an OpenSSF malicious report. [V] So "replace the typosquat with its target" can itself land on a vulnerable version.
6. **The correct response differs by category.** Remove or correct a nonexistent name; replace a typosquat with the intended package; remove a malicious package; avoid specific versions of a compromised package; upgrade a vulnerable one. A system that merges the categories cannot recommend correctly, which is the practical reason behind D-012.

Point 5 is the core of the remediation problem: **a recommendation is a new dependency decision and can itself be nonexistent, malicious, a typosquat or vulnerable.** [H] The literature supports that LLMs make such errors (`LITERATURE_REVIEW.md` H1, R1, R3).

---

## 3. What the available data can and cannot evaluate

| Category | Evaluable now? | Positive ground truth | Scope | Main weakness |
|---|---|---|---|---|
| Nonexistent / hallucinated | **Yes, small** | 34 human-confirmed names (Package Hallucination), dated | PyPI | Tiny positive set; LibHalluBench adds prompts, not labels |
| Typosquat | **Yes** | 406 npm pairs (YCTT) + Ecosyste.ms pairs (95 PyPI, 37 npm) after review of non-attack rows | npm, PyPI | Ecosyste.ms is mixed-intent; overlaps malicious lists |
| Malicious (reported) | **Yes** | OpenSSF 11,992 PyPI; DataDog 48,600 npm and 1,835 PyPI names | PyPI, npm (names only) | Reporter overlap; no code; "not listed" is inconclusive |
| Compromised version | **Limited** | DataDog version lists (2,074 npm, 18 PyPI) | mostly npm | No independent confirmation |
| Vulnerable | **Yes, PyPI only** | 14,830 GHSA+PYSEC records, 1,697 PyPI names, fixed versions in most | PyPI | No npm; alias double counting; no reachability |
| Benign reference | **Candidates only** | YCTT popular and target sets; real manifests | npm, PyPI | Not proven safe |
| Dependency confusion | **No** | One documented row (`torchtriton`) | — | No dataset |
| Impersonation beyond name similarity (metadata, author, README) | **No** | — | — | No metadata or code available |
| Slopsquatting as an observed attack | **No** | 2 "registered after" mentions, unlabelled as to intent | — | No dataset |
| Remediation correctness | **Partly, by properties** (see below) | Typosquat targets; advisory fixed versions | PyPI, npm | No human-labelled "correct recommendation" set exists |

**No gold set of correct recommendations exists, and creating one by hand or by model would be synthetic ground truth (forbidden, D-002).** What the data does support is checking *properties* of a recommendation against source records [P]:

- the recommended package is not reported malicious, not a listed typosquat variant, and not withdrawn-only;
- the recommended version is outside every known affected range;
- for a typosquat with a source-stated target, the recommendation names that target;
- every factual claim in the recommendation cites an evidence record that exists and says what is claimed.

Whether the recommended package and version **exist** needs a registry lookup. No registry snapshot is in the data; live lookups need owner approval and must be time-stamped (see `RESEARCH_QUESTIONS.md` §6 and §8).

---

## 4. Proposed scope [P]

**In scope**

1. Four risk families, kept separate end to end: nonexistent, typosquat, malicious (with compromised-version as a sub-scope), vulnerable.
2. Ecosystems: **PyPI for all four families; npm for typosquat and malicious only.** This follows the data, not preference.
3. The remediation step: producing a recommendation for a flagged dependency, and independently verifying that recommendation before it is shown.
4. Name-level and version-level evidence only.

**Out of scope**

- Dependency confusion, metadata or author impersonation, and slopsquatting as an observed attack (no data).
- Code-level malware detection (no samples may be opened; well covered by prior work).
- Reachability, exploitability and build compatibility of an upgrade (no data, would require installing packages).
- Measuring hallucination rates of LLMs (already done at scale by prior work; our data cannot add to it).
- Ecosystems other than PyPI and npm.
- Automatic application of fixes (no `pip install`, no merges).

**Problem statement [P].** Given a project's declared dependencies, (a) attach to each dependency the evidence that it is nonexistent, a typosquat, reported malicious or known vulnerable, without merging these claims; (b) recommend a remediation whose every claim is traceable to that evidence; and (c) independently verify that the recommendation does not itself introduce a nonexistent, typosquatted, malicious or vulnerable dependency. The research interest is in (b) and (c): how reliable remediation recommendations are, and how much an independent deterministic check improves them.

---

## 5. Open data issues that affect this scope

1. The nonexistent family has 34 confirmed positives. Any result on it will have wide confidence intervals.
2. No historical registry snapshot exists. Existence checks are either dated labels from sources (Package Hallucination, YCTT) or new time-stamped lookups.
3. Malicious sources are not independent, so cross-source agreement cannot be used as validation.
4. The LibHalluBench template artifact (963 rows) must be traced upstream before those rows are used.
5. Ecosyste.ms rows need a documented per-row review (attack, research demo, synthetic, legitimate fork) before use as typosquat positives.
6. Licenses for OSV and the real manifests remain unverified.
