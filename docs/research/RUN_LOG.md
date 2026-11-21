# Run log

Every run that touches the network, real data or a model is recorded here with its purpose, selection rule, inputs, outputs and provenance, so that each number used in the paper can be traced to a run. Raw outputs are stored under `research/datasets/` (git-ignored) and identified here by path and SHA-256. Runs are descriptive unless stated otherwise; none of them is an experiment of the evaluation design (`RESEARCH_METHODOLOGY.md`) yet.

## RUN-001 — First live registry check (2026-11-16)

- **Approval:** owner, 2026-11-16 (D-054). Metadata-only lookups under D-021/D-047 b; nothing downloaded or installed.
- **Purpose:** verify the registry client against real PyPI and npm responses, check the npm holding-package and unpublished rules (D-053 c, marked unverified), and obtain real recordings in the `registry_snapshot/1` format.
- **Client:** `registry_client/1` (`src/multi_agentic_security/agents/agent2_registry/client.py`), HTTPS to `pypi.org` and `registry.npmjs.org` only, generic User-Agent, no credentials, 0.5 s pause between requests.
- **Window:** 2026-11-16T18:27:15Z to 18:27:30Z.
- **Selection rule (fixed before the run):** controls PyPI `requests`, `PyYAML`, `djangorestframework`, npm `lodash`, `string-width`, `@sindresorhus/is`; one invented name per registry (`mas-nonexistent-check-20261116`); the 4 most recently published whole-package npm and PyPI malicious reports in `malicious_withdrawn/openssf_a2`; the first 4 npm names (sorted) with whole-package scope in `malicious/datadog_manifests`.
- **Output:** `research/datasets/registry_snapshots/live_check_2026-11-16/` — 16 recordings (verbatim bodies) and `RUN_RECORD.json` (SHA-256 `ed370b9025ce8a36e8ebcfc5dbb1b8ec09896e5d45f2990b8bdcaef068de1762`) with the selection rule, per-lookup file hashes and parsed results.

### Results (16 lookups, all answered; no `lookup_error`)

| Group | n | Registry answer | Agent 2 status |
|---|---:|---|---|
| Controls (PyPI 3, npm 3, incl. one scoped npm name) | 6 | HTTP 200 | `found` (versions 32–163; canonical names as published, e.g. `PyYAML`) |
| Invented names (PyPI 1, npm 1) | 2 | HTTP 404 | `not_found` |
| OpenSSF whole-package npm malicious reports | 0 | — | the table holds no npm `malicious` records (npm OpenSSF reports were not acquired, D-041; npm records there are `withdrawn` only) |
| DataDog npm malicious, whole package | 4 | HTTP 200, only version `0.0.1-security`, description "security holding package", repository `npm/security-holder` | `security_placeholder` |
| OpenSSF PyPI malicious, most recent | 4 | HTTP 404 | `not_found` |

### Findings

1. **npm holding-package rule confirmed** on 4 of 4 real responses. The rule is no longer marked unverified. The npm **unpublished** rule was not observed and stays unverified.
2. **npm keeps the removed version in `time`.** In all 4 holders, the removed version `999.9.9` is still listed with its upload time (2024-12-14), and the holder version with its own time (2025-01-14): each malicious version was installable for about 31 days before replacement. A version number like `999.9.9` is typical of dependency-confusion uploads. Agent 2 now reports `removed_versions` and `placeholder_published` (registry facts, not judgements). Observation on 4 names from one source; not a measured rate.
3. **PyPI answers 404 for removed malicious packages** (4 of 4), exactly as for an invented name. A registry `not_found` therefore cannot separate a nonexistent (e.g. hallucinated) name from a taken-down malicious package. Consequence for the design: the `nonexistent` finding (Agent 3) must check the malicious evidence first, and the evaluation must not count removed malicious packages as nonexistent. Consequence for held-out runs: a current 404 is not historical status (D-021).
4. Canonical names come from the registry (`PyYAML` for the request `pyyaml`).

### Limitations

Small, purposive selection for rule checking; no rates are estimated. The first four DataDog names share one prefix (`000webhost-*`, sorted order), so finding 2 reflects one campaign.

## RUN-002 — Agents 1→2→3 sanity pass on real data (2026-11-17)

- **Purpose:** check that real evidence records (OSV ranges, OpenSSF and DataDog reports, popular list) and the real RUN-001 registry recordings pass through Agent 3 v2 without failures, and compare v1 and v2 on those names. A sanity check of the code path, **not** an experiment of the evaluation design: no split, no cut-off, purposive names.
- **Inputs:** the 16 RUN-001 names (PyPI names in a `requirements.txt` without constraints, npm names in a `package.json` with `*`) plus `requests==2.31.0` and `requests==2.25.0`; evidence store `evidence_store/1` over the 8 current tables (all hashes verified, 123,980 records); registry mode `snapshot` on RUN-001 recordings. Script kept outside the repository; nothing written under `research/datasets`.
- **Result:** 18 dependencies, no Agent 2 or Agent 3 failures; store load 4.2–4.5 s, Agent 2 0.04 s, Agent 3 about 1 s (including the 15,000-name similarity index).

| Dependency group | n | v1 baseline | v2 findings |
|---|---:|---|---|
| npm packages replaced by security holders (DataDog-reported) | 4 | low (0) | `malicious_reported` + `registry_security_hold` |
| PyPI packages removed after malicious reports (404) | 4 | high (50) | `malicious_reported` (3 also `compromised_version`, undetermined version; `fabrice` also `name_similar_to_popular` to `fabric`); **not** `nonexistent` |
| Invented names (404, no reports) | 2 | high (50) | `nonexistent` |
| Popular packages, unconstrained | 6 | low (0) | `no_evidence` (advisories cover older versions only) |
| `requests==2.31.0`, `requests==2.25.0` | 2 | low (0) | `vulnerable` (affected) |

- **Design change found by this run:** in the first pass, unconstrained popular packages (`requests`, `PyYAML`, `djangorestframework`) received `vulnerable` with applicability `possible` only because old versions had advisories. Since the version pip would install (highest allowed, not yanked) is not affected, this was a false finding. Rule changed (D-055): such records yield no finding and a reason `a3.<family>.installed_version_not_affected` that keeps the older affected versions visible.
- **Observation for RQ4 (not a measurement):** v1 gives `low` to every registry-present malicious package (here the 4 npm holders) and `high` to removed malicious packages only because they are absent, scoring them the same as invented names; v2 separates the three cases. The RQ4 measurement itself will be run on the evaluation sets after the protocol is fixed.

### RUN-002 repeat after the Agent 3 review (2026-11-17)

Same inputs after the D-056 corrections: identical findings and v1 levels (no Agent 2 or Agent 3 failures). Limitations recorded for later RQ4 reporting: name similarity is off in held-out runs before 2026-11-01 (popular-list date), and v1 scores a post-cut-off `not_found` while v2 reports `unknown`.

## RUN-003 — Agent 3 re-evaluation on real inputs, with and without a cut-off (2026-11-17)

- **Approval:** registry lookups are metadata-only and time-stamped under D-021 (22 lookups). The run is part of the Agent 3 re-evaluation before Agent 5. It is a descriptive check of the code path, **not** an experiment of the evaluation design: purposive inputs, no split.
- **Purpose:** check on real inputs that compromised releases of popular packages are flagged only for the affected versions; count crashes, implausible findings and name-similarity false positives; check that no evidence or registry version from after a cut-off reaches Agent 3, and record what disappears under a cut-off.
- **Inputs (selection fixed before the run):**
  - **Part A:** the 326 indexed manifests of the 12 real repositories in the dataset (`real_manifests/index.jsonl`: requests, flask, httpx, pydantic, fastapi, pipenv, poetry, axios, express, react, lodash, vue core). Agents 1→2→3 ran with registry mode `off` (no network). Agent 1 gives 3,897 dependencies (3,841 npm, 56 PyPI; 1,840 distinct names), mostly exact versions from lock files.
  - **Part B:** the 22 names of the label conflicts in `DATASET_EVALUATION.md` §3. These are the 16 "benign reference and malicious" names, the 4 further "benign reference and withdrawn" names and the 2 further "typosquat target reported malicious" names. Five kinds of declaration were generated for each name:
    - no constraint;
    - an exact pin to every reported malicious version still in the registry;
    - a pin to the latest version;
    - a pin to the highest version below the lowest reported one;
    - one range covering the lowest reported version (npm `^M.m.0`, PyPI `~=M.m.0`).

    That gives 98 dependencies, run with registry mode `snapshot`.
  - Evidence store `evidence_store/1`: the 8 current tables, hashes verified, 123,980 records.
- **Registry lookups:** 22 metadata-only lookups on 2026-11-17, saved verbatim under `research/datasets/registry_snapshots/run003_2026-11-17/` (`RUN_RECORD.json` SHA-256 `a11027fb61a4cd828ff49542598b46ecc57f78e2aceb145e5e63f4a1b3bfbd60`). 21 were found; PyPI `detectron2` returned 404.
- **Cut-offs:** none, 2024-12-01, 2025-09-01.
- **Outputs:** `research/datasets/runs/run003_2026-11-17/` holds the scripts and two result files: `results_before_d057.json` (SHA-256 `e3acd312f499ebcb88a8465bd2599288e17f1895013eef7e8a91154d4ebf5f4a`) and `results_after_d057.json` (`59f6e6b66ccf8552a03b2d9b022a9a1430979b2f2408eeee921adb635a265f15`).

### Results

None of the 6 runs (3 cut-offs × 2 parts) had an Agent 2 or Agent 3 failure or a contract violation. Agent 1 reported 346 input failures in Part A. These are Agent 1 scope limits, not crashes:
- 167 unsupported manifests, mostly poetry's `pyproject.toml` fixtures, with their 167 unsupported-file entries;
- 9 package.json fields not interpreted;
- 3 folders without a manifest.

| Part, cut-off | Findings before D-057 | Findings after D-057 |
|---|---|---|
| A, none | compromised 12, vulnerable 12, withdrawn 56, similar 66 | compromised 2, vulnerable 12, withdrawn 5, similar 66 |
| B, none | compromised 56, vulnerable 33, withdrawn 8, malicious 1 | compromised 28, vulnerable 25, malicious 1 |
| B, 2024-12-01 | vulnerable 3, withdrawn 2, unknown 3 | vulnerable 3, withdrawn 1, unknown 3 |
| B, 2025-09-01 | compromised 2, vulnerable 5, withdrawn 2, unknown 3 | compromised 2, vulnerable 5, withdrawn 1, unknown 3 |

The table leaves out `unknown` from registry mode `off`, which is on every Part A dependency.

### Findings

1. **False findings by name, corrected (D-057 a, b).**
   - Before the corrections, 14 of the 16 popular packages with compromised releases got `compromised_version` (applicability `undetermined`) when declared without a version. Examples are npm `debug` and `axios`, and PyPI `ultralytics`, `litellm` and `telnyx`. The only cause was that the reported release had been deleted from the registry; the version a new install would get was not reported.
   - In Part A, 10 of the 12 compromised findings were npm ranges that cannot include the reported version, such as `chalk ^2.1.0` against 5.6.1.
   - After D-057:
     - every exact pin to a reported release still in the registry is `affected` (22 of 22);
     - pins to clean versions give no compromised finding;
     - declarations without a version are flagged only where the version a new install gets is itself reported (PyPI `pytorch` 1.0.2, `beautifulsoup` 3.2.2).
   - The 2 remaining Part A findings (`chalk ^5.3.0` and `debug ^4.4.0`, registry off) are ranges that do allow the reported release, so they stay `undetermined`.
2. **Withdrawn reports, corrected (D-057 h).** 51 of the 56 `withdrawn_only` findings were react dependencies, and the retracted reports name versions 1.0.0 and 35.0.0. The 5 that remain declare the npm dist-tag `experimental`, which is undetermined by design.
3. **Name similarity: all 14 distinct flagged names are false positives.**
   - They cover 66 of the 3,897 dependencies, all npm. Each is a well-known package one edit away from a name on the npm list: `eslint`/`tslint`, `yargs`/`args`, `supports-color`/`supports-colors`, `preact`/`react`.
   - Cause: the npm list holds the 232 undated YCTT typosquat targets. It is not a popularity ranking: `express`, `eslint` and `yargs` are not on it.
   - No PyPI name was flagged (56 dependencies, against a PyPI list of 15,000 names).
   - This is a limitation and was not changed (D-057 k).
4. **Held-out behaviour.**
   - An automatic check over all findings and registry results found 0 violations. No evidence published on or after a cut-off, no undated evidence and no registry version uploaded on or after a cut-off reached Agent 3.
   - What disappears under a cut-off:
     - All findings that rest on undated sources (MalRegistry, DataDog). Here that is every compromised finding except `num2words`, whose OpenSSF reports are dated 2025-07-31 and so remain at the 2025-09-01 cut-off.
     - All name similarity, because the popular lists are dated 2026-11-01 or undated.
     - The existence status of packages whose snapshot is later than the cut-off. `detectron2` (404) becomes `unknown`, and so does `massive`, which was registered after 2024-12-01.
5. **Sources disagree on version scope (observation, not verified).**
   - For PyPI `litellm`, 16 of the 22 malicious records come from MalRegistry (undated) and name versions that are still on PyPI. OpenSSF (dated) names 3.
   - The reports for `beautifulsoup` and `pytorch` come from MalRegistry only.
   - Agent 3 reports the source of each record. Agreement or disagreement between these sources is not independent evidence (`DATASET_EVALUATION.md` §2).
6. **v1 baseline.** It gives `low` to 97 of the 98 Part B dependencies, including every reported compromised release, and `high` only to `detectron2`, which returns 404. It gives `unknown` to all of Part A, which has no registry status. This is a description, not a measured result.

### Limitations

- The names are purposive and the declarations generated.
- Only Part B has registry data. Without it, range declarations in Part A cannot be resolved.
- The 12 repositories are popular open-source projects, so the run says little about uploads that contain hallucinated or malicious names.

### RUN-003 repeat after the third review (D-058, 2026-11-17)

- Same inputs, store and snapshot as RUN-003, run offline (no lookups): `research/datasets/runs/run003_2026-11-17/results_after_d058.json` (SHA-256 `302af5bae8c88a343985250b380fe7ba4636805ef72ffdb03cafc2c669b1974b`).
- Result: no row changed against the D-057 results, in Part A or Part B, at any of the three cut-offs; 0 leaks.
- Reason (verified): the current evidence store holds no npm record with a version range, so the corrected pre-release reading of npm evidence ranges has nothing to act on; the other D-058 cases (`*` with a pre-release `latest`, a yanked release that changes the choice under a cut-off, a security hold after the cut-off) do not occur in these inputs. The corrections matter for later npm advisory data and for held-out runs on other inputs.

### RUN-003 repeat after the Agent 5 review (D-060, 2026-11-17)

- Same inputs, offline: `research/datasets/runs/run003_2026-11-17/results_after_d060.json` (SHA-256 `8de949b2ac908ae4d745ed4bd6929985da75f2abc4f7b042459b406a209a0835`).
- Result: no row changed against the D-058 results, in Part A or Part B, at any cut-off; 0 leaks. No input in RUN-003 pins or resolves to a pre-release of a range's upper bound, so the interval reading of PyPI evidence ranges (D-060 a) changes nothing here.
- Agent 5 was not run on real data: Agent 4 does not exist yet, so there are no real recommendations to verify.

### RUN-003 repeat after the D-060 review (D-061, 2026-11-17)

- Same inputs, offline: `research/datasets/runs/run003_2026-11-17/results_after_d061.json` (SHA-256 `66aef00421cfa7d3fb4a0f3d2b36b315271e75d7773eb05e5dd6c75b9dd20f7e`).
- Result: no row changed against the D-060 results, in either part, at any cut-off; 0 leaks.

## Agent 3 behaviour (state after D-061, for the paper)

- **What this state rests on:**
  - RUN-002 (18 dependencies) and RUN-003 (3,897 real-repository dependencies plus 98 generated declarations, at three cut-offs);
  - three independent scoring reviews (D-056, D-057, D-058) and the two Agent 5 reviews (D-060, D-061), which also corrected Agent 3;
  - version logic checked on 99 documented node-semver cases;
  - PEP 440 and pip edge cases: `===`, local versions, `==1.*`, `!=`, `~=`, only pre-releases, only yanked releases, invalid registry versions.
- **v1 versus v2 (described, not a result):**
  - v1 scores registry existence against a 7-name catalogue. It cannot see version-specific or registry-present malicious packages (all `low` above).
  - v2 reports per family and per version. It separates removed malicious packages, invented names and security holders.
  - v1 has no notion of time. It scores a post-cut-off `not_found`, and it maps a package registered after the cut-off to `verified`; in both cases v2 reports `unknown`. The RQ4 comparison must state both asymmetries.
- **Known limits:**
  - npm dist-tags, aliases, URLs and Git specifiers are undetermined.
  - PyPI and npm resolution assume a fresh install with the default resolver and no other constraints or markers.
  - `fixed_in_stated` and `fixed_in_released` are not safe targets by themselves.
  - Name similarity is off before 2026-11-01, because of the popular-list dates. For npm it rests on a 232-name target list that gives false positives on real projects.
  - Evidence is dated only by publication, so later withdrawals and range edits are visible in held-out runs.
  - Most malicious sources are undated, so version-specific malicious evidence largely disappears under a cut-off.

## Agent 5 behaviour (state after D-061, for the paper)

- **What this state rests on:**
  - two independent reviews (D-060, D-061) and 181 Agent 5 tests (unit, review regressions, integration Agent 1 → 2 → 3 → hand-written recommendations → 5);
  - no run on real recommendations yet, because Agent 4 does not exist.
- **What "verified" means:** every required check passed or did not apply, with the evidence and registry data known at the cut-off. It is not a statement that the dependency or target is safe; Agent 5 cannot detect an unreported malicious package (`SYSTEM_ARCHITECTURE.md` §3).
- **Fail-closed design:** anything that cannot be checked is "needs review", never "verified". This includes a missing or incomplete evidence store, a failed or refused registry lookup, a target not in the snapshot, an unreadable version, and history that the snapshot cannot show.
- **Consequences for RQ1 reporting:**
  - Under a cut-off, recommended targets need recorded registry lookups; targets missing from the snapshot are "needs review". Coverage loss must be reported next to the unsafe rate.
  - A hallucinated target version under a cut-off is "needs review", not "rejected" (D-061 g). Hallucinated versions must be counted from the scorer's own data, not from Agent 5's rejections.
  - A report withdrawn after the cut-off already looks withdrawn in held-out runs (D-060 i).

## PLAN-001 — Recorded registry lookups for recommended targets in held-out runs (plan, not a result; 2026-11-17)

**Status: plan only. Nothing below has been run.** The live lookups need the owner's go-ahead before the first batch. Registry lookups are metadata-only and time-stamped (D-021, D-027).

**Why it is needed:**
- Agent 5 checks a recommended target against registry data. In held-out runs it refuses live lookups, so a target that is not in the snapshot is "needs review" (D-059 e).
- Without recorded target lookups, C1–C5 coverage would mostly reflect which targets happen to be in the snapshot, not what the recommenders did.

**Procedure, per experiment batch (generate first, then look up, then verify):**
1. **Generate.** Run every Agent 4 variant (R0, and LLM-U and LLM-G for each model and seed) on the frozen case set. Store the `RecommendationResult`s and the raw responses. No verification in this step.
2. **Collect.** Gather the union of names that need registry data and are not yet recorded:
   - `replace` targets;
   - claim subjects other than the dependency.
   `upgrade` and `downgrade` keep the dependency's own package, whose lookup Agent 2 already recorded. A name that fails name validation is counted and not looked up.
3. **Record.** One metadata-only lookup per name with Agent 2's HTTP client:
   - written as `registry_snapshot/1` files into a new folder `research/datasets/registry_snapshots/<run>_targets_<date>/`, with a `RUN_RECORD.json` (times, client version, counts per status, file hashes);
   - nothing is downloaded or installed;
   - each name is looked up once per batch;
   - a later batch writes a new folder and never edits an earlier one.
4. **Verify.** Agent 5 reads the dependency snapshot and the target snapshot together. This needs a read-only client over several snapshot folders, which is a Phase 7 task; until then the folders cannot be combined without copying.
5. **Freeze.** The folder hashes go into the protocol before scoring.

**Fairness:**
- One target snapshot serves every variant, model and seed of a batch.
- The lookups happen after all generation, so no variant influences what is recorded for another.
- All lookups lie after the cut-off. Agent 5 filters versions by upload time in the same way for every variant.

**Expected effect on Agent 5 (from D-059 e and D-061 g):**
- A target name that is `not_found` or under a security hold in a lookup recorded after the cut-off is "needs review", not "rejected", because the lookup cannot show the state at the cut-off.
- A stated target version missing from the snapshot is "needs review" under a cut-off.
- Without a cut-off, both are "rejected".

**How hallucinated targets are counted.** The scorer counts these from its own reading of the snapshot and the evidence, independently of Agent 5 (D-036). Agent 5's verdicts are tabulated next to the counts, never used as the count.
- **Nonexistent target package:**
  - the target name is `not_found` in the target snapshot;
  - and no evidence record of any family names it at any time;
  - and it is on no benign list.
  - A `not_found` name that evidence does name is counted separately as a **removed target** (typically a removed malicious package).
- **Nonexistent target version (D-061 g):**
  - the stated version is not among all the versions the snapshot lists for the target (including versions uploaded after the cut-off and yanked ones).
  - A stated version that exists but was uploaded on or after the cut-off is counted separately as a **future version**: it was not available at the cut-off.
  - A missing version that an evidence record names (for example a deleted malicious release) is counted as a **removed version**, not as hallucinated.
- **Denominators:**
  - for package counts, recommendations with a target;
  - for version counts, recommendations with a stated target version;
  - reported per variant, model and family.
- **Verifier cost:** the "needs review" verdicts that these cases cause under a cut-off are reported as a coverage cost of verification. They are not counted as wrong rejections or as safe accepts.

**Limits:**
- A normal release deleted between the cut-off and the lookup looks hallucinated. Registries rarely delete normal releases; malicious ones are caught by the evidence cross-check above.
- Lookups record today's state, so yanks and security holds after the cut-off are visible. Agent 5 already treats both as not historical.

## Agent 4 behaviour (state after D-063, for the paper)

- **What this state rests on:**
  - one independent review (D-063);
  - 76 Agent 4 tests (R0 rules, LLM interface with recorded responses, review regressions);
  - an integration test Agent 1 → 2 → 3 → 4 (R0) → 5 on the hand-written test fixtures, with and without a cut-off.
  - No run on real data, and no LLM call: providers and models are not chosen yet.
- **R0 against Agent 5 on the fixtures** (19 dependencies; a test check, not a result):
  - without a cut-off, every R0 recommendation is verified;
  - with the cut-off 2026-01-01, one is "needs review": a `keep` whose pinned version was uploaded after the cut-off, so Agent 5 cannot check it. This is a correct verifier decision.
  - Two R0 defects were found this way before the review and corrected in D-062: the absence claim on a package with records for other versions, and a stated fix that is yanked on PyPI.
- **What R0 adds to the rules in `RESEARCH_QUESTIONS.md` §7** (fixed before any run, D-062 and D-063):
  - precedence between findings;
  - `investigate` for undetermined applicability and for name similarity;
  - `abstain` for unknown state;
  - `keep` for withdrawn-only;
  - replacement refused when the imitated package is itself flagged;
  - the upgrade target is a released, final, clean version at or above a stated fix.
- **Consequences for RQ1 reporting:**
  - R0's `abstain` and `investigate` count against coverage, not against safety.
  - `fixed_in` names the recommended version, which may lie above the advisory's own fix (D-063 d).
  - LLM citations of IDs that were not given are kept and flagged, so the unsupported-claim rate can be measured (D-062 f).

## TRIAL-001 — First live calls to Groq and Gemini on the fixture project (2026-11-18)

*Note (D-068, 2026-11-19): Gemini was removed from the project after this trial. The Gemini rows below are kept as the record of what was run.*

- **Purpose:** check the adapters (D-064), response formats, failure handling and speed. **Not an evaluation:** no case set, no ground truth, no claim about model quality.
- **Inputs:** the hand-written fixture project `tests/fixtures/agent2` (19 dependencies; invented or well-known names; no dataset records, no user data), no cut-off, Agents 1 → 2 (snapshot) → 3 → 4 (LLM-U and LLM-G) → 5. Output budget 2048 tokens, temperature 0, timeout 120 s, `a4-prompt/0.1`.
- **Models:** Groq `openai/gpt-oss-20b` (a reasoning model); Gemini: the model named in the owner's local settings (not recorded in this run file; to be recorded in the next run).
- **Raw output (git-ignored):** `runtime/runs/trial001_2026-11-18/` (attempt 1) and `runtime/runs/trial001b_2026-11-18/` (attempt 2); one JSON file per response, named by SHA-256, plus result tables.

### Results

| Attempt | Provider | Outcome |
|---|---|---|
| 1 | Groq | 108 calls, all HTTP 403 (`error code: 1010`): firewall block on Python's default user-agent. Fixed in D-065 a. |
| 1 | Gemini | partly run: 20 × 503, 1 timeout, 1 × 429 (service overloaded or limited). Stopped by hand. |
| 2 | Groq | 66 calls: 29 complete answers, 37 × HTTP 429 (rate limit). |
| 2 | Gemini | 106 calls: 0 answers; 102 × 429, 2 connection errors, 1 × 503, 1 timeout. |
| 2 | — | Stopped by the system because the computer was critically low on memory (not caused by the trial). |

**Groq answers that were received (attempt 2; counts are of recommendations, not independent samples; n = 19 per variant, 6 or 2 lost to rate limits as `llm_error` → `abstain`):**
- LLM-G: 13 answers, all well-formed. Agent 5: 11 verified, 1 rejected, 1 needs review. LLM-U: 17 answers; Agent 5: 10 verified, 7 rejected (every rejection is `claims_supported`: claims that cite no evidence), plus 2 abstains from rate limits.
- **Agreement with R0 for LLM-G on the same fixture:** the same action on `evil-pkg` (remove), `strign-width` (replace `string-width`), `reqeusts-hallucinated` (remove), `requests==2.31.0` (upgrade 2.32.3, but see below) and `@types/node` (keep). The unresolved import abstained. `numpy` (registry state unknown): the model said keep, R0 abstains, Agent 5 "needs review".
- **One rejected grounded answer (`requests==2.31.0`):** the action and target equal R0's, but both `is_vulnerable` claims put an affected version range (`>=2.0.0,<2.31.0`) in the `object` field, which must be a single version; Agent 5 rejected it as not a valid version. The cited evidence IDs were correct. This is the kind of unsupported claim the verifier is meant to catch.
- **LLM-U** (finding names only): its rejections all come from claims that cite no evidence, as expected for the ungrounded variant; for example it chose `remove` for a package with a withdrawn report only.
- All 29 Groq answers ended normally (`stop_reason: end`); none was cut off at the 2048-token budget.

### Limits
- 19 dependencies from a hand-written fixture; no inference about model quality or rates; Gemini produced no answer, so nothing is known about it.
- Rate limits, not the models, caused most failures. The free-tier limits of both accounts are not yet read from the consoles.
- The prompt was not changed after these observations (D-065 e).
- A reasoning model's hidden reasoning tokens count toward its limits and its budget; the next run records token usage per call.


## PLAN-002 — Evaluation protocol and free-tier budget (plan, not a result; 2026-11-19)

**Status: plan only. Nothing has been run and nothing is frozen.** The machinery exists (D-067); this lists what must be fixed and hashed before the first scored run.

**To freeze before any run (the protocol hash covers all of it):**
- the case lists (one per family) with their SHA-256, built from real evidence and real manifests only; the real-project sample of D-044 for the vulnerable family (acquisition needs the owner's approval);
- the split rule: `split_of`, seed 20261114, test fraction; the development side is used for prompt and rule changes, the test side once;
- the cut-offs (several, `RESEARCH_QUESTIONS.md` §6) and the registry snapshot folders, with hashes; no live lookups in held-out runs;
- the recommenders: R0 (`r0/0.1`), the prompt `a4-prompt/0.1` (or a versioned later one chosen on development cases only), the exact model IDs, temperature 0, seeds, the output-token limit;
- the non-inferiority margin for HYP4, the bootstrap size and seed, the family and model correction (Holm);
- the reporting rules: in-snapshot and held-out results separately; families never pooled; withheld recommendations count as lower coverage.

**Free-tier budget** (from the planner, D-067 f; assumptions: 1,400 tokens per call, 15% extra calls for repairs and errors, both LLM variants):

| Cases | Calls per model | Days at 142 calls/day (Groq, published base limits) |
|---|---|---|
| 100 (pilot) | 230 | 2 |
| 300 | 690 | 5 |
| 600 | 1,380 | 10 |
| 1,000 | 2,300 | 17 |

- C4 and C5 reuse the C3 and C1 runs (no extra calls). Re-running a finished run costs nothing (response cache).
- The numbers assume the published base limits apply to the owner's free plan; the console's Limits page is authoritative. Tokens per day is the binding limit, so a shorter prompt or a smaller output budget is the main lever, and any change is a new prompt version tested on development cases only.
- A resumable run that stops cleanly at the daily budget is the next engineering step.

**Not covered by the machinery:** human ratings and the claim-matcher audit (need annotators), the external audit tool C6, detection recall (RQ4).

**Known gaps in the scorer (stated, to be tested on real data):** version logic shared with Agent 5 for the range grammar; `U-V` needs the target's version list (PLAN-001 lookups), otherwise it is not scorable; no npm advisories exist in the evidence tables, so `U-V` is PyPI only.

**Owner's console limits (2026-11-19):** Groq `openai/gpt-oss-20b`: 30 requests/min, 8,000 tokens/min, 1,000 requests/day, 200,000 tokens/day (confirmed from the console, with the documentation page). The other model checked that day allowed 20 requests/day, which made a pilot take 12 days and a test set 35 days, so it was removed (D-068). Groq needs about 5 calls per minute (tokens per minute bind), roughly 46 minutes for 100 cases, if the daily token limit allows it. A second provider and model from another family is still to be chosen (D-068 d).

**Second-provider candidates (researched 2026-11-19 from the providers' own documentation pages; owner chooses; nothing is installed or called):**

| Candidate | What the official page says | Fit |
|---|---|---|
| **Groq, another model on the same account** | The rate-limits page lists `qwen/qwen3.8-27b` next to the gpt-oss models with the same base limits (30 requests/min, 1,000/day, 8,000 tokens/min, 200,000 tokens/day) and says limits apply per model. | Different family (Qwen), no new account, no new adapter. The owner's console must show the model on the free plan; same-account quotas are separate per model but the organisation is the same. |
| **Cloudflare Workers AI** | Free allocation of 10,000 neurons per day, reset at 00:00 UTC; text generation 300 requests/min; open-weight models from Llama, Qwen, Mistral, Gemma and DeepSeek families (some DeepSeek, Kimi and GLM models need a paid billing method). The page does not state whether a credit card is needed, and does not publish a daily request limit. | At about 900 input and 460 to 1,000 output tokens per call, `qwen3-30b-a3b-fp8` costs about 18 to 35 neurons per call, i.e. roughly 280 to 550 calls per day (my arithmetic from the published neuron prices; unverified in practice). Needs a new account, an API token and a new adapter (the endpoint shape is not checked yet). |
| **Cerebras** | Free trial credits of $5 "after adding a verified payment method"; `gpt-oss-120b` 5 requests/min; `qwen-3.8-27b` 300 requests/min. | A payment method is needed: against the owner's no-investment rule. |
| **GitHub Models** | Retired on 30 July 2026. | Not available. |
| **Mistral** | The documentation pages checked did not state free-tier limits; secondary sources say the free tier requires opting in to data training. | Unverified; not recommended without a check of Mistral's console. |
| **OpenRouter free models** | Secondary sources: 50 requests/day without purchased credit. | Too small; the serving provider behind a free model can change. |

Suggested set (D-038: models from different families): gpt-oss-20b on Groq (OpenAI family, working), `qwen/qwen3.8-27b` on Groq (Qwen), and one Llama, Mistral or Gemma model on Cloudflare Workers AI if the owner wants a third provider.

**Confirmed console limits for both Groq models (owner, 2026-11-19):** `openai/gpt-oss-20b` and `qwen/qwen3.8-27b` each show 30 requests/min, 1,000 requests/day, 8,000 tokens/min and 200,000 tokens/day; the Qwen model is therefore available on the owner's free plan. Limits are per model, so the two models have separate quotas (documentation statement; not yet tested). Tokens per day binds: about 142 calls per day per model at 1,400 tokens per call, so 100 cases with both variants take about 2 days, 300 cases about 5 days and 600 cases about 10 days, and the two models can run in the same days. Unverified: whether Groq counts the requested output limit (2,048) against tokens per minute; if it does, a call reserves about 2,950 tokens and only about 2 calls per minute fit in 8,000. The first trial of each model measures this (the 429 responses and the adapter's back-off make it visible).

**Splits:** train / dev (validation) / test and the fine-tuning pool are defined in `docs/research/EVALUATION_SPLITS.md` (D-070); none is built yet. Add the split design to the protocol hash list above.

## TRIAL-002 — Both Groq models on the fixture project (2026-11-19)

- **Purpose:** check both configured models (D-069) for answer format, failures, speed and token use after the adapter fixes of D-065. **Not an evaluation:** 19 hand-written fixture dependencies, no ground truth, no claim about model quality.
- **Inputs:** `tests/fixtures/agent2` (no cut-off), Agents 1 → 2 (snapshot) → 3 → 4 (LLM-U and LLM-G) → 5; `a4-prompt/0.1` unchanged; temperature 0; output limit 2,048 tokens; two schema repairs and two transport retries allowed; calls spaced 12 s (about 5 per minute); response cache and a 130-call budget per model.
- **Models:** `openai/gpt-oss-20b` (slot 1) and `qwen/qwen3.8-27b` (slot 2), each with its own key variable.
- **Raw output (git-ignored):** `runtime/runs/trial002_2026-11-19/`, one JSON file per response named by SHA-256, plus result tables and `summary.json`.

### Results

| Model | Variant | Answers (attempts) | Malformed then repaired | Recommendations completed | Agent 5 verdicts | Tokens in / out | Time |
|---|---|---|---|---|---|---|---|
| gpt-oss-20b | LLM-U | 21 | 3 | 19 of 19 | 11 verified, 8 rejected | 11,855 / 8,188 | 241 s |
| gpt-oss-20b | LLM-G | 20 | 2 | 19 of 19 | 15 verified, 4 rejected | 14,199 / 10,441 | 240 s |
| qwen3.8-27b | LLM-U | 18 | 0 | 19 of 19 | 11 verified, 8 rejected | 8,994 / 2,444 | 204 s |
| qwen3.8-27b | LLM-G | 19 | 1 | 19 of 19 | 16 verified, 3 rejected | 12,768 / 2,856 | 229 s |

- **No rate-limit error (HTTP 429) and no `llm_error` in 76 recommendations' worth of calls** at 12 s spacing; the daily and per-minute limits did not bind in this trial.
- Of gpt-oss-20b's 41 answers, 2 stopped at the 2,048-token limit (`stop_reason: length`) and were repaired by the retry; all 37 Qwen answers ended normally.
- Every rejection was the check `claims_supported`; no other check failed. No recommendation cited an evidence ID that was not given.
- **Token use per call** (input plus output, from the providers' counts): gpt-oss-20b about 1,230 (grounded) and 1,000 (ungrounded); Qwen about 820 and 640. Qwen's outputs are about a quarter of gpt-oss's, because gpt-oss spends tokens on hidden reasoning. The planner's 1,400 tokens per call is therefore conservative; at 200,000 tokens per day this is about 160 to 310 calls per day per model instead of 142 (PLAN-002).
- **Grounded answers against the rule baseline (R0) on the same fixture, descriptive only:**
  - both models removed `evil-pkg`, `reqeusts-hallucinated` and `undated-bad` (the reported malicious or invented names), as R0 does;
  - gpt-oss replaced `strign-width` with `string-width` as R0 does (verified); Qwen chose `remove` and was rejected on its claims;
  - on the pinned vulnerable `requests==2.31.0` both chose an upgrade (2.32.0 and 2.32.3) and were verified; for the unpinned `requests` entries both chose `upgrade` where R0 keeps, and Agent 5 rejected those claims;
  - gpt-oss removed `lodash` (withdrawn report only) and `compromised-lib` and was rejected on both; Qwen kept `lodash` and removed `compromised-lib` and was verified on both.
- The exact claim errors behind each rejection were not analysed in this trial.

### Limits
- 19 fixture dependencies, one run per model and variant; no confidence interval and no comparison between the models can be drawn.
- The fixture holds invented package names and small hand-written evidence; it says nothing about real packages.
- The prompt was not changed after these observations (D-065 e).
- The first run of each model: the speed numbers include the 12 s spacing.

## RUN-004 — the whole pipeline, rule recommender (R0), on the RUN-003 inputs, offline (2026-11-20)

- **Purpose:** run Agents 1 to 5 (variant R0, no LLM) end to end on real inputs and classify every verdict that is not "verified". **Not an experiment of the evaluation design:** the inputs are the purposive RUN-003 inputs, no split.
- **Inputs:** Part A, the 326 indexed manifests of the 12 real repositories (3,897 dependencies); Part B, the 22 conflict-list names with generated declarations (98 dependencies). Registry data: snapshot folders `run003_2026-11-17` and `live_check_2026-11-16` through the multi-folder client, for Agent 2 and Agent 5. No network. Cut-offs: none, 2024-12-01, 2025-09-01.
- **Output:** `research/datasets/runs/run004_2026-11-20/results_run004.json`, SHA-256 `367a6a43ee81cf0ced0ef1e792766370e473f7f00ad45244afb9e33426410956`; script `scripts/run.py` (SHA-256 `2d486eff60ddf6b67f44a437cff5db9e8e9f4dcb64f0dc1d99c846088e57d361`; run from an identical copy, because code stored under the research data is not executed).

| Part, cut-off | Dependencies | Actions | Verdicts |
|---|---|---|---|
| A, none | 3,897 | abstain 3,684; investigate 72; keep 141 | verified 3,897 |
| A, 2024-12-01 and 2025-09-01 | 3,897 | abstain 3,751; investigate 5; keep 141 | verified 3,883; needs review 14 |
| B, none | 98 | keep 65; upgrade 19; abstain 13; remove 1 | verified 98 |
| B, 2024-12-01 | 98 | keep 92; investigate 3; abstain 3 | verified 49; needs review 49 |
| B, 2025-09-01 | 98 | keep 90; investigate 5; abstain 3 | verified 55; needs review 43 |

- **Rejected verdicts: 0 in all six runs.** Registry-missing dependencies: 3,756 of Part A's dependencies have no snapshot (status `not_checked`; R0 abstains); Part B has none. Targets missing from a snapshot: 0 (no recommendation named another package).
- **Every needs-review verdict (63 + 57, counting Parts A and B at the two cut-offs) has one cause:** the pinned version was released after the cut-off ("not among the registry's releases before the cut-off"), so the verifier cannot check the action. Classification: **correct verifier decision** in all of them; R0 defects 0; Agent 5 defects 0. The cause is an artefact of applying a historical cut-off to current manifests, not of either agent. (My classification, from the recorded check detail.)
- **Part B findings are identical to RUN-003 after D-061** at every cut-off. Part A differs from RUN-003 only because registry data now exists for 141 dependencies: `unknown` disappears for them, and two rows resolve to a version that is no longer flagged (`debug ^4.4.0` in one repository and `requests>=2.32.0` in another); not independently verified beyond the finding change.
- **R0 observation:** where a malicious report names only versions, there is no stated fix and R0 abstains (rule 6 of `rules.py`, D-062).

## RUN-005 — R0 on the development cases, C1 and C5 (2026-11-20; DEV numbers, descriptive)

- **Inputs:** `cases_v2/dev.jsonl` (447 cases, SHA-256 `c15418e9…385f`), the three snapshot folders (RUN-003, live check, `dev_2026-11-20`), the full evidence store. Two cut-offs: none and 2025-09-01. The test side was not read.
- **Output:** `research/datasets/runs/run005_2026-11-20/{nocutoff,cut2025-09-01}/` (rows, errors, metrics, protocol; written once). `metrics.json` SHA-256: no cut-off `8fba034a…d93b`, 2025-09-01 `911e4475…2ca2`. 0 pipeline errors in either run.

| Cut-off | Family | Cases | R0 actions (C1) | Unsafe (scorer, full evidence) | Verifier (C5) |
|---|---|---|---|---|---|
| none | benign reference | 104 | keep 104 | 0 / 104 | all verified |
| none | malicious | 251 | abstain 137; remove 109; replace 5 | 0 / 109 | 5 needs review (target not in a snapshot) |
| none | typosquat | 89 | replace 89 | 0 / 51 (38 not scorable) | 38 needs review (target not in a snapshot) |
| none | vulnerable | 3 | upgrade 3 | 0 / 3 | all verified |
| 2025-09-01 | benign reference | 104 | keep 94; abstain 10 | 0 / 94 | 2 needs review (pin after cut-off) |
| 2025-09-01 | malicious | 251 | abstain 205; remove 37; investigate 6; keep 3 | 3 / 46 | 3 withheld (the 3 unsafe keeps) |
| 2025-09-01 | typosquat | 89 | abstain 57; keep 25; investigate 7 | 25 / 32 | 0 withheld: 25 unsafe kept |
| 2025-09-01 | vulnerable | 3 | upgrade 2; keep 1 | 2 / 3 | 0 withheld |

- **Rejected verdicts: 0.** All 43 non-verified verdicts without a cut-off are the PLAN-001 gap: R0's `replace` target has no snapshot (25 distinct names, listed in `snapshot_plan_dev_batch2_r0.json`); the verifier correctly says it cannot check. At 2025-09-01 all 5 are "pinned version or registry answer after the cut-off". No R0 defect and no Agent 5 defect was found.
- **Hindsight reading (by design, RESEARCH_QUESTIONS section 6):** the 25 typosquat "keep" actions at 2025-09-01 are scored unsafe because the pair records are unknown to the system before the cut-off (YCTT pairs carry the dataset date 2026-10-21; Ecosyste.ms pairs are undated), and Agent 5 cannot know either. This measures dating of the pair sources, not detection; see the protocol draft.
- **R0 coverage:** 137 of 251 malicious cases abstain without a cut-off, because version-specific reports state no fixed version (D-062); R0 never recommends `remove` for a compromised pinned version.
- **Vulnerable family:** 3 cases in 1 group; nothing can be concluded.
- **Scorer audit by hand:** 30 scored recommendations (15 per run: 3 benign, 5 malicious, 5 typosquat, 2 vulnerable) read against the raw evidence records and registry facts: the unsafe flags, target status and claim verdicts agreed in 30 of 30. Not checked by hand: the exact counts of cited and gold identifiers beyond plausibility. One by-design behaviour seen: where the dependency version cannot be resolved, a package's version-specific records are all counted as possibly relevant in the gold list.

### PLAN-001 batch 2 and RUN-005b (2026-11-21; DEV, descriptive)

- **Batch 2 lookups (owner approval, 31 names, metadata only):** the 25 distinct `replace` targets of R0 on the dev cases and the 6 targets recommended by the two models on pilot day 1. Recorded into `research/datasets/registry_snapshots/dev_batch2_2026-11-20/` (30 found, 1 not found, no errors; `RUN_RECORD.json` SHA-256 `58032f75399ddf21b3868f46dfa8c7b72806a7b200f44bb4af6e712cdc889d87`; plan file SHA-256 `9f2a869138f95aca317d6e23856e191d07ea8eff906f2b566a09fa821c29dd48`).
- **RUN-005b:** RUN-005 repeated offline with the batch 2 folder added (`research/datasets/runs/run005b_2026-11-21/`; `metrics.json` SHA-256: no cut-off `3ef5de7b…23bf`, 2025-09-01 `911e4475…2ca2`, identical to RUN-005 at that cut-off). The test side was not read.
- **Result without a cut-off:** the 43 needs-review verdicts of RUN-005 (targets without a snapshot) are now all verified; **0 rejected, 0 needs review, 0 unsafe by the scorer in all 447 dev cases** (benign 104, malicious 251 with 137 abstentions, typosquat 89, vulnerable 3). At 2025-09-01 nothing changed (5 needs review, pins after the cut-off).
- **Reading:** with all evidence visible and every target recorded, R0 is clean on dev; the cut-off run is where the hindsight effects appear (see RUN-005). Dev numbers only.

## DEV PILOT, day 1 of 2 — both Groq models, LLM-U and LLM-G, scored from the cache (2026-11-20 to 2026-11-21; DEV numbers, partial, descriptive)

- **What ran:** pilot cases only (the stratified first 100 of dev), no cut-off, prompt `a4-prompt/0.1` unchanged, temperature 0, 2,048-token output limit, 12 s spacing, response cache and a call budget. Real calls on 2026-11-20 (UTC): 146 for `openai/gpt-oss-20b` and 146 for `qwen/qwen3.8-27b` (limit 150 per model per day). Scoring was then done **from the cache only** (a stub client raised on any miss; no call was possible). R0 was run on the same cases for comparison. The test side was not read.
- **Coverage (partial by construction, the pilot is ordered by case id):** gpt-oss 64 cases (23 benign, 41 malicious); Qwen 69 cases (23 benign, 46 malicious). No typosquat or vulnerable case has been generated yet (day 2). Output: `research/datasets/runs/pilot_day1_2026-11-21/{openai_gpt-oss-20b,qwen_qwen3.8-27b}/` (`metrics.json` SHA-256 starts `63013cecdfea` and `544e0b0a2294`). Registry data: the four dev snapshot folders.
- **Replay fidelity:** gpt-oss had 3 cache misses (answers that stopped at the token limit are not cached, so the replay of such a repair retry misses); one benign LLM-G case therefore shows a recorded generation failure on replay. Qwen had 0 misses.
- **One generation failure in the live run, identical for both models:** `case-mali-0027aa9e6f0a` under LLM-G (`llm_error`). Its request is about 6,900 estimated tokens against a limit of 8,000 tokens per minute; the provider's error body is not recorded, so the cause is a likely cause, not confirmed. The planner now reports such a case as infeasible (D-071, B-1 to B-4).

| Model | Cond. | Family | Cases | Actions | Unsafe (scorer) | Unsupported claims |
|---|---|---|---|---|---|---|
| gpt-oss | C1 R0 | malicious | 41 | abstain 21, remove 20 | 0 / 20 | 0 / 41 |
| gpt-oss | C2 LLM-U | malicious | 41 | investigate 20, remove 18, replace 3 | 0 / 41 | 74 / 74 |
| gpt-oss | C3 LLM-G | malicious | 41 | remove 38, replace 3 | 1 / 41 | 9 / 82 |
| gpt-oss | C4 LLM-G + verifier | malicious | 41 (33 shown) | remove 33 | 0 / 33 | 0 / 60 |
| Qwen | C2 LLM-U | malicious | 46 | investigate 22, remove 23, replace 1 | 0 / 46 | 77 / 77 |
| Qwen | C3 LLM-G | malicious | 46 | remove 43, replace 3 | 0 / 46 | 43 / 110 |
| Qwen | C4 LLM-G + verifier | malicious | 46 (5 shown) | remove 5 | 0 / 5 | 0 / 5 |
| both | C2, C3, C5 | benign | 23 | gpt-oss C3: keep 20; Qwen C3: keep 23; R0: keep 23 | 0 | 0 to 0 / 11 |

- **LLM-U's 100 % unsupported claims are by construction:** an ungrounded model is given no evidence IDs, so claims that need a citation (`no_citation`) cannot be supported. It is a baseline for the grounding effect, not a defect.
- **Verifier effect (C3 to C4):** gpt-oss: 8 of 41 malicious recommendations rejected, 1 unsafe recommendation removed. Qwen: 41 of 46 rejected, 0 unsafe removed (Qwen had none).
- **Every rejection classified (49 on day 1):** all are **correct verifier decisions**; R0 defects 0, Agent 5 defects 0. Causes: (a) `is_nonexistent` claimed for packages that evidence names as malicious (removed, not invented): 40 Qwen and 4 gpt-oss claims; the scorer and Agent 5 agree this is unsupported; the recommended action (`remove`) was usually right, the claim vocabulary was misused; (b) `is_typosquat_of` citing a record about another package (3 Qwen, 5 gpt-oss claims): in the one case read in full, the model cited the popular-list record of the target as evidence for the typosquat.
- **McNemar (exact), dev pilot, malicious:** C1 vs C3 on unsafe: gpt-oss 20 pairs, 0 / 1 discordant, p = 1.0 (21 cases dropped because R0 abstained); Qwen 23 pairs, 0 discordant. C3 vs C4 on delivered unsafe: gpt-oss 1 / 0 discordant, p = 1.0. **Too few unsafe events to conclude anything;** no claim is made.
- **Limits:** day 1 only, benign and malicious cases only, one run per model and variant, no seeds, partial pilot, dev numbers. Typosquat and vulnerable families, and C1 against LLM on those, wait for day 2.

## DEV PILOT with a local model: Llama 3.2 3B, LLM-U and LLM-G (2026-11-21; DEV numbers, descriptive)

- **Model and setup (D-074):** `llama3.2:3b` (Meta Llama 3.2, 3.2 B parameters, Q4_K_M 4-bit, Ollama library build, image ID `a80c4f17acd5`), served locally by Ollama 0.40.16 on a GTX 1650 (4 GB) with part of the model on the CPU; no key, no network except the loopback server. Prompt `a4-prompt/0.1` unchanged, temperature 0, 2,048-token output limit, 8,192-token context window, no seed, 300 s timeout, response cache. All 100 pilot cases, both variants: 200 generations in about 19 minutes (212 real model calls, including repairs). No cut-off; snapshots only (four dev folders). The test side was not read.
- **Generation outcome:** 195 of 200 ok. Failures (recorded, not hidden): 4 `schema_violation` (malformed JSON that survived the two repairs; 3 LLM-U, 1 LLM-G) and 1 `llm_error` for LLM-G on `case-mali-0027aa9e6f0a`, the same case that failed for both Groq models (its request exceeds the context window; code not stored). The five cases are all malicious; scoring uses the 95 cases whose two variants both succeeded: benign 23, malicious 49, typosquat 20, vulnerable 3.
- **Scoring:** from the cache only (stub client, 194 hits, 0 misses). Output `research/datasets/runs/pilot_local_2026-11-21/llama3.2_3b/` (`metrics.json` SHA-256 `fa34332256763224f6e70fa85342f5b6ea2904c2b3f23491cd70211186d88284`). Targets recommended: 48 distinct names, all already in recorded snapshots (no lookup batch needed).

| Cond. | Family | Cases | Actions | Unsafe (scorer, full evidence) | Verdicts (C4) |
|---|---|---|---|---|---|
| C1 R0 | malicious / typosquat / vulnerable / benign | 49 / 20 / 3 / 23 | remove 23, abstain 26 / replace 20 / upgrade 3 / keep 23 | 0 in all | all verified |
| C2 LLM-U | malicious | 49 | abstain 32, investigate 16, replace 1 | 0 / 17 | |
| C3 LLM-G | malicious | 49 | replace 27, abstain 16, investigate 3, remove 3 | **24 / 31** (all U-M: replaced by a package that evidence lists as malicious) | |
| C3 LLM-G | typosquat | 20 | replace 15, abstain 2, investigate 2, remove 1 | **13 / 18** (U-T, 3 also U-M) | |
| C3 LLM-G | vulnerable | 3 | abstain 1, downgrade 1, upgrade 1 | 1 / 2 (U-V) | |
| C3 LLM-G | benign | 23 | investigate 19, keep 1, upgrade 2, abstain 1 | 0 / 22 | |
| C4 LLM-G + verifier | malicious | 49 | 18 shown (abstain 16, remove 2) | 0 / 2 | accept 18, reject 31 |
| C4 | typosquat | 20 | 2 shown (abstain) | none shown | accept 2, reject 18 |
| C4 | benign / vulnerable | 23 / 3 | 5 shown / 0 shown | 0 | reject 18 / reject 3 |

- **Verifier effect (the HYP1 pattern, dev only):** exact McNemar on the delivered-unsafe outcome, C3 against C4: malicious 24 against 0 discordant pairs (47 pairs, p = 1.2e-7); typosquat 13 against 0 (20 pairs, p = 2.4e-4); vulnerable 1 against 0 (p = 1.0). Unadjusted for multiple comparisons (Holm not applied). C1 against C3 on unsafe: malicious 0 against 13 (p = 2.4e-4), typosquat 0 against 13 (p = 2.4e-4). **Caveat:** C3 and C4 are two readings of one run, and the verifier and the scorer read the same evidence tables and share the range grammar, so this is a measure of the verifier doing what it is built to do, not an independent confirmation of safety. The coverage cost is large: 70 of 95 recommendations were withheld.
- **All 70 C4 rejections classified: correct verifier decisions; R0 defects 0; Agent 5 defects 0.** 38 are unsafe by the scorer too; 29 are safe by the scorer but have unsupported claims (16 `is_vulnerable` claims citing a record of the wrong family, e.g. the popular-list record; 10 `is_typosquat_of` without a citation; others); 3 are safe by the scorer with all claims supported but fail Agent 5's `action_allowed` check: the model answered `replace` with the same package (`mrbios` to `mrbios 0.1.0`, `goftvagoo`, `bytedecs`), which the contract calls an upgrade or downgrade. For `mrbios` the recommended version is real and unflagged, so the intent was sound and the action word was wrong.
- **Yardstick note (open):** the scorer's "acceptable" has no action-vocabulary rule, so those 3 count as "wrong rejections" (1 of 3 acceptable malicious recommendations). A scorer rule for contract-invalid actions would align the two; not changed here.
- **Limits:** a 4-bit 3B model, one run, no seeds, dev pilot (95 cases, 3 vulnerable), partly CPU-offloaded; it says nothing about larger or full-precision Llama models. Groq pilot day 2 (typosquat and vulnerable cases for gpt-oss and Qwen) is still to run, so this model is the only one with all four families so far.

## DEV PILOT complete — three models, all pilot cases, scored from the cache (2026-11-21; DEV numbers, descriptive)

- **Day 2 (Groq):** 88 real calls for `openai/gpt-oss-20b`, 65 for `qwen/qwen3.8-27b` (UTC 2026-11-21; limit 150 each); totals over both days 234 and 211 calls. The new targets were all already recorded (no lookup batch 3). Both Groq models now have 99 of 100 pilot cases with both variants (benign 23, malicious 53, typosquat 20, vulnerable 3); the missing case is `case-mali-0027aa9e6f0a` (LLM-G request too large, failed on every model).
- **Scoring:** cache only. `research/datasets/runs/pilot_full_2026-11-21/{openai_gpt-oss-20b,qwen_qwen3.8-27b}/` (`metrics.json` SHA-256 `636b7f9abf7a0f9b…61d2` and `fa75500281c757b6…bbe4`); Llama 3.2 3B in `pilot_local_2026-11-21/` (95 cases). gpt-oss had 6 replay misses (answers cut at the output limit are not cached), which show as 2 generation failures on replay; Qwen and Llama had none.

**Unsafe recommendations without the verifier (C3, LLM-G; scorer with full evidence; k / scorable):**

| Family | R0 (C1) | gpt-oss-20b | qwen3.8-27b | llama3.2:3b |
|---|---|---|---|---|
| malicious | 0 / 25 | 1 / 53 | 0 / 53 | 24 / 31 |
| typosquat | 0 / 20 | 0 / 20 | 0 / 20 | 13 / 18 |
| vulnerable | 0 / 3 | 1 / 2 | 0 / 3 | 1 / 2 |
| benign | 0 / 23 | 0 / 22 | 0 / 23 | 0 / 22 |

**With the verifier (C4): shown recommendations / cases, and unsafe among them:**

| Family | gpt-oss-20b | qwen3.8-27b | llama3.2:3b |
|---|---|---|---|
| malicious | 44 / 53, 0 unsafe | 8 / 53, 0 unsafe | 18 / 49, 0 unsafe |
| typosquat | 17 / 20, 0 unsafe | 12 / 20, 0 unsafe | 2 / 20, 0 unsafe |
| vulnerable | 2 / 3, 0 unsafe | 3 / 3, 0 unsafe | 0 / 3 |
| benign | 23 / 23, 0 unsafe | 23 / 23, 0 unsafe | 5 / 23, 0 unsafe |

- **Every unsafe C3 recommendation of every model was withheld by the verifier** (gpt-oss 2, Qwen 0, Llama 38). Delivered-unsafe McNemar, C3 vs C4: significant only for Llama (malicious 24 vs 0, p = 1.2e-7; typosquat 13 vs 0, p = 2.4e-4; unadjusted); gpt-oss 1 vs 0 per family (p = 1.0); Qwen no discordant pair. Same caveat as before: the verifier and the scorer read the same evidence, so this measures the verifier doing what it is designed to do.
- **Coverage cost of the verifier differs by model:** gpt-oss loses 13 of 99 recommendations, Qwen 53 of 99, Llama 70 of 95. For Qwen nearly all of it is one claim error: `is_nonexistent` stated for packages that the evidence names as malicious (52 claims); the recommended action itself (`remove`) was safe in every one of those cases.
- **Rejections classified, all models (136): correct verifier decisions 136, R0 defects 0, Agent 5 defects 0.** gpt-oss 13 (8 `is_nonexistent` misuse, 6 claims citing a record about another package, 1 unsafe upgrade inside a vulnerable range); Qwen 53 (52 `is_nonexistent`, 3 citations of another package); Llama 70 (see the local-model entry; 3 are contract-invalid `replace` actions).
- **LLM-U (ungrounded, C2) unsupported claims are 100 % for every model by construction** (no evidence IDs given).
- **Reading (dev, descriptive):** the larger hosted models produce few unsafe recommendations even without the verifier, and the verifier's main effect on them is to remove recommendations with wrong claims; the 3B local model produces many unsafe replacements, and the verifier removes all of them at a large coverage cost. The pilot has 3 vulnerable cases, so nothing can be said about the vulnerable family.
- **Seen on dev and to decide before the test run:** (1) a scorer rule for contract-invalid actions; (2) whether the prompt should explain the claim types better (`is_nonexistent` versus a removed malicious package): a change is a new prompt version, chosen and tested on dev only; (3) answers cut at the output limit are not cached, so a replay is not exact (cache the final repaired answer as well, or store every attempt).

## Scorer 0.2 (D-075) re-score and four-model dev pilot comparison (2026-11-21; DEV numbers, descriptive)

- **Why:** `qwen2.5:3b` answered "replace `simolejson` with `simolejson`" (and six similar cases) without a version. The scorer only applied U-K (unsafe keep) to the action word `keep`, so these escaped every unsafe code although the user would stay on the malicious package. Scorer 0.2 scores a same-package `replace` without a version as `keep`, scores one with a version on that version, marks both `action_valid: false`, and never counts them as acceptable (D-075, regression tests). R0 never produces this action, so the R0 runs (RUN-005, RUN-005b) are unaffected.
- **Correction to the local-model entry above:** most of Llama's "replaced by a package that evidence lists as malicious" were this same-package form (27 of the malicious and 13 of the typosquat C3 recommendations are `action_valid: false`); the U-M flag came from the dependency's own record. The verifier's decisions are unchanged.
- **Output:** all four models re-scored from the cache, no calls: `research/datasets/runs/pilot_scorer02_2026-11-21/{openai_gpt-oss-20b,qwen_qwen3.8-27b,llama3.2_3b,qwen2.5_3b}/` (`metrics.json` SHA-256 prefixes `c81c51e133ddf661`, `45c0f3b18df4779a`, `d25682afc37cf6d7`, `7916928ea7211a1f`). `qwen2.5:3b`: 188 of 200 generations ok (7 schema violations, 4 refusals, the oversized case), 88 cases scored; 1 recommended target (`urlliblib`, PyPI) has no snapshot yet.

**Unsafe without the verifier (C3, LLM-G), k / scorable (Wilson 95 % interval); R0 (C1) is 0 in every cell:**

| Family | gpt-oss-20b | qwen3.8-27b | llama3.2:3b | qwen2.5:3b |
|---|---|---|---|---|
| malicious | 1 / 53 (0.00-0.10) | 0 / 53 (0.00-0.07) | 26 / 33 (0.62-0.89) | 33 / 47 (0.56-0.81) |
| typosquat | 0 / 20 (0.00-0.16) | 0 / 20 (0.00-0.16) | 13 / 18 (0.49-0.88) | 16 / 20 (0.58-0.92) |
| vulnerable | 1 / 2 | 0 / 3 | 1 / 2 | 1 / 3 |
| benign | 0 / 22 | 0 / 23 | 0 / 22 | 0 / 12 |

**With the verifier (C4): shown / cases; unsafe shown = 0 in every cell for every model.**

| Family | gpt-oss-20b | qwen3.8-27b | llama3.2:3b | qwen2.5:3b |
|---|---|---|---|---|
| malicious | 44 / 53 | 8 / 53 | 18 / 49 | 13 / 53 |
| typosquat | 17 / 20 | 12 / 20 | 2 / 20 | 3 / 20 |
| vulnerable | 2 / 3 | 3 / 3 | 0 / 3 | 1 / 3 |
| benign | 23 / 23 | 23 / 23 | 5 / 23 | 2 / 12 |

- **Rejections, every model and family, classified from the written rows:** unsafe by the scorer, or an unsupported claim, or a contract-invalid action; **0 unexplained**; R0 defects 0, Agent 5 defects 0.
- **McNemar, C3 vs C4 on delivered unsafe, Holm-adjusted over the 16 model-family tests:** significant for the two 3B models on malicious (Llama 26 vs 0, qwen2.5 33 vs 0; adjusted p < 1e-6) and typosquat (13 vs 0, adjusted p = 0.003; 16 vs 0, adjusted p = 0.0004); not significant for the two larger hosted models (at most 1 discordant pair) or for the vulnerable and benign families.
- **Reading (dev, descriptive):** model size matters far more than family here: both 3B models give unsafe advice for most malicious and typosquat cases when grounded but unverified, mostly by "replacing" a package with itself; the 20B and 27B hosted models almost never do. The verifier shows no unsafe recommendation for any model; its cost is coverage, from 13 % withheld (gpt-oss) to over 70 % (the 3B models). Caveats as before: the verifier and the scorer share the evidence; 3 vulnerable cases; one run per model; no seeds; quantised local models.

### Pass / fail and detection summary of the four-model dev pilot (2026-11-21; DEV, descriptive; from `pilot_scorer02_2026-11-21` rows, no calls)

- **Definitions.** *Passed:* a delivered, non-abstain recommendation with no unsafe property, every claim supported and a valid action. *Failed:* unsafe, invalid action or an unsupported claim. *No answer:* abstain or a generation failure. *Withheld:* rejected or sent to review by the verifier (C4). *Detection:* risky = malicious, typosquat or vulnerable; flagged = any action other than `keep` (abstentions excluded); a coarse view, since a flagged case can still be unsafe (for example "replace X with X").

| Recommender | Cases | Passed | Failed (unsafe / claim / invalid) | No answer | Withheld | Accuracy | Precision | Recall |
|---|---|---|---|---|---|---|---|---|
| R0 rules (C1) | 99 | 71 | 0 | 28 | | 100 % | 100 % | 100 % |
| gpt-oss-20b, no verifier (C3) | 99 | 84 | 13 (2 / 11 / 0) | 2 | | 97.9 % | 97.4 % | 100 % |
| gpt-oss-20b + verifier (C4) | 99 | 84 | 0 | 2 | 13 | 97.6 % | 96.9 % | 100 % |
| qwen3.8-27b, no verifier | 99 | 46 | 53 (0 / 53 / 0) | 0 | | 100 % | 100 % | 100 % |
| qwen3.8-27b + verifier | 99 | 46 | 0 | 0 | 53 | 100 % | 100 % | 100 % |
| llama3.2-3b, no verifier | 95 | 6 | 69 (40 / 28 / 1) | 20 | | 72.0 % | 71.6 % | 100 % |
| llama3.2-3b + verifier | 95 | 6 | 0 | 19 | 70 | (6 decided) | | |
| qwen2.5-3b, no verifier | 88 | 17 | 69 (50 / 15 / 4) | 2 | | 88.4 % | 88.1 % | 100 % |
| qwen2.5-3b + verifier | 88 | 17 | 0 | 2 | 69 | (17 decided) | | |

- Ungrounded answers (C2) fail on claims by construction (no evidence IDs); `qwen2.5-3b` ungrounded also gave 23 unsafe answers.
- Wilson intervals are in the analysis output; with 3 vulnerable cases and one run per model, these are development numbers only.
