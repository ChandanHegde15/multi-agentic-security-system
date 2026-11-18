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
