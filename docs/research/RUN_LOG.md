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

## Agent 3 behaviour (state after D-057, for the paper)

- **What this state rests on:**
  - RUN-002 (18 dependencies) and RUN-003 (3,897 real-repository dependencies plus 98 generated declarations, at three cut-offs);
  - two independent scoring reviews (D-056, D-057);
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
