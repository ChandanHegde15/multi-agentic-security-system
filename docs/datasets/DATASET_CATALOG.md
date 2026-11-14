# Dataset catalog

All research data lives in `research/datasets/` inside the repository folder and is **git-ignored**: it is never committed or published (D-017). It was moved there from `D:\RESEARCH_DATA` on 2026-11-13 by a verified, byte-identical rename (`DATASET_MIGRATION_PLAN.md`). Facts below were verified on 2026-11-13 against the actual files.
Full reports (local only):
- `research/datasets/inspected/DATASET_INSPECTION_REPORT.md`
- `research/datasets/inspected/PHASE3_DATA_FOUNDATION_REPORT.md`

These historical reports cite the old `D:\RESEARCH_DATA\...` paths; `research/datasets/provenance/MIGRATION_RECORD.md` maps them to the new ones.

## 1. Storage layout

| Path | Contents | Rules |
|---|---|---|
| `incoming\dataset_submission.zip` | Original submission, 478,991,113 bytes, SHA-256 `33e409abbfb17ab8840a0cadb73ee44ce963b5d80bf1ccd8f35fc073572f0d00` | Immutable |
| `incoming\extras_only.zip` | Supplementary acquisitions (2026-11-14), SHA-256 `fa362e7a8a4a16487468b4ab7c97d5396d78e55414332b9137981148f007392e` | Immutable |
| `extracted\extras_v1\` | Text-only extraction of `extras_only.zip` (146 files), same record files as `v1` | Read-only |
| `extracted\v1\` | Text-only allowlisted extraction. `EXTRACTION_MANIFEST.csv` lists every file with its SHA-256; `EXTRACTION_SKIPPED.csv` lists what was not written. | Read-only |
| `review\code\` | 43 submission scripts and notebooks saved as `.txt` | Read only, never run |
| `inspected\` | Inspection reports, `archive_inventory.csv` | Historical |
| `verified\` | Normalized evidence tables built from raw sources (§2.2) | — |
| `provenance\` | Migration record, pre/post hash trees, quarantine record, old README | — |
| `D:\RESEARCH_DATA\legacy_archive\agentic-security-system_v1\` (outside the repository folder) | Legacy datasets and model (temporary, D-003) | Not for the new pipeline |

Paths in the first column are relative to `research/datasets/` unless absolute.

**Not extracted:**
- 1,624 npm `.tgz` packages from You Can't Touch This: **394 malicious** and 1,230 benign but untrusted.
- `.pyc` and `.DS_Store` files.
- A truncated duplicate zip.

**Quarantined by Defender after extraction (7 files):**
- OpenSSF `pypi/fastapi-requests/MAL-2026-1261.json`, `pypi/fastapis-requests/MAL-2026-1262.json`, `pypi/durabletask/MAL-2026-4174.json`
- OSV `MAL-2026-1261`, `MAL-2026-1262`, `MAL-2026-4174`, `GHSA-wx9m-wx4f-4cmg` (`.json`)

The originals are intact in the zip; read them in memory (D-009). The other 39,693 extracted files match their recorded SHA-256 (re-verified before and after the migration). Full table: `research/datasets/provenance/QUARANTINE_RECORD.md`.

## 2. Sources

Paths are under `extracted\v1\data\sources\`.

| Source | Location | Version / provenance | Contents (verified) | Completeness | License (evidence) |
|---|---|---|---|---|---|
| LibHalluBench | `libhallubench/raw/` | HF export 2026-11-12; **revision not recorded** | 4,173 tasks: 321 control, 1,926 describe, 1,926 specify; fields id, split, type, prompt, seed_id, mistake | Complete (count matches) | **CC-BY-4.0, no training or fine-tuning use, gated**: read on the Hugging Face dataset card on 2026-11-13 (Session 01) through an automated page read. No card or LICENSE is archived locally. Evaluation-only (D-013). |
| Package Hallucination | `package_hallucination/raw/package-hallucination-data/`, `record_metadata.json` | Zenodo 23962898 v1.0 (2026-11-04), MD5 verified | generations.jsonl, responses, packages, popularity, manual_review CSVs, tasks_v2.json | Complete | **CC-BY-4.0** (Zenodo metadata) |
| Ecosyste.ms Typosquatting | `ecosyste_ms_typosquatting/raw/typosquats.csv` | git commit `ccda8797` | 167 variant→target **name pairs**: pypi 95, npm 37, rubygems 15, go 10, github_actions 8, crates.io 2. The upstream README states that inclusion does not establish that a package is malicious (research demos, synthetic cases and a legitimate fork are included). | Complete at that commit | **CC0 1.0** (LICENSE) |
| You Can't Touch This | `you_cant_touch_this/raw/you_cant_touch_this_v1.1.0.verified/` (text only) | Zenodo 23520699 v1.1.0, MD5 verified | 406 npm typosquat mappings; feature CSVs for 394 own malware, benign packages, Backstabber's and MalOSS sets. **Package tarballs only in the original zip.** | Complete; upstream ships no package source for Backstabber's or MalOSS | **MIT** (c) 2024 Minh Truong; Backstabber's and MalOSS terms unverified |
| OpenSSF Malicious Packages | `openssf_malicious_packages/raw/` | git commit `b6d4ae95`, sparse clone | 11,995 PyPI malicious reports + 362 withdrawn (OSV JSON) | **Partial**: no npm, RubyGems or NuGet | **Apache-2.0** (LICENSE) |
| DataDog malicious packages | `datadog_malicious_packages/raw/` | git commit `72c723be` | Manifests only: 50,742 names (npm 48,600, pypi 1,835, ai-skills 204, ide 103); 2,093 version-scoped | **Partial**: no samples | **Apache-2.0** + NOTICE; samples may carry their own licenses |
| OSV.dev | `osv/raw/osv_PyPI/` | `PyPI/all.zip`, Last-Modified 2026-11-12 06:48 GMT, SHA-256 verified | 26,863 records: MAL 12,020, PYSEC 7,986, GHSA 6,845, OSV 12 | **Partial**: PyPI export only | **Unverified** (per upstream source) |
| PyPI MalRegistry | `pypi_malregistry/tree_listing.txt` | git commit `b85fe774` | Path listing: 12,600 version paths, 10,790 names | **Listing only**: no package archives | **None stated**; do not redistribute |
| deps.dev | — | — | — | **Absent** | — |
| Real-world manifests | `real_manifests/files/` | 12 GitHub repos; commit per case in `benchmarks/agent1/real_manifest_cases.jsonl` | 326 indexed manifests (109 project, 217 fixture): package.json 146, pyproject.toml 116, yarn.lock 46, package-lock.json 8, requirements.txt 5, Pipfile 4, pnpm-lock.yaml 1 | Complete for those repos | **Unverified** (per repository) |

### 2.1 Supplementary acquisitions (2026-11-14, D-045)

Paths are under `extracted\extras_v1\data\`. Each raw response keeps its retrieval time; per-source notes are in `manifests\extras_sources.json`.

| Source | Location | Contents (verified 2026-11-14) | Limits | License (evidence) |
|---|---|---|---|---|
| PyPI popular list | `sources\pypi_popular\raw\`, `normalized\package_identities\pypi_popular_top.jsonl` | 15,000 names by 30-day downloads, list dated 2026-11-01 | Popularity says nothing about safety | **Unverified** (hugovk/top-pypi-packages; PSF BigQuery data) |
| PyPI version lists | `sources\pypi_versions\raw\`, `normalized\registry_metadata\pypi_versions.jsonl` | 125 names queried (top-100 popular + Ecosyste.ms PyPI targets): 123 found, 2 not found; versions, first upload time, yanked flag | Registry state at retrieval; vulnerable-family targets not covered | PyPI public metadata, none stated |
| Requirements pins (development) | `sources\real_manifests\requirements_pins\` + `index.jsonl` | 13 files, 1,436 pinned lines from 5 repositories | Hand-picked: development and pilot only, never the test set | **Unverified** (per repository) |
| LibHalluBench card | `sources\libhallubench\card\` | Card text and revision `6882a8a46fecdcef42dccdbb72aa65de0dd94b12` | — | Card states CC-BY-4.0, no training use |


### 2.2 Normalized evidence tables (built 2026-11-14)

Built by code in `src/multi_agentic_security/datasets/`, written under `verified/normalized/v1/<family>/<table>/` (git-ignored), each with `MANIFEST.json` (counts, source version, licence, SHA-256 of outputs), `skips.csv` (every unmapped input and why) and `notes.csv`. Schema `evidence/1.1` (adds the typosquat target; identifiers unchanged). Mapping rules: D-046 (OSV) and D-048 (all others). Not yet approved for evaluation or training use (D-024 item 7). Cross-table evaluation: `DATASET_EVALUATION.md`.

| Table | Adapter | Records | Distinct packages | Dated | Notes (verified from the manifests) |
|---|---|---:|---:|---|---|
| `vulnerable/osv_pypi_a2` | `osv_pypi/2` | 23,632 | 1,696 (PyPI) | 100% | 14,212 advisories; skipped 12,017 `MAL-`, 607 withdrawn advisories, 483 non-PyPI entries, 1,535 `GIT` ranges, 23 uninterpretable ranges (13 recovered from listed versions), 23 without version data |
| `malicious_withdrawn/openssf_a2` | `openssf/2` | 18,348 (malicious 17,498; withdrawn 850) | 12,354 | 99.95% (2022-05-31 to 2026-11-11) | All 12,354 reports mapped (11,992 malicious PyPI, 362 withdrawn PyPI and npm) |
| `malicious/datadog_manifests` | `datadog/1` | 53,632 (npm 51,784; PyPI 1,848) | 50,434 | none | 48,343 whole-package, 5,289 listed versions; ai-skills and IDE manifests skipped; `Roblox.-com` and `roblox-com` are one PyPI name |
| `malicious/malregistry_listing` | `malregistry/1` | 12,600 | 10,790 (PyPI) | none | Listed versions only; 38 non-package lines skipped; no licence stated |
| `typosquat/ecosystems_typosquats` | `ecosystems/1` | 130 (PyPI 93, npm 37) | 130 | none | 35 other-ecosystem rows and 2 rows whose variant equals its target skipped |
| `typosquat/yctt_pairs` | `yctt/1` | 406 (npm) | 406 | 100% (release date) | Dated by the dataset release, not the package upload time |
| `benign_reference/pypi_popular` | `popular/1` | 15,000 | 15,000 | 100% (list date) | Candidates only |
| `benign_reference/yctt_targets` | `yctt/1` | 232 (npm) | 232 | none | Candidates only |

Superseded folders kept until the owner removes them: `vulnerable/osv_pypi` (adapter 1, no listed-version fallback) and `malicious_withdrawn/openssf` (adapter 1, skipped 113 withdrawn npm reports with `SEMVER` ranges).

Open checks (unverified): PROBLEM_DEFINITION.md section 1 counts 1,697 names with a non-withdrawn advisory and 606 withdrawn GHSA+PYSEC records; the OSV table has 1,696 and 607 (likely causes: the quarantined GHSA record; a withdrawn `OSV-` record). GHSA/PYSEC aliases still double-count the same vulnerability until alias groups are built.

## 3. Submitter-derived material (review status, not ground truth)

- `extracted\v1\data\normalized\`: 12 JSONL/CSV files with a shared record schema.
  - Not human-reviewed, except 65 Package Hallucination rows.
- `extracted\v1\data\benchmarks\`: draft Agent 1/2/3 sets.
  - Built on *current* registry lookups.
  - Not approved.
- Per D-011 these are cross-checks only; normalized data will be rebuilt from raw.

## 4. Approval status

All sources: `approved_for_evaluation = false` and `approved_for_training = false`. They change only by an owner decision recorded in `DECISIONS.md`.

## 5. Known data-quality issues

1. The normalized YCTT malicious file has 2,394 rows, but the authors' own malware set is 394. Needs re-derivation from raw.
2. `dataset_manifest.json` status fields disagree with the actual files. `docs/DATASET_REGISTER.md` (2026-11-11) is outdated; `docs/LOCAL_REGISTER.md` is newer.
3. Sources overlap:
   - 9,480 of 10,790 MalRegistry names are in OpenSSF.
   - OSV MAL republishes OpenSSF.
   - 1,372 OpenSSF names are in DataDog.
4. Label conflicts:
   - `axios`, `pytorch` and `detectron2` are both typosquat targets and on malicious lists.
   - `pillow-simd` (a legitimate fork) is listed as a typosquat.
5. 36 of 37 npm typosquats still return HTTP 200 (mostly `0.0.1-security` placeholders). Current lookups do not reflect historical status.
6. The OSV PyPI export contains 488 affected-package entries for other ecosystems.
7. Only 65 rows in the whole submission are human-reviewed.

### Added in Session 01 (verified against the raw files, 2026-11-13)

8. LibHalluBench: 963 describe rows ("lesser known", "not widely used", "hidden gem") contain an unrendered template string (`{<HallucinationLevel.LIBRARY: 'library'>: ...}`) in the prompt. Whether this is upstream or an export artifact is unverified.
9. LibHalluBench `mistake` names are not nonexistence labels: 25 of the 1,049 distinct names are names of OpenSSF-reported malicious PyPI packages (34 are in at least one malicious or typosquat list). They occur in 192 of the 1,926 specify prompts. See `docs/research/FOUNDATION_REVIEW.md` §3.
13. The submitter's `benchmarks/agent2/libhallubench_specify_lookup.jsonl` records `registry_error` for 859 of its 1,049 lookups (189 `not_found`, 1 `verified`). It cannot be used even as a cross-check of which names exist.
10. Package Hallucination: 63 mentions are absent at generation (29 distinct normalized names in `packages.csv`); `manual_review.csv` has 45 rows (34 hallucination, 4 real, 7 other). The 29-versus-45 relationship is unresolved. `generations.jsonl` holds six model names; the README names three.
11. Ecosyste.ms is not independent of the malicious lists: 82 of 167 rows are attributed to OpenSSF or DataDog.
12. Readable on disk after quarantine: 11,992 OpenSSF malicious reports and 26,859 OSV records.

Per-dataset meaning, legitimate ground truth and limits: `docs/research/PROBLEM_DEFINITION.md` §1.

## 6. Missing or partial sources (acquisition deferred, D-010)

| Missing item | Notes |
|---|---|
| deps.dev | Entire source |
| OpenSSF npm, RubyGems, NuGet reports | — |
| OSV npm and other ecosystem exports | npm approved (D-027), not yet acquired |
| DataDog encrypted samples | **Live malware** |
| PyPI MalRegistry package archives | **Live malware**, no license |
| LibHalluBench dataset card and revision | Acquired 2026-11-14 (§2.1) |
| Real-manifest licenses; human gold for 5 `requirements.txt` and 4 Pipfile manifests | — |
| The normalized-record JSON schema referenced by the submission's `data/README.md` | Absent |
