# Agent contracts

Status 2026-11-13:
- Only the **Agent 3 v1 baseline** contract is implemented. It is documented below from the code in `src/multi_agentic_security/agents/agent3_risk/baseline_v1/` and is unchanged.
- **Draft contracts** for Agents 1, 2, 4 and 5 and for Agent 3 v2 are at the end of this file. They are **approved as the design baseline (D-025) but not implemented**; changes during implementation go through recorded decisions. The design rationale is in `SYSTEM_ARCHITECTURE.md`.

## Requirements that apply to every new contract (from approved decisions)

- Versioned schemas, so every output records the contract version.
- Provenance on every evidence item (source, source version, record ID, retrieval time).
- Label families stay separate (malicious, withdrawn, typosquat, vulnerable, nonexistent, benign-reference). No single merged malicious/benign field (D-012).
- Registry lookups carry a timestamp, and current status is kept distinct from historical status.
- Failures are explicit states, never silently replaced with defaults or mock output.

---

## Agent 3 v1 baseline: deterministic risk scoring (frozen)

- **Code:** `src/multi_agentic_security/agents/agent3_risk/baseline_v1/`
  - `analyzer.py`: scoring
  - `similarity.py`: Levenshtein
  - `reference_packages.py`: catalogue
  - `models.py`: outputs
  - `inputs.py`: input types
- **Entry points:**
  - `analyze_verification(verification, *, reference_packages=None, policy=None) -> dict`
  - `RiskAnalyzer(reference_packages=None, policy=RiskPolicy()).analyze(verification) -> RiskResult`
- **No network access, no recommendations.**

### Input

Either an `inputs.VerificationResult`, or a mapping with the same shape:

```
{ "project_id": str,
  "dependencies": [ { "package_name": str|null, "ecosystem": str|null, "version_constraint": str|null,
                      "source_file": str|null, "status": str,
                      "exists": bool|null, "registry_metadata": object|null } ] }
```

- `exists` and `registry_metadata` are accepted but not used for scoring.
- `status` values with defined behaviour: `verified`, `not_found`, `registry_error`, `unsupported_ecosystem`, `invalid_input`. Any other value is treated as invalid.
- If the top-level input is malformed (no string `project_id` or no list `dependencies`), the result is `{"project_id": "", "dependencies": []}`.

### Scoring (v1 policy)

| Status | Score | Level | Signals |
|---|---|---|---|
| `verified` | 0 | low | none |
| `not_found` | `min(100, 50 + similarity weight)` | from cutoffs | `not_found` (50), plus optionally `name_similarity` |
| `registry_error`, `unsupported_ecosystem`, `invalid_input`, other | null | unknown | one zero-weight signal of that type (`invalid_input` for unrecognised statuses) |
| Missing or invalid required fields | null | unknown | `invalid_input` |

**Similarity.**
- Computed only for `not_found`, using normalized Levenshtein: `1 - distance / max(len)`, case-insensitive.
- Compared against the same-ecosystem reference catalogue; the best match is used.
- Weights: ≥ 0.90 adds 40 (`name_similarity`, strong); ≥ 0.80 adds 20 (moderate); otherwise no signal.

**Levels.** Score ≤ 19 is low, ≤ 49 medium, ≤ 74 high, otherwise critical.

**Catalogue.** pypi: requests, numpy, pandas, flask. npm: express, axios, react.

**Policy.** Overridable per call via `RiskPolicy` and `reference_packages`. The defaults above are the v1 baseline and are pinned by tests.

### Output (`RiskResult.to_dict()`)

```
{ "project_id": str,
  "dependencies": [ { "package_name", "ecosystem", "version_constraint", "source_file",
                      "registry_status": str|null, "risk_score": int|null,
                      "risk_level": "low"|"medium"|"high"|"critical"|"unknown",
                      "signals": [ { "type", "weight", "evidence",
                                     "reference_package"?, "similarity"? } ] } ] }
```

### Known limitations (verified)

- **Only `not_found` packages can score above 0.** Malicious or typosquatted packages that still exist in a registry score 0 / low.
  - On 132 confirmed typosquats (Ecosyste.ms PyPI + npm), every flagged case was a not-found case. Source: `research/datasets/extracted/v1/data/manifests/eval_run_2026-11-12T182055+0000.json`.
  - That run used current registry lookups.
- **The reference catalogue is tiny and was chosen for the legacy pilot projects.** Similarity detection covers only those 7 names. This is a dataset-dependent limitation of the baseline.
- **The weights and cutoffs are a project-defined experimental policy, not a security standard.**

---

## Draft contracts (approved as design baseline, D-025; not implemented)

All records carry `contract_version` (starting at `"0.1-draft"`). Field names may change during implementation through recorded decisions.

### Shared types

```
PackageRef   { "ecosystem": "pypi"|"npm", "name_raw": str, "name_normalized": str }

Evidence     { "evidence_id": str,                 // stable, derived from source + source_record_id
               "family": "registry_state"|"malicious_report"|"compromised_version"|
                         "withdrawn_report"|"typosquat_pair"|"vulnerability_advisory",
               "package": PackageRef,
               "version_scope": "all"|"listed"|"range"|"none",
               "versions": [str]|null, "ranges": [object]|null,
               "target_package": PackageRef|null,   // typosquat_pair only
               "fixed_versions": [str]|null,        // vulnerability_advisory only
               "source_dataset": str, "source_version": str, "source_record_id": str,
               "source_file_sha256": str|null, "license": str|null,
               "published_at": str|null,            // source publication time
               "retrieved_at": str,                 // when we obtained it
               "corroborates": [str] }              // evidence_ids of the same report in other sources

Failure      { "stage": str, "code": str, "detail": str }
```

Rules that apply to every contract:

- `family` values are never merged or mapped onto a malicious/benign flag (D-012).
- `registry_state` evidence always has `retrieved_at`, and its state is one of `present`, `absent`, `security_placeholder`, `error`. A current lookup is never stored as historical status.
- An evidence record with `published_at` later than the run's cut-off is invisible to Agents 2–5.
- An evidence record with no `published_at` is visible in ordinary runs and is excluded from held-out experiments, by both the agents and the scorer (added in the review).
- In held-out experiments `registry_mode` must not be `live` for target existence checks, because today's registry reflects takedowns after the cut-off (added in the review).
- A failure is returned as a `Failure`, never replaced by a default.

### Agent 1: dependency extraction (draft)

```
input   { "project_id": str, "manifest_paths": [str] }

output  { "contract_version": str, "project_id": str,
          "dependencies": [ { "dependency_id": str, "package": PackageRef|null,
                              "version_constraint": str|null,
                              "source_file": str, "source_line": int|null,
                              "group": str|null,                 // e.g. "dev", "optional:test"
                              "origin": "registry"|"vcs"|"url"|"path"|"unknown" } ],
          "failures": [Failure] }
```

Codes: `file_unreadable`, `unsupported_format`, `malformed_entry`.

### Agent 2: evidence collection (draft)

```
input   { "dependencies": [...Agent 1 dependencies...],
          "evidence_cutoff": str,                    // ISO date
          "registry_mode": "live"|"snapshot"|"off" }

output  { "contract_version": str, "evidence_cutoff": str, "store_version": str,
          "dependencies": [ { "dependency_id": str, "evidence": [Evidence] } ],
          "failures": [Failure] }
```

Codes: `registry_error`, `registry_rate_limited`, `store_unavailable`, `unsupported_ecosystem`.
An empty `evidence` list means "no record found in the store", which is not a statement that the package is safe.

### Agent 3 v2: risk analysis (draft; allowed by D-020)

```
input   Agent 2 output

output  { "contract_version": str, "agent3_version": "2.x",
          "dependencies": [ { "dependency_id": str,
                              "findings": [ { "finding": "nonexistent"|"typosquat_listed"|
                                                         "name_similar_to_popular"|"malicious_reported"|
                                                         "compromised_version"|"vulnerable"|
                                                         "withdrawn_only"|"no_evidence"|"unknown",
                                              "evidence_ids": [str],
                                              "detail": object|null } ] } ] }
```

There is no combined score or level. The v1 baseline keeps its own contract (above); an adapter outside `src/multi_agentic_security/agents/agent3_risk/baseline_v1/` feeds it from Agent 2's `registry_state`.

### Agent 4: recommendation (draft)

```
input   { "dependency": ..., "findings": [...], "evidence": [Evidence],
          "variant": "R0"|"LLM-U"|"LLM-G", "model": str|null, "seed": int|null }

output  { "contract_version": str, "dependency_id": str, "variant": str, "model": str|null,
          "action": "remove"|"replace"|"upgrade"|"keep"|"abstain",
          "target": { "package": PackageRef, "version": str|null }|null,   // replace, upgrade
          "claims": [ { "type": "is_reported_malicious"|"is_compromised_version"|
                                "is_typosquat_of"|"is_nonexistent"|"is_vulnerable"|
                                "fixed_in"|"report_withdrawn"|"no_evidence_found",
                        "subject": PackageRef, "object": str|null,
                        "evidence_ids": [str] } ],
          "explanation": str|null,                  // free text; never scored as fact
          "raw_response_ref": str|null,
          "failure": Failure|null }
```

Codes: `llm_error`, `llm_timeout`, `schema_violation`, `refusal`. Only `claims` are evaluated for support; `explanation` is for the reader.

Variants (clarified in the review): `R0` and `LLM-G` receive `evidence`. `LLM-U` receives an empty `evidence` list and the finding names only; whether it should receive even the finding names is an open choice.

### Agent 5: independent verification (draft)

```
input   { "dependency": ..., "recommendation": ...Agent 4 output...,
          "evidence_cutoff": str, "registry_mode": "live"|"snapshot"|"off" }

output  { "contract_version": str, "dependency_id": str,
          "verdict": "accept"|"reject"|"abstain",
          "checks": [ { "check": "schema"|"claims_supported"|"target_exists"|
                                 "target_not_malicious"|"target_not_typosquat"|
                                 "target_version_not_vulnerable"|"action_consistent",
                        "result": "pass"|"fail"|"not_run"|"not_applicable",
                        "evidence_ids": [str], "detail": str|null } ],
          "failures": [Failure] }
```

Rules: any `fail` gives `reject`; any `not_run` on a required check gives `abstain`; `accept` requires every required check to `pass` or be `not_applicable`. The four `target_*` checks are `not_applicable` when the action has no target (`remove`, `keep`, `abstain`). Agent 5 reads the recommendation's structured fields only and re-queries the evidence store for the target.

The evaluation scorer is not an agent and has no contract here; see `SYSTEM_ARCHITECTURE.md` §4.
