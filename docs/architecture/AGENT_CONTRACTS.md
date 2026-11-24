# Agent contracts

Status 2026-11-17:
- **Agent 1** is implemented (see "Agent 1: dependency extraction" below, D-049 to D-052).
- **Agent 2** is implemented (see "Agent 2: registry verification and evidence lookup" below, D-053).
- **Agent 3 v2** and the adapter to the frozen v1 baseline are implemented (see "Agent 3: risk findings" below, D-055 to D-058, D-060, D-061).
- **Agent 5** is implemented (see "Agent 5: independent verification" below, D-059 to D-061).
- The **Agent 3 v1 baseline** contract is implemented. It is documented below from the code in `src/multi_agentic_security/agents/agent3_risk/baseline_v1/` and is unchanged.
- **Agent 4** is implemented (see "Agent 4: recommendation" below, D-062): the R0 rules, the provider-independent LLM interface and the Groq adapter (D-064, D-068). The design rationale is in `SYSTEM_ARCHITECTURE.md`.

## Requirements that apply to every new contract (from approved decisions)

- Versioned schemas, so every output records the contract version.
- Provenance on every evidence item (source, source version, record ID, retrieval time).
- Label families stay separate (malicious, withdrawn, typosquat, vulnerable, nonexistent, benign-reference). No single merged malicious/benign field (D-012).
- Registry lookups carry a timestamp, and current status is kept distinct from historical status.
- Failures are explicit states, never silently replaced with defaults or mock output.

---

## System specification adjustments (D-047)

These take precedence over the draft contracts below until those are rewritten from the implemented code.

| Agent | Change |
|---|---|
| All | Every decision record carries `reasons`: `[{rule_id, outcome, explanation, inputs, evidence_ids}]`. A decision without a reason is a contract violation. |
| Agent 1 | Input sources: `requirements_txt`, `package_json`, `package_lock_json`, `python_code`, `javascript_code`, `install_command_text`, `archive`, `directory`, `git_repository`. Dependency types: `runtime`, `dev`, `optional`, `peer`, `import`, `install_command`. Each record keeps the original declaration, source path and line, and an `extraction_status` (`ok`, `warning`, `unresolved`). Import names that cannot be mapped to a package stay `unresolved`. |
| Agent 2 | Registry statuses `found`, `not_found`, `security_placeholder`, `lookup_error`, `invalid_response`, `not_checked`; `registry_mode` `live`, `snapshot`, `off`. |
| Agent 3 | Output holds the frozen v1 result (labeled baseline) and the v2 findings side by side. |
| Agent 4 | Actions `remove`, `replace`, `upgrade`, `downgrade`, `keep`, `investigate`, `abstain`. Hosted LLM API behind one interface; records `backend`, `model`, `prompt_version`, `generation_status`. |
| Agent 5 | Runs isolated from Agent 4 (no import of Agent 4 code, no LLM, reads only the structured recommendation, the evidence store and read-only registry lookups). Verdict shown as verified (`accept`), rejected (`reject`) or needs review (`abstain`). |

## Agent 3 v1 baseline: deterministic risk scoring (frozen)

- **Code:** `src/multi_agentic_security/agents/agent3_risk/baseline_v1/`
  - `analyzer.py`: scoring
  - `similarity.py`: Levenshtein
  - `reference_packages.py`: catalog
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
- `status` values with defined behavior: `verified`, `not_found`, `registry_error`, `unsupported_ecosystem`, `invalid_input`. Any other value is treated as invalid.
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
- Compared against the same-ecosystem reference catalog; the best match is used.
- Weights: ≥ 0.90 adds 40 (`name_similarity`, strong); ≥ 0.80 adds 20 (moderate); otherwise no signal.

**Levels.** Score ≤ 19 is low, ≤ 49 medium, ≤ 74 high, otherwise critical.

**Catalog.** pypi: requests, numpy, pandas, flask. npm: express, axios, react.

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
- **The reference catalog is tiny and was chosen for the legacy pilot projects.** Similarity detection covers only those 7 names. This is a dataset-dependent limitation of the baseline.
- **The weights and cutoffs are a project-defined experimental policy, not a security standard.**

---

## Draft contracts (approved as design baseline, D-025; now implemented, see each agent)

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

### Agent 1: dependency extraction (implemented, D-049 to D-052)

- **Code:** `src/multi_agentic_security/agents/agent1_ingestion/` (stage version `agent1/0.1`), output `contracts.pipeline.ExtractionResult`.
- **Entry points:** `extract_files(project_id, files)` for in-memory files, `extract_zip(project_id, data, upload_name)`, `extract_directory(project_id, root, label=...)`, `extract_text(project_id, text)` for pasted text, `extract_git(project_id, url, fetcher)` for a public GitHub link (the fetcher is required; `HttpsFetcher` is the real one). Optional `limits=IntakeLimits(...)` and an injectable clock.
- **Sources:** `requirements_txt` (`requirements*.txt`, `*-requirements.txt`, `requirements.in`, `requirements/*.txt`), `package_json`, `package_lock_json` (also `npm-shrinkwrap.json`), `python_code` (`.py`, Python blocks in Markdown or pasted text), `javascript_code` (`.js .mjs .cjs .jsx .ts .tsx .mts .cts`, JS blocks), `install_command_text` (shell scripts, Dockerfiles, shell blocks and prompted command lines in Markdown or pasted text), `archive` (ZIP), `directory`, `git_repository` (public GitHub). Manifests are parsed first; their names, and names in install commands, are used to attribute Python imports (D-050).
- **Records:** one per declaration or lockfile entry, with the original declaration (credentials redacted), source path, line (`null` for JSON; the reasons carry a JSON pointer), dependency type, origin (`registry`, `vcs`, `url`, `path`, `unknown`), raw and normalized constraint, `extraction_status` (`ok`, `warning`, `unresolved`), warnings and reasons.
- **Reason rule IDs:** `a1.code.{python_import,js_import,conditional_import,import_mapped,import_matches_declared_package,import_unmapped}`, `a1.install.{command,executes_package,dependency_flag}`, `a1.requirements.{parsed,pinned,range,unpinned,marker,direct_reference,editable,location,unparseable}`, `a1.npm.{declared,pinned,range,unpinned,dist_tag,alias,vcs,url,path,unrecognized_spec,non_string_spec,invalid_name}`, `a1.package_lock.{entry,version,dev_optional,bundled,install_script_declared,no_integrity}`.
- **Failure codes (stage `agent1`):** `a1.source.{too_large,decode_error,binary_content,invalid_json,unexpected_structure,unsupported_file,unsupported_manifest,constraints_file,duplicate_path,no_manifest}`, `a1.json.duplicate_section`, `a1.requirements.{include_not_followed,package_source_option,global_option,unknown_option}`, `a1.package_json.{field_not_interpreted,section_not_object}`, `a1.package_lock.{no_entries,unknown_version,entry_not_object,workspace_entries,too_deep}`, `a1.code.{python_syntax_error,python_unparseable,js_unparseable,dynamic_import,stdlib_imports,local_imports,node_builtin_imports}`, `a1.install.{pipe_to_shell,unparseable,unsupported_tool,requirements_file_not_followed,package_source_option,no_packages,prose_line_not_read}`, `a1.source.{notebook_not_parsed,output_capped}`, `a1.git.{invalid_url,unsupported_host,fetch_error,too_large,http_status,redirect_refused}`.
- **Failure codes (stage `intake`):** `intake.path.{absolute,traversal,nul_character,duplicate,trailing_dot_or_space}`, `intake.limit.{upload_size,entries,total_size,file_size,read_total,compression_ratio,depth,path_length}`, `intake.zip.{invalid,symlink,encrypted,entry_unreadable}`, `intake.dir.{unreadable,not_a_directory,symlink,hard_link,changed_while_reading,special_file,outside_root}`, `intake.vendored_directory_skipped`, `intake.nested_archive`, `intake.limit.code_files`. A rejected upload yields no records and a failure that says it was rejected.
- **Safety:** uploads are read in memory as text; nothing is extracted to disk, imported, installed or executed (Python is parsed to a syntax tree only, JavaScript is tokenized); links are never followed; only files Agent 1 parses are read; repository links are downloaded as one archive into memory, never cloned.
- **Import mapping:** Python imports map to a package only through `import_map/1` or a package named by a manifest or install command in the same upload (the upload's own package wins over the table); otherwise the record is `unresolved` with the import name as a candidate in its reasons. Agent 2 does not look up such candidates (owner decision, D-053 b).

### Agent 2: registry verification and evidence lookup (implemented, D-053)

- **Code:** `src/multi_agentic_security/agents/agent2_registry/` (stage version `agent2/0.1`), output `contracts.pipeline.RegistryResult`. Evidence index: `src/multi_agentic_security/evidence_store/` (`evidence_store/1`, read-only, shared with Agents 3 and 5).
- **Entry point:** `verify(extraction, *, mode, client, evidence_store, evidence_cutoff=None, clock=...)`. `mode` is `off`, `snapshot` (`SnapshotRegistryClient(folder)`) or `live` (`HttpRegistryClient()`, constructed explicitly by the caller; there is no default client). `EvidenceStore.load(root)` loads the allow-listed current tables.
- **Output:** one `RegistryVerification` per Agent 1 `dependency_id`, in Agent 1's order: `status`, `registry`, registry facts (`canonical_name`, `versions`, `version_upload_times`, `latest_version`, selected `metadata`, `source_url`, `retrieved_at`, `error`), the `evidence_ids` of records about this package's own name (all families, all versions; typosquat records that only name it as the *target* are cited in the `a2.evidence.typosquat_target` reason, not here) and `reasons`. Version applicability is left to Agent 3.
- **Statuses:** `found`, `not_found` (HTTP 404; npm unpublished, unverified rule), `security_placeholder` (npm holding package; confirmed on 4 real responses, D-054; metadata lists `removed_versions` with upload times and `placeholder_published`), `lookup_error` (timeouts, connection errors, 429, 5xx, other HTTP errors, conflicting snapshot recordings, client failures; never `not_found`), `invalid_response` (malformed JSON or unexpected structure), `not_checked` (see below).
- **Reason rule IDs:** registry `a2.status.{found,not_found,npm_unpublished,security_placeholder,lookup_error,invalid_response,snapshot_conflict}`, `a2.registry.private_index`; not checked `a2.not_checked.{mode_off,no_client,client_mismatch,live_refused_held_out,unresolved,non_registry_origin,unsupported_ecosystem,invalid_name,not_in_snapshot}`; cut-off `a2.cutoff.{snapshot_after_cutoff,versions_filtered,no_version_before_cutoff}`; evidence `a2.evidence.{malicious,withdrawn,vulnerable,typosquat_name,typosquat_target,benign_reference,undated_included,excluded_after_cutoff,excluded_undated,no_match,not_looked_up,not_available,store_incomplete}`. Each evidence reason lists its evidence IDs, tables, version scopes and undated IDs.
- **Run failures (stage `agent2`):** `a2.mode.{client_missing,client_mismatch,live_with_cutoff}`, `a2.snapshot.unusable_file`, `a2.evidence.store_missing`, `evidence_store.{table_missing,manifest_invalid,hash_mismatch,size_mismatch,invalid_record,count_mismatch,unreadable,duplicate_evidence_id}`.
- **Cut-off:** `evidence_cutoff` set means a held-out run: evidence published on or after the cut-off date and undated evidence are excluded (counts reported); live lookups are refused; snapshot versions are limited to those uploaded before the cut-off and `latest_version` is withheld. A status from a snapshot taken after the cut-off (reason `a2.cutoff.snapshot_after_cutoff`) shows the state at retrieval time; Agent 3 must not treat such a `not_found` or `security_placeholder` as known at the cut-off. Excluded evidence IDs are listed in the reasons' `inputs.excluded_ids`. Without a cut-off, undated evidence is included and flagged.
- **Snapshot format** (`registry_snapshot/1`, one JSON file per lookup): `format`, `ecosystem`, `name`, `retrieved_at` (timezone-aware), `http_status` (or `null` with `error`), and `body` (JSON) or `body_raw` (text, for recorded malformed answers); optional `url`.
- **Evidence-store record (`pipeline/0.2`, D-054):** `RegistryResult.evidence_store` lists every allow-listed table with loaded flag, record count, SHA-256, schema/adapter/source versions, licenses and undated count.
- **Live use:** first live check (16 lookups): statuses as expected. PyPI returns 404 for removed malicious packages, so `not_found` alone never means nonexistent. A snapshot folder may contain `RUN_RECORD.json` (skipped when loading).

### Agent 3: risk findings (implemented, D-055)

- **Code:** `src/multi_agentic_security/agents/agent3_risk/` (stage `agent3/0.1`, findings `agent3_v2/0.1`): `assess.py`, `versions.py`, `similarity_v2.py`, `v1_adapter.py` (D-055 to D-058). The npm range grammar is in the neutral module `src/multi_agentic_security/versioning/npm_semver.py`, shared with Agent 5 (D-058). Output `contracts.pipeline.RiskResult`.
- **Entry point:** `assess(extraction, registry, *, evidence_store, clock=...)`. The cut-off is taken from `registry.evidence_cutoff`.
- **Per dependency:** `baseline_v1` (frozen v1 score, unchanged, labeled `agent3/v1`), `findings` (v2, one per family, no combined score), `reference_package` (typosquat target or the single similar popular name), `reasons` (first `a3.v1.baseline`, last `a3.summary`).
- **v1 status map:** `found`/`security_placeholder` -> `verified`; `not_found` -> `not_found`; `lookup_error`/`invalid_response` -> `registry_error`; `not_checked` -> `unsupported_ecosystem` when Agent 2 said so, else `registry_error`; unresolved -> no name (v1 returns `invalid_input`).
- **Findings:** `malicious_reported`, `compromised_version`, `withdrawn_only`, `vulnerable` (detail `advisories`, `fixed_in_stated`, `fixed_in_released`, `fixed_in_note`), `typosquat_listed`, `nonexistent` (registry `not_found`, evidence searched in a complete, matching store, no record of any family names it, not a post-cut-off snapshot), `registry_security_hold` (`pipeline/0.2`), `name_similar_to_popular` (edit distance 1 to a popular-list name known before the cut-off), `unknown`, `no_evidence` (not a safety statement). Version-scoped findings carry `detail.applicability`: `all_versions`, `affected`, `likely_affected`, `possible`, `undetermined`; records that only cover other allowed versions (`allowed_not_resolved`), a reported release that the constraint allows but that is no longer in the registry when no cut-off is set (`removed_from_registry`, D-057), or versions the constraint excludes (`not_affected`) give a reason, not a finding. `withdrawn_only` is version-aware too (D-057). Under a cut-off, when today's yanked list would change the installed version and the two choices disagree about a record, the applicability is `undetermined` (D-058).
- **Reason rule IDs:** `a3.v1.baseline`, `a3.summary`, `a3.malicious.whole_package.<applicability>`, `a3.malicious.version.<applicability>`, `a3.<family>.installed_version_not_affected`, `a3.<family>.reported_release_removed`, `a3.<family>.other_versions_only` (also for `withdrawn`), `a3.vulnerable.<applicability>`, `a3.withdrawn.{only,with_malicious}`, `a3.typosquat.listed`, `a3.nonexistent.{registry_not_found,published_before,evidence_not_checked,not_historical}`, `a3.cutoff.no_version_before_cutoff`, `a3.version.pin_not_in_registry`, `a3.evidence.incomplete`, `a3.registry.{security_hold,security_hold_not_historical}`, `a3.similarity.{edit_distance_1,no_list,not_checked}`, `a3.unknown.{unresolved,registry}`, `a3.evidence.not_used`, `a3.no_evidence`.
- **Failure codes (stage `agent3`):** `a3.input.{project_mismatch,duplicate_registry_result,unknown_dependency,missing_registry_result}`, `a3.evidence.{store_missing,not_looked_up_by_agent2,store_mismatch,store_incomplete,unknown_id,wrong_package,after_cutoff}`.
- **Limits:** declared npm ranges follow the documented node-semver grammar (pre-releases only through a comparator naming the same version); evidence ranges (both ecosystems) are ordered intervals that include pre-releases, as OSV orders versions by precedence (D-058, D-060; `versioning/evidence_ranges.py`); `*`, `""` and `latest` install the `latest` dist-tag even when it is a pre-release, and `x` is an ordinary range (D-058, D-060); under a cut-off a listed pre-release that `*` could install is `undetermined`; tags, URLs and aliases stay `undetermined`. The resolved version ignores other constraints of the environment. A release missing from the registry list is `undetermined`. Similarity uses one edit only and is off in held-out runs before the popular lists' date (2026-11-01). Agent 2 sets `retrieved_after_cutoff` on every looked-up result when a cut-off is given.

### Agent 4: recommendation (implemented, D-062 to D-064)

- **Code:** `src/multi_agentic_security/agents/agent4_recommendation/` (stage `agent4/0.1`): `packet.py` (inputs per variant), `rules.py` (R0), `llm.py` (provider-independent interface, recorded client, raw-response stores), `prompt.py`, `parse.py`, `recommend.py`, `providers.py` (Groq adapter, the only module with network access, D-064, D-068). Output `contracts.pipeline.RecommendationResult`; the contract is unchanged.
- **Entry point:** `recommend(extraction, registry, risk, *, evidence_store, variant="R0", llm=None, response_store=None, options=None, clock=...)`. One recommendation per Agent 1 dependency, in Agent 1's order. The cut-off is `registry.evidence_cutoff`. `RecommendationResult.stage_version` is `agent4/0.1+r0/0.1` or `agent4/0.1+a4-prompt/0.1`.
- **Variants** (run parameter):
  - `R0`: rules, backend `rules`.
  - `LLM-G`: an LLM with the dependency's evidence records.
  - `LLM-U`: an LLM with finding names only; no evidence records, IDs, versions from records or imitated names (D-062 b).
  - R0 and LLM-G receive the records Agent 2 cited for the dependency, those Agent 3's findings cite and, for a typosquat finding, the imitated packages' own malicious and typosquat records (D-063), read again from the store and filtered again by the cut-off. Without a usable store, LLM-G gets finding names only.
  - The variant is recorded in `prompt_version` (`a4-prompt/0.1+LLM-G`) and in the first reason `a4.input.packet`, which lists the evidence IDs given.
- **R0 rules** (first match wins; D-062 c, D-063):

  | Finding | Action | Claims |
  |---|---|---|
  | No package, no assessment | `abstain` | none |
  | Typosquat, one imitated package | `replace` with it; `remove` when the imitated package is itself reported malicious or a listed typosquat | `is_typosquat_of` (+ `is_reported_malicious`) |
  | Typosquat, several imitated packages | `remove` | `is_typosquat_of` each |
  | Whole-package malicious | `remove` | `is_reported_malicious` |
  | Security hold | `remove` | none |
  | Nonexistent | `remove` | `is_nonexistent` |
  | Compromised version / vulnerable (applicability not `undetermined`) | `upgrade` to the lowest registry release at or above a stated fix (`<X`) that is past every applying record and covered by no given record (final releases first, no local versions, yanked skipped without a cut-off); `abstain` when none or when the registry list is unknown | `is_compromised_version` / `is_vulnerable` (pinned version when covered), `fixed_in` (object: the recommended version) |
  | Same families, only `undetermined` | `investigate` | none |
  | Name similar to a popular package | `investigate` | none |
  | Unknown | `abstain` | none |
  | Withdrawn report only | `keep` | `report_withdrawn` |
  | No evidence | `keep` | `no_evidence_found` only when the store is usable and no risk record names the package |

- **LLM back end:**
  - `LLMClient.generate(LLMRequest) -> LLMResponse` is the only interface (D-022, D-038).
  - Adapter (D-064, D-068): `GroqClient`. Keys are read from the environment at each call and never recorded; model identifiers must be exact (no `latest`); no JSON mode is requested; calls are spaced for free-tier limits. The first live calls are in TRIAL-001. The local open-weight model is deferred (D-064 b); Gemini was removed (D-068).
  - Local adapter (D-074): `OllamaClient` (provider `ollama`): a model served by a local Ollama server through `/api/chat`; no key is read; the model must be an exact `name:tag` (no bare name, no `:latest`); the base URL must be plain http to a loopback address, so prompts cannot leave the machine through it; a prompt that would not fit the context window is refused (`prompt_too_long`) instead of being truncated by the server; a model that is not pulled is `model_not_found`; stop reasons `stop` and `length` map to `end` and `length`. Tested with a fake transport only.
  - Prompt versions (D-076): `LLMOptions.prompt_version` selects the text (`prompt.PROMPTS`): `a4-prompt/0.1` (default, frozen by a hash test) or `a4-prompt/0.2` (the 0.1 text plus the action and claim rules spelled out). The version is recorded on every recommendation (`prompt_version`) and in the stage version; the two versions produce different requests, so cached answers never mix. Cloud-tagged Ollama models are refused by the local adapter (D-074 e).
  - `RecordedLLMClient` replays responses by request hash or in order.
  - The prompt is built only from structured fields inside one JSON object marked as data. The original declaration, file contents, source paths and Agent 3's explanation texts are never sent.
  - Answers are parsed strictly into the contract.
  - Retries are bounded and recorded (`LLMOptions`: schema repairs and transport retries, default 2, maximum 5). Refusals are not retried.
  - Raw responses go to a `ResponseStore` (`FileResponseStore`: one file per response named by SHA-256, never overwritten); `raw_response_ref` is `a4raw:sha256:<hex>`.
  - Environment variables (values only in the git-ignored local secrets file; no template is kept): `AGENT4_GROQ_API_KEY1` with `AGENT4_GROQ_MODEL` (main model; the single name `AGENT4_GROQ_API_KEY` is a fallback key), optional `AGENT4_GROQ_API_KEY2` with `AGENT4_GROQ_MODEL_2` (a second Groq model, e.g. of another family; limits are per model; slot 2 never borrows slot 1's key, and keys are never rotated across requests or models), `AGENT4_LLM_TIMEOUT_SECONDS`, `AGENT4_LLM_MAX_OUTPUT_TOKENS`. `load_secrets(path)` loads only these names.
- **Failures are states:** `llm_error`, `llm_timeout`, `schema_violation` (after the bound) and `refusal` give `abstain` with a `Failure` `a4.llm.<status>`. Client exceptions are recorded by type and an optional validated code only, never by message (D-063). A client answer of the wrong type and a response-store failure are `llm_error`. Without a package or an assessment the model is not called.
- **Citations:** R0 cites only IDs it was given. LLM citations of IDs not given are kept and flagged (`a4.llm.cited_not_given`), so RQ1a can measure them; Agent 5 and the scorer judge them.
- **Reason rule IDs:**
  - `a4.input.packet`;
  - R0: `a4.r0.{no_package,no_assessment,typosquat.replace,typosquat.target_flagged_remove,typosquat.several_targets_remove,malicious.remove,security_hold.remove,nonexistent.remove,version.upgrade,version.no_target,version.undetermined_investigate,similar_name.investigate,unknown.abstain,withdrawn.keep,no_evidence.keep,no_evidence.keep_other_versions,no_evidence.keep_unverified,<finding>.evidence_not_given,no_rule}`;
  - LLM: `a4.llm.{attempt.<status>,<status>,no_package,no_assessment,cited_not_given,recommendation}`.
- **Failure codes (stage `agent4`):** `a4.input.{project_mismatch,duplicate_registry_result,duplicate_assessment,unknown_dependency,missing_registry_result,missing_assessment}`, `a4.evidence.{store_missing,not_looked_up_by_agent2,store_mismatch,unknown_id,after_cutoff}`, `a4.llm.{schema_violation,llm_error,llm_timeout,refusal}`.
- **Limits:**
  - R0 never recommends a downgrade, because no source names an earlier safe version.
  - Typosquat target names in the evidence are not validated as package names (D-063 k).
  - The "replace" branch of the nonexistent rule is inactive (no approved pair source).
  - Upgrade targets ignore other constraints of the project; the semver distance and constraint compatibility are reported by Agent 5 (D-036).
  - Targets in held-out runs need recorded registry lookups.

### Agent 5: independent verification (implemented, D-059 to D-061)

- **Code:** `src/multi_agentic_security/agents/agent5_verification/` (stage `agent5/0.1`): `verify.py` (checks and verdict), `versions.py` (Agent 5's own version logic). Output `contracts.pipeline.VerificationResult`; the contract is unchanged.
- **Entry point:** `verify_recommendations(extraction, registry, recommendations, *, evidence_store, target_client=None, enabled_checks=None, clock=...)`. `recommendations` is a `RecommendationResult` or a mapping of the same shape; each recommendation is validated on its own. `target_client` is a registry client used only for recommended targets and for claim subjects other than the dependency (`SnapshotRegistryClient` in experiments). The cut-off is `registry.evidence_cutoff`.
- **Isolation:** no import from Agent 3 or Agent 4, no LLM, no network library (AST test); only structured fields are read (never `rationale`); Agent 3's findings are not an input.
- **Checks** (one `CheckResult` each, in `CheckName` order): `schema`, `dependency_identity`, `action_allowed`, `claims_supported`, `target_exists`, `target_not_malicious`, `target_not_typosquat`, `target_version_not_vulnerable`, `replacement_matches_reference`, `action_consistent`. Target checks are `not_applicable` without a target; `replacement_matches_reference` applies to `replace` of a dependency that a typosquat record lists; `action_consistent` applies to `keep`, `upgrade` and `downgrade`. Rules in D-059 (b).
- **Verdict:** `verdict_from_checks` (any `fail` -> `reject`; any required `not_run` -> `abstain`; otherwise `accept`). Anything that cannot be checked is `not_run`, never `pass`.
- **Cut-off:** evidence published on or after it and undated evidence are not used (citing it fails the claim); a live client is refused; target and dependency versions count only when uploaded before the cut-off (Agent 5 filters again); a `not_found` or security hold recorded after the cut-off, a package without a release before the cut-off, and an unversioned target whose newer reported release may have been the install then all leave the check `not_run` (D-060).
- **Ablation:** every check except `schema` can be switched off (`enabled_checks`); it is then `not_run` with `required=False`.
- **Reason rule IDs:** `a5.check.<check>.{pass,fail,not_run,not_applicable,switched_off}` (inputs and evidence IDs per check; `action_allowed` reports `semver_distance` and `constraint_admits_target`, D-036) and `a5.verdict.{accept,reject,abstain}`.
- **Failure codes (stage `agent5`):** `a5.input.{project_mismatch,invalid_recommendations,unknown_dependency,duplicate_recommendation,missing_registry_result,missing_recommendation}`, `a5.evidence.{store_missing,store_incomplete,store_differs_from_agent2}`, `a5.registry.{no_client,live_with_cutoff,client_error}`.
- **Limits:** Agent 5 knows only what the evidence store and the registry know at the cut-off; it cannot detect an unreported malicious package, and a report withdrawn after the cut-off already looks withdrawn in a held-out run. Releases inside an affected range that were deleted later are not visible. Under a cut-off a stated target version that does not exist is `not_run`, never `reject` (the snapshot cannot show that it was absent then). Name similarity and the target's own dependencies are not checked. Version resolution assumes a fresh install with the default resolver.

### Pipeline orchestrator (implemented, D-066)

- **Code:** `src/multi_agentic_security/pipeline/` (`graph.py`, `guardrails.py`, `llm_wrappers.py`, `snapshots.py`). LangGraph state graph; contracts unchanged.
- **Entry point:** `run_pipeline(PipelineConfig(...)) -> RunResult(status, report, failures, run_dir, record, resumed_stages)`. `PipelineConfig` holds the project ID, the files (or an `extract_fn` for ZIP or Git intake), registry mode and clients, the evidence store, the cut-off, the Agent 4 variant, the LLM client (wrapped for cache and budget), options, `run_dir` and `resume`.
- **Graph:** `guard_input -> extract -> extract_guard -> registry -> risk -> recommend -> verify -> report`.
- **Failure codes (stage `pipeline`):** `pipeline.guard.{project_id,variant,llm_missing,registry_mode,live_with_cutoff,client_missing,too_many_dependencies,secret_in_output}`, `pipeline.stage_error.{extract,registry,risk,recommend,verify,report}`.
- **Run record:** `RUN_RECORD.json` next to the stage files (`extract.json`, `registry.json`, `risk.json`, `recommend.json`, `verify.json`, `report.json`) with versions, configuration, evidence-store fingerprint, cost counters and file hashes.
- **Cost control:** `BudgetedLLMClient` and `CachingLLMClient`. **Snapshots:** `MultiSnapshotClient`.

The evaluation scorer is not an agent and has no pipeline contract (D-067): `src/multi_agentic_security/evaluation/` holds the independent scorer (`score(case, recommendation, ScoreContext) -> Score`; no agent import), `metrics.aggregate` (conditions C1-C5 per family), `stats` (Wilson, grouped bootstrap, exact McNemar, Holm, kappa, non-inferiority), `cases` (case schema, deterministic grouped split, D-044 pin rule), `harness.run_evaluation` and `budget.plan_llm_calls`. See `SYSTEM_ARCHITECTURE.md` §4. After the independent review (D-071): the scorer refuses a non-snapshot registry client and a timezone-naive cut-off, resolves an unpinned dependency inside its declared specifier, treats unreadable or missing version data as a state (never as nonexistent), requires a `fixed_in` version to be a real, unyanked release before the cut-off, and treats a cited record published after the cut-off as unsupported. `metrics.delivered_unsafe_outcome` is the outcome for McNemar between a verifier-off and a verifier-on condition; `paired_binary` reports pairs it drops; a verifier condition without a verdict is an error. `stats.bootstrap_ci` gives no interval below `min_groups` groups; `paired_diff_ci_by_key` pairs by case ID. `cases.verify_splits` recomputes group connectivity and, with `check_seed=True`, compares against `split_three_way`; `mark_eval_only` also checks expected targets. The default split fractions are 70 / 15 / 15 (D-072). Scorer 0.2 (D-075): a `replace` naming the dependency's own package is scored as `keep` (no version) or on its version, is marked `action_valid: false` and is never acceptable.
