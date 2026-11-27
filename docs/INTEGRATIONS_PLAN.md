# Developer integrations: plan

Status: **planned, not built.** Nothing in this file is implemented yet.

This plan is separate from the web interface (`docs/WEB_HANDOVER.md`). The web interface is for people who
want to upload a file and read the agents' reasons. The integrations below are for developers who will not
open a website: the check runs where they already work.

```
             ┌──────────────────── core (Python, this repository) ──────────────────┐
             │   Agents 1–5 + evidence store  →  run_pipeline()  →  check_package()  │
             └──────────▲───────────────────────▲──────────────────────▲─────────────┘
                        │                       │                      │
              ┌─────────┴────────┐   ┌──────────┴─────────┐   ┌────────┴─────────┐
              │ MCP server       │   │ CLI + pre-commit   │   │ GitHub Action    │
              │ used by AI       │   │ used by the        │   │ runs on every    │
              │ coding assistants│   │ developer's git    │   │ pull request     │
              └──────────────────┘   └────────────────────┘   └──────────────────┘
```

None of these is part of the web interface, and none needs it.

## 1. Why

AI coding assistants sometimes suggest packages that do not exist, lookalike (typosquatted) names, or
vulnerable versions. A developer who trusts the assistant will not stop to check. The earliest and least
effort point to catch this is **inside the assistant, before it suggests the package**. A check on every
pull request catches anything that slips through.

## 2. Ownership and order

| Step | What | Owner | Depends on |
|---|---|---|---|
| 1 | `check_package` shared function, with tests | Core maintainer | Nothing (existing pipeline) |
| 2 | MCP server | Core maintainer | Step 1 |
| 3 | CLI (and pre-commit hook) | Core maintainer | Step 1 |
| 4 | GitHub Action | Web developer or core maintainer, if time allows | Step 3 |

Rules:

- Agents 1 to 5 are **not changed** by any step. Integrations only call `run_pipeline`.
- The web back end may call `check_package` (for a "check one package" box) but never changes it.

## 3. Step 1: the shared function `check_package`

File: `src/multi_agentic_security/integrations/check.py`.

### 3.1 What it does

1. Validate the input (section 3.4).
2. Write one line into an in-memory manifest: `requirements.txt` for PyPI, `package.json` for npm.
3. Run the existing pipeline with the rule-based variant:
   `PipelineConfig(..., variant="R0", registry_mode="off" or "snapshot", ...)`.
4. Map the `PipelineReport` to the output in section 3.2.

```python
from multi_agentic_security.agents.agent1_ingestion import UploadedFile
from multi_agentic_security.pipeline import PipelineConfig, run_pipeline

def check_package(name, ecosystem="pypi", version=None, *, store, run_dir, registry_mode="off"):
    # validate name, ecosystem and version first (section 3.4)
    if ecosystem == "pypi":
        line = f"{name}=={version}" if version else name
        files = [UploadedFile("requirements.txt", (line + "\n").encode())]
    else:
        dep = version or "*"
        files = [UploadedFile("package.json", json.dumps({"dependencies": {name: dep}}).encode())]
    result = run_pipeline(PipelineConfig(project_id=f"check-{name}", files=files, evidence_store=store,
                                         variant="R0", registry_mode=registry_mode, run_dir=run_dir))
    return to_output(result)   # section 3.2
```

Why `R0` (rules and verifier, no language model):

- In the held-out evaluation with all evidence visible (S0, TEST), the verified language model was no safer
  than the rules, and the rules gave advice in more cases. A live tool sees all current evidence, which is
  closest to S0.
- It needs no GPU, no API key and no network. (Response time is not measured yet; measure it in step 1.)
- Agent 5 still checks every rule-based recommendation, and its verdict decides whether a fix is shown.

### 3.2 Output

The output uses the existing contract fields (`contracts/pipeline.py`); it does not invent new labels.

```json
{
  "package": "reqeusts",
  "ecosystem": "pypi",
  "version": null,
  "status": "done | failed",
  "risk_level": "low | medium | high | critical | unknown",
  "findings": ["typosquat_listed", "name_similar_to_popular"],
  "recommendation": { "action": "replace", "target": "requests", "target_version": null },
  "verification": "accept | reject | abstain",
  "suggested_fix": "requests",
  "reasons": [ { "rule": "...", "evidence_ids": ["..."], "sentence": "..." } ],
  "evidence_snapshot": "manifest hash of the evidence store used",
  "checker_version": "integrations-check/0.1"
}
```

| Field | Source in `PipelineReport` |
|---|---|
| `risk_level`, `findings` | `risk.assessments[0]` (Agent 3; `FindingType` values) |
| `recommendation` | `recommendations.recommendations[0]` (`action`, `target`) |
| `verification` | `verification.verifications[0].verdict` (Agent 5) |
| `reasons` | `reasons` of the Agent 3, 4 and 5 decisions, in order |
| `status` | `RunResult.status`; on `failed`, `RunResult.failures` |

Safety rules for the output:

- **`suggested_fix` is filled only when Agent 5 returns `accept`.** On `reject` or `abstain` it is `null`,
  and the reasons say why. An unverified fix is never shown as a fix.
- **`unknown` is a real answer** ("no evidence was found"), never shown as safe.
- A pipeline failure returns `status: "failed"` with the failure, never a default verdict.

### 3.3 Evidence store

- Load the store **once** (at server or process start), not on every call.
- The path comes from an environment variable, for example `MAS_EVIDENCE_STORE`. Never hard-code it.
- The research evidence store is a frozen snapshot. Integrations read it and never write to it.

### 3.4 Input validation (untrusted input)

Package names come from an AI assistant or a file, so they are untrusted.

- `ecosystem` must be `pypi` or `npm`.
- `name`: 1 to 214 characters from `[A-Za-z0-9._@/-]`; otherwise `status: "failed"` with a reason.
- `version`: at most 64 characters, no whitespace.
- Never pass input to a shell, never install, download, import or run a package.

### 3.5 Tests (no network)

File: `tests/unit/test_integrations_check.py`, using `tests/fixtures/agent2/` only.

- One test per kind of result: a known malicious name, a typosquat, a vulnerable version, a nonexistent
  name, a known benign package, and a name with no evidence (`unknown`).
- `suggested_fix` is `null` whenever the verification verdict is not `accept`.
- Invalid names and ecosystems give `failed` with a reason.
- The same input gives the same output twice (deterministic).

## 4. Step 2: the MCP server

MCP (Model Context Protocol) is an open standard that lets AI coding assistants call local tools. The server
runs on the developer's own computer; there is no website and no hosting.

### 4.1 Build

- Package: `mcp`, the official Python SDK. Install it only when this step starts; add it as an optional
  dependency (`[project.optional-dependencies] integrations = ["mcp"]`), not a core one.
- File: `src/multi_agentic_security/integrations/mcp_server.py`, transport `stdio`.
- One tool, `check_package(name, ecosystem="pypi", version=None)`, returning the output of section 3.2.
  Its description tells the assistant when to use it: *"Check a package before suggesting, adding or
  installing it. Returns the risk, the evidence and a verified fix if one exists."*
- Load the evidence store once at start-up. Read-only.
- Check the SDK's current documentation for the exact server API before writing it.

### 4.2 How a developer uses it

One-time setup:

1. Install: `pip install multi-agentic-security[integrations]` (after a release; until then,
   `git clone` and `pip install -e .[integrations]`).
2. Get the evidence data and set `MAS_EVIDENCE_STORE` to its folder.
3. Register the server in the assistant's MCP settings (file name and format depend on the assistant):
   ```json
   { "servers": { "mas-check": { "command": "python",
     "args": ["-m", "multi_agentic_security.integrations.mcp_server"] } } }
   ```
4. Add one line to the project's assistant instruction file (for example `AGENTS.md` or
   `.github/copilot-instructions.md`):
   *"Before adding or suggesting any dependency, call `check_package`."*

Every day after that:

1. The developer asks the assistant as usual: *"Add a library to parse YAML."*
2. The assistant calls `check_package("pyyamll", "pypi")`.
3. The tool returns, for example, a typosquat finding with its evidence and the verified fix `pyyaml`.
4. The assistant suggests the safe package. The developer did nothing extra.

### 4.3 Done when

- [ ] The server starts with `python -m multi_agentic_security.integrations.mcp_server`.
- [ ] An AI assistant on a local machine calls `check_package` and shows the result (screenshot for the demo).
- [ ] A test calls the tool function directly on fixtures (no network, no assistant needed).

## 5. Step 3: CLI and pre-commit hook

- `python -m multi_agentic_security.integrations.cli requirements.txt` (or `package.json`) checks every
  dependency in the file through the full pipeline (`R0`), prints one line per package and exits with:
  `0` all clear, `1` at least one package rejected or rated high or critical, `2` the check itself failed.
- Pre-commit: a `.pre-commit-hooks.yaml` entry that runs the CLI on changed manifest files.
- Done when: the CLI exits `1` on a fixture manifest containing a known typosquat and `0` on a clean one.

## 6. Step 4: GitHub Action (optional)

- Workflow `.github/workflows/dependency-check.yml`: on pull requests that change `requirements*.txt`,
  `pyproject.toml` or `package.json`, run the CLI and fail on exit code `1`.
- This is the safety net: an assistant may skip the MCP tool, but this check cannot be skipped.
- The full evidence store is not public. The Action needs either a small published subset (only sources
  whose licenses allow redistribution) or a self-hosted runner where the store is available.

## 7. Limits (state these honestly in any demo or report)

- **Frozen data.** The evidence store is a research snapshot. Advisories and malicious packages published
  after it are missing. A live version must fetch fresh data (for example from the OSV API) into a
  **separate** store, record when it did, and never change the research store.
- **The assistant may not call the tool.** The instruction line helps; the GitHub Action covers the rest.
- **Results in the paper do not transfer automatically.** The paper evaluates the pipeline on held-out
  cases. The integrations are a delivery mechanism and have not been evaluated as such.
- **No package is ever installed or run** by any integration. The datasets behind the evidence contain
  real malware.
