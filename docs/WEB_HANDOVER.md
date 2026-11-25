# Web interface: handover guide

This guide is for the developer who builds the web interface of the Multi-Agentic Security System. It explains
what already exists, how to set it up, where the web code plugs in, and the rules that keep the research results
valid.

## 1. What already exists

The system is a Python library with five agents that run in a fixed order:

| Agent | Code folder (`src/multi_agentic_security/agents/`) | What it does |
|---|---|---|
| 1 Dependency Extraction | `agent1_ingestion` | Reads `requirements.txt`, `pyproject.toml`, `Pipfile`, `package.json` |
| 2 Evidence Collection | `agent2_registry` | Looks up each package in the evidence store and registry recordings |
| 3 Risk Assessment | `agent3_risk` | One finding per label family (malicious, typosquat, vulnerable, nonexistent) |
| 4 Recommendation and Remediation | `agent4_recommendation` | Proposes an action (rules, or a local language model) |
| 5 Verification | `agent5_verification` | Accepts, rejects or abstains on each recommendation |

The agents are connected by a LangGraph state graph in `src/multi_agentic_security/pipeline/graph.py`. The whole
system is one function call: `run_pipeline(PipelineConfig(...))`. It returns a report that holds every agent's
output and the reasons for every decision.

There is no web code yet. Your job is to add it **on top of** this library without changing the agents.

Read first: `README.md`, `docs/architecture/SYSTEM_ARCHITECTURE.md` and `docs/architecture/AGENT_CONTRACTS.md`
(the input and output of every agent).

## 2. Install

| Tool | Needed for |
|---|---|
| Git | Cloning and branches |
| Python 3.13 or newer | The library |
| Node.js LTS (includes npm) | The React front end |
| Ollama (optional) | Running a local language model for Agent 4 |

```
git clone https://github.com/ChandanHegde15/multi-agentic-security-system.git
cd multi-agentic-security-system
git checkout -b web-integration
python -m pip install -e ".[dev]"
python -m pytest -q                 # expected: 1321 passed, 1 skipped
```

If pytest complains about a temporary folder, add `--basetemp=.pytest_tmp`.

Optional local models (about 2 to 5 GB each):

```
ollama pull llama3.2:3b
ollama pull qwen2.5:3b
ollama pull qwen2.5:7b
```

No API key is needed. The rule-based recommender and all tests work without any model.

## 3. Data

- **For development**, use the small test fixtures in `tests/fixtures/agent2/` (an evidence store in
  `evidence/v1/` and sample uploads in `upload/`). They are in the repository.
- **For real scans**, the full evidence store (about 106 MB) is shared separately by the project lead as a private
  download. Unzip it outside the repository, or under `research/datasets/verified/normalized/v1/`, which is
  git-ignored. Never commit it.
- The raw source archives contain real malware samples. They are not part of the handover and must never be
  downloaded, extracted or opened.

## 4. Run the pipeline from Python

This example runs offline on the test fixtures (rules only, no model, no network):

```python
from pathlib import Path
from multi_agentic_security.agents.agent1_ingestion import UploadedFile
from multi_agentic_security.evidence_store import EvidenceStore
from multi_agentic_security.pipeline import PipelineConfig, run_pipeline

FIX = Path("tests/fixtures/agent2")
files = [UploadedFile(p.name, p.read_bytes()) for p in sorted((FIX / "upload").iterdir())]
store = EvidenceStore.load(FIX / "evidence" / "v1")          # load once at server start, reuse

result = run_pipeline(PipelineConfig(project_id="demo-1", files=files, evidence_store=store,
                                     variant="R0", run_dir=Path("runtime/runs/demo-1")))
print(result.status)                              # "done" or "failed"
print(result.report.summary.model_dump(mode="json"))
report_json = result.report.model_dump_json()     # send this to the front end
```

Useful `PipelineConfig` fields:

| Field | Values |
|---|---|
| `variant` | `"R0"` rules; `"LLM-U"` model with finding names only; `"LLM-G"` model with the evidence records |
| `llm` | Needed for `LLM-U` / `LLM-G`, e.g. `OllamaClient("qwen2.5:7b")` from `multi_agentic_security.agents.agent4_recommendation.providers` |
| `response_store` | Needed with `llm`, e.g. `FileResponseStore("runtime/responses")` from `multi_agentic_security.agents.agent4_recommendation` |
| `evidence_cutoff` | Optional `datetime` (UTC); evidence published later is hidden from the agents |
| `registry_mode` | `"off"` (default) or `"snapshot"` with a recorded registry client. Keep it `"off"` at first |
| `run_dir` | Folder where the run record is written; use a new folder per run under `runtime/` |

The report (`result.report`) has one section per agent: `extraction`, `registry`, `risk`, `recommendations`,
`verification`, and a `summary`. Every decision carries `reasons`: the rule, its inputs, the evidence IDs and a
plain sentence. Show these in the interface; they are what makes the system explainable.

## 5. What to build

Suggested stack: **FastAPI** (back end) and **React with Vite** (front end).

```
python -m pip install fastapi uvicorn python-multipart
npm create vite@latest web -- --template react
```

Suggested folders (new code only):

```
src/multi_agentic_security/api/      FastAPI app (endpoints, upload handling)
web/                                 React app
tests/api/                           API tests (offline, using the fixtures)
```

### Back end (minimum)

| Endpoint | Purpose |
|---|---|
| `POST /api/scans` | Accept one or more manifest files, run the pipeline, return a scan ID and the report |
| `GET /api/scans/{id}` | Return a stored report |
| `GET /api/health` | Simple status check |

Run the pipeline in a background task or worker if model runs are slow; a local 7B model can take minutes per
project.

### Front end (minimum)

1. **Upload page** with a drop zone for the four manifest types and a choice of recommender (rules or a local
   model) and verifier on or off.
2. **Results overview**: one row per dependency with a colored label (malicious, typosquat, vulnerable,
   nonexistent, no evidence) and the final verdict.
3. **One tab per agent**, showing that agent's output and its reasons.
4. **Clear failure states**: if a stage fails or a recommendation is withheld, say so; never show a blank or a
   default "safe".

### Nice to have

- Download the report as JSON.
- A list of past scans.
- A side-by-side view of the recommendation with and without the verifier.
- An evidence cut-off date picker for demonstrations.

### Database

Not needed at first: each run is written once to its own folder under `runtime/runs/`. If a scan history is
needed later, use **SQLite** for scan records only. **Never move the evidence store into a database**; it is a
set of frozen files with SHA-256 hashes, and the research results depend on it staying unchanged.

## 6. Rules

1. **Uploads are untrusted.** Never execute, import or install an uploaded file, and never run install or
   lifecycle scripts. Pass the bytes to `UploadedFile` only. Limit the upload size and accept only the four
   manifest types.
2. **Store uploads and runs only under `runtime/`** (git-ignored). Never commit them.
3. **Do not change Agents 1, 2, 3 or 5**, the Agent 3 v1 baseline
   (`src/multi_agentic_security/agents/agent3_risk/baseline_v1/`) or
   `docs/research/EVALUATION_PROTOCOL.md`. If you find a bug in an agent, write a failing test and report it
   first.
4. **Tests never use the network.** Use the fixtures and recorded responses.
5. **No secrets in the repository.** No API keys are needed; if any are added later, keep them in a git-ignored
   `.env`.
6. **The live registry is off by default.** Do not add live registry lookups without agreeing on it first.
7. **Work on a branch and open a pull request** to `main`; `main` needs one approving review.

## 7. Done when

- [ ] A user can upload a manifest in the browser and see the report with one tab per agent and its reasons.
- [ ] Failures and withheld recommendations are shown clearly.
- [ ] `python -m pytest -q` still passes, including new API tests that run offline.
- [ ] No file in `src/multi_agentic_security/agents/` was changed.
- [ ] `README.md` has a short "Run the web interface" section.
