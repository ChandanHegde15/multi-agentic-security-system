"""Held-out runner (D-095) offline on tests/fixtures/agent2: freeze gate, case hashes, resume, locks, the daily
ledger, spacing and image checks, target listing and the cache-only replay check. Fake clients only; no network."""

import json
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent2_registry import SnapshotRegistryClient
from multi_agentic_security.agents.agent4_recommendation import LLMError, LLMResponse, LLMTimeout
from multi_agentic_security.evaluation import Case, write_cases
from multi_agentic_security.evaluation import heldout as H
from multi_agentic_security.evidence_store import EvidenceStore
from multi_agentic_security.pipeline import MultiSnapshotClient

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "agent2"
T0 = datetime(2026, 11, 30, 10, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def case(family, eco, name, decl, **kw):
    return Case(case_id=f"case-{family[:4]}-{name[:10]}", family=family, ecosystem=eco, name=name, declaration=decl,
                group=name, label_source="hand-written fixture", **kw)


CASES = [
    case("malicious", "npm", "evil-pkg", "evil-pkg@1.0.0"),
    case("vulnerable", "pypi", "requests", "requests==2.31.0"),
    case("typosquat", "npm", "strign-width", "strign-width@1.0.0", expected_target="string-width"),
    case("benign_reference", "pypi", "pyyaml", "PyYAML>=6"),
]
KEEP = '{"action": "keep", "claims": []}'


class Fake:
    """A stand-in for a real client: fixed answers per package name, optional failures, counted calls."""

    def __init__(self, provider="ollama", model="llama3.2:3b", answers=None, fail=(), spacing=12.0, cut_first=False, slow=()):
        self.provider, self.model, self._min_interval = provider, model, spacing
        self.answers, self.fail, self.cut_first, self.calls = answers or {}, set(fail), cut_first, 0
        self.slow = set(slow)

    def generate(self, request):
        self.calls += 1
        text = request.messages[0][1]
        for name in self.fail:
            if f'"package": "{name}"' in text:
                raise LLMError(code="http_503")
        for name in self.slow:
            if f'"package": "{name}"' in text:
                raise LLMTimeout(code="timeout")
        if self.cut_first and len(request.messages) == 1:
            return LLMResponse(text="", stop_reason="length")
        for name, answer in self.answers.items():
            if f'"package": "{name}"' in text:
                return LLMResponse(text=answer)
        return LLMResponse(text=KEEP)


def jobs_for(cases_file, sha):
    return [
        {"job_id": "S0__ollama__llama3.2_3b", "setting": "S0", "provider": "ollama", "model": "llama3.2:3b",
         "prompt_version": "a4-prompt/0.2", "cases_file": cases_file, "cases_sha256": sha, "image_id": "a80c4f17acd5"},
        {"job_id": "S0__groq__gpt-oss", "setting": "S0", "provider": "groq", "model": "openai/gpt-oss-20b",
         "prompt_version": "a4-prompt/0.2", "cases_file": cases_file, "cases_sha256": sha},
        {"job_id": "S1__ollama__llama3.2_3b", "setting": "S1", "provider": "ollama", "model": "llama3.2:3b",
         "prompt_version": "a4-prompt/0.2", "cases_file": cases_file, "cases_sha256": sha, "cutoff": "2026-01-01",
         "image_id": "a80c4f17acd5"},
    ]


@pytest.fixture
def world(tmp_path):
    sha = write_cases(tmp_path / "cases" / "test.jsonl", CASES)
    (tmp_path / "PROTOCOL.md").write_text("# frozen protocol (fixture)\n", encoding="utf-8")
    plan = {"format": H.PLAN_FORMAT, "protocol": "PROTOCOL.md", "evidence_store": str(FIX / "evidence" / "v1"),
            "snapshot_folders": [str(FIX / "registry_snapshot")], "out_root": "out", "cache_root": "cache",
            "results_root": "results", "ledger_dir": "ledgers", "max_output_tokens": 2048,
            "excluded_case_ids": ["case-beni-pyyaml"], "jobs": jobs_for("cases/test.jsonl", sha)}
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    freeze = tmp_path / "FREEZE_RECORD.json"
    freeze.write_text(json.dumps({"format": H.FREEZE_FORMAT, "status": "frozen",
                                  "protocol_sha256": H.sha256_text(tmp_path / "PROTOCOL.md"),
                                  "plan_sha256": H.sha256_text(plan_path)}), encoding="utf-8")
    p = H.load_plan(plan_path, tmp_path)
    return {"root": tmp_path, "plan": p, "plan_path": plan_path, "freeze": freeze,
            "store": EvidenceStore.load(FIX / "evidence" / "v1"),
            "client": MultiSnapshotClient([FIX / "registry_snapshot"])}


def gen(w, job_id="S0__ollama__llama3.2_3b", llm=None, **kw):
    kw.setdefault("utc_now", lambda: T0)
    if job_id.split("__")[1] == "ollama":
        kw.setdefault("image_id", "a80c4f17acd5f00d")
    return H.generate(w["plan"], w["plan"].job(job_id), llm=llm or Fake(), store=w["store"],
                      registry_client=w["client"], log=lambda s: None, **kw)


# --------------------------------------------------------------------------- gates

def test_the_freeze_gate_refuses_a_missing_record_and_any_changed_file(world):
    w = world
    assert H.check_frozen(w["plan_path"], w["plan"], w["freeze"])["status"] == "frozen"
    with pytest.raises(H.RunnerError, match="not frozen"):
        H.check_frozen(w["plan_path"], w["plan"], w["root"] / "nope.json")
    (w["root"] / "PROTOCOL.md").write_text("# edited after the freeze\n", encoding="utf-8")
    with pytest.raises(H.RunnerError, match="protocol differs"):
        H.check_frozen(w["plan_path"], w["plan"], w["freeze"])


def test_line_ending_conversion_does_not_break_the_freeze(world):
    proto = world["root"] / "PROTOCOL.md"
    proto.write_bytes(proto.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))     # what a CRLF checkout does
    assert b"\r\n" in proto.read_bytes()
    assert H.check_frozen(world["plan_path"], world["plan"], world["freeze"])["status"] == "frozen"


def test_the_freeze_gate_refuses_a_changed_plan(world):
    w = world
    w["plan_path"].write_text(w["plan_path"].read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(H.RunnerError, match="plan differs"):
        H.check_frozen(w["plan_path"], w["plan"], w["freeze"])


def test_a_changed_case_file_is_refused(world):
    with open(world["root"] / "cases" / "test.jsonl", "a", encoding="utf-8") as fh:
        fh.write("\n")
    with pytest.raises(H.RunnerError, match="case file hash"):
        gen(world)


@pytest.mark.parametrize("bad", [{"setting": "S0", "cutoff": "2025-09-01"}, {"setting": "S1", "cutoff": None},
                                 {"provider": "ollama", "image_id": None}, {"setting": "S9"}])
def test_job_definitions_are_validated(bad):
    base = {"job_id": "j", "setting": "S0", "provider": "groq", "model": "m", "prompt_version": "a4-prompt/0.2",
            "cases_file": "c", "cases_sha256": "0" * 64}
    with pytest.raises(H.RunnerError):
        H.Job(**{**base, **bad})


def test_live_registry_clients_and_wrong_models_are_refused(world):
    class Live:
        mode = "live"
    with pytest.raises(H.RunnerError, match="snapshot client"):
        H.generate(world["plan"], world["plan"].job("S0__ollama__llama3.2_3b"), llm=Fake(), store=world["store"],
                   registry_client=Live(), image_id="a80c4f17acd5", log=lambda s: None)
    with pytest.raises(H.RunnerError, match="not the job's model"):
        gen(world, llm=Fake(model="qwen2.5:3b"))
    with pytest.raises(H.RunnerError, match="planned image"):
        gen(world, image_id="845dbda0ea48")
    with pytest.raises(H.RunnerError, match="planned image"):
        gen(world, image_id=None)


# --------------------------------------------------------------------------- local generation, resume, lock

def test_local_generation_resumes_without_new_calls(world):
    fake = Fake()
    s = gen(world, llm=fake)
    assert s["complete"] and s["ok_pairs"] == 8 and s["generated"] == 8 and fake.calls == 8
    again = Fake()
    s2 = gen(world, llm=again)
    assert s2["generated"] == 0 and again.calls == 0 and s2["already_ok"] == 8
    lines = (world["root"] / "out" / "S0__ollama__llama3.2_3b" / "generations.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 8 and all(json.loads(l)["prompt_version"].startswith("a4-prompt/0.2") for l in lines)


def test_failed_generations_are_states_and_are_retried_on_the_next_run(world):
    s = gen(world, llm=Fake(fail={"evil-pkg"}))
    assert s["failed_pairs"] == 2 and s["ok_pairs"] == 6 and s["complete"]
    fixed = Fake()
    s2 = gen(world, llm=fixed)
    assert s2["generated"] == 2 and fixed.calls == 2 and s2["failed_pairs"] == 0


def test_a_redo_regenerates_exactly_the_named_pairs_and_records_why(world):
    """D-102: a pair whose recorded request cannot be reproduced is regenerated on purpose, nothing else."""
    gen(world, llm=Fake(fail={"evil-pkg"}))                          # 2 failed pairs stay failed below
    lines_path = world["root"] / "out" / "S0__ollama__llama3.2_3b" / "generations.jsonl"
    before = lines_path.read_text(encoding="utf-8").splitlines()
    pair = (json.loads(before[0])["case_id"], json.loads(before[0])["variant"])
    with pytest.raises(H.RunnerError):
        gen(world, redo=[pair])                                        # no reason
    with pytest.raises(H.RunnerError):
        gen(world, redo=[("case-nope", "LLM-G")], redo_reason="x")    # not in the job
    fake = Fake(fail={"evil-pkg"})
    s = gen(world, llm=fake, redo=[pair], redo_reason="D-102 test")
    after = lines_path.read_text(encoding="utf-8").splitlines()
    assert s["generated"] == 1 and len(after) == len(before) + 1 and after[:len(before)] == before
    assert json.loads(after[-1])["redo_reason"] == "D-102 test" and s["failed_pairs"] == 2


def test_only_one_gpu_job_runs_at_a_time(world):
    with H.lock_for(world["plan"], world["plan"].job("S1__ollama__llama3.2_3b")):
        with pytest.raises(H.RunnerError, match="gpu.lock is held"):
            gen(world)
    assert gen(world)["complete"], "the lock is released when the holder ends"


# --------------------------------------------------------------------------- hosted: ledger, spacing, UTC day

def hosted(**kw):
    return Fake(provider="groq", model="openai/gpt-oss-20b", **kw)


def test_hosted_jobs_need_the_ledger_and_12_s_spacing(world):
    with pytest.raises(H.RunnerError, match="ledger"):
        gen(world, "S0__groq__gpt-oss", llm=hosted())
    with pytest.raises(H.RunnerError, match="spacing"):
        gen(world, "S0__groq__gpt-oss", llm=hosted(spacing=2.5), ledger=H.Ledger(world["root"] / "ledgers", "openai/gpt-oss-20b"))


def test_the_shared_daily_ledger_caps_real_calls(world):
    ledger = H.Ledger(world["root"] / "ledgers", "openai/gpt-oss-20b")
    day = T0.date().isoformat()
    ledger.add(day, 146)                                   # another run used 146 calls today
    fake = hosted()
    s = gen(world, "S0__groq__gpt-oss", llm=fake, ledger=ledger)
    assert s["stopped"] == "daily_cap" and fake.calls == 0 and ledger.used(day) == 146
    nxt = T0 + timedelta(days=1)
    fake2 = hosted()
    s2 = gen(world, "S0__groq__gpt-oss", llm=fake2, ledger=ledger, utc_now=lambda: nxt)
    assert s2["complete"] and fake2.calls == 8 and ledger.used(nxt.date().isoformat()) == 8
    data = json.loads(ledger.path.read_text(encoding="utf-8"))
    assert data == {"openai/gpt-oss-20b": {day: 146, nxt.date().isoformat(): 8}}


def test_a_run_stops_when_the_utc_day_changes(world):
    times = iter([T0] * 4 + [T0 + timedelta(days=1)] * 100)
    ledger = H.Ledger(world["root"] / "ledgers", "openai/gpt-oss-20b")
    s = gen(world, "S0__groq__gpt-oss", llm=hosted(), ledger=ledger, utc_now=lambda: next(times))
    assert s["stopped"] == "utc_day_changed" and not s["complete"]
    assert ledger.used(T0.date().isoformat()) == s["real_calls"] > 0


# --------------------------------------------------------------------------- targets and score

def test_targets_without_a_snapshot_are_listed(world):
    answers = {"strign-width": '{"action": "replace", "target": {"package": "string-widthh"}, "claims": []}',
               "evil-pkg": '{"action": "replace", "target": {"package": "string-width"}, "claims": []}'}
    gen(world, llm=Fake(answers=answers))
    t = H.missing_targets(world["plan"], world["plan"].job("S0__ollama__llama3.2_3b"), world["client"])
    assert [m["name"] for m in t["missing"]] == ["string-widthh"] and t["distinct_targets"] == 2


def test_score_refuses_an_incomplete_generation_log(world):
    ledger = H.Ledger(world["root"] / "ledgers", "openai/gpt-oss-20b")
    ledger.add(T0.date().isoformat(), 140)
    gen(world, "S0__groq__gpt-oss", llm=hosted(), ledger=ledger)                    # 10 calls left: stops early
    with pytest.raises(H.RunnerError, match="no generation yet"):
        H.score(world["plan"], world["plan"].job("S0__groq__gpt-oss"), store=world["store"],
                registry_client=world["client"], n_boot=20)


def test_score_replays_from_the_cache_and_writes_once(world):
    gen(world, llm=Fake(fail={"evil-pkg"}))                 # 2 recorded failures stay failures on replay
    job = world["plan"].job("S0__ollama__llama3.2_3b")
    out = H.score(world["plan"], job, store=world["store"], registry_client=world["client"], n_boot=20)
    assert out["rows"] == 4 * 5 and out["cache_hits"] == 6
    proto = json.loads((world["root"] / "results" / job.job_id / "protocol.json").read_text(encoding="utf-8"))
    assert proto["runner"] == H.RUNNER_VERSION and proto["excluded_case_ids_in_job"] == ["case-beni-pyyaml"]
    rows = [json.loads(l) for l in (world["root"] / "results" / job.job_id / "rows.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {r["generation_status"] for r in rows if r["case_id"] == "case-mali-evil-pkg" and r["condition"] in ("C2", "C3")} == {"llm_error"}
    with pytest.raises(FileExistsError):
        H.score(world["plan"], job, store=world["store"], registry_client=world["client"], n_boot=20)


def test_a_recorded_timeout_replays_as_a_timeout(world):
    """D-103: errors are never cached, so a cache-only replay used to turn a recorded llm_timeout into llm_error and the
    replay check refused the job. The replay now raises the recorded timeout for that exact request."""
    gen(world, llm=Fake(slow={"evil-pkg"}))
    job = world["plan"].job("S0__ollama__llama3.2_3b")
    out = H.score(world["plan"], job, store=world["store"], registry_client=world["client"], n_boot=20)
    rows = [json.loads(l) for l in (world["root"] / "results" / job.job_id / "rows.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {r["generation_status"] for r in rows if r["case_id"] == "case-mali-evil-pkg" and r["condition"] in ("C2", "C3")} == {"llm_timeout"}
    assert out["cache_hits"] == 6


def test_a_replay_that_differs_from_the_run_writes_nothing(world):
    gen(world)
    victim = sorted((world["root"] / "cache" / "ollama_llama3.2_3b").glob("*.json"))[0]
    victim.unlink()                                          # an answer the replay can no longer see
    job = world["plan"].job("S0__ollama__llama3.2_3b")
    with pytest.raises(H.RunnerError, match="replay differs"):
        H.score(world["plan"], job, store=world["store"], registry_client=world["client"], n_boot=20)
    assert not (world["root"] / "results" / job.job_id).exists()


def test_a_repaired_cut_off_answer_replays_exactly(world):
    """D-094 end to end: empty cut-off first answers, repaired; the replay must agree with the log."""
    gen(world, llm=Fake(cut_first=True))
    out = H.score(world["plan"], world["plan"].job("S0__ollama__llama3.2_3b"), store=world["store"],
                  registry_client=world["client"], n_boot=20)
    assert out["cache_misses"] == 0 and out["cache_hits"] == 16


def test_a_cut_off_job_passes_its_cut_off_to_the_pipeline(world):
    gen(world, "S1__ollama__llama3.2_3b")
    out = H.score(world["plan"], world["plan"].job("S1__ollama__llama3.2_3b"), store=world["store"],
                  registry_client=world["client"], n_boot=20)
    proto = json.loads((world["root"] / "results" / "S1__ollama__llama3.2_3b" / "protocol.json").read_text(encoding="utf-8"))
    assert proto["cutoff"].startswith("2026-01-01") and out["cache_misses"] == 0


def test_score_needs_every_planned_snapshot_folder(world):
    gen(world)
    client = MultiSnapshotClient([FIX / "registry_snapshot", world["root"] / "targets_not_recorded_yet"])
    with pytest.raises(H.RunnerError, match="snapshot folders missing"):
        H.score(world["plan"], world["plan"].job("S0__ollama__llama3.2_3b"), store=world["store"], registry_client=client, n_boot=20)


def test_scoring_waits_for_the_task_c_record_but_generation_does_not(world):
    plan_d = json.loads(world["plan_path"].read_text(encoding="utf-8"))
    plan_d["score_gate"] = "TASK_C_RESULT.json"
    world["plan_path"].write_text(json.dumps(plan_d), encoding="utf-8")
    plan = H.load_plan(world["plan_path"], world["root"])
    job = plan.job("S0__ollama__llama3.2_3b")
    assert H.generate(plan, job, llm=Fake(), store=world["store"], registry_client=world["client"],
                      image_id="a80c4f17acd5", utc_now=lambda: T0, log=lambda s: None)["complete"]
    with pytest.raises(H.RunnerError, match="scoring is closed"):
        H.score(plan, job, store=world["store"], registry_client=world["client"], n_boot=20)
    (world["root"] / "TASK_C_RESULT.json").write_text('{"status": "pilot only"}', encoding="utf-8")
    with pytest.raises(H.RunnerError, match="stays closed"):
        H.score(plan, job, store=world["store"], registry_client=world["client"], n_boot=20)
    (world["root"] / "TASK_C_RESULT.json").write_text('{"status": "done"}', encoding="utf-8")
    H.score(plan, job, store=world["store"], registry_client=world["client"], n_boot=20)
    proto = json.loads((world["root"] / "results" / job.job_id / "protocol.json").read_text(encoding="utf-8"))
    assert proto["score_gate"]["file"] == "TASK_C_RESULT.json"


# --------------------------------------------------------------------------- local image ID

def test_the_local_image_id_is_read_from_the_loopback_server_only():
    seen = []

    def fetch(url):
        seen.append(url)
        return json.dumps({"models": [{"name": "llama3.2:3b", "digest": "a80c4f17acd5abc"}]}).encode()
    assert H.ollama_image_id("llama3.2:3b", fetch=fetch) == "a80c4f17acd5abc" and seen == ["http://127.0.0.1:11434/api/tags"]
    assert H.ollama_image_id("qwen2.5:7b", fetch=fetch) is None
    with pytest.raises(ValueError):
        H.ollama_image_id("llama3.2:3b", base_url="http://example.org:11434", fetch=fetch)


def test_amendment_a1_plan_matches_the_frozen_plan_except_the_case_lists():
    # D-098: the A1 local jobs differ from the frozen local jobs only in their case lists, which are the hosted lists.
    docs = Path(__file__).resolve().parents[2] / "docs" / "research"
    base = json.loads((docs / "heldout_plan.json").read_text(encoding="utf-8"))
    a1 = json.loads((docs / "heldout_plan_A1.json").read_text(encoding="utf-8"))
    assert {k: v for k, v in a1.items() if k not in ("jobs", "decision")} == {k: v for k, v in base.items() if k not in ("jobs", "decision")}
    hosted = {j["setting"]: (j["cases_file"], j["cases_sha256"]) for j in base["jobs"] if j["provider"] == "groq"}
    local = {j["job_id"]: j for j in base["jobs"] if j["provider"] == "ollama"}
    assert len(a1["jobs"]) == len(local) == 9
    for j in a1["jobs"]:
        o = local[j["job_id"].removesuffix("__A1")]
        assert (j["cases_file"], j["cases_sha256"]) == hosted[j["setting"]]
        assert {k: v for k, v in j.items() if k not in ("job_id", "cases_file", "cases_sha256")} == \
               {k: v for k, v in o.items() if k not in ("job_id", "cases_file", "cases_sha256")}
    freeze = json.loads((docs / "PROTOCOL_FREEZE_A1.json").read_text(encoding="utf-8"))
    base_freeze = json.loads((docs / "PROTOCOL_FREEZE.json").read_text(encoding="utf-8"))
    assert freeze["protocol_sha256"] == base_freeze["protocol_sha256"]
    assert freeze["plan_sha256"] == H.sha256_text(docs / "heldout_plan_A1.json")
    # D-101: plan A3 is plan A1 with no score gate, under its own freeze record.
    a3 = json.loads((docs / "heldout_plan_A3.json").read_text(encoding="utf-8"))
    assert a3["score_gate"] is None and {k: v for k, v in a3.items() if k not in ("decision", "score_gate")} ==         {k: v for k, v in a1.items() if k not in ("decision", "score_gate")}
    assert json.loads((docs / "PROTOCOL_FREEZE_A3.json").read_text(encoding="utf-8"))["plan_sha256"] == H.sha256_text(docs / "heldout_plan_A3.json")
