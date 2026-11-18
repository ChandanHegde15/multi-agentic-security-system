"""Evaluation harness end to end on tests/fixtures/agent2 (D-067): cases -> real pipeline -> scorer
-> metrics for C1-C5, with hand-written cases whose true answers are known. No network."""

import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent2_registry import SnapshotRegistryClient
from multi_agentic_security.agents.agent4_recommendation import LLMResponse, MemoryResponseStore
from multi_agentic_security.contracts.evidence import LabelFamily
from multi_agentic_security.evaluation import Case, EvalEnv, run_evaluation, write_result
from multi_agentic_security.evidence_store import EvidenceStore

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "agent2"
T0 = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def case(family, eco, name, decl, **kw):
    cid = f"case-{family[:4]}-{name.replace('@', '').replace('/', '')[:10]}"
    return Case(case_id=cid, family=family, ecosystem=eco, name=name, declaration=decl, group=name,
                label_source="hand-written fixture", **kw)


CASES = [
    case("malicious", "npm", "evil-pkg", "evil-pkg@1.0.0"),
    case("vulnerable", "pypi", "requests", "requests==2.31.0"),
    case("typosquat", "npm", "strign-width", "strign-width@1.0.0", expected_target="string-width"),
    case("nonexistent", "pypi", "reqeusts-hallucinated", "reqeusts-hallucinated"),
    case("benign_reference", "pypi", "pyyaml", "PyYAML>=6"),
]


class Always:
    provider, model = "fake", "keep-1"

    def generate(self, request):
        return LLMResponse(text='{"action": "keep", "claims": []}')


def env(**kw):
    return EvalEnv(evidence_store=EvidenceStore.load(FIX / "evidence" / "v1"),
                   registry_client=SnapshotRegistryClient(FIX / "registry_snapshot"), clock=lambda: T0, **kw)


def test_r0_conditions_c1_and_c5_on_known_cases():
    res = run_evaluation(CASES, env(), ["R0"], n_boot=50)
    assert res.errors == [] and {r.condition for r in res.rows} == {"C1", "C5"} and len(res.rows) == 10
    by = {(r.condition, r.case.name): r for r in res.rows}
    assert by[("C1", "evil-pkg")].score.action == "remove" and by[("C1", "evil-pkg")].score.unsafe["U-K"] is False
    assert by[("C1", "requests")].score.action == "upgrade" and by[("C1", "requests")].score.target.version == "2.32.3"
    assert by[("C1", "requests")].score.unsafe["U-V"] is False
    ts = by[("C1", "strign-width")].score
    assert ts.action == "replace" and ts.target_agreement is True and ts.target.kind == "ok"
    assert by[("C1", "reqeusts-hallucinated")].score.action == "remove"
    assert all(r.score.n_unsupported == 0 for r in res.rows), "R0's claims must all be supported under full evidence"
    for fam, block in res.metrics["C1"].items():
        assert block["unsafe"]["any"]["k"] == 0, fam
    assert res.metrics["C5"]["malicious"]["shown"] == 1 and res.metrics["C5"]["malicious"]["verifier"]["verdicts"] == {"accept": 1}


def test_llm_that_always_keeps_is_unsafe_and_the_verifier_removes_it():
    e = env(llms={"LLM-G": Always()}, response_store=MemoryResponseStore())
    res = run_evaluation(CASES, e, ["R0", "LLM-G"], n_boot=50)
    c3, c4 = res.metrics["C3"], res.metrics["C4"]
    assert c3["malicious"]["unsafe"]["U-K"]["k"] == 1                      # keep on a reported-malicious package
    assert c3["typosquat"]["unsafe"]["U-K"]["k"] == 1 and c3["vulnerable"]["unsafe"]["U-K"]["k"] == 1
    assert c4["malicious"]["shown"] == 0 and c4["malicious"]["verifier"]["unsafe_removed"] == 1
    assert c4["vulnerable"]["verifier"]["unsafe_kept"] == 0
    # the verifier never counts a withheld recommendation as covered
    assert c4["malicious"]["coverage"]["k"] == 0 and c3["malicious"]["coverage"]["k"] == 1
    assert c3["benign_reference"]["unsafe"]["U-K"]["k"] == 0


def test_a_case_the_pipeline_cannot_read_is_reported_not_dropped():
    bad = case("vulnerable", "pypi", "weird", "# only a comment, no dependency")
    res = run_evaluation(CASES[:1] + [bad], env(), ["R0"], n_boot=10)
    assert len(res.errors) == 1 and res.errors[0]["case_id"] == bad.case_id
    assert res.protocol["errors"] == 1 and res.protocol["cases"] == 2


def test_results_are_written_once_with_hashes(tmp_path):
    res = run_evaluation(CASES[:2], env(), ["R0"], n_boot=10)
    hashes = write_result(tmp_path / "out", res)
    assert set(hashes) == {"rows.jsonl", "errors.json", "metrics.json", "protocol.json"}
    assert json.loads((tmp_path / "out" / "protocol.json").read_text())["store"]["complete"] is True
    with pytest.raises(FileExistsError):
        write_result(tmp_path / "out", res)
    again = run_evaluation(CASES[:2], env(), ["R0"], n_boot=10)
    write_result(tmp_path / "out2", again)
    assert (tmp_path / "out" / "rows.jsonl").read_text() == (tmp_path / "out2" / "rows.jsonl").read_text()


def test_llm_variant_without_a_client_is_a_configuration_error():
    with pytest.raises(ValueError):
        run_evaluation(CASES[:1], env(), ["LLM-G"])
