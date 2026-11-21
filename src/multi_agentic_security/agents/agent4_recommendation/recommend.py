"""Agent 4 entry point: Agent 1-3 outputs -> ``RecommendationResult`` (pipeline/0.2, D-047 d, D-062).

``variant`` is a run parameter:

* ``R0``    - deterministic rules (``rules.py``), backend ``rules``;
* ``LLM-G`` - an LLM given the dependency's evidence records, backend ``llm``;
* ``LLM-U`` - an LLM given finding names only, backend ``llm``.

One recommendation per Agent 1 dependency, in Agent 1's order. Failures are states: an
LLM error, timeout, refusal or an answer that still violates the schema after the
bounded repairs gives ``abstain`` with a ``Failure``; nothing falls back to a default action.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional

from pydantic import ValidationError

from multi_agentic_security.contracts.pipeline import (
    ExtractionResult, Failure, Reason, Recommendation, RecommendationResult, RegistryResult, RiskResult,
)
from multi_agentic_security.evidence_store import EvidenceStore

from . import prompt as P
from .llm import LLMClient, LLMError, LLMOptions, LLMResponse, LLMTimeout, ResponseStore, raw_record
from .packet import GROUNDED, Packet, build_packets
from .parse import Refusal, SchemaViolation, parse_answer
from .rules import RULES_VERSION, decide

STAGE_VERSION = "agent4/0.1"
Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _packet_reason(p: Packet) -> Reason:
    ids = p.evidence_ids
    if p.variant in GROUNDED:
        text = (f"Variant {p.variant}: {len(ids)} evidence record(s) given" +
                ("" if p.evidence_usable else " (the evidence store was missing or not the one Agent 2 used)") + ".")
    else:
        text = "Variant LLM-U: no evidence records given, only the finding names."
    return Reason(rule_id="a4.input.packet", outcome=p.variant, explanation=text, evidence_ids=ids,
                  inputs={"variant": p.variant, "findings": p.finding_names(),
                          "cutoff": p.cutoff_date.isoformat() if p.cutoff_date else None,
                          "evidence_usable": p.evidence_usable})


def _rules_recommendation(p: Packet) -> Recommendation:
    d = decide(p)
    return Recommendation(dependency_id=p.dependency.dependency_id, action=d.action, target=d.target,
                          claims=d.claims, rationale=d.rationale, uncertainty=d.uncertainty, backend="rules",
                          model=None, prompt_version=None, reasons=[_packet_reason(p)] + d.reasons)


def _llm_recommendation(p: Packet, client: LLMClient, store: ResponseStore, options: LLMOptions, clock: Clock,
                        failures: list[Failure]) -> Recommendation:
    dep = p.dependency
    model = f"{client.provider}/{client.model}"
    pv = P.prompt_version(p.variant, options)
    reasons = [_packet_reason(p)]
    if dep.package is None or p.assessment is None:
        # Same inputs as R0's first rule: without a package or an assessment the model is not called (D-063).
        what = "no_package" if dep.package is None else "no_assessment"
        text = ("Agent 1 could not determine a package" if dep.package is None
                else "Agent 3 produced no assessment for this dependency")
        reasons.append(Reason(rule_id=f"a4.llm.{what}", outcome="abstain",
                              explanation=f"{text}; the model was not called."))
        return Recommendation(dependency_id=dep.dependency_id, action="abstain", backend="llm", model=model,
                              prompt_version=pv, reasons=reasons, rationale=f"{text}.")

    request = P.build_request(p, options)
    attempt, transport_fail, schema_fail = 0, 0, 0
    status, detail, ref, fields = "ok", "", None, None
    while True:
        attempt += 1
        key = request.key(client.provider, client.model)
        try:
            resp = client.generate(request)
            if not isinstance(resp, LLMResponse):
                raise LLMError(code="not_an_llm_response")
        except Exception as exc:   # every client failure is a state
            kind = "llm_timeout" if isinstance(exc, LLMTimeout) else "llm_error"
            # Type and validated code only: provider messages may echo keys (D-063).
            msg = type(exc).__name__ + (f" ({exc.code})" if isinstance(exc, LLMError) and exc.code else "")
            ref, store_error = _put(store, raw_record(request, client, attempt, clock(), error=msg))
            if store_error:
                status, detail = "llm_error", store_error
                reasons.append(Reason(rule_id="a4.llm.attempt.llm_error", outcome="llm_error",
                                      explanation=f"Attempt {attempt}: {msg}; {store_error}.",
                                      inputs={"attempt": attempt, "request_key": key}))
                break
            reasons.append(Reason(rule_id=f"a4.llm.attempt.{kind}", outcome=kind, explanation=f"Attempt {attempt}: {msg}.",
                                  inputs={"attempt": attempt, "request_key": key, "raw_response_ref": ref}))
            transport_fail += 1
            if transport_fail > options.max_transport_retries:
                status, detail = kind, msg
                break
            continue
        ref, store_error = _put(store, raw_record(request, client, attempt, clock(), response=resp))
        if store_error:
            # The raw response must be kept by reference; without it the answer is not used (D-063).
            status, detail = "llm_error", store_error
            reasons.append(Reason(rule_id="a4.llm.attempt.llm_error", outcome="llm_error",
                                  explanation=f"Attempt {attempt}: {store_error}; the answer is not used.",
                                  inputs={"attempt": attempt, "request_key": key}))
            break
        base = {"attempt": attempt, "request_key": key, "raw_response_ref": ref, "stop_reason": resp.stop_reason,
                "usage": dict(resp.usage)}
        try:
            if resp.stop_reason == "refusal":
                raise Refusal("the provider reported a refusal")
            fields = parse_answer(resp.text, dep.ecosystem)
            Recommendation(dependency_id=dep.dependency_id, backend="llm", model=model,
                           reasons=reasons, **fields)  # contract rules (target/action) are part of the schema
        except Refusal as exc:
            reasons.append(Reason(rule_id="a4.llm.attempt.refusal", outcome="refusal",
                                  explanation=f"Attempt {attempt}: the model declined ({exc}).", inputs=base))
            status, detail = "refusal", str(exc)
            break
        except (SchemaViolation, ValidationError) as exc:
            msg = str(exc) if isinstance(exc, SchemaViolation) else _contract_error(exc)
            reasons.append(Reason(rule_id="a4.llm.attempt.schema_violation", outcome="schema_violation",
                                  explanation=f"Attempt {attempt}: the answer does not match the schema ({msg}).",
                                  inputs=base))
            schema_fail += 1
            fields = None
            if schema_fail > options.max_schema_retries:
                status, detail = "schema_violation", msg
                break
            request = request.followed_by(resp.text, P.repair_message(msg))
            continue
        reasons.append(Reason(rule_id="a4.llm.attempt.ok", outcome="ok",
                              explanation=f"Attempt {attempt}: a well-formed answer was received.", inputs=base))
        break

    if status != "ok":
        failure = Failure(stage="agent4", code=f"a4.llm.{status}", detail=detail[:300], dependency_id=dep.dependency_id)
        failures.append(failure)
        reasons.append(Reason(rule_id=f"a4.llm.{status}", outcome="abstain",
                              explanation=f"Generation ended with {status} after {attempt} attempt(s) "
                                          f"(limits: {options.max_schema_retries} schema repairs, "
                                          f"{options.max_transport_retries} transport retries); the recommendation "
                                          "abstains instead of using a default action.",
                              inputs={"attempts": attempt, "schema_violations": schema_fail,
                                      "transport_failures": transport_fail}))
        return Recommendation(dependency_id=dep.dependency_id, action="abstain", backend="llm", model=model,
                              prompt_version=pv, generation_status=status, failure=failure, raw_response_ref=ref,
                              reasons=reasons)

    given = set(p.evidence_ids)
    cited = sorted({e for c in fields["claims"] for e in c.evidence_ids})
    not_given = [e for e in cited if e not in given]
    if not_given:
        reasons.append(Reason(rule_id="a4.llm.cited_not_given", outcome="flagged",
                              explanation=f"The answer cites {len(not_given)} evidence ID(s) that were not in the "
                                          "input. They are kept as produced; the verifier and the scorer judge them.",
                              evidence_ids=not_given, inputs={"variant": p.variant}))
    reasons.append(Reason(rule_id="a4.llm.recommendation", outcome=fields["action"],
                          explanation=f"The model recommends {fields['action']!r} with {len(fields['claims'])} "
                                      "claim(s). Its rationale is shown as text and never scored as fact.",
                          evidence_ids=[e for e in cited if e in given],
                          inputs={"attempts": attempt, "claims": [c.type for c in fields["claims"]]}))
    return Recommendation(dependency_id=dep.dependency_id, backend="llm", model=model, prompt_version=pv,
                          generation_status="ok", raw_response_ref=ref, reasons=reasons, **fields)


def _put(store: ResponseStore, record: dict) -> tuple[Optional[str], Optional[str]]:
    """(reference, None) or (None, error text). A store failure is a state, never a crash."""
    try:
        ref = store.put(record)
    except Exception as exc:
        return None, f"the raw response could not be stored ({type(exc).__name__})"
    if not isinstance(ref, str) or not ref:
        return None, "the response store returned no reference"
    return ref, None


def _contract_error(exc: ValidationError) -> str:
    e = exc.errors()[0] if exc.errors() else {}
    return str(e.get("msg", "contract violation"))[:200]


def recommend(extraction: ExtractionResult, registry: RegistryResult, risk: RiskResult, *,
              evidence_store: Optional[EvidenceStore], variant: str = "R0", llm: Optional[LLMClient] = None,
              response_store: Optional[ResponseStore] = None, options: Optional[LLMOptions] = None,
              clock: Clock = _utc_now) -> RecommendationResult:
    """One ``Recommendation`` per Agent 1 dependency, in Agent 1's order.

    ``llm`` and ``response_store`` are required for ``LLM-U`` and ``LLM-G`` (a configuration
    error raises ``ValueError``; failures during the run are states)."""
    started = clock()
    if variant != "R0" and (llm is None or response_store is None):
        raise ValueError(f"variant {variant} needs an LLM client and a response store")
    if variant != "R0" and not (getattr(llm, "provider", None) and getattr(llm, "model", None)):
        raise ValueError("the LLM client must name its provider and exact model")
    options = options or LLMOptions()
    failures: list[Failure] = []
    packets = build_packets(extraction, registry, risk, evidence_store=evidence_store, variant=variant,
                            failures=failures)
    if variant == "R0":
        recs = [_rules_recommendation(p) for p in packets]
        stage = f"{STAGE_VERSION}+{RULES_VERSION}"
    else:
        recs = [_llm_recommendation(p, llm, response_store, options, clock, failures) for p in packets]
        stage = f"{STAGE_VERSION}+{options.prompt_version}"
    return RecommendationResult(project_id=extraction.project_id, stage_version=stage, started_at=started,
                                finished_at=max(clock(), started), recommendations=recs, failures=failures)
