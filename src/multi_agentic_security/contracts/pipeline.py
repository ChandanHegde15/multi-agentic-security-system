"""Pipeline contracts between the five agents, version ``pipeline/0.1``.

Every stage consumes the validated output of the previous stage; nothing is
passed as free text. Every decision carries ``reasons`` (rule, inputs,
evidence IDs, plain-language explanation) so each dashboard can show why a
result was produced (D-047). Label families are never merged (D-012).

Stage outputs:
    Agent 1  ExtractionResult       dependency records
    Agent 2  RegistryResult         registry verification per dependency
    Agent 3  RiskResult             v1 baseline score + v2 findings per dependency
    Agent 4  RecommendationResult   one structured recommendation per dependency
    Agent 5  VerificationResult     verdict per recommendation
             PipelineReport         everything above plus a summary
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from multi_agentic_security.datasets.names import normalize_name

CONTRACT_VERSION = "pipeline/0.1"

Ecosystem = Literal["pypi", "npm"]
Stage = Literal["intake", "agent1", "agent2", "agent3", "agent4", "agent5", "pipeline"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------- shared

class Reason(Contract):
    """One explainable step of a decision."""

    rule_id: str = Field(min_length=1, description="Stable identifier of the rule that fired, e.g. 'a2.status.not_found'")
    outcome: str = Field(min_length=1, description="What the rule decided")
    explanation: str = Field(min_length=1, description="Plain-language reason shown on the dashboard")
    inputs: dict[str, Any] = Field(default_factory=dict, description="Values the rule looked at")
    evidence_ids: list[str] = Field(default_factory=list)


class Failure(Contract):
    stage: Stage
    code: str = Field(min_length=1)
    detail: str = ""
    dependency_id: Optional[str] = None
    source_path: Optional[str] = None


class PackageRef(Contract):
    ecosystem: Ecosystem
    name_raw: str = Field(min_length=1)
    name_normalized: str = Field(min_length=1)

    @model_validator(mode="after")
    def _check_normalized(self) -> "PackageRef":
        expected = normalize_name(self.ecosystem, self.name_raw)
        if self.name_normalized != expected:
            raise ValueError(f"name_normalized {self.name_normalized!r} != normalize({self.name_raw!r}) = {expected!r}")
        return self

    @classmethod
    def of(cls, ecosystem: str, name_raw: str) -> "PackageRef":
        return cls(ecosystem=ecosystem, name_raw=name_raw.strip(), name_normalized=normalize_name(ecosystem, name_raw))


class StageHeader(Contract):
    contract_version: Literal["pipeline/0.1"] = CONTRACT_VERSION
    project_id: str = Field(min_length=1)
    stage_version: str = Field(min_length=1, description="Version of the agent implementation that produced this output")
    started_at: datetime
    finished_at: datetime

    @model_validator(mode="after")
    def _check_times(self) -> "StageHeader":
        for t in (self.started_at, self.finished_at):
            if t.tzinfo is None:
                raise ValueError("timestamps must be timezone-aware")
        if self.finished_at < self.started_at:
            raise ValueError("finished_at is before started_at")
        return self


def make_dependency_id(source_path: str, source_line: Optional[int], ecosystem: Optional[str], declaration: str) -> str:
    """Stable ID: the same declaration in the same place always gets the same ID."""
    parts = (source_path.replace("\\", "/"), str(source_line or 0), ecosystem or "", declaration.strip())
    return "dep-" + hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------- Agent 1

SourceKind = Literal[
    "requirements_txt", "package_json", "package_lock_json", "python_code", "javascript_code",
    "install_command_text", "archive", "directory", "git_repository",
]
DependencyType = Literal["runtime", "dev", "optional", "peer", "import", "install_command"]
Origin = Literal["registry", "vcs", "url", "path", "unknown"]
ExtractionStatus = Literal["ok", "warning", "unresolved"]


class InputSource(Contract):
    kind: SourceKind
    locator: str = Field(min_length=1, description="Path inside the upload, or the repository URL")
    sha256: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    size_bytes: Optional[int] = Field(default=None, ge=0)


class DependencyRecord(Contract):
    dependency_id: str = Field(pattern=r"^dep-[0-9a-f]{16}$")
    ecosystem: Optional[Ecosystem]
    package: Optional[PackageRef] = Field(description="None when the package could not be determined (e.g. an unmapped import)")
    original_declaration: str = Field(min_length=1)
    version_constraint_raw: Optional[str] = None
    version_constraint_normalized: Optional[str] = None
    dependency_type: DependencyType
    origin: Origin = "registry"
    source_kind: SourceKind
    source_path: str = Field(min_length=1)
    source_line: Optional[int] = Field(default=None, ge=1)
    extraction_status: ExtractionStatus
    warnings: list[str] = Field(default_factory=list)
    reasons: list[Reason] = Field(min_length=1)

    @model_validator(mode="after")
    def _check(self) -> "DependencyRecord":
        if self.package is not None and self.ecosystem != self.package.ecosystem:
            raise ValueError("ecosystem must match package.ecosystem")
        if self.package is None and self.extraction_status != "unresolved":
            raise ValueError("a record without a package must be 'unresolved'")
        if self.extraction_status == "warning" and not self.warnings:
            raise ValueError("status 'warning' needs at least one warning")
        return self


class ExtractionResult(StageHeader):
    sources: list[InputSource]
    dependencies: list[DependencyRecord]
    failures: list[Failure] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> "ExtractionResult":
        ids = [d.dependency_id for d in self.dependencies]
        if len(ids) != len(set(ids)):
            raise ValueError("dependency_id values must be unique")
        return self


# --------------------------------------------------------------------------- Agent 2

RegistryStatus = Literal["found", "not_found", "security_placeholder", "lookup_error", "invalid_response", "not_checked"]
RegistryMode = Literal["live", "snapshot", "off"]


class RegistryVerification(Contract):
    dependency_id: str
    registry: Optional[Literal["pypi", "npm"]]
    status: RegistryStatus
    canonical_name: Optional[str] = None
    versions: Optional[list[str]] = None
    latest_version: Optional[str] = None
    version_upload_times: Optional[dict[str, Optional[datetime]]] = None
    metadata: dict[str, Any] = Field(default_factory=dict, description="Selected registry fields (summary, homepage, licence, ...)")
    source_url: Optional[str] = None
    retrieved_at: Optional[datetime] = None
    error: Optional[str] = None
    evidence_ids: list[str] = Field(default_factory=list)
    reasons: list[Reason] = Field(min_length=1)

    @model_validator(mode="after")
    def _check(self) -> "RegistryVerification":
        looked_up = self.status in ("found", "not_found", "security_placeholder", "lookup_error", "invalid_response")
        if looked_up and self.retrieved_at is None:
            raise ValueError(f"status {self.status!r} requires retrieved_at")
        if self.retrieved_at is not None and self.retrieved_at.tzinfo is None:
            raise ValueError("retrieved_at must be timezone-aware")
        if self.status in ("lookup_error", "invalid_response") and not self.error:
            raise ValueError(f"status {self.status!r} requires an error message")
        if self.status != "found" and self.versions:
            raise ValueError("versions are only reported for status 'found'")
        return self


class RegistryResult(StageHeader):
    registry_mode: RegistryMode
    evidence_cutoff: Optional[datetime] = None
    results: list[RegistryVerification]
    failures: list[Failure] = Field(default_factory=list)


# --------------------------------------------------------------------------- Agent 3

FindingType = Literal[
    "nonexistent", "typosquat_listed", "name_similar_to_popular", "malicious_reported",
    "compromised_version", "vulnerable", "withdrawn_only", "no_evidence", "unknown",
]


class BaselineV1Score(Contract):
    """Output of the frozen Agent 3 v1 baseline, unchanged, labelled as baseline."""

    policy_version: Literal["agent3/v1"] = "agent3/v1"
    registry_status_v1: Optional[str]
    risk_score: Optional[int] = Field(ge=0, le=100)
    risk_level: Literal["low", "medium", "high", "critical", "unknown"]
    signals: list[dict[str, Any]]
    catalogue_version: str


class Finding(Contract):
    finding: FindingType
    evidence_ids: list[str] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)
    reasons: list[Reason] = Field(min_length=1)

    @model_validator(mode="after")
    def _evidence_needed(self) -> "Finding":
        evidence_backed = ("typosquat_listed", "malicious_reported", "compromised_version", "vulnerable", "withdrawn_only")
        if self.finding in evidence_backed and not self.evidence_ids:
            raise ValueError(f"finding {self.finding!r} must cite evidence")
        return self


class RiskAssessment(Contract):
    dependency_id: str
    baseline_v1: Optional[BaselineV1Score]
    findings: list[Finding]
    reference_package: Optional[PackageRef] = Field(default=None, description="Legitimate package this one may imitate, when justified by evidence")
    findings_version: str
    reasons: list[Reason] = Field(min_length=1)


class RiskResult(StageHeader):
    assessments: list[RiskAssessment]
    failures: list[Failure] = Field(default_factory=list)


# --------------------------------------------------------------------------- Agent 4

Action = Literal["remove", "replace", "upgrade", "downgrade", "keep", "investigate", "abstain"]
TARGET_ACTIONS = frozenset({"replace", "upgrade", "downgrade"})
ClaimType = Literal[
    "is_reported_malicious", "is_compromised_version", "is_typosquat_of", "is_nonexistent",
    "is_vulnerable", "fixed_in", "report_withdrawn", "no_evidence_found",
]
GenerationStatus = Literal["ok", "schema_violation", "llm_error", "llm_timeout", "refusal"]


class Target(Contract):
    package: PackageRef
    version: Optional[str] = None


class Claim(Contract):
    type: ClaimType
    subject: PackageRef
    object: Optional[str] = None
    evidence_ids: list[str] = Field(default_factory=list)


class Recommendation(Contract):
    dependency_id: str
    action: Action
    target: Optional[Target] = None
    claims: list[Claim] = Field(default_factory=list)
    rationale: Optional[str] = Field(default=None, description="Free text for the reader; never scored as fact")
    uncertainty: Optional[str] = None
    backend: Literal["rules", "llm", "audit_tool"]
    model: Optional[str] = None
    prompt_version: Optional[str] = None
    generation_status: GenerationStatus = "ok"
    failure: Optional[Failure] = None
    raw_response_ref: Optional[str] = None
    reasons: list[Reason] = Field(min_length=1)

    @model_validator(mode="after")
    def _check(self) -> "Recommendation":
        if self.action in TARGET_ACTIONS and self.target is None:
            raise ValueError(f"action {self.action!r} needs a target")
        if self.action not in TARGET_ACTIONS and self.target is not None:
            raise ValueError(f"action {self.action!r} takes no target")
        if self.action in ("upgrade", "downgrade") and self.target is not None and not self.target.version:
            raise ValueError(f"action {self.action!r} needs a target version")
        if self.backend == "llm" and not self.model:
            raise ValueError("an LLM recommendation must record its model")
        if self.generation_status != "ok" and self.action != "abstain":
            raise ValueError("a failed generation can only yield 'abstain'")
        return self


class RecommendationResult(StageHeader):
    recommendations: list[Recommendation]
    failures: list[Failure] = Field(default_factory=list)


# --------------------------------------------------------------------------- Agent 5

CheckName = Literal[
    "schema", "dependency_identity", "action_allowed", "claims_supported", "target_exists",
    "target_not_malicious", "target_not_typosquat", "target_version_not_vulnerable",
    "replacement_matches_reference", "action_consistent",
]
CheckOutcome = Literal["pass", "fail", "not_run", "not_applicable"]
Verdict = Literal["accept", "reject", "abstain"]
VERDICT_LABEL = {"accept": "verified", "reject": "rejected", "abstain": "needs review"}


class CheckResult(Contract):
    check: CheckName
    result: CheckOutcome
    required: bool = True
    evidence_ids: list[str] = Field(default_factory=list)
    detail: str = ""


def verdict_from_checks(checks: list[CheckResult]) -> Verdict:
    """Any fail -> reject; any required not_run -> abstain; otherwise accept."""
    if any(c.result == "fail" for c in checks):
        return "reject"
    if not checks or any(c.required and c.result == "not_run" for c in checks):
        return "abstain"
    return "accept"


class RecommendationVerification(Contract):
    dependency_id: str
    verdict: Verdict
    checks: list[CheckResult] = Field(min_length=1)
    verifier_version: str
    reasons: list[Reason] = Field(min_length=1)

    @property
    def label(self) -> str:
        return VERDICT_LABEL[self.verdict]

    @model_validator(mode="after")
    def _consistent(self) -> "RecommendationVerification":
        names = [c.check for c in self.checks]
        if len(names) != len(set(names)):
            raise ValueError("each check may appear once")
        expected = verdict_from_checks(self.checks)
        if self.verdict != expected:
            raise ValueError(f"verdict {self.verdict!r} contradicts the checks (expected {expected!r})")
        return self


class VerificationResult(StageHeader):
    verifications: list[RecommendationVerification]
    failures: list[Failure] = Field(default_factory=list)


# --------------------------------------------------------------------------- report

class PipelineSummary(Contract):
    total_dependencies: int = Field(ge=0)
    by_ecosystem: dict[str, int]
    registry_status_counts: dict[str, int]
    finding_counts: dict[str, int]
    baseline_level_counts: dict[str, int]
    action_counts: dict[str, int]
    verdict_counts: dict[str, int]
    failures: int = Field(ge=0)


class PipelineReport(Contract):
    contract_version: Literal["pipeline/0.1"] = CONTRACT_VERSION
    project_id: str
    created_at: datetime
    extraction: ExtractionResult
    registry: Optional[RegistryResult] = None
    risk: Optional[RiskResult] = None
    recommendations: Optional[RecommendationResult] = None
    verification: Optional[VerificationResult] = None
    summary: PipelineSummary

    @model_validator(mode="after")
    def _trace(self) -> "PipelineReport":
        """Every later stage may only refer to dependency IDs produced by Agent 1."""
        known = {d.dependency_id for d in self.extraction.dependencies}
        stages = {
            "registry": [r.dependency_id for r in self.registry.results] if self.registry else [],
            "risk": [a.dependency_id for a in self.risk.assessments] if self.risk else [],
            "recommendations": [r.dependency_id for r in self.recommendations.recommendations] if self.recommendations else [],
            "verification": [v.dependency_id for v in self.verification.verifications] if self.verification else [],
        }
        for name, ids in stages.items():
            unknown = set(ids) - known
            if unknown:
                raise ValueError(f"{name} refers to unknown dependency IDs: {sorted(unknown)[:3]}")
        for stage in (self.extraction, self.registry, self.risk, self.recommendations, self.verification):
            if stage is not None and stage.project_id != self.project_id:
                raise ValueError("all stages must belong to the same project_id")
        return self


ALL_CONTRACTS = {
    "ExtractionResult": ExtractionResult,
    "RegistryResult": RegistryResult,
    "RiskResult": RiskResult,
    "RecommendationResult": RecommendationResult,
    "VerificationResult": VerificationResult,
    "PipelineReport": PipelineReport,
}


def json_schemas() -> dict[str, dict]:
    """JSON Schemas for every stage output (for the API and the dashboards)."""
    return {name: model.model_json_schema() for name, model in ALL_CONTRACTS.items()}
