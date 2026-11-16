"""Adapter from Agent 2 (pipeline/0.2) to the frozen Agent 3 v1 baseline (D-004, D-020, D-055).

The v1 code in ``baseline_v1/`` is called unchanged with its default policy and
catalogue. Only its input is built here, from the Agent 1 record and the Agent 2
result, with this status mapping (v1 knows only its legacy statuses):

* ``found``                -> ``verified``
* ``security_placeholder`` -> ``verified``  (a legacy existence check sees a package
                                              that exists; this is the documented v1
                                              blind spot that RQ4 measures)
* ``not_found``            -> ``not_found``
* ``lookup_error``, ``invalid_response`` -> ``registry_error``
* ``not_checked``          -> ``unsupported_ecosystem`` when Agent 2 said so,
                              otherwise ``registry_error`` (no lookup was available)
* no package (unresolved)  -> package name ``None``; v1 itself returns ``invalid_input``

The v1 name is the normalized package name. The v1 output is copied into
``BaselineV1Score`` without reinterpretation.
"""

from __future__ import annotations

from typing import Optional

from multi_agentic_security.contracts.pipeline import BaselineV1Score, DependencyRecord, RegistryVerification

from .baseline_v1 import RiskAnalyzer
from .baseline_v1.reference_packages import DEFAULT_REFERENCE_PACKAGES

ADAPTER_VERSION = "agent3_v1_adapter/1"
CATALOGUE_VERSION = "v1-default:" + ";".join(f"{e}={','.join(p)}" for e, p in sorted(DEFAULT_REFERENCE_PACKAGES.items()))

STATUS_MAP = {
    "found": "verified",
    "security_placeholder": "verified",
    "not_found": "not_found",
    "lookup_error": "registry_error",
    "invalid_response": "registry_error",
}


def v1_status(reg: Optional[RegistryVerification]) -> str:
    if reg is None:
        return "registry_error"
    if reg.status == "not_checked":
        if any(r.rule_id == "a2.not_checked.unsupported_ecosystem" for r in reg.reasons):
            return "unsupported_ecosystem"
        return "registry_error"
    return STATUS_MAP[reg.status]


def v1_input(dep: DependencyRecord, reg: Optional[RegistryVerification]) -> dict:
    status = v1_status(reg)
    return {
        "package_name": dep.package.name_normalized if dep.package else None,
        "ecosystem": dep.ecosystem,
        "version_constraint": dep.version_constraint_raw,
        "source_file": dep.source_path,
        "exists": {"verified": True, "not_found": False}.get(status) if reg is not None else None,
        "status": status,
        "registry_metadata": None,
    }


def run_v1(project_id: str, pairs: list[tuple[DependencyRecord, Optional[RegistryVerification]]]) -> list[BaselineV1Score]:
    """Score all dependencies with the frozen v1 analyzer (one call, order kept)."""
    out = RiskAnalyzer().analyze({"project_id": project_id,
                                  "dependencies": [v1_input(d, r) for d, r in pairs]}).to_dict()
    scores = []
    for (dep, reg), row in zip(pairs, out["dependencies"]):
        scores.append(BaselineV1Score(registry_status_v1=row["registry_status"], risk_score=row["risk_score"],
                                      risk_level=row["risk_level"], signals=row["signals"],
                                      catalogue_version=CATALOGUE_VERSION))
    if len(scores) != len(pairs):
        raise RuntimeError("v1 baseline returned a different number of records")
    return scores
