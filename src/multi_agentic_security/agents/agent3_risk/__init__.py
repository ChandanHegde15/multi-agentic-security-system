"""Agent 3: risk findings (pipeline/0.2 ``RiskResult``).

``baseline_v1`` is the frozen legacy baseline (D-004), called unchanged through
``v1_adapter``. v2 (D-020, D-055) reports one version-aware finding per label
family with evidence IDs and reasons, and no combined score.
"""

from .assess import FINDINGS_VERSION, STAGE_VERSION, assess

__all__ = ["FINDINGS_VERSION", "STAGE_VERSION", "assess"]
