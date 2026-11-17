"""Agent 5: independent deterministic verification of recommendations (D-047 e, D-059).

No LLM, no import from Agent 4, nothing installed or executed. Every check is
re-derived from the evidence store, Agent 2's registry facts for the dependency
and a read-only registry client for the recommended target.
"""

from .verify import ALL_CHECKS, STAGE_VERSION, SWITCHABLE, verify_recommendations

__all__ = ["ALL_CHECKS", "STAGE_VERSION", "SWITCHABLE", "verify_recommendations"]
