"""Input record types accepted by the Agent 3 baseline.

Copied verbatim (fields and serialization) from the legacy Agent 2 module
``agents/registry_verification/models.py`` at commit f3d998b, so the frozen
Agent 3 baseline no longer depends on the removed Agent 2 implementation.
Agent 3 also accepts plain mappings with the same keys.
"""

from dataclasses import asdict, dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class VerificationRecord:
    package_name: Optional[str]
    ecosystem: Optional[str]
    version_constraint: Optional[str]
    source_file: Optional[str]
    exists: Optional[bool]
    status: str
    registry_metadata: Optional[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class VerificationResult:
    project_id: str
    dependencies: tuple[VerificationRecord, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "dependencies": [dependency.to_dict() for dependency in self.dependencies],
        }
