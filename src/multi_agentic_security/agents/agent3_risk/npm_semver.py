"""npm version ranges for Agent 3: moved to ``multi_agentic_security.versioning.npm_semver``
so that Agent 5 can share the grammar without importing Agent 3 (D-058). Kept as a re-export."""

from multi_agentic_security.versioning.npm_semver import (  # noqa: F401
    Comparator, parse_version, satisfies, satisfies_evidence_range,
)
