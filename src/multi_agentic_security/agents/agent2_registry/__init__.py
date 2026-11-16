"""Agent 2: registry verification and evidence lookup (pipeline/0.2 ``RegistryResult``, D-053, D-054).

Reports facts without judging them: time-stamped PyPI/npm registry metadata
(modes ``off``, ``snapshot``, ``live``) and the IDs of evidence records whose
package name matches, per label family, with the cut-off rule applied. Version
applicability is decided by Agent 3.
"""

from .client import (
    CLIENT_VERSION, SNAPSHOT_FORMAT, HttpRegistryClient, LookupOutcome, RegistryClient, SnapshotRegistryClient,
    registry_url, valid_registry_name,
)
from .verify import PRIVATE_INDEX_MARKERS, STAGE_VERSION, verify

__all__ = [
    "CLIENT_VERSION", "SNAPSHOT_FORMAT", "HttpRegistryClient", "LookupOutcome", "RegistryClient",
    "SnapshotRegistryClient", "registry_url", "valid_registry_name", "PRIVATE_INDEX_MARKERS", "STAGE_VERSION", "verify",
]
