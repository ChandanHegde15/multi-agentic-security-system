"""Read-only, in-memory index over the normalized evidence tables (evidence/1.1).

Shared by Agent 2 (name lookup), Agent 3 (version applicability) and Agent 5
(independent re-checks), so none of them has to import another agent.
"""

from .index import (
    CURRENT_TABLES, STORE_VERSION, EvidenceMatch, EvidenceStore, QueryResult, StoreFailure, TableInfo, TableSpec,
)

__all__ = ["CURRENT_TABLES", "STORE_VERSION", "EvidenceMatch", "EvidenceStore", "QueryResult", "StoreFailure",
           "TableInfo", "TableSpec"]
