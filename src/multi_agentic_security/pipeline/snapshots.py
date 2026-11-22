"""A read-only registry client over several snapshot folders (PLAN-001 step 4, D-066).

Held-out runs record Agent 2's dependency lookups in one folder and the recommended
targets' lookups in later folders (written once, never edited). Agent 5 reads them
together through this client. If two folders answer for the same package and the
answers differ, the package is a ``lookup_error`` (the snapshots cannot say which is
right), as in a single folder with conflicting recordings. Nothing touches the network.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional, Union

from multi_agentic_security.agents.agent2_registry import LookupOutcome, SnapshotRegistryClient


def _same(a: LookupOutcome, b: LookupOutcome) -> bool:
    return (a.status, a.canonical_name, a.versions, a.latest_version) == (b.status, b.canonical_name, b.versions,
                                                                          b.latest_version)


class MultiSnapshotClient:
    mode = "snapshot"

    def __init__(self, folders: Iterable[Union[str, Path]]):
        self.clients = [SnapshotRegistryClient(f) for f in folders]
        if not self.clients:
            raise ValueError("at least one snapshot folder is needed")
        self.load_failures = [x for c in self.clients for x in c.load_failures]

    def supports(self, ecosystem: str) -> bool:
        return all(c.supports(ecosystem) for c in self.clients)

    def lookup(self, ecosystem: str, name_normalized: str) -> Optional[LookupOutcome]:
        found = [(c, o) for c in self.clients if (o := c.lookup(ecosystem, name_normalized)) is not None]
        if not found:
            return None
        answered = [(c, o) for c, o in found if o.status != "lookup_error"]
        if answered and len(answered) < len(found):
            found = answered          # D-092: a recorded failure (timeout, refused connection) is no answer, not a
                                      # competing one; a folder with an answer supersedes it. Answers still must agree.
        first = found[0][1]
        if len(found) == 1 or all(_same(first, o) for _, o in found[1:]):
            return first
        folders = sorted(str(c.folder.name) for c, _ in found)
        return LookupOutcome(status="lookup_error", rule_id="a2.status.snapshot_conflict",
                             explanation="Several snapshot folders hold different recordings for this package, so they "
                                         "cannot say which one is right.",
                             retrieved_at=max(o.retrieved_at for _, o in found), source_url=first.source_url,
                             error=f"conflicting recordings in folders: {', '.join(folders)}",
                             inputs={"folders": folders})
