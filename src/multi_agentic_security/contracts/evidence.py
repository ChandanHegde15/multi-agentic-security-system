"""Evidence record contract, version 1.

One record is one claim made by one source about one package (and, where the
source says so, one version or version range). Records are never merged into a
single row per package, and label families are never merged into one flag
(D-012; RESEARCH_METHODOLOGY.md section 3).

Every record carries its provenance and, where the source gives one, its
publication date, so that the evidence store can answer "what was known before
date T" (RESEARCH_QUESTIONS.md section 6).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any, Optional

from multi_agentic_security.datasets.names import normalize_ecosystem, normalize_name

SCHEMA_VERSION = "evidence/1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class LabelFamily(str, Enum):
    """Separate label families. A record belongs to exactly one."""

    MALICIOUS = "malicious"
    WITHDRAWN = "withdrawn"
    TYPOSQUAT = "typosquat"
    VULNERABLE = "vulnerable"
    NONEXISTENT = "nonexistent"
    BENIGN_REFERENCE = "benign_reference"


class VersionScope(str, Enum):
    """What the source's claim covers."""

    ALL = "all"        # the whole package
    LISTED = "listed"  # one explicitly listed version
    RANGE = "range"    # a version range, kept as the source states it


@dataclass(frozen=True)
class Provenance:
    source_dataset: str
    source_version: str
    source_record_id: str
    source_file: str
    source_file_sha256: str
    license: str
    retrieved_at: datetime
    human_reviewed: bool = False

    def __post_init__(self) -> None:
        for field_name in ("source_dataset", "source_version", "source_record_id", "source_file", "license"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"provenance.{field_name} must be a non-empty string")
        if not _SHA256.match(self.source_file_sha256):
            raise ValueError("provenance.source_file_sha256 must be 64 lower-case hex characters")
        if not isinstance(self.retrieved_at, datetime) or self.retrieved_at.tzinfo is None:
            raise ValueError("provenance.retrieved_at must be a timezone-aware datetime")


@dataclass(frozen=True)
class EvidenceRecord:
    family: LabelFamily
    ecosystem: str
    name_raw: str
    name_normalized: str
    version_scope: VersionScope
    provenance: Provenance
    version: Optional[str] = None
    version_range: Optional[str] = None
    published: Optional[date] = None
    corroborating_sources: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.family, LabelFamily):
            raise ValueError("family must be a LabelFamily")
        if not isinstance(self.version_scope, VersionScope):
            raise ValueError("version_scope must be a VersionScope")
        if self.ecosystem != normalize_ecosystem(self.ecosystem):
            raise ValueError(f"ecosystem must be canonical, got {self.ecosystem!r}")
        expected = normalize_name(self.ecosystem, self.name_raw)
        if self.name_normalized != expected:
            raise ValueError(
                f"name_normalized {self.name_normalized!r} does not match the normalization of "
                f"{self.name_raw!r} ({expected!r})"
            )
        if self.version_scope is VersionScope.ALL and (self.version or self.version_range):
            raise ValueError("version_scope 'all' takes no version and no version_range")
        if self.version_scope is VersionScope.LISTED and (not self.version or self.version_range):
            raise ValueError("version_scope 'listed' needs a version and no version_range")
        if self.version_scope is VersionScope.RANGE and (not self.version_range or self.version):
            raise ValueError("version_scope 'range' needs a version_range and no version")
        if self.published is not None and (
            not isinstance(self.published, date) or isinstance(self.published, datetime)
        ):
            raise ValueError("published must be a date")

    @property
    def evidence_id(self) -> str:
        """Stable identifier, derived only from the record's identifying fields."""
        parts = (
            SCHEMA_VERSION,
            self.family.value,
            self.provenance.source_dataset,
            self.provenance.source_version,
            self.provenance.source_record_id,
            self.ecosystem,
            self.name_normalized,
            self.version_scope.value,
            self.version or "",
            self.version_range or "",
        )
        digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]
        return f"ev-{self.family.value}-{digest}"

    def known_before(self, cutoff: date) -> bool:
        """True if the record was published strictly before ``cutoff``.

        A record without a publication date cannot be placed in time and is
        never treated as known before a cut-off.
        """
        return self.published is not None and self.published < cutoff

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["schema_version"] = SCHEMA_VERSION
        data["evidence_id"] = self.evidence_id
        data["family"] = self.family.value
        data["version_scope"] = self.version_scope.value
        data["published"] = self.published.isoformat() if self.published else None
        data["provenance"]["retrieved_at"] = self.provenance.retrieved_at.isoformat()
        data["corroborating_sources"] = list(self.corroborating_sources)
        return data
