from datetime import date, datetime, timezone

import pytest

from multi_agentic_security.contracts.evidence import (
    SCHEMA_VERSION,
    EvidenceRecord,
    LabelFamily,
    Provenance,
    VersionScope,
)
from multi_agentic_security.datasets.names import normalize_ecosystem, normalize_name

SHA = "a" * 64


def provenance(**overrides):
    values = dict(
        source_dataset="osv",
        source_version="PyPI/all.zip 2026-11-12",
        source_record_id="GHSA-xxxx-yyyy-zzzz",
        source_file="osv/raw/osv_PyPI/GHSA-xxxx-yyyy-zzzz.json",
        source_file_sha256=SHA,
        license="unverified",
        retrieved_at=datetime(2026, 11, 12, 6, 48, tzinfo=timezone.utc),
    )
    values.update(overrides)
    return Provenance(**values)


def record(**overrides):
    values = dict(
        family=LabelFamily.VULNERABLE,
        ecosystem="pypi",
        name_raw="Flask_Cors",
        name_normalized="flask-cors",
        version_scope=VersionScope.RANGE,
        version_range=">=0,<4.0.1",
        published=date(2026, 3, 1),
        provenance=provenance(),
    )
    values.update(overrides)
    return EvidenceRecord(**values)


# --- name normalization -------------------------------------------------

@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Flask_Cors", "flask-cors"),
        ("zope.interface", "zope-interface"),
        ("A--B__c..D", "a-b-c-d"),
        ("  requests  ", "requests"),
    ],
)
def test_pypi_names_follow_pep_503(raw, expected):
    assert normalize_name("pypi", raw) == expected


def test_npm_names_are_lower_cased_and_keep_scope_and_separators():
    assert normalize_name("npm", "@Babel/Core") == "@babel/core"
    assert normalize_name("npm", "lodash.merge") == "lodash.merge"
    assert normalize_name("npm", "left_pad") == "left_pad"


def test_ecosystem_is_canonicalized_and_unknown_is_rejected():
    assert normalize_ecosystem(" PyPI ") == "pypi"
    with pytest.raises(ValueError):
        normalize_ecosystem("rubygems")


@pytest.mark.parametrize("bad", ["", "   ", None, 3])
def test_empty_or_non_string_names_are_rejected(bad):
    with pytest.raises(ValueError):
        normalize_name("pypi", bad)


# --- evidence record ----------------------------------------------------

def test_valid_record_round_trips_to_dict():
    data = record().to_dict()
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["family"] == "vulnerable"
    assert data["version_scope"] == "range"
    assert data["published"] == "2026-03-01"
    assert data["provenance"]["source_record_id"] == "GHSA-xxxx-yyyy-zzzz"
    assert data["evidence_id"].startswith("ev-vulnerable-")


def test_evidence_id_is_stable_and_depends_on_identity_fields_only():
    base = record()
    assert base.evidence_id == record().evidence_id
    # provenance details that do not identify the claim do not change the ID
    assert base.evidence_id == record(provenance=provenance(license="CC-BY-4.0")).evidence_id
    assert base.evidence_id == record(published=date(2025, 1, 1)).evidence_id
    # identity fields do
    assert base.evidence_id != record(version_range=">=0,<5").evidence_id
    assert base.evidence_id != record(provenance=provenance(source_record_id="PYSEC-1")).evidence_id
    assert base.evidence_id != record(family=LabelFamily.MALICIOUS).evidence_id


def test_same_package_in_two_families_gives_two_distinct_records():
    vulnerable = record()
    malicious = record(
        family=LabelFamily.MALICIOUS, version_scope=VersionScope.ALL, version_range=None
    )
    assert vulnerable.name_normalized == malicious.name_normalized
    assert vulnerable.evidence_id != malicious.evidence_id


def test_normalized_name_must_match_raw_name():
    with pytest.raises(ValueError):
        record(name_normalized="flask_cors")


@pytest.mark.parametrize(
    "overrides",
    [
        dict(version_scope=VersionScope.ALL),                                   # range left set
        dict(version_scope=VersionScope.LISTED, version_range=None),            # no version
        dict(version_scope=VersionScope.RANGE, version_range=None),             # no range
        dict(version_scope=VersionScope.RANGE, version="1.0"),                  # both set
        dict(ecosystem="PyPI"),                                                 # not canonical
        dict(family="vulnerable"),                                              # not an enum
        dict(published=datetime(2026, 3, 1)),                                   # datetime, not date
    ],
)
def test_inconsistent_records_are_rejected(overrides):
    with pytest.raises(ValueError):
        record(**overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        dict(source_file_sha256="abc"),
        dict(source_file_sha256="A" * 64),
        dict(retrieved_at=datetime(2026, 11, 12)),   # naive datetime
        dict(source_record_id=" "),
    ],
)
def test_incomplete_provenance_is_rejected(overrides):
    with pytest.raises(ValueError):
        provenance(**overrides)


def test_known_before_uses_publication_date_and_never_guesses():
    rec = record(published=date(2026, 3, 1))
    assert rec.known_before(date(2026, 3, 2))
    assert not rec.known_before(date(2026, 3, 1))   # strictly before
    assert not record(published=None).known_before(date(2030, 1, 1))


def test_evidence_id_unchanged_by_schema_1_1():
    # Value computed with schema evidence/1 before the target field existed.
    import hashlib
    from multi_agentic_security.contracts.evidence import ID_NAMESPACE
    r = record()
    parts = (ID_NAMESPACE, "vulnerable", "osv", "PyPI/all.zip 2026-11-12", "GHSA-xxxx-yyyy-zzzz", "pypi", "flask-cors", "range", "", ">=0,<4.0.1")
    assert ID_NAMESPACE == "evidence/1"
    assert r.evidence_id == "ev-vulnerable-" + hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]


def test_typosquat_target_rules():
    base = dict(family=LabelFamily.TYPOSQUAT, ecosystem="pypi", name_raw="reqeusts", name_normalized="reqeusts",
                version_scope=VersionScope.ALL, version_range=None, provenance=provenance())
    with pytest.raises(ValueError):
        record(**base)
    ok = record(**base, target_name_raw="Requests", target_name_normalized="requests")
    assert ok.to_dict()["target_name_normalized"] == "requests"
    assert ok.evidence_id != record(**base, target_name_raw="reqs", target_name_normalized="reqs").evidence_id
    with pytest.raises(ValueError):
        record(**base, target_name_raw="reqeusts", target_name_normalized="reqeusts")
    with pytest.raises(ValueError):
        record(target_name_raw="x", target_name_normalized="x")
