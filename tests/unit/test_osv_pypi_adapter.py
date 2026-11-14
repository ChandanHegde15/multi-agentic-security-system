"""Tests for the OSV PyPI adapter. All inputs are small hand-written OSV-shaped
dictionaries that exercise the format rules; they are test fixtures, not data."""

import json
from datetime import date, datetime, timezone

import pytest

from multi_agentic_security.contracts.evidence import LabelFamily, VersionScope
from multi_agentic_security.datasets.osv_pypi import (
    OsvSnapshot,
    ecosystem_intervals,
    load_directory,
    load_file,
    parse_record,
)

SNAP = OsvSnapshot(source_version="test-export", retrieved_at=datetime(2026, 11, 12, 7, 30, tzinfo=timezone.utc))
SHA = "b" * 64


def adv(**overrides):
    data = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "published": "2024-03-05T12:00:00Z",
        "aliases": ["PYSEC-2024-1", "CVE-2024-0001"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "Flask_Cors"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.0.1"}]}],
                "versions": ["4.0.0"],
            }
        ],
    }
    data.update(overrides)
    return data


def parse(data):
    return parse_record(data, source_file="osv/x.json", source_file_sha256=SHA, snapshot=SNAP)


def test_basic_range_record():
    res = parse(adv())
    assert len(res.records) == 1 and not res.skips
    r = res.records[0]
    assert r.family is LabelFamily.VULNERABLE
    assert (r.ecosystem, r.name_raw, r.name_normalized) == ("pypi", "Flask_Cors", "flask-cors")
    assert r.version_scope is VersionScope.RANGE and r.version_range == ">=0,<4.0.1" and r.version is None
    assert r.published == date(2024, 3, 5)
    assert r.corroborating_sources == ("CVE-2024-0001", "PYSEC-2024-1")
    assert r.provenance.source_record_id == "GHSA-aaaa-bbbb-cccc"
    assert r.provenance.retrieved_at == SNAP.retrieved_at


def test_versions_list_ignored_when_ecosystem_range_present():
    assert all(r.version_scope is VersionScope.RANGE for r in parse(adv()).records)


@pytest.mark.parametrize(
    "events, expected",
    [
        ([{"introduced": "0"}, {"fixed": "1.0"}], [">=0,<1.0"]),
        ([{"introduced": "1.0"}, {"last_affected": "1.5"}], [">=1.0,<=1.5"]),
        ([{"introduced": "2.0"}], [">=2.0"]),
        ([{"introduced": "0"}, {"fixed": "1.0"}, {"introduced": "2.0"}, {"fixed": "2.3"}], [">=0,<1.0", ">=2.0,<2.3"]),
        ([{"introduced": "1.0"}, {"limit": "3.0"}], [">=1.0,<3.0"]),
        ([{"introduced": "1.0"}, {"introduced": "2.0"}, {"fixed": "2.1"}], [">=1.0", ">=2.0,<2.1"]),
    ],
)
def test_intervals(events, expected):
    assert ecosystem_intervals(events) == expected


@pytest.mark.parametrize("events", [[{"fixed": "1.0"}], [{"bogus": "1"}], [{"introduced": ""}], ["x"]])
def test_malformed_events_raise(events):
    with pytest.raises(ValueError):
        ecosystem_intervals(events)


def test_multiple_intervals_give_multiple_records_with_distinct_ids():
    data = adv(affected=[{"package": {"ecosystem": "PyPI", "name": "pkg"}, "ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}, {"introduced": "2.0"}, {"fixed": "2.3"}]}]}])
    recs = parse(data).records
    assert [r.version_range for r in recs] == [">=0,<1.0", ">=2.0,<2.3"]
    assert len({r.evidence_id for r in recs}) == 2


def test_mal_records_out_of_scope():
    res = parse(adv(id="MAL-2024-1"))
    assert not res.records and res.skips[0].reason == "malicious_report_out_of_scope"


def test_withdrawn_advisory_skipped_not_relabelled():
    res = parse(adv(withdrawn="2025-01-01T00:00:00Z"))
    assert not res.records and res.skips[0].reason == "withdrawn_advisory"


def test_other_ecosystem_entries_skipped():
    data = adv(affected=[
        {"package": {"ecosystem": "npm", "name": "x"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]},
        {"package": {"ecosystem": "PyPI", "name": "y"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
    ])
    res = parse(data)
    assert [r.name_normalized for r in res.records] == ["y"]
    assert [s.reason for s in res.skips] == ["other_ecosystem"]


def test_only_other_ecosystems():
    data = adv(affected=[{"package": {"ecosystem": "Maven", "name": "x"}, "versions": ["1"]}])
    res = parse(data)
    assert not res.records and {s.reason for s in res.skips} == {"other_ecosystem", "no_pypi_affected_entry"}


def test_git_range_skipped_and_versions_used_as_listed():
    data = adv(affected=[{"package": {"ecosystem": "PyPI", "name": "pkg"},
                          "ranges": [{"type": "GIT", "repo": "r", "events": [{"introduced": "abc"}, {"fixed": "def"}]}],
                          "versions": ["1.0", "1.1", "1.1"]}])
    res = parse(data)
    assert [(r.version_scope, r.version) for r in res.records] == [(VersionScope.LISTED, "1.0"), (VersionScope.LISTED, "1.1")]
    assert res.duplicates_dropped == 1
    assert [s.reason for s in res.skips] == ["non_ecosystem_range"]


def test_no_version_information_never_widened():
    data = adv(affected=[{"package": {"ecosystem": "PyPI", "name": "pkg"}}])
    res = parse(data)
    assert not res.records and res.skips[0].reason == "no_version_information"


def test_missing_published_is_noted_and_never_known_before():
    data = adv()
    del data["published"]
    res = parse(data)
    assert res.records[0].published is None
    assert res.records[0].known_before(date(2100, 1, 1)) is False
    assert res.notes[0].reason == "no_published_date"


def test_published_converted_to_utc_date():
    assert parse(adv(published="2024-03-05T23:30:00-05:00")).records[0].published == date(2024, 3, 6)


def test_duplicate_affected_entries_deduplicated():
    entry = adv()["affected"][0]
    res = parse(adv(affected=[entry, entry]))
    assert len(res.records) == 1 and res.duplicates_dropped == 1


def test_missing_id_and_name():
    assert parse(adv(id="")).skips[0].reason == "missing_id"
    res = parse(adv(affected=[{"package": {"ecosystem": "PyPI", "name": " "}, "versions": ["1"]}]))
    assert res.skips[0].reason == "missing_package_name"


def test_evidence_id_stable_across_runs():
    assert parse(adv()).records[0].evidence_id == parse(adv()).records[0].evidence_id


def test_load_file_hashes_bytes_and_relative_path(tmp_path):
    root = tmp_path / "root"
    (root / "osv").mkdir(parents=True)
    f = root / "osv" / "GHSA-aaaa-bbbb-cccc.json"
    f.write_text(json.dumps(adv()), encoding="utf-8")
    import hashlib
    rec = load_file(f, data_root=root, snapshot=SNAP).records[0]
    assert rec.provenance.source_file == "osv/GHSA-aaaa-bbbb-cccc.json"
    assert rec.provenance.source_file_sha256 == hashlib.sha256(f.read_bytes()).hexdigest()


def test_load_directory_and_unreadable(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps(adv()), encoding="utf-8")
    (tmp_path / "b.json").write_text("{not json", encoding="utf-8")
    res = load_directory(tmp_path, data_root=tmp_path, snapshot=SNAP)
    assert len(res.records) == 1 and res.skips[0].reason == "unreadable_json"


def test_build_writes_outputs_and_refuses_overwrite(tmp_path):
    from multi_agentic_security.datasets import build_osv_pypi as b

    root = tmp_path / "data"
    osv = root / b.OSV_DIR
    osv.mkdir(parents=True)
    (osv / "GHSA-aaaa-bbbb-cccc.json").write_text(json.dumps(adv()), encoding="utf-8")
    (osv / "MAL-2024-9.json").write_text(json.dumps(adv(id="MAL-2024-9")), encoding="utf-8")
    log = root / b.DOWNLOAD_LOG
    log.parent.mkdir(parents=True)
    log.write_text(json.dumps({"source": "osv", "action": "download", "at": "2026-11-12T07:30:29+00:00",
                               "url": "https://example.invalid/osv/PyPI/all.zip", "sha256": "c" * 64,
                               "last_modified": "Thu, 12 Nov 2026 06:48:13 GMT"}) + "\n", encoding="utf-8")
    out = tmp_path / "out"
    manifest = b.build(root, out)
    assert manifest["counts"]["records"] == 1
    assert manifest["counts"]["skips_by_reason"] == {"malicious_report_out_of_scope": 1}
    assert manifest["expected_missing_quarantined"] == sorted(b.EXPECTED_MISSING)
    assert "sha256:" + "c" * 64 in manifest["source_version"]
    line = json.loads((out / "records.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert line["family"] == "vulnerable" and line["version_range"] == ">=0,<4.0.1"
    with pytest.raises(SystemExit):
        b.build(root, out)


def test_malformed_range_falls_back_to_listed_versions():
    data = adv(affected=[{"package": {"ecosystem": "PyPI", "name": "instack"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "7.2.0"},
                                                                      {"last_affected": "6.1.0"}]}],
                          "versions": ["5.0.0", "6.1.0"]}])
    res = parse(data)
    assert [(r.version_scope, r.version) for r in res.records] == [(VersionScope.LISTED, "5.0.0"), (VersionScope.LISTED, "6.1.0")]
    assert [s.reason for s in res.skips] == ["malformed_range"]
    assert [n.reason for n in res.notes] == ["malformed_range_listed_versions_used"]


def test_malformed_range_without_versions_gives_nothing():
    data = adv(affected=[{"package": {"ecosystem": "PyPI", "name": "p"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.0"}]}]}])
    res = parse(data)
    assert not res.records
    assert {s.reason for s in res.skips} == {"malformed_range", "no_version_information"}
