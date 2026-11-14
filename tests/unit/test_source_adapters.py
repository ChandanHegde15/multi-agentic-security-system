"""Tests for the OpenSSF, DataDog, MalRegistry, typosquat and popular-list adapters.
All inputs are small hand-written files in tmp_path (fixtures, not data)."""

import json
from datetime import date, datetime, timezone

import pytest

from multi_agentic_security.contracts.evidence import LabelFamily, VersionScope
from multi_agentic_security.datasets import listings, openssf
from multi_agentic_security.datasets.adapter_common import Snapshot, parse_utc_date

SNAP = Snapshot(source_version="git abc", retrieved_at=datetime(2026, 11, 12, tzinfo=timezone.utc), license="Apache-2.0")


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def mal(id_="MAL-2025-1", name="evil-pkg", eco="PyPI", **affected_extra):
    aff = {"package": {"ecosystem": eco, "name": name}}
    aff.update(affected_extra)
    return {"id": id_, "published": "2025-03-28T13:05:11Z", "affected": [aff],
            "database_specific": {"malicious-packages-origins": [{"source": "reversing-labs", "id": "RL-1"}]}}


# ---------------------------------------------------------------- OpenSSF

def test_openssf_listed_versions_and_origins(tmp_path):
    root = tmp_path / "osv"
    write(root / "malicious/pypi/evil-pkg/MAL-2025-1.json", json.dumps(mal(versions=["0.1", "0.2"])))
    res = openssf.load(root, data_root=tmp_path, snapshot=SNAP)
    assert [(r.family, r.version_scope, r.version) for r in res.records] == [
        (LabelFamily.MALICIOUS, VersionScope.LISTED, "0.1"), (LabelFamily.MALICIOUS, VersionScope.LISTED, "0.2")]
    r = res.records[0]
    assert r.published == date(2025, 3, 28)
    assert r.corroborating_sources == ("origin:reversing-labs:RL-1",)
    assert r.provenance.source_file == "osv/malicious/pypi/evil-pkg/MAL-2025-1.json"
    assert res.files_read == 1


def test_openssf_all_versions_range_maps_to_all_and_other_ranges_kept(tmp_path):
    root = tmp_path / "osv"
    write(root / "malicious/pypi/a/MAL-1.json", json.dumps(mal("MAL-1", "a", ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}])))
    write(root / "malicious/pypi/b/MAL-2.json", json.dumps(mal("MAL-2", "b", ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "2.0"}]}])))
    recs = {r.name_normalized: r for r in openssf.load(root, data_root=tmp_path, snapshot=SNAP).records}
    assert recs["a"].version_scope is VersionScope.ALL
    assert recs["b"].version_scope is VersionScope.RANGE and recs["b"].version_range == ">=1.0,<2.0"


def test_openssf_semver_range_read(tmp_path):
    root = tmp_path / "osv"
    write(root / "malicious/npm/s/MAL-5.json", json.dumps(mal("MAL-5", "s", eco="npm", ranges=[{"type": "SEMVER", "events": [{"introduced": "0"}]}])))
    write(root / "malicious/npm/g/MAL-6.json", json.dumps(mal("MAL-6", "g", eco="npm", ranges=[{"type": "GIT", "events": [{"introduced": "abc"}]}])))
    res = openssf.load(root, data_root=tmp_path, snapshot=SNAP)
    assert [(r.name_normalized, r.version_scope) for r in res.records] == [("s", VersionScope.ALL)]
    assert sorted(s.reason for s in res.skips) == ["no_version_information", "non_ecosystem_range"]


def test_openssf_withdrawn_kept_separate(tmp_path):
    root = tmp_path / "osv"
    d = mal("MAL-9", "oops", versions=["1"]); d["withdrawn"] = "2026-06-13T01:41:13Z"
    write(root / "withdrawn/npm/oops/MAL-9.json", json.dumps(d | {"affected": [{"package": {"ecosystem": "npm", "name": "oops"}, "versions": ["1"]}]}))
    write(root / "malicious/pypi/x/MAL-8.json", json.dumps(d))
    res = openssf.load(root, data_root=tmp_path, snapshot=SNAP)
    assert {r.family for r in res.records} == {LabelFamily.WITHDRAWN}
    assert {r.ecosystem for r in res.records} == {"npm", "pypi"}
    assert [n.reason for n in res.notes] == ["withdrawn_field_in_malicious_dir"]


def test_openssf_unsupported_ecosystem_and_no_versions(tmp_path):
    root = tmp_path / "osv"
    write(root / "malicious/x/MAL-3.json", json.dumps(mal("MAL-3", "g", eco="Go", versions=["1"])))
    write(root / "malicious/x/MAL-4.json", json.dumps(mal("MAL-4", "h")))
    write(root / "malicious/x/bad.json", "{")
    res = openssf.load(root, data_root=tmp_path, snapshot=SNAP)
    assert not res.records
    assert sorted(s.reason for s in res.skips) == ["no_version_information", "unreadable_json", "unsupported_ecosystem"]


# ---------------------------------------------------------------- DataDog / MalRegistry

def test_datadog_manifest_scopes(tmp_path):
    samples = tmp_path / "samples"
    write(samples / "pypi/manifest.json", json.dumps({"evil": None, "durabletask": ["1.4.1", "1.4.2"], "bad": 5}))
    write(samples / "npm/manifest.json", json.dumps({"@scope/Thing": None}))
    write(samples / "ide_extensions/manifest.json", json.dumps({"x": None}))
    res = listings.load_datadog(samples, data_root=tmp_path, snapshot=SNAP)
    got = sorted((r.ecosystem, r.name_normalized, r.version_scope.value, r.version) for r in res.records)
    assert got == [("npm", "@scope/thing", "all", None), ("pypi", "durabletask", "listed", "1.4.1"),
                   ("pypi", "durabletask", "listed", "1.4.2"), ("pypi", "evil", "all", None)]
    assert sorted(s.reason for s in res.skips) == ["unrecognised_version_field", "unsupported_ecosystem"]
    assert all(r.published is None and not r.known_before(date(2100, 1, 1)) for r in res.records)


def test_malregistry_listing(tmp_path):
    listing = write(tmp_path / "tree_listing.txt", ".gitignore\n0x000testqwe/5.20.4/0x000testqwe-5.20.4.tar.gz\n0x000testqwe/5.20.4/dup.zip\n\n")
    res = listings.load_malregistry(listing, data_root=tmp_path, snapshot=SNAP)
    assert [(r.name_normalized, r.version) for r in res.records] == [("0x000testqwe", "5.20.4")]
    assert res.duplicates_dropped == 1 and [s.reason for s in res.skips] == ["not_name_version_file"]


# ---------------------------------------------------------------- typosquats

def test_ecosystems_typosquats(tmp_path):
    csv_path = write(tmp_path / "typosquats.csv",
                     "malicious_package,target_package,ecosystem,registry,classification,source\n"
                     "aiohttpp,aiohttp,pypi,https://pypi.org,repetition,ossf/malicious-packages\n"
                     "foo,foo,npm,,,\n"
                     "x,y,go,,,\n")
    res = listings.load_ecosystems_typosquats(csv_path, data_root=tmp_path, snapshot=SNAP)
    (r,) = res.records
    assert r.family is LabelFamily.TYPOSQUAT and r.target_name_normalized == "aiohttp"
    assert r.corroborating_sources == ("listed_by:ossf/malicious-packages",)
    assert sorted(s.reason for s in res.skips) == ["unsupported_ecosystem", "variant_equals_target"]


def test_yctt_pairs_use_release_date_not_package_upload(tmp_path):
    csv_path = write(tmp_path / "pairs.csv", "package_name,target,exists,unpublished,published,removed\n"
                                             "-gzip-ize,gzip-size,True,False,2022-08-18 15:50:28+00:00,\n")
    (r,) = listings.load_yctt_pairs(csv_path, data_root=tmp_path, snapshot=SNAP, release_date=date(2026, 10, 21)).records
    assert r.published == date(2026, 10, 21)
    assert (r.name_normalized, r.target_name_normalized) == ("-gzip-ize", "gzip-size")


# ---------------------------------------------------------------- benign reference

def test_pypi_popular_and_yctt_targets(tmp_path):
    js = write(tmp_path / "top.json", json.dumps({"last_update": "2026-11-01 06:41:05",
                                                  "rows": [{"project": "boto3"}, {"project": "Typing_Extensions"}, {"project": ""}]}))
    res = listings.load_pypi_popular(js, data_root=tmp_path, snapshot=SNAP)
    assert [(r.name_normalized, r.provenance.source_record_id) for r in res.records] == [
        ("boto3", "rank:1:boto3"), ("typing-extensions", "rank:2:Typing_Extensions")]
    assert all(r.family is LabelFamily.BENIGN_REFERENCE and r.published == date(2026, 11, 1) for r in res.records)
    tg = write(tmp_path / "targets.csv", "package_name,exists\ngzip-size,True\n")
    (t,) = listings.load_yctt_targets(tg, data_root=tmp_path, snapshot=SNAP).records
    assert t.ecosystem == "npm" and t.family is LabelFamily.BENIGN_REFERENCE


@pytest.mark.parametrize("value, expected", [("2025-03-28T13:05:11Z", date(2025, 3, 28)), ("", None), ("junk", None),
                                              ("2024-03-05T23:30:00-05:00", date(2024, 3, 6))])
def test_parse_utc_date(value, expected):
    assert parse_utc_date(value) == expected


def test_build_tables_registry_is_complete():
    from pathlib import Path
    from multi_agentic_security.datasets.build_tables import tables
    names = set(tables(Path(".")))
    assert names == {"openssf_a2", "datadog_manifests", "malregistry_listing", "ecosystems_typosquats",
                     "yctt_pairs", "yctt_targets", "pypi_popular"}
