"""One-pass evaluation of the evidence tables and benchmark sources (read-only on data).

Usage (from the repository root):

    python -m multi_agentic_security.datasets.evaluate \
        --data-root research/datasets --out research/datasets/inspected/evaluation_<date>

Writes ``evaluation.json``, ``conflicts.csv`` and ``libhallubench_exclusions.csv``
into a new folder (refuses to overwrite). Overlap between sources is reported
as overlap, never as confirmation; conflicts are facts for review.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from multi_agentic_security.datasets.names import normalize_name

TABLE_ROOT = Path("verified/normalized/v1")
CURRENT_TABLES = (
    "vulnerable/osv_pypi_a2",
    "malicious_withdrawn/openssf_a2",
    "malicious/datadog_manifests",
    "malicious/malregistry_listing",
    "typosquat/ecosystems_typosquats",
    "typosquat/yctt_pairs",
    "benign_reference/pypi_popular",
    "benign_reference/yctt_targets",
)
SUPERSEDED = ("vulnerable/osv_pypi", "malicious_withdrawn/openssf")
V1 = Path("extracted/v1/data")
EXTRAS = Path("extracted/extras_v1/data")


def load_tables(data_root: Path) -> tuple[dict[str, dict], list[dict]]:
    manifests, records = {}, []
    for rel in CURRENT_TABLES:
        folder = data_root / TABLE_ROOT / rel
        manifests[rel] = json.loads((folder / "MANIFEST.json").read_text(encoding="utf-8"))
        with (folder / "records.jsonl").open(encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                records.append({
                    "table": rel, "family": r["family"], "ecosystem": r["ecosystem"], "name": r["name_normalized"],
                    "scope": r["version_scope"], "version": r["version"], "published": r["published"],
                    "target": r.get("target_name_normalized"), "source": r["provenance"]["source_dataset"],
                    "license": r["provenance"]["license"],
                })
    return manifests, records


def table_summary(manifests: dict[str, dict], records: list[dict]) -> dict:
    out = {}
    by_table = defaultdict(list)
    for r in records:
        by_table[r["table"]].append(r)
    for rel, m in manifests.items():
        rows = by_table[rel]
        years = Counter(r["published"][:4] for r in rows if r["published"])
        out[rel] = {
            "adapter_version": m["adapter_version"],
            "records": len(rows),
            "distinct_packages": len({(r["ecosystem"], r["name"]) for r in rows}),
            "by_family": dict(Counter(r["family"] for r in rows)),
            "by_ecosystem": dict(Counter(r["ecosystem"] for r in rows)),
            "by_scope": dict(Counter(r["scope"] for r in rows)),
            "dated_share": round(sum(1 for r in rows if r["published"]) / len(rows), 4) if rows else None,
            "published_by_year": dict(sorted(years.items())),
            "licenses": m.get("licenses") or [m.get("license")],          # build_osv_pypi writes the singular keys
            "source_versions": m.get("source_versions") or [m.get("source_version")],
            "skips_by_reason": m["counts"]["skips_by_reason"],
            "records_jsonl_sha256": m["files"]["records.jsonl"]["sha256"],
        }
    return out


def name_sets(records: list[dict]) -> dict[str, set]:
    s: dict[str, set] = defaultdict(set)
    for r in records:
        key = (r["ecosystem"], r["name"])
        s[f"family:{r['family']}"].add(key)
        s[f"source:{r['source']}:{r['family']}"].add(key)
        if r["family"] == "typosquat" and r["target"]:
            s["typosquat_target"].add((r["ecosystem"], r["target"]))
    return s


def overlaps(sets: dict[str, set]) -> dict:
    mal = {k: sets.get(f"source:{k}:malicious", set()) for k in
           ("openssf_malicious_packages", "datadog_malicious_packages", "pypi_malregistry")}
    pypi = {k: {x for x in v if x[0] == "pypi"} for k, v in mal.items()}
    a, b, c = pypi["openssf_malicious_packages"], pypi["datadog_malicious_packages"], pypi["pypi_malregistry"]
    malicious = sets["family:malicious"]
    return {
        "malicious_pypi_names": {"openssf": len(a), "datadog": len(b), "malregistry": len(c),
                                 "openssf&datadog": len(a & b), "openssf&malregistry": len(a & c),
                                 "datadog&malregistry": len(b & c), "all_three": len(a & b & c),
                                 "union": len(a | b | c), "only_one_source": len((a | b | c)) - len((a & b) | (a & c) | (b & c))},
        "malicious_npm_names": {"openssf": len({x for x in mal["openssf_malicious_packages"] if x[0] == "npm"}),
                                "datadog": len({x for x in mal["datadog_malicious_packages"] if x[0] == "npm"})},
        "withdrawn_only_names": len(sets["family:withdrawn"] - malicious),
        "withdrawn_and_malicious_names": len(sets["family:withdrawn"] & malicious),
        "vulnerable_and_malicious_names": len(sets["family:vulnerable"] & malicious),
        "typosquat_variant_and_malicious": len(sets["family:typosquat"] & malicious),
        "typosquat_variant_not_reported_malicious": len(sets["family:typosquat"] - malicious),
        "vulnerable_in_popular": len(sets["family:vulnerable"] & sets["source:pypi_popular:benign_reference"]),
    }


def conflicts(sets: dict[str, set]) -> list[dict]:
    benign = sets["family:benign_reference"]
    rows = []
    for fam in ("malicious", "typosquat", "withdrawn"):
        for eco, name in sorted(benign & sets[f"family:{fam}"]):
            rows.append({"ecosystem": eco, "name": name, "benign_reference_and": fam})
    for eco, name in sorted(sets["typosquat_target"] & sets["family:malicious"]):
        rows.append({"ecosystem": eco, "name": name, "benign_reference_and": "typosquat_target_reported_malicious"})
    return rows


def libhallubench(data_root: Path, sets: dict[str, set]) -> tuple[dict, list[dict]]:
    mistakes = Counter()
    for split in ("control", "describe", "specify"):
        path = data_root / V1 / f"sources/libhallubench/raw/libhallubench_{split}.jsonl"
        for line in path.read_text(encoding="utf-8").splitlines():
            m = (json.loads(line).get("mistake") or "").strip()
            if m:
                try:
                    mistakes[normalize_name("pypi", m)] += 1
                except ValueError:
                    continue
    names = {("pypi", n) for n in mistakes}
    risky = sets["family:malicious"] | sets["family:typosquat"]
    excl = sorted(names & risky)
    rows = [{"ecosystem": e, "name": n, "in_malicious": (e, n) in sets["family:malicious"],
             "in_typosquat": (e, n) in sets["family:typosquat"], "tasks": mistakes[n]} for e, n in excl]
    return ({"mistake_tasks": sum(mistakes.values()), "distinct_mistake_names": len(names),
             "mistake_names_in_malicious_or_typosquat": len(excl),
             "mistake_names_in_popular_list": len(names & sets["source:pypi_popular:benign_reference"]),
             "mistake_names_in_vulnerable": len(names & sets["family:vulnerable"])}, rows)


def package_hallucination(data_root: Path, sets: dict[str, set]) -> dict:
    path = data_root / V1 / "sources/package_hallucination/raw/package-hallucination-data/package-hallucination-data/data/packages.csv"
    rows = list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8"))))
    absent = {("pypi", r["norm"]) for r in rows if r.get("absent_at_generation") == "True" and r.get("norm")}
    imports = {(r["import_name"], r["norm"]) for r in rows if r.get("source") == "import" and r.get("import_name") and r.get("norm")}
    renamed = {p for p in imports if normalize_name("pypi", p[0]) != p[1]}
    return {"mentions": len(rows), "models": sorted({r["model"] for r in rows}),
            "distinct_names": len({r["norm"] for r in rows if r.get("norm")}),
            "absent_at_generation_names": len(absent),
            "absent_names_in_malicious_or_typosquat": len(absent & (sets["family:malicious"] | sets["family:typosquat"])),
            "import_to_package_pairs": len(imports), "import_pairs_with_different_name": len(renamed)}


def agent_inputs(data_root: Path, sets: dict[str, set]) -> dict:
    idx = [json.loads(l) for l in (data_root / V1 / "sources/real_manifests/index.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    pins = (data_root / EXTRAS / "sources/real_manifests/requirements_pins")
    versions = [json.loads(l) for l in (data_root / EXTRAS / "normalized/registry_metadata/pypi_versions.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    vlist = {("pypi", normalize_name("pypi", v["package_name"])) for v in versions}
    gens = data_root / V1 / "sources/package_hallucination/raw/package-hallucination-data/package-hallucination-data/data/generations.jsonl"
    return {
        "real_manifests": {"files": len(idx), "repos": len({r["repo_url"] for r in idx}), "by_format": dict(Counter(r["format"] for r in idx))},
        "requirements_pin_files_dev_only": len([p for p in pins.rglob("*") if p.is_file()]) if pins.exists() else 0,
        "generated_code_generations": sum(1 for _ in gens.open(encoding="utf-8")) if gens.exists() else 0,
        "pypi_version_lists": len(vlist),
        "vulnerable_targets_with_version_list": len(sets["family:vulnerable"] & vlist),
        "vulnerable_targets_total": len(sets["family:vulnerable"]),
    }


def evaluate(data_root: Path, out_dir: Path) -> dict:
    if out_dir.exists():
        raise SystemExit(f"output folder exists, refusing to overwrite: {out_dir}")
    manifests, records = load_tables(data_root)
    sets = name_sets(records)
    conf = conflicts(sets)
    lhb, lhb_rows = libhallubench(data_root, sets)
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tables": table_summary(manifests, records),
        "superseded_tables_present": [t for t in SUPERSEDED if (data_root / TABLE_ROOT / t).exists()],
        "family_name_counts": {k.split(":", 1)[1]: len(v) for k, v in sets.items() if k.startswith("family:")},
        "overlaps": overlaps(sets),
        "conflicts": dict(Counter(r["benign_reference_and"] for r in conf)),
        "libhallubench": lhb,
        "package_hallucination": package_hallucination(data_root, sets),
        "agent_inputs": agent_inputs(data_root, sets),
    }
    out_dir.mkdir(parents=True)
    (out_dir / "evaluation.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for name, rows, fields in (("conflicts.csv", conf, ["ecosystem", "name", "benign_reference_and"]),
                               ("libhallubench_exclusions.csv", lhb_rows, ["ecosystem", "name", "in_malicious", "in_typosquat", "tasks"])):
        with (out_dir / name).open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
            w.writeheader()
            w.writerows(rows)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    print(json.dumps(evaluate(args.data_root, args.out), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
