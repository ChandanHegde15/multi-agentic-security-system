# Dataset migration: `D:\RESEARCH_DATA` → `research/datasets/`

Status: **executed and verified on 2026-11-13** under decision D-017. The full record, with hash trees, is `research/datasets/provenance/MIGRATION_RECORD.md` on the owner's machine (that folder is git-ignored and not published).

The owner designated the dataset as the project's primary dataset and asked for it to be organized inside the repository folder. It stays out of git.

## 1. Decisions taken before the move

| # | Question | Outcome |
|---|---|---|
| M1 | Supersede the location clause of D-008 | Recorded as D-017 |
| M2 | Update the local working rules for the new location | Done: data inside the repository folder, git-ignored; never `git clean -x`/`-X` |
| M3 | Legacy archive | Stays at `D:\RESEARCH_DATA\legacy_archive\` |
| M4 | External backup of `dataset_submission.zip` | Confirmed by the owner before the move |
| M5 | Read-only attribute on the zip | Set after verification |
| M6 | Old root | Kept as a stub with `MOVED.txt` and the old README |
| M7 | Target path | Exactly `research\datasets\`, because the longest file path is 255 characters there (limit 260) |

## 2. Controls for keeping data inside the repository folder

| Risk | Control in place |
|---|---|
| Data staged in git | `/research/datasets/` in `.gitignore`, added and tested with `git check-ignore` before any file was moved |
| `git clean -fdx` deleting the only copy | Rule: never run `git clean` with `-x` or `-X`; external backup exists |
| Publishing malware or unlicensed data | Ignore rule; only the owner commits (D-015) |
| Defender quarantining more files on a move | Same-volume rename (no file rewritten); full re-hash afterwards found no new missing file |
| Test runners and tools walking the data | `pytest.ini` restricts collection to `agents` and excludes `research`; never accept an editor offer to install dependencies from the dataset's manifests |
| Repository backups or sync including the data | Exclude `research/datasets/` from anything that leaves the machine |
| Broken references | Historical reports are not rewritten; the migration record maps old to new paths |

## 3. Procedure as performed

1. Ignore rule added and tested; `git status` showed no data files.
2. Baseline at the old location: SHA-256 and size of all 39,743 files (39,700 in the moved set), zip hash, manifest check, legacy manifest check, read-only counts. A copy of the baseline was stored outside the repository.
3. Five top-level folders moved by same-volume rename, in the order `inspected`, `review`, `verified`, `extracted`, `incoming`. The legacy archive and the old README were not moved.
4. Full re-hash at the new location and comparison with the baseline.
5. Provenance written: migration record, pre- and post-migration hash trees, quarantine record, a verbatim copy of the old README, a new README, and `D:\RESEARCH_DATA\MOVED.txt`.

## 4. Results

| Check | Before | After |
|---|---|---|
| Files / bytes in the moved set | 39,700 / 833,390,567 | 39,700 / 833,390,567 |
| Per-file SHA-256 and size | — | **0 differences** |
| Zip SHA-256 `33e409ab…0d00` | pass | pass |
| `EXTRACTION_MANIFEST.csv` match / mismatch / missing | 39,693 / 0 / 7 | 39,693 / 0 / 7 |
| Missing files are exactly the 7 quarantined files | yes | yes |
| Read-only files (`extracted`, `review`) | 39,650, 43 | 39,650, 43 |
| Longest path | 238 | 255 |
| Legacy archive manifest (not moved) | 40/40 | — |
| Test suite | 13 passed | 13 passed |

## 5. The seven Defender-quarantined files

They were absent before the move and are absent after it. They were not restored and no Defender setting was changed (D-009). Their originals are intact inside `dataset_submission.zip` and are read in memory when needed. The table with paths, sizes and SHA-256 values is in `research/datasets/provenance/QUARANTINE_RECORD.md` and in `DATASET_CATALOG.md` §1.

## 6. What the migration did not do

- No further extraction from the zip; no `.tgz` opened; no submission script run.
- No normalization, renaming, de-duplication or reorganization of dataset contents.
- No file content edited. `extracted/v1/EXTRACTION_INFO.json` still names the archive's old path; the migration record explains it.
- No deletion, including the legacy archive.
- No commit or push.
