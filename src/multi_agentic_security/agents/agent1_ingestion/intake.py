"""Safe intake of uploads: a ZIP archive or a folder.

Nothing is extracted to disk and nothing is executed. A ZIP is read in memory
through ``zipfile``; a folder is walked without following links. Only files
that Agent 1 can parse are read; other manifests are listed as unsupported.
Every check runs before a file's content is read:

- entry names: no absolute paths, drive letters, ``..`` segments or NUL
  characters (any of these rejects the whole archive as hostile);
- duplicate paths after normalisation (case-insensitive) reject the archive,
  because two files with one name can show a scanner different content than
  an installer;
- symbolic links, junctions, encrypted entries and special files are skipped
  and reported;
- limits on the number of entries, folder depth, each file's size, the total
  size and the compression ratio (zip bombs). Sizes declared in the archive
  are checked first and the real number of bytes read is capped as well.
"""

from __future__ import annotations

import io
import os
import re
import stat
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from multi_agentic_security.contracts.pipeline import Failure, InputSource

from .common import UploadedFile, failure, sha256_hex


@dataclass(frozen=True)
class IntakeLimits:
    max_upload_bytes: int = 100 * 1024 * 1024       # size of the uploaded ZIP itself
    max_entries: int = 20_000                        # entries in the archive / files in the folder
    max_total_bytes: int = 500 * 1024 * 1024         # uncompressed bytes declared by all entries
    max_file_bytes: int = 20 * 1024 * 1024           # one manifest
    max_read_bytes: int = 100 * 1024 * 1024          # bytes actually read for all parsed files
    max_compression_ratio: int = 200                 # uncompressed / compressed for one entry
    max_depth: int = 32                              # path segments
    max_path_length: int = 512
    max_code_files: int = 2_000                      # source, script, Dockerfile and Markdown files read
    max_code_file_bytes: int = 2 * 1024 * 1024       # one such file


DEFAULT_LIMITS = IntakeLimits()

# Folders whose content is vendored or generated. Their manifests describe
# installed packages, not the project's declarations (the lockfile covers
# node_modules). They are skipped and reported once per folder.
VENDORED_DIRS = frozenset({"node_modules", ".git", ".hg", ".svn", "site-packages", ".venv", "venv",
                           "__pycache__", ".tox", "bower_components"})
NESTED_ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".whl", ".egg", ".jar",
                           ".7z", ".rar", ".gz")

_DRIVE = re.compile(r"^[A-Za-z]:")


@dataclass
class IntakeResult:
    source: InputSource
    files: list[UploadedFile] = field(default_factory=list)
    failures: list[Failure] = field(default_factory=list)
    rejected: bool = False


class _Reject(Exception):
    def __init__(self, code: str, detail: str, path: Optional[str] = None):
        super().__init__(detail)
        self.code, self.detail, self.path = code, detail, path


def safe_relative_path(name: str, limits: IntakeLimits = DEFAULT_LIMITS) -> str:
    """Normalise an entry name to a relative ``a/b/c`` path or raise ``_Reject``."""
    if "\x00" in name:
        raise _Reject("intake.path.nul_character", "entry name contains a NUL character", None)
    p = name.replace("\\", "/")
    if p.startswith("/") or _DRIVE.match(p):
        raise _Reject("intake.path.absolute", f"entry '{p}' is an absolute path", p)
    parts = [s for s in p.split("/") if s not in ("", ".")]
    if any(s == ".." for s in parts):
        raise _Reject("intake.path.traversal", f"entry '{p}' leaves the upload folder ('..')", p)
    if len(p) > limits.max_path_length:
        raise _Reject("intake.limit.path_length", f"entry path longer than {limits.max_path_length} characters", p[:80])
    if len(parts) > limits.max_depth:
        raise _Reject("intake.limit.depth", f"entry '{p}' is nested deeper than {limits.max_depth} levels", p)
    return "/".join(parts)


def vendored_prefix(path: str) -> Optional[str]:
    parts = path.split("/")
    for i, part in enumerate(parts[:-1]):
        if part.lower() in VENDORED_DIRS:
            return "/".join(parts[: i + 1])
    return None


def is_nested_archive(path: str) -> bool:
    return path.lower().endswith(NESTED_ARCHIVE_SUFFIXES)


def _label(name: str) -> str:
    """Only the base name of the upload is reported, never a local path."""
    base = name.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return base or "upload"


# --------------------------------------------------------------------------- ZIP

def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return info.create_system == 3 and stat.S_ISLNK(mode)


def read_zip(data: bytes, upload_name: str, wanted, limits: IntakeLimits = DEFAULT_LIMITS) -> IntakeResult:
    """Read the files selected by ``wanted(path) -> bool`` from a ZIP held in memory.

    ``wanted`` decides which entries are parsed; other entries are only
    validated (names, sizes), never read.
    """
    source = InputSource(kind="archive", locator=_label(upload_name), sha256=sha256_hex(data), size_bytes=len(data))
    result = IntakeResult(source=source)
    if len(data) > limits.max_upload_bytes:
        return _rejected(result, "intake.limit.upload_size",
                         f"upload is {len(data)} bytes; the limit is {limits.max_upload_bytes}")
    declared_entries = _declared_entry_count(data)
    if declared_entries is not None and declared_entries > limits.max_entries:
        return _rejected(result, "intake.limit.entries",
                         f"{declared_entries} entries declared; the limit is {limits.max_entries}")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, OSError) as exc:
        return _rejected(result, "intake.zip.invalid", f"not a readable ZIP archive ({exc})")
    with zf:
        try:
            plan = _plan_zip(zf, limits, result)
        except _Reject as r:
            return _rejected(result, r.code, r.detail, r.path)
        read_total = 0
        selected = []
        for path, info in plan:
            decision = wanted(path)
            if decision:
                selected.append((0 if decision is True else 1, path, info, _file_cap(decision, limits)))
        # Manifests first, so code files can never use up the read budget a manifest needs.
        for _, path, info, file_cap in sorted(selected, key=lambda x: (x[0], x[1])):
            if info.flag_bits & 0x1:
                result.failures.append(failure("intake", "intake.zip.encrypted", "encrypted entry; not read", path))
                continue
            if info.file_size > file_cap:
                result.failures.append(failure("intake", "intake.limit.file_size",
                                               f"declared size {info.file_size} bytes exceeds {file_cap}; not read", path))
                continue
            if info.compress_size and info.file_size / info.compress_size > limits.max_compression_ratio \
                    and info.file_size > 1024 * 1024:
                result.failures.append(failure("intake", "intake.limit.compression_ratio",
                                               f"compression ratio above {limits.max_compression_ratio}; not read", path))
                continue
            remaining = limits.max_read_bytes - read_total
            if info.file_size > remaining:
                result.failures.append(failure("intake", "intake.limit.read_total",
                                               f"reading this file would exceed the total read limit of {limits.max_read_bytes} bytes; not read", path))
                continue
            try:
                content = _read_capped(zf, info, file_cap, remaining)
            except _Reject as r:
                result.failures.append(failure("intake", r.code, r.detail, path))
                continue
            except (zipfile.BadZipFile, NotImplementedError, RuntimeError, zlib.error, EOFError, OSError) as exc:
                result.failures.append(failure("intake", "intake.zip.entry_unreadable", f"entry could not be read ({exc})", path))
                continue
            read_total += len(content)
            result.files.append(UploadedFile(path=path, data=content))
    return result


def _file_cap(decision, limits: IntakeLimits) -> int:
    """``wanted`` returns True (default cap) or an int (a smaller cap for that file)."""
    if decision is True:
        return limits.max_file_bytes
    return min(int(decision), limits.max_file_bytes)


def _declared_entry_count(data: bytes) -> Optional[int]:
    """Entry count from the end-of-central-directory record (ZIP64 aware), or None.

    Read before ``zipfile`` builds its index, so an archive with millions of
    tiny entries is refused without parsing them.
    """
    tail_start = max(0, len(data) - (65535 + 22))
    eocd = data.rfind(b"PK\x05\x06", tail_start)
    if eocd < 0 or eocd + 22 > len(data):
        return None
    count = int.from_bytes(data[eocd + 10:eocd + 12], "little")
    if count != 0xFFFF:
        return count
    loc = eocd - 20
    if loc >= 0 and data[loc:loc + 4] == b"PK\x06\x07":
        z64 = int.from_bytes(data[loc + 8:loc + 16], "little")
        if z64 + 40 <= len(data) and data[z64:z64 + 4] == b"PK\x06\x06":
            return int.from_bytes(data[z64 + 32:z64 + 40], "little")
    return None


def _dup_key(path: str) -> str:
    """Key for duplicate detection: case-insensitive, trailing dots/spaces ignored (as on Windows)."""
    return "/".join(seg.rstrip(" .") for seg in path.split("/")).casefold()


def _plan_zip(zf: zipfile.ZipFile, limits: IntakeLimits, result: IntakeResult) -> list[tuple[str, zipfile.ZipInfo]]:
    infos = zf.infolist()
    if len(infos) > limits.max_entries:
        raise _Reject("intake.limit.entries", f"{len(infos)} entries; the limit is {limits.max_entries}")
    declared = sum(i.file_size for i in infos)
    if declared > limits.max_total_bytes:
        raise _Reject("intake.limit.total_size",
                      f"entries declare {declared} uncompressed bytes; the limit is {limits.max_total_bytes}")
    seen: dict[str, str] = {}
    plan: list[tuple[str, zipfile.ZipInfo]] = []
    vendored: set[str] = set()
    for info in infos:
        path = safe_relative_path(info.filename, limits)
        if not path:
            continue
        key = _dup_key(path)
        if key in seen:
            raise _Reject("intake.path.duplicate", f"'{path}' occurs more than once (also as '{seen[key]}')", path)
        seen[key] = path
        if info.is_dir():
            continue
        if _is_zip_symlink(info):
            result.failures.append(failure("intake", "intake.zip.symlink", "symbolic link entry; not followed or read", path))
            continue
        prefix = vendored_prefix(path)
        if prefix is not None:
            vendored.add(prefix)
            continue
        plan.append((path, info))
    for prefix in sorted(vendored):
        result.failures.append(failure("intake", "intake.vendored_directory_skipped",
                                       "vendored or generated folder; its files are not read", prefix))
    return plan


def _read_capped(zf: zipfile.ZipFile, info: zipfile.ZipInfo, file_cap: int, remaining: int) -> bytes:
    cap = min(file_cap, remaining)
    chunks: list[bytes] = []
    size = 0
    with zf.open(info) as fh:
        while True:
            chunk = fh.read(min(65536, cap + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > cap:
                if cap == file_cap:
                    raise _Reject("intake.limit.file_size",
                                  f"content is larger than its declared size and exceeds {file_cap} bytes; not read")
                raise _Reject("intake.limit.read_total",
                              "content is larger than its declared size and would exceed the total read limit; not read")
            chunks.append(chunk)
    return b"".join(chunks)


def _rejected(result: IntakeResult, code: str, detail: str, path: Optional[str] = None) -> IntakeResult:
    result.files.clear()
    result.failures.append(failure("intake", code, detail + "; the upload was rejected and nothing was read", path))
    result.rejected = True
    return result


# --------------------------------------------------------------------------- folder

def read_directory(root: Union[str, Path], wanted, limits: IntakeLimits = DEFAULT_LIMITS,
                   label: Optional[str] = None) -> IntakeResult:
    """Read the files selected by ``wanted(path)`` from a folder without following links."""
    root = Path(root)
    source = InputSource(kind="directory", locator=label or _label(str(root)))
    result = IntakeResult(source=source)
    try:
        st = os.lstat(root)
    except OSError as exc:
        return _rejected(result, "intake.dir.unreadable", f"folder cannot be read ({exc.strerror})")
    if stat.S_ISLNK(st.st_mode) or _is_junction(root) or not stat.S_ISDIR(st.st_mode):
        return _rejected(result, "intake.dir.not_a_directory", "the upload root is not a plain folder")
    root_real = os.path.realpath(root)

    count = 0
    total = 0
    read_total = 0
    seen: dict[str, str] = {}
    candidates: list[tuple[int, str, str, os.stat_result, int]] = []
    stack: list[tuple[Path, str]] = [(root, "")]
    while stack:
        current, rel = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda e: e.name)
        except OSError as exc:
            result.failures.append(failure("intake", "intake.dir.unreadable", f"folder cannot be listed ({exc.strerror})", rel or "."))
            continue
        for entry in entries:
            path = f"{rel}/{entry.name}" if rel else entry.name
            try:
                path = safe_relative_path(path, limits)
            except _Reject as r:
                return _rejected(result, r.code, r.detail, r.path)
            count += 1
            if count > limits.max_entries:
                return _rejected(result, "intake.limit.entries", f"more than {limits.max_entries} entries")
            key = _dup_key(path)
            if key in seen:
                return _rejected(result, "intake.path.duplicate", f"'{path}' occurs more than once (also as '{seen[key]}')", path)
            seen[key] = path
            if entry.is_symlink() or _is_junction(entry):
                result.failures.append(failure("intake", "intake.dir.symlink", "symbolic link or junction; not followed", path))
                continue
            if entry.is_dir(follow_symlinks=False):
                if entry.name.lower() in VENDORED_DIRS:
                    result.failures.append(failure("intake", "intake.vendored_directory_skipped",
                                                   "vendored or generated folder; its files are not read", path))
                else:
                    stack.append((Path(entry.path), path))
                continue
            if not entry.is_file(follow_symlinks=False):
                result.failures.append(failure("intake", "intake.dir.special_file", "not a regular file; not read", path))
                continue
            try:
                st = os.lstat(entry.path)
            except OSError as exc:
                result.failures.append(failure("intake", "intake.dir.unreadable", f"file cannot be read ({exc.strerror})", path))
                continue
            size = st.st_size
            total += size
            if total > limits.max_total_bytes:
                return _rejected(result, "intake.limit.total_size", f"files exceed {limits.max_total_bytes} bytes in total")
            decision = wanted(path)
            if not decision:
                continue
            file_cap = _file_cap(decision, limits)
            if size > file_cap:
                result.failures.append(failure("intake", "intake.limit.file_size",
                                               f"{size} bytes exceeds {file_cap}; not read", path))
                continue
            if st.st_nlink > 1:
                result.failures.append(failure("intake", "intake.dir.hard_link",
                                               "file has more than one hard link and may be a file from outside the upload; not read", path))
                continue
            real = os.path.realpath(entry.path)
            if os.path.commonpath([root_real, real]) != root_real:
                result.failures.append(failure("intake", "intake.dir.outside_root", "resolves outside the upload folder; not read", path))
                continue
            candidates.append((0 if decision is True else 1, path, entry.path, st, file_cap))

    # Manifests first, so code files can never use up the read budget a manifest needs.
    for _, path, full_path, st, file_cap in sorted(candidates, key=lambda x: (x[0], x[1])):
        size = st.st_size
        remaining = limits.max_read_bytes - read_total
        if size > remaining:
            result.failures.append(failure("intake", "intake.limit.read_total",
                                           f"reading this file would exceed the total read limit of {limits.max_read_bytes} bytes; not read", path))
            continue
        cap = min(file_cap, remaining)
        try:
            with open(full_path, "rb") as fh:
                opened = os.fstat(fh.fileno())
                if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                    result.failures.append(failure("intake", "intake.dir.changed_while_reading",
                                                   "file was replaced between the check and the read; not read", path))
                    continue
                content = fh.read(cap + 1)
        except OSError as exc:
            result.failures.append(failure("intake", "intake.dir.unreadable", f"file cannot be read ({exc.strerror})", path))
            continue
        if len(content) > cap:
            code = "intake.limit.file_size" if cap == file_cap else "intake.limit.read_total"
            result.failures.append(failure("intake", code, f"file grew beyond {cap} bytes while being read; not read", path))
            continue
        read_total += len(content)
        result.files.append(UploadedFile(path=path, data=content))
    result.files.sort(key=lambda f: f.path)
    return result


def _is_junction(p) -> bool:
    fn = getattr(p, "is_junction", None)
    if fn is not None:
        try:
            return bool(fn())
        except OSError:
            return True
    return False
