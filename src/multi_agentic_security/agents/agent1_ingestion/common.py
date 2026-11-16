"""Shared helpers for Agent 1 (dependency extraction).

Uploaded content is untrusted. Everything here works on bytes and text already
in memory: nothing is executed, imported, installed or written to disk.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from multi_agentic_security.contracts.pipeline import (
    DependencyRecord,
    Failure,
    InputSource,
    PackageRef,
    Reason,
    make_dependency_id,
)

STAGE_VERSION = "agent1/0.1"

# Credentials in URLs (``https://user:token@host``) are never copied into
# records, reasons or failures.
# The user-info part runs to the LAST "@" before the host, so passwords that
# contain "@" are removed completely (over-redaction is acceptable).
_URL_USERINFO = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*://)[^/\s]+@")
# Secret-looking environment assignments (GITHUB_TOKEN=..., PIP_PASSWORD=...).
_SECRET_ASSIGN = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|PASS|API_?KEY|AUTH|CREDENTIALS?|PRIVATE_?KEY)[A-Z0-9_]*)=(\S+)")
# npm auth settings (--//registry/:_authToken=..., _auth=..., _password=..., --otp=...).
_NPM_AUTH = re.compile(r"(?i)(_authToken|_auth|_password|--otp)(=|\s+)(\S+)")
# HTTP authorization headers.
_AUTH_HEADER = re.compile(r"(?i)\b(Authorization|Proxy-Authorization|X-API-Key|PRIVATE-TOKEN)(\s*:\s*)(\S+(?:\s+[^\s'\"]+)?)")
# Well-known token formats.
_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|glpat-[A-Za-z0-9_\-]{8,}|"
                    r"npm_[A-Za-z0-9]{8,}|xox[abpr]-[A-Za-z0-9\-]{8,}|sk-[A-Za-z0-9_\-]{16,}|hf_[A-Za-z0-9]{8,}|"
                    r"AKIA[0-9A-Z]{16}|pypi-[A-Za-z0-9_\-]{16,})")


def redact(text: str) -> str:
    """Remove credentials: URL user-info, secret-looking assignments, npm auth settings,
    authorization headers and well-known token formats are replaced with ``***``."""
    text = _URL_USERINFO.sub(lambda m: m.group("scheme") + "***@", text)
    text = _SECRET_ASSIGN.sub(lambda m: m.group(1) + "=***", text)
    text = _NPM_AUTH.sub(lambda m: m.group(1) + m.group(2) + "***", text)
    text = _AUTH_HEADER.sub(lambda m: m.group(1) + m.group(2) + "***", text)
    return _TOKEN.sub("***", text)


MAX_RECORDS_PER_FILE = 5_000
MAX_FAILURES_PER_RULE = 20


def cap_output(path: str, deps: list, failures: list) -> tuple[list, list]:
    """Bound what one file can add to the result; the cut is reported, never silent."""
    notes = []
    if len(deps) > MAX_RECORDS_PER_FILE:
        notes.append(failure("agent1", "a1.source.output_capped",
                             f"{len(deps)} dependency records; only the first {MAX_RECORDS_PER_FILE} are kept", path))
        deps = deps[:MAX_RECORDS_PER_FILE]
    kept, counts = [], {}
    for f in failures:
        counts[f.code] = counts.get(f.code, 0) + 1
        if counts[f.code] <= MAX_FAILURES_PER_RULE:
            kept.append(f)
    for code, n in sorted(counts.items()):
        if n > MAX_FAILURES_PER_RULE:
            notes.append(failure("agent1", "a1.source.output_capped",
                                 f"{n} entries with code {code}; only the first {MAX_FAILURES_PER_RULE} are kept", path))
    return deps, kept + notes


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    return value


def reason(rule_id: str, outcome: str, explanation: str, **inputs: Any) -> Reason:
    """A ``Reason`` whose explanation and string inputs are redacted."""
    return Reason(rule_id=rule_id, outcome=outcome, explanation=redact(explanation), inputs=_redact_value(inputs))


def failure(stage: str, code: str, detail: str, source_path: Optional[str] = None) -> Failure:
    return Failure(stage=stage, code=code, detail=redact(detail), source_path=source_path)


@dataclass(frozen=True)
class UploadedFile:
    """One file of an upload, held in memory. ``path`` is relative and uses ``/``."""

    path: str
    data: bytes


@dataclass
class FileExtraction:
    """What one parser produced for one file."""

    source: InputSource
    dependencies: list[DependencyRecord] = field(default_factory=list)
    failures: list[Failure] = field(default_factory=list)


def package_ref(ecosystem: str, name: str) -> Optional[PackageRef]:
    """Return a ``PackageRef``, or ``None`` when the name cannot be normalized."""
    try:
        return PackageRef.of(ecosystem, name)
    except ValueError:
        return None


def build_record(
    *,
    source_path: str,
    source_kind: str,
    ecosystem: str,
    declaration: str,
    package: Optional[PackageRef],
    dependency_type: str,
    origin: str,
    reasons: list[Reason],
    warnings: list[str],
    source_line: Optional[int] = None,
    constraint_raw: Optional[str] = None,
    constraint_normalized: Optional[str] = None,
    id_key: Optional[str] = None,
) -> DependencyRecord:
    """Build a ``DependencyRecord`` and derive its status from what is known.

    ``unresolved`` when no package could be determined, ``warning`` when there
    are warnings, ``ok`` otherwise. ``id_key`` replaces the declaration in the
    identifier when the declaration alone is not unique (JSON files without
    line numbers).
    """
    declaration = redact(declaration.strip()) or "<empty>"
    warnings = [redact(w) for w in warnings]
    if package is None:
        status = "unresolved"
    elif warnings:
        status = "warning"
    else:
        status = "ok"
    return DependencyRecord(
        dependency_id=make_dependency_id(source_path, source_line, ecosystem, id_key or declaration),
        ecosystem=ecosystem,
        package=package,
        original_declaration=declaration,
        version_constraint_raw=redact(constraint_raw) if constraint_raw else None,
        version_constraint_normalized=constraint_normalized or None,
        dependency_type=dependency_type,
        origin=origin,
        source_kind=source_kind,
        source_path=source_path,
        source_line=source_line,
        extraction_status=status,
        warnings=warnings,
        reasons=reasons,
    )


def decode_text(f: UploadedFile, kind: str, max_bytes: int) -> tuple[InputSource, Optional[str], list[Failure]]:
    """Decode an uploaded manifest as UTF-8 (a BOM is accepted).

    Returns the ``InputSource`` and the text, or ``None`` and a failure when the
    file is too large or not valid UTF-8. Nothing is guessed: a file that is not
    UTF-8 is reported, never silently decoded with another code page.
    """
    source = InputSource(kind=kind, locator=f.path, sha256=sha256_hex(f.data), size_bytes=len(f.data))
    if len(f.data) > max_bytes:
        return source, None, [failure("agent1", "a1.source.too_large",
                                      f"{len(f.data)} bytes exceeds the limit of {max_bytes} bytes; file not parsed", f.path)]
    try:
        text = f.data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        return source, None, [failure("agent1", "a1.source.decode_error",
                                      f"not valid UTF-8 at byte {exc.start}; file not parsed", f.path)]
    if "\x00" in text:
        return source, None, [failure("agent1", "a1.source.binary_content",
                                      "file contains NUL characters; not a text manifest; file not parsed", f.path)]
    return source, text, []
