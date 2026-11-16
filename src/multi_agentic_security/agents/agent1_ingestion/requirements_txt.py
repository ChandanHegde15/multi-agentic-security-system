"""Parser for pip requirements files (``requirements*.txt``).

The file is read as text only. Requirement strings are parsed with
``packaging.requirements.Requirement`` (PEP 508). pip options are recognised
but never acted on: ``-r``/``-c`` includes are not followed, index URLs are not
contacted, environment variables are not expanded and markers are not
evaluated. Every non-empty, non-comment line ends up either as a dependency
record or as a failure entry; nothing is dropped silently.
"""

from __future__ import annotations

import re
from typing import Iterator, Optional

from packaging.requirements import InvalidRequirement, Requirement

from multi_agentic_security.contracts.pipeline import DependencyRecord

from .common import FileExtraction, UploadedFile, build_record, decode_text, failure, package_ref, reason, redact

KIND = "requirements_txt"
ECO = "pypi"

# pip strips comments that start a line or follow whitespace ("pkg  # note").
_COMMENT = re.compile(r"(^|\s+)#.*$")
# Per-requirement options start at the first whitespace followed by "--" or "-X".
_REQ_OPTIONS = re.compile(r"\s+(?=--?[A-Za-z])")
_ENV_VAR = re.compile(r"\$\{[A-Za-z0-9_]+\}")
_EGG = re.compile(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)")
_NAME_AND_EXTRAS = re.compile(r"^\s*[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[[^\]]*\])?\s*")
_VCS_PREFIX = ("git+", "hg+", "svn+", "bzr+")
_ARCHIVE_SUFFIX = (".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar")

INCLUDE_OPTIONS = {"-r", "--requirement", "-c", "--constraint"}
EDITABLE_OPTIONS = {"-e", "--editable"}
# Options that make pip resolve names somewhere other than (or besides) PyPI.
SOURCE_OPTIONS = {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host", "--no-index"}
OTHER_GLOBAL_OPTIONS = {
    "--pre", "--prefer-binary", "--only-binary", "--no-binary", "--require-hashes",
    "--use-feature", "--global-option", "--config-settings", "-C",
}


def _logical_lines(text: str) -> Iterator[tuple[int, str, bool]]:
    """Yield ``(first_line_number, joined_text, unterminated)``.

    Mirrors pip's ``join_lines``: a line ending in a backslash is joined to
    the next line with no separator (``evil\\`` + ``pkg`` is ``evilpkg``), and
    a comment line ends a continuation. A continuation that runs into the end
    of the file is flagged.
    """
    buf: list[str] = []
    start = 0
    for number, line in enumerate(text.splitlines(), start=1):
        is_comment = _COMMENT.match(line) is not None
        if not line.endswith("\\") or is_comment:
            if is_comment:
                line = " " + line  # keeps the comment strippable after joining
            if buf:
                buf.append(line)
                yield start, "".join(buf), False
                buf = []
            else:
                yield number, line, False
        else:
            if not buf:
                start = number
            buf.append(line.strip("\\"))
    if buf:
        yield start, "".join(buf), True


def _origin_of_url(url: str) -> str:
    low = url.lower()
    if low.startswith(_VCS_PREFIX):
        return "vcs"
    if low.startswith("file:"):
        return "path"
    if "://" in low:
        return "url"
    return "path"


def _looks_like_location(text: str) -> bool:
    low = text.lower()
    return (
        "://" in low
        or low.startswith(_VCS_PREFIX)
        or low.startswith((".", "/", "~", "file:"))
        or re.match(r"^[a-z]:[\\/]", low) is not None
        or low.endswith(_ARCHIVE_SUFFIX)
    )


_SHORT_WITH_VALUE = {"-r", "-c", "-e", "-i", "-f", "-C"}


def _split_option(line: str) -> tuple[str, str]:
    """Split an option line into ``(option, value)`` as pip's optparse would.

    Handles ``-r file``, ``-rfile``, ``--requirement=file`` and
    ``--requirement file``.
    """
    token, _, rest = line.partition(" ")
    rest = rest.strip()
    if token.startswith("--"):
        name, eq, value = token.partition("=")
        return name, (value + (" " + rest if rest else "")).strip() if eq else rest
    if len(token) > 2 and token[:2] in _SHORT_WITH_VALUE:
        return token[:2], (token[2:].lstrip("=") + (" " + rest if rest else "")).strip()
    return token, rest


def _option_name(line: str) -> str:
    return _split_option(line)[0]


def parse_requirements(f: UploadedFile, *, max_bytes: int) -> FileExtraction:
    source, text, failures = decode_text(f, KIND, max_bytes)
    out = FileExtraction(source=source, failures=failures)
    if text is None:
        return out

    lines = [(n, _COMMENT.sub("", joined).strip(), unterminated) for n, joined, unterminated in _logical_lines(text)]
    # An alternative index anywhere in the file affects every name in it.
    file_sources = [ln for _, ln, _ in lines if ln.startswith("-") and _option_name(ln) in SOURCE_OPTIONS]
    for line_no, line, unterminated in lines:
        if not line:
            continue
        warnings: list[str] = []
        if unterminated:
            warnings.append("line continuation ('\\') runs into the end of the file")
        if _ENV_VAR.search(line):
            warnings.append("contains an environment variable that pip would expand at install time; not expanded here")

        if line.startswith("-"):
            opt, target = _split_option(line)
            if opt in EDITABLE_OPTIONS:
                out.dependencies.append(_location_record(f.path, line_no, line, target, warnings, editable=True))
            elif opt in INCLUDE_OPTIONS:
                out.failures.append(failure(
                    "agent1", "a1.requirements.include_not_followed",
                    f"line {line_no}: '{redact(line)}' refers to another file; it is not followed. "
                    "The referenced file is extracted only if it is part of the upload", f.path))
            elif opt in SOURCE_OPTIONS:
                out.failures.append(failure(
                    "agent1", "a1.requirements.package_source_option",
                    f"line {line_no}: '{redact(line)}' changes where pip looks for packages; names in this file may "
                    "resolve outside the public PyPI index. Not contacted", f.path))
            elif opt in OTHER_GLOBAL_OPTIONS:
                out.failures.append(failure(
                    "agent1", "a1.requirements.global_option",
                    f"line {line_no}: pip option '{redact(line)}' recorded, not interpreted", f.path))
            else:
                out.failures.append(failure(
                    "agent1", "a1.requirements.unknown_option",
                    f"line {line_no}: unrecognised option line '{redact(line)}'; not interpreted", f.path))
            continue

        req_text, *option_parts = _REQ_OPTIONS.split(line, maxsplit=1)
        options = option_parts[0] if option_parts else ""
        hashes = len(re.findall(r"--hash[=\s]", options))
        other_options = re.sub(r"--hash[=\s]+\S+", "", options).strip()
        if other_options:
            warnings.append(f"per-requirement options not interpreted: {other_options}")

        out.dependencies.append(requirement_record(
            f.path, line_no, line, req_text, warnings, hashes=hashes,
            index_note=("this file changes the package index (" + "; ".join(redact(x) for x in file_sources)
                        + "); the name may resolve outside the public PyPI index") if file_sources else None))
    return out


def requirement_record(path: str, line_no: int, declaration: str, req_text: str, warnings: list[str], *,
                       hashes: int = 0, index_note: Optional[str] = None, source_kind: str = KIND,
                       dependency_type: str = "runtime", extra_reasons: tuple = (),
                       id_key: Optional[str] = None) -> DependencyRecord:
    """One pip requirement string -> record (shared by requirements files and install commands)."""
    ctx = dict(kind=source_kind, dep_type=dependency_type, extra_reasons=list(extra_reasons), id_key=id_key)
    # A wheel or sdist file name is a valid PEP 508 name to ``packaging``,
    # but pip installs it as a local archive file.
    # ("name @ url" stays a named direct reference.)
    bare = req_text.split(";", 1)[0].strip()
    if "@" not in bare and bare.lower().endswith(_ARCHIVE_SUFFIX):
        return _location_record(path, line_no, declaration, req_text, warnings, editable=False, **ctx)
    try:
        req = Requirement(req_text)
    except InvalidRequirement as exc:
        if _looks_like_location(req_text):
            return _location_record(path, line_no, declaration, req_text, warnings, editable=False, **ctx)
        return build_record(
            source_path=path, source_kind=source_kind, ecosystem=ECO, declaration=declaration, source_line=line_no,
            package=None, dependency_type=dependency_type, origin="unknown", id_key=id_key,
            warnings=warnings + [f"not a valid PEP 508 requirement: {str(exc).splitlines()[0]}"],
            reasons=list(extra_reasons) + [reason("a1.requirements.unparseable", "unresolved",
                                                  "The text could not be parsed as a requirement, so no package name was determined.",
                                                  line=line_no, text=redact(req_text), error=str(exc).splitlines()[0])])
    if index_note and not req.url:
        warnings = warnings + [index_note]
    return _requirement_record(path, line_no, declaration, req_text, req, hashes, warnings, **ctx)


def _requirement_record(path: str, line_no: int, line: str, req_text: str, req: Requirement,
                        hashes: int, warnings: list[str], *, kind: str = KIND, dep_type: str = "runtime",
                        extra_reasons: Optional[list] = None, id_key: Optional[str] = None) -> DependencyRecord:
    pkg = package_ref(ECO, req.name)
    warnings = list(warnings)
    reasons = list(extra_reasons or []) + [reason("a1.requirements.parsed", "dependency",
                      f"Line {line_no} declares the PyPI package '{req.name}'.",
                      line=line_no, name=req.name, extras=sorted(req.extras), hashes=hashes)]
    origin = "registry"
    raw: Optional[str] = None
    normalized: Optional[str] = None
    if req.url:
        origin = _origin_of_url(req.url)
        warnings.append(f"installed from a direct {origin} reference, not from the registry")
        reasons.append(reason("a1.requirements.direct_reference", origin,
                              "The package is taken from a direct reference; the registry version is not used.",
                              url=redact(req.url)))
    else:
        spec_part = _NAME_AND_EXTRAS.sub("", req_text.split(";", 1)[0], count=1).strip()
        raw = spec_part or None
        normalized = str(req.specifier) or None
        specs = list(req.specifier)
        if not specs:
            reasons.append(reason("a1.requirements.unpinned", "any_version",
                                  "No version is given, so any version from the index may be installed.", specifier=None))
        elif len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
            reasons.append(reason("a1.requirements.pinned", "exact_version",
                                  f"The version is pinned to {specs[0].version}.", specifier=normalized))
        else:
            reasons.append(reason("a1.requirements.range", "version_range",
                                  f"A version range ({normalized}) is allowed; the installed version is decided at install time.",
                                  specifier=normalized))
    if req.marker is not None:
        reasons.append(reason("a1.requirements.marker", "conditional",
                              "The requirement applies only when its environment marker is true; the marker is not evaluated.",
                              marker=str(req.marker)))
    return build_record(
        source_path=path, source_kind=kind, ecosystem=ECO, declaration=line, source_line=line_no,
        package=pkg, dependency_type=dep_type, origin=origin, warnings=warnings, reasons=reasons,
        constraint_raw=raw, constraint_normalized=normalized, id_key=id_key)


def _location_record(path: str, line_no: int, line: str, target: str, warnings: list[str], *, editable: bool,
                     kind: str = KIND, dep_type: str = "runtime", extra_reasons: Optional[list] = None,
                     id_key: Optional[str] = None) -> DependencyRecord:
    """A requirement given as a URL, VCS link or local path (optionally ``-e``)."""
    origin = _origin_of_url(target)
    egg = _EGG.search(target)
    pkg = None
    if egg:
        # Legacy "#egg=name-1.0": the part from the first "-<digit>" is a version.
        egg_name = re.split(r"-(?=\d)", egg.group(1), maxsplit=1)[0]
        if egg_name != egg.group(1):
            warnings = warnings + [f"'#egg={egg.group(1)}' includes a version; the name is taken as '{egg_name}'"]
        pkg = package_ref(ECO, egg_name)
    rule = "a1.requirements.editable" if editable else "a1.requirements.location"
    label = "editable install" if editable else "location"
    if pkg is not None:
        warnings = warnings + [f"{label} from a {origin} reference, not from the registry; name taken from '#egg='"]
        explanation = (f"Line {line_no} installs '{pkg.name_raw}' from a {origin} reference; the name comes from the "
                       "'#egg=' fragment and is not checked against the referenced content.")
        outcome = "dependency"
    else:
        warnings = warnings + [f"{label} from a {origin} reference; the package name cannot be determined without fetching it (not fetched)"]
        explanation = f"Line {line_no} refers to a {origin} reference without a package name, so the package is unresolved."
        outcome = "unresolved"
    return build_record(
        source_path=path, source_kind=kind, ecosystem=ECO, declaration=line, source_line=line_no,
        package=pkg, dependency_type=dep_type, origin=origin, warnings=warnings, id_key=id_key,
        reasons=list(extra_reasons or []) + [reason(rule, outcome, explanation, line=line_no, target=redact(target))])
