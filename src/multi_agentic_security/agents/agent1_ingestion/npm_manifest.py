"""Parsers for ``package.json`` and ``package-lock.json`` / ``npm-shrinkwrap.json``.

Files are parsed with ``json`` only. Lifecycle scripts are never run and
version specifiers are never resolved. JSON has no line numbers in Python's
parser, so records carry ``source_line = None`` and a JSON pointer in their
reasons (D-049). Duplicate keys are kept and flagged, because npm silently
uses the last one.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterator, Optional

from multi_agentic_security.contracts.pipeline import DependencyRecord

from .common import FileExtraction, UploadedFile, build_record, decode_text, failure, package_ref, reason, redact

ECO = "npm"
MAX_LOCK_V1_DEPTH = 64

SECTIONS = {
    "dependencies": "runtime",
    "devDependencies": "dev",
    "optionalDependencies": "optional",
    "peerDependencies": "peer",
}
NOT_INTERPRETED = ("overrides", "resolutions", "bundleDependencies", "bundledDependencies", "workspaces")

_NPM_NAME = re.compile(r"^(?:@[a-z0-9\-~][a-z0-9\-._~]*/)?[a-z0-9\-~][a-z0-9\-._~]*$", re.IGNORECASE)
_EXACT_SEMVER = re.compile(r"^v?=?\s*\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$")
# One comparator of an npm semver range: optional operator, then a full or
# partial version (x/X/* wildcards allowed), optional pre-release and build.
_COMPARATOR = re.compile(
    r"^(?:<=|>=|<|>|=|~>|~|\^)?\s*v?(?:\d+|[xX*])(?:\.(?:\d+|[xX*])){0,2}"
    r"(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$")
_OPERATOR_GAP = re.compile(r"(<=|>=|<|>|=|~>|~|\^)\s+")
_TARBALL_SUFFIX = (".tgz", ".tar.gz", ".tar")
_SCP_GIT = re.compile(r"^[A-Za-z0-9_.\-]+@[A-Za-z0-9_.\-]+:")
_DIST_TAG = re.compile(r"^[A-Za-z][A-Za-z0-9._\-]*$")
_GITHUB_SHORTHAND = re.compile(r"^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+(?:#.*)?$")
_VCS_PREFIX = ("git+", "git://", "github:", "gitlab:", "bitbucket:", "gist:")
_PATH_PREFIX = ("file:", "link:", "./", "../", "/", "~/", "workspace:", "portal:")
DEFAULT_REGISTRY = "https://registry.npmjs.org/"


class _Pairs(list):
    """A JSON object kept as an ordered list of pairs (duplicates preserved)."""

    def get(self, key: str, default: Any = None) -> Any:
        found = default
        for k, v in self:
            if k == key:
                found = v  # last one wins, as in npm
        return found

    def keys(self) -> set[str]:
        return {k for k, _ in self}


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def _load(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_Pairs, parse_constant=_reject_constant)


def _is_semver_range(spec: str) -> bool:
    """True when ``spec`` is a valid-looking npm range (``||`` sets, hyphen ranges, comparators)."""
    for part in spec.split("||"):
        part = _OPERATOR_GAP.sub(lambda m: m.group(1), part.strip())
        if not part:
            return False
        tokens = part.split()
        if len(tokens) == 3 and tokens[1] == "-":
            tokens = [tokens[0], tokens[2]]
        if not all(_COMPARATOR.match(t) for t in tokens):
            return False
    return True


def split_alias(body: str) -> tuple[str, str]:
    """Split ``name@spec`` (after ``npm:``); a scoped name keeps its leading ``@``."""
    at = body.find("@", 1 if body.startswith("@") else 0)
    if at < 0:
        return body, ""
    return body[:at], body[at + 1:]


def _pointer(*parts: str) -> str:
    return "/" + "/".join(p.replace("~", "~0").replace("/", "~1") for p in parts)


def _valid_npm_name(name: str) -> bool:
    return 0 < len(name) <= 214 and _NPM_NAME.match(name) is not None


def _name_warnings(name: str) -> list[str]:
    if name != name.lower():
        return ["npm package names have been lowercase since 2017; uppercase names exist only for legacy packages"]
    return []


def _load_json(f: UploadedFile, kind: str, max_bytes: int) -> tuple[FileExtraction, Optional[Any]]:
    source, text, failures = decode_text(f, kind, max_bytes)
    out = FileExtraction(source=source, failures=failures)
    if text is None:
        return out, None
    try:
        data = _load(text)
    except (ValueError, RecursionError) as exc:
        out.failures.append(failure("agent1", "a1.source.invalid_json", f"not valid JSON ({exc}); file not parsed", f.path))
        return out, None
    if not isinstance(data, _Pairs):
        out.failures.append(failure("agent1", "a1.source.unexpected_structure",
                                    "top-level JSON value is not an object; file not parsed", f.path))
        return out, None
    return out, data


def _report_duplicate_sections(data: _Pairs, keys, out: FileExtraction, path: str) -> None:
    """A repeated top-level section: npm keeps only the last; the earlier ones are reported."""
    counts = _dup_counts(data)
    for key in keys:
        if counts.get(key, 0) > 1:
            earlier = [v for k, v in data if k == key][:-1]
            names = [n for block in earlier if isinstance(block, _Pairs) for n, _ in block]
            shown = ", ".join(names[:20]) + (" ..." if len(names) > 20 else "")
            out.failures.append(failure(
                "agent1", "a1.json.duplicate_section",
                f"'{key}' appears {counts[key]} times; npm uses only the last. The earlier occurrences "
                f"({len(names)} entries: {shown or 'none'}) are not dependency records", path))


def _dup_counts(pairs: _Pairs) -> dict[str, int]:
    counts: dict[str, int] = {}
    for k, _ in pairs:
        counts[k] = counts.get(k, 0) + 1
    return counts


# --------------------------------------------------------------------------- package.json

def classify_spec(spec: str) -> tuple[str, str, Optional[str], list[str], Optional[str]]:
    """Classify an npm dependency specifier.

    Returns ``(origin, rule_id, alias_target, warnings, normalized_constraint)``.
    """
    s = spec.strip()
    low = s.lower()
    if low.startswith("npm:"):
        target, rng = split_alias(s[4:])
        rng = rng.strip()
        if rng and rng not in ("latest", "*") and not _is_semver_range(rng) and not _DIST_TAG.match(rng):
            return ("unknown", "a1.npm.alias", target,
                    ["alias with a specifier that is not a registry range or tag; npm rejects or reinterprets it"], None)
        return "registry", "a1.npm.alias", target, [], (rng or None)
    if low.startswith(("http://", "https://")):
        return "url", "a1.npm.url", None, ["installed from a URL, not from the registry"], None
    if low.startswith(_PATH_PREFIX) or low.endswith(_TARBALL_SUFFIX):
        return "path", "a1.npm.path", None, ["installed from a local path, tarball or workspace, not from the registry"], None
    if low.startswith(_VCS_PREFIX) or _SCP_GIT.match(s) or (_GITHUB_SHORTHAND.match(s) and not s.startswith((".", "@"))):
        return "vcs", "a1.npm.vcs", None, ["installed from a version-control reference, not from the registry"], None
    if s in ("", "*", "x", "X", "latest"):
        return "registry", "a1.npm.unpinned", None, [], (s or None)
    if _EXACT_SEMVER.match(s):
        return "registry", "a1.npm.pinned", None, [], s.lstrip("v=").strip()
    if _is_semver_range(s):
        return "registry", "a1.npm.range", None, [], s
    if _DIST_TAG.match(s):
        return "registry", "a1.npm.dist_tag", None, [], s
    return "unknown", "a1.npm.unrecognized_spec", None, ["specifier not recognised as a range, tag, URL or path"], None


_SPEC_EXPLANATION = {
    "a1.npm.alias": "The key is an alias; npm installs a differently named package.",
    "a1.npm.vcs": "The package is taken from a version-control reference; the registry version is not used.",
    "a1.npm.url": "The package is downloaded from a URL; the registry version is not used.",
    "a1.npm.path": "The package comes from a local path or workspace; the registry version is not used.",
    "a1.npm.unpinned": "No version is fixed, so any (or the latest) version may be installed.",
    "a1.npm.pinned": "The version is pinned to a single release.",
    "a1.npm.range": "A version range is allowed; the installed version is decided at install time.",
    "a1.npm.dist_tag": "A distribution tag is used; the version it points to can change at any time.",
    "a1.npm.unrecognized_spec": "The specifier could not be classified.",
}


def parse_package_json(f: UploadedFile, *, max_bytes: int) -> FileExtraction:
    out, data = _load_json(f, "package_json", max_bytes)
    if data is None:
        return out
    _report_duplicate_sections(data, SECTIONS, out, f.path)
    for key in NOT_INTERPRETED:
        if key in data.keys():
            out.failures.append(failure("agent1", "a1.package_json.field_not_interpreted",
                                        f"'{key}' is present and can change which packages npm installs; it is not interpreted",
                                        f.path))
    for section, dep_type in SECTIONS.items():
        block = data.get(section)
        if block is None:
            continue
        if not isinstance(block, _Pairs):
            out.failures.append(failure("agent1", "a1.package_json.section_not_object",
                                        f"'{section}' is not a JSON object; section not parsed", f.path))
            continue
        counts = _dup_counts(block)
        seen: dict[str, int] = {}
        for name, value in block:
            seen[name] = seen.get(name, 0) + 1
            out.dependencies.append(_package_json_record(f.path, section, dep_type, name, value,
                                                         seen[name], counts[name]))
    return out


def _package_json_record(path: str, section: str, dep_type: str, key: str, value: Any,
                         occurrence: int, total: int) -> DependencyRecord:
    pointer = _pointer(section, key)
    declaration = f"{json.dumps(key)}: {json.dumps(value) if not isinstance(value, _Pairs) else '{...}'}"
    id_key = f"{pointer}#{occurrence}"
    warnings: list[str] = []
    if total > 1:
        warnings.append(f"key appears {total} times in '{section}'; npm uses the last value (this is occurrence {occurrence})")
    base = dict(source_path=path, source_kind="package_json", ecosystem=ECO, declaration=declaration,
                dependency_type=dep_type, id_key=id_key)

    if not isinstance(value, str):
        pkg = package_ref(ECO, key) if _valid_npm_name(key) else None
        return build_record(**base, package=pkg, origin="unknown",
                            warnings=warnings + ["version specifier is not a string"],
                            reasons=[reason("a1.npm.non_string_spec", "unparsed",
                                            "The value is not a string, so no version or origin could be read.",
                                            pointer=pointer, value_type=type(value).__name__)])

    origin, rule, alias_target, spec_warnings, normalized = classify_spec(value)
    warnings += spec_warnings
    reasons = [reason("a1.npm.declared", "dependency", f"'{key}' is declared in '{section}' ({dep_type}).",
                      pointer=pointer, section=section, key=key)]
    name = key
    if alias_target is not None:
        name = alias_target
        warnings.append(f"alias: the key '{key}' installs the package '{alias_target}'")
    if not _valid_npm_name(name):
        reasons.append(reason("a1.npm.invalid_name", "unresolved",
                              f"'{name}' is not a valid npm package name, so the package is unresolved.", name=name))
        return build_record(**base, package=None, origin=origin, reasons=reasons, constraint_raw=value,
                            warnings=warnings + [f"invalid npm package name: {name!r}"])
    warnings += _name_warnings(name)
    reasons.append(reason(rule, origin, _SPEC_EXPLANATION[rule], specifier=redact(value),
                          **({"alias_of": key, "installs": alias_target} if alias_target else {})))
    return build_record(**base, package=package_ref(ECO, name), origin=origin, reasons=reasons, warnings=warnings,
                        constraint_raw=value, constraint_normalized=normalized)


# --------------------------------------------------------------------------- package-lock.json

def _resolved_origin(resolved: Optional[str], link: bool) -> tuple[str, list[str]]:
    if link:
        return "path", ["linked local package (workspace or file dependency), not from the registry"]
    if not resolved:
        return "registry", []
    low = resolved.lower()
    if low.startswith(DEFAULT_REGISTRY):
        return "registry", []
    if low.startswith(("git+", "git://", "github:")):
        return "vcs", ["resolved from a version-control reference, not from the registry"]
    if low.startswith("file:") or not ("://" in low):
        return "path", ["resolved from a local path, not from the registry"]
    return "url", [f"resolved from a non-default registry or URL ({redact(resolved)}); the name may not refer to the public npm package"]


def _lock_type(entry: _Pairs) -> tuple[str, list]:
    if entry.get("peer") is True:
        return "peer", []
    if entry.get("dev") is True:
        return "dev", []
    if entry.get("devOptional") is True:
        return "dev", [reason("a1.package_lock.dev_optional", "dev",
                              "Marked devOptional: installed for development, and optionally at run time.")]
    if entry.get("optional") is True:
        return "optional", []
    return "runtime", []


def _lock_record(path: str, kind: str, pointer: str, name: str, entry: _Pairs, warnings: list[str],
                 occurrence: int = 1) -> DependencyRecord:
    version = entry.get("version")
    link = entry.get("link") is True
    resolved = entry.get("resolved") if isinstance(entry.get("resolved"), str) else None
    dep_type, extra_reasons = _lock_type(entry)
    reasons = [reason("a1.package_lock.entry", "dependency",
                      f"The lockfile records '{name}' as installed ({dep_type}).", pointer=pointer)]
    reasons += extra_reasons
    origin, origin_warnings = _resolved_origin(resolved, link)
    warnings = list(warnings) + origin_warnings
    normalized: Optional[str] = None
    if isinstance(version, str) and version.lower().startswith("npm:"):
        # lockfile v1 alias: "version": "npm:real-name@1.2.3"
        real, version = split_alias(version[4:])
        version = version or None
        warnings.append(f"alias: '{name}' is installed from the package '{real}'")
        name = real
    if isinstance(version, str) and _EXACT_SEMVER.match(version):
        normalized = version.lstrip("v=").strip()
        reasons.append(reason("a1.package_lock.version", "exact_version", f"Installed version {normalized}.", version=version))
    elif isinstance(version, str):
        warnings.append(f"lockfile version is not a plain semantic version: {version}")
        if origin == "registry" and ("://" in version or version.startswith(("git", "file:"))):
            origin = "vcs" if version.startswith("git") else ("path" if version.startswith("file:") else "url")
    elif version is not None:
        warnings.append(f"lockfile version is not a string ({type(version).__name__}); ignored")
    elif not link:
        warnings.append("no version recorded for this entry")
    if entry.get("inBundle") is True or entry.get("bundled") is True:
        reasons.append(reason("a1.package_lock.bundled", "bundled",
                              "Shipped inside its parent package's tarball rather than fetched on its own."))
    if entry.get("hasInstallScript") is True:
        reasons.append(reason("a1.package_lock.install_script_declared", "install_script",
                              "The lockfile says this package runs an install script; it was not run."))
    if entry.get("integrity") is None and not link and origin in ("registry", "url"):
        reasons.append(reason("a1.package_lock.no_integrity", "no_integrity",
                              "No integrity hash is recorded, so the downloaded content is not pinned."))
    valid = _valid_npm_name(name)
    if valid:
        warnings += _name_warnings(name)
    else:
        warnings.append(f"invalid npm package name: {name!r}")
        reasons.append(reason("a1.npm.invalid_name", "unresolved",
                              f"'{name}' is not a valid npm package name, so the package is unresolved.", name=name))
    declaration = f"{pointer.lstrip('/')} {version if isinstance(version, str) else ''}".strip()
    return build_record(
        source_path=path, source_kind=kind, ecosystem=ECO, declaration=declaration, id_key=f"{pointer}#{occurrence}",
        package=package_ref(ECO, name) if valid else None, dependency_type=dep_type, origin=origin,
        warnings=warnings, reasons=reasons,
        constraint_raw=version if isinstance(version, str) else None, constraint_normalized=normalized)


def _name_from_lock_path(key: str) -> Optional[str]:
    marker = "node_modules/"
    idx = key.rfind(marker)
    if idx < 0:
        return None
    return key[idx + len(marker):] or None


def parse_package_lock(f: UploadedFile, *, max_bytes: int) -> FileExtraction:
    out, data = _load_json(f, "package_lock_json", max_bytes)
    if data is None:
        return out
    _report_duplicate_sections(data, ("packages", "dependencies"), out, f.path)
    lock_version = data.get("lockfileVersion")
    packages = data.get("packages")
    if isinstance(packages, _Pairs):
        _parse_lock_packages(f.path, packages, out)
    elif isinstance(data.get("dependencies"), _Pairs):
        for pointer, name, entry, occ, total in _walk_lock_v1(data.get("dependencies"), ("dependencies",), 0, out, f.path):
            warnings = [f"key appears {total} times; npm uses the last value"] if total > 1 else []
            out.dependencies.append(_lock_record(f.path, "package_lock_json", pointer, name, entry, warnings, occ))
    else:
        out.failures.append(failure("agent1", "a1.package_lock.no_entries",
                                    f"lockfileVersion {lock_version!r}: neither 'packages' nor 'dependencies' is an object; "
                                    "no dependencies read", f.path))
    if lock_version not in (1, 2, 3):
        out.failures.append(failure("agent1", "a1.package_lock.unknown_version",
                                    f"lockfileVersion {lock_version!r} is not 1, 2 or 3; parsed on a best-effort basis", f.path))
    return out


def _parse_lock_packages(path: str, packages: _Pairs, out: FileExtraction) -> None:
    counts = _dup_counts(packages)
    seen: dict[str, int] = {}
    workspace_entries = 0
    for key, entry in packages:
        seen[key] = seen.get(key, 0) + 1
        if key == "":
            continue  # the project itself
        pointer = _pointer("packages", key)
        if not isinstance(entry, _Pairs):
            out.failures.append(failure("agent1", "a1.package_lock.entry_not_object",
                                        f"entry {pointer} is not a JSON object; not read", path))
            continue
        name = _name_from_lock_path(key)
        if name is None:
            workspace_entries += 1
            continue
        warnings: list[str] = []
        if counts[key] > 1:
            warnings.append(f"key appears {counts[key]} times; npm uses the last value")
        real = entry.get("name")
        if isinstance(real, str) and real and real != name:
            warnings.append(f"alias: installed at '{key}' from the package '{real}'")
            name = real
        out.dependencies.append(_lock_record(path, "package_lock_json", pointer, name, entry, warnings, seen[key]))
    if workspace_entries:
        out.failures.append(failure("agent1", "a1.package_lock.workspace_entries",
                                    f"{workspace_entries} entries are local workspace folders (not under node_modules/); "
                                    "they are the project's own packages and are not dependency records", path))


def _walk_lock_v1(block: _Pairs, prefix: tuple[str, ...], depth: int, out: FileExtraction,
                  path: str) -> Iterator[tuple[str, str, _Pairs, int, int]]:
    if depth > MAX_LOCK_V1_DEPTH:
        out.failures.append(failure("agent1", "a1.package_lock.too_deep",
                                    f"nesting deeper than {MAX_LOCK_V1_DEPTH} levels at {_pointer(*prefix)}; not read further", path))
        return
    counts = _dup_counts(block)
    seen: dict[str, int] = {}
    for name, entry in block:
        seen[name] = seen.get(name, 0) + 1
        parts = prefix + (name,)
        if not isinstance(entry, _Pairs):
            out.failures.append(failure("agent1", "a1.package_lock.entry_not_object",
                                        f"entry {_pointer(*parts)} is not a JSON object; not read", path))
            continue
        yield _pointer(*parts), name, entry, seen[name], counts[name]
        nested = entry.get("dependencies")
        if isinstance(nested, _Pairs):
            yield from _walk_lock_v1(nested, parts + ("dependencies",), depth + 1, out, path)
