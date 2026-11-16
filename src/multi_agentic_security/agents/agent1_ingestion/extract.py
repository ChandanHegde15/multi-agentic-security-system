"""Agent 1 entry points: uploaded files, a ZIP archive, a folder or pasted text -> ``ExtractionResult``."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional, Union

from multi_agentic_security.contracts.pipeline import DependencyRecord, ExtractionResult, Failure, InputSource

from .code_imports import CodeContext, local_python_modules, parse_js_code, parse_python_code
from .common import STAGE_VERSION, FileExtraction, UploadedFile, cap_output, decode_text, failure, sha256_hex
from .intake import DEFAULT_LIMITS, IntakeLimits, IntakeResult, is_nested_archive, read_directory, read_zip
from .npm_manifest import parse_package_json, parse_package_lock
from .requirements_txt import parse_requirements
from .text_sources import kind_of_text_file, parse_dockerfile, parse_markdown, parse_shell

Clock = Callable[[], datetime]

# requirements.txt, requirements-dev.txt, dev-requirements.txt, test_requirements.txt,
# requirements.in (pip-tools input, same syntax).
_REQUIREMENTS = re.compile(r"^(?:[^/]*[-_.])?requirements(?:[-_.][^/]*)?\.(?:txt|in)$", re.IGNORECASE)
_CONSTRAINTS = re.compile(r"^(?:[^/]*[-_.])?constraints(?:[-_.][^/]*)?\.txt$", re.IGNORECASE)

MANIFEST_KINDS = ("requirements_txt", "package_json", "package_lock_json")
CODE_KINDS = ("python_code", "javascript_code", "shell", "dockerfile", "markdown")
PY_SUFFIXES = (".py", ".pyw")
JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")

# Manifests that declare dependencies but are not parsed yet (or are out of
# scope, D-047). They are reported so that a user never mistakes "not read"
# for "no dependencies".
UNSUPPORTED_MANIFESTS = frozenset({
    "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "pipfile.lock", "poetry.lock", "uv.lock",
    "pdm.lock", "environment.yml", "environment.yaml", "conda.yaml", "yarn.lock", "pnpm-lock.yaml",
    "bun.lockb", "bun.lock", "pom.xml", "build.gradle", "build.gradle.kts",
})


def manifest_base(path: str) -> str:
    """Base name with trailing dots and spaces removed (Windows drops them on extraction,
    so ``package.json.`` becomes ``package.json``)."""
    return path.rsplit("/", 1)[-1].rstrip(" .")


def classify(path: str) -> Optional[str]:
    """Return what Agent 1 reads ``path`` as, or ``None``.

    Manifests: ``requirements_txt``, ``package_json``, ``package_lock_json``.
    Code and text: ``python_code``, ``javascript_code``, ``shell``, ``dockerfile``, ``markdown``.
    """
    parts = path.split("/")
    base = manifest_base(path)
    low = base.lower()
    if _REQUIREMENTS.match(base):
        return "requirements_txt"
    if low.endswith(".txt") and len(parts) > 1 and parts[-2].lower() == "requirements":
        return "requirements_txt"
    if low == "package.json":
        return "package_json"
    if low in ("package-lock.json", "npm-shrinkwrap.json"):
        return "package_lock_json"
    if low == "setup.py":
        return None  # a manifest, reported as unsupported; never read as code
    if low.endswith(PY_SUFFIXES):
        return "python_code"
    if low.endswith(JS_SUFFIXES) and not low.endswith(".d.ts"):
        return "javascript_code"
    return kind_of_text_file(base)


def _parse_manifest(f: UploadedFile, kind: str, limits: IntakeLimits) -> FileExtraction:
    if kind == "requirements_txt":
        return parse_requirements(f, max_bytes=limits.max_file_bytes)
    if kind == "package_json":
        return parse_package_json(f, max_bytes=limits.max_file_bytes)
    return parse_package_lock(f, max_bytes=limits.max_file_bytes)


def _declared_names(deps: list[DependencyRecord]) -> dict[str, set[str]]:
    declared: dict[str, set[str]] = {"pypi": set(), "npm": set()}
    for d in deps:
        # Manifests and install commands name packages; registry origin only.
        if d.package is not None and d.origin == "registry" and d.dependency_type != "import":
            declared[d.package.ecosystem].add(d.package.name_normalized)
    return declared


def _parse_code(f: UploadedFile, kind: str, ctx: CodeContext, limits: IntakeLimits
                ) -> tuple[list[InputSource], list[DependencyRecord], list[Failure]]:
    sources, deps, failures = _parse_code_uncapped(f, kind, ctx, limits)
    deps, failures = cap_output(f.path, deps, failures)
    return sources, deps, failures


def _parse_code_uncapped(f: UploadedFile, kind: str, ctx: CodeContext, limits: IntakeLimits
                         ) -> tuple[list[InputSource], list[DependencyRecord], list[Failure]]:
    source_kind = {"python_code": "python_code", "javascript_code": "javascript_code"}.get(kind, "install_command_text")
    source, text, failures = decode_text(f, source_kind, limits.max_code_file_bytes)
    if text is None:
        return [source], [], failures
    deps: list[DependencyRecord] = []
    if kind == "python_code":
        res = parse_python_code(f.path, text, ctx)
        return [source], res.dependencies, failures + res.failures
    if kind == "javascript_code":
        res = parse_js_code(f.path, text, ctx)
        return [source], res.dependencies, failures + res.failures
    if kind in ("shell", "dockerfile"):
        res = parse_shell(f.path, text) if kind == "shell" else parse_dockerfile(f.path, text)
        return [source], res.dependencies, failures + res.failures
    md = parse_markdown(f.path, text, ctx)
    for _, c in md.code:
        deps.extend(c.dependencies)
        failures.extend(c.failures)
    for x in md.installs:
        deps.extend(x.dependencies)
        failures.extend(x.failures)
    sources = [InputSource(kind=k, locator=f.path, sha256=sha256_hex(f.data), size_bytes=len(f.data))
               for k in sorted(md.kinds())]
    return sources, deps, failures


def markdown_install_names(f: UploadedFile, limits: IntakeLimits) -> list[tuple[str, str]]:
    """(ecosystem, normalized name) of registry packages named by install commands in a Markdown file."""
    _, text, _ = decode_text(f, "install_command_text", limits.max_code_file_bytes)
    if text is None:
        return []
    md = parse_markdown(f.path, text, CodeContext())
    return [(d.package.ecosystem, d.package.name_normalized) for x in md.installs for d in x.dependencies
            if d.package is not None and d.origin == "registry"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def extract_files(project_id: str, files: Iterable[UploadedFile], *, limits: IntakeLimits = DEFAULT_LIMITS,
                  sources: Iterable[InputSource] = (), failures: Iterable[Failure] = (),
                  all_paths: Iterable[str] = (), clock: Clock = _now) -> ExtractionResult:
    """Parse already-validated in-memory files.

    Manifests are parsed first; their declared names let imports in code be
    attributed to a package (D-050). ``all_paths`` lists every file name of
    the upload (read or not), so that local modules, unsupported manifests and
    nested archives can be recognised.
    """
    started = clock()
    out_sources = list(sources)
    out_failures = list(failures)
    deps: list[DependencyRecord] = []
    files = sorted(files, key=lambda f: f.path)
    unique: list[tuple[UploadedFile, Optional[str]]] = []
    seen_paths: set[str] = set()
    for f in files:
        if f.path in seen_paths:
            out_failures.append(failure("agent1", "a1.source.duplicate_path",
                                        "the same path was supplied more than once; only the first copy was parsed", f.path))
            continue
        seen_paths.add(f.path)
        unique.append((f, classify(f.path)))

    for f, kind in unique:
        if kind in MANIFEST_KINDS:
            parsed = _parse_manifest(f, kind, limits)
            out_sources.append(parsed.source)
            deps.extend(parsed.dependencies)
            out_failures.extend(parsed.failures)

    # Scripts and Dockerfiles next: their install commands also name packages.
    for f, kind in unique:
        if kind in ("shell", "dockerfile"):
            code_sources, code_deps, code_failures = _parse_code(f, kind, CodeContext(), limits)
            out_sources.extend(code_sources)
            deps.extend(code_deps)
            out_failures.extend(code_failures)

    every_path = set(all_paths) | seen_paths
    declared = _declared_names(deps)
    # Install commands in any Markdown file also name packages for imports elsewhere in the upload.
    for f, kind in unique:
        if kind == "markdown":
            for name_eco, name in markdown_install_names(f, limits):
                declared.setdefault(name_eco, set()).add(name)
    ctx = CodeContext(local_python_modules=local_python_modules(every_path), declared=declared)
    for f, kind in unique:
        if kind in MANIFEST_KINDS or kind in ("shell", "dockerfile"):
            continue
        if kind is None:
            out_failures.append(failure("agent1", "a1.source.unsupported_file", "file type is not parsed by Agent 1", f.path))
            continue
        code_sources, code_deps, code_failures = _parse_code(f, kind, ctx, limits)
        out_sources.extend(code_sources)
        deps.extend(code_deps)
        out_failures.extend(code_failures)

    for path in sorted(every_path):
        base = manifest_base(path).lower()
        if base != path.rsplit("/", 1)[-1].lower() and classify(path) is not None:
            out_failures.append(failure("intake", "intake.path.trailing_dot_or_space",
                                        f"file name ends with a dot or space; parsed as '{manifest_base(path)}', "
                                        "which is what Windows would create", path))
        if _CONSTRAINTS.match(base):
            out_failures.append(failure("agent1", "a1.source.constraints_file",
                                        "constraints file: it limits versions but installs nothing by itself; not parsed", path))
        elif base in UNSUPPORTED_MANIFESTS:
            out_failures.append(failure("agent1", "a1.source.unsupported_manifest",
                                        f"'{base}' declares dependencies but is not parsed by this version; "
                                        "its dependencies are not in the result", path))
        elif base.endswith(".ipynb"):
            out_failures.append(failure("agent1", "a1.source.notebook_not_parsed",
                                        "Jupyter notebook: imports and !pip commands in it are not read by this version", path))
        elif is_nested_archive(path):
            out_failures.append(failure("intake", "intake.nested_archive",
                                        "archive inside the upload; not opened", path))
    if not any(s.kind not in ("archive", "directory", "git_repository") for s in out_sources):
        out_failures.append(failure("agent1", "a1.source.no_manifest",
                                    "no supported dependency source (manifest, source code, script, Dockerfile or "
                                    "Markdown with code) was found"))
    return ExtractionResult(project_id=project_id, stage_version=STAGE_VERSION, started_at=started,
                            finished_at=max(clock(), started), sources=out_sources, dependencies=deps,
                            failures=out_failures)


def extract_text(project_id: str, text: str, *, name: str = "pasted.md", clock: Clock = _now,
                 limits: IntakeLimits = DEFAULT_LIMITS) -> ExtractionResult:
    """Pasted text (for example an LLM answer): fenced code, inline commands and unfenced Python."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1] or "pasted.md"
    if classify(base) != "markdown":
        base += ".md"
    return extract_files(project_id, [UploadedFile(base, text.encode("utf-8"))], limits=limits, clock=clock)


def _from_intake(project_id: str, intake: IntakeResult, all_paths: Iterable[str], limits: IntakeLimits,
                 clock: Clock, extra_failures: Iterable[Failure] = ()) -> ExtractionResult:
    if intake.rejected:
        started = clock()
        return ExtractionResult(project_id=project_id, stage_version=STAGE_VERSION, started_at=started,
                                finished_at=max(clock(), started), sources=[intake.source], dependencies=[],
                                failures=intake.failures)
    return extract_files(project_id, intake.files, limits=limits, sources=[intake.source],
                         failures=list(intake.failures) + list(extra_failures), all_paths=all_paths, clock=clock)


class _Selector:
    """Decides which upload files are read; caps the number of code/text files."""

    def __init__(self, limits: IntakeLimits):
        self.limits = limits
        self.paths: list[str] = []
        self.code_files = 0
        self.skipped: list[str] = []

    def __call__(self, path: str):
        """False: not read. True: read first (manifests). An int: read later, with that byte cap (code and text)."""
        self.paths.append(path)
        kind = classify(path)
        if kind in CODE_KINDS:
            if self.code_files >= self.limits.max_code_files:
                self.skipped.append(path)
                return False
            self.code_files += 1
            return self.limits.max_code_file_bytes
        return kind is not None

    def failures(self) -> list[Failure]:
        if not self.skipped:
            return []
        return [failure("intake", "intake.limit.code_files",
                        f"more than {self.limits.max_code_files} code, script or Markdown files; "
                        f"{len(self.skipped)} were not read (first: {self.skipped[0]})")]


def extract_zip(project_id: str, data: bytes, upload_name: str, *, limits: IntakeLimits = DEFAULT_LIMITS,
                clock: Clock = _now, source: Optional[InputSource] = None) -> ExtractionResult:
    select = _Selector(limits)
    intake = read_zip(data, upload_name, select, limits)
    if source is not None:
        intake.source = source
    return _from_intake(project_id, intake, select.paths, limits, clock, select.failures())


def extract_directory(project_id: str, root: Union[str, Path], *, label: Optional[str] = None,
                      limits: IntakeLimits = DEFAULT_LIMITS, clock: Clock = _now) -> ExtractionResult:
    select = _Selector(limits)
    intake = read_directory(root, select, limits, label=label)
    return _from_intake(project_id, intake, select.paths, limits, clock, select.failures())
