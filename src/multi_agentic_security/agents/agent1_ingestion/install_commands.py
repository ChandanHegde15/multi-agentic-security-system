"""Install commands written in text (shell scripts, Dockerfile ``RUN`` lines, code
blocks, pasted text): ``pip install``, ``uv add``, ``poetry add``, ``npm install``,
``yarn add``, ``pnpm add``, ``npx`` and similar.

Commands are split with ``shlex`` and read; they are never executed. Each
package argument becomes an ``install_command`` record, reusing the pip
requirement rules (``requirements_txt.requirement_record``) and the npm
specifier rules (``npm_manifest.classify_spec``).
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Iterator, Optional

from multi_agentic_security.contracts.pipeline import DependencyRecord, Failure

from .common import build_record, failure, package_ref, reason, redact
from .npm_manifest import _SPEC_EXPLANATION, _name_warnings, _valid_npm_name, classify_spec, split_alias
from .requirements_txt import requirement_record

KIND = "install_command_text"

_PROMPT = re.compile(r"^\s*(?:\(\S+\)\s*)?(?:[$>%!]|PS [^>]*>)\s*")
_SHELL_COMMENT = re.compile(r"(?:^|\s)#.*$")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SEPARATORS = {"&&", "||", ";", "|", "&", ";;", "(", ")"}
# Downloading a script and running it: "curl ... | [sudo -E] bash -", "sh -c "$(curl ...)"",
# "bash <(curl ...)", "irm ... | iex", "iex (iwr ...)".
_FETCHERS = r"(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|fetch)"
_RUNNERS = r"(?:sh|bash|zsh|dash|ksh|fish|python\d?(?:\.\d+)?|node|perl|ruby|iex|pwsh|powershell|Invoke-Expression)"
_REMOTE_SCRIPT = [
    re.compile(r"(?i)\b" + _FETCHERS + r"\b[^|]*\|\s*(?:sudo(?:\s+-\S+)*\s+)?(?:env\s+)?" + _RUNNERS + r"\b"),
    re.compile(r"(?i)\b" + _RUNNERS + r"\s+(?:-\S+\s+)*[\"']?\$\(\s*" + _FETCHERS + r"\b"),
    re.compile(r"(?i)(?:\b" + _RUNNERS + r"|\bsource|(?:^|\s)\.)\s+<\(\s*" + _FETCHERS + r"\b"),
    re.compile(r"(?i)\b(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*(?:" + _FETCHERS + r"|New-Object)\b"),
]
MAX_RECORDS_PER_TEXT = 5_000


def runs_remote_script(text: str) -> bool:
    return any(p.search(text) for p in _REMOTE_SCRIPT)

# pip options that take a value (short and long forms)
_PIP_VALUE_OPTS = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url",
    "-f", "--find-links", "--trusted-host", "-t", "--target", "--prefix", "--root", "--platform",
    "--python-version", "--implementation", "--abi", "--only-binary", "--no-binary", "--proxy", "--timeout",
    "--retries", "--cache-dir", "--src", "--progress-bar", "-C", "--config-settings", "--global-option",
    "--upgrade-strategy", "--log", "--report", "--python", "-p", "--group", "--source", "--index",
    "--default-index", "-E", "--extras", "--extra", "--optional",
}
_PIP_SOURCE_OPTS = {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host", "--index",
                    "--default-index", "--source"}
_PIP_SHORT_VALUE = set("rceifCtpE")      # short pip options that take a value (combinable: -qr file)
# npm/yarn/pnpm options that take a value
_NPM_VALUE_OPTS = {"--registry", "--prefix", "--tag", "--cache", "--workspace", "--filter", "--userconfig",
                   "-C", "--dir", "--package", "-p", "--omit", "--include", "--install-strategy", "--before",
                   "--loglevel", "--otp", "--save-prefix", "--network-concurrency", "--modules-folder", "--cwd"}
_NPM_DEV = {"-D", "--save-dev", "--dev", "--development"}
_NPM_OPT = {"-O", "--save-optional", "--optional"}
_NPM_PEER = {"-P", "--save-peer", "--peer"}

UNSUPPORTED_TOOLS = {"conda", "mamba", "micromamba", "apt", "apt-get", "apk", "yum", "dnf", "brew", "gem", "cargo",
                     "go", "composer", "choco", "winget", "easy_install", "bun", "deno"}


@dataclass
class InstallExtraction:
    dependencies: list[DependencyRecord] = field(default_factory=list)
    failures: list[Failure] = field(default_factory=list)


def logical_shell_lines(text: str, start_line: int = 1) -> Iterator[tuple[int, str]]:
    """Join backslash (and PowerShell backtick) continuations; strip prompts and comments."""
    buf: list[str] = []
    first = start_line
    for n, raw in enumerate(text.splitlines(), start=start_line):
        if not buf:
            first = n
        stripped = raw.rstrip()
        if stripped.endswith(("\\", "`")) and not stripped.lstrip().startswith("#"):
            buf.append(stripped[:-1])
            continue
        buf.append(stripped)
        yield first, " ".join(x.strip() for x in buf)
        buf = []
    if buf:
        yield first, " ".join(x.strip() for x in buf)


def dockerfile_run_lines(text: str) -> Iterator[tuple[int, str]]:
    """Shell commands of ``RUN`` instructions (shell form, JSON exec form and ``<<EOF`` heredocs)."""
    raw_lines = text.splitlines()
    heredoc_end: dict[int, int] = {}
    for line_no, line in logical_shell_lines(text):
        if any(a <= line_no <= b for a, b in heredoc_end.items()):
            continue  # inside a heredoc body already yielded
        m = re.match(r"^\s*RUN\s+(.*)$", line, re.IGNORECASE)
        if not m:
            continue
        body = m.group(1).strip()
        body = re.sub(r"^(--[a-z]+=\S+\s+)+", "", body)  # RUN --mount=... flags
        here = re.search(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?", body)
        if here:
            delim, j = here.group(1), line_no
            while j < len(raw_lines) and raw_lines[j].strip() != delim:
                yield j + 1, raw_lines[j]
                j += 1
            heredoc_end[line_no + 1] = j + 1
            rest = body[:here.start()].strip()
            if rest and not re.fullmatch(r"(?:sh|bash|/bin/(?:ba)?sh)(?:\s+-\S+)*", rest):
                yield line_no, rest
            continue
        if body.startswith("["):
            try:
                argv = json.loads(body)
                if isinstance(argv, list) and all(isinstance(a, str) for a in argv):
                    body = " ".join(shlex.quote(a) for a in argv)
            except ValueError:
                pass
        yield line_no, body


def _segments(tokens: list[str]) -> Iterator[list[str]]:
    seg: list[str] = []
    for t in tokens:
        if t in _SEPARATORS:
            if seg:
                yield seg
            seg = []
        else:
            seg.append(t)
    if seg:
        yield seg


def _strip_prefix(seg: list[str]) -> list[str]:
    """Drop ``sudo``, ``env``, ``VAR=value``, ``time``, ``exec`` and notebook ``!`` prefixes."""
    i = 0
    while i < len(seg):
        t = seg[i]
        if t in ("sudo", "env", "time", "exec", "command", "nohup") or _ENV_ASSIGN.match(t) or t.startswith("-") and i and seg[i - 1] == "sudo":
            i += 1
            continue
        break
    out = seg[i:]
    if out and out[0].startswith("!"):
        out = [out[0][1:]] + out[1:]
    return out


def _tool_of(seg: list[str]) -> tuple[Optional[str], list[str]]:
    """Identify the installer and return ``(tool, args after the install verb)``."""
    if not seg:
        return None, []
    cmd = seg[0].rsplit("/", 1)[-1].lower()
    if cmd.endswith(".exe"):
        cmd = cmd[:-4]
    rest = seg[1:]
    if re.fullmatch(r"(python|py)(\d(\.\d+)?)?", cmd) and len(rest) >= 2 and rest[0] == "-m":
        mod = rest[1].lower()
        if mod == "pip" and len(rest) >= 3 and rest[2] == "install":
            return "pip", rest[3:]
        if mod == "pipx" and len(rest) >= 3 and rest[2] in ("install", "run"):
            return "pipx", rest[3:]
        return None, []
    if re.fullmatch(r"pip\d?(\.\d+)?", cmd) and rest[:1] == ["install"]:
        return "pip", rest[1:]
    if cmd == "uv" and rest[:2] == ["pip", "install"]:
        return "pip", rest[2:]
    if cmd == "uv" and rest[:1] == ["add"]:
        return "pip", rest[1:]
    if cmd in ("uvx",) or (cmd == "uv" and rest[:2] == ["tool", "run"]) or (cmd == "uv" and rest[:2] == ["tool", "install"]):
        return "pipx", rest[2:] if cmd == "uv" else rest
    if cmd == "pipx" and rest[:1] and rest[0] in ("install", "run"):
        return "pipx", rest[1:]
    if cmd in ("poetry", "pdm", "hatch", "rye") and rest[:1] == ["add"]:
        return "pip", rest[1:]
    if cmd == "npm" and rest[:1] and rest[0] in ("install", "i", "add", "isntall", "in"):
        return "npm", rest[1:]
    if cmd == "yarn" and rest[:1] == ["add"]:
        return "npm", rest[1:]
    if cmd == "yarn" and rest[:2] == ["global", "add"]:
        return "npm", ["-g"] + rest[2:]
    if cmd == "pnpm" and rest[:1] and rest[0] in ("add", "install", "i"):
        return "npm", rest[1:]
    if cmd in ("npx", "bunx") or (cmd in ("pnpm", "yarn") and rest[:1] == ["dlx"]) or (cmd == "npm" and rest[:1] == ["exec"]):
        return "npx", rest[1:] if cmd in ("pnpm", "yarn", "npm") else rest
    if cmd in UNSUPPORTED_TOOLS and rest[:1] and rest[0] in ("install", "add", "get"):
        return "unsupported:" + cmd, rest[1:]
    return None, []


def parse_install_text(path: str, lines: Iterator[tuple[int, str]]) -> InstallExtraction:
    """Read install commands from ``(line_number, command_text)`` pairs."""
    out = InstallExtraction()
    seen: dict[str, int] = {}
    for line_no, raw in lines:
        text = _PROMPT.sub("", raw, count=1).strip()
        if not text or text.startswith("#"):
            continue
        if len(out.dependencies) >= MAX_RECORDS_PER_TEXT:
            out.failures.append(failure("agent1", "a1.source.output_capped",
                                        f"more than {MAX_RECORDS_PER_TEXT} install-command records; the rest of this "
                                        "text was not read", path))
            break
        if runs_remote_script(text):
            out.failures.append(failure("agent1", "a1.install.pipe_to_shell",
                                        f"line {line_no}: downloads a script and runs it in a shell ('{redact(text)[:160]}'); "
                                        "what it installs cannot be determined without running it", path))
        # A shell comment starts only where "#" begins a word ("x#egg=y" is not a comment).
        text = _SHELL_COMMENT.sub("", text)
        try:
            lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|()")
            lexer.whitespace_split = True
            lexer.commenters = ""
            tokens = list(lexer)
        except ValueError as exc:
            if re.search(r"\b(pip|npm|yarn|pnpm|npx|uv|poetry)\b", text):
                out.failures.append(failure("agent1", "a1.install.unparseable",
                                            f"line {line_no}: command could not be split ({exc}); not read", path))
            continue
        for seg in _segments(tokens):
            tool, args = _tool_of(_strip_prefix(seg))
            if tool is None:
                continue
            command = redact(" ".join(seg))
            if tool.startswith("unsupported:"):
                out.failures.append(failure("agent1", "a1.install.unsupported_tool",
                                            f"line {line_no}: '{tool.split(':', 1)[1]}' installs packages outside PyPI and npm; "
                                            f"not analysed ('{command[:160]}')", path))
                continue
            if tool in ("pip", "pipx"):
                _pip_args(path, line_no, command, args, tool, out, seen)
            else:
                manager = _strip_prefix(seg)[0].rsplit("/", 1)[-1].lower().removesuffix(".exe")
                _npm_args(path, line_no, command, args, tool, out, seen, manager)
    return out


def _id_key(command: str, arg: str, seen: dict[str, int]) -> str:
    key = f"{command}\x1f{arg}"
    seen[key] = seen.get(key, 0) + 1
    return f"{key}#{seen[key]}"


def _command_reason(tool: str, command: str, line_no: int):
    if tool in ("pipx", "npx"):
        return reason("a1.install.executes_package", "runs_package",
                      f"Line {line_no} downloads and RUNS a package ({tool}); it was not run here.",
                      command=command, tool=tool)
    return reason("a1.install.command", "install",
                  f"Line {line_no} installs packages with '{tool}'; the command was read, not run.",
                  command=command, tool=tool)


def _pip_args(path: str, line_no: int, command: str, args: list[str], tool: str,
              out: InstallExtraction, seen: dict[str, int]) -> None:
    positional: list[str] = []
    editable: list[str] = []
    sources: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            positional.extend(args[i + 1:])
            break
        if a.startswith("-"):
            name, eq, val = a.partition("=")
            if not a.startswith("--") and len(a) > 2:
                # Combined short options as optparse reads them: "-qr file", "-Ur file", "-rfile".
                for k, ch in enumerate(a[1:], start=1):
                    if ch in _PIP_SHORT_VALUE:
                        name, val = "-" + ch, a[k + 1:]
                        eq = "=" if val else ""
                        break
                else:
                    i += 1
                    continue  # only boolean flags, e.g. -qU
            if name == "--no-index":
                sources.append("--no-index")
            if name in _PIP_VALUE_OPTS:
                if not eq:
                    i += 1
                    val = args[i] if i < len(args) else ""
                if name in ("-e", "--editable"):
                    editable.append(val)
                elif name in ("-r", "--requirement", "-c", "--constraint"):
                    out.failures.append(failure("agent1", "a1.install.requirements_file_not_followed",
                                                f"line {line_no}: '{name} {redact(val)}' installs from a file; the file is "
                                                "extracted only if it is part of the upload", path))
                elif name in _PIP_SOURCE_OPTS:
                    sources.append(f"{name} {redact(val)}")
            i += 1
            continue
        positional.append(a)
        i += 1
    if sources:
        out.failures.append(failure("agent1", "a1.install.package_source_option",
                                    f"line {line_no}: {'; '.join(sources)} changes where packages are looked up", path))
    index_note = ("this command changes the package index (" + "; ".join(sources)
                  + "); the name may resolve outside the public PyPI index") if sources else None
    base = _command_reason(tool, command, line_no)
    warnings = ["the package is executed by this command, not only installed"] if tool == "pipx" else []
    for target in editable:
        from .requirements_txt import _location_record
        out.dependencies.append(_location_record(path, line_no, command, target, list(warnings), editable=True,
                                                 kind=KIND, dep_type="install_command", extra_reasons=[base],
                                                 id_key=_id_key(command, "-e " + target, seen)))
    for arg in positional:
        if tool == "pipx" and arg in ("--spec",):
            continue
        out.dependencies.append(requirement_record(
            path, line_no, command, arg, list(warnings), index_note=index_note, source_kind=KIND,
            dependency_type="install_command", extra_reasons=(base,), id_key=_id_key(command, arg, seen)))
    if not positional and not editable:
        out.failures.append(failure("agent1", "a1.install.no_packages",
                                    f"line {line_no}: '{command[:160]}' names no package directly", path))


def _npm_args(path: str, line_no: int, command: str, args: list[str], tool: str,
              out: InstallExtraction, seen: dict[str, int], manager: str = "npm") -> None:
    dep_flag = "runtime"
    registry: Optional[str] = None
    global_install = False
    positional: list[str] = []
    runner_packages = False  # npx -p <pkg>: the packages are named by -p, positionals are the command
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            if tool != "npx":
                positional.extend(args[i + 1:])
            break
        if a.startswith("-"):
            name, eq, val = a.partition("=")
            if name in _NPM_DEV:
                dep_flag = "dev"
            elif name in _NPM_OPT:
                dep_flag = "optional"
            elif name in _NPM_PEER:
                dep_flag = "peer"
            elif name in ("-g", "--global", "--location"):
                global_install = True
                if name == "--location" and not eq:
                    i += 1
            elif name == "-w" and manager == "npm":
                if not eq:
                    i += 1  # npm -w <workspace>; for pnpm and yarn, -w is a flag
            elif name in _NPM_VALUE_OPTS:
                if not eq:
                    i += 1
                    val = args[i] if i < len(args) else ""
                if name == "--registry":
                    registry = redact(val)
                elif name in ("--package", "-p") and tool == "npx":
                    positional.append(val)
                    runner_packages = True
            i += 1
            continue
        if not (tool == "npx" and runner_packages):
            positional.append(a)
        i += 1
        if tool == "npx":
            break  # the first positional is the package (or, after -p, the command) to run; the rest are its arguments
    if registry:
        out.failures.append(failure("agent1", "a1.install.package_source_option",
                                    f"line {line_no}: --registry {registry} changes where packages are looked up", path))
    base = _command_reason(tool, command, line_no)
    for spec in positional:
        warnings: list[str] = []
        if tool == "npx":
            warnings.append("the package is executed by this command, not only installed")
        if global_install:
            warnings.append("installed globally (-g)")
        if registry:
            warnings.append(f"this command uses the registry {registry}; the name may not refer to the public npm package")
        out.dependencies.append(_npm_record(path, line_no, command, spec, dep_flag, warnings, base,
                                            _id_key(command, spec, seen)))
    if not positional:
        out.failures.append(failure("agent1", "a1.install.no_packages",
                                    f"line {line_no}: '{command[:160]}' names no package directly (it may install from "
                                    "package.json)", path))


def _npm_record(path: str, line_no: int, command: str, spec: str, dep_flag: str, warnings: list[str],
                base, id_key: str) -> DependencyRecord:
    reasons = [base]
    if dep_flag != "runtime":
        reasons.append(reason("a1.install.dependency_flag", dep_flag, f"The command saves the package as a {dep_flag} dependency."))
    low = spec.lower()
    if low.startswith(("git", "github:", "gitlab:", "bitbucket:", "http://", "https://", "file:", ".", "/", "~")) \
            or low.endswith((".tgz", ".tar.gz", ".tar")):
        origin, rule, _, spec_warnings, _ = classify_spec(spec)
        reasons.append(reason(rule, origin, _SPEC_EXPLANATION[rule], specifier=spec))
        return build_record(source_path=path, source_kind=KIND, ecosystem="npm", declaration=command, source_line=line_no,
                            package=None, dependency_type="install_command", origin=origin, id_key=id_key,
                            warnings=warnings + spec_warnings + ["the package name cannot be determined without fetching (not fetched)"],
                            reasons=reasons)
    name, rng = split_alias(spec)
    alias_target = None
    if rng.lower().startswith("npm:"):
        alias_target, rng = split_alias(rng[4:])
        warnings.append(f"alias: '{name}' installs the package '{alias_target}'")
        name = alias_target
    origin, rule, _, spec_warnings, normalized = classify_spec(rng)
    warnings += spec_warnings
    if not _valid_npm_name(name):
        reasons.append(reason("a1.npm.invalid_name", "unresolved",
                              f"'{name}' is not a valid npm package name, so the package is unresolved.", name=name))
        return build_record(source_path=path, source_kind=KIND, ecosystem="npm", declaration=command, source_line=line_no,
                            package=None, dependency_type="install_command", origin=origin, id_key=id_key,
                            warnings=warnings + [f"invalid npm package name: {name!r}"], reasons=reasons,
                            constraint_raw=rng or None)
    warnings += _name_warnings(name)
    reasons.append(reason(rule, origin, _SPEC_EXPLANATION[rule], specifier=rng or None))
    return build_record(source_path=path, source_kind=KIND, ecosystem="npm", declaration=command, source_line=line_no,
                        package=package_ref("npm", name), dependency_type="install_command", origin=origin,
                        warnings=warnings, reasons=reasons, constraint_raw=rng or None,
                        constraint_normalized=normalized, id_key=id_key)
