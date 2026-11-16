"""Code and commands embedded in text: Markdown files, pasted LLM answers.

Fenced code blocks are dispatched by their language tag: Python blocks to the
Python import reader, JavaScript/TypeScript blocks to the JS reader, shell and
Dockerfile blocks to the install-command reader. Untagged blocks are scanned
for install commands and, if they parse as Python, for Python imports.
Outside blocks, only inline code spans and lines with a shell prompt
(``$ pip install x``) are read. Other lines that merely start with an
installer ("pip install the latest version") are reported, not turned into
packages, because prose words would otherwise become package names.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Iterator, Optional

from .code_imports import CodeContext, CodeExtraction, parse_js_code, parse_python_code
from .common import failure, redact
from .install_commands import InstallExtraction, dockerfile_run_lines, logical_shell_lines, parse_install_text

PY_TAGS = {"python", "py", "python3", "py3", "ipython", "ipython3", "pycon", "sage"}
JS_TAGS = {"js", "javascript", "jsx", "ts", "typescript", "tsx", "mjs", "cjs", "node", "nodejs", "es6"}
SHELL_TAGS = {"bash", "sh", "shell", "console", "zsh", "terminal", "shell-session", "powershell", "ps1", "pwsh",
              "cmd", "bat", "batch", "fish"}
DOCKER_TAGS = {"dockerfile", "docker"}

_FENCE = re.compile(r"^(?P<indent> {0,3})(?P<fence>`{3,}|~{3,})\s*(?P<info>[^`]*)$")
_INLINE = re.compile(r"`([^`\n]+)`")
_TOOL_START = re.compile(r"^\s*(?:[$>%!]\s*)?(?:sudo\s+)?(?:pip\d?(?:\.\d+)?|python\d?(?:\.\d+)?\s+-m\s+pip|py\s+-m\s+pip|uv|uvx|pipx|poetry|"
                         r"npm|npx|yarn|pnpm|bunx)\s+\S")


@dataclass
class Block:
    tag: str            # lower-case first word of the info string, "" when untagged
    start_line: int     # line number of the first line of content
    text: str


def fenced_blocks(text: str) -> tuple[list[Block], list[tuple[int, str]]]:
    """Return fenced blocks and the remaining ``(line_number, line)`` pairs outside them."""
    blocks: list[Block] = []
    outside: list[tuple[int, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = _FENCE.match(lines[i])
        if not m:
            outside.append((i + 1, lines[i]))
            i += 1
            continue
        fence = m.group("fence")
        tag = (m.group("info").strip().split() or [""])[0].lower().strip("{}.")
        body: list[str] = []
        j = i + 1
        while j < len(lines):
            close = lines[j].strip()
            if close.startswith(fence[0] * len(fence)) and set(close) == {fence[0]}:
                break
            body.append(lines[j])
            j += 1
        blocks.append(Block(tag=tag, start_line=i + 2, text="\n".join(body)))
        i = j + 1
    return blocks, outside


_PROMPTED = re.compile(r"^\s*(?:\(\S+\)\s*)?(?:\$|>|PS [^>]*>)\s+")


def _loose_command_lines(outside: list[tuple[int, str]], skipped: list[tuple[int, str]]) -> Iterator[tuple[int, str]]:
    for n, line in outside:
        spans = _INLINE.findall(line)
        for span in spans:
            if _TOOL_START.match(span):
                yield n, span
        bare = line.strip()
        if _PROMPTED.match(bare) and _TOOL_START.match(_PROMPTED.sub("", bare, count=1)):
            yield n, bare
        elif not spans and _TOOL_START.match(bare):
            skipped.append((n, bare))


def _looks_like_python_with_imports(text: str) -> bool:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    return any(isinstance(n, (ast.Import, ast.ImportFrom)) for n in ast.walk(tree))


@dataclass
class TextExtraction:
    code: list[tuple[str, CodeExtraction]]          # (source kind, extraction)
    installs: list[InstallExtraction]

    def kinds(self) -> set[str]:
        found = {k for k, c in self.code if c.dependencies or c.failures}
        if any(x.dependencies or x.failures for x in self.installs):
            found.add("install_command_text")
        return found


def parse_markdown(path: str, text: str, ctx: CodeContext) -> TextExtraction:
    blocks, outside = fenced_blocks(text)
    result = TextExtraction(code=[], installs=[])
    offset_of = lambda b: b.start_line - 1  # noqa: E731  (block line 1 = file line start_line)
    # Install commands first, so that imports in the same text can be attributed to the packages they name.
    for b in blocks:
        if b.tag in PY_TAGS:
            result.installs.append(parse_install_text(path, (
                (n, ln) for n, ln in logical_shell_lines(b.text, b.start_line) if ln.lstrip().startswith(("!", "%"))
            )))
        elif b.tag in SHELL_TAGS or b.tag in ("", "text", "txt", "plaintext"):
            result.installs.append(parse_install_text(path, logical_shell_lines(b.text, b.start_line)))
        elif b.tag in DOCKER_TAGS:
            shifted = ((n + offset_of(b), ln) for n, ln in dockerfile_run_lines(b.text))
            result.installs.append(parse_install_text(path, shifted))
    skipped: list[tuple[int, str]] = []
    result.installs.append(parse_install_text(path, _loose_command_lines(outside, skipped)))
    if skipped:
        note = InstallExtraction()
        for n, line in skipped[:20]:
            note.failures.append(failure("agent1", "a1.install.prose_line_not_read",
                                         f"line {n}: '{redact(line)[:120]}' looks like an install command but is plain text "
                                         "(no code formatting or shell prompt); not read, so that words are not taken as "
                                         "package names", path))
        result.installs.append(note)
    declared = {eco: set(names) for eco, names in ctx.declared.items()}
    for x in result.installs:
        for d in x.dependencies:
            if d.package is not None and d.origin == "registry":
                declared.setdefault(d.package.ecosystem, set()).add(d.package.name_normalized)
    ctx = CodeContext(local_python_modules=ctx.local_python_modules, declared=declared)
    for b in blocks:
        if b.tag in PY_TAGS:
            # Notebook-style "!pip install x" / "%pip install x" lines are commands, not Python;
            # blank them (keeping line numbers) before parsing the rest as Python.
            py_text = "\n".join("" if ln.lstrip().startswith(("!", "%")) else ln for ln in b.text.split("\n"))
            result.code.append(("python_code", parse_python_code(path, py_text, ctx, line_offset=offset_of(b))))
        elif b.tag in JS_TAGS:
            result.code.append(("javascript_code", parse_js_code(path, b.text, ctx, line_offset=offset_of(b))))
        elif b.tag in ("", "text", "txt", "plaintext") and _looks_like_python_with_imports(b.text):
            result.code.append(("python_code", parse_python_code(path, b.text, ctx, line_offset=offset_of(b))))
    if not blocks and _looks_like_python_with_imports(text):
        # Pasted code without fences.
        result.code.append(("python_code", parse_python_code(path, text, ctx)))
    return result


def parse_shell(path: str, text: str) -> InstallExtraction:
    return parse_install_text(path, logical_shell_lines(text))


def parse_dockerfile(path: str, text: str) -> InstallExtraction:
    return parse_install_text(path, dockerfile_run_lines(text))


def dockerfile_name(base: str) -> bool:
    low = base.lower()
    return low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile") or low == "containerfile"


def kind_of_text_file(base: str) -> Optional[str]:
    low = base.lower()
    if dockerfile_name(base):
        return "dockerfile"
    if low.endswith((".sh", ".bash", ".zsh", ".ps1")):
        return "shell"
    if low.endswith((".md", ".markdown")):
        return "markdown"
    return None
