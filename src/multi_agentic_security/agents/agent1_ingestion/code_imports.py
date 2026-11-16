"""Package imports in generated or uploaded source code (Python and JavaScript/TypeScript).

The code is never executed, compiled to bytecode, imported or evaluated:

- Python is parsed with ``ast.parse`` (syntax tree only).
- JavaScript/TypeScript is read with a small tokenizer that skips comments,
  strings, template literals and regular-expression literals; there is no JS
  engine.

Python import names map to packages only through the documented table in
``import_map.py`` or when the upload's own manifest declares a package of the
same normalized name; other third-party imports stay ``unresolved`` with the
import name kept as a candidate in the reasons (D-047, D-050). JavaScript
specifiers are npm package names, so they need no table.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from typing import Iterable, Optional

from multi_agentic_security.contracts.pipeline import DependencyRecord, Failure
from multi_agentic_security.datasets.names import normalize_name

from .common import build_record, failure, package_ref, reason
from .import_map import IMPORT_MAP_VERSION, IMPORT_TO_DISTRIBUTION
from .npm_manifest import _valid_npm_name

PY_STDLIB = frozenset(sys.stdlib_module_names) | {"__future__", "__main__"}
STDLIB_SOURCE = f"sys.stdlib_module_names (Python {sys.version_info.major}.{sys.version_info.minor})"

NODE_BUILTINS = frozenset({
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto", "dgram",
    "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https", "inspector", "module",
    "net", "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline", "repl", "stream",
    "string_decoder", "sys", "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi",
    "worker_threads", "zlib",
})  # "test", "sqlite" and "sea" are built-ins only as "node:test" etc.; without the prefix they are npm packages


@dataclass
class CodeContext:
    """What the rest of the upload tells us, used to resolve or skip imports."""

    local_python_modules: frozenset[str] = frozenset()
    declared: dict[str, set[str]] = field(default_factory=lambda: {"pypi": set(), "npm": set()})


@dataclass
class CodeExtraction:
    dependencies: list[DependencyRecord] = field(default_factory=list)
    failures: list[Failure] = field(default_factory=list)


def local_python_modules(paths: Iterable[str]) -> frozenset[str]:
    """Module names defined by the upload itself: ``x.py`` files and folders with ``__init__.py``.

    Folders without ``__init__.py`` do not count, so an example folder named
    ``requests/`` cannot hide a real (or hallucinated) ``import requests``.
    """
    names: set[str] = set()
    for p in paths:
        parts = p.split("/")
        if parts[-1] == "__init__.py" and len(parts) > 1:
            names.add(parts[-2])
        elif parts[-1].endswith(".py"):
            names.add(parts[-1][:-3])
    names.discard("__init__")
    return frozenset(n for n in names if n.isidentifier())


# --------------------------------------------------------------------------- Python

@dataclass
class _PyImport:
    module: str
    line: int
    kind: str          # "import", "from", "dynamic"
    conditional: bool


def _python_imports(tree: ast.AST) -> tuple[list[_PyImport], list[tuple[int, str]]]:
    found: list[_PyImport] = []
    dynamic_unknown: list[tuple[int, str]] = []
    guards = (ast.Try, ast.If, getattr(ast, "TryStar", ast.Try))
    stack: list[tuple[ast.AST, bool]] = [(tree, False)]
    while stack:  # iterative walk: deep trees cannot exhaust the Python stack here
        node, cond = stack.pop()
        child_cond = cond or isinstance(node, guards)
        stack.extend((child, child_cond) for child in ast.iter_child_nodes(node))
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append(_PyImport(alias.name, node.lineno, "import", cond))
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                found.append(_PyImport(node.module, node.lineno, "from", cond))
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None
            if name in ("__import__", "import_module"):
                arg = node.args[0] if node.args else None
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value and not arg.value.startswith("."):
                    found.append(_PyImport(arg.value, node.lineno, "dynamic", cond))
                elif not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                    dynamic_unknown.append((node.lineno, name))
    return found, dynamic_unknown


def parse_python_code(path: str, text: str, ctx: CodeContext, *, line_offset: int = 0) -> CodeExtraction:
    """Extract package imports from Python source. ``line_offset`` shifts lines for code blocks."""
    out = CodeExtraction()
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as exc:
        out.failures.append(failure("agent1", "a1.code.python_syntax_error",
                                    f"line {(exc.lineno or 0) + line_offset}: not valid Python 3 ({exc.msg}); "
                                    "imports not read", path))
        return out
    except (RecursionError, MemoryError, ValueError) as exc:
        out.failures.append(failure("agent1", "a1.code.python_unparseable",
                                    f"Python source could not be parsed ({type(exc).__name__}); imports not read", path))
        return out

    try:
        imports, dynamic_unknown = _python_imports(tree)
    except RecursionError:
        out.failures.append(failure("agent1", "a1.code.python_unparseable",
                                    "syntax tree too deep to walk; imports not read", path))
        return out
    for line, fn in dynamic_unknown:
        out.failures.append(failure("agent1", "a1.code.dynamic_import",
                                    f"line {line + line_offset}: {fn}() with a computed name; the module cannot be "
                                    "determined without running the code", path))

    first: dict[str, list[_PyImport]] = {}
    for imp in imports:
        top = imp.module.split(".", 1)[0]
        first.setdefault(top, []).append(imp)

    stdlib = sorted(t for t in first if t in PY_STDLIB)
    local = sorted(t for t in first if t not in PY_STDLIB and t in ctx.local_python_modules)
    if stdlib:
        out.failures.append(failure("agent1", "a1.code.stdlib_imports",
                                    f"standard-library modules ({STDLIB_SOURCE}), not packages: {', '.join(stdlib)}", path))
    if local:
        out.failures.append(failure("agent1", "a1.code.local_imports",
                                    f"modules defined inside the upload, not packages: {', '.join(local)}", path))

    for top, occ in first.items():
        if top in PY_STDLIB or top in ctx.local_python_modules:
            continue
        out.dependencies.append(_python_record(path, top, occ, ctx, line_offset))
    return out


def _python_record(path: str, top: str, occ: list[_PyImport], ctx: CodeContext, line_offset: int) -> DependencyRecord:
    occ = sorted(occ, key=lambda i: i.line)
    head = occ[0]
    line = head.line + line_offset
    lines = [i.line + line_offset for i in occ]
    declaration = (f"import {head.module}" if head.kind == "import"
                   else f"from {head.module} import ..." if head.kind == "from"
                   else f"import_module({head.module!r})")
    reasons = [reason("a1.code.python_import", "import",
                      f"The code imports the module '{top}' (first at line {line}).",
                      module=top, lines=lines, statement=head.kind)]
    warnings: list[str] = []
    if any(i.kind == "dynamic" for i in occ):
        warnings.append("imported dynamically with a literal name")
    if all(i.conditional for i in occ):
        reasons.append(reason("a1.code.conditional_import", "conditional",
                              "Every import of this module is inside an if/try block, so it may be optional."))

    mapped = IMPORT_TO_DISTRIBUTION.get(top)
    norm_top = normalize_name("pypi", top)
    declared = ctx.declared.get("pypi", set())
    pkg = None
    if norm_top in declared:
        # What the upload itself installs wins over the table: "serial" and "pyserial" are different packages.
        pkg = package_ref("pypi", top)
        reasons.append(reason("a1.code.import_matches_declared_package", "mapped",
                              f"A manifest or install command in the same upload names a package '{top}', so the "
                              "import is attributed to it.", candidate=top))
        if mapped is not None and normalize_name("pypi", mapped) != norm_top:
            warnings.append(f"the import table maps '{top}' to '{mapped}', but the upload installs a package named "
                            f"'{top}'; these are different packages")
    elif mapped is not None:
        pkg = package_ref("pypi", mapped)
        reasons.append(reason("a1.code.import_mapped", "mapped",
                              f"The import name '{top}' is provided by the distribution '{mapped}' "
                              f"according to the documented table {IMPORT_MAP_VERSION}.",
                              table=IMPORT_MAP_VERSION, distribution=mapped))
    else:
        reasons.append(reason("a1.code.import_unmapped", "unresolved",
                              f"'{top}' is not in the documented import table and no manifest in the upload declares it, "
                              "so the package that provides it is undetermined. The import name is kept as a candidate "
                              "only.", candidate=top, table=IMPORT_MAP_VERSION))
        warnings.append(f"package for import '{top}' undetermined (candidate name '{top}', not verified)")
    return build_record(
        source_path=path, source_kind="python_code", ecosystem="pypi", declaration=declaration, source_line=line,
        package=pkg, dependency_type="import", origin="registry" if pkg else "unknown",
        warnings=warnings, reasons=reasons, id_key=f"python-import:{top}")


# --------------------------------------------------------------------------- JavaScript / TypeScript

@dataclass
class _Tok:
    kind: str   # "id", "str", "punct", "tmpl", "regex"
    value: str
    line: int
    regex_ok: bool = False   # for ")": a "/" right after it starts a regex (closing "if (...)" etc.)


_REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%<>~^") | {""}
_REGEX_KEYWORDS = {"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await"}
_PAREN_REGEX_KEYWORDS = {"if", "while", "for", "with"}
MAX_TEMPLATE_DEPTH = 8


def _js_tokens(src: str, line: int = 1, depth: int = 0) -> list[_Tok]:
    """Tokenize enough of JS/TS to find import specifiers. Never evaluates anything.

    Template-literal expressions (``${...}``) are tokenized too, so a
    ``require()`` inside them is seen; nesting is limited.
    """
    toks: list[_Tok] = []
    parens: list[bool] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += src.count("\n", i, j)
            i = j
        elif c in "'\"":
            j, buf, start_line = i + 1, [], line
            while j < n and src[j] != c and src[j] != "\n":
                if src[j] == "\\" and j + 1 < n:
                    if src[j + 1] == "\n":
                        line += 1  # line continuation inside a string
                    buf.append(src[j + 1])
                    j += 2
                    continue
                buf.append(src[j])
                j += 1
            toks.append(_Tok("str", "".join(buf), start_line))
            i = j + 1 if j < n and src[j] == c else j  # an unterminated string leaves its newline to be counted
        elif c == "`":
            j, start_line, plain = i + 1, line, True
            while j < n and src[j] != "`":
                if src[j] == "\\":
                    if j + 1 < n and src[j + 1] == "\n":
                        line += 1
                    j += 2
                    continue
                if src.startswith("${", j):
                    plain = False
                    k, braces = j + 2, 1
                    while k < n and braces:
                        if src[k] == "{":
                            braces += 1
                        elif src[k] == "}":
                            braces -= 1
                        k += 1
                    inner = src[j + 2:k - 1] if braces == 0 else src[j + 2:k]
                    if depth < MAX_TEMPLATE_DEPTH:
                        toks.extend(_js_tokens(inner, line, depth + 1))
                    line += inner.count("\n")
                    j = k
                    continue
                if src[j] == "\n":
                    line += 1
                j += 1
            toks.append(_Tok("str" if plain else "tmpl", src[i + 1:j] if plain else "", start_line))
            i = j + 1
        elif c == "/":
            prev = toks[-1] if toks else None
            if prev is None or (prev.kind == "punct" and (prev.value in _REGEX_PRECEDERS or prev.regex_ok)) or \
                    (prev.kind == "id" and prev.value in _REGEX_KEYWORDS):
                j, in_class = i + 1, False
                while j < n and src[j] != "\n":
                    ch = src[j]
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == "[":
                        in_class = True
                    elif ch == "]":
                        in_class = False
                    elif ch == "/" and not in_class:
                        break
                    j += 1
                if j < n and src[j] == "/":
                    j += 1
                    while j < n and src[j].isalnum():
                        j += 1
                toks.append(_Tok("regex", "", line))
                i = j  # an unterminated regex leaves its newline to be counted
            else:
                toks.append(_Tok("punct", "/", line))
                i += 1
        elif c.isalpha() or c in "_$":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            toks.append(_Tok("id", src[i:j], line))
            i = j
        else:
            tok = _Tok("punct", c, line)
            if c == "(":
                prev = toks[-1] if toks else None
                parens.append(prev is not None and prev.kind == "id" and prev.value in _PAREN_REGEX_KEYWORDS)
            elif c == ")":
                tok.regex_ok = parens.pop() if parens else False
            toks.append(tok)
            i += 1
    return toks


def _js_specifiers(toks: list[_Tok]) -> tuple[list[tuple[str, int, str]], list[tuple[int, str]]]:
    """Return ``([(specifier, line, form)], [(line, form) of non-literal loads])``."""
    found: list[tuple[str, int, str]] = []
    dynamic: list[tuple[int, str]] = []
    pending_from = False
    for k, t in enumerate(toks):
        prev = toks[k - 1] if k else None
        nxt = toks[k + 1] if k + 1 < len(toks) else None
        after_dot = prev is not None and prev.kind == "punct" and prev.value == "."
        if t.kind == "id" and t.value in ("import", "export") and not after_dot:
            if t.value == "import" and nxt is not None and nxt.kind == "punct" and nxt.value == "(":
                arg = toks[k + 2] if k + 2 < len(toks) else None
                close = toks[k + 3] if k + 3 < len(toks) else None
                if arg is not None and arg.kind == "str" and close is not None and close.value in (")", ","):
                    found.append((arg.value, t.line, "dynamic_import"))
                else:
                    dynamic.append((t.line, "import()"))
                continue
            if t.value == "import" and nxt is not None and nxt.kind == "str":
                found.append((nxt.value, t.line, "import"))
                continue
            if nxt is not None and nxt.kind == "punct" and nxt.value == ".":
                continue  # import.meta
            pending_from = True
        elif t.kind == "id" and t.value == "from" and pending_from and nxt is not None and nxt.kind == "str":
            found.append((nxt.value, nxt.line, "import"))
            pending_from = False
        elif t.kind == "punct" and t.value == ";":
            pending_from = False
        elif t.kind == "id" and t.value == "require" and not after_dot and nxt is not None and nxt.value == "(":
            arg = toks[k + 2] if k + 2 < len(toks) else None
            close = toks[k + 3] if k + 3 < len(toks) else None
            if arg is not None and arg.kind == "str" and close is not None and close.value == ")":
                found.append((arg.value, t.line, "require"))
            else:
                dynamic.append((t.line, "require()"))
    return found, dynamic


def npm_package_of_specifier(spec: str) -> Optional[str]:
    """``lodash/fp`` -> ``lodash``; ``@a/b/c`` -> ``@a/b``; relative, absolute, URL, ``#``, ``node:`` -> None."""
    if not spec or spec.startswith((".", "/", "#", "~")) or ":" in spec.split("/", 1)[0]:
        return None
    parts = spec.split("/")
    if spec.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 else spec
    return parts[0]


def parse_js_code(path: str, text: str, ctx: CodeContext, *, line_offset: int = 0) -> CodeExtraction:
    out = CodeExtraction()
    try:
        toks = _js_tokens(text)
    except RecursionError:
        out.failures.append(failure("agent1", "a1.code.js_unparseable", "source could not be tokenized; imports not read", path))
        return out
    specs, dynamic = _js_specifiers(toks)
    if len(dynamic) > 20:
        out.failures.append(failure("agent1", "a1.source.output_capped",
                                    f"{len(dynamic)} computed require()/import() calls; only the first 20 are listed", path))
        dynamic = dynamic[:20]
    for line, form in dynamic:
        out.failures.append(failure("agent1", "a1.code.dynamic_import",
                                    f"line {line + line_offset}: {form} with a computed specifier; the package cannot be "
                                    "determined without running the code", path))
    grouped: dict[str, list[tuple[str, int, str]]] = {}
    builtins: set[str] = set()
    for spec, line, form in specs:
        if spec.startswith("node:") or spec.split("/", 1)[0] in NODE_BUILTINS:
            builtins.add(spec)
            continue
        name = npm_package_of_specifier(spec)
        if name is None:
            continue  # relative or absolute path inside the project
        grouped.setdefault(name, []).append((spec, line, form))
    if builtins:
        out.failures.append(failure("agent1", "a1.code.node_builtin_imports",
                                    f"Node.js built-in modules, not packages: {', '.join(sorted(builtins))}", path))
    for name, occ in grouped.items():
        occ.sort(key=lambda o: o[1])
        spec, line, form = occ[0]
        line += line_offset
        reasons = [reason("a1.code.js_import", "import",
                          f"The code loads '{spec}' ({form}), which is provided by the npm package '{name}'.",
                          specifier=spec, lines=[o[1] + line_offset for o in occ], form=form)]
        warnings: list[str] = []
        if any(o[2] == "dynamic_import" for o in occ):
            warnings.append("loaded with a dynamic import() of a literal specifier")
        if normalize_name("npm", name) in ctx.declared.get("npm", set()):
            reasons.append(reason("a1.code.import_matches_declared_package", "declared",
                                  f"A manifest or install command in the same upload names '{name}'."))
        pkg = None
        if _valid_npm_name(name):
            pkg = package_ref("npm", name)
        else:
            warnings.append(f"invalid npm package name: {name!r}")
            reasons.append(reason("a1.npm.invalid_name", "unresolved",
                                  f"'{name}' is not a valid npm package name, so the package is unresolved.", name=name))
        declaration = (f"require({spec!r})" if form == "require" else f"import({spec!r})" if form == "dynamic_import"
                       else f"import ... from {spec!r}")
        out.dependencies.append(build_record(
            source_path=path, source_kind="javascript_code", ecosystem="npm", declaration=declaration, source_line=line,
            package=pkg, dependency_type="import", origin="registry" if pkg else "unknown",
            warnings=warnings, reasons=reasons, id_key=f"js-import:{name}"))
    return out
