"""Agent 1 steps 3-5: imports in code, install commands in text, Git repository links.

Fixtures are hand-written (tests/fixtures/agent1/code/). Nothing is executed;
the Git fetcher is replaced by recorded in-memory responses; no network.
"""

import io
import os
import socket
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent1_ingestion import (
    FetchResponse, GitLinkError, UploadedFile, classify, extract_files, extract_git, extract_text, parse_repo_url,
)
from multi_agentic_security.agents.agent1_ingestion.code_imports import (
    CodeContext, _js_specifiers, _js_tokens, npm_package_of_specifier, parse_python_code,
)
from multi_agentic_security.agents.agent1_ingestion.git_fetch import check_redirect
from multi_agentic_security.agents.agent1_ingestion.import_map import IMPORT_TO_DISTRIBUTION
from multi_agentic_security.agents.agent1_ingestion.install_commands import parse_install_text
from multi_agentic_security.contracts.pipeline import ExtractionResult

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "agent1" / "code"
T0 = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def codes(r):
    return [f.code for f in r.failures]


def names(r, kind=None):
    return sorted(d.package.name_normalized for d in r.dependencies
                  if d.package and (kind is None or d.source_kind == kind))


def run_files(*pairs, all_paths=()):
    files = [UploadedFile(p, d if isinstance(d, bytes) else d.encode()) for p, d in pairs]
    return extract_files("proj-1", files, all_paths=all_paths, clock=lambda: T0)


@pytest.fixture(scope="module")
def fixture_result():
    files = [UploadedFile(f"proj/{p.name}", p.read_bytes()) for p in sorted(FIX.iterdir())]
    files += [UploadedFile("proj/localpkg/__init__.py", b""), UploadedFile("proj/requirements.txt", b"ujson\n")]
    return extract_files("proj-1", files, all_paths=[f.path for f in files], clock=lambda: T0)


# --------------------------------------------------------------------------- classification

@pytest.mark.parametrize("path,kind", [
    ("a/app.py", "python_code"), ("x.pyw", "python_code"), ("setup.py", None),
    ("web.ts", "javascript_code"), ("c.mjs", "javascript_code"), ("types.d.ts", None),
    ("Dockerfile", "dockerfile"), ("Dockerfile.dev", "dockerfile"), ("api.dockerfile", "dockerfile"),
    ("install.sh", "shell"), ("setup.ps1", "shell"), ("README.md", "markdown"), ("notes.txt", None),
])
def test_classify_code(path, kind):
    assert classify(path) == kind


# --------------------------------------------------------------------------- never executed

def test_fixture_code_is_never_executed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = (FIX / "app.py").read_bytes()
    r = run_files(("app.py", data))
    assert not (tmp_path / "AGENT1_EXECUTED_MARKER").exists()
    assert names(r)  # it was read


def test_no_compile_exec_or_import_of_uploaded_code(monkeypatch):
    import ast
    import builtins
    real_compile = builtins.compile

    def ast_only_compile(source, filename, mode, flags=0, *a, **k):
        # ast.parse calls compile() with PyCF_ONLY_AST: a syntax tree, never a code object.
        assert flags & ast.PyCF_ONLY_AST, "uploaded code compiled to bytecode"
        return real_compile(source, filename, mode, flags, *a, **k)

    monkeypatch.setattr(builtins, "compile", ast_only_compile)
    for fn in ("exec", "eval", "__import__"):
        real = getattr(builtins, fn)
        if fn == "__import__":
            def guarded(name, *a, _real=real, **k):
                assert name not in ("yaml", "numpy", "cv2", "totally_made_up_pkg_xyz"), f"imported {name}"
                return _real(name, *a, **k)
            monkeypatch.setattr(builtins, fn, guarded)
        else:
            monkeypatch.setattr(builtins, fn, lambda *a, _n=fn, **k: (_ for _ in ()).throw(AssertionError(_n)))
    run_files(("app.py", (FIX / "app.py").read_bytes()), ("web.ts", (FIX / "web.ts").read_bytes()))


# --------------------------------------------------------------------------- Python imports

def test_python_mapped_unmapped_and_skipped(fixture_result):
    py = [d for d in fixture_result.dependencies if d.source_path == "proj/app.py"]
    resolved = {d.package.name_normalized for d in py if d.package}
    assert resolved == {"opencv-python", "scikit-learn", "pyyaml", "python-dateutil", "ujson"}
    unresolved = {d.reasons[-1].inputs["candidate"] for d in py if d.package is None}
    assert unresolved == {"numpy", "requests", "totally_made_up_pkg_xyz"}
    assert all(d.extraction_status == "unresolved" and d.dependency_type == "import" for d in py if d.package is None)
    # strings and comments are not imports
    assert not any("not_a_real_import" in d.original_declaration or "also_not_real" in d.original_declaration for d in py)


def test_python_one_record_per_module_with_all_lines(fixture_result):
    req, = [d for d in fixture_result.dependencies if d.source_path == "proj/app.py"
            and d.package is None and d.reasons[-1].inputs.get("candidate") == "requests"]
    assert req.reasons[0].inputs["lines"] == [9, 10] and req.source_line == 9


def test_python_failures_and_notes(fixture_result):
    app = [f for f in fixture_result.failures if f.source_path == "proj/app.py"]
    by = {f.code: f.detail for f in app}
    assert "winreg" in by["a1.code.stdlib_imports"] and "os" in by["a1.code.stdlib_imports"]
    assert "localpkg" in by["a1.code.local_imports"]
    assert "a1.code.dynamic_import" in by


def test_python_conditional_and_manifest_match(fixture_result):
    uj, = [d for d in fixture_result.dependencies if d.source_path == "proj/app.py"
           and d.package and d.package.name_normalized == "ujson"]
    rules = [r.rule_id for r in uj.reasons]
    assert "a1.code.conditional_import" in rules and "a1.code.import_matches_declared_package" in rules


def test_python_mapping_reason_cites_table(fixture_result):
    cv, = [d for d in fixture_result.dependencies if d.package and d.package.name_normalized == "opencv-python"]
    mapped = [r for r in cv.reasons if r.rule_id == "a1.code.import_mapped"][0]
    assert mapped.inputs["table"] == "import_map/1"


@pytest.mark.parametrize("src,code", [
    ("print 'python2'\n", "a1.code.python_syntax_error"),
    ("x = (" * 300 + ")" * 300, "a1.code.python_unparseable"),
])
def test_python_unparseable(src, code):
    r = run_files(("a.py", src))
    assert r.dependencies == [] and (code in codes(r) or "a1.code.python_syntax_error" in codes(r))


def test_python_deeply_nested_ifs_are_walked():
    src = "".join("    " * i + "if x:\n" for i in range(80)) + "    " * 80 + "import cv2\n"
    r = run_files(("deep.py", src))
    assert names(r) == ["opencv-python"]


def test_relative_and_future_imports_produce_no_record():
    r = run_files(("pkg/m.py", "from __future__ import annotations\nfrom . import a\nfrom ..b import c\n"))
    assert r.dependencies == []


def test_import_table_has_no_identity_or_stdlib_entries():
    import sys
    for imp, dist in IMPORT_TO_DISTRIBUTION.items():
        assert imp.lower().replace("_", "-") != dist.lower(), imp
        assert imp not in sys.stdlib_module_names, imp


def test_python_line_offset():
    r = parse_python_code("x.md", "import cv2\n", CodeContext(), line_offset=10)
    assert r.dependencies[0].source_line == 11


# --------------------------------------------------------------------------- JavaScript

def test_js_imports(fixture_result):
    js = [d for d in fixture_result.dependencies if d.source_path == "proj/web.ts"]
    assert {d.package.name_normalized for d in js} == {"express", "lodash", "@scope/side-effect", "@other/pkg", "axios", "chalk"}
    express, = [d for d in js if d.package.name_normalized == "express"]
    assert express.reasons[0].inputs["lines"] == [2, 5]


def test_js_ignores_strings_comments_regex_templates(fixture_result):
    dumped = fixture_result.model_dump_json()
    for fake in ("not-a-real-dep", "also-not-real", "commented-out", "old-dep", "regex-not-real", "left-pad\", \"web"):
        assert f"'{fake}'" not in dumped or fake == "left-pad\", \"web"
    js_names = names(fixture_result, "javascript_code")
    assert not set(js_names) & {"not-a-real-dep", "also-not-real", "commented-out", "old-dep", "regex-not-real"}


def test_js_builtins_and_dynamic(fixture_result):
    web = {f.code: f.detail for f in fixture_result.failures if f.source_path == "proj/web.ts"}
    assert "node:fs/promises" in web["a1.code.node_builtin_imports"] and "path" in web["a1.code.node_builtin_imports"]
    assert "require()" in web["a1.code.dynamic_import"]


@pytest.mark.parametrize("spec,pkg", [
    ("lodash/fp", "lodash"), ("@a/b/c", "@a/b"), ("@a/b", "@a/b"), ("./x", None), ("/abs", None),
    ("#internal", None), ("https://cdn.invalid/x.js", None), ("react", "react"),
])
def test_npm_package_of_specifier(spec, pkg):
    assert npm_package_of_specifier(spec) == pkg


def test_js_tokenizer_unterminated_inputs_do_not_crash():
    for src in ["'unterminated", "`tpl ${ x", "/* open", "require(", "import(", "a / b / c", "x = /[/]/; require('ok')"]:
        _js_specifiers(_js_tokens(src))
    found, _ = _js_specifiers(_js_tokens("x = /[/]/; require('ok')"))
    assert [f[0] for f in found] == ["ok"]


# --------------------------------------------------------------------------- install commands

def test_dockerfile(fixture_result):
    d = [x for x in fixture_result.dependencies if x.source_path == "proj/Dockerfile"]
    assert sorted(x.package.name_normalized for x in d) == ["flask", "gunicorn", "uvicorn"]
    assert all(x.dependency_type == "install_command" and x.source_kind == "install_command_text" for x in d)
    f = {x.code for x in fixture_result.failures if x.source_path == "proj/Dockerfile"}
    assert {"a1.install.unsupported_tool", "a1.install.pipe_to_shell", "a1.install.requirements_file_not_followed"} <= f


def test_shell_script(fixture_result):
    sh = [x for x in fixture_result.dependencies if x.source_path == "proj/setup_env.sh"]
    got = {x.package.name_normalized for x in sh if x.package}
    assert got == {"pip", "internal-tool", "requests-oauthlib", "jest", "typescript", "lodash", "left-pad",
                   "@scope/thing", "create-react-app", "httpx"}
    assert "not-a-command-here" not in got
    tool, = [x for x in sh if x.package and x.package.name_normalized == "internal-tool"]
    assert any("package index" in w for w in tool.warnings)
    cra, = [x for x in sh if x.package and x.package.name_normalized == "create-react-app"]
    assert cra.reasons[0].rule_id == "a1.install.executes_package" and cra.extraction_status == "warning"
    jest, = [x for x in sh if x.package and x.package.name_normalized == "jest"]
    assert any(r.rule_id == "a1.install.dependency_flag" and r.outcome == "dev" for r in jest.reasons)
    assert "tok3n" not in fixture_result.model_dump_json()


@pytest.mark.parametrize("cmd,expected", [
    ("pip install 'requests[socks]>=2' flask", ["flask", "requests"]),
    ("python3 -m pip install -U numpy==1.26.4", ["numpy"]),
    ("py -m pip install pandas", ["pandas"]),
    ("!pip install -q transformers", ["transformers"]),
    ("%pip install torch", ["torch"]),
    ("FOO=1 sudo -E pip install x1", ["x1"]),
    ("cd app && npm ci && npm i -g serve", ["serve"]),
    ("pnpm add -D vitest", ["vitest"]),
    ("yarn add react@18.2.0", ["react"]),
    ("pip install -e git+https://h.invalid/r.git#egg=tool", ["tool"]),
    ("pip install ./dist/pkg-1.0-py3-none-any.whl", []),
    ("echo pip install nope", []),
    ("poetry add rich --group dev", ["rich"]),
    ("pip download not-installed", []),
])
def test_install_command_variants(cmd, expected):
    r = parse_install_text("x.sh", iter([(1, cmd)]))
    got = sorted(d.package.name_normalized for d in r.dependencies if d.package)
    assert got == expected


def test_unclosed_quote_is_a_failure():
    r = parse_install_text("x.sh", iter([(1, "pip install 'oops")]))
    assert r.dependencies == [] and [f.code for f in r.failures] == ["a1.install.unparseable"]


def test_vcs_fragment_is_not_a_shell_comment():
    r = parse_install_text("x.sh", iter([(1, "pip install git+https://h.invalid/r.git#egg=tool")]))
    assert [d.package.name_normalized for d in r.dependencies if d.package] == ["tool"]


# --------------------------------------------------------------------------- Markdown / pasted text

def test_markdown_answer(fixture_result):
    md = [d for d in fixture_result.dependencies if d.source_path == "proj/answer.md"]
    got = [(d.source_kind, d.package.name_normalized if d.package else None) for d in md]
    assert ("install_command_text", "pydantic") in got and ("install_command_text", "express") in got
    assert ("install_command_text", "sentence-transformers") in got
    assert ("install_command_text", "fastapi") in got and ("install_command_text", "uvicorn") in got
    assert ("install_command_text", "untagged-block-pkg") in got and ("install_command_text", "docker-block-pkg") in got
    assert ("javascript_code", "ws") in got and ("python_code", "pillow") in got
    assert ("python_code", "fastapi") in got  # named by an install command in the same answer
    assert ("python_code", None) in got       # hallucinated_helper_lib stays unresolved
    prose = {d.package.name_normalized for d in md if d.package}
    assert not {"it", "to", "get", "going"} & prose


def test_markdown_line_numbers(fixture_result):
    pyd, = [d for d in fixture_result.dependencies if d.package and d.package.name_normalized == "pydantic"]
    assert pyd.source_line == 8
    pil, = [d for d in fixture_result.dependencies if d.package and d.package.name_normalized == "pillow"]
    assert pil.source_line == 17


def test_extract_text_unfenced_python():
    r = extract_text("proj-1", "import cv2\nfrom bs4 import BeautifulSoup\n", clock=lambda: T0)
    assert names(r) == ["beautifulsoup4", "opencv-python"]
    assert {s.kind for s in r.sources} == {"python_code"}


def test_extract_text_nothing_found():
    r = extract_text("proj-1", "Just some prose without code.", clock=lambda: T0)
    assert r.dependencies == [] and "a1.source.no_manifest" in codes(r)


# --------------------------------------------------------------------------- whole result

def test_fixture_result_validates_and_ids_unique(fixture_result):
    again = ExtractionResult.model_validate_json(fixture_result.model_dump_json())
    assert again == fixture_result
    ids = [d.dependency_id for d in fixture_result.dependencies]
    assert len(ids) == len(set(ids)) and all(d.reasons for d in fixture_result.dependencies)


def test_code_file_limits():
    from multi_agentic_security.agents.agent1_ingestion import IntakeLimits, extract_zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(5):
            zf.writestr(f"m{i}.py", "import cv2\n")
    r = extract_zip("proj-1", buf.getvalue(), "u.zip", limits=IntakeLimits(max_code_files=3), clock=lambda: T0)
    assert len(r.dependencies) == 3 and "intake.limit.code_files" in codes(r)
    big = run_files(("big.py", "#" * (3 * 1024 * 1024)))
    assert "a1.source.too_large" in codes(big)


def test_notebook_reported():
    r = run_files(("requirements.txt", "a\n"), all_paths=["nb.ipynb"])
    assert "a1.source.notebook_not_parsed" in codes(r)


# --------------------------------------------------------------------------- Git links

class RecordedFetcher:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    def fetch(self, url, *, max_bytes, timeout):
        self.calls.append((url, max_bytes, timeout))
        if self.error:
            raise self.error
        return self.response


def repo_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("demo-main/requirements.txt", "flask==3.0.0\n")
        zf.writestr("demo-main/app.py", "import cv2\n")
    return buf.getvalue()


def test_git_happy_path():
    f = RecordedFetcher(FetchResponse("https://codeload.github.com/o/demo/zip/refs/heads/main", 200, repo_zip()))
    r = extract_git("proj-1", "https://github.com/o/demo", f, clock=lambda: T0)
    assert f.calls[0][0] == "https://github.com/o/demo/archive/HEAD.zip"
    assert names(r) == ["flask", "opencv-python"]
    src = [s for s in r.sources if s.kind == "git_repository"][0]
    assert src.locator == "https://github.com/o/demo" and src.sha256


def test_git_ref_url():
    ref = parse_repo_url("https://github.com/o/demo.git/tree/release/v1")
    assert (ref.owner, ref.repo, ref.ref) == ("o", "demo", "release/v1")
    assert ref.archive_url == "https://github.com/o/demo/archive/release/v1.zip"


@pytest.mark.parametrize("url,code", [
    ("http://github.com/o/r", "a1.git.invalid_url"),
    ("https://user:tok@github.com/o/r", "a1.git.invalid_url"),
    ("https://github.com:8443/o/r", "a1.git.invalid_url"),
    ("https://gitlab.com/o/r", "a1.git.unsupported_host"),
    ("https://evil.invalid/github.com/o/r", "a1.git.unsupported_host"),
    ("https://github.com/o", "a1.git.invalid_url"),
    ("https://github.com/o/r/blob/main/x.py", "a1.git.invalid_url"),
    ("https://github.com/o/r/tree/../../x", "a1.git.invalid_url"),
    ("https://github.com/o/r?x=1", "a1.git.invalid_url"),
    ("file:///etc/passwd", "a1.git.invalid_url"),
    ("git@github.com:o/r.git", "a1.git.invalid_url"),
])
def test_git_invalid_links_never_fetch(url, code):
    f = RecordedFetcher(FetchResponse("https://github.com/x", 200, repo_zip()))
    r = extract_git("proj-1", url, f, clock=lambda: T0)
    assert f.calls == [] and r.dependencies == [] and codes(r) == [code]
    assert "tok" not in r.model_dump_json()


@pytest.mark.parametrize("error,code", [
    (GitLinkError("a1.git.fetch_error", "timeout"), "a1.git.fetch_error"),
    (GitLinkError("a1.git.too_large", "big"), "a1.git.too_large"),
    (GitLinkError("a1.git.redirect_refused", "evil"), "a1.git.redirect_refused"),
])
def test_git_fetch_failures_are_states(error, code):
    r = extract_git("proj-1", "https://github.com/o/r", RecordedFetcher(error=error), clock=lambda: T0)
    assert r.dependencies == [] and codes(r) == [code]


def test_git_http_status_and_final_url_checked():
    r = extract_git("proj-1", "https://github.com/o/r", RecordedFetcher(FetchResponse("https://github.com/o/r", 404, b"")),
                    clock=lambda: T0)
    assert codes(r) == ["a1.git.http_status"]
    r = extract_git("proj-1", "https://github.com/o/r", RecordedFetcher(FetchResponse("https://evil.invalid/x", 200, repo_zip())),
                    clock=lambda: T0)
    assert codes(r) == ["a1.git.redirect_refused"] and r.dependencies == []


def test_git_hostile_archive_rejected_by_intake():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../escape/requirements.txt", "x\n")
    r = extract_git("proj-1", "https://github.com/o/r",
                    RecordedFetcher(FetchResponse("https://codeload.github.com/o/r/zip/HEAD", 200, buf.getvalue())),
                    clock=lambda: T0)
    assert r.dependencies == [] and "intake.path.traversal" in codes(r)
    assert r.sources[0].kind == "git_repository"


@pytest.mark.parametrize("url,ok", [
    ("https://codeload.github.com/o/r/zip/refs/heads/main", True),
    ("https://github.com/o/r/archive/HEAD.zip", True),
    ("http://codeload.github.com/o/r", False),
    ("https://evil.invalid/x.zip", False),
    ("https://u:p@codeload.github.com/x", False),
])
def test_redirect_allow_list(url, ok):
    if ok:
        check_redirect(url)
    else:
        with pytest.raises(GitLinkError):
            check_redirect(url)


def test_extract_git_requires_explicit_fetcher():
    import inspect
    param = inspect.signature(extract_git).parameters["fetcher"]
    assert param.default is inspect.Parameter.empty
