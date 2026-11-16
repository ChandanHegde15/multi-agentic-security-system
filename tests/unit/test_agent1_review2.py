"""Regression tests for the second Agent 1 review (steps 3-5, 2026-11-16).

Hand-written inputs only; no network; nothing executed.
"""

import http.client
import io
import socket
import zipfile
from datetime import datetime, timezone

import pytest

from multi_agentic_security.agents.agent1_ingestion import (
    FetchResponse, IntakeLimits, UploadedFile, extract_files, extract_git, extract_text, extract_zip,
)
from multi_agentic_security.agents.agent1_ingestion.code_imports import _js_specifiers, _js_tokens, local_python_modules
from multi_agentic_security.agents.agent1_ingestion.common import redact
from multi_agentic_security.agents.agent1_ingestion.git_fetch import GitLinkError, _AllowListRedirects
from multi_agentic_security.agents.agent1_ingestion.install_commands import (
    dockerfile_run_lines, parse_install_text, runs_remote_script,
)

T0 = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def run(*pairs, all_paths=()):
    files = [UploadedFile(p, d if isinstance(d, bytes) else d.encode()) for p, d in pairs]
    return extract_files("proj-1", files, all_paths=all_paths, clock=lambda: T0)


def codes(r):
    return [f.code for f in r.failures]


def pkgs(r, path=None):
    return sorted(d.package.name_normalized for d in r.dependencies
                  if d.package and (path is None or d.source_path == path))


def install(cmd):
    r = parse_install_text("x.sh", iter([(1, cmd)]))
    return sorted(d.package.name_normalized for d in r.dependencies if d.package), [f.code for f in r.failures]


# 1. output caps

def test_flood_of_dynamic_imports_is_capped():
    r = run(("a.js", "import(x);" * 5000))
    assert codes(r).count("a1.code.dynamic_import") <= 20 and "a1.source.output_capped" in codes(r)


def test_flood_of_install_commands_is_capped():
    text = "\n".join(f"$ pip install pkg{i}" for i in range(6000))
    r = run(("README.md", text))
    assert len(r.dependencies) <= 5000 and "a1.source.output_capped" in codes(r)


# 2. fetcher exceptions become states

class Raising:
    def __init__(self, exc):
        self.exc = exc

    def fetch(self, url, *, max_bytes, timeout):
        raise self.exc


@pytest.mark.parametrize("exc", [http.client.IncompleteRead(b""), RuntimeError("boom"), ValueError("x")])
def test_any_fetcher_exception_is_fetch_error(exc):
    r = extract_git("proj-1", "https://github.com/o/r", Raising(exc), clock=lambda: T0)
    assert codes(r) == ["a1.git.fetch_error"] and r.dependencies == []


def test_oversized_or_bogus_fetch_response():
    class Big:
        def fetch(self, url, *, max_bytes, timeout):
            return FetchResponse("https://codeload.github.com/o/r", 200, b"x" * (max_bytes + 1))

    class Bogus:
        def fetch(self, url, *, max_bytes, timeout):
            return "not a response"

    lim = IntakeLimits(max_upload_bytes=100)
    assert codes(extract_git("p", "https://github.com/o/r", Big(), limits=lim, clock=lambda: T0)) == ["a1.git.too_large"]
    assert codes(extract_git("p", "https://github.com/o/r", Bogus(), clock=lambda: T0)) == ["a1.git.fetch_error"]


def test_redirect_handler_refuses_other_hosts():
    handler = _AllowListRedirects()
    with pytest.raises(GitLinkError):
        handler.redirect_request(None, None, 302, "Found", {}, "https://evil.invalid/x.zip")


# 3. declared package wins over the table

def test_manifest_package_wins_over_import_table():
    r = run(("requirements.txt", "serial\njwt\n"), ("a.py", "import serial\nimport jwt\n"))
    a = [d for d in r.dependencies if d.source_path == "a.py"]
    assert sorted(d.package.name_normalized for d in a) == ["jwt", "serial"]
    assert all(any("different packages" in w for w in d.warnings) for d in a)


def test_table_used_when_upload_declares_nothing():
    assert pkgs(run(("a.py", "import serial\n"))) == ["pyserial"]


# 4. prose is not read as packages

@pytest.mark.parametrize("prose", ["pip install the latest version", "npm install it globally",
                                   "pip install the package and restart"])
def test_prose_lines_are_reported_not_records(prose):
    r = extract_text("proj-1", f"Some answer.\n{prose}\nMore text.", clock=lambda: T0)
    assert r.dependencies == [] and "a1.install.prose_line_not_read" in codes(r)


def test_prompted_and_inline_lines_are_read():
    r = extract_text("proj-1", "$ pip install fastapi\nRun `npm i express` first.\n", clock=lambda: T0)
    assert pkgs(r) == ["express", "fastapi"]


# 5. credential redaction

@pytest.mark.parametrize("text,secret", [
    ("GITHUB_TOKEN=ghp_SECRET123456 pip install foo", "SECRET123456"),
    ("npm install bar --//registry.npmjs.org/:_authToken=npm_SECRETXYZ12", "SECRETXYZ12"),
    ("curl -H 'Authorization: token ghp_LEAKLEAK123' https://x.invalid/i.sh | sh", "LEAKLEAK123"),
    ("PIP_PASSWORD=hunter2hunter pip install x", "hunter2hunter"),
    ("export HF_TOKEN=hf_abcdefgh12345", "abcdefgh12345"),
    ("npm publish --otp 123456", "123456"),
])
def test_redaction_of_secrets(text, secret):
    assert secret not in redact(text)
    r = parse_install_text("x.sh", iter([(1, text)]))
    dumped = "".join(d.model_dump_json() for d in r.dependencies) + "".join(f.model_dump_json() for f in r.failures)
    assert secret not in dumped


# 6. remote scripts

@pytest.mark.parametrize("cmd", [
    "curl -fsSL https://deb.nodesource.invalid/setup_18.x | sudo -E bash -",
    'sh -c "$(curl -fsSL https://x.invalid/install.sh)"',
    "bash <(curl -s https://x.invalid/i.sh)",
    "irm https://x.invalid/install.ps1 | iex",
    "iex (iwr https://x.invalid/i.ps1)",
    "wget -qO- https://x.invalid/i.sh | python3",
])
def test_remote_script_forms(cmd):
    assert runs_remote_script(cmd)
    _, fails = install(cmd)
    assert "a1.install.pipe_to_shell" in fails


def test_not_a_remote_script():
    assert not runs_remote_script("curl -o file.tgz https://x.invalid/f.tgz && tar xzf file.tgz")


# 7. local modules

def test_folder_without_init_does_not_hide_imports():
    assert "requests" not in local_python_modules(["examples/requests/demo.py", "app.py"])
    assert "mypkg" in local_python_modules(["src/mypkg/__init__.py"])
    assert "helpers" in local_python_modules(["helpers.py"])
    r = run(("examples/requests/demo.py", ""), ("app.py", "import requests\n"))
    assert any(d.source_path == "app.py" for d in r.dependencies)


# low-severity items

@pytest.mark.parametrize("cmd,expected", [
    ("pip install -qr requirements.txt", []),
    ("pip install -Ur reqs.txt flask", ["flask"]),
    ("pip install -qU flask", ["flask"]),
    ("npx -p typescript tsc --init", ["typescript"]),
    ("pnpm add -w lodash", ["lodash"]),
    ("npm install -w packages/a lodash", ["lodash"]),
    ("npm install --omit dev express", ["express"]),
])
def test_flag_parsing(cmd, expected):
    got, _ = install(cmd)
    assert got == expected


def test_no_index_reported():
    _, fails = install("pip install --no-index --find-links ./wheels x")
    assert "a1.install.package_source_option" in fails
    _, fails = install("pip install --no-index x")
    assert "a1.install.package_source_option" in fails


def test_node_prefix_only_builtins():
    r = run(("a.js", "import sqlite from 'sqlite';\nconst t = require('test');\nimport s from 'node:sqlite';\n"))
    assert pkgs(r) == ["sqlite", "test"]
    assert "node:sqlite" in [f.detail for f in r.failures if f.code == "a1.code.node_builtin_imports"][0]


def test_dockerfile_heredoc():
    text = "FROM x\nRUN <<EOF\npip install evilpkg\nnpm i leftpad2\nEOF\nRUN pip install after\n"
    lines = list(dockerfile_run_lines(text))
    assert (3, "pip install evilpkg") in lines and any("after" in t for _, t in lines)
    r = run(("Dockerfile", text))
    assert pkgs(r) == ["after", "evilpkg", "leftpad2"]


def test_code_size_checked_before_reading_and_manifests_first():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(3):
            zf.writestr(f"a{i}.js", "x" * (3 * 1024 * 1024))
        zf.writestr("z/requirements.txt", "flask\n")
    lim = IntakeLimits(max_read_bytes=8 * 1024 * 1024)
    r = extract_zip("proj-1", buf.getvalue(), "u.zip", limits=lim, clock=lambda: T0)
    assert pkgs(r) == ["flask"]
    assert codes(r).count("intake.limit.file_size") == 3


def test_js_line_numbers_after_unterminated_constructs():
    src = "'unterminated\nconst b = /re\nconst c = 1;\nrequire('lodash')\n"
    found, _ = _js_specifiers(_js_tokens(src))
    assert found == [("lodash", 4, "require")]


def test_js_regex_after_if_paren():
    found, _ = _js_specifiers(_js_tokens("if (ok) /\\/*/.test(s);\nrequire('evilpkg')\n"))
    assert [f[0] for f in found] == ["evilpkg"]


def test_js_division_after_call_paren_still_division():
    found, _ = _js_specifiers(_js_tokens("x = f(a) / 2; require('ok')\n"))
    assert [f[0] for f in found] == ["ok"]


def test_require_inside_template_expression():
    found, _ = _js_specifiers(_js_tokens("const s = `${require('x-in-template')}`;\n"))
    assert [f[0] for f in found] == ["x-in-template"]


def test_markdown_installs_count_across_upload():
    r = run(("README.md", "```bash\npip install fancylib\n```\n"), ("a.py", "import fancylib\n"))
    a, = [d for d in r.dependencies if d.source_path == "a.py"]
    assert a.package.name_normalized == "fancylib"
