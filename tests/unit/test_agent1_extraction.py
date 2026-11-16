"""Agent 1 manifest parsers (requirements.txt, package.json, package-lock.json).

All inputs are hand-written fixtures in tests/fixtures/agent1/ or inline
strings. No network, no dataset files.
"""

import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from multi_agentic_security.agents.agent1_ingestion import UploadedFile, classify, extract_files
from multi_agentic_security.agents.agent1_ingestion.common import redact
from multi_agentic_security.agents.agent1_ingestion.npm_manifest import classify_spec
from multi_agentic_security.contracts.pipeline import ExtractionResult

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "agent1"
T0 = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def run(*files):
    return extract_files("proj-1", [UploadedFile(path=p, data=d if isinstance(d, bytes) else d.encode()) for p, d in files],
                         clock=lambda: T0)


def fixture(name, as_path):
    return as_path, (FIX / name).read_bytes()


def by_name(result, name):
    return [d for d in result.dependencies if d.package and d.package.name_normalized == name]


def codes(result):
    return [f.code for f in result.failures]


# --------------------------------------------------------------------------- classification

@pytest.mark.parametrize("path,kind", [
    ("requirements.txt", "requirements_txt"),
    ("sub/requirements-dev.txt", "requirements_txt"),
    ("Requirements_Test.TXT", "requirements_txt"),
    ("requirements/base.txt", "requirements_txt"),
    ("notes.txt", None),
    ("package.json", "package_json"),
    ("a/b/package-lock.json", "package_lock_json"),
    ("npm-shrinkwrap.json", "package_lock_json"),
    ("pyproject.toml", None),
])
def test_classify(path, kind):
    assert classify(path) == kind


# --------------------------------------------------------------------------- requirements.txt

@pytest.fixture(scope="module")
def req_result():
    return extract_files("proj-1", [UploadedFile("requirements.txt", (FIX / "requirements_mixed.txt").read_bytes())],
                         clock=lambda: T0)


def test_requirements_pinned_range_unpinned(req_result):
    flask, = by_name(req_result, "flask")
    assert flask.source_line == 2 and flask.extraction_status == "warning"  # file sets an alternative index
    assert flask.version_constraint_normalized == "==2.3.3"
    assert [r.rule_id for r in flask.reasons] == ["a1.requirements.parsed", "a1.requirements.pinned"]
    requests, = by_name(req_result, "requests")
    assert requests.version_constraint_raw == ">=2.31,<3"
    assert requests.reasons[1].rule_id == "a1.requirements.range"
    numpy, = by_name(req_result, "numpy")
    assert numpy.version_constraint_raw is None and numpy.reasons[1].rule_id == "a1.requirements.unpinned"


def test_requirements_name_normalized_and_raw_kept(req_result):
    drf, = by_name(req_result, "django-rest-framework")
    assert drf.package.name_raw == "Django_Rest.Framework"
    assert drf.reasons[0].inputs["extras"] == ["extra1"]


def test_requirements_marker_is_recorded_not_evaluated(req_result):
    pandas, = by_name(req_result, "pandas")
    marker = [r for r in pandas.reasons if r.rule_id == "a1.requirements.marker"]
    assert marker and "python_version" in marker[0].inputs["marker"]


def test_requirements_continuation_and_hashes(req_result):
    urllib3, = by_name(req_result, "urllib3")
    assert urllib3.source_line == 11
    assert urllib3.version_constraint_normalized == "==2.0.7"
    assert urllib3.reasons[0].inputs["hashes"] == 1


def test_requirements_index_option_is_reported_and_redacted(req_result):
    src = [f for f in req_result.failures if f.code == "a1.requirements.package_source_option"]
    assert len(src) == 1 and "s3cret" not in src[0].detail and "***@" in src[0].detail
    flask, = by_name(req_result, "flask")
    assert any("package index" in w for w in flask.warnings)


def test_requirements_include_not_followed(req_result):
    assert "a1.requirements.include_not_followed" in codes(req_result)


def test_requirements_editable_vcs_with_egg(req_result):
    tool, = by_name(req_result, "local-tool")
    assert tool.origin == "vcs" and tool.extraction_status == "warning"
    assert tool.reasons[0].rule_id == "a1.requirements.editable"


def test_requirements_unresolvable_lines_are_records_not_dropped(req_result):
    unresolved = [d for d in req_result.dependencies if d.extraction_status == "unresolved"]
    rules = sorted(d.reasons[0].rule_id for d in unresolved)
    # -e ./libs/internal, the bare wheel URL, the garbage line, the ${VAR} line
    assert rules == ["a1.requirements.editable", "a1.requirements.location",
                     "a1.requirements.unparseable", "a1.requirements.unparseable"]
    assert all(d.package is None and d.warnings for d in unresolved)
    env = [d for d in unresolved if "${PKG_VERSION}" in d.original_declaration][0]
    assert any("environment variable" in w for w in env.warnings)


def test_requirements_direct_reference(req_result):
    mypkg, = by_name(req_result, "mypkg")
    assert mypkg.origin == "url" and mypkg.version_constraint_raw is None
    assert any(r.rule_id == "a1.requirements.direct_reference" for r in mypkg.reasons)


def test_requirements_unknown_option(req_result):
    assert "a1.requirements.unknown_option" in codes(req_result)


def test_requirements_every_content_line_is_accounted_for(req_result):
    text = (FIX / "requirements_mixed.txt").read_text()
    content_lines = {i for i, l in enumerate(text.splitlines(), 1) if l.strip() and not l.strip().startswith("#")}
    content_lines.discard(12)  # continuation of line 11
    record_lines = {d.source_line for d in req_result.dependencies}
    failure_lines = {int(f.detail.split(":")[0].split()[1]) for f in req_result.failures if f.detail.startswith("line ")}
    assert content_lines == record_lines | failure_lines


def test_requirements_crlf_bom_and_editable_equals_form():
    r = run(("requirements.txt", b"\xef\xbb\xbfalpha==1.0\r\n--editable=git+https://h.invalid/r.git#egg=Beta\r\n"))
    assert [d.package.name_normalized for d in r.dependencies] == ["alpha", "beta"]
    assert r.dependencies[0].extraction_status == "ok"


def test_requirements_wildcard_equality_is_a_range():
    d, = run(("requirements.txt", "alpha==1.*\n")).dependencies
    assert d.reasons[1].rule_id == "a1.requirements.range"


def test_requirements_unterminated_continuation_warns():
    d, = run(("requirements.txt", "alpha==1.0 \\")).dependencies
    assert d.extraction_status == "warning" and "end of the file" in d.warnings[0]


def test_comment_line_ending_in_backslash_does_not_continue():
    r = run(("requirements.txt", "# note \\\nalpha==1.0\n"))
    assert [(d.package.name_normalized, d.source_line) for d in r.dependencies] == [("alpha", 2)]


def test_non_utf8_file_is_a_failure():
    r = run(("requirements.txt", b"alpha==1.0\n\xff\xfe\n"))
    assert r.dependencies == [] and "a1.source.decode_error" in codes(r)


def test_binary_content_is_a_failure():
    r = run(("requirements.txt", b"alpha\x00==1.0\n"))
    assert r.dependencies == [] and "a1.source.binary_content" in codes(r)


# --------------------------------------------------------------------------- package.json

@pytest.fixture(scope="module")
def pj_result():
    return extract_files("proj-1", [UploadedFile("package.json", (FIX / "package.json").read_bytes())], clock=lambda: T0)


def test_package_json_sections_map_to_types(pj_result):
    types = {d.package.name_normalized: d.dependency_type for d in pj_result.dependencies if d.package}
    assert types["express"] == "runtime" and types["jest"] == "dev"
    assert types["fsevents"] == "optional" and types["react"] == "peer"


def test_package_json_alias_records_installed_package(pj_result):
    lp, = by_name(pj_result, "left-pad")
    assert lp.origin == "registry" and lp.version_constraint_normalized == "^1.3.0"
    assert any("my-alias" in w for w in lp.warnings)


def test_package_json_non_registry_origins(pj_result):
    assert by_name(pj_result, "from-git")[0].origin == "vcs"
    assert by_name(pj_result, "local-lib")[0].origin == "path"
    tarball, = by_name(pj_result, "tarball")
    assert tarball.origin == "url" and "tok" not in tarball.original_declaration


def test_package_json_duplicate_keys_both_kept_with_distinct_ids(pj_result):
    lodash = by_name(pj_result, "lodash")
    assert [d.version_constraint_raw for d in lodash] == ["4.17.21", "4.17.20"]
    assert lodash[0].dependency_id != lodash[1].dependency_id
    assert all(d.extraction_status == "warning" for d in lodash)


def test_package_json_invalid_name_and_non_string_spec(pj_result):
    bad = [d for d in pj_result.dependencies if "bad name!" in d.original_declaration][0]
    assert bad.package is None and bad.extraction_status == "unresolved"
    weird, = by_name(pj_result, "weird")
    assert weird.origin == "unknown" and weird.reasons[0].rule_id == "a1.npm.non_string_spec"


def test_package_json_uppercase_scope_warns(pj_result):
    thing, = by_name(pj_result, "@scope/thing")
    assert thing.package.name_raw == "@Scope/Thing" and thing.extraction_status == "warning"


def test_package_json_overrides_reported_and_scripts_ignored(pj_result):
    assert "a1.package_json.field_not_interpreted" in codes(pj_result)
    assert all("postinstall" not in d.original_declaration for d in pj_result.dependencies)


def test_package_json_records_carry_json_pointer(pj_result):
    express, = by_name(pj_result, "express")
    assert express.source_line is None and express.reasons[0].inputs["pointer"] == "/dependencies/express"


@pytest.mark.parametrize("spec,origin,rule", [
    ("^1.2.3", "registry", "a1.npm.range"),
    ("1.2.3", "registry", "a1.npm.pinned"),
    ("v1.2.3", "registry", "a1.npm.pinned"),
    (">=1.0.0 <2 || 3.x", "registry", "a1.npm.range"),
    ("", "registry", "a1.npm.unpinned"),
    ("latest", "registry", "a1.npm.unpinned"),
    ("beta", "registry", "a1.npm.dist_tag"),
    ("user/repo", "vcs", "a1.npm.vcs"),
    ("git+ssh://git@h.invalid/r.git", "vcs", "a1.npm.vcs"),
    ("https://h.invalid/x.tgz", "url", "a1.npm.url"),
    ("workspace:*", "path", "a1.npm.path"),
    ("../sibling", "path", "a1.npm.path"),
    ("npm:@scope/real@1.0.0", "registry", "a1.npm.alias"),
    ("1.0.0 && echo hi", "unknown", "a1.npm.unrecognized_spec"),
])
def test_classify_spec(spec, origin, rule):
    got_origin, got_rule, *_ = classify_spec(spec)
    assert (got_origin, got_rule) == (origin, rule)


def test_scoped_alias_target():
    _, _, target, _, rng = classify_spec("npm:@scope/real@1.0.0")
    assert target == "@scope/real" and rng == "1.0.0"


@pytest.mark.parametrize("content,code", [
    ("{not json", "a1.source.invalid_json"),
    ("[1, 2]", "a1.source.unexpected_structure"),
    ('{"dependencies": {"a": NaN}}', "a1.source.invalid_json"),
    ("[" * 100000 + "]" * 100000, "a1.source.invalid_json"),
    ('{"dependencies": ["a"]}', "a1.package_json.section_not_object"),
], ids=["broken", "array", "nan", "deep_nesting", "section_array"])
def test_package_json_malformed(content, code):
    r = run(("package.json", content))
    assert r.dependencies == [] and code in codes(r)


# --------------------------------------------------------------------------- package-lock.json

@pytest.fixture(scope="module")
def lock3():
    return extract_files("proj-1", [UploadedFile("package-lock.json", (FIX / "package-lock-v3.json").read_bytes())],
                         clock=lambda: T0)


def test_lock_v3_entries(lock3):
    names = sorted(d.package.name_normalized for d in lock3.dependencies if d.package)
    assert names == ["@types/node", "debug", "express", "fsevents", "left-pad", "local-lib", "private-thing"]
    assert by_name(lock3, "@types/node")[0].dependency_type == "dev"
    assert by_name(lock3, "fsevents")[0].dependency_type == "optional"
    assert by_name(lock3, "express")[0].version_constraint_normalized == "4.18.2"
    assert by_name(lock3, "express")[0].extraction_status == "ok"


def test_lock_v3_nested_name(lock3):
    debug, = by_name(lock3, "debug")
    assert debug.reasons[0].inputs["pointer"] == "/packages/node_modules~1express~1node_modules~1debug"


def test_lock_v3_alias_uses_real_name(lock3):
    lp, = by_name(lock3, "left-pad")
    assert any("my-alias" in w for w in lp.warnings)


def test_lock_v3_private_registry_and_install_script(lock3):
    p, = by_name(lock3, "private-thing")
    assert p.origin == "url" and p.extraction_status == "warning"
    rules = {r.rule_id for r in p.reasons}
    assert {"a1.package_lock.install_script_declared", "a1.package_lock.no_integrity"} <= rules


def test_lock_v3_link_and_workspace_and_broken(lock3):
    assert by_name(lock3, "local-lib")[0].origin == "path"
    assert {"a1.package_lock.workspace_entries", "a1.package_lock.entry_not_object"} <= set(codes(lock3))


def test_lock_v1_tree_and_alias():
    r = run(fixture("package-lock-v1.json", "package-lock.json"))
    names = [d.package.name_normalized for d in r.dependencies]
    assert names == ["accepts", "mime-types", "real-pkg", "devthing"]
    real, = by_name(r, "real-pkg")
    assert real.version_constraint_normalized == "2.0.0" and real.extraction_status == "warning"
    assert by_name(r, "devthing")[0].dependency_type == "dev"


def test_lock_unknown_version_and_no_entries():
    r = run(("package-lock.json", '{"lockfileVersion": 9}'))
    assert {"a1.package_lock.no_entries", "a1.package_lock.unknown_version"} <= set(codes(r))


def test_lock_duplicate_keys_get_distinct_ids():
    lock = '{"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0"}, "node_modules/a": {"version": "1.0.0"}}}'
    r = run(("package-lock.json", lock))
    assert len(r.dependencies) == 2 and len({d.dependency_id for d in r.dependencies}) == 2


def test_lock_v1_depth_limit():
    inner = '{"version": "1.0.0"}'
    for _ in range(70):
        inner = '{"version": "1.0.0", "dependencies": {"x": %s}}' % inner
    r = run(("package-lock.json", '{"lockfileVersion": 1, "dependencies": {"x": %s}}' % inner))
    assert "a1.package_lock.too_deep" in codes(r)


# --------------------------------------------------------------------------- whole result

def all_fixture_files():
    return [fixture("requirements_mixed.txt", "requirements.txt"), fixture("package.json", "web/package.json"),
            fixture("package-lock-v3.json", "web/package-lock.json"),
            fixture("package-lock-v1.json", "old/package-lock.json")]


def test_result_validates_and_roundtrips():
    r = run(*all_fixture_files())
    again = ExtractionResult.model_validate_json(r.model_dump_json())
    assert again == r
    assert all(d.reasons for d in r.dependencies)
    assert {s.kind for s in r.sources} == {"requirements_txt", "package_json", "package_lock_json"}
    assert all(s.sha256 and len(s.sha256) == 64 for s in r.sources)


def test_ids_are_stable_and_unique():
    a, b = run(*all_fixture_files()), run(*all_fixture_files())
    ids = [d.dependency_id for d in a.dependencies]
    assert ids == [d.dependency_id for d in b.dependencies] and len(ids) == len(set(ids))


def test_no_credentials_anywhere_in_output():
    dumped = run(*all_fixture_files()).model_dump_json()
    assert "s3cret" not in dumped and "user:tok" not in dumped


def test_redact():
    assert redact("see https://u:p@h.invalid/x and git+ssh://git@h/x") == "see https://***@h.invalid/x and git+ssh://***@h/x"


def test_unsupported_manifest_and_no_manifest_reported():
    r = extract_files("proj-1", [], all_paths=["pyproject.toml", "src/app.py"], clock=lambda: T0)
    assert {"a1.source.unsupported_manifest", "a1.source.no_manifest"} <= set(codes(r))


def test_file_size_limit():
    from multi_agentic_security.agents.agent1_ingestion import IntakeLimits
    r = extract_files("proj-1", [UploadedFile("requirements.txt", b"a==1\n" * 100)],
                      limits=IntakeLimits(max_file_bytes=100), clock=lambda: T0)
    assert r.dependencies == [] and "a1.source.too_large" in codes(r)


def test_parsing_never_reads_dataset_or_env(monkeypatch):
    """The parsers only see the bytes they are given."""
    opened = []
    import builtins
    real_open = builtins.open
    monkeypatch.setattr(builtins, "open", lambda *a, **k: opened.append(a[0]) or real_open(*a, **k))
    run(("requirements.txt", "alpha==1.0\n-r other.txt\n"))
    assert opened == []


# --------------------------------------------------------------------------- review regressions (2026-11-16)

def test_redaction_of_password_containing_at():
    r = run(("requirements.txt", "--index-url https://user:p@ss@h.invalid/simple\nalpha\n"))
    dumped = r.model_dump_json()
    assert "p@ss" not in dumped and "ss@h" not in dumped


def test_alias_to_url_does_not_leak_or_become_name():
    r = run(("package.json", '{"dependencies":{"k":"npm:foo@https://u:SECRET@h.invalid/x.tgz"}}'))
    assert "SECRET" not in r.model_dump_json()
    d, = r.dependencies
    assert d.package.name_normalized == "foo" and d.origin == "unknown"


def test_continuation_joins_without_space_like_pip():
    r = run(("requirements.txt", "evil\\\npkg==1.0\nfoo==1.\\\n0\n"))
    assert [(d.package.name_normalized, d.version_constraint_normalized, d.source_line) for d in r.dependencies] == [
        ("evilpkg", "==1.0", 1), ("foo", "==1.0", 3)]


def test_comment_inside_continuation_ends_it():
    # pip appends the comment line to the continuation, then strips it as a comment.
    r = run(("requirements.txt", "alpha==1.0 \\\n# comment\nbeta\n"))
    assert [(d.package.name_normalized, d.source_line) for d in r.dependencies] == [("alpha", 1), ("beta", 3)]


@pytest.mark.parametrize("path", ["dev-requirements.txt", "test_requirements.txt", "requirements.in",
                                  "requirements.txt.", "requirements.txt "])
def test_more_requirements_names_are_parsed(path):
    assert classify(path) == "requirements_txt"


def test_trailing_dot_and_constraints_reported():
    r = extract_files("proj-1", [UploadedFile("package.json.", b'{"dependencies": {"a": "1.0.0"}}')],
                      all_paths=["constraints.txt"], clock=lambda: T0)
    assert [d.package.name_normalized for d in r.dependencies] == ["a"]
    assert {"intake.path.trailing_dot_or_space", "a1.source.constraints_file"} <= set(codes(r))


@pytest.mark.parametrize("line", ["anon-1.0-py3-none-any.whl", "foo-1.0.tar.gz"])
def test_archive_file_names_are_paths_not_registry_names(line):
    d, = run(("requirements.txt", line + "\n")).dependencies
    assert d.package is None and d.origin == "path" and d.reasons[0].rule_id == "a1.requirements.location"


def test_glued_short_options():
    r = run(("requirements.txt", "-ihttps://pypi.corp.invalid/simple\n-egit+https://h.invalid/r.git#egg=tool\n-rother.txt\nflask\n"))
    flask, = by_name(r, "flask")
    assert any("package index" in w for w in flask.warnings)
    assert by_name(r, "tool")[0].origin == "vcs"
    assert {"a1.requirements.package_source_option", "a1.requirements.include_not_followed"} <= set(codes(r))


def test_global_option_reported():
    assert "a1.requirements.global_option" in codes(run(("requirements.txt", "--pre\nalpha\n")))


def test_egg_with_version():
    d, = run(("requirements.txt", "git+https://h.invalid/r.git#egg=foo-1.0\n")).dependencies
    assert d.package.name_normalized == "foo" and any("includes a version" in w for w in d.warnings)


def test_duplicate_top_level_sections_reported():
    r = run(("package.json", '{"dependencies":{"first-block":"1.0.0"},"dependencies":{"second":"1.0.0"}}'))
    assert [d.package.name_normalized for d in r.dependencies] == ["second"]
    f = [x for x in r.failures if x.code == "a1.json.duplicate_section"]
    assert f and "first-block" in f[0].detail
    lock = run(("package-lock.json", '{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}},'
                                     '"packages":{"node_modules/b":{"version":"1.0.0"}}}'))
    assert "a1.json.duplicate_section" in codes(lock)


def test_duplicate_paths_are_a_failure_not_a_crash():
    r = run(("requirements.txt", "a\n"), ("requirements.txt", "a\n"))
    assert len(r.dependencies) == 1 and "a1.source.duplicate_path" in codes(r)


@pytest.mark.parametrize("spec,origin,rule", [
    ("pkg-1.0.0.tgz", "path", "a1.npm.path"),
    ("vendor/pkg.tgz", "path", "a1.npm.path"),
    ("evil2", "registry", "a1.npm.dist_tag"),
    ("git@github.com:u/r.git", "vcs", "a1.npm.vcs"),
    ("1.2.3 - 2.3.4", "registry", "a1.npm.range"),
    (">= 1.2.3 < 2", "registry", "a1.npm.range"),
    ("^1.2.3-beta.1", "registry", "a1.npm.range"),
])
def test_classify_spec_review_cases(spec, origin, rule):
    got_origin, got_rule, *_ = classify_spec(spec)
    assert (got_origin, got_rule) == (origin, rule)


def test_lock_non_string_version_and_flags():
    lock = ('{"lockfileVersion":3,"packages":{'
            '"node_modules/a":{"version":1},'
            '"node_modules/b":{"version":"1.0.0","devOptional":true,"integrity":"x"},'
            '"node_modules/c":{"version":"1.0.0","inBundle":true,"integrity":"x"}}}')
    r = run(("package-lock.json", lock))
    a, = by_name(r, "a")
    assert any("not a string" in w for w in a.warnings)
    b, = by_name(r, "b")
    assert b.dependency_type == "dev" and any(x.rule_id == "a1.package_lock.dev_optional" for x in b.reasons)
    c, = by_name(r, "c")
    assert any(x.rule_id == "a1.package_lock.bundled" for x in c.reasons)


def test_lock_invalid_name_is_unresolved():
    d, = run(("package-lock.json", '{"lockfileVersion":3,"packages":{"node_modules/Bad Name":{"version":"1.0.0"}}}')).dependencies
    assert d.package is None and any(x.rule_id == "a1.npm.invalid_name" for x in d.reasons)


def test_unsupported_file_given_directly():
    assert "a1.source.unsupported_file" in codes(run(("notes.xyz", "x")))
