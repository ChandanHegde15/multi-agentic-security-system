"""Agent 1 safe intake of ZIP archives and folders.

Archives are built in memory from hand-written content; nothing is extracted
to disk. Folder tests use pytest's tmp_path. No network.
"""

import io
import os
import socket
import stat
import zipfile
from datetime import datetime, timezone

import pytest

from multi_agentic_security.agents.agent1_ingestion import IntakeLimits, extract_directory, extract_zip
from multi_agentic_security.contracts.pipeline import ExtractionResult

T0 = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
REQ = b"alpha==1.0\nbeta>=2\n"
PJ = b'{"dependencies": {"left-pad": "1.3.0"}}'


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def make_zip(entries, compression=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in entries:
            if isinstance(name, zipfile.ZipInfo):
                zf.writestr(name, data)
            else:
                zf.writestr(name, data)
    return buf.getvalue()


def zx(data, **kw):
    return extract_zip("proj-1", data, kw.pop("name", "upload.zip"), clock=lambda: T0, **kw)


def codes(r):
    return [f.code for f in r.failures]


# --------------------------------------------------------------------------- ZIP

def test_zip_happy_path():
    r = zx(make_zip([("proj/requirements.txt", REQ), ("proj/web/package.json", PJ), ("proj/README.md", b"hi")]))
    assert isinstance(r, ExtractionResult)
    assert sorted(d.package.name_normalized for d in r.dependencies) == ["alpha", "beta", "left-pad"]
    assert r.sources[0].kind == "archive" and r.sources[0].locator == "upload.zip" and r.sources[0].sha256
    assert {d.source_path for d in r.dependencies} == {"proj/requirements.txt", "proj/web/package.json"}
    assert r.failures == []


def test_zip_label_never_contains_local_path():
    r = zx(make_zip([("requirements.txt", REQ)]), name="C:\\Users\\someone\\Desktop\\upload.zip")
    assert r.sources[0].locator == "upload.zip"


@pytest.mark.parametrize("bad,code", [
    ("../evil/requirements.txt", "intake.path.traversal"),
    ("a/../../requirements.txt", "intake.path.traversal"),
    ("/etc/requirements.txt", "intake.path.absolute"),
    ("C:/x/requirements.txt", "intake.path.absolute"),
    ("..\\win\\requirements.txt", "intake.path.traversal"),
])
def test_zip_hostile_names_reject_whole_archive(bad, code):
    r = zx(make_zip([("requirements.txt", REQ), (bad, REQ)]))
    assert r.dependencies == [] and code in codes(r)
    assert any("rejected" in f.detail for f in r.failures)


def test_zip_duplicate_names_reject_archive():
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # zipfile warns about the duplicate name
        data = make_zip([("requirements.txt", b"good==1.0\n"), ("Requirements.txt", b"evil==6.6.6\n")])
    r = zx(data)
    assert r.dependencies == [] and "intake.path.duplicate" in codes(r)


def test_zip_symlink_entry_skipped():
    info = zipfile.ZipInfo("requirements.txt")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    r = zx(make_zip([(info, b"/etc/passwd"), ("web/package.json", PJ)]))
    assert "intake.zip.symlink" in codes(r)
    assert [d.source_path for d in r.dependencies] == ["web/package.json"]


def test_zip_encrypted_entry_skipped():
    data = bytearray(make_zip([("requirements.txt", REQ)], compression=zipfile.ZIP_STORED))
    cd = data.find(b"PK\x01\x02")
    data[cd + 8] |= 0x01  # general-purpose flag in the central directory: encrypted
    r = zx(bytes(data))
    assert r.dependencies == [] and "intake.zip.encrypted" in codes(r)


def test_zip_bomb_ratio_skipped():
    r = zx(make_zip([("requirements.txt", b"#" + b" " * (5 * 1024 * 1024))]))
    assert "intake.limit.compression_ratio" in codes(r)


def test_zip_entry_count_limit():
    r = zx(make_zip([(f"f{i}.txt", b"x") for i in range(11)]), limits=IntakeLimits(max_entries=10))
    assert r.dependencies == [] and "intake.limit.entries" in codes(r)


def test_zip_total_size_limit():
    r = zx(make_zip([("a.bin", b"x" * 600), ("requirements.txt", REQ)]), limits=IntakeLimits(max_total_bytes=500))
    assert r.dependencies == [] and "intake.limit.total_size" in codes(r)


def test_zip_file_size_limit():
    r = zx(make_zip([("requirements.txt", REQ * 100), ("package.json", PJ)]), limits=IntakeLimits(max_file_bytes=500))
    assert "intake.limit.file_size" in codes(r)
    assert [d.package.name_normalized for d in r.dependencies] == ["left-pad"]


def test_zip_declared_size_lie_is_caught():
    data = bytearray(make_zip([("requirements.txt", REQ * 50)], compression=zipfile.ZIP_STORED))
    # Shrink the declared uncompressed size in the central directory only.
    cd = data.find(b"PK\x01\x02")
    data[cd + 24:cd + 28] = (10).to_bytes(4, "little")
    r = zx(bytes(data), limits=IntakeLimits(max_file_bytes=100))
    assert r.dependencies == []
    assert set(codes(r)) & {"intake.limit.file_size", "intake.zip.entry_unreadable"}


def test_zip_upload_size_limit():
    r = zx(make_zip([("requirements.txt", REQ)]), limits=IntakeLimits(max_upload_bytes=10))
    assert r.dependencies == [] and "intake.limit.upload_size" in codes(r)


def test_zip_invalid():
    r = zx(b"this is not a zip")
    assert r.dependencies == [] and "intake.zip.invalid" in codes(r)


def test_zip_depth_limit():
    r = zx(make_zip([("/".join(["d"] * 40) + "/requirements.txt", REQ)]))
    assert "intake.limit.depth" in codes(r)


def test_zip_vendored_nested_and_unsupported_reported():
    r = zx(make_zip([
        ("requirements.txt", REQ),
        ("node_modules/evil/package.json", b'{"dependencies": {"x": "1"}}'),
        ("vendor.zip", b"PK"),
        ("pyproject.toml", b"[project]\n"),
    ]))
    assert sorted(d.package.name_normalized for d in r.dependencies) == ["alpha", "beta"]
    assert {"intake.vendored_directory_skipped", "intake.nested_archive", "a1.source.unsupported_manifest"} <= set(codes(r))


def test_zip_unparsed_entries_are_not_read(monkeypatch):
    data = make_zip([("requirements.txt", REQ), ("src/data.bin", b"\x00\x01"), ("setup.py", b"evil()")])
    opened = []
    real = zipfile.ZipFile.open
    monkeypatch.setattr(zipfile.ZipFile, "open", lambda self, name, *a, **k: opened.append(getattr(name, "filename", name)) or real(self, name, *a, **k))
    zx(data)
    assert opened == ["requirements.txt"]


def test_zip_nothing_written_to_disk(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    zx(make_zip([("requirements.txt", REQ), ("web/package.json", PJ)]))
    assert list(tmp_path.iterdir()) == []


# --------------------------------------------------------------------------- folder

def write(root, rel, data):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def dx(root, **kw):
    return extract_directory("proj-1", root, label="upload", clock=lambda: T0, **kw)


def test_dir_happy_path(tmp_path):
    write(tmp_path, "requirements.txt", REQ)
    write(tmp_path, "web/package.json", PJ)
    write(tmp_path, "node_modules/x/package.json", PJ)
    write(tmp_path, "notes.md", b"x")
    r = dx(tmp_path)
    assert sorted(d.package.name_normalized for d in r.dependencies) == ["alpha", "beta", "left-pad"]
    assert r.sources[0].kind == "directory" and r.sources[0].locator == "upload"
    assert codes(r) == ["intake.vendored_directory_skipped"]
    assert str(tmp_path) not in r.model_dump_json()


def test_dir_symlink_not_followed(tmp_path):
    outside = tmp_path / "outside"
    write(outside, "requirements.txt", b"secret==1.0\n")
    root = tmp_path / "root"
    write(root, "requirements.txt", REQ)
    try:
        os.symlink(outside, root / "linked", target_is_directory=True)
        os.symlink(outside / "requirements.txt", root / "requirements-dev.txt")
    except (OSError, NotImplementedError):
        pytest.skip("creating symbolic links is not permitted here")
    r = dx(root)
    assert "secret" not in [d.package.name_normalized for d in r.dependencies]
    assert codes(r).count("intake.dir.symlink") == 2


def test_dir_root_must_be_folder(tmp_path):
    write(tmp_path, "requirements.txt", REQ)
    r = dx(tmp_path / "requirements.txt")
    assert r.dependencies == [] and "intake.dir.not_a_directory" in codes(r)


def test_dir_missing_root(tmp_path):
    r = dx(tmp_path / "nope")
    assert "intake.dir.unreadable" in codes(r)


def test_dir_limits(tmp_path):
    for i in range(6):
        write(tmp_path, f"f{i}.txt", b"x")
    assert "intake.limit.entries" in codes(dx(tmp_path, limits=IntakeLimits(max_entries=5)))
    write(tmp_path, "requirements.txt", REQ * 100)
    r = dx(tmp_path, limits=IntakeLimits(max_file_bytes=100))
    assert "intake.limit.file_size" in codes(r)
    assert "intake.limit.total_size" in codes(dx(tmp_path, limits=IntakeLimits(max_total_bytes=100)))


def test_dir_and_zip_give_same_ids(tmp_path):
    write(tmp_path, "requirements.txt", REQ)
    write(tmp_path, "web/package.json", PJ)
    a = dx(tmp_path)
    b = zx(make_zip([("requirements.txt", REQ), ("web/package.json", PJ)]))
    assert [d.dependency_id for d in a.dependencies] == [d.dependency_id for d in b.dependencies]


def test_dir_junction_not_followed(tmp_path):
    winapi = pytest.importorskip("_winapi")
    outside = tmp_path / "outside"
    write(outside, "requirements.txt", b"secret==1.0\n")
    root = tmp_path / "root"
    write(root, "requirements.txt", REQ)
    try:
        winapi.CreateJunction(str(outside), str(root / "junction"))
    except OSError:
        pytest.skip("cannot create a junction here")
    r = dx(root)
    assert [d.package.name_normalized for d in r.dependencies] == ["alpha", "beta"]
    assert "intake.dir.symlink" in codes(r)


# --------------------------------------------------------------------------- review regressions (2026-11-16)

def test_zip_entry_count_checked_before_parsing(monkeypatch):
    data = make_zip([(f"f{i}.txt", b"") for i in range(30)])
    monkeypatch.setattr(zipfile, "ZipFile", lambda *a, **k: (_ for _ in ()).throw(AssertionError("parsed")))
    r = zx(data, limits=IntakeLimits(max_entries=10))
    assert "intake.limit.entries" in codes(r)


def test_zip_read_total_limit_code():
    r = zx(make_zip([("a/requirements.txt", b"a" * 88), ("b/requirements.txt", b"b" * 50)]),
           limits=IntakeLimits(max_read_bytes=100))
    assert codes(r).count("intake.limit.read_total") == 1


def test_zip_nul_and_path_length():
    # zipfile itself truncates entry names at NUL, so the check is tested directly.
    from multi_agentic_security.agents.agent1_ingestion.intake import _Reject, safe_relative_path
    with pytest.raises(_Reject) as exc:
        safe_relative_path("a\x00b/requirements.txt")
    assert exc.value.code == "intake.path.nul_character"
    assert "intake.limit.path_length" in codes(zx(make_zip([("a" * 600 + "/requirements.txt", REQ)])))


def test_zip_trailing_dot_duplicate_rejected():
    r = zx(make_zip([("requirements.txt", b"good\n"), ("requirements.txt.", b"evil\n")]))
    assert r.dependencies == [] and "intake.path.duplicate" in codes(r)


def test_dir_hard_link_refused(tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_bytes(b"password=hunter2\n")
    root = tmp_path / "root"
    root.mkdir()
    try:
        os.link(outside, root / "requirements.txt")
    except (OSError, NotImplementedError):
        pytest.skip("cannot create hard links here")
    r = dx(root)
    assert r.dependencies == [] and "intake.dir.hard_link" in codes(r)
    assert "hunter2" not in r.model_dump_json()


def test_dir_read_total_limit(tmp_path):
    write(tmp_path, "a/requirements.txt", b"a" * 88)
    write(tmp_path, "b/requirements.txt", b"b" * 50)
    assert "intake.limit.read_total" in codes(dx(tmp_path, limits=IntakeLimits(max_read_bytes=100)))
