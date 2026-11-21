"""D-044 GitHub pin sampler (D-077): frame windows, seeded band order, file selection, pin counting, snapshot rules,
rate limits, token handling, resumability. A fake transport replays answers; no network, no real token."""

import json
import random
from datetime import date

import pytest

from multi_agentic_security.datasets import github_pins as G

FAKE = "test-token-not-real"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    import socket as s

    def refuse(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr(s, "socket", refuse)
    monkeypatch.setattr(s, "create_connection", refuse)
    monkeypatch.setattr(s, "getaddrinfo", refuse)
    monkeypatch.setenv(G.TOKEN_VAR, FAKE)


class Fake:
    """Routes by URL prefix; records every URL and header set."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, dict(headers)))
        for prefix, answer in self.routes:
            if url.startswith(prefix) or prefix in url:
                a = answer(url) if callable(answer) else answer
                status, body = a[0], a[1]
                hdrs = a[2] if len(a) > 2 else {}
                return status, hdrs, body if isinstance(body, bytes) else json.dumps(body).encode()
        return 404, {}, b"{}"


def client(fake, **kw):
    return G.GitHubClient(transport=fake, sleep=lambda s: None, clock=lambda: 0.0, **kw)


def test_the_token_is_sent_only_in_a_header_and_never_in_a_url():
    f = Fake([("/repos/o/r", (200, {"ok": 1}))])
    client(f).get("/repos/o/r")
    url, headers = f.calls[0]
    assert FAKE not in url and headers["Authorization"] == f"Bearer {FAKE}"


def test_a_missing_token_is_refused(monkeypatch):
    monkeypatch.delenv(G.TOKEN_VAR)
    with pytest.raises(ValueError) as e:
        G.GitHubClient(transport=Fake([]))
    assert FAKE not in str(e.value)


def test_month_windows():
    w = G.month_windows("2015-01", "2015-03")
    assert w == [(date(2015, 1, 1), date(2015, 1, 31)), (date(2015, 2, 1), date(2015, 2, 28)), (date(2015, 3, 1), date(2015, 3, 31))]
    assert len(G.month_windows("2015-01", "2024-11")) == 119


def item(n, stars=50):
    return {"full_name": f"o/r{n}", "stargazers_count": stars, "created_at": "2020-01-01T00:00:00Z", "default_branch": "main",
            "license": {"spdx_id": "MIT"}, "fork": False, "archived": False}


def test_a_window_over_the_cap_is_split_until_it_fits():
    seen = []

    def search(url):
        seen.append(url)
        if "2020-01-01..2020-01-31" in url:
            return 200, {"total_count": 1500, "items": []}
        return 200, {"total_count": 2, "items": [item(len(seen)), item(len(seen) + 100)]}
    c = client(Fake([("/search/repositories", search)]))
    rows = G.search_window(c, date(2020, 1, 1), date(2020, 1, 31))
    assert len(rows) == 4 and any("2020-01-01..2020-01-16" in u for u in seen) and any("2020-01-17..2020-01-31" in u for u in seen)
    assert all(r["license"] == "MIT" for r in rows)


def test_a_single_day_over_the_cap_is_recorded_as_truncated():
    c = client(Fake([("/search/repositories", (200, {"total_count": 1200, "items": [item(1)]}))]))
    rows = G.search_window(c, date(2020, 1, 1), date(2020, 1, 1))
    assert rows[-1]["full_name"] is None and rows[-1]["total_count"] == 1200


def test_build_frame_is_written_once_and_resumes(tmp_path):
    c = client(Fake([("/search/repositories", (200, {"total_count": 1, "items": [item(7)]}))]))
    w = G.month_windows("2020-01", "2020-02")
    r1 = G.build_frame(c, w, tmp_path)
    calls = c.calls
    r2 = G.build_frame(c, w, tmp_path)
    assert r1["repositories"] == r2["repositories"] == 1 and c.calls == calls     # nothing re-fetched
    assert json.loads((tmp_path / "frame.jsonl").read_text().splitlines()[0])["full_name"] == "o/r7"


def test_bands_and_the_seeded_order_follow_d044_item_4():
    frame = [{"full_name": f"o/a{i}", "stars": s} for i, s in enumerate([10, 99, 100, 999, 1000, 5000, 9])]
    frame.append({"full_name": "o/fork", "stars": 50, "fork": True})
    b = G.ordered_bands(frame, excluded=["O/A1"])
    assert set(b["10-99"]) == {"o/a0"} and set(b["100-999"]) == {"o/a2", "o/a3"} and set(b["1000+"]) == {"o/a4", "o/a5"}
    names = sorted(f"o/x{i}" for i in range(30))
    expected = list(names)
    random.Random(20261114).shuffle(expected)
    assert G.ordered_bands([{"full_name": n, "stars": 20} for n in names])["10-99"] == expected


def test_file_selection_root_first_then_folder_at_most_three():
    paths = ["setup.py", "requirements/test.txt", "requirements-dev.txt", "requirements.txt", "requirements/base.txt",
             "docs/requirements.txt", "REQUIREMENTS.TXT", "requirements.in"]
    assert G.select_files(paths) == ["REQUIREMENTS.TXT", "requirements-dev.txt", "requirements.txt"]
    assert G.select_files(["requirements/b.txt", "requirements/a.txt"]) == ["requirements/a.txt", "requirements/b.txt"]
    assert G.select_files(["src/requirements.txt", "requirements/sub/x.txt"]) == []


def test_pin_counting_matches_the_case_builder_rule():
    from multi_agentic_security.evaluation.cases import _PIN
    assert G._PIN.pattern == _PIN.pattern
    text = "# c\nflask==2.0.1\nrequests>=2\n-r base.txt\nnumpy==1.26.0 ; python_version>'3.8'\n\npkg==1.0  # x\n-e .\n"
    assert G.count_pins(text) == {"lines": 6, "exact_pins": 3, "other": 3}     # -r and -e lines are counted, not pins


def commit_route(date_str, sha="abc"):
    return ("/commits?", (200, [{"sha": sha, "commit": {"committer": {"date": date_str}}}]))


def tree_route(paths, folder=False):
    t = [{"path": p, "type": "blob"} for p in paths] + ([{"path": "requirements", "type": "tree"}] if folder else [])
    return ("/git/trees/", (200, {"tree": t}))


REPO = {"full_name": "o/r", "default_branch": "main", "stars": 50}


def test_snapshot_eligible_with_five_pins_and_texts_kept():
    pins = "\n".join(f"p{i}==1.{i}" for i in range(5))
    f = Fake([commit_route("2024-10-01T00:00:00Z"), tree_route(["requirements.txt", "setup.py"]),
              ("/contents/requirements.txt", (200, pins.encode()))])
    s = G.snapshot(client(f), REPO, date(2024, 12, 1))
    assert s["eligible"] and s["reason"] == "eligible" and s["files"] == ["requirements.txt"] and s["counts"]["exact_pins"] == 5
    assert "until=2024-11-30T23%3A59%3A59Z" in f.calls[0][0] and "sha=main" in f.calls[0][0]
    assert f.calls[2][1]["Accept"] == "application/vnd.github.raw"


@pytest.mark.parametrize("routes,reason", [
    ([("/commits?", (200, []))], "no_commit_before_cutoff"),
    ([commit_route("2022-11-30T00:00:00Z")], "inactive_24_months"),
    ([commit_route("2024-10-01T00:00:00Z"), tree_route(["setup.py"])], "no_requirements_file"),
    ([commit_route("2024-10-01T00:00:00Z"), tree_route(["requirements.txt"]), ("/contents/requirements.txt", (200, b"a==1\nb>=2\n"))],
     "fewer_than_5_exact_pins"),
    ([("/commits?", (409, {}))], "commit_lookup_empty_repository"),
    ([commit_route("not a date")], "commit_date_unreadable"),
])
def test_snapshot_rejections_are_states_with_reasons(routes, reason):
    s = G.snapshot(client(Fake(routes)), REPO, date(2024, 12, 1))
    assert s["eligible"] is False and s["reason"] == reason


def test_activity_boundary_is_24_months():
    assert G.months_before(date(2024, 12, 1), 24) == date(2022, 12, 1)
    pins = "\n".join(f"p{i}==1" for i in range(5)).encode()
    ok = Fake([commit_route("2022-12-01T00:00:00Z"), tree_route(["requirements.txt"]), ("/contents/requirements.txt", (200, pins))])
    assert G.snapshot(client(ok), REPO, date(2024, 12, 1))["eligible"] is True


def test_requirements_folder_is_listed_at_the_same_commit():
    pins = "\n".join(f"p{i}==1" for i in range(5)).encode()
    f = Fake([commit_route("2024-10-01T00:00:00Z", sha="s1"), tree_route([], folder=True),
              ("/contents/requirements?ref=s1", (200, [{"name": "base.txt", "type": "file"}, {"name": "x", "type": "dir"}])),
              ("/contents/requirements/base.txt", (200, pins))])
    s = G.snapshot(client(f), REPO, date(2024, 12, 1))
    assert s["files"] == ["requirements/base.txt"] and s["eligible"]


def test_rate_limits_wait_and_retry():
    waits, n = [], {"i": 0}

    def answer(url):
        n["i"] += 1
        if n["i"] == 1:
            return 403, {}, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "100"}
        if n["i"] == 2:
            return 429, {}, {"Retry-After": "7"}
        return 200, {"ok": True}
    c = G.GitHubClient(transport=Fake([("/x", answer)]), sleep=waits.append, clock=lambda: 40.0)
    assert c.get("/x") == {"ok": True} and waits == [61.0, 8.0]
    plain_403 = G.GitHubClient(transport=Fake([("/y", (403, {}))]), sleep=waits.append, clock=lambda: 0.0)
    with pytest.raises(G.GitHubError) as e:
        plain_403.get("/y")
    assert e.value.code == "http_403"


def test_search_calls_are_spaced():
    waits, t = [], {"now": 0.0}
    c = G.GitHubClient(transport=Fake([("/search/repositories", (200, {"total_count": 0, "items": []}))]),
                       sleep=lambda s: (waits.append(s), t.__setitem__("now", t["now"] + s)), clock=lambda: t["now"])
    c.get("/search/repositories", {"q": "x"}, search=True)
    c.get("/search/repositories", {"q": "x"}, search=True)
    assert waits and waits[0] == pytest.approx(2.2)


def test_sample_stops_at_the_band_target_logs_every_repo_and_resumes(tmp_path):
    pins = "\n".join(f"p{i}==1" for i in range(5)).encode()

    def commits(url):
        if "o/bad" in url:
            return 200, []
        return 200, [{"sha": "s", "commit": {"committer": {"date": "2024-10-01T00:00:00Z"}}}]
    f = Fake([("/commits?", commits), tree_route(["requirements.txt"]), ("/contents/requirements.txt", (200, pins))])
    frame = {n: {"full_name": n, "stars": 20, "default_branch": "main", "license": "MIT"} for n in ("o/bad", "o/g1", "o/g2", "o/g3")}
    bands = {"10-99": ["o/bad", "o/g1", "o/g2", "o/g3"], "100-999": [], "1000+": []}
    r = G.sample(client(f), frame, bands, [date(2024, 12, 1)], tmp_path, per_band=2)
    assert r.accepted["10-99"] == ["o/g1", "o/g2"] and r.checked == 3
    lines = [json.loads(l) for l in (tmp_path / "checked.jsonl").read_text().splitlines()]
    assert [l["repo"] for l in lines] == ["o/bad", "o/g1", "o/g2"] and lines[0]["snapshots"][0]["reason"] == "no_commit_before_cutoff"
    assert (tmp_path / "files" / "o__g1" / "2024-12-01" / "requirements.txt").read_text().startswith("p0==1")
    assert "texts" not in lines[1]["snapshots"][0]
    calls = len(f.calls)
    r2 = G.sample(client(f), frame, bands, [date(2024, 12, 1)], tmp_path, per_band=3)
    assert r2.accepted["10-99"] == ["o/g1", "o/g2", "o/g3"] and len(f.calls) > calls     # only o/g3 is new
