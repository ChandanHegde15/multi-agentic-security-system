"""Sampling real-project dependency pins from GitHub (D-040, D-041 c, D-044; RESEARCH_METHODOLOGY section 7.1).

Read-only and text-only: repository search, one commit query per cut-off, one directory listing and at most three
``requirements*.txt`` files per snapshot, fetched as text. Nothing is cloned, installed or executed. The network sits
behind ``Transport`` so that tests replay recorded answers. The token is read from the environment at each call,
sent only in a header, never stored on an object, never written to a record.

Steps (each written once, resumable):

1. ``build_frame``: search ``language:Python fork:false archived:false stars:>=10`` over consecutive creation windows
   (monthly; a window whose result count exceeds the search API's 1,000-result cap is split in halves until it fits,
   so the frame is the full list, not the first pages).
2. ``ordered_bands``: three star bands (10-99, 100-999, >=1,000; stars at retrieval), each the sorted ``owner/repo``
   list shuffled once with ``random.Random(20261114)``.
3. ``snapshot``: for each cut-off T the last default-branch commit before T; eligible activity if that commit is no
   older than 24 months before T; files ``requirements*.txt`` at the root, then ``requirements/*.txt``, at most three,
   root first, then alphabetical; at least five exact pins (``name==version``) across them.
4. ``sample``: candidates in band order until each band has the target number of eligible repositories; every checked
   repository is logged with the reason it was accepted or rejected.

Interpretation recorded in D-077: a repository is eligible when at least one cut-off snapshot is eligible; every
snapshot, eligible or not, is logged.
"""

from __future__ import annotations

import calendar
import json
import os
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable, Mapping, Optional

API = "https://api.github.com"
USER_AGENT = "multi-agentic-security-research/0.1"
TOKEN_VAR = "GITHUB_TOKEN"
SEED = 20261114
QUERY = "language:Python fork:false archived:false stars:>=10"
BANDS = (("10-99", 10, 99), ("100-999", 100, 999), ("1000+", 1000, None))
MAX_FILES = 3
MIN_PINS = 5
ACTIVE_MONTHS = 24
SEARCH_CAP = 1000
_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)\s*(?:;.*)?(?:#.*)?$")
_REQ_ROOT = re.compile(r"^requirements[^/]*\.txt$", re.IGNORECASE)
_REQ_DIR = re.compile(r"^requirements/[^/]+\.txt$", re.IGNORECASE)

# Transport: (url, headers, timeout) -> (status, response headers, body bytes)
Transport = Callable[[str, Mapping[str, str], float], tuple[int, Mapping[str, str], bytes]]


class GitHubError(Exception):
    """A request failed; ``code`` is a short machine code, the message never contains the token."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def urllib_get(url: str, headers: Mapping[str, str], timeout: float) -> tuple[int, Mapping[str, str], bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **dict(headers)}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(5_000_000)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read(200_000) if e.fp is not None else b"")
    except (urllib.error.URLError, OSError, TimeoutError):
        raise GitHubError("connection_error") from None


class GitHubClient:
    """Rate-limit aware GET client. Search calls are spaced (``search_interval_s``); an exhausted limit waits for the
    reset time it reports; a secondary limit (403/429 with Retry-After) waits and retries a bounded number of times."""

    def __init__(self, *, transport: Optional[Transport] = None, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.time, search_interval_s: float = 2.2, retries: int = 4,
                 timeout_s: float = 30.0):
        if not os.environ.get(TOKEN_VAR):
            raise ValueError(f"{TOKEN_VAR} is not set")       # the name only, never a value
        self._t, self._sleep, self._clock = transport or urllib_get, sleep, clock
        self._search_gap, self._retries, self._timeout = search_interval_s, retries, timeout_s
        self._last_search = None
        self.calls = 0

    def _headers(self, raw: bool) -> dict:
        token = os.environ.get(TOKEN_VAR, "")
        if not token:
            raise GitHubError("missing_token")
        return {"Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28",
                "Accept": "application/vnd.github.raw" if raw else "application/vnd.github+json"}

    def get(self, path: str, params: Optional[dict] = None, *, raw: bool = False, search: bool = False):
        url = API + path + ("?" + urllib.parse.urlencode(params) if params else "")
        for attempt in range(self._retries + 1):
            if search and self._last_search is not None:
                wait = self._search_gap - (self._clock() - self._last_search)
                if wait > 0:
                    self._sleep(wait)
            status, headers, body = self._t(url, self._headers(raw), self._timeout)
            self.calls += 1
            if search:
                self._last_search = self._clock()
            h = {k.lower(): v for k, v in (headers or {}).items()}
            if status in (403, 429) and (h.get("retry-after") or h.get("x-ratelimit-remaining") == "0"):
                if h.get("retry-after"):
                    wait = float(h["retry-after"])
                else:
                    wait = max(float(h.get("x-ratelimit-reset", self._clock() + 60)) - self._clock(), 1.0)
                self._sleep(min(wait + 1.0, 3700.0))
                continue
            if status >= 500:
                self._sleep(min(5.0 * 2 ** attempt, 120.0))
                continue
            if status == 404:
                raise GitHubError("not_found")
            if status == 409:                                  # empty repository
                raise GitHubError("empty_repository")
            if status != 200:
                raise GitHubError(f"http_{status}")
            if raw:
                return body.decode("utf-8", errors="replace")
            try:
                return json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise GitHubError("invalid_response") from None
        raise GitHubError("retries_exhausted")


# --------------------------------------------------------------------------- frame

def month_windows(first: str, last: str) -> list[tuple[date, date]]:
    """Consecutive calendar months from ``first`` to ``last`` (``YYYY-MM``), inclusive."""
    y, m = map(int, first.split("-"))
    ly, lm = map(int, last.split("-"))
    out = []
    while (y, m) <= (ly, lm):
        out.append((date(y, m, 1), date(y, m, calendar.monthrange(y, m)[1])))
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    return out


def _repo_row(item: dict) -> dict:
    lic = item.get("license") or {}
    return {"full_name": item["full_name"], "stars": int(item.get("stargazers_count") or 0),
            "created_at": item.get("created_at"), "default_branch": item.get("default_branch"),
            "license": lic.get("spdx_id"), "fork": bool(item.get("fork")), "archived": bool(item.get("archived"))}


def search_window(client: GitHubClient, lo: date, hi: date, query: str = QUERY) -> list[dict]:
    """Every repository created in [lo, hi]; splits the window while the result count is above the cap."""
    q = f"{query} created:{lo.isoformat()}..{hi.isoformat()}"
    first = client.get("/search/repositories", {"q": q, "per_page": 100, "page": 1, "sort": "stars", "order": "desc"},
                       search=True)
    total = int(first.get("total_count") or 0)
    if total > SEARCH_CAP and lo < hi:
        mid = lo + (hi - lo) // 2
        return search_window(client, lo, mid, query) + search_window(client, mid + timedelta(days=1), hi, query)
    rows = [_repo_row(i) for i in first.get("items") or []]
    pages = min((min(total, SEARCH_CAP) + 99) // 100, 10)
    for page in range(2, pages + 1):
        r = client.get("/search/repositories", {"q": q, "per_page": 100, "page": page, "sort": "stars", "order": "desc"},
                       search=True)
        rows += [_repo_row(i) for i in r.get("items") or []]
    if total > SEARCH_CAP:                                     # a single day above the cap: recorded, not hidden
        rows.append({"full_name": None, "truncated_window": [lo.isoformat(), hi.isoformat()], "total_count": total})
    return rows


def build_frame(client: GitHubClient, windows: Iterable[tuple[date, date]], out: Path, *, query: str = QUERY) -> dict:
    """Write ``frame.jsonl`` (one repository per line, sorted, de-duplicated) once; resumable per window through
    ``frame_windows.jsonl``. Returns counts."""
    out.mkdir(parents=True, exist_ok=True)
    wlog = out / "frame_windows.jsonl"
    done = set()
    if wlog.exists():
        done = {json.loads(l)["window"][0] for l in wlog.read_text(encoding="utf-8").splitlines() if l.strip()}
    for lo, hi in windows:
        if lo.isoformat() in done:
            continue
        rows = search_window(client, lo, hi, query)
        with open(wlog, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"window": [lo.isoformat(), hi.isoformat()], "rows": rows}, sort_keys=True) + "\n")
    allrows, truncated = {}, []
    for l in wlog.read_text(encoding="utf-8").splitlines():
        for r in json.loads(l)["rows"]:
            if r.get("full_name"):
                allrows[r["full_name"]] = r
            else:
                truncated.append(r)
    frame = out / "frame.jsonl"
    if not frame.exists():
        frame.write_text("".join(json.dumps(allrows[k], sort_keys=True) + "\n" for k in sorted(allrows)), encoding="utf-8")
    return {"repositories": len(allrows), "truncated_windows": truncated}


def band_of(stars: int) -> Optional[str]:
    for name, lo, hi in BANDS:
        if stars >= lo and (hi is None or stars <= hi):
            return name
    return None


def ordered_bands(frame: Iterable[dict], excluded: Iterable[str] = (), seed: int = SEED) -> dict[str, list[str]]:
    """Per band: the sorted ``owner/repo`` list shuffled once with ``random.Random(seed)`` (D-044 item 4)."""
    ex = {e.lower() for e in excluded}
    bands: dict[str, list[str]] = {b[0]: [] for b in BANDS}
    for r in frame:
        b = band_of(int(r.get("stars") or 0))
        if b and r["full_name"].lower() not in ex and not r.get("fork") and not r.get("archived"):
            bands[b].append(r["full_name"])
    out = {}
    for b, names in bands.items():
        names = sorted(names)
        random.Random(seed).shuffle(names)
        out[b] = names
    return out


# --------------------------------------------------------------------------- snapshots

def select_files(paths: Iterable[str]) -> list[str]:
    """At most three requirement files: root ``requirements*.txt`` first, then ``requirements/*.txt``, alphabetical."""
    paths = sorted(set(paths))
    root = [p for p in paths if _REQ_ROOT.match(p)]
    sub = [p for p in paths if _REQ_DIR.match(p)]
    return (root + sub)[:MAX_FILES]


def count_pins(text: str) -> dict:
    out = {"lines": 0, "exact_pins": 0, "other": 0}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out["lines"] += 1
        if _PIN.match(s):
            out["exact_pins"] += 1
        else:
            out["other"] += 1
    return out


def months_before(t: date, months: int) -> date:
    y, m = t.year, t.month - months
    while m <= 0:
        y, m = y - 1, m + 12
    return date(y, m, min(t.day, calendar.monthrange(y, m)[1]))


def snapshot(client: GitHubClient, repo: dict, cutoff: date) -> dict:
    """The repository at the last default-branch commit before ``cutoff``: commit, activity, files and pins."""
    name, branch = repo["full_name"], repo.get("default_branch") or "main"
    rec = {"repo": name, "cutoff": cutoff.isoformat(), "eligible": False}
    until = datetime(cutoff.year, cutoff.month, cutoff.day, tzinfo=timezone.utc) - timedelta(seconds=1)
    try:
        commits = client.get(f"/repos/{name}/commits", {"sha": branch, "until": until.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                                         "per_page": 1})
    except GitHubError as e:
        return {**rec, "reason": f"commit_lookup_{e.code}"}
    if not commits:
        return {**rec, "reason": "no_commit_before_cutoff"}
    sha = commits[0]["sha"]
    when = (commits[0].get("commit") or {}).get("committer", {}).get("date") or ""
    rec.update({"commit": sha, "commit_date": when})
    try:
        cdate = datetime.fromisoformat(when.replace("Z", "+00:00")).date()
    except ValueError:
        return {**rec, "reason": "commit_date_unreadable"}
    if cdate < months_before(cutoff, ACTIVE_MONTHS):
        return {**rec, "reason": "inactive_24_months"}
    try:
        tree = client.get(f"/repos/{name}/git/trees/{sha}")
    except GitHubError as e:
        return {**rec, "reason": f"tree_{e.code}"}
    paths = [t["path"] for t in tree.get("tree") or [] if t.get("type") == "blob"]
    if any(t.get("path") == "requirements" and t.get("type") == "tree" for t in tree.get("tree") or []):
        try:
            sub = client.get(f"/repos/{name}/contents/requirements", {"ref": sha})
            paths += [f"requirements/{x['name']}" for x in sub if x.get("type") == "file"]
        except GitHubError:
            pass
    files = select_files(paths)
    if not files:
        return {**rec, "reason": "no_requirements_file"}
    texts, counts = {}, {"lines": 0, "exact_pins": 0, "other": 0}
    for f in files:
        try:
            texts[f] = client.get(f"/repos/{name}/contents/{urllib.parse.quote(f)}", {"ref": sha}, raw=True)
        except GitHubError as e:
            return {**rec, "files": files, "reason": f"file_{e.code}"}
        for k, v in count_pins(texts[f]).items():
            counts[k] += v
    rec.update({"files": files, "counts": counts, "texts": texts})
    if counts["exact_pins"] < MIN_PINS:
        return {**rec, "reason": "fewer_than_5_exact_pins"}
    return {**rec, "eligible": True, "reason": "eligible"}


@dataclass
class SampleResult:
    accepted: dict
    checked: int


def sample(client: GitHubClient, frame: dict[str, dict], bands: dict[str, list[str]], cutoffs: list[date], out: Path,
           *, per_band: int = 100) -> SampleResult:
    """Check candidates in band order until each band has ``per_band`` eligible repositories. Writes
    ``checked.jsonl`` (one line per repository with every snapshot's reason) and the files of eligible snapshots under
    ``files/<owner>__<repo>/<cutoff>/``. Resumable: repositories already in ``checked.jsonl`` are not re-fetched."""
    out.mkdir(parents=True, exist_ok=True)
    log = out / "checked.jsonl"
    seen = {}
    if log.exists():
        for l in log.read_text(encoding="utf-8").splitlines():
            if l.strip():
                d = json.loads(l)
                seen[d["repo"]] = d
    accepted = {b: [r for r, d in seen.items() if d["band"] == b and d["eligible"]] for b in bands}
    checked = len(seen)
    for band, names in bands.items():
        for name in names:
            if len(accepted[band]) >= per_band:
                break
            if name in seen:
                continue
            snaps = [snapshot(client, frame[name], t) for t in cutoffs]
            eligible = any(s["eligible"] for s in snaps)
            for s in snaps:
                if s["eligible"]:
                    folder = out / "files" / name.replace("/", "__") / s["cutoff"]
                    folder.mkdir(parents=True, exist_ok=True)
                    for f, text in s["texts"].items():
                        (folder / f.replace("/", "__")).write_text(text, encoding="utf-8", newline="\n")
            row = {"repo": name, "band": band, "stars": frame[name]["stars"], "license": frame[name].get("license"),
                   "eligible": eligible, "snapshots": [{k: v for k, v in s.items() if k != "texts"} for s in snaps]}
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
            checked += 1
            if eligible:
                accepted[band].append(name)
    return SampleResult(accepted=accepted, checked=checked)
