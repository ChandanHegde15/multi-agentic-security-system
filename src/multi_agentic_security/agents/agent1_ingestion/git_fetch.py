"""Public Git repository links (``git_repository`` source, D-047, D-052).

A repository link is never cloned: no ``git`` process, no hooks, no
submodules, no LFS. The repository is downloaded once as a ZIP archive over
HTTPS into memory and handed to the same intake checks as an uploaded ZIP.

Only public GitHub repositories are supported in this version
(``https://github.com/<owner>/<repo>`` with an optional ``/tree/<ref>``).
Downloads go through a ``Fetcher`` interface; the HTTPS implementation follows
redirects only to an allow-list of GitHub hosts, sends no credentials or
cookies, enforces a timeout and stops reading at the size limit. Tests replace
the fetcher with recorded responses and never use the network.
"""

from __future__ import annotations

import http.client
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional, Protocol

from multi_agentic_security.contracts.pipeline import ExtractionResult, InputSource

from .common import STAGE_VERSION, failure, redact, sha256_hex
from .extract import extract_zip
from .intake import DEFAULT_LIMITS, IntakeLimits

ALLOWED_HOSTS = frozenset({"github.com", "codeload.github.com"})
_SEGMENT = re.compile(r"^[A-Za-z0-9_.\-]{1,100}$")
_REF = re.compile(r"^[A-Za-z0-9_.\-/]{1,200}$")
USER_AGENT = "multi-agentic-security-agent1/0.1"
DEFAULT_TIMEOUT_S = 30.0          # per socket operation
DEFAULT_DEADLINE_S = 120.0        # whole download


class GitLinkError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code, self.detail = code, detail


@dataclass(frozen=True)
class RepoRef:
    owner: str
    repo: str
    ref: Optional[str]

    @property
    def canonical_url(self) -> str:
        base = f"https://github.com/{self.owner}/{self.repo}"
        return base + (f"/tree/{self.ref}" if self.ref else "")

    @property
    def archive_url(self) -> str:
        # The default branch is fetched through HEAD.
        return f"https://github.com/{self.owner}/{self.repo}/archive/{urllib.parse.quote(self.ref or 'HEAD', safe='/')}.zip"


def parse_repo_url(url: str) -> RepoRef:
    """Validate a public GitHub repository link or raise ``GitLinkError``."""
    if not isinstance(url, str) or not url.strip() or len(url) > 2048:
        raise GitLinkError("a1.git.invalid_url", "empty or overlong link")
    text = url.strip()
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme != "https":
        raise GitLinkError("a1.git.invalid_url", "only https:// links are accepted")
    if parsed.username or parsed.password:
        raise GitLinkError("a1.git.invalid_url", "links with credentials are refused")
    if parsed.port not in (None, 443):
        raise GitLinkError("a1.git.invalid_url", "links with a port are refused")
    host = (parsed.hostname or "").lower()
    if host in ("www.github.com",):
        host = "github.com"
    if host != "github.com":
        raise GitLinkError("a1.git.unsupported_host", f"host '{host}' is not supported; only public GitHub repositories are")
    if parsed.query or parsed.fragment:
        raise GitLinkError("a1.git.invalid_url", "links with a query or fragment are refused")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise GitLinkError("a1.git.invalid_url", "the link must name an owner and a repository")
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    for seg in (owner, repo):
        if not _SEGMENT.match(seg) or seg in (".", ".."):
            raise GitLinkError("a1.git.invalid_url", "owner or repository name has invalid characters")
    ref: Optional[str] = None
    if len(parts) > 2:
        if parts[2] != "tree" or len(parts) < 4:
            raise GitLinkError("a1.git.invalid_url", "only repository root or /tree/<ref> links are accepted")
        ref = "/".join(parts[3:])
        if not _REF.match(ref) or ".." in ref.split("/"):
            raise GitLinkError("a1.git.invalid_url", "the branch, tag or commit name has invalid characters")
    return RepoRef(owner, repo, ref)


@dataclass(frozen=True)
class FetchResponse:
    final_url: str
    status: int
    data: bytes


class Fetcher(Protocol):
    def fetch(self, url: str, *, max_bytes: int, timeout: float) -> FetchResponse:
        """Return the body, or raise ``GitLinkError`` (codes ``a1.git.*``)."""


class _AllowListRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_redirect(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_redirect(newurl: str) -> None:
    parts = urllib.parse.urlsplit(newurl)
    if parts.scheme != "https" or (parts.hostname or "").lower() not in ALLOWED_HOSTS or parts.username:
        raise GitLinkError("a1.git.redirect_refused", f"redirect to '{redact(newurl)[:200]}' is outside the allowed hosts")


class HttpsFetcher:
    """Real downloads. Used by the application only; tests use recorded responses."""

    def fetch(self, url: str, *, max_bytes: int, timeout: float) -> FetchResponse:
        check_redirect(url)
        opener = urllib.request.build_opener(_AllowListRedirects())
        opener.addheaders = [("User-Agent", USER_AGENT), ("Accept", "application/zip")]
        try:
            with opener.open(url, timeout=timeout) as resp:
                declared = resp.headers.get("Content-Length")
                if declared and declared.isdigit() and int(declared) > max_bytes:
                    raise GitLinkError("a1.git.too_large", f"archive is {declared} bytes; the limit is {max_bytes}")
                chunks, size = [], 0
                deadline = time.monotonic() + max(timeout * 4, DEFAULT_DEADLINE_S)
                while True:
                    if time.monotonic() > deadline:
                        raise GitLinkError("a1.git.fetch_error", "download took longer than the time limit")
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > max_bytes:
                        raise GitLinkError("a1.git.too_large", f"archive exceeds the limit of {max_bytes} bytes")
                    chunks.append(chunk)
                check_redirect(resp.geturl())
                return FetchResponse(final_url=resp.geturl(), status=resp.status, data=b"".join(chunks))
        except GitLinkError:
            raise
        except urllib.error.HTTPError as exc:
            raise GitLinkError("a1.git.http_status", f"the server answered HTTP {exc.code}") from None
        except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError, ValueError) as exc:
            raise GitLinkError("a1.git.fetch_error", f"download failed ({type(exc).__name__})") from None


def extract_git(project_id: str, url: str, fetcher: Fetcher, *, limits: IntakeLimits = DEFAULT_LIMITS,
                timeout: float = DEFAULT_TIMEOUT_S, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
                ) -> ExtractionResult:
    """Download a public GitHub repository as a ZIP into memory and extract it.

    The fetcher is a required argument so that no code path reaches the
    network by default.
    """
    started = clock()

    def failed(code: str, detail: str, locator: str) -> ExtractionResult:
        return ExtractionResult(
            project_id=project_id, stage_version=STAGE_VERSION, started_at=started,
            finished_at=max(clock(), started),
            sources=[InputSource(kind="git_repository", locator=locator)], dependencies=[],
            failures=[failure("agent1", code, detail + "; nothing was extracted")])

    try:
        ref = parse_repo_url(url)
    except GitLinkError as exc:
        return failed(exc.code, exc.detail, "invalid-link")
    try:
        resp = fetcher.fetch(ref.archive_url, max_bytes=limits.max_upload_bytes, timeout=timeout)
    except GitLinkError as exc:
        return failed(exc.code, exc.detail, ref.canonical_url)
    except Exception as exc:  # any other fetcher problem is a failure state, never a crash
        return failed("a1.git.fetch_error", f"download failed ({type(exc).__name__})", ref.canonical_url)
    if not isinstance(resp, FetchResponse) or not isinstance(resp.data, bytes):
        return failed("a1.git.fetch_error", "the fetcher returned no archive", ref.canonical_url)
    if len(resp.data) > limits.max_upload_bytes:
        return failed("a1.git.too_large", f"archive exceeds the limit of {limits.max_upload_bytes} bytes", ref.canonical_url)
    if resp.status != 200:
        return failed("a1.git.http_status", f"the server answered HTTP {resp.status}", ref.canonical_url)
    try:
        check_redirect(resp.final_url)
    except GitLinkError as exc:
        return failed(exc.code, exc.detail, ref.canonical_url)
    source = InputSource(kind="git_repository", locator=ref.canonical_url, sha256=sha256_hex(resp.data),
                         size_bytes=len(resp.data))
    return extract_zip(project_id, resp.data, f"{ref.repo}.zip", limits=limits, clock=clock, source=source)
