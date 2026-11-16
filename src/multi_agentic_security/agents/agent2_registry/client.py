"""Registry clients for Agent 2 (D-021, D-034, D-047 b, D-053).

Three modes:

* ``off``      - no client; every record is ``not_checked`` (handled in ``verify``).
* ``snapshot`` - ``SnapshotRegistryClient`` reads recorded, dated responses from a
                 folder given as an argument. It never opens a network connection.
* ``live``     - ``HttpRegistryClient`` asks the PyPI JSON API and the npm registry
                 for metadata only. Nothing is downloaded as a package or installed.

Both real clients turn a registry response into a ``LookupOutcome`` with the
same parsers, so a recorded response and a live response give the same result.

Rules that hold everywhere:

* HTTP 404 is ``not_found``. Timeouts, connection errors, HTTP 429 and 5xx are
  ``lookup_error`` - never ``not_found``. Malformed JSON or an unexpected
  structure is ``invalid_response``.
* Every lookup carries ``retrieved_at`` (D-021). A lookup is a current fact, not a
  historical one.
* ``canonical_name``, the version list, the per-version upload times and
  ``latest_version`` come from the registry response, never from the request.
* No request is built from a name that is not valid for its registry.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, Protocol, Union

from multi_agentic_security.datasets.names import normalize_name

Clock = Callable[[], datetime]

CLIENT_VERSION = "registry_client/1"
SNAPSHOT_FORMAT = "registry_snapshot/1"
RUN_RECORD_NAME = "RUN_RECORD.json"   # selection rule and hashes of a snapshot run; skipped when loading

PYPI_HOST = "pypi.org"
NPM_HOST = "registry.npmjs.org"
ALLOWED_HOSTS = frozenset({PYPI_HOST, NPM_HOST})
# Generic: names the software, not the user or the machine.
USER_AGENT = "registry-metadata-client/1"

DEFAULT_TIMEOUT_S = 15.0
DEFAULT_DEADLINE_S = 60.0
DEFAULT_MAX_BYTES = 50 * 1024 * 1024     # large npm documents (thousands of versions) stay below this
DEFAULT_RETRIES = 2                      # 3 attempts in total
DEFAULT_BACKOFF_S = 1.0
MAX_BACKOFF_S = 10.0
MAX_SNAPSHOT_FILE_BYTES = 64 * 1024 * 1024
MAX_METADATA_CHARS = 300

# PEP 508 project names; npm names after normalization (lower case, optional scope).
_PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,198}[A-Za-z0-9])?$")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- outcome

@dataclass(frozen=True)
class LookupOutcome:
    """What one registry lookup established. ``status`` uses the contract values."""

    status: str
    rule_id: str
    explanation: str
    retrieved_at: datetime
    source_url: str
    canonical_name: Optional[str] = None
    versions: Optional[list[str]] = None
    upload_times: Optional[dict[str, Optional[datetime]]] = None
    latest_version: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    inputs: dict[str, Any] = field(default_factory=dict)


class RegistryClient(Protocol):
    mode: str  # "live" or "snapshot"

    def supports(self, ecosystem: str) -> bool:
        """True if this client can look up packages of ``ecosystem``."""

    def lookup(self, ecosystem: str, name_normalized: str) -> Optional[LookupOutcome]:
        """Look up one package. ``None`` means "no data" (a snapshot without this package)."""


# --------------------------------------------------------------------------- names and URLs

def valid_registry_name(ecosystem: str, name: str) -> bool:
    if not isinstance(name, str) or len(name) > 214:
        return False
    if ecosystem == "pypi":
        return bool(_PYPI_NAME.fullmatch(name))
    if ecosystem == "npm":
        return bool(_NPM_NAME.fullmatch(name)) and ".." not in name
    return False


def registry_url(ecosystem: str, name: str) -> str:
    """Metadata URL of a package. Scoped npm names are URL-encoded (``@a/b`` -> ``@a%2Fb``)."""
    if not valid_registry_name(ecosystem, name):
        raise ValueError(f"not a valid {ecosystem} package name: {name!r}")
    if ecosystem == "pypi":
        return f"https://{PYPI_HOST}/pypi/{urllib.parse.quote(name, safe='')}/json"
    return f"https://{NPM_HOST}/{urllib.parse.quote(name, safe='@')}"


# --------------------------------------------------------------------------- parsing (shared by live and snapshot)

class InvalidResponse(ValueError):
    pass


def _text(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = _CONTROL.sub("", value).strip()
    return value[:MAX_METADATA_CHARS] if value else None


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if t.tzinfo is None:  # PyPI's plain "upload_time" is UTC
            t = t.replace(tzinfo=timezone.utc)
        return t.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _order(times: dict[str, Optional[datetime]]) -> list[str]:
    """Upload order (unknown times last), then the version string; deterministic."""
    far = datetime.max.replace(tzinfo=timezone.utc)
    return sorted(times, key=lambda v: (times[v] is None, times[v] or far, v))


def parse_pypi(doc: Any, *, retrieved_at: datetime, url: str) -> LookupOutcome:
    """PyPI JSON API document (``/pypi/<name>/json``) -> ``found``."""
    if not isinstance(doc, dict) or not isinstance(doc.get("info"), dict):
        raise InvalidResponse("PyPI response has no 'info' object")
    info = doc["info"]
    name = info.get("name")
    if not isinstance(name, str) or not name.strip():
        raise InvalidResponse("PyPI response has no package name")
    releases = doc.get("releases")
    if not isinstance(releases, dict):
        raise InvalidResponse("PyPI response has no 'releases' object")
    times: dict[str, Optional[datetime]] = {}
    yanked: list[str] = []
    for version, files in releases.items():
        if not isinstance(version, str) or not version or not isinstance(files, list):
            raise InvalidResponse("PyPI 'releases' entry is not a version with a file list")
        stamps = []
        for f in files:
            if not isinstance(f, dict):
                raise InvalidResponse("PyPI release file entry is not an object")
            t = _parse_time(f.get("upload_time_iso_8601")) or _parse_time(f.get("upload_time"))
            if t is not None:
                stamps.append(t)
        times[version] = min(stamps) if stamps else None
        if files and all(isinstance(f, dict) and f.get("yanked") is True for f in files):
            yanked.append(version)
    latest = info.get("version") if isinstance(info.get("version"), str) else None
    metadata = {k: v for k, v in {
        "summary": _text(info.get("summary")),
        "home_page": _text(info.get("home_page")),
        "license": _text(info.get("license")),
        "yanked_versions": sorted(yanked) or None,
        "versions_without_files": sorted(v for v, t in times.items() if t is None) or None,
    }.items() if v is not None}
    versions = _order(times)
    return LookupOutcome(
        status="found", rule_id="a2.status.found",
        explanation=f"PyPI lists '{name}' with {len(versions)} version(s).",
        retrieved_at=retrieved_at, source_url=url, canonical_name=name.strip(), versions=versions,
        upload_times={v: times[v] for v in versions}, latest_version=latest, metadata=metadata,
        inputs={"registry": "pypi", "versions": len(versions)})


def _npm_security_holder(versions: dict, dist_tags: dict) -> bool:
    """npm replaces removed malicious packages with a holding package ``0.0.1-security``.

    Rule: every listed version ends in ``-security`` and the ``latest`` tag points to
    one of them. Checked against 4 of 4 recorded real responses (live check
    2026-11-16, D-054): versions ``{"0.0.1-security"}``, description "security
    holding package", repository ``npm/security-holder``; ``time`` still lists the
    removed versions with their upload times.
    """
    if not versions:
        return False
    latest = dist_tags.get("latest") if isinstance(dist_tags, dict) else None
    return all(isinstance(v, str) and v.endswith("-security") for v in versions) and (
        isinstance(latest, str) and latest in versions)


def parse_npm(doc: Any, *, retrieved_at: datetime, url: str) -> LookupOutcome:
    """npm registry packument -> ``found``, ``security_placeholder`` or ``not_found`` (unpublished)."""
    if not isinstance(doc, dict):
        raise InvalidResponse("npm response is not an object")
    name = doc.get("name")
    if not isinstance(name, str) or not name.strip():
        raise InvalidResponse("npm response has no package name")
    raw_versions = doc.get("versions", {})
    raw_time = doc.get("time", {})
    dist_tags = doc.get("dist-tags", {})
    if not isinstance(raw_versions, dict) or not isinstance(raw_time, dict) or not isinstance(dist_tags, dict):
        raise InvalidResponse("npm 'versions', 'time' or 'dist-tags' is not an object")
    if not raw_versions:
        if "unpublished" in raw_time:
            # UNVERIFIED rule: an unpublished package keeps a document with time.unpublished
            # and no versions. Nothing can be installed, so it counts as not found.
            return LookupOutcome(
                status="not_found", rule_id="a2.status.npm_unpublished",
                explanation=f"npm package '{name}' was unpublished; no version can be installed.",
                retrieved_at=retrieved_at, source_url=url, canonical_name=None,
                metadata={"unpublished": True}, inputs={"registry": "npm"})
        raise InvalidResponse("npm response lists no versions")
    if _npm_security_holder(raw_versions, dist_tags):
        # Versions that were removed still appear in "time": their upload times date the original
        # package; the holder's own time dates the takedown. Both are registry facts, not judgements.
        removed = {v: _parse_time(t) for v, t in raw_time.items()
                   if isinstance(v, str) and v not in raw_versions and v not in ("created", "modified", "unpublished")}
        holder_times = [_parse_time(raw_time.get(v)) for v in raw_versions]
        holder_times = [t for t in holder_times if t is not None]
        repo = doc.get("repository")
        if isinstance(repo, dict):
            repo = repo.get("url")
        return LookupOutcome(
            status="security_placeholder", rule_id="a2.status.security_placeholder",
            explanation=(f"npm shows '{name}' only as a security holding package "
                         f"({', '.join(sorted(raw_versions))}); the registry removed the original package"
                         + (f" ({len(removed)} removed version(s) still listed with upload times)." if removed else ".")),
            retrieved_at=retrieved_at, source_url=url, canonical_name=name.strip(),
            metadata={k: v for k, v in {
                "placeholder_versions": sorted(raw_versions),
                "description": _text(doc.get("description")),
                "repository": _text(repo),
                "placeholder_published": min(holder_times).isoformat() if holder_times else None,
                "removed_versions": {v: (t.isoformat() if t else None) for v, t in sorted(removed.items())} or None,
            }.items() if v is not None},
            inputs={"registry": "npm", "versions": sorted(raw_versions), "removed_versions": len(removed)})
    times = {v: _parse_time(raw_time.get(v)) for v in raw_versions if isinstance(v, str) and v}
    if len(times) != len(raw_versions):
        raise InvalidResponse("npm 'versions' has a non-string key")
    licence = doc.get("license")
    if isinstance(licence, dict):
        licence = licence.get("type")
    repo = doc.get("repository")
    if isinstance(repo, dict):
        repo = repo.get("url")
    latest = dist_tags.get("latest") if isinstance(dist_tags.get("latest"), str) else None
    metadata = {k: v for k, v in {
        "description": _text(doc.get("description")),
        "homepage": _text(doc.get("homepage")),
        "license": _text(licence),
        "repository": _text(repo),
        "created": _text(raw_time.get("created")),
        "deprecated_latest": _text((raw_versions.get(latest) or {}).get("deprecated")) if latest and isinstance(
            raw_versions.get(latest), dict) else None,
    }.items() if v is not None}
    versions = _order(times)
    return LookupOutcome(
        status="found", rule_id="a2.status.found",
        explanation=f"npm lists '{name}' with {len(versions)} version(s).",
        retrieved_at=retrieved_at, source_url=url, canonical_name=name.strip(), versions=versions,
        upload_times={v: times[v] for v in versions}, latest_version=latest, metadata=metadata,
        inputs={"registry": "npm", "versions": len(versions)})


def outcome_from_response(ecosystem: str, url: str, http_status: Optional[int], body: Optional[bytes],
                          retrieved_at: datetime, *, attempts: int = 1, error: Optional[str] = None,
                          requested: Optional[str] = None) -> LookupOutcome:
    """Map one HTTP result (live or recorded) to an outcome. Shared by both clients."""
    inputs = {"registry": ecosystem, "http_status": http_status, "attempts": attempts}
    if http_status is None:
        return LookupOutcome(status="lookup_error", rule_id="a2.status.lookup_error",
                             explanation=f"The {ecosystem} registry could not be reached ({error or 'no response'}); "
                                         "existence is unknown, which is not the same as not found.",
                             retrieved_at=retrieved_at, source_url=url, error=error or "no response", inputs=inputs)
    if http_status == 404:
        return LookupOutcome(status="not_found", rule_id="a2.status.not_found",
                             explanation=f"The {ecosystem} registry answered 404: no package with this name exists "
                                         "there at the time of the lookup.",
                             retrieved_at=retrieved_at, source_url=url, inputs=inputs)
    if http_status != 200:
        kind = "rate limited" if http_status == 429 else ("server error" if http_status >= 500 else "unexpected status")
        return LookupOutcome(status="lookup_error", rule_id="a2.status.lookup_error",
                             explanation=f"The {ecosystem} registry answered HTTP {http_status} ({kind}); existence is "
                                         "unknown, which is not the same as not found.",
                             retrieved_at=retrieved_at, source_url=url,
                             error=f"HTTP {http_status} after {attempts} attempt(s)", inputs=inputs)
    try:
        doc = json.loads((body or b"").decode("utf-8"))
        parser = parse_pypi if ecosystem == "pypi" else parse_npm
        outcome = parser(doc, retrieved_at=retrieved_at, url=url)
        if requested is not None and outcome.canonical_name is not None and \
                normalize_name(ecosystem, outcome.canonical_name) != requested:
            raise InvalidResponse(f"the response describes '{outcome.canonical_name[:100]}', not the requested package")
    # ValueError covers JSONDecodeError, InvalidResponse and integer-size limits; OverflowError covers date arithmetic.
    except (UnicodeDecodeError, ValueError, OverflowError, RecursionError) as exc:
        detail = str(exc) if isinstance(exc, InvalidResponse) else f"malformed JSON ({type(exc).__name__})"
        return LookupOutcome(status="invalid_response", rule_id="a2.status.invalid_response",
                             explanation=f"The {ecosystem} registry answered, but the response could not be read "
                                         f"({detail}); existence is not decided.",
                             retrieved_at=retrieved_at, source_url=url, error=detail[:300], inputs=inputs)
    return LookupOutcome(**{**outcome.__dict__, "inputs": {**outcome.inputs, **inputs}})


# --------------------------------------------------------------------------- live (HTTP)

@dataclass(frozen=True)
class HttpResponse:
    status: int
    final_url: str
    headers: dict[str, str]
    body: bytes


class TransportError(Exception):
    """``kind``: timeout, connection, too_large, redirect_refused, host_refused."""

    def __init__(self, kind: str, detail: str):
        super().__init__(detail)
        self.kind, self.detail = kind, detail


class Transport(Protocol):
    def get(self, url: str, *, timeout: float, max_bytes: int, deadline_s: float) -> HttpResponse:
        """Return the response (any HTTP status) or raise ``TransportError``."""


def check_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "").lower() not in ALLOWED_HOSTS or parts.username \
            or parts.password or parts.port not in (None, 443):
        raise TransportError("redirect_refused", "URL outside the registry allow-list")


class _AllowListRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _read_capped(resp, max_bytes: int, deadline: float) -> bytes:
    declared = resp.headers.get("Content-Length")
    if declared and declared.isdigit() and int(declared) > max_bytes:
        raise TransportError("too_large", f"response of {declared} bytes exceeds the limit of {max_bytes}")
    chunks, size = [], 0
    while True:
        if time.monotonic() > deadline:
            raise TransportError("timeout", "response took longer than the time limit")
        chunk = resp.read(65536)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > max_bytes:
            raise TransportError("too_large", f"response exceeds the limit of {max_bytes} bytes")
        chunks.append(chunk)


class UrllibTransport:
    """HTTPS GET with the standard library: no cookies, no credentials, no proxy settings
    from the environment, redirects only inside the allow-list."""

    def __init__(self) -> None:
        # ProxyHandler({}) ignores proxy environment variables; build_opener adds no cookie processor.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _AllowListRedirects())
        self._opener.addheaders = [("User-Agent", USER_AGENT), ("Accept", "application/json")]

    def get(self, url: str, *, timeout: float, max_bytes: int, deadline_s: float) -> HttpResponse:
        check_url(url)
        deadline = time.monotonic() + deadline_s
        try:
            with self._opener.open(url, timeout=timeout) as resp:
                body = _read_capped(resp, max_bytes, deadline)
                check_url(resp.geturl())
                return HttpResponse(resp.status, resp.geturl(), {k.lower(): v for k, v in resp.headers.items()}, body)
        except TransportError:
            raise
        except urllib.error.HTTPError as exc:
            try:
                body = _read_capped(exc, max_bytes, deadline) if exc.fp is not None else b""
            except TransportError:
                body = b""
            headers = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
            return HttpResponse(exc.code, exc.geturl() or url, headers, body)
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise TransportError("timeout", "connection timed out") from None
            if isinstance(exc.reason, TransportError):
                raise exc.reason from None
            raise TransportError("connection", f"connection failed ({type(exc.reason).__name__})") from None
        except (socket.timeout, TimeoutError):
            raise TransportError("timeout", "connection timed out") from None
        except (http.client.HTTPException, OSError, ValueError) as exc:
            raise TransportError("connection", f"connection failed ({type(exc).__name__})") from None


def _retry_after(headers: dict[str, str]) -> Optional[float]:
    value = headers.get("retry-after", "")
    return float(value) if value.strip().isdigit() else None


class HttpRegistryClient:
    """Live, metadata-only lookups against pypi.org and registry.npmjs.org.

    Constructed only by an application that has decided to use the network; no
    other code path creates one. Tests inject a recorded ``transport``.
    """

    mode = "live"

    def __init__(self, *, transport: Optional[Transport] = None, clock: Clock = _utc_now,
                 timeout: float = DEFAULT_TIMEOUT_S, deadline_s: float = DEFAULT_DEADLINE_S,
                 max_bytes: int = DEFAULT_MAX_BYTES, retries: int = DEFAULT_RETRIES,
                 backoff_s: float = DEFAULT_BACKOFF_S, sleep: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] = time.monotonic):
        if retries < 0 or retries > 5:
            raise ValueError("retries must be between 0 and 5")
        if not (0 < timeout <= 120 and 0 < deadline_s <= 600 and 0 <= backoff_s <= MAX_BACKOFF_S
                and 0 < max_bytes <= 512 * 1024 * 1024):
            raise ValueError("timeout, deadline_s, backoff_s or max_bytes out of range")
        self._transport = transport if transport is not None else UrllibTransport()
        self._clock, self._timeout, self._deadline = clock, timeout, deadline_s
        self._max_bytes, self._retries, self._backoff, self._sleep = max_bytes, retries, backoff_s, sleep
        self._monotonic = monotonic

    def supports(self, ecosystem: str) -> bool:
        return ecosystem in ("pypi", "npm")

    def lookup(self, ecosystem: str, name_normalized: str) -> LookupOutcome:
        url = registry_url(ecosystem, name_normalized)
        last_error, last_status = "no response", None
        end = self._monotonic() + self._deadline  # one deadline for all attempts and waits together
        made = 0
        for attempt in range(1, self._retries + 2):
            retry_wait: Optional[float] = None
            remaining = end - self._monotonic()
            if remaining <= 0:
                last_error = f"overall deadline of {self._deadline:.0f} s reached; {last_error}"
                break
            made = attempt
            try:
                resp = self._transport.get(url, timeout=min(self._timeout, remaining), max_bytes=self._max_bytes,
                                           deadline_s=remaining)
            except TransportError as exc:
                last_error, last_status = f"{exc.kind}: {exc.detail}", None
                if exc.kind not in ("timeout", "connection"):
                    return outcome_from_response(ecosystem, url, None, None, self._clock(), attempts=attempt,
                                                 error=last_error)
            except Exception as exc:  # a broken transport is a failure state, never a crash
                return outcome_from_response(ecosystem, url, None, None, self._clock(), attempts=attempt,
                                             error=f"transport failed ({type(exc).__name__})")
            else:
                if resp.status == 429 or resp.status >= 500:
                    last_status = resp.status
                    retry_wait = _retry_after(resp.headers)
                else:
                    return outcome_from_response(ecosystem, url, resp.status, resp.body, self._clock(),
                                                 attempts=attempt, requested=name_normalized)
            if attempt <= self._retries:
                wait = min(MAX_BACKOFF_S, max(self._backoff * (2 ** (attempt - 1)), retry_wait or 0.0))
                if self._monotonic() + wait >= end:
                    last_error = f"overall deadline of {self._deadline:.0f} s reached; {last_error}"
                    break
                self._sleep(wait)
        return outcome_from_response(ecosystem, url, last_status, None, self._clock(),
                                     attempts=max(made, 1), error=last_error)


# --------------------------------------------------------------------------- snapshot

@dataclass(frozen=True)
class SnapshotEntry:
    ecosystem: str
    name_normalized: str
    url: str
    retrieved_at: datetime
    http_status: Optional[int]
    body: Optional[bytes]
    error: Optional[str]
    file: str


def _snapshot_entry(path: Path) -> SnapshotEntry:
    if path.stat().st_size > MAX_SNAPSHOT_FILE_BYTES:
        raise ValueError(f"larger than {MAX_SNAPSHOT_FILE_BYTES} bytes")
    doc = json.loads(path.read_bytes().decode("utf-8"))
    if not isinstance(doc, dict) or doc.get("format") != SNAPSHOT_FORMAT:
        raise ValueError(f"not a {SNAPSHOT_FORMAT} file")
    ecosystem, name = doc.get("ecosystem"), doc.get("name")
    if ecosystem not in ("pypi", "npm") or not isinstance(name, str):
        raise ValueError("ecosystem or name missing")
    normalized = normalize_name(ecosystem, name)
    retrieved = doc.get("retrieved_at")
    t = datetime.fromisoformat(retrieved) if isinstance(retrieved, str) else None
    if t is None or t.tzinfo is None:
        raise ValueError("retrieved_at missing or without a time zone")
    t = t.astimezone(timezone.utc)  # may raise OverflowError: reported as an unusable recording
    status = doc.get("http_status")
    if status is not None and (not isinstance(status, int) or isinstance(status, bool)):
        raise ValueError("http_status is not an integer")
    if "body" in doc and "body_raw" in doc:
        raise ValueError("both body and body_raw given")
    if "body_raw" in doc:
        if not isinstance(doc["body_raw"], str):
            raise ValueError("body_raw is not a string")
        body = doc["body_raw"].encode("utf-8")
    elif doc.get("body") is not None:
        body = json.dumps(doc["body"]).encode("utf-8")
    else:
        body = None
    if status is None and not doc.get("error"):
        raise ValueError("a recording without http_status needs an error")
    url = doc.get("url") if isinstance(doc.get("url"), str) else registry_url(ecosystem, normalized)
    return SnapshotEntry(ecosystem, normalized, url, t, status, body,
                         str(doc["error"])[:300] if doc.get("error") else None, path.name)


class SnapshotRegistryClient:
    """Recorded registry responses in ``folder`` (one ``registry_snapshot/1`` JSON file
    per lookup, non-recursive). Never touches the network.

    ``load_failures`` lists files that could not be used; two files for the same
    package make that package a ``lookup_error`` (the snapshot cannot answer).
    """

    mode = "snapshot"

    def __init__(self, folder: Union[str, Path]):
        self.folder = Path(folder)
        self.load_failures: list[tuple[str, str]] = []
        self._entries: dict[tuple[str, str], SnapshotEntry] = {}
        self._conflicts: dict[tuple[str, str], list[SnapshotEntry]] = {}
        if not self.folder.is_dir():
            self.load_failures.append((str(self.folder.name), "snapshot folder does not exist"))
            return
        for path in sorted(self.folder.glob("*.json")):
            if path.name == RUN_RECORD_NAME:  # the run's own description, not a recording
                continue
            if not path.is_file() or path.is_symlink():
                self.load_failures.append((path.name, "not a regular file"))
                continue
            try:
                entry = _snapshot_entry(path)
            except (OSError, ValueError, OverflowError, UnicodeDecodeError, RecursionError) as exc:
                self.load_failures.append((path.name, f"unusable recording: {str(exc)[:200]}"))
                continue
            key = (entry.ecosystem, entry.name_normalized)
            if key in self._entries or key in self._conflicts:
                first = self._entries.pop(key, None)
                self._conflicts.setdefault(key, [first] if first else []).append(entry)
                continue
            self._entries[key] = entry

    def supports(self, ecosystem: str) -> bool:
        return ecosystem in ("pypi", "npm")

    def lookup(self, ecosystem: str, name_normalized: str) -> Optional[LookupOutcome]:
        key = (ecosystem, name_normalized)
        if key in self._conflicts:
            entries = self._conflicts[key]
            files = sorted(e.file for e in entries)
            return LookupOutcome(status="lookup_error", rule_id="a2.status.snapshot_conflict",
                                 explanation="The snapshot holds more than one recording for this package, so it "
                                             "cannot say which one is right.",
                                 retrieved_at=max(e.retrieved_at for e in entries),
                                 source_url=registry_url(ecosystem, name_normalized),
                                 error=f"conflicting snapshot recordings: {', '.join(files)}",
                                 inputs={"registry": ecosystem, "files": files})
        entry = self._entries.get(key)
        if entry is None:
            return None
        outcome = outcome_from_response(ecosystem, entry.url, entry.http_status, entry.body, entry.retrieved_at,
                                        error=entry.error, requested=name_normalized)
        return LookupOutcome(**{**outcome.__dict__, "inputs": {**outcome.inputs, "snapshot_file": entry.file}})
