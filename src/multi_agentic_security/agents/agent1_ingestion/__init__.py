"""Agent 1: deterministic dependency extraction (pipeline contract ``ExtractionResult``).

Sources: ``requirements*.txt``, ``package.json``, ``package-lock.json`` /
``npm-shrinkwrap.json``; imports in Python and JavaScript/TypeScript code;
install commands in shell scripts, Dockerfiles, Markdown and pasted text;
ZIP archives, folders and public GitHub repository links (downloaded as an
archive into memory). Uploaded content is read as text only and never
executed, imported or installed.
"""

from .common import STAGE_VERSION, UploadedFile
from .extract import classify, extract_directory, extract_files, extract_text, extract_zip
from .git_fetch import Fetcher, FetchResponse, GitLinkError, HttpsFetcher, extract_git, parse_repo_url
from .intake import DEFAULT_LIMITS, IntakeLimits

__all__ = [
    "STAGE_VERSION", "UploadedFile", "classify", "extract_directory", "extract_files", "extract_text", "extract_zip",
    "extract_git", "parse_repo_url", "Fetcher", "FetchResponse", "GitLinkError", "HttpsFetcher",
    "DEFAULT_LIMITS", "IntakeLimits",
]
