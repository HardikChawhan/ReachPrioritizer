"""Download a public GitHub repository as a ZIP so it can be scanned like an upload.

Only https://github.com/<owner>/<repo> URLs are accepted, the download goes to
GitHub's own archive host (codeload.github.com) and the same size / zip-bomb /
path-traversal checks as a manual upload are applied before anything is extracted.
"""
from __future__ import annotations

import logging
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple

from app.config import MAX_ZIP_SIZE

logger = logging.getLogger(__name__)

CODELOAD = "https://codeload.github.com"
_NAME = r"[A-Za-z0-9_.-]{1,100}"
_URL_RE = re.compile(
    rf"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>{_NAME})/(?P<repo>{_NAME}?)(?:\.git)?"
    rf"(?:/(?:tree|commit|blob)/(?P<ref>[^?#]+?))?/?(?:[?#].*)?$"
)
_REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")


class GitHubImportError(Exception):
    """User-facing error (bad URL, repo not found, too large, ...)."""


def parse_github_url(url: str, branch: Optional[str] = None) -> Tuple[str, str, Optional[str]]:
    """Return (owner, repo, ref). Accepts .../owner/repo, .git, /tree/<branch> and 'owner/repo'."""
    u = (url or "").strip()
    if re.match(rf"^{_NAME}/{_NAME}$", u):
        u = f"https://github.com/{u}"
    m = _URL_RE.match(u)
    if not m:
        raise GitHubImportError("Enter a public GitHub repository link like https://github.com/OWASP/NodeGoat")
    owner, repo, ref = m.group("owner"), m.group("repo"), m.group("ref")
    if repo.endswith(".git"):
        repo = repo[:-4]
    if owner in (".", "..") or repo in (".", "..", ""):
        raise GitHubImportError("Invalid repository name")
    ref = (branch or "").strip() or (urllib.parse.unquote(ref).strip("/") if ref else None)
    if ref and (not _REF_RE.match(ref) or ".." in ref):
        raise GitHubImportError("Invalid branch / tag name")
    return owner, repo, ref


def _candidates(owner: str, repo: str, ref: Optional[str]):
    base = f"{CODELOAD}/{owner}/{repo}/zip"
    if not ref:
        yield f"{base}/HEAD"
        return
    q = urllib.parse.quote(ref, safe="/")
    yield f"{base}/refs/heads/{q}"
    yield f"{base}/refs/tags/{q}"
    yield f"{base}/{q}"  # commit SHA


def _fetch(url: str, dest: Path) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": "ReachPrioritizer"})
    total = 0
    with urllib.request.urlopen(req, timeout=60) as r, open(dest, "wb") as out:
        length = r.headers.get("Content-Length")
        if length and int(length) > MAX_ZIP_SIZE:
            raise GitHubImportError(f"Repository archive is larger than the {MAX_ZIP_SIZE // (1024 * 1024)} MB limit")
        while True:
            chunk = r.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ZIP_SIZE:
                raise GitHubImportError(f"Repository archive is larger than the {MAX_ZIP_SIZE // (1024 * 1024)} MB limit")
            out.write(chunk)
    return total


def download_repo(url: str, dest: Path, branch: Optional[str] = None) -> Dict[str, object]:
    """Download the repository ZIP to `dest`. Returns {owner, repo, ref, commit, size, source_url}."""
    owner, repo, ref = parse_github_url(url, branch)
    last_404 = False
    for candidate in _candidates(owner, repo, ref):
        try:
            size = _fetch(candidate, dest)
            break
        except urllib.error.HTTPError as exc:
            dest.unlink(missing_ok=True)
            if exc.code == 404:
                last_404 = True
                continue
            raise GitHubImportError(f"GitHub answered HTTP {exc.code} for {owner}/{repo}") from exc
        except GitHubImportError:
            dest.unlink(missing_ok=True)
            raise
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            dest.unlink(missing_ok=True)
            raise GitHubImportError(f"Could not download from GitHub ({getattr(exc, 'reason', exc)}). Check your internet connection.") from exc
    else:
        if last_404:
            what = f"branch/tag '{ref}' of " if ref else ""
            raise GitHubImportError(f"Could not find {what}{owner}/{repo}. The repository may be private or the name is wrong.")
        raise GitHubImportError("Download failed")
    commit = None
    try:
        with zipfile.ZipFile(dest) as zf:
            c = (zf.comment or b"").decode("ascii", "ignore").strip()
            if re.fullmatch(r"[0-9a-f]{40}", c):
                commit = c  # GitHub stores the commit SHA in the archive comment
    except zipfile.BadZipFile as exc:
        dest.unlink(missing_ok=True)
        raise GitHubImportError("GitHub did not return a valid ZIP archive") from exc
    return {
        "owner": owner, "repo": repo, "ref": ref, "commit": commit, "size": size,
        "source_url": f"https://github.com/{owner}/{repo}" + (f"/tree/{ref}" if ref else ""),
        "label": (ref or "default branch") + (f" @ {commit[:7]}" if commit else ""),
    }


__all__ = ["GitHubImportError", "parse_github_url", "download_repo"]
