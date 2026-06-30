"""Fetch PushEvents from GH Archive and pull diffs from git forges.

Supported forges:
  - github        Bearer token  repos/{o}/{r}/commits/{sha}
  - gitlab        PRIVATE-TOKEN projects/{o}%2F{r}/repository/commits/{sha}
  - gitea         Bearer token  repos/{o}/{r}/git/commits/{sha}
  - gogs          Bearer token  repos/{o}/{r}/git/commits/{sha}
  - bitbucket     Bearer token  repositories/{o}/{r}/commit/{sha}
  - azure_devops  Basic:PAT     {org}/{project}/_apis/git/repositories/{repo}/commits/{commitId}
  - codecommit    (clone only)  AWS SigV4 too complex — falls back to git clone
  - sourceforge   Bearer token  p/{o}/{r}/git/commits/{sha}
  - custom        Bearer token  user-provided URL pattern
  → Self-hosted: set --forge-type and --git-api-base
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import logging
import subprocess
import tempfile
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

from . import config

log = logging.getLogger(__name__)


class GitAPIClient:
    """Multi-forge git API client with caching.

    Token behaviour per forge:
      github/gitea/gogs/bitbucket/sourceforge/custom → Authorization: Bearer
      gitlab                                          → PRIVATE-TOKEN header
      azure_devops                                    → Basic auth with PAT
      codecommit                                      → clone only (no API)
    """

    def __init__(
        self,
        token: str | None = None,
        api_base: str | None = None,
        forge_type: str = "github",
    ) -> None:
        self.token = token
        self.forge_type = forge_type.lower()
        self.api_base = (
            api_base or config.FORGE_API_DEFAULTS.get(self.forge_type, config.GH_API_BASE)
        )
        self.api_base = self.api_base.rstrip("/")

        headers = {"User-Agent": config.USER_AGENT}

        if token:
            if self.forge_type == "gitlab":
                headers["PRIVATE-TOKEN"] = token
            elif self.forge_type == "azure_devops":
                b64 = base64.b64encode(f":{token}".encode()).decode()
                headers["Authorization"] = f"Basic {b64}"
            else:
                headers["Authorization"] = f"Bearer {token}"

        self._client = httpx.Client(headers=headers, timeout=30)
        self._msg_cache: dict[str, str | None] = {}
        self._diff_cache: dict[str, str | None] = {}
        self.rate_remaining = 5000 if token else 60
        self.rate_reset = 0.0
        self.api_calls = 0

    # ── URL builders per forge ────────────────────────────────────

    def _commit_url(self, owner: str, repo: str, sha: str) -> str:
        ft = self.forge_type
        if ft == "gitlab":
            return (f"{self.api_base}/projects/{owner}%2F{repo}"
                    f"/repository/commits/{sha}")
        if ft == "bitbucket":
            return f"{self.api_base}/repositories/{owner}/{repo}/commit/{sha}"
        if ft == "azure_devops":
            return (f"{self.api_base}/{owner}/{repo}/_apis/git/repositories/"
                    f"{repo}/commits/{sha}?api-version=7.0")
        if ft == "sourceforge":
            return f"{self.api_base}/p/{owner}/{repo}/git/commits/{sha}"
        # github, gitea, gogs, custom default to /repos/{o}/{r}/commits/{sha}
        return f"{self.api_base}/repos/{owner}/{repo}/commits/{sha}"

    def _diff_url(self, owner: str, repo: str, sha: str) -> str:
        ft = self.forge_type

        # PR diff routing
        if sha.startswith("pr-"):
            pr_num = sha.split("-", 1)[1]
            if ft == "github":
                return f"{self.api_base}/repos/{owner}/{repo}/pulls/{pr_num}"
            if ft == "gitlab":
                return (f"{self.api_base}/projects/{owner}%2F{repo}"
                        f"/merge_requests/{pr_num}/diffs")
            if ft in ("gitea", "gogs"):
                return f"{self.api_base}/repos/{owner}/{repo}/pulls/{pr_num}.diff"
            # fallback: treat as commit
            return f"{self.api_base}/repos/{owner}/{repo}/commits/{sha}"

        base = self._commit_url(owner, repo, sha)
        if ft == "gitlab":
            return f"{base}/diff"
        if ft == "bitbucket":
            return f"{base}/diff"
        if ft == "azure_devops":
            return f"{base}/changes?api-version=7.0"
        return base

    # ── Rate-limit handling ───────────────────────────────────────

    def _check_rate_limit(self) -> None:
        if self.rate_remaining > 0:
            return
        now = time.time()
        if now < self.rate_reset:
            log.warning("Rate limit exhausted, sleeping %.0fs", self.rate_reset - now + 1)
            time.sleep(self.rate_reset - now + 1)

    def _update_rate_limit(self) -> None:
        if self.forge_type != "github":
            return
        try:
            resp = self._client.get(f"{self.api_base}/rate_limit")
            if resp.status_code == 200:
                core = resp.json().get("resources", {}).get("core", {})
                self.rate_remaining = core.get("remaining", 0)
                self.rate_reset = core.get("reset", 0)
        except Exception:
            pass

    # ── Fetch commit message ──────────────────────────────────────

    def fetch_commit_message(self, owner: str, repo: str, sha: str) -> str | None:
        key = f"{owner}/{repo}/{sha}"
        if key in self._msg_cache:
            return self._msg_cache[key]
        if self.forge_type == "codecommit":
            return self._fetch_codecommit_msg(owner, repo, sha)

        self._check_rate_limit()
        url = self._commit_url(owner, repo, sha)
        try:
            resp = self._client.get(url)
            self.api_calls += 1
            self.rate_remaining = max(0, self.rate_remaining - 1)
            if resp.status_code == 200:
                msg = self._extract_message(resp)
                self._msg_cache[key] = msg
                return msg
            elif resp.status_code in (403, 429):
                self._update_rate_limit()
                return None
            elif resp.status_code == 404:
                self._msg_cache[key] = None
                return None
            else:
                log.debug("Commit msg %s: HTTP %d", url, resp.status_code)
                return None
        except Exception as exc:
            log.warning("Commit msg fetch failed: %s", exc)
            return None

    def _extract_message(self, resp: httpx.Response) -> str | None:
        ft = self.forge_type
        data = resp.json()
        if ft == "gitlab":
            raw = data.get("message", "")
        elif ft == "bitbucket":
            raw = (data.get("summary") or {}).get("raw", "")
        elif ft == "azure_devops":
            raw = data.get("comment", "")
        elif ft == "sourceforge":
            raw = data.get("message", "") or data.get("title", "")
        else:
            raw = (data.get("commit") or {}).get("message", "")
        first = raw.split("\n")[0] if raw else None
        return first

    def _fetch_codecommit_msg(self, owner: str, repo: str, sha: str) -> str | None:
        """CodeCommit has no REST API — fall back to git clone + log."""
        url = self._codecommit_clone_url(owner, repo)
        try:
            p = clone_repo(url, sha)
            result = subprocess.run(
                ["git", "-C", str(p), "log", "--format=%s", "-1", sha],
                capture_output=True, text=True, timeout=30,
            )
            return result.stdout.strip() or None
        except Exception as exc:
            log.warning("CodeCommit msg fetch failed: %s", exc)
            return None

    def _codecommit_clone_url(self, owner: str, repo: str) -> str:
        region = owner  # owner acts as region for codecommit
        if self.token:
            return (f"https://{self.token}@git-codecommit.{region}.amazonaws.com/"
                    f"v1/repos/{repo}")
        return f"https://git-codecommit.{region}.amazonaws.com/v1/repos/{repo}"

    # ── Fetch diff ────────────────────────────────────────────────

    def fetch_diff(self, owner: str, repo: str, sha: str) -> str | None:
        key = f"{owner}/{repo}/{sha}"
        if key in self._diff_cache:
            return self._diff_cache[key]
        if self.forge_type == "codecommit":
            return self._fetch_codecommit_diff(owner, repo, sha)

        self._check_rate_limit()
        url = self._diff_url(owner, repo, sha)
        headers = {"User-Agent": config.USER_AGENT}
        ft = self.forge_type

        if ft == "github":
            headers["Accept"] = "application/vnd.github.v3.diff"
        elif ft == "bitbucket":
            headers["Accept"] = "application/x.diff"
        elif ft in ("gitea", "gogs"):
            headers["Accept"] = "application/vnd.git.diff"
        elif ft == "sourceforge":
            headers["Accept"] = "application/vnd.git.diff"

        if self.token:
            if ft == "gitlab":
                headers["PRIVATE-TOKEN"] = self.token
            elif ft == "azure_devops":
                b64 = base64.b64encode(f":{self.token}".encode()).decode()
                headers["Authorization"] = f"Basic {b64}"
            else:
                headers["Authorization"] = f"Bearer {self.token}"

        try:
            resp = self._client.get(url, headers=headers)
            self.api_calls += 1
            self.rate_remaining = max(0, self.rate_remaining - 1)

            if resp.status_code == 200:
                text = self._extract_diff(resp)
                self._diff_cache[key] = text
                return text
            return None
        except Exception as exc:
            log.warning("Diff fetch failed: %s", exc)
            return None

    def _extract_diff(self, resp: httpx.Response) -> str:
        ct = resp.headers.get("content-type", "")
        ft = self.forge_type
        # GitLab returns JSON list
        if ft == "gitlab" and ct.startswith("application/json"):
            raw = resp.json()
            lines: list[str] = []
            for d in raw:
                lines.append(f"diff --git a/{d['old_path']} b/{d['new_path']}")
                lines.append(f"--- a/{d['old_path']}")
                lines.append(f"+++ b/{d['new_path']}")
                if d.get("diff"):
                    lines.append(d["diff"])
            return "\n".join(lines)
        # BitBucket returns JSON with diffs
        if ft == "bitbucket" and ct.startswith("application/json"):
            raw = resp.json()
            lines = []
            for d in raw.get("values", []) if isinstance(raw, dict) else raw:
                lines.append(f"diff --git a/{d.get('old',{}).get('path','')} "
                             f"b/{d.get('new',{}).get('path','')}")
                if d.get("diff"):
                    lines.append(d["diff"])
            return "\n".join(lines)
        # Azure DevOps paginated
        if ft == "azure_devops":
            try:
                data = resp.json()
                lines = []
                for ch in data.get("changes", []):
                    item = ch.get("item", {})
                    lines.append(f"diff --git a/{item.get('path','')} b/{item.get('path','')}")
                    if ch.get("diff"):
                        lines.append(ch["diff"])
                return "\n".join(lines) or resp.text
            except Exception:
                pass
        return resp.text

    def _fetch_codecommit_diff(self, owner: str, repo: str, sha: str) -> str | None:
        url = self._codecommit_clone_url(owner, repo)
        try:
            p = clone_repo(url, sha)
            result = subprocess.run(
                ["git", "-C", str(p), "show", "--format=full", sha],
                capture_output=True, text=True, timeout=30,
            )
            return result.stdout or None
        except Exception as exc:
            log.warning("CodeCommit diff fetch failed: %s", exc)
            return None

    def close(self) -> None:
        self._client.close()


# ── GH Archive helpers ────────────────────────────────────────────

def archive_hour_url(dt: datetime | None = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return f"{config.GH_ARCHIVE_BASE}/{dt.strftime('%Y-%m-%d-%H')}.json.gz"


def fetch_archive(url: str) -> list[dict[str, Any]]:
    log.info("Fetching %s", url)
    resp = httpx.get(url, headers={"User-Agent": config.USER_AGENT}, timeout=120, follow_redirects=True)
    resp.raise_for_status()
    buf = gzip.GzipFile(fileobj=io.BytesIO(resp.content))
    events: list[dict[str, Any]] = []
    for line in buf:
        line = line.decode("utf-8", errors="replace").strip()
        if line:
            events.append(json.loads(line))
    return events


def extract_pushevents(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pushevents: list[dict[str, Any]] = []
    for ev in events:
        if ev.get("type") != "PushEvent":
            continue
        payload = ev.get("payload") or {}
        repo = ev.get("repo") or {}
        pushevents.append({
            "_event_type": "push",
            "repo": repo.get("name", ""),
            "head": payload.get("head", ""),
            "ref": payload.get("ref", ""),
            "ts": ev.get("created_at", ""),
        })
    return pushevents


def extract_pullrequest_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    prevents: list[dict[str, Any]] = []
    for ev in events:
        if ev.get("type") != "PullRequestEvent":
            continue
        payload = ev.get("payload") or {}
        action = payload.get("action", "")
        if action not in ("opened", "reopened"):
            continue
        pr = payload.get("pull_request") or {}
        repo = ev.get("repo") or {}
        prevents.append({
            "_event_type": "pr",
            "repo": repo.get("name", ""),
            "title": pr.get("title", ""),
            "pr_number": pr.get("number", 0),
            "pr_url": pr.get("html_url", ""),
            "action": action,
            "ts": ev.get("created_at", ""),
        })
    return prevents


def resolve_commit_messages(
    pushevents: list[dict[str, Any]],
    git_client: GitAPIClient | None = None,
) -> list[dict[str, Any]]:
    if git_client is None:
        git_client = GitAPIClient()
    commits: list[dict[str, Any]] = []
    for pe in pushevents:
        event_type = pe.get("_event_type", "push")
        repo_name = pe["repo"]

        if event_type == "pr":
            title = pe.get("title", "")
            if not title or not repo_name:
                continue
            commits.append({
                "sha": f"pr-{pe.get('pr_number', 0)}",
                "message": title,
                "repo": repo_name,
                "_is_pr": True,
                "pr_url": pe.get("pr_url", ""),
                "action": pe.get("action", ""),
                "ts": pe.get("ts", ""),
            })
            continue

        # push event
        sha = pe.get("head", "")
        if not sha or not repo_name:
            continue
        parts = repo_name.split("/")
        if len(parts) != 2:
            continue
        owner, repo = parts
        message = git_client.fetch_commit_message(owner, repo, sha)
        if message:
            commits.append({
                "sha": sha,
                "message": message,
                "repo": repo_name,
                "_is_pr": False,
                "ref": pe.get("ref", ""),
                "ts": pe.get("ts", ""),
            })
    return commits


# ── Standalone diff fetchers (used by `url` subcommand) ───────────

def fetch_diff_from_github(owner: str, repo: str, sha: str, token: str | None = None) -> str | None:
    url = f"{config.GH_API_BASE}/repos/{owner}/{repo}/commits/{sha}"
    headers = {"Accept": "application/vnd.github.v3.diff", "User-Agent": config.USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = httpx.get(url, headers=headers, timeout=30)
        return resp.text if resp.status_code == 200 else None
    except Exception as exc:
        log.warning("GitHub diff fetch failed: %s", exc)
        return None


def fetch_diff_from_gitlab(project_id: str, sha: str, token: str | None = None) -> str | None:
    url = f"{config.GITLAB_API_BASE}/projects/{project_id}/repository/commits/{sha}/diff"
    headers = {"User-Agent": config.USER_AGENT}
    if token:
        headers["PRIVATE-TOKEN"] = token
    try:
        resp = httpx.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            return None
        raw = resp.json()
        lines: list[str] = []
        for d in raw:
            lines.append(f"diff --git a/{d['old_path']} b/{d['new_path']}")
            lines.append(f"--- a/{d['old_path']}")
            lines.append(f"+++ b/{d['new_path']}")
            if d.get("diff"):
                lines.append(d["diff"])
        return "\n".join(lines)
    except Exception as exc:
        log.warning("GitLab diff fetch failed: %s", exc)
        return None


def fetch_diff_from_gitea(owner: str, repo: str, sha: str, base_url: str, token: str | None = None) -> str | None:
    url = f"{base_url}/repos/{owner}/{repo}/git/commits/{sha}.diff"
    headers = {"User-Agent": config.USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = httpx.get(url, headers=headers, timeout=30)
        return resp.text if resp.status_code == 200 else None
    except Exception as exc:
        log.warning("Gitea diff fetch failed: %s", exc)
        return None


def fetch_diff_from_bitbucket(owner: str, repo: str, sha: str, token: str | None = None) -> str | None:
    url = f"{config.BITBUCKET_API_BASE}/repositories/{owner}/{repo}/diff/{sha}"
    headers = {"Accept": "application/x.diff", "User-Agent": config.USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = httpx.get(url, headers=headers, timeout=30)
        return resp.text if resp.status_code == 200 else None
    except Exception as exc:
        log.warning("BitBucket diff fetch failed: %s", exc)
        return None


def fetch_diff_from_azure_devops(org: str, project: str, repo: str, sha: str, token: str | None = None) -> str | None:
    url = (f"{config.AZURE_DEVOPS_API_BASE}/{org}/{project}/_apis/git/repositories/"
           f"{repo}/commits/{sha}/changes?api-version=7.0")
    headers = {"User-Agent": config.USER_AGENT}
    if token:
        b64 = base64.b64encode(f":{token}".encode()).decode()
        headers["Authorization"] = f"Basic {b64}"
    try:
        resp = httpx.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            return None
        data = resp.json()
        lines: list[str] = []
        for ch in data.get("changes", []):
            item = ch.get("item", {})
            lines.append(f"diff --git a/{item.get('path','')} b/{item.get('path','')}")
            if ch.get("diff"):
                lines.append(ch["diff"])
        return "\n".join(lines) or resp.text
    except Exception as exc:
        log.warning("Azure DevOps diff fetch failed: %s", exc)
        return None


def clone_repo(repo_url: str, ref: str = "HEAD") -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="ghleak_"))
    log.info("Cloning %s @ %s into %s", repo_url, ref, tmp)
    subprocess.run(
        ["git", "clone", "--depth", "1", "--single-branch", repo_url, str(tmp)],
        capture_output=True, timeout=120,
    )
    if ref != "HEAD":
        subprocess.run(["git", "-C", str(tmp), "checkout", ref], capture_output=True, timeout=30)
    return tmp


def git_url_parts(url: str) -> dict[str, str]:
    url = url.strip()
    parts: dict[str, str] = {"protocol": "", "host": "", "owner": "", "repo": "", "full": ""}

    if url.startswith("git@") or url.startswith("ssh://"):
        if "://" in url:
            rest = url.split("://", 1)[1]
            parts["protocol"] = "ssh"
            at_split = rest.split("@", 1)
            after_at = at_split[1] if len(at_split) > 1 else rest
            parts["host"] = after_at.split("/")[0]
            path = "/".join(after_at.split("/")[1:])
        else:
            parts["protocol"] = "ssh"
            after_at = url.split("@", 1)[1] if "@" in url else url
            parts["host"] = after_at.split(":")[0]
            path = after_at.split(":", 1)[1] if ":" in after_at else ""
    elif url.startswith("https://") or url.startswith("http://"):
        parts["protocol"] = "https"
        rest = url.split("://", 1)[1]
        parts["host"] = rest.split("/")[0]
        path = "/".join(rest.split("/")[1:])
    else:
        return parts

    path = path.removesuffix(".git")
    path_parts = path.split("/")
    if len(path_parts) >= 2:
        parts["owner"] = path_parts[0]
        parts["repo"] = "/".join(path_parts[1:])
    parts["full"] = f"{parts['host']}/{path}"
    return parts


def fetch_diff_from_url(repo_url: str, sha: str, token: str | None = None) -> str | None:
    """Auto-detect forge from URL and fetch the diff."""
    import urllib.parse

    parts = git_url_parts(repo_url)
    if not parts["host"] or not parts["owner"] or not parts["repo"]:
        log.warning("Cannot parse repo URL: %s", repo_url)
        return None

    host = parts["host"].lower()
    owner, repo_name = parts["owner"], parts["repo"]

    if "github" in host:
        return fetch_diff_from_github(owner, repo_name, sha, token)
    if "gitlab" in host:
        # GitLab API requires URL-encoded namespace
        encoded_id = urllib.parse.quote(f"{owner}/{repo_name}", safe="")
        return fetch_diff_from_gitlab(encoded_id, sha, token)
    if "gitea" in host or "gogs" in host:
        base = f"https://{host}/api/v1"
        return fetch_diff_from_gitea(owner, repo_name, sha, base, token)
    if "bitbucket" in host:
        return fetch_diff_from_bitbucket(owner, repo_name, sha, token)
    if "dev.azure" in host or "azure" in host:
        # Azure URL: https://dev.azure.com/{org}/{project}/_git/{repo}
        repo_str = parts["repo"]
        if "/_git/" in repo_str:
            project, real_repo = repo_str.split("/_git/", 1)
        else:
            project = real_repo = repo_str
        return fetch_diff_from_azure_devops(owner, project, real_repo, sha, token)

    log.info("Unknown forge %s, falling back to clone", host)
    try:
        p = clone_repo(repo_url, sha)
        result = subprocess.run(
            ["git", "-C", str(p), "show", "--format=full", sha],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout
    except Exception as exc:
        log.warning("Clone + show failed: %s", exc)
        return None


def resolve_repo_url(repo_name: str, forge: str = "github") -> str:
    m: dict[str, str] = {
        "github": f"https://github.com/{repo_name}.git",
        "gitlab": f"https://gitlab.com/{repo_name}.git",
        "gitea": f"https://gitea.com/{repo_name}.git",
        "gogs": f"https://try.gogs.io/{repo_name}.git",
        "bitbucket": f"https://bitbucket.org/{repo_name}.git",
    }
    return m.get(forge, f"https://{forge}/{repo_name}.git")


def find_latest_archive_hour() -> datetime | None:
    now = datetime.now(timezone.utc)
    for offset in range(1, 25):
        candidate = now - timedelta(hours=offset)
        url = archive_hour_url(candidate)
        try:
            resp = httpx.head(url, headers={"User-Agent": config.USER_AGENT}, timeout=15)
            if resp.status_code == 200:
                return candidate
        except Exception:
            continue
    return None


def stream_hours(
    hours_back: int = 1,
    include_current: bool = True,
    end_hour: datetime | None = None,
    start_hour: datetime | None = None,
    enterprise_filter: Any = None,
) -> Iterator[list[dict[str, Any]]]:
    now = datetime.now(timezone.utc)

    if end_hour is None:
        probe = now.replace(minute=0, second=0, microsecond=0)
        try:
            resp = httpx.head(archive_hour_url(probe), headers={"User-Agent": config.USER_AGENT}, timeout=15)
            end_hour = probe if resp.status_code == 200 else (find_latest_archive_hour() or now) + timedelta(hours=1)
        except Exception:
            end_hour = now - timedelta(hours=1)

    if start_hour is None:
        start_hour = end_hour - timedelta(hours=hours_back)

    cursor = start_hour.replace(minute=0, second=0, microsecond=0)
    end = end_hour.replace(minute=0, second=0, microsecond=0)
    while cursor < end:
        url = archive_hour_url(cursor)
        try:
            events = fetch_archive(url)

            # Optional enterprise pre-filter — drops non-target events early
            if enterprise_filter is not None:
                filtered: list[dict[str, Any]] = []
                for ev in events:
                    passes, _, _ = enterprise_filter.analyze_event(ev)
                    if passes:
                        filtered.append(ev)
                events = filtered

            pushes = extract_pushevents(events)
            prevents = extract_pullrequest_events(events)
            combined = pushes + prevents
            log.info("Hour %s: %d events, %d PushEvents, %d PREvents",
                     cursor.strftime("%Y-%m-%dT%H"), len(events), len(pushes), len(prevents))
            yield combined
        except Exception as exc:
            log.error("Failed to process hour %s: %s", cursor, exc)
        cursor += timedelta(hours=1)
