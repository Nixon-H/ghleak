"""TruffleHog wrapper — runs scans with verification enabled."""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from . import config

log = logging.getLogger(__name__)


class TruffleHogResult:
    """Wraps a single verified finding from TruffleHog."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self.raw = raw
        self.source_metadata: dict[str, Any] = raw.get("SourceMetadata", {})
        data = raw.get("Data", {})
        self.detector = raw.get("DetectorName", "")
        self.detector_type = raw.get("DetectorType", 0)
        self.decoder = raw.get("DecoderName", "")
        self.verified = raw.get("Verified", False)
        self.redacted = raw.get("Redacted", False)
        self.raw_v2 = data.get("RawV2", "")

        meta = self.source_metadata.get("Data", {}).get("Git", {})
        self.commit = meta.get("commit", "")
        self.file = meta.get("file", "")
        self.email = meta.get("email", "")
        self.timestamp = meta.get("timestamp", "")
        self.repository = meta.get("repository", "")
        self.committer = meta.get("committer", "")

    def __repr__(self) -> str:
        v = "VERIFIED" if self.verified else "unverified"
        return f"[{v}] {self.detector} in {self.file} @ {self.commit[:12]}"


class TruffleHogScanner:
    """Runs TruffleHog on git repos, diffs, or raw text."""

    def __init__(
        self,
        binary: str = "trufflehog",
        only_verified: bool = True,
        fail_on_error: bool = False,
        extra_args: list[str] | None = None,
    ):
        self.binary = binary
        self.only_verified = only_verified
        self.fail_on_error = fail_on_error
        self.extra_args = extra_args or []

    def scan_git_path(self, path: Path) -> list[TruffleHogResult]:
        """Scan a local git repository with TruffleHog."""
        cmd = [
            self.binary, "git", "file://.",
            "--since-commit", "HEAD",
            "--json",
        ]
        if self.only_verified:
            cmd.append("--only-verified")
        cmd.extend(self.extra_args)

        results = self._run(cmd, cwd=path)
        log.info("Scanned %s: %d findings, %d verified",
                 path, len(results), sum(1 for r in results if r.verified))
        return results

    def scan_diff(self, diff_text: str) -> list[TruffleHogResult]:
        """Scan a plain-text diff with TruffleHog."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".diff", delete=False, prefix="ghleak_"
        ) as f:
            f.write(diff_text)
            diff_path = f.name

        cmd = [
            self.binary, "filesystem", diff_path,
            "--json",
        ]
        if self.only_verified:
            cmd.append("--only-verified")
        cmd.extend(self.extra_args)

        results = self._run(cmd)
        Path(diff_path).unlink(missing_ok=True)
        return results

    def scan_commit_from_gh(
        self, owner: str, repo: str, sha: str, github_token: str | None = None
    ) -> list[TruffleHogResult]:
        """Scan a GitHub commit directly (clones + scans)."""
        clone_url = f"https://github.com/{owner}/{repo}.git"
        if github_token:
            clone_url = f"https://x-access-token:{github_token}@github.com/{owner}/{repo}.git"

        tmp = Path(tempfile.mkdtemp(prefix="ghleak_"))
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", clone_url, str(tmp)],
                capture_output=True, timeout=120, check=True,
            )
            subprocess.run(
                ["git", "-C", str(tmp), "fetch", "--depth", "1", "origin", sha],
                capture_output=True, timeout=30, check=True,
            )
            subprocess.run(
                ["git", "-C", str(tmp), "checkout", sha],
                capture_output=True, timeout=30, check=True,
            )
            return self.scan_git_path(tmp)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def _run(self, cmd: list[str], cwd: str | Path | None = None) -> list[TruffleHogResult]:
        """Execute trufflehog and parse JSON output."""
        log.debug("Running: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(cwd) if cwd else None,
            )
        except subprocess.TimeoutExpired:
            log.warning("TruffleHog timed out: %s", " ".join(cmd[:4]))
            return []
        except FileNotFoundError:
            log.error("TruffleHog binary not found at %s", self.binary)
            raise

        results: list[TruffleHogResult] = []
        for line in proc.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                results.append(TruffleHogResult(raw))
            except json.JSONDecodeError:
                continue

        if self.fail_on_error and proc.returncode not in (0, 1):
            log.error("TruffleHog failed (exit %d): %s", proc.returncode, proc.stderr[:500])

        return results


def summarize_findings(results: list[TruffleHogResult]) -> dict[str, Any]:
    """Aggregate scan results into a summary dict."""
    detector_counts: dict[str, int] = {}
    verified_count = 0
    file_paths: set[str] = set()
    emails: set[str] = set()
    repos: set[str] = set()

    for r in results:
        detector_counts[r.detector] = detector_counts.get(r.detector, 0) + 1
        if r.verified:
            verified_count += 1
        if r.file:
            file_paths.add(r.file)
        if r.email:
            emails.add(r.email)
        if r.repository:
            repos.add(r.repository)

    return {
        "total_findings": len(results),
        "verified_count": verified_count,
        "detectors": dict(sorted(detector_counts.items(), key=lambda x: -x[1])),
        "unique_files": len(file_paths),
        "unique_emails": len(emails),
        "unique_repos": list(repos),
    }
