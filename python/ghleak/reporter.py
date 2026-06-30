"""Results reporting — JSON, CSV, terminal table, markdown."""

from __future__ import annotations

import csv
import json
import logging
import textwrap
from collections import Counter
from datetime import datetime, timezone
from typing import Any, TextIO

from .scanner import TruffleHogResult

log = logging.getLogger(__name__)


class Report:
    """Aggregate report for a pipeline run."""

    def __init__(self) -> None:
        self.start_time = datetime.now(timezone.utc)
        self.end_time: datetime | None = None
        self.hours_scanned: int = 0
        self.commits_seen: int = 0
        self.suspicious_commits: list[dict[str, Any]] = []
        self.verified_findings: list[TruffleHogResult] = []
        self.classifier_stats: dict[str, int] = {}
        self.errors: list[str] = []

    def add_suspicious(self, repo: str, sha: str, message: str, classification: str) -> None:
        self.suspicious_commits.append({
            "repo": repo,
            "sha": sha,
            "message": message,
            "classification": classification,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def add_finding(self, finding: TruffleHogResult) -> None:
        self.verified_findings.append(finding)

    def finish(self) -> None:
        self.end_time = datetime.now(timezone.utc)

    @property
    def duration(self) -> str:
        if not self.end_time:
            return "running"
        delta = self.end_time - self.start_time
        return f"{delta.total_seconds():.1f}s"

    @property
    def verified_count(self) -> int:
        return sum(1 for f in self.verified_findings if f.verified)

    def summary_text(self, width: int = 72) -> str:
        lines = [
            "═" * width,
            "  GhLeak — Secret Scan Report",
            "═" * width,
            f"  Scanned hours : {self.hours_scanned}",
            f"  Commits seen  : {self.commits_seen:,}",
            f"  Suspicious    : {len(self.suspicious_commits)}",
            f"  Verified      : {self.verified_count}",
            f"  Total findings: {len(self.verified_findings)}",
            f"  Duration      : {self.duration}",
        ]

        if self.classifier_stats:
            lines.append("")
            lines.append("  Classifier stats:")
            for k, v in self.classifier_stats.items():
                lines.append(f"    {k}: {v}")

        if self.verified_findings:
            lines.append("")
            lines.append(f"  Top detectors (verified):")
            detector_counts = Counter(
                f.detector for f in self.verified_findings if f.verified
            )
            for detector, count in detector_counts.most_common(10):
                lines.append(f"    {detector}: {count}")

            lines.append("")
            lines.append("  Sample verified findings:")
            for f in self.verified_findings[:5]:
                if f.verified:
                    lines.append(
                        f"    [{f.detector}] {f.repository} @ {f.commit[:12]}"
                        f"  ({f.file})"
                    )

        if self.errors:
            lines.append("")
            lines.append(f"  Errors ({len(self.errors)}):")
            for err in self.errors[:5]:
                lines.append(f"    ! {err}")

        lines.append("═" * width)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "hours_scanned": self.hours_scanned,
            "commits_seen": self.commits_seen,
            "suspicious_count": len(self.suspicious_commits),
            "verified_count": self.verified_count,
            "total_findings": len(self.verified_findings),
            "classifier_stats": self.classifier_stats,
            "suspicious_commits": self.suspicious_commits,
            "verified_findings": [
                {
                    "detector": f.detector,
                    "verified": f.verified,
                    "commit": f.commit,
                    "file": f.file,
                    "repository": f.repository,
                    "email": f.email,
                    "redacted": f.redacted,
                    "raw": f.raw_v2[:120] + "..." if len(f.raw_v2) > 120 else f.raw_v2,
                }
                for f in self.verified_findings
            ],
            "errors": self.errors,
        }

    def to_json(self, file: TextIO | None = None) -> str:
        data = self.to_dict()
        out = json.dumps(data, indent=2, default=str)
        if file:
            file.write(out)
        return out

    def to_csv(self, file: TextIO) -> None:
        writer = csv.writer(file)
        writer.writerow(["detector", "verified", "commit", "file", "repository", "email"])
        for f in self.verified_findings:
            writer.writerow([f.detector, f.verified, f.commit, f.file, f.repository, f.email])

    def to_markdown(self) -> str:
        """Render as GitHub-flavored markdown (like the blog post style)."""
        lines = [
            "# GhLeak Scan Report",
            "",
            f"**Scan period:** {self.start_time.isoformat()} — {self.end_time.isoformat() if self.end_time else 'running'}",
            f"**Duration:** {self.duration}",
            f"**Hours scanned:** {self.hours_scanned}",
            f"**Commits seen:** {self.commits_seen:,}",
            f"**Suspicious commits flagged:** {len(self.suspicious_commits)}",
            f"**Verified secrets found:** {self.verified_count}",
            f"**Total findings:** {len(self.verified_findings)}",
            "",
        ]

        if self.verified_findings:
            lines.append("## Verified Findings by Detector")
            lines.append("")
            lines.append("| Detector | Count |")
            lines.append("|----------|-------|")
            detector_counts = Counter(
                f.detector for f in self.verified_findings if f.verified
            )
            for detector, count in detector_counts.most_common():
                lines.append(f"| {detector} | {count} |")

            lines.append("")
            lines.append("## Sample Verified Secrets")
            lines.append("")
            lines.append("| Detector | Repository | Commit | File |")
            lines.append("|----------|------------|--------|------|")
            for f in self.verified_findings[:20]:
                if f.verified:
                    lines.append(
                        f"| {f.detector} | {f.repository or '—'} | "
                        f"`{f.commit[:12]}` | {f.file or '—'} |"
                    )

        if self.suspicious_commits:
            lines.append("")
            lines.append("## Suspicious Commits (by message classification)")
            lines.append("")
            lines.append("| Repository | Commit | Message |")
            lines.append("|------------|--------|---------|")
            for c in self.suspicious_commits[:30]:
                msg = textwrap.shorten(c["message"], width=60, placeholder="...")
                lines.append(
                    f"| {c['repo']} | `{c['sha'][:12]}` | {msg} |"
                )

        return "\n".join(lines)
