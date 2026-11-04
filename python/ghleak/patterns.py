"""Built-in secret-value pattern scanning — works with or without TruffleHog.

TruffleHog is the gold standard (it *verifies* secrets against the provider),
but it must be installed separately. This module provides a high-confidence,
zero-dependency first pass that detects well-known credential formats by
prefix, length, and charset. Findings from here are marked `verified=False`
and act as candidates — TruffleHog (when available) upgrades them to verified.

Every pattern is tuned for low false positives:
  - exact known prefixes (ghp_, AKIA, xoxb-, …)
  - strict charset + length bounds
  - negative lookbehinds so config examples like `ghp_YOUR_TOKEN_HERE`
    or `xxx` placeholders do not match.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# A shared guard: word boundary on the left, and a rejection of ALL-CAPS
# placeholder middles ("YOUR_TOKEN", "EXAMPLE", "XXXX…") and of pure
# placeholder words after the prefix.
_PLACEHOLDER = r"(?!YOUR|EXAMPLE|XXXX|PLACEHOLDER|REDACTED|TOKEN|SECRET|KEY|SAMPLE|TEST)"

# Word-ish boundary that also works when the token is quoted or at EOL.
_L = r"(?<![A-Za-z0-9_-])"


@dataclass
class PatternFinding:
    """A candidate secret found by built-in pattern matching."""

    detector: str          # e.g. "github_pat", "aws_access_key_id"
    value: str             # the matched candidate (full match)
    redacted: str          # safe-for-display version (first 10 chars + …)
    line_number: int       # 1-based line inside the scanned text
    line_snippet: str = "" # the line, with the value redacted
    verified: bool = False # builtin patterns never verify — trufflehog does
    extra: dict = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"[candidate] {self.detector} @ line {self.line_number} ({self.redacted})"


def _redact(value: str) -> str:
    if len(value) <= 10:
        return value[:4] + "…"
    return value[:10] + "…"


def _snip(line: str, value: str) -> str:
    idx = line.find(value)
    if idx == -1:
        return line[:120]
    return (line[:idx] + _redact(value) + line[idx + len(value):])[:160]


def _pat(name: str, body: str, flags: int = 0) -> tuple[str, re.Pattern[str], str]:
    return name, re.compile(_L + body, flags), name


# ── The catalog ───────────────────────────────────────────────────
# name → (regex, description).  Order matters only for reporting.

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    _pat(
        "github_classic_pat",
        r"ghp_" + _PLACEHOLDER + r"[A-Za-z0-9]{36,38}(?![A-Za-z0-9])",
    ),
    _pat(
        "github_oauth_token",
        r"gho_" + _PLACEHOLDER + r"[A-Za-z0-9]{36,38}(?![A-Za-z0-9])",
    ),
    _pat(
        "github_user_token",
        r"ghu_" + _PLACEHOLDER + r"[A-Za-z0-9]{36,38}(?![A-Za-z0-9])",
    ),
    _pat(
        "github_server_token",
        r"ghs_" + _PLACEHOLDER + r"[A-Za-z0-9]{36,38}(?![A-Za-z0-9])",
    ),
    _pat(
        "github_refresh_token",
        r"ghr_" + _PLACEHOLDER + r"[A-Za-z0-9]{36,38}(?![A-Za-z0-9])",
    ),
    _pat(
        "github_fine_grained_pat",
        r"github_pat_" + _PLACEHOLDER + r"[A-Za-z0-9_]{80,84}(?![A-Za-z0-9_])",
    ),
    _pat(
        "gitlab_pat",
        r"glpat-" + _PLACEHOLDER + r"[A-Za-z0-9_-]{20,27}(?![A-Za-z0-9_-])",
    ),
    _pat(
        "aws_access_key_id",
        r"(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![0-9A-Z])",
    ),
    _pat(
        "google_api_key",
        r"AIza" + _PLACEHOLDER + r"[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])",
    ),
    _pat(
        "anthropic_api_key",
        r"sk-ant-" + _PLACEHOLDER + r"[A-Za-z0-9_-]{24,120}(?![A-Za-z0-9_-])",
    ),
    _pat(
        "openai_api_key",
        r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])",
    ),
    _pat(
        "openai_generic",
        r"sk-" + _PLACEHOLDER + r"[A-Za-z0-9_-]{40,60}(?![A-Za-z0-9_-])",
    ),
    _pat(
        "slack_token",
        r"xox[abprs]-" + _PLACEHOLDER + r"[A-Za-z0-9-]{10,250}(?![A-Za-z0-9-])",
    ),
    _pat(
        "telegram_bot_token",
        r"\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])",
    ),
    _pat(
        "stripe_secret_key",
        r"[sr]k_live_" + _PLACEHOLDER + r"[A-Za-z0-9]{24,99}(?![A-Za-z0-9])",
    ),
    _pat(
        "shopify_token",
        r"sh(p|a|pss)at_" + _PLACEHOLDER + r"[a-f0-9]{32}(?![a-f0-9])",
    ),
    _pat(
        "sendgrid_api_key",
        r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])",
    ),
    _pat(
        "twilio_api_key",
        r"SK[0-9a-fA-F]{32}(?![0-9a-fA-F])",
    ),
    _pat(
        "npm_token",
        r"npm_" + _PLACEHOLDER + r"[A-Za-z0-9]{36}(?![A-Za-z0-9])",
    ),
    _pat(
        "pypi_token",
        r"pypi-" + _PLACEHOLDER + r"[A-Za-z0-9_-]{50,}(?![A-Za-z0-9_-])",
    ),
    _pat(
        "heroku_api_key",
        r"heroku_" + _PLACEHOLDER + r"[0-9a-f]{32}(?![0-9a-f])",
    ),
    _pat(
        "square_access_token",
        r"EAAA[A-Za-z0-9_-]{30,60}(?![A-Za-z0-9_-])",
    ),
    _pat(
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    ),
    _pat(
        "firebase_cloud_messaging",
        r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{130,140}(?![A-Za-z0-9_-])",
    ),
    _pat(
        "aws_secret_access_key",
        r"[A-Za-z0-9/+]{40}(?![A-Za-z0-9])(?=[^\n]*(?:aws|secret|_key))",
        re.IGNORECASE,
    ),
]


def scan_text(text: str) -> list[PatternFinding]:
    """Scan arbitrary text (a diff, a file, a message) for credential values."""
    findings: list[PatternFinding] = []
    if not text:
        return findings
    lines = text.splitlines()
    seen: set[tuple[str, int]] = set()
    for lineno, line in enumerate(lines, start=1):
        # Skip pure diff headers and commit-message metadata lines.
        stripped = line.lstrip()
        if stripped.startswith(("+++", "---", "diff --git", "index ", "@@")):
            continue
        for name, pat, _desc in _SECRET_PATTERNS:
            for m in pat.finditer(line):
                key = (m.group(0), lineno)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(PatternFinding(
                    detector=name,
                    value=m.group(0),
                    redacted=_redact(m.group(0)),
                    line_number=lineno,
                    line_snippet=_snip(line, m.group(0)),
                ))
    return findings


def pattern_names() -> list[str]:
    return [name for name, _p, _d in _SECRET_PATTERNS]
