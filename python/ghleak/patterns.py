"""Built-in secret-value pattern scanning — works with or without TruffleHog.

TruffleHog is the gold standard (it *verifies* secrets against the provider),
but it must be installed separately. This module provides a high-confidence,
zero-dependency first pass that detects well-known credential formats by
prefix, length, and charset. Findings from here are marked `verified=False`
and act as candidates — TruffleHog (when available) upgrades them to verified.

The catalog merges the pattern sets from:
  - SecretFinder (m4ll0k) — https://github.com/m4ll0k/SecretFinder
  - APK Secret Finder (viralvaghela) — https://github.com/viralvaghela
  - gitleaks/trufflehog-style modern token prefixes

Every pattern is tuned for low false positives:
  - known prefixes or context keywords (aws/facebook/heroku/jenkins/…)
  - strict charset + length bounds
  - placeholder guards reject `ghp_YOUR_TOKEN_HERE`, `password = "your_password"`
  - values are redacted before they reach logs or reports
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Left boundary that also works when the token is quoted or at EOL.
_L = r"(?<![A-Za-z0-9_-])"

_PLACEHOLDERS = (
    "YOUR", "EXAMPLE", "XXXX", "PLACEHOLDER", "REDACTED",
    "TOKEN", "SECRET", "KEY", "SAMPLE", "TESTSECRET",
)
_PLACEHOLDER = r"(?!" + "|".join(_PLACEHOLDERS) + r")"


@dataclass(frozen=True)
class SecretPattern:
    """One detector in the catalog."""

    name: str
    regex: re.Pattern[str]
    severity: str                      # Critical | High | Medium | Low
    prefix_len: int = 0                # chars of fixed prefix (placeholder check)
    context: tuple[str, ...] = ()      # require one of these on the line
    capture_group: bool = False        # group(1) is the secret value


@dataclass
class PatternFinding:
    """A candidate secret found by built-in pattern matching."""

    detector: str
    value: str
    redacted: str
    line_number: int
    severity: str = "High"
    line_snippet: str = ""
    verified: bool = False
    extra: dict = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"[{self.severity}] {self.detector} @ line {self.line_number} ({self.redacted})"


def _redact(value: str) -> str:
    if len(value) <= 10:
        return value[:4] + "…"
    return value[:10] + "…"


def _snip(line: str, value: str) -> str:
    idx = line.find(value)
    if idx == -1:
        return line[:160]
    return (line[:idx] + _redact(value) + line[idx + len(value):])[:160]


def _pat(name: str, body: str, severity: str, *, prefix_len: int = 0,
         context: tuple[str, ...] = (), capture: bool = False,
         flags: int = 0) -> SecretPattern:
    return SecretPattern(
        name=name,
        regex=re.compile((_L if not capture else "") + body, flags),
        severity=severity,
        prefix_len=prefix_len,
        context=context,
        capture_group=capture,
    )


# ── The catalog ───────────────────────────────────────────────────
# Ordered roughly by severity then family.

SECRET_PATTERNS: list[SecretPattern] = [
    # ── Critical: private keys, cloud roots of trust, GitHub tokens ──
    _pat("private_key_block",
         r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
         "Critical"),
    _pat("github_classic_pat", r"ghp_" + _PLACEHOLDER + r"[A-Za-z0-9]{36,38}(?![A-Za-z0-9])",
         "Critical", prefix_len=4),
    _pat("github_oauth_token", r"gho_" + _PLACEHOLDER + r"[A-Za-z0-9]{36,38}(?![A-Za-z0-9])",
         "Critical", prefix_len=4),
    _pat("github_user_token", r"ghu_" + _PLACEHOLDER + r"[A-Za-z0-9]{36,38}(?![A-Za-z0-9])",
         "Critical", prefix_len=4),
    _pat("github_server_token", r"ghs_" + _PLACEHOLDER + r"[A-Za-z0-9]{36,38}(?![A-Za-z0-9])",
         "Critical", prefix_len=4),
    _pat("github_refresh_token", r"ghr_" + _PLACEHOLDER + r"[A-Za-z0-9]{36,38}(?![A-Za-z0-9])",
         "Critical", prefix_len=4),
    _pat("github_fine_grained_pat", r"github_pat_" + _PLACEHOLDER + r"[A-Za-z0-9_]{80,84}(?![A-Za-z0-9_])",
         "Critical", prefix_len=11),
    _pat("aws_secret_access_key",
         r"(?i)(?:aws|secret|access)[^\n]{0,40}?['\"]([A-Za-z0-9/+=]{40})['\"]",
         "Critical", capture=True),
    _pat("google_service_account_json", r'"type"\s*:\s*"service_account"', "Critical"),
    _pat("firebase_cloud_messaging", r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{130,140}(?![A-Za-z0-9_-])",
         "Critical", prefix_len=7),
    _pat("openai_api_key", r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])",
         "Critical", prefix_len=3),
    _pat("anthropic_api_key", r"sk-ant-" + _PLACEHOLDER + r"[A-Za-z0-9_-]{24,120}(?![A-Za-z0-9_-])",
         "Critical", prefix_len=7),
    _pat("password_in_url",
         r"\b[a-zA-Z][a-zA-Z0-9+.-]{2,9}://[^\s:@/]{1,30}:([^\s@/]{3,60})@[^\s\"'<>]{3,}",
         "Critical", capture=True),
    _pat("github_creds_in_url", r"https?://[^:@/\s]+:([^@/\s]{3,60})@github\.com",
         "Critical", capture=True),

    # ── High: provider tokens with precise shapes ─────────────────
    _pat("gitlab_pat", r"glpat-[A-Za-z0-9_-]{20,27}(?![A-Za-z0-9_-])", "High", prefix_len=6),
    _pat("google_api_key", r"AIza" + _PLACEHOLDER + r"[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])",
         "High", prefix_len=4),
    _pat("google_oauth_refresh", r"ya29\.[0-9A-Za-z_-]{20,}", "High", prefix_len=5),
    _pat("openai_generic", r"sk-" + _PLACEHOLDER + r"[A-Za-z0-9_-]{40,60}(?![A-Za-z0-9_-])",
         "High", prefix_len=3),
    _pat("slack_token", r"xox[abprs]-" + _PLACEHOLDER + r"[A-Za-z0-9-]{10,250}(?![A-Za-z0-9-])",
         "High", prefix_len=5),
    _pat("slack_webhook",
         r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,12}/B[A-Za-z0-9_]{8,12}/[A-Za-z0-9_]{20,32}",
         "High"),
    _pat("discord_bot_token",
         r"[M-Z][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}(?![A-Za-z0-9_-])",
         "High"),
    _pat("telegram_bot_token", r"[0-9]{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])", "High"),
    _pat("stripe_secret_key", r"[sr]k_live_" + _PLACEHOLDER + r"[A-Za-z0-9]{24,99}(?![A-Za-z0-9])",
         "High", prefix_len=8),
    _pat("stripe_webhook_secret", r"whsec_[A-Za-z0-9]{24,}", "High", prefix_len=6),
    _pat("shopify_token", r"sh(?:p|a|pss)at_" + _PLACEHOLDER + r"[a-f0-9]{32}(?![a-f0-9])",
         "High", prefix_len=6),
    _pat("sendgrid_api_key", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])",
         "High", prefix_len=3),
    _pat("mailgun_api_key", r"key-[0-9a-zA-Z]{32}(?![0-9a-zA-Z])", "High", prefix_len=4),
    _pat("mailchimp_api_key", r"[0-9a-f]{32}-us[0-9]{1,2}(?![0-9])", "High"),
    _pat("twilio_api_key", r"SK[0-9a-fA-F]{32}(?![0-9a-fA-F])", "High", prefix_len=2),
    _pat("square_access_token", r"(?:sq0atp-[0-9A-Za-z_-]{22}|EAAA[0-9A-Za-z_-]{30,60})(?![A-Za-z0-9_-])",
         "High"),
    _pat("square_oauth_secret", r"sq0csp-[0-9A-Za-z_-]{43}(?![0-9A-Za-z_-])", "High", prefix_len=7),
    _pat("paypal_braintree_token", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
         "High"),
    _pat("facebook_access_token", r"EAACEdEose0cBA[0-9A-Za-z]+", "High", prefix_len=15),
    _pat("facebook_oauth_secret",
         r"(?i)facebook[^\n]{0,40}?['\"]([0-9a-f]{32})['\"]", "High", capture=True),
    _pat("twitter_access_token",
         r"(?i)twitter[^\n]{0,60}?([1-9][0-9]{6,}-[0-9a-zA-Z]{40})", "High", capture=True),
    _pat("twitter_oauth_secret",
         r"(?i)twitter[^\n]{0,40}?['\"]([0-9a-zA-Z]{35,44})['\"]", "High", capture=True),
    _pat("heroku_api_key",
         r"(?i)heroku[^\n]{0,40}?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
         "High", capture=True),
    _pat("azure_client_secret",
         r"(?i)(?:azure|client[_-]?secret)[^\n]{0,40}?['\"]([A-Za-z0-9~_.-]{30,})['\"]",
         "High", capture=True),
    _pat("aws_access_key_id", r"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![0-9A-Z])", "High"),
    _pat("aws_mws_auth_token",
         r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "High"),
    _pat("generic_api_key_assignment",
         r"(?i)\b(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\b\s*[:=]\s*['\"]?"
         r"([A-Za-z0-9_.-]{20,64})", "High", capture=True),
    _pat("generic_secret_assignment",
         r"(?i)\bsecret\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=-]{16,64})", "High", capture=True),
    _pat("generic_password_assignment",
         r"(?i)\b(?:password|passwd|pwd|pass)\b\s*[:=]\s*['\"]?([^\s'\"/\\,;<>]{8,64})",
         "High", capture=True),
    _pat("jwt", r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "High"),
    _pat("jenkins_api_token",
         r"(?i)jenkins[^\n]{0,40}?\b(11[0-9a-f]{32})\b", "High", capture=True),
    _pat("npm_token", r"npm_" + _PLACEHOLDER + r"[A-Za-z0-9]{36}(?![A-Za-z0-9])",
         "High", prefix_len=4),
    _pat("pypi_token", r"pypi-" + _PLACEHOLDER + r"[A-Za-z0-9_-]{50,}(?![A-Za-z0-9_-])",
         "High", prefix_len=5),
    _pat("grafana_service_token", r"glsa_[A-Za-z0-9]{32}(?![A-Za-z0-9])", "High", prefix_len=5),
    _pat("newrelic_api_key", r"NRAK-[A-Z0-9]{27}(?![A-Z0-9])", "High", prefix_len=5),
    _pat("doppler_token", r"dp\.pt\.[A-Za-z0-9]{43}(?![A-Za-z0-9])", "High", prefix_len=6),
    _pat("netlify_token", r"nfp_" + _PLACEHOLDER + r"[A-Za-z0-9]{40}(?![A-Za-z0-9])",
         "High", prefix_len=4),

    # ── High: URLs that embed credentials ─────────────────────────
    _pat("db_uri_with_credentials",
         r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|rediss|amqp|amqps)://"
         r"[^\s:@/]{1,40}:([^\s@/]{1,60})@[^\s\"'<>]+", "High", capture=True),
    _pat("cloudinary_url", r"cloudinary://[0-9]+:([A-Za-z0-9_-]{10,})@[A-Za-z0-9_-]+",
         "High", capture=True),

    # ── Medium: auth schemes and endpoints ────────────────────────
    _pat("authorization_bearer", r"(?i)\bbearer\s+([A-Za-z0-9_.=:_+/-]{12,200})",
         "Medium", capture=True),
    _pat("authorization_basic", r"(?i)\bbasic\s+([A-Za-z0-9=:_+/-]{12,200})",
         "Medium", capture=True),
    _pat("firebaseio_url", r"[a-z0-9-]+\.firebaseio\.com(?![a-z0-9-])", "Medium"),

    # ── Low: identifiers that likely accompany a secret ───────────
    _pat("twilio_account_sid", r"AC[0-9a-zA-Z_-]{32}(?![0-9A-Za-z_-])", "Low", prefix_len=2),
]


def scan_text(text: str) -> list[PatternFinding]:
    """Scan arbitrary text (a diff, a file, a message) for credential values."""
    findings: list[PatternFinding] = []
    if not text:
        return findings
    seen: set[tuple[str, int]] = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        if stripped.startswith(("+++ ", "--- ", "diff --git", "index ", "@@")):
            continue
        low = line.lower()
        for pat in SECRET_PATTERNS:
            if pat.context and not any(c in low for c in pat.context):
                continue
            for m in pat.regex.finditer(line):
                value = m.group(1) if pat.capture_group and m.lastindex else m.group(0)
                if not value:
                    continue
                start = m.start(1) if pat.capture_group and m.lastindex else m.start(0)
                if start > 0 and (line[start - 1].isalnum() or line[start - 1] in "_-"):
                    continue
                upper = value.upper()
                if pat.prefix_len and upper[pat.prefix_len:].startswith(_PLACEHOLDERS):
                    continue
                if upper.startswith(_PLACEHOLDERS):
                    continue
                key = (pat.name, value, lineno)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(PatternFinding(
                    detector=pat.name,
                    value=value,
                    redacted=_redact(value),
                    line_number=lineno,
                    severity=pat.severity,
                    line_snippet=_snip(line, value),
                ))
    return findings


def pattern_names() -> list[str]:
    return [p.name for p in SECRET_PATTERNS]
