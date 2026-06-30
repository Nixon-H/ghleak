"""Configuration, regex patterns, and detector mappings for ghleak."""

from __future__ import annotations

import re

# ── Secret pattern detection ──────────────────────────────────────

HIGH_CONFIDENCE_ACTION_VERBS = [
    "remove", "delete", "revoke", "invalidate",
    "rotate", "regenerate", "leak", "expose",
    "compromise",
]

HIGH_CONFIDENCE_OBJECT_NOUNS = [
    "api_key", "apikey", "access_token", "auth_token",
    "private_key", "secret_key", "client_secret",
    "credential", "credentials", "password", "passwd",
    "aws_secret", "aws_access_key", ".env", "dotenv",
]

BROAD_ACTION_VERBS = [
    "update", "change", "fix", "patch", "clean",
    "remove", "delete", "purge", "wipe", "scrub",
    "strip", "clear", "sanitize", "redact", "hide",
]

BROAD_OBJECT_NOUNS = [
    "key", "token", "secret", "password", "credential",
    "aws", "amazon", "gcp", "google", "azure", "oauth",
    "openai", "anthropic", "stripe", "twilio", "sendgrid",
    "mailgun", "slack", "discord", "telegram", "github_pat",
    "gitlab", "datadog", "newrelic", "cloudflare", "algolia",
    "mongodb", "postgres", "mysql", "redis", "snowflake",
    "jwt", "bearer", "firebase", "supabase", "vercel",
    "netlify", "heroku", "digitalocean", "doppler",
    "hashicorp", "vault", "docker", "kubernetes", "k8s",
    "wandb", "weights_and_biases", "weights & biases",
    "huggingface", "deepseek", "groq", "elevenlabs",
    "cohere", "replicate", "together", "perplexity",
    "cloudinary", "dropbox", "box", "pagerduty",
    "sentry", "rollbar", "logz", "logdna", "papertrail",
    "s3", "ec2", "iam", "rds", "ses", "sns", "sqs",
    "cloudfront", "route53", "lambda", "eks", "ecr",
]

SECRET_REMOVAL_PATTERNS = [
    re.compile(
        r'\b(remove|delete|revoke|invalidate|rotate|regenerate)\b.*\b'
        r'(key|token|secret|password|credential)\b',
        re.IGNORECASE,
    ),
    re.compile(r'\b(fix|patch)\b.*\b(leak|expose|compromise)\b', re.IGNORECASE),
    re.compile(r'\b(revert)\b.*for.*security.*reason', re.IGNORECASE),
]

GIT_CRED_SWEEP_PATTERNS = [
    re.compile(r'\bremove\s+(hard[-\s]?)?coded\b', re.IGNORECASE),
    re.compile(r'\b(rm|remove|delete)\s+\.env\b', re.IGNORECASE),
    re.compile(r'\brotate\s+(all\s+)?(api\s+)?keys?\b', re.IGNORECASE),
    re.compile(r'\b(pushed|commit|added)\s+(by\s+)?mistake\b', re.IGNORECASE),
    re.compile(r'\bthis\s+is\s+not\s+(a\s+)?real\b', re.IGNORECASE),
    re.compile(r'\breplace\s+(with|your|actual)\b', re.IGNORECASE),
    re.compile(r'\bsecurity\s+fix\b', re.IGNORECASE),
    re.compile(r'\bcredentials?\s+leak', re.IGNORECASE),
    re.compile(r'\bsecret\s+(exposure|exposed|in code)', re.IGNORECASE),
]

TRUFFLEHOG_DETECTORS = [
    "aws", "gcp", "azure", "github", "gitlab", "slack",
    "discord", "telegram", "openai", "anthropic", "stripe",
    "twilio", "sendgrid", "mailgun", "datadog", "newrelic",
    "pagerduty", "sentry", "cloudflare", "algolia",
    "mongodb", "postgresql", "mysql", "redis", "snowflake",
    "jwt", "firebase", "supabase", "vercel", "netlify",
    "heroku", "docker", "kubernetes", "hashicorp",
    "huggingface", "cohere", "replicate", "together",
    "perplexity", "cloudinary", "dropbox",
    "weights_and_biases", "deepseek", "groq", "elevenlabs",
    "artifactory", "jfrog", "npm", "pypi", "rubygems",
    "grafana", "consul", "vault", "okta", "auth0",
]

DEFAULT_RULES = {
    "high_confidence_verbs": HIGH_CONFIDENCE_ACTION_VERBS,
    "high_confidence_nouns": HIGH_CONFIDENCE_OBJECT_NOUNS,
    "broad_verbs": BROAD_ACTION_VERBS,
    "broad_nouns": BROAD_OBJECT_NOUNS,
}

# ── Git forge API configuration ───────────────────────────────────

GH_ARCHIVE_BASE = "https://data.gharchive.org"
GH_API_BASE = "https://api.github.com"
GITLAB_API_BASE = "https://gitlab.com/api/v4"
GITEA_API_BASE = "https://gitea.com/api/v1"
BITBUCKET_API_BASE = "https://api.bitbucket.org/2.0"
AZURE_DEVOPS_API_BASE = "https://dev.azure.com"

FORGE_TYPES = {
    "github", "gitlab", "gitea", "gogs", "bitbucket",
    "azure_devops", "codecommit", "sourceforge", "custom",
}

FORGE_API_DEFAULTS: dict[str, str] = {
    "github": GH_API_BASE,
    "gitlab": GITLAB_API_BASE,
    "gitea": GITEA_API_BASE,
    "gogs": "https://try.gogs.io/api/v1",
    "bitbucket": BITBUCKET_API_BASE,
    "azure_devops": AZURE_DEVOPS_API_BASE,
    "sourceforge": "https://sourceforge.net/rest",
}

# ── LLM / AI fallback configuration ───────────────────────────────

LLM_PROVIDERS = {"openai", "gemini", "anthropic", "custom"}

DEFAULT_LLM_PROVIDER = "openai"
DEFAULT_LLM_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
DEFAULT_LLM_MODEL = "gemini-2.5-flash-lite"

ONE_SHOT_PROMPT = """Analyze the following Git commit message to determine if it is fixing a secret leak.
The message might mention revoking, removing, or rotating keys, tokens, passwords, or other credentials.
Respond with only "true" if it is highly likely to be fixing a secret leak, otherwise respond with "false".

Commit Message:
---
{commit_message}
---"""

BATCH_PROMPT = """Analyze the following Git commit messages to determine if any of them are fixing a secret leak.
A message is considered to be fixing a secret leak if it mentions revoking, removing, or rotating keys, tokens, passwords, or credentials.
Return a JSON object where each key is the numeric index of the commit message (as a string) and the value is a boolean (`true` or `false`).
Ensure your response is only the JSON object.

Commit Messages:
---
{messages}
---"""

USER_AGENT = "ghleak/1.0 (security research; +https://github.com)"
