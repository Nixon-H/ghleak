# GhLeak — Secret Leak Pipeline

Replicates the pipeline from [aydinnyunus's blog post](https://yunusaydin.org/your-ai-just-leaked-a-secret): monitors the GitHub Archive firehose for commit messages that smell like a leaked credential, fetches the diff, and runs TruffleHog with verification enabled.

**Supports:** GitHub (via GH Archive + API), GitLab (via API), and any git forge (via clone).

Also ships a **built-in secret-pattern scanner** (no external binary required) and **rate-limit-aware fetching** — see below.

## How it works

```
GH Archive → PushEvents → GitHub API (commit msgs) → regex classifier → fetch diff → TruffleHog → verified findings
```

### Phase 1: GH Archive streaming

Every public GitHub action lands in GH Archive as a JSON event stream. We filter to PushEvents, extracting `(repo, head_sha)` pairs. ~160k events/hour, ~128k PushEvents/hour.

### Phase 2: Commit message classification

Regex-first, AI-fallback approach:

1. **SECRET_REMOVAL_PATTERNS** — compiled regexes that catch canonical "I just leaked a secret" messages (`remove|delete|revoke.*key|token|secret`)
2. **Tier 1** — high-confidence verb (remove, revoke, rotate) AND high-confidence noun (api_key, credential, .env)
3. **Tier 2** — broad verb (update, change, fix) AND broad noun (any of ~80 brand/infra terms from TruffleHog's detector catalog)
4. **LLM fallback** — ambiguous messages go to Gemini (optional)

### Phase 3: Active verification

Suspicious commits get their diff fetched via GitHub API, then scanned with `trufflehog --only-verified`. TruffleHog's verifiers build real authentication requests against the issuing service.

### Built-in secret patterns (no TruffleHog required)

Every diff is *also* scanned by a zero-dependency pattern engine that matches credential **values** directly. This works even when the `trufflehog` binary is not installed, and its candidates are merged with TruffleHog's findings (TruffleHog stays authoritative; builtin hits are `verified=false`).

**57 detectors**, each with a severity level (Critical/High/Medium/Low):

| Family | Patterns |
|---|---|
| Private keys | `BEGIN RSA/DSA/EC/OPENSSH/PGP PRIVATE KEY` blocks |
| GitHub | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`, credentials in clone URLs |
| GitLab | `glpat-` |
| AWS | `AKIA`/`ASIA`/`ABIA`/`ACCA` key IDs, 40-char secret keys, MWS auth tokens |
| Google | `AIza…` API keys, `ya29.…` OAuth refresh tokens, service-account JSON |
| LLM providers | `sk-ant-…` (Anthropic), `sk-…T3BlbkFJ…` / `sk-proj-…` (OpenAI) |
| Messaging | `xox[abprs]-` (Slack), Slack webhooks, Discord bot tokens, Telegram bots |
| Payments | `[rs]k_live_…` (Stripe), `whsec_…` webhooks, `shpat_…` (Shopify), `sq0atp`/`sq0csp`/`EAAA…` (Square), PayPal Braintree tokens |
| Email | `SG.…` (SendGrid), `key-…` (Mailgun), `…-usNN` (MailChimp) |
| Cloud/ops | `AKIA`-adjacent Twilio keys + SIDs, Heroku UUIDs, Azure client secrets, Jenkins tokens, Grafana `glsa_`, New Relic `NRAK-`, Doppler `dp.pt.`, Netlify `nfp_`, npm, PyPI |
| Social | Facebook access tokens + app secrets, Twitter access + OAuth secrets |
| Credentialed URLs | `mongodb(+srv)://user:pass@`, `postgres://`, `mysql://`, `redis://`, `amqp(s)://`, Cloudinary URLs, password-in-URL |
| Generic assignments | `password=`, `api_key=`, `secret=` (context-anchored, length-bounded) |
| Auth headers | `Bearer …`, `Basic …`, JWTs (`eyJ….eyJ….`), Firebase FCM keys |

Placeholder guards reject `ghp_YOUR_TOKEN_HERE` / `password = "your_password"`-style examples, and each hit is redacted (`ghp_AbcDef…`) before it reaches logs or reports.

### Rate limits

The tool is designed to *not* burn through API budgets:

- **Authoritative accounting** — every response's `x-ratelimit-remaining` and `x-ratelimit-reset` headers update the budget; no guessed counters.
- **Proactive pacing** — under 200 remaining requests, calls are spread so the budget lasts until the reset instead of slamming into the wall.
- **Retry-After honored** — 403/429 responses wait exactly as long as the server asks.
- **Exponential backoff with jitter** — 403/429/5xx and transport errors retry up to 5 times; commits are no longer silently dropped.
- **LLM calls** retry 429/5xx with backoff too, and a failed batch never poisons the classifier cache with false "clean" results.

### Phase 4: Remediation

Rotate at the issuer first (not in the file), then clean git history with `git-filter-repo`. Pre-commit hooks (`trufflehog` as a pre-commit hook) block the next one.

## Installation

Single Go implementation — no runtime dependencies beyond the optional
`trufflehog` binary. (Go-only since v1.4.0; the former Python implementation
was removed and remains available in git history.)

### Go (from source)

```bash
go install github.com/Nixon-H/ghleak/go@latest
# Binary will be at $GOPATH/bin/ghleak
```

Or clone and build:
```bash
git clone https://github.com/Nixon-H/ghleak.git
cd ghleak/go
go build -o ghleak .
```

**Requires:** `trufflehog` binary in `PATH` — optional: without it, the
built-in pattern scanner still reports candidates (marked unverified).

Needs a GitHub token (set `GITHUB_TOKEN` env var) for commit message and diff fetching. Without one, rate limits are 60 req/hr — effectively unusable for archive scanning.

## Usage

### Scan recent GH Archive hours

```bash
# Scan last 2 hours (default)
ghleak scan

# Scan last 6 hours, save JSON report
ghleak scan --hours 6 --output json --output-file report.json

# Quick scan with 1% sampling (test the pipeline)
ghleak scan --hours 4 --sample 0.01 --skip-diffs

# Markdown report
ghleak scan --hours 24 --output md --output-file report.md
```

### Continuous monitoring

```bash
ghleak monitor --interval 15   # Check GH Archive every 15 minutes
```

### Scan a specific commit

```bash
# By repo + SHA (GitHub)
ghleak commit microsoft/maro <sha>

# By git URL (any forge)
ghleak url https://github.com/owner/repo.git <sha>
ghleak url git@gitlab.com:owner/repo.git <sha>
```

## Output formats

- `text` — terminal summary with top detectors and sample findings
- `json` — full structured report
- `csv` — spreadsheet-ready
- `md` — GitHub-flavored markdown report

## Classifier accuracy

Tested against 13 known patterns:

```
remove leaked api key             → suspicious  ✓
fix: expose secret token          → suspicious  ✓
revoke aws credentials            → suspicious  ✓
remove hard coded api key         → suspicious  ✓
security fix: remove credentials  → suspicious  ✓
rotate database password          → suspicious  ✓
credentials leak fixed            → suspicious  ✓
update readme                     → clean       ✓
fix keyboard shortcut             → clean       ✓
add new feature                   → clean       ✓
```

## Architecture

```
ghleak/
├── main.go              # CLI entry point (scan/monitor/commit/url)
├── cmd/
│   └── scan.go          # scan + monitor pipelines
└── internal/
    ├── config.go        # endpoints, prompts, word lists, detector keywords
    ├── classifier.go    # CommitClassifier (regex-first, AI-fallback)
    ├── fetcher.go       # GH Archive download, GitHub/GitLab API, rate limits
    ├── patterns.go      # built-in 57-detector secret-value scanner
    ├── scanner.go       # TruffleHog engine + subprocess wrapper
    ├── reporter.go      # text/JSON/CSV/MD reports
    └── corporate.go     # Fortune 500 / big-tech target filter
```

## References

- [aydinnyunus: Your AI Just Leaked a Secret](https://yunusaydin.org/your-ai-just-leaked-a-secret)
- [GH Archive](https://www.gharchive.org/)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [How to Rotate](https://howtorotate.com/)
