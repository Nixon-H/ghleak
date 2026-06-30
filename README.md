# GhLeak — Secret Leak Pipeline

Replicates the pipeline from [aydinnyunus's blog post](https://yunusaydin.org/your-ai-just-leaked-a-secret): monitors the GitHub Archive firehose for commit messages that smell like a leaked credential, fetches the diff, and runs TruffleHog with verification enabled.

**Supports:** GitHub (via GH Archive + API), GitLab (via API), and any git forge (via clone).

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

### Phase 4: Remediation

Rotate at the issuer first (not in the file), then clean git history with `git-filter-repo`. Pre-commit hooks (`trufflehog` as a pre-commit hook) block the next one.

## Installation

Two implementations available — Python and Go. Either is sufficient.

### Python (PyPI)

```bash
pip install ghleak
# Requires: trufflehog binary in PATH
```

Or from source: `pip install -e ./python`

### Go (from source)

```bash
go install github.com/nixon-h/ghleak/go@latest
# Binary will be at $GOPATH/bin/ghleak
```

Or clone and build:
```bash
git clone https://github.com/Nixon-H/ghleak.git
cd ghleak/go
go build -o ghleak .
```

**Requires:** `trufflehog` binary in `PATH` for both versions.

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
├── __init__.py          # Package entry
├── config.py            # Regex patterns, detector keywords, prompts
├── classifier.py        # CommitClassifier (regex-first, AI-fallback)
├── fetcher.py           # GH Archive download, GitHub/GitLab API, URL parsing
├── scanner.py           # TruffleHog wrapper (git, filesystem, diff modes)
├── reporter.py          # Report aggregation + text/JSON/CSV/MD output
└── main.py              # CLI entry point
```

## References

- [aydinnyunus: Your AI Just Leaked a Secret](https://yunusaydin.org/your-ai-just-leaked-a-secret)
- [GH Archive](https://www.gharchive.org/)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [How to Rotate](https://howtorotate.com/)
