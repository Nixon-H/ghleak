package internal

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

// Built-in secret-value pattern scanning — works with or without TruffleHog.
//
// TruffleHog remains the verification authority. This scanner is a
// zero-dependency first pass that detects well-known credential formats by
// prefix, charset, length, and context keywords. Findings are candidates:
// Verified=false, DetectorName="builtin/<name>".
//
// Catalog merges SecretFinder (m4ll0k), the viralvaghela APK scanner, and
// gitleaks/trufflehog-style modern token prefixes.
//
// RE2 notes: Go's regexp has no lookbehind/lookahead. Word boundaries plus
// explicit validation in validateCandidate cover the same ground.

type secretPattern struct {
	Name         string
	Re           *regexp.Regexp
	Severity     string   // Critical | High | Medium | Low
	PrefixLen    int      // chars of fixed prefix (placeholder checks)
	Placeholders []string // rejected right after the prefix / at value start
	NeedContext  []string // require one of these words on the line (lowercase)
	CaptureGroup bool     // group 1 is the secret value
}

var placeholderWords = []string{
	"YOUR", "EXAMPLE", "XXXX", "PLACEHOLDER", "REDACTED",
	"TOKEN", "SECRET", "KEY", "SAMPLE", "TESTSECRET",
}

func pat(name, expr, severity string) secretPattern {
	return secretPattern{
		Name:         name,
		Re:           regexp.MustCompile(expr),
		Severity:     severity,
		Placeholders: placeholderWords,
	}
}

func patCtx(name, expr, severity string, ctx ...string) secretPattern {
	p := pat(name, expr, severity)
	p.NeedContext = ctx
	return p
}

func patCap(name, expr, severity string) secretPattern {
	p := pat(name, expr, severity)
	p.CaptureGroup = true
	return p
}

// SecretPatterns is the detection catalog. Order only affects reporting.
var SecretPatterns = []secretPattern{
	// ── Critical: private keys, cloud roots of trust, GitHub tokens ──
	pat("private_key_block", `-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`, "Critical"),
	pat("github_classic_pat", `ghp_[A-Za-z0-9]{36,38}\b`, "Critical"),
	pat("github_oauth_token", `gho_[A-Za-z0-9]{36,38}\b`, "Critical"),
	pat("github_user_token", `ghu_[A-Za-z0-9]{36,38}\b`, "Critical"),
	pat("github_server_token", `ghs_[A-Za-z0-9]{36,38}\b`, "Critical"),
	pat("github_refresh_token", `ghr_[A-Za-z0-9]{36,38}\b`, "Critical"),
	pat("github_fine_grained_pat", `github_pat_[A-Za-z0-9_]{80,84}\b`, "Critical"),
	patCap("aws_secret_access_key", `(?i)(?:aws|secret|access)[^\n]{0,40}?['"]([A-Za-z0-9/+=]{40})['"]`, "Critical"),
	pat("google_service_account_json", `"type"\s*:\s*"service_account"`, "Critical"),
	pat("firebase_cloud_messaging", `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{130,140}\b`, "Critical"),
	pat("openai_api_key", `sk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b`, "Critical"),
	pat("anthropic_api_key", `sk-ant-[A-Za-z0-9_-]{24,120}\b`, "Critical"),
	patCap("password_in_url", `\b[a-zA-Z][a-zA-Z0-9+.-]{2,9}://[^\s:@/]{1,30}:([^\s@/]{3,60})@[^\s"'<>]{3,}`, "Critical"),
	patCap("github_creds_in_url", `https?://[^:@/\s]+:([^@/\s]{3,60})@github\.com`, "Critical"),

	// ── High: provider tokens with precise shapes ─────────────────
	pat("gitlab_pat", `glpat-[A-Za-z0-9_-]{20,27}\b`, "High"),
	pat("google_api_key", `AIza[0-9A-Za-z_-]{35}\b`, "High"),
	pat("google_oauth_refresh", `ya29\.[0-9A-Za-z_-]{20,}`, "High"),
	pat("openai_generic", `sk-[A-Za-z0-9_-]{40,60}\b`, "High"),
	pat("slack_token", `xox[abprs]-[A-Za-z0-9-]{10,250}\b`, "High"),
	pat("slack_webhook", `https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,12}/B[A-Za-z0-9_]{8,12}/[A-Za-z0-9_]{20,32}`, "High"),
	pat("discord_bot_token", `[M-Z][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}\b`, "High"),
	pat("telegram_bot_token", `\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b`, "High"),
	pat("stripe_secret_key", `[sr]k_live_[A-Za-z0-9]{24,99}\b`, "High"),
	pat("stripe_webhook_secret", `whsec_[A-Za-z0-9]{24,}\b`, "High"),
	pat("shopify_token", `sh(?:p|a|pss)at_[a-f0-9]{32}\b`, "High"),
	pat("sendgrid_api_key", `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`, "High"),
	pat("mailgun_api_key", `key-[0-9a-zA-Z]{32}\b`, "High"),
	pat("mailchimp_api_key", `[0-9a-f]{32}-us[0-9]{1,2}\b`, "High"),
	pat("twilio_api_key", `\bSK[0-9a-fA-F]{32}\b`, "High"),
	pat("square_access_token", `(?:sq0atp-[0-9A-Za-z_-]{22}|EAAA[0-9A-Za-z_-]{30,60})\b`, "High"),
	pat("square_oauth_secret", `sq0csp-[0-9A-Za-z_-]{43}\b`, "High"),
	pat("paypal_braintree_token", `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`, "High"),
	pat("facebook_access_token", `EAACEdEose0cBA[0-9A-Za-z]+`, "High"),
	patCap("facebook_oauth_secret", `(?i)facebook[^\n]{0,40}?['"]([0-9a-f]{32})['"]`, "High"),
	patCap("twitter_access_token", `(?i)twitter[^\n]{0,60}?([1-9][0-9]{6,}-[0-9a-zA-Z]{40})`, "High"),
	patCap("twitter_oauth_secret", `(?i)twitter[^\n]{0,40}?['"]([0-9a-zA-Z]{35,44})['"]`, "High"),
	patCap("heroku_api_key", `(?i)heroku[^\n]{0,40}?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`, "High"),
	patCap("azure_client_secret", `(?i)(?:azure|client[_-]?secret)[^\n]{0,40}?['"]([A-Za-z0-9~_.-]{30,})['"]`, "High"),
	pat("aws_access_key_id", `\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`, "High"),
	pat("aws_mws_auth_token", `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, "High"),
	patCap("generic_api_key_assignment", `(?i)\b(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\b\s*[:=]\s*['"]?([A-Za-z0-9_.-]{20,64})`, "High"),
	patCap("generic_secret_assignment", `(?i)\bsecret\b\s*[:=]\s*['"]?([A-Za-z0-9/+=-]{16,64})`, "High"),
	patCap("generic_password_assignment", `(?i)\b(?:password|passwd|pwd|pass)\b\s*[:=]\s*['"]?([^\s'"/\\,;<>]{8,64})`, "High"),
	pat("jwt", `eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`, "High"),
	patCap("jenkins_api_token", `(?i)jenkins[^\n]{0,40}?\b(11[0-9a-f]{32})\b`, "High"),
	pat("npm_token", `npm_[A-Za-z0-9]{36}\b`, "High"),
	pat("pypi_token", `pypi-[A-Za-z0-9_-]{50,}\b`, "High"),
	pat("grafana_service_token", `glsa_[A-Za-z0-9]{32}\b`, "High"),
	pat("newrelic_api_key", `NRAK-[A-Z0-9]{27}\b`, "High"),
	pat("doppler_token", `dp\.pt\.[A-Za-z0-9]{43}\b`, "High"),
	pat("netlify_token", `nfp_[A-Za-z0-9]{40}\b`, "High"),

	// ── High: URLs that embed credentials ─────────────────────────
	patCap("db_uri_with_credentials", `\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|rediss|amqp|amqps)://[^\s:@/]{1,40}:([^\s@/]{1,60})@[^\s"'<>]+`, "High"),
	patCap("cloudinary_url", `cloudinary://[0-9]+:([A-Za-z0-9_-]{10,})@[A-Za-z0-9_-]+`, "High"),

	// ── Medium: auth schemes and endpoints ────────────────────────
	patCap("authorization_bearer", `(?i)\bbearer\s+([A-Za-z0-9_.=:_+/-]{12,200})`, "Medium"),
	patCap("authorization_basic", `(?i)\bbasic\s+([A-Za-z0-9=:_+/-]{12,200})`, "Medium"),
	pat("firebaseio_url", `[a-z0-9-]+\.firebaseio\.com\b`, "Medium"),

	// ── Low: identifiers that likely accompany a secret ───────────
	pat("twilio_account_sid", `AC[0-9a-zA-Z_-]{32}\b`, "Low"),
}

func init() {
	// PrefixLen is derivable from the fixed prefix in the name's regex;
	// set it explicitly where a placeholder guard matters.
	for i := range SecretPatterns {
		switch SecretPatterns[i].Name {
		case "github_classic_pat", "github_oauth_token", "github_user_token",
			"github_server_token", "github_refresh_token":
			SecretPatterns[i].PrefixLen = 4
		case "github_fine_grained_pat":
			SecretPatterns[i].PrefixLen = 11
		case "gitlab_pat":
			SecretPatterns[i].PrefixLen = 6
		case "google_api_key":
			SecretPatterns[i].PrefixLen = 4
		case "anthropic_api_key":
			SecretPatterns[i].PrefixLen = 7
		case "openai_api_key", "openai_generic":
			SecretPatterns[i].PrefixLen = 3
		case "slack_token":
			SecretPatterns[i].PrefixLen = 5
		case "stripe_secret_key":
			SecretPatterns[i].PrefixLen = 8
		case "stripe_webhook_secret":
			SecretPatterns[i].PrefixLen = 6
		case "square_oauth_secret":
			SecretPatterns[i].PrefixLen = 7
		case "sendgrid_api_key":
			SecretPatterns[i].PrefixLen = 3
		case "mailgun_api_key":
			SecretPatterns[i].PrefixLen = 4
		case "facebook_access_token":
			SecretPatterns[i].PrefixLen = 15
		case "firebase_cloud_messaging", "telegram_bot_token":
			SecretPatterns[i].PrefixLen = 0
		}
	}
}

func isTokenChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-'
}

// validateCandidate applies the guards that RE2 cannot express inline.
func validateCandidate(p secretPattern, line string, start int, value string) bool {
	// Template placeholders ({token}) and regex sources ([A-Za-z]) are not
	// secret values — skip pseudo-matches.
	if strings.ContainsAny(value, "{}[]()\\|<>") {
		return false
	}
	if start > 0 && isTokenChar(line[start-1]) {
		return false // left boundary
	}
	if p.PrefixLen > 0 && len(value) > p.PrefixLen {
		after := strings.ToUpper(value[p.PrefixLen:])
		for _, w := range p.Placeholders {
			if strings.HasPrefix(after, w) {
				return false
			}
		}
	}
	upper := strings.ToUpper(value)
	for _, w := range p.Placeholders {
		if strings.HasPrefix(upper, w) {
			return false
		}
	}
	if len(p.NeedContext) > 0 {
		low := strings.ToLower(line)
		found := false
		for _, c := range p.NeedContext {
			if strings.Contains(low, strings.ToLower(c)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func redactValue(v string) string {
	if len(v) <= 10 {
		return v[:4] + "…"
	}
	return v[:10] + "…"
}

// PatternFinding is a candidate secret found by built-in pattern matching.
type PatternFinding struct {
	Detector    string
	Value       string
	Redacted    string
	Severity    string
	LineNumber  int
	LineSnippet string
}

// ScanTextCandidates scans arbitrary text (diff, file, message) for credentials.
func ScanTextCandidates(text string) []PatternFinding {
	var findings []PatternFinding
	if text == "" {
		return findings
	}
	seen := map[string]struct{}{}
	lineNo := 0
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		lineNo++
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "diff --git") || strings.HasPrefix(trimmed, "+++ ") ||
			strings.HasPrefix(trimmed, "--- ") || strings.HasPrefix(trimmed, "@@") ||
			strings.HasPrefix(trimmed, "index ") {
			continue
		}
		for _, p := range SecretPatterns {
			locs := p.Re.FindAllStringSubmatchIndex(line, -1)
			for _, loc := range locs {
				start, end := loc[0], loc[1]
				value := line[start:end]
				if p.CaptureGroup && len(loc) >= 4 && loc[2] >= 0 && loc[3] > loc[2] {
					start, end = loc[2], loc[3]
					value = line[start:end]
				}
				if !validateCandidate(p, line, start, value) {
					continue
				}
				key := fmt.Sprintf("%s:%s:%d", p.Name, value, lineNo)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				snippet := line
				if len(snippet) > 160 {
					snippet = snippet[:160]
				}
				snippet = strings.Replace(snippet, value, redactValue(value), 1)
				findings = append(findings, PatternFinding{
					Detector:    p.Name,
					Value:       value,
					Redacted:    redactValue(value),
					Severity:    p.Severity,
					LineNumber:  lineNo,
					LineSnippet: snippet,
				})
			}
		}
	}
	return findings
}

// PatternNames returns the detector catalog names.
func PatternNames() []string {
	names := make([]string, 0, len(SecretPatterns))
	for _, p := range SecretPatterns {
		names = append(names, p.Name)
	}
	return names
}

// patternFindingToFinding converts a candidate into the standard Finding shape.
func patternFindingToFinding(pf PatternFinding) Finding {
	return Finding{
		DetectorName: "builtin/" + pf.Detector,
		DetectorType: "0",
		Decoder:      "PLAIN",
		Verified:     false,
		Redacted:     true,
		Severity:     pf.Severity,
		RawV2:        pf.Redacted,
		File:         pf.LineSnippet,
		Commit:       fmt.Sprintf("line:%d", pf.LineNumber),
	}
}
