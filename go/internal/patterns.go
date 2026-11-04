package internal

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

// Built-in secret-value pattern scanning — works with or without TruffleHog.
//
// TruffleHog remains the verification authority (it makes live auth requests
// against the provider). This scanner is a zero-dependency first pass that
// detects well-known credential formats by prefix, charset, and length.
// Findings are candidates: Verified=false, DetectorName="builtin/<name>".
//
// RE2 notes: Go's regexp has no lookbehind/lookahead. Word boundaries (\b)
// plus explicit validation in validateCandidate cover the same ground.

type secretPattern struct {
	Name          string
	Re            *regexp.Regexp
	PrefixLen     int      // chars of fixed prefix (for placeholder checks)
	Placeholders  []string // rejected right after the prefix
	NeedContext   []string // require one of these words on the line (lowercase)
	ContextWindow int      // ignored when NeedContext is empty
}

var placeholderWords = []string{"YOUR", "EXAMPLE", "XXXX", "PLACEHOLDER", "REDACTED", "TOKEN", "SECRET", "KEY", "SAMPLE", "TEST"}

func pat(name, expr string, prefixLen int) secretPattern {
	return secretPattern{Name: name, Re: regexp.MustCompile(expr), PrefixLen: prefixLen}
}

// SecretPatterns is the detection catalog. Order only affects reporting.
var SecretPatterns = []secretPattern{
	pat("github_classic_pat", `ghp_[A-Za-z0-9]{36,38}\b`, 4),
	pat("github_oauth_token", `gho_[A-Za-z0-9]{36,38}\b`, 4),
	pat("github_user_token", `ghu_[A-Za-z0-9]{36,38}\b`, 4),
	pat("github_server_token", `ghs_[A-Za-z0-9]{36,38}\b`, 4),
	pat("github_refresh_token", `ghr_[A-Za-z0-9]{36,38}\b`, 4),
	pat("github_fine_grained_pat", `github_pat_[A-Za-z0-9_]{80,84}\b`, 11),
	pat("gitlab_pat", `glpat-[A-Za-z0-9_-]{20,27}\b`, 6),
	pat("aws_access_key_id", `\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`, 4),
	pat("google_api_key", `AIza[0-9A-Za-z_-]{35}\b`, 4),
	pat("anthropic_api_key", `sk-ant-[A-Za-z0-9_-]{24,120}\b`, 7),
	pat("openai_api_key", `sk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b`, 3),
	pat("openai_generic", `sk-[A-Za-z0-9_-]{40,60}\b`, 3),
	pat("slack_token", `xox[abprs]-[A-Za-z0-9-]{10,250}\b`, 5),
	pat("telegram_bot_token", `\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b`, 0),
	pat("stripe_secret_key", `\b[rs]k_live_[A-Za-z0-9]{24,99}\b`, 8),
	pat("shopify_token", `sh(?:p|a|pss)at_[a-f0-9]{32}\b`, 6),
	pat("sendgrid_api_key", `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`, 3),
	pat("twilio_api_key", `\bSK[0-9a-fA-F]{32}\b`, 2),
	pat("npm_token", `npm_[A-Za-z0-9]{36}\b`, 4),
	pat("pypi_token", `pypi-[A-Za-z0-9_-]{50,}\b`, 5),
	pat("heroku_api_key", `heroku_[0-9a-f]{32}\b`, 7),
	pat("square_access_token", `EAAA[A-Za-z0-9_-]{30,60}\b`, 4),
	pat("jwt", `\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`, 3),
	pat("firebase_cloud_messaging", `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{130,140}\b`, 4),
}

func init() {
	for i := range SecretPatterns {
		if len(SecretPatterns[i].Placeholders) == 0 {
			SecretPatterns[i].Placeholders = placeholderWords
		}
	}
}

func isTokenChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-'
}

// validateCandidate applies the guards that RE2 cannot express inline.
func validateCandidate(p secretPattern, line string, start, end int) bool {
	if start > 0 && isTokenChar(line[start-1]) {
		return false // left boundary
	}
	// Placeholder guard: look right after the fixed prefix.
	rest := line[start:end]
	if p.PrefixLen > 0 && len(rest) > p.PrefixLen {
		after := strings.ToUpper(rest[p.PrefixLen:])
		for _, w := range p.Placeholders {
			if strings.HasPrefix(after, w) {
				return false
			}
		}
	}
	// Context guard (e.g. a 40-char base64 blob only counts as an AWS secret
	// when the line mentions aws/secret/key).
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
		if strings.HasPrefix(trimmed, "diff --git") || strings.HasPrefix(trimmed, "+++") ||
			strings.HasPrefix(trimmed, "---") || strings.HasPrefix(trimmed, "@@") ||
			strings.HasPrefix(trimmed, "index ") {
			continue
		}
		for _, p := range SecretPatterns {
			for _, loc := range p.Re.FindAllStringIndex(line, -1) {
				start, end := loc[0], loc[1]
				if !validateCandidate(p, line, start, end) {
					continue
				}
				val := line[start:end]
				key := fmt.Sprintf("%s:%d", val, lineNo)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				snippet := line
				if len(snippet) > 160 {
					snippet = snippet[:160]
				}
				snippet = strings.Replace(snippet, val, redactValue(val), 1)
				findings = append(findings, PatternFinding{
					Detector:    p.Name,
					Value:       val,
					Redacted:    redactValue(val),
					LineNumber:  lineNo,
					LineSnippet: snippet,
				})
			}
		}
	}
	return findings
}

// PatternNames returns the detector catalog names (useful for --list-patterns).
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
		RawV2:        pf.Redacted,
		File:         pf.LineSnippet,
		Commit:       fmt.Sprintf("line:%d", pf.LineNumber),
	}
}
