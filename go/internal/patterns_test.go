package internal

import "testing"

func TestScanTextCandidatesPositives(t *testing.T) {
	// Synthetic, spec-shaped (not real) candidates.
	fineGrained := "github_pat_" + repeat("A1b2C3d4E5f6G7h8I9j0", 5)[:82]
	cases := []struct {
		text string
		want string
	}{
		{"token: ghp_AbcDefGhiJklMnoPqrStuvWxYz0123456789ab done", "github_classic_pat"},
		{fineGrained, "github_fine_grained_pat"},
		{"aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "aws_access_key_id"},
		{"key=AIzaSyA1234567890abcdefghijklmnopqrstuv", "google_api_key"},
		{"sk-ant-api03-abcdef1234567890abcdef1234567890abcdef12", "anthropic_api_key"},
		{"SLACK_TOKEN=xoxb-123456789012-abcdef", "slack_token"},
		{"BOT=123456789:AAHfiqksKZ8WmoU3b9zJZmZ4nL1pQ2rS3tU", "telegram_bot_token"},
		{"auth: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c", "jwt"},
		{"glpat-abcdef1234567890abcdef", "gitlab_pat"},
	}
	for _, c := range cases {
		found := false
		for _, f := range ScanTextCandidates(c.text) {
			if f.Detector == c.want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s in %q, got none", c.want, c.text)
		}
	}
}

func TestScanTextCandidatesNegatives(t *testing.T) {
	negatives := []string{
		"ghp_YOUR_TOKEN_HERE",
		"token=ghp_EXAMPLE_PLACEHOLDER_XXXX",
		"revoked my ghp_ short",
		"const x = 'sk-...' // example",
		"update readme",
		"AKIA short",
	}
	for _, text := range negatives {
		if findings := ScanTextCandidates(text); len(findings) > 0 {
			t.Errorf("unexpected findings for %q: %+v", text, findings)
		}
	}
}

func TestScanTextCandidatesNoDuplicatesPerLine(t *testing.T) {
	line := "ghp_AbcDefGhiJklMnoPqrStuvWxYz0123456789ab"
	findings := ScanTextCandidates(line + "\n" + line)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (one per line), got %d", len(findings))
	}
	if findings[0].LineNumber != 1 || findings[1].LineNumber != 2 {
		t.Errorf("bad line numbers: %d, %d", findings[0].LineNumber, findings[1].LineNumber)
	}
	if findings[0].Value == findings[0].Redacted {
		t.Errorf("value should be redacted for display")
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
