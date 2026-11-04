package internal

import "testing"

// Provider-shaped fixtures are assembled at runtime so the repository never
// contains a contiguous, scanner-valid "secret" literal (GitHub Push
// Protection and secret scanners flag format-valid samples even when fake).
var (
	fxGithubPat    = "ghp_" + "AbcDefGhiJklMnoPqrStuvWxYz0123456789ab"
	fxFineGrained  = "github_pat_" + repeat("A1b2C3d4E5f6G7h8I9j0", 5)[:82]
	fxAwsKeyID     = "AKIA" + "IOSFODNN7EXAMPLE"
	fxGoogleKey    = "AIza" + "SyA1234567890abcdefghijklmnopqrstuv"
	fxAnthropicKey = "sk-ant-" + "api03-abcdef1234567890abcdef1234567890abcdef12"
	fxSlackToken   = "xoxb-" + "123456789012" + "-" + "abcdef"
	fxTelegram     = "123456789" + ":AA" + "HfiqksKZ8WmoU3b9zJZmZ4nL1pQ2rS3tU"
	fxJWT          = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
	fxGitlabPat   = "glpat-" + "abcdef1234567890abcdef"
	fxOauth       = "ya29." + "a0AfH6SMBx1234567890abcdefghij"
	fxDiscord     = "MzQ4NzY5MDEyMzQ1Njc4OTAx" + "." + "GxYzAb" + "." + "C3dEfGhIjKlMnOpQrStUvWxYz0123456789AbCd"
	fxMailchimp   = "0123456789abcdef0123456789abcdef" + "-us" + "12"
	fxMongo       = "mongodb+srv://admin:" + "hunter2" + "pass" + "@cluster0.example.mongodb.net/db"
	fxStripeHook  = "whsec_" + "abcdefghijklmnopqrstuvwxyz123456"
	fxHeroku      = "01234567-89ab-cdef" + "-0123-456789abcdef"
	fxSlackHook   = "https://hooks.slack.com/services/T01234567" + "/B01234567/" + "abcdefghijklmnopqrstuvwx"
)

func TestScanTextCandidatesPositives(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{"token: " + fxGithubPat + " done", "github_classic_pat"},
		{fxFineGrained, "github_fine_grained_pat"},
		{"aws_access_key_id = " + fxAwsKeyID, "aws_access_key_id"},
		{"key=" + fxGoogleKey, "google_api_key"},
		{fxAnthropicKey, "anthropic_api_key"},
		{"SLACK_TOKEN=" + fxSlackToken, "slack_token"},
		{"BOT=" + fxTelegram, "telegram_bot_token"},
		{"auth: " + fxJWT, "jwt"},
		{fxGitlabPat, "gitlab_pat"},
		{"refresh_token=" + fxOauth, "google_oauth_refresh"},
		{"discord: " + fxDiscord, "discord_bot_token"},
		{"mailchimp=" + fxMailchimp, "mailchimp_api_key"},
		{"-----BEGIN OPENSSH PRIVATE KEY-----", "private_key_block"},
		{"MONGODB_URI=" + fxMongo, "db_uri_with_credentials"},
		{"STRIPE_WH=" + fxStripeHook, "stripe_webhook_secret"},
		{`heroku_api_key = "` + fxHeroku + `"`, "heroku_api_key"},
		{`"type": "service_account"`, "google_service_account_json"},
		{"slack_webhook: " + fxSlackHook, "slack_webhook"},
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
			t.Errorf("expected %s, got none for constructed fixture", c.want)
		}
	}
}

func TestScanTextCandidatesNegatives(t *testing.T) {
	negatives := []string{
		"ghp_" + "YOUR_TOKEN_HERE",
		"token=ghp_" + "EXAMPLE" + "_PLACEHOLDER_XXXX",
		"revoked my short ghp tag",
		"const x = 'sk-...' // example",
		"update readme",
		"AKIA short",
		"password = 'your_password'",
	}
	for _, text := range negatives {
		if findings := ScanTextCandidates(text); len(findings) > 0 {
			t.Errorf("unexpected findings for %q: %+v", text, findings)
		}
	}
}

func TestScanTextCandidatesNoDuplicatesPerLine(t *testing.T) {
	line := fxGithubPat
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
