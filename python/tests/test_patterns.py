"""Regression tests for the built-in secret pattern scanner (stdlib only).

Run:  cd python && python3 -m unittest discover -s tests -v

Provider-shaped fixtures are assembled at runtime so the repository never
contains a contiguous, scanner-valid "secret" literal (GitHub Push Protection
flags format-valid samples even when fake).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghleak.patterns import SECRET_PATTERNS, scan_text
from ghleak.scanner import TruffleHogScanner

FX_GITHUB_PAT = "ghp_" + "AbcDefGhiJklMnoPqrStuvWxYz0123456789ab"
FX_FINE_GRAINED = "github_pat_" + ("A1b2C3d4E5f6G7h8I9j0" * 5)[:82]
FX_AWS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
FX_GOOGLE_KEY = "AIza" + "SyA1234567890abcdefghijklmnopqrstuv"
FX_ANTHROPIC = "sk-ant-" + "api03-abcdef1234567890abcdef1234567890abcdef12"
FX_SLACK = "xoxb-" + "123456789012" + "-" + "abcdef"
FX_TELEGRAM = "123456789" + ":AA" + "HfiqksKZ8WmoU3b9zJZmZ4nL1pQ2rS3tU"
FX_JWT = ("eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "."
          + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")
FX_GITLAB = "glpat-" + "abcdef1234567890abcdef"
FX_OAUTH = "ya29." + "a0AfH6SMBx1234567890abcdefghij"
FX_DISCORD = ("MzQ4NzY5MDEyMzQ1Njc4OTAx" + "." + "GxYzAb" + "."
              + "C3dEfGhIjKlMnOpQrStUvWxYz0123456789AbCd")
FX_MAILCHIMP = "0123456789abcdef0123456789abcdef" + "-us" + "12"
FX_MONGO = "mongodb+srv://admin:" + "hunter2" + "pass" + "@cluster0.example.mongodb.net/db"
FX_STRIPE_HOOK = "whsec_" + "abcdefghijklmnopqrstuvwxyz123456"
FX_HEROKU = "01234567-89ab-cdef" + "-0123-456789abcdef"
FX_SLACK_HOOK = ("https://hooks.slack.com/services/T01234567"
                 + "/B01234567/" + "abcdefghijklmnopqrstuvwx")


class TestCatalog(unittest.TestCase):
    def test_catalog_is_large(self):
        self.assertGreaterEqual(len(SECRET_PATTERNS), 50)

    def test_detector_names_unique(self):
        names = [p.name for p in SECRET_PATTERNS]
        self.assertEqual(len(names), len(set(names)))

    def test_all_severities_known(self):
        allowed = {"Critical", "High", "Medium", "Low"}
        for p in SECRET_PATTERNS:
            self.assertIn(p.severity, allowed, p.name)


class TestPositives(unittest.TestCase):
    CASES = [
        ("token: " + FX_GITHUB_PAT, "github_classic_pat"),
        (FX_FINE_GRAINED, "github_fine_grained_pat"),
        ("aws_access_key_id = " + FX_AWS_KEY_ID, "aws_access_key_id"),
        ("key=" + FX_GOOGLE_KEY, "google_api_key"),
        (FX_ANTHROPIC, "anthropic_api_key"),
        ("SLACK_TOKEN=" + FX_SLACK, "slack_token"),
        ("BOT=" + FX_TELEGRAM, "telegram_bot_token"),
        ("auth: " + FX_JWT, "jwt"),
        (FX_GITLAB, "gitlab_pat"),
        ("refresh_token=" + FX_OAUTH, "google_oauth_refresh"),
        ("discord: " + FX_DISCORD, "discord_bot_token"),
        ("mailchimp=" + FX_MAILCHIMP, "mailchimp_api_key"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "private_key_block"),
        ("MONGODB_URI=" + FX_MONGO, "db_uri_with_credentials"),
        ("STRIPE_WH=" + FX_STRIPE_HOOK, "stripe_webhook_secret"),
        ('heroku_api_key = "' + FX_HEROKU + '"', "heroku_api_key"),
        ('"type": "service_account"', "google_service_account_json"),
        ("slack_webhook: " + FX_SLACK_HOOK, "slack_webhook"),
    ]

    def test_each_case_detected(self):
        for text, want in self.CASES:
            with self.subTest(want=want):
                detectors = {f.detector for f in scan_text(text)}
                self.assertIn(want, detectors)

    def test_severity_is_reported(self):
        findings = scan_text(FX_GITHUB_PAT)
        self.assertTrue(findings)
        self.assertEqual(findings[0].severity, "Critical")

    def test_values_are_redacted(self):
        findings = scan_text(FX_GITHUB_PAT)
        self.assertNotEqual(findings[0].value, findings[0].redacted)


class TestNegatives(unittest.TestCase):
    NEGATIVES = [
        "ghp_" + "YOUR_TOKEN_HERE",
        "token=ghp_" + "EXAMPLE" + "_PLACEHOLDER_XXXX",
        "revoked my short ghp tag",
        "const x = 'sk-...' // example",
        "update readme",
        "AKIA short",
        "password = 'your_password'",
        "https://example.com/docs",
    ]

    def test_no_false_positives(self):
        for text in self.NEGATIVES:
            with self.subTest(text=text):
                self.assertEqual([], scan_text(text))


class TestScannerFallback(unittest.TestCase):
    def test_works_without_trufflehog(self):
        diff = (
            "diff --git a/.env b/.env\n"
            "+++ b/.env\n"
            "@@ -0,0 +1,2 @@\n"
            "+GITHUB_TOKEN=" + FX_GITHUB_PAT + "\n"
            "+AWS_ACCESS_KEY_ID=" + FX_AWS_KEY_ID + "\n"
        )
        scanner = TruffleHogScanner(binary="trufflehog-not-installed", only_verified=True)
        findings = scanner.scan_diff(diff)
        detectors = " ".join(f.detector for f in findings)
        self.assertIn("github_classic_pat", detectors)
        self.assertIn("aws_access_key_id", detectors)
        self.assertTrue(all(not f.verified for f in findings))


if __name__ == "__main__":
    unittest.main()
