package internal

import (
	"os"
	"strings"
	"testing"
)

func TestClassifierPatterns(t *testing.T) {
	classifier := NewCommitClassifier(nil)

	tests := []struct {
		msg      string
		want     Classification
		comment  string
	}{
		{"remove leaked api key", Suspicious, "leaked api key removal"},
		{"fix: expose secret token", Suspicious, "expose secret token"},
		{"revoke aws credentials", Suspicious, "revoke aws credentials"},
		{"update readme", Clean, "innocuous readme update"},
		{"fix keyboard shortcut", Clean, "innocuous keyboard fix"},
		{"remove hard coded api key from config", Suspicious, "hard coded key removal"},
		{"security fix: remove hardcoded credentials", Suspicious, "hardcoded credentials"},
		{"rotate database password", Suspicious, "rotate password"},
		{"chore: clean up env file", Clean, "cleanup chore"},
		{"replace actual api key placeholder", Suspicious, "replace key placeholder"},
		{"this is not a real key", Suspicious, "negation pattern match"},
		{"credentials leak fixed", Suspicious, "credentials leak"},
		{"add new feature", Clean, "new feature"},
	}

	for _, tc := range tests {
		got := classifier.Classify(tc.msg)
		if got != tc.want {
			t.Errorf("Classify(%q) = %s, want %s (%s)", tc.msg, got, tc.want, tc.comment)
		}
	}

	stats := classifier.Stats()
	t.Logf("Classifier stats: %v", stats)
}

func TestArchivePipeline(t *testing.T) {
	if os.Getenv("GHLEAK_INTEGRATION") == "" {
		t.Skip("Skipping integration test; set GHLEAK_INTEGRATION=1 to run")
	}

	latest := FindLatestArchiveHour()
	if latest == nil {
		t.Fatal("No archive data available")
	}
	t.Logf("Latest archive hour: %s", latest.Format("2006-01-02T15:04:05Z07:00"))

	url := ArchiveHourURL(*latest)
	t.Logf("Fetching: %s", url)
	events, err := FetchArchive(url)
	if err != nil {
		t.Fatalf("FetchArchive failed: %v", err)
	}
	t.Logf("Got %d events", len(events))

	pushes := ExtractPushEvents(events)
	t.Logf("Got %d PushEvents", len(pushes))

	classifier := NewCommitClassifier(nil)
	suspiciousFound := 0
	limit := 5000
	if len(pushes) < limit {
		limit = len(pushes)
	}
	for _, pe := range pushes[:limit] {
		msg := pe.Ref
		if msg != "" {
			result := classifier.Classify(msg)
			if result == Suspicious {
				suspiciousFound++
			}
		}
	}
	t.Logf("Suspicious (from ref names in %d sample): %d", limit, suspiciousFound)
	t.Logf("Classifier stats: %v", classifier.Stats())

	msgs := []string{
		"remove leaked api key",
		"fix: expose secret token",
		"revoke aws credentials",
		"update readme",
		"fix keyboard shortcut",
		"remove hard coded api key from config",
		"security fix: remove hardcoded credentials",
		"rotate database password",
		"chore: clean up env file",
		"replace actual api key placeholder",
		"this is not a real key",
		"credentials leak fixed",
		"add new feature",
	}
	for _, msg := range msgs {
		result := classifier.Classify(msg)
		mark := " "
		if result == Suspicious {
			mark = "!"
		}
		t.Logf("  %s  %12s: %s", mark, result, msg)
	}
	t.Logf("Final classifier stats: %v", classifier.Stats())
}

// Example-based test for String() on Finding
func TestFindingString(t *testing.T) {
	f := Finding{
		DetectorName: "AWS Key",
		Verified:     true,
		Commit:       "abc123def456ghi789",
		File:         "config.env",
	}
	s := f.String()
	if !strings.Contains(s, "VERIFIED") {
		t.Errorf("Expected VERIFIED in String(), got: %s", s)
	}
	if !strings.Contains(s, "AWS Key") {
		t.Errorf("Expected 'AWS Key' in String(), got: %s", s)
	}
}

// Test the Version constant matches Python's version
func TestVersion(t *testing.T) {
	expected := "1.1.0"
	if Version != expected {
		t.Errorf("Version = %s, want %s", Version, expected)
	}
}
