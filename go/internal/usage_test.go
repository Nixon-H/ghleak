package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUsageLedgerRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	l := LoadUsage(path)

	l.Observe(BackendStats{
		Provider: "openai", Model: "gpt-4o-mini",
		Requests: 2, InputTokens: 1000, CachedTokens: 900, OutputTokens: 50,
	})
	l.Observe(BackendStats{
		Provider: "openai", Model: "gpt-4o-mini",
		Requests: 1, Errors: 1,
	})
	if err := l.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	l2 := LoadUsage(path)
	recs := l2.Snapshot()
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.Requests != 3 || r.Errors != 1 {
		t.Errorf("requests/errors = %d/%d, want 3/1", r.Requests, r.Errors)
	}
	if r.InputTokens != 1000 || r.CachedTokens != 900 || r.OutputTokens != 50 {
		t.Errorf("tokens = %d/%d/%d, want 1000/900/50", r.InputTokens, r.CachedTokens, r.OutputTokens)
	}
	if got := r.HitRate(); got < 89.99 || got > 90.01 {
		t.Errorf("hit rate = %.2f, want 90.00", got)
	}

	req, errs, in, cached, out := l2.Totals()
	if req != 3 || errs != 1 || in != 1000 || cached != 900 || out != 50 {
		t.Errorf("totals = %d/%d/%d/%d/%d", req, errs, in, cached, out)
	}
}

func TestUsageLedgerMissingFile(t *testing.T) {
	l := LoadUsage(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if len(l.Snapshot()) != 0 {
		t.Error("missing file should yield an empty ledger")
	}
	req, errs, in, cached, out := l.Totals()
	if req+errs+in+cached+out != 0 {
		t.Error("empty ledger totals should be zero")
	}
}

func TestUsageLedgerCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if l := LoadUsage(path); len(l.Snapshot()) != 0 {
		t.Error("corrupt file should be treated as empty, not panic")
	}
}

func TestFormatUsageTable(t *testing.T) {
	records := []UsageRecord{
		{Provider: "openai", Model: "gpt-4o-mini", Requests: 2, InputTokens: 100, CachedTokens: 90},
	}
	out := FormatUsage(records, [5]int64{2, 0, 100, 90, 0}, "/tmp/usage.json")
	for _, want := range []string{"openai/gpt-4o-mini", "90.0%", "TOTAL", "/tmp/usage.json"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
}
