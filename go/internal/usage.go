package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// UsageRecord is cumulative LLM usage for one provider/model pair.
type UsageRecord struct {
	Provider     string `json:"provider"`
	Model        string `json:"model"`
	Requests     int64  `json:"requests"`
	Errors       int64  `json:"errors"`
	InputTokens  int64  `json:"input_tokens"`
	CachedTokens int64  `json:"cached_tokens"`
	OutputTokens int64  `json:"output_tokens"`
	LastUsedUnix int64  `json:"last_used_unix"`
}

// HitRate is cached input tokens as a percentage of total input tokens.
func (r *UsageRecord) HitRate() float64 {
	if r.InputTokens == 0 {
		return 0
	}
	return float64(r.CachedTokens) / float64(r.InputTokens) * 100
}

// UsageLedger persists cumulative provider usage across runs.
type UsageLedger struct {
	mu      sync.Mutex
	Path    string
	Records map[string]*UsageRecord
}

// DefaultUsagePath returns $XDG_CACHE_HOME/ghleak/usage.json.
func DefaultUsagePath() string {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "ghleak", "usage.json")
}

// LoadUsage loads the ledger at path; a missing or corrupt file starts empty.
func LoadUsage(path string) *UsageLedger {
	l := &UsageLedger{Path: path, Records: map[string]*UsageRecord{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return l
	}
	var file struct {
		Records     []*UsageRecord `json:"records"`
		UpdatedUnix int64          `json:"updated_unix"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return l
	}
	for _, r := range file.Records {
		if r == nil || r.Provider == "" {
			continue
		}
		l.Records[r.Provider+"/"+r.Model] = r
	}
	return l
}

// Observe folds one backend's session snapshot into the ledger.
func (l *UsageLedger) Observe(s BackendStats) {
	if s.Requests == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key := s.Provider + "/" + s.Model
	r, ok := l.Records[key]
	if !ok {
		r = &UsageRecord{Provider: s.Provider, Model: s.Model}
		l.Records[key] = r
	}
	r.Requests += s.Requests
	r.Errors += s.Errors
	r.InputTokens += s.InputTokens
	r.CachedTokens += s.CachedTokens
	r.OutputTokens += s.OutputTokens
	r.LastUsedUnix = time.Now().Unix()
}

// Snapshot returns records sorted by provider then model.
func (l *UsageLedger) Snapshot() []UsageRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]UsageRecord, 0, len(l.Records))
	for _, r := range l.Records {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].Model < out[j].Model
	})
	return out
}

// Totals aggregates every record.
func (l *UsageLedger) Totals() (requests, errors, input, cached, output int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.Records {
		requests += r.Requests
		errors += r.Errors
		input += r.InputTokens
		cached += r.CachedTokens
		output += r.OutputTokens
	}
	return
}

// Save writes the ledger atomically.
func (l *UsageLedger) Save() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o755); err != nil {
		return err
	}
	records := make([]*UsageRecord, 0, len(l.Records))
	for _, r := range l.Records {
		records = append(records, r)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Provider != records[j].Provider {
			return records[i].Provider < records[j].Provider
		}
		return records[i].Model < records[j].Model
	})
	payload := map[string]any{
		"updated_unix": time.Now().Unix(),
		"records":      records,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	tmp := l.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, l.Path)
}

// FormatUsage renders the ledger as an aligned table.
func FormatUsage(records []UsageRecord, totals [5]int64, path string) string {
	var b []byte
	b = append(b, []byte(fmt.Sprintf("GHLEAK LLM USAGE  %s\n\n", path))...)
	b = append(b, []byte(fmt.Sprintf("%-26s %8s %7s %12s %12s %7s %10s  %s\n",
		"PROVIDER/MODEL", "REQ", "ERR", "INPUT", "CACHED", "HIT%", "OUTPUT", "LAST USED"))...)
	for _, r := range records {
		last := "-"
		if r.LastUsedUnix > 0 {
			last = time.Unix(r.LastUsedUnix, 0).Format("2006-01-02 15:04")
		}
		b = append(b, []byte(fmt.Sprintf("%-26s %8d %7d %12d %12d %6.1f%% %10d  %s\n",
			r.Provider+"/"+r.Model, r.Requests, r.Errors, r.InputTokens,
			r.CachedTokens, r.HitRate(), r.OutputTokens, last))...)
	}
	hit := 0.0
	if totals[2] > 0 {
		hit = float64(totals[3]) / float64(totals[2]) * 100
	}
	b = append(b, []byte(fmt.Sprintf("%-26s %8d %7d %12d %12d %6.1f%% %10d\n",
		"TOTAL", totals[0], totals[1], totals[2], totals[3], hit, totals[4]))...)
	return string(b)
}
