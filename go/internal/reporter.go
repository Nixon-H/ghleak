package internal

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// NewReport creates an empty thread-safe report.
func NewReport() *Report {
	return &Report{
		SuspiciousCommits: []SuspiciousCommit{},
		Findings:          []Finding{},
		ClassifierStats:   map[string]int{},
		Errors:            []string{},
		StartTime:         time.Now().UTC().Format(time.RFC3339),
	}
}

// IncHoursScanned safely increments the hours counter.
func (r *Report) IncHoursScanned() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.HoursScanned++
}

// IncCommitsSeen safely increments the commits counter.
func (r *Report) IncCommitsSeen() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.CommitsSeen++
}

// AddSuspicious appends a flagged commit to the report securely.
func (r *Report) AddSuspicious(repo, sha, message, result string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.SuspiciousCommits = append(r.SuspiciousCommits, SuspiciousCommit{
		Repo: repo, SHA: sha, Message: message, Result: result,
	})
}

// AddFinding appends a TruffleHog finding securely.
func (r *Report) AddFinding(f Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Findings = append(r.Findings, f)
	if f.Verified {
		r.VerifiedCount++
	}
}

// AddError records a pipeline error.
func (r *Report) AddError(err string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Errors = append(r.Errors, err)
}

// Finish records the end time.
func (r *Report) Finish() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.EndTime = time.Now().UTC().Format(time.RFC3339)
}

// Duration returns the elapsed time between start and end as a formatted string.
func (r *Report) Duration() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	start, err := time.Parse(time.RFC3339, r.StartTime)
	if err != nil {
		return "unknown"
	}
	end, err := time.Parse(time.RFC3339, r.EndTime)
	if err != nil {
		return "unknown"
	}
	d := end.Sub(start)
	return fmt.Sprintf("%.0fs", d.Seconds())
}

// SummaryText returns a human-readable summary matching Python's format.
func (r *Report) SummaryText() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var b strings.Builder
	b.WriteString("════════════════════════════════════════════════════════════════════════\n")
	b.WriteString("  GhLeak — Secret Scan Report\n")
	b.WriteString("════════════════════════════════════════════════════════════════════════\n")
	b.WriteString(fmt.Sprintf("  Scanned hours : %d\n", r.HoursScanned))
	b.WriteString(fmt.Sprintf("  Commits seen  : %d\n", r.CommitsSeen))
	b.WriteString(fmt.Sprintf("  Suspicious    : %d\n", len(r.SuspiciousCommits)))
	b.WriteString(fmt.Sprintf("  Verified      : %d\n", r.VerifiedCount))
	b.WriteString(fmt.Sprintf("  Total findings: %d\n", len(r.Findings)))

	if len(r.SuspiciousCommits) > 0 {
		b.WriteString("\n  Suspicious Commits:\n")
		b.WriteString(fmt.Sprintf("  %-20s | %-12s | %s\n", "Repository", "SHA", "Message"))
		b.WriteString(fmt.Sprintf("  %s\n", strings.Repeat("-", 72)))
		for _, sc := range r.SuspiciousCommits {
			sha := sc.SHA
			if len(sha) > 12 {
				sha = sha[:12]
			}
			msg := sc.Message
			if len(msg) > 50 {
				msg = msg[:50] + "..."
			}
			b.WriteString(fmt.Sprintf("  %-20s | %-12s | %s\n", sc.Repo, sha, msg))
		}
	}

	if len(r.Findings) > 0 {
		b.WriteString(fmt.Sprintf("\n  Top detectors (verified):\n"))
		detectorCounts := map[string]int{}
		for _, f := range r.Findings {
			if f.Verified {
				detectorCounts[f.DetectorName]++
			}
		}
		type dc struct {
			name  string
			count int
		}
		sorted := make([]dc, 0, len(detectorCounts))
		for name, count := range detectorCounts {
			sorted = append(sorted, dc{name, count})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})
		for i, d := range sorted {
			if i >= 10 {
				break
			}
			b.WriteString(fmt.Sprintf("    %s: %d\n", d.name, d.count))
		}

		b.WriteString("\n  Sample verified findings:\n")
		sampleCount := 0
		for _, f := range r.Findings {
			if sampleCount >= 5 {
				break
			}
			if f.Verified {
				commit := f.Commit
				if len(commit) > 12 {
					commit = commit[:12]
				}
				b.WriteString(fmt.Sprintf("    [%s] %s @ %s  (%s)\n",
					f.DetectorName, f.Repository, commit, f.File))
				sampleCount++
			}
		}
	}

	if len(r.ClassifierStats) > 0 {
		b.WriteString("\n  Classifier stats:\n")
		for k, v := range r.ClassifierStats {
			b.WriteString(fmt.Sprintf("    %s: %d\n", k, v))
		}
	}

	if len(r.Errors) > 0 {
		b.WriteString(fmt.Sprintf("\n  Errors (%d):\n", len(r.Errors)))
		for i, err := range r.Errors {
			if i >= 5 {
				break
			}
			b.WriteString(fmt.Sprintf("    ! %s\n", err))
		}
	}

	b.WriteString("════════════════════════════════════════════════════════════════════════\n")
	return b.String()
}

// ToJSON serializes the report as indented JSON with transformed findings.
func (r *Report) ToJSON() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	transformedFindings := make([]map[string]any, 0, len(r.Findings))
	for _, f := range r.Findings {
		raw := f.RawV2
		if len(raw) > 120 {
			raw = raw[:120] + "..."
		}
		transformedFindings = append(transformedFindings, map[string]any{
			"detector":   f.DetectorName,
			"verified":   f.Verified,
			"commit":     f.Commit,
			"file":       f.File,
			"repository": f.Repository,
			"email":      f.Email,
			"redacted":   f.Redacted,
			"raw":        raw,
		})
	}

	out := map[string]any{
		"start_time":         r.StartTime,
		"end_time":           r.EndTime,
		"hours_scanned":      r.HoursScanned,
		"commits_seen":       r.CommitsSeen,
		"suspicious_count":   len(r.SuspiciousCommits),
		"verified_count":     r.VerifiedCount,
		"total_findings":     len(r.Findings),
		"classifier_stats":   r.ClassifierStats,
		"suspicious_commits": r.SuspiciousCommits,
		"verified_findings":  transformedFindings,
		"errors":             r.Errors,
	}

	data, _ := json.MarshalIndent(out, "", "  ")
	return string(data)
}

// ToCSV writes findings to a CSV writer matching Python's columns.
func (r *Report) ToCSV(w io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cw := csv.NewWriter(w)
	cw.Write([]string{"detector", "verified", "commit", "file", "repository", "email"})
	for _, f := range r.Findings {
		cw.Write([]string{
			f.DetectorName,
			fmt.Sprintf("%v", f.Verified),
			f.Commit,
			f.File,
			f.Repository,
			f.Email,
		})
	}
	cw.Flush()
	return cw.Error()
}

// ToMarkdown formats the report as Markdown matching Python's format.
func (r *Report) ToMarkdown() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var b strings.Builder
	b.WriteString("# GhLeak Scan Report\n\n")

	b.WriteString(fmt.Sprintf("**Hours scanned:** %d\n", r.HoursScanned))
	b.WriteString(fmt.Sprintf("**Commits seen:** %d\n", r.CommitsSeen))
	b.WriteString(fmt.Sprintf("**Suspicious:** %d\n", len(r.SuspiciousCommits)))
	b.WriteString(fmt.Sprintf("**Verified secrets:** %d\n\n", r.VerifiedCount))

	if len(r.Findings) > 0 {
		b.WriteString("## Verified Findings by Detector\n\n")
		b.WriteString("| Detector | Count |\n")
		b.WriteString("|----------|-------|\n")
		detectorCounts := map[string]int{}
		for _, f := range r.Findings {
			if f.Verified {
				detectorCounts[f.DetectorName]++
			}
		}
		type dc struct {
			name  string
			count int
		}
		sorted := make([]dc, 0, len(detectorCounts))
		for name, count := range detectorCounts {
			sorted = append(sorted, dc{name, count})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})
		for _, d := range sorted {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", d.name, d.count))
		}

		b.WriteString("\n## Sample Verified Secrets\n\n")
		b.WriteString("| Detector | Repository | Commit | File |\n")
		b.WriteString("|----------|------------|--------|------|\n")
		sampleCount := 0
		for _, f := range r.Findings {
			if sampleCount >= 20 {
				break
			}
			if f.Verified {
				repo := f.Repository
				if repo == "" {
					repo = "—"
				}
				file := f.File
				if file == "" {
					file = "—"
				}
				commit := f.Commit
				if len(commit) > 12 {
					commit = commit[:12]
				}
				b.WriteString(fmt.Sprintf("| %s | %s | `%s` | %s |\n",
					f.DetectorName, repo, commit, file))
				sampleCount++
			}
		}
	}

	if len(r.SuspiciousCommits) > 0 {
		b.WriteString("\n## Suspicious Commits (by message classification)\n\n")
		b.WriteString("| Repository | Commit | Message |\n")
		b.WriteString("|------------|--------|---------|\n")
		for i, sc := range r.SuspiciousCommits {
			if i >= 30 {
				break
			}
			sha := sc.SHA
			if len(sha) > 12 {
				sha = sha[:12]
			}
			msg := sc.Message
			if len(msg) > 60 {
				msg = msg[:60] + "..."
			}
			b.WriteString(fmt.Sprintf("| %s | `%s` | %s |\n", sc.Repo, sha, msg))
		}
	}

	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// OutputReport handles formatting and writing the report.
func OutputReport(r *Report, format string, outFile string) {
	var output string

	switch format {
	case "json":
		output = r.ToJSON()
	case "csv":
		if outFile != "" {
			f, err := os.Create(outFile)
			if err == nil {
				r.ToCSV(f)
				f.Close()
				fmt.Printf("Report written to %s\n", outFile)
				return
			}
		}
		r.ToCSV(os.Stdout)
		return
	case "md":
		output = r.ToMarkdown()
	default:
		output = r.SummaryText()
	}

	if outFile != "" {
		os.WriteFile(outFile, []byte(output), 0644)
		fmt.Printf("Report written to %s\n", outFile)
	} else {
		fmt.Println(output)
	}
}
