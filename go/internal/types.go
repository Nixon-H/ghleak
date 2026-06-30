package internal

import "sync"

// Classification result for a single commit/PR message.
type Classification string

const (
	Clean      Classification = "clean"
	Suspicious Classification = "suspicious"
	Ambiguous  Classification = "ambiguous"
)

// Event is a parsed GH Archive event (push or PR).
type Event struct {
	EventType string `json:"_event_type"`
	Repo      string `json:"repo"`
	Head      string `json:"head,omitempty"`
	Ref       string `json:"ref,omitempty"`
	Timestamp string `json:"ts,omitempty"`

	// PR-specific
	Title    string `json:"title,omitempty"`
	PRNumber int    `json:"pr_number,omitempty"`
	PRURL    string `json:"pr_url,omitempty"`
	Action   string `json:"action,omitempty"`
	IsPR     bool   `json:"_is_pr"`
}

// CommitInfo holds the resolved commit/PR data for classification.
type CommitInfo struct {
	SHA     string `json:"sha"`
	Message string `json:"message"`
	Repo    string `json:"repo"`
	Ref     string `json:"ref,omitempty"`
	TS      string `json:"ts,omitempty"`
	IsPR    bool   `json:"_is_pr"`
	PRURL   string `json:"pr_url,omitempty"`
}

// Finding from TruffleHog scan (maps to TruffleHogResult).
type Finding struct {
	DetectorName string `json:"detector_name"`
	DetectorType string `json:"detector_type"`
	Decoder      string `json:"decoder"`
	Verified     bool   `json:"verified"`
	Redacted     bool   `json:"redacted"`
	RawV2        string `json:"raw_v2"`
	Commit       string `json:"commit"`
	File         string `json:"file"`
	Email        string `json:"email"`
	Timestamp    string `json:"timestamp"`
	Repository   string `json:"repository"`
	Committer    string `json:"committer"`
}

func (f Finding) String() string {
	v := "unverified"
	if f.Verified {
		v = "VERIFIED"
	}
	short := f.Commit
	if len(short) > 12 {
		short = short[:12]
	}
	return "[" + v + "] " + f.DetectorName + " in " + f.File + " @ " + short
}

// SuspiciousCommit entry for the report.
type SuspiciousCommit struct {
	Repo    string `json:"repo"`
	SHA     string `json:"sha"`
	Message string `json:"message"`
	Result  string `json:"result"`
}

// Report holds the full scan results with thread-safe operations.
type Report struct {
	mu                sync.Mutex
	HoursScanned      int                `json:"hours_scanned"`
	CommitsSeen       int                `json:"commits_seen"`
	SuspiciousCommits []SuspiciousCommit `json:"suspicious_commits"`
	Findings          []Finding          `json:"findings"`
	VerifiedCount     int                `json:"verified_count"`
	ClassifierStats   map[string]int     `json:"classifier_stats"`
	Errors            []string           `json:"errors"`
	StartTime         string             `json:"start_time"`
	EndTime           string             `json:"end_time"`
}

// Enrichment metadata from corporate filter.
type Enrichment struct {
	IsCorporate  bool   `json:"is_corporate"`
	MatchedVia   string `json:"matched_via,omitempty"`
	MatchedValue string `json:"matched_value,omitempty"`
	OrgHandle    string `json:"org_handle,omitempty"`
}
