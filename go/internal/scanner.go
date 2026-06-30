package internal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// TruffleHogScanner wraps trufflehog for secret verification.
// Uses native Go engine when possible; subprocess CLI as fallback.
type TruffleHogScanner struct {
	OnlyVerified bool
	UseEngine    bool
	Binary       string
	FailOnError  bool
	ExtraArgs    []string
}

func NewTruffleHogScanner(onlyVerified bool) *TruffleHogScanner {
	return &TruffleHogScanner{OnlyVerified: onlyVerified, UseEngine: true, Binary: "trufflehog"}
}

// ScanDiff runs trufflehog against a raw diff string.
func (s *TruffleHogScanner) ScanDiff(diff string) []Finding {
	if diff == "" {
		return nil
	}

	if s.UseEngine {
		findings, err := s.scanEngine(diff)
		if err == nil {
			return findings
		}
		log.Printf("Engine unavailable (%v), falling back to subprocess", err)
	}
	return s.scanSubprocess(diff)
}

// scanGitPath scans a local git repository path with trufflehog git subcommand.
func (s *TruffleHogScanner) scanGitPath(path string) []Finding {
	if s.UseEngine {
		findings, err := s.scanGitEngine(path)
		if err == nil {
			return findings
		}
		log.Printf("Git engine unavailable (%v), falling back to subprocess", err)
	}

	cmd := exec.Command(s.Binary,
		"git", "file://.",
		"--since-commit", "HEAD",
		"--json", "--no-update",
	)
	if s.OnlyVerified {
		cmd.Args = append(cmd.Args, "--only-verified")
	}
	cmd.Args = append(cmd.Args, s.ExtraArgs...)
	cmd.Dir = path

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	output, err := cmd.Output()
	if err != nil && len(output) == 0 {
		if s.FailOnError {
			log.Fatalf("trufflehog git failed: %v\nstderr: %s", err, stderr.String())
		}
		log.Printf("trufflehog git stderr: %s", stderr.String())
		return nil
	}
	return parseTHJSON(string(output))
}

// scanCommitFromGH clones a GitHub repo (depth=1), checks out a specific SHA,
// and scans the checkout with trufflehog filesystem.
func (s *TruffleHogScanner) scanCommitFromGH(owner, repo, sha, tmpDir, token string) []Finding {
	cloneURL := fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
	if token != "" {
		cloneURL = fmt.Sprintf("https://x-access-token:%s@github.com/%s/%s.git", token, owner, repo)
	}

	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		log.Printf("failed to create tmp dir %s: %v", tmpDir, err)
		return nil
	}

	cloneCmd := exec.Command("git", "clone", "--depth", "1", "--single-branch", cloneURL, tmpDir)
	if out, err := cloneCmd.CombinedOutput(); err != nil {
		log.Printf("git clone failed: %v\n%s", err, string(out))
		return nil
	}

	fetchCmd := exec.Command("git", "-C", tmpDir, "fetch", "--depth", "1", "origin", sha)
	if out, err := fetchCmd.CombinedOutput(); err != nil {
		log.Printf("git fetch sha failed: %v\n%s", err, string(out))
		return nil
	}

	checkoutCmd := exec.Command("git", "-C", tmpDir, "checkout", sha)
	if out, err := checkoutCmd.CombinedOutput(); err != nil {
		log.Printf("git checkout failed: %v\n%s", err, string(out))
		return nil
	}

	return s.scanGitPath(tmpDir)
}

// summarizeFindings aggregates findings into a summary.
func summarizeFindings(findings []Finding) map[string]any {
	detectorCounts := map[string]int{}
	verifiedCount := 0
	fileSet := map[string]struct{}{}
	emailSet := map[string]struct{}{}
	repoSet := map[string]struct{}{}

	for _, f := range findings {
		detectorCounts[f.DetectorName]++
		if f.Verified {
			verifiedCount++
		}
		if f.File != "" {
			fileSet[f.File] = struct{}{}
		}
		if f.Email != "" {
			emailSet[f.Email] = struct{}{}
		}
		if f.Repository != "" {
			repoSet[f.Repository] = struct{}{}
		}
	}

	uniqueRepos := make([]string, 0, len(repoSet))
	for r := range repoSet {
		uniqueRepos = append(uniqueRepos, r)
	}
	sort.Strings(uniqueRepos)

	return map[string]any{
		"total_findings": len(findings),
		"verified_count": verifiedCount,
		"detectors":      detectorCounts,
		"unique_files":   len(fileSet),
		"unique_emails":  len(emailSet),
		"unique_repos":   uniqueRepos,
	}
}

// ── Native engine path ─────────────────────────────────────────────

func (s *TruffleHogScanner) scanEngine(diff string) ([]Finding, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultsCh := make(chan detectors.ResultWithMetadata, 200)

	eng, err := engine.NewEngine(ctx, &engine.Config{
		Concurrency:   4,
		Verify:        s.OnlyVerified,
		SourceManager: sources.NewManager(),
		Dispatcher:    &dispatcherCollector{ch: resultsCh},
	})
	if err != nil {
		return nil, fmt.Errorf("engine init: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		eng.Start(ctx)
	}()

	eng.ScanChunk(&sources.Chunk{
		Data:       []byte(diff),
		SourceType: sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM,
		SourceName: "ghleak",
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Filesystem{
				Filesystem: &source_metadatapb.Filesystem{File: "diff"},
			},
		},
		SourceVerify: s.OnlyVerified,
	})

	if err := eng.Finish(ctx); err != nil {
		log.Printf("engine finish err: %v", err)
	}
	close(resultsCh)
	wg.Wait()

	var findings []Finding
	for r := range resultsCh {
		f := Finding{
			DetectorName: r.DetectorName,
			DetectorType: r.DetectorType.String(),
			Decoder:      r.DecoderType.String(),
			Verified:     r.Verified,
			Redacted:     r.Redacted != "",
			RawV2:        string(r.RawV2),
		}
		if meta := r.SourceMetadata.GetFilesystem(); meta != nil {
			f.File = meta.GetFile()
		}
		if meta := r.SourceMetadata.GetGit(); meta != nil {
			f.File = meta.GetFile()
			f.Commit = meta.GetCommit()
			f.Email = meta.GetEmail()
			f.Timestamp = meta.GetTimestamp()
			f.Repository = meta.GetRepository()
		}
		findings = append(findings, f)
	}
	return findings, nil
}

type dispatcherCollector struct {
	ch chan detectors.ResultWithMetadata
}

func (d *dispatcherCollector) Dispatch(ctx context.Context, result detectors.ResultWithMetadata) error {
	d.ch <- result
	return nil
}

// scanGitEngine uses the native Go engine to scan a local git repository.
func (s *TruffleHogScanner) scanGitEngine(path string) ([]Finding, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultsCh := make(chan detectors.ResultWithMetadata, 200)

	eng, err := engine.NewEngine(ctx, &engine.Config{
		Concurrency:   4,
		Verify:        s.OnlyVerified,
		SourceManager: sources.NewManager(),
		Dispatcher:    &dispatcherCollector{ch: resultsCh},
	})
	if err != nil {
		return nil, fmt.Errorf("engine init: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		eng.Start(ctx)
	}()

	if _, err := eng.ScanGit(ctx, sources.GitConfig{
		URI: fmt.Sprintf("file://.%s%s", string(os.PathSeparator), path),
	}); err != nil {
		return nil, fmt.Errorf("engine git scan: %w", err)
	}

	if err := eng.Finish(ctx); err != nil {
		log.Printf("engine finish err: %v", err)
	}
	close(resultsCh)
	wg.Wait()

	var findings []Finding
	for r := range resultsCh {
		f := Finding{
			DetectorName: r.DetectorName,
			DetectorType: r.DetectorType.String(),
			Decoder:      r.DecoderType.String(),
			Verified:     r.Verified,
			Redacted:     r.Redacted != "",
			RawV2:        string(r.RawV2),
		}
		if meta := r.SourceMetadata.GetFilesystem(); meta != nil {
			f.File = meta.GetFile()
		}
		if meta := r.SourceMetadata.GetGit(); meta != nil {
			f.File = meta.GetFile()
			f.Commit = meta.GetCommit()
			f.Email = meta.GetEmail()
			f.Timestamp = meta.GetTimestamp()
			f.Repository = meta.GetRepository()
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ── Subprocess path ────────────────────────────────────────────────

func (s *TruffleHogScanner) scanSubprocess(diff string) []Finding {
	cmd := exec.Command(s.Binary,
		"filesystem", "--no-update", "--json",
	)
	if s.OnlyVerified {
		cmd.Args = append(cmd.Args, "--only-verified")
	}
	cmd.Args = append(cmd.Args, s.ExtraArgs...)
	cmd.Args = append(cmd.Args, "-")
	cmd.Stdin = bytes.NewReader([]byte(diff))

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	output, err := cmd.Output()
	if err != nil && len(output) == 0 {
		if s.FailOnError {
			log.Fatalf("trufflehog subprocess failed: %v\nstderr: %s", err, stderr.String())
		}
		log.Printf("trufflehog stderr: %s", stderr.String())
		return nil
	}
	return parseTHJSON(string(output))
}

func parseTHJSON(raw string) []Finding {
	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var data map[string]any
		if err := json.Unmarshal([]byte(line), &data); err != nil {
			continue
		}

		f := Finding{}

		if v, ok := data["DetectorName"].(string); ok {
			f.DetectorName = v
		}
		f.DetectorType = fmt.Sprintf("%v", data["DetectorType"])
		if v, ok := data["DecoderName"].(string); ok {
			f.Decoder = v
		}
		if v, ok := data["Verified"].(bool); ok {
			f.Verified = v
		}
		if v, ok := data["Redacted"].(bool); ok {
			f.Redacted = v
		}

		// RawV2 from Data.RawV2 or top-level RawV2
		if rd, ok := data["Data"].(map[string]any); ok {
			if rv2, ok := rd["RawV2"].(string); ok {
				f.RawV2 = rv2
			}
		} else if rv2, ok := data["RawV2"].(string); ok {
			f.RawV2 = rv2
		}

		// SourceMetadata — support both with and without Data wrapper
		if sm, ok := data["SourceMetadata"].(map[string]any); ok {
			var gitData, fsData map[string]any
			if d, ok := sm["Data"].(map[string]any); ok {
				gitData, _ = d["git"].(map[string]any)
				fsData, _ = d["filesystem"].(map[string]any)
			}
			if gitData == nil {
				gitData, _ = sm["git"].(map[string]any)
			}
			if fsData == nil {
				fsData, _ = sm["filesystem"].(map[string]any)
			}

			if fsData != nil {
				if file, ok := fsData["file"].(string); ok {
					f.File = file
				}
			}
			if gitData != nil {
				if file, ok := gitData["file"].(string); ok {
					f.File = file
				}
				if commit, ok := gitData["commit"].(string); ok {
					f.Commit = commit
				}
				if email, ok := gitData["email"].(string); ok {
					f.Email = email
				}
				if ts, ok := gitData["timestamp"].(string); ok {
					f.Timestamp = ts
				}
				if repo, ok := gitData["repository"].(string); ok {
					f.Repository = repo
				}
				if committer, ok := gitData["committer"].(string); ok {
					f.Committer = committer
				}
			}
		}

		findings = append(findings, f)
	}
	return findings
}
