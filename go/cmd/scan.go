package cmd

import (
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/nixon/ghleak/go/internal"
)

// ScanConfig holds parameters for scan/monitor commands.
type ScanConfig struct {
	Hours          int
	Sample         float64
	SkipDiffs      bool
	OnlyVerified   bool
	MaxCommits     int
	EnterpriseOnly bool
	OutputFormat   string
	OutputFile     string
	Debug          bool

	LLMProvider string
	LLMEndpoint string
	LLMKey      string
	LLMModel    string

	GitHubToken string
	GitAPIBase  string
	ForgeType   string

	MonitorIntervalMinutes int
}

type suspiciousJob struct {
	commit internal.CommitInfo
	idx    int
}

// RunScan executes the historical GH Archive scan with concurrent diff fetching.
func RunScan(cfg ScanConfig) int {
	report := internal.NewReport()

	llm := initLLM(cfg.LLMProvider, cfg.LLMEndpoint, cfg.LLMKey, cfg.LLMModel)
	classifier := internal.NewBatchClassifier(llm)
	scanner := internal.NewTruffleHogScanner(cfg.OnlyVerified)
	gh := internal.NewGitAPIClient(cfg.GitHubToken, cfg.GitAPIBase, cfg.ForgeType)

	var entFilter *internal.CorporateTargetFilter
	if cfg.EnterpriseOnly {
		entFilter = internal.NewCorporateTargetFilter(true)
		log.Println("Enterprise-only mode — filtering to Fortune 500 / big-tech")
	}

	log.Printf("Scanning last %d hour(s) of GH Archive...", cfg.Hours)
	totalPushes := 0

	for events := range internal.StreamHours(cfg.Hours, entFilter) {
		report.IncHoursScanned()

		if cfg.Sample < 1.0 && len(events) > 0 {
			sampled := make([]internal.Event, 0, len(events))
			for _, e := range events {
				if rand.Float64() < cfg.Sample {
					sampled = append(sampled, e)
				}
			}
			events = sampled
			if cfg.Debug {
				log.Printf("  Sampled %d events (sample=%.2f)", len(events), cfg.Sample)
			}
		}

		totalPushes += len(events)
		log.Printf("Resolving %d events concurrently...", len(events))

		commits := internal.ResolveCommitMessagesConcurrent(events, gh, 20)

		messages := make([]string, len(commits))
		for i, c := range commits {
			messages[i] = c.Message
		}

		classifications := classifier.ClassifyBatch(messages)

		var suspicious []suspiciousJob
		for i, commit := range commits {
			report.IncCommitsSeen()
			if classifications[i] != internal.Suspicious {
				if cfg.Debug {
					log.Printf("  CLEAN: %s @ %s — %s", commit.Repo, shortSHA(commit.SHA), truncate(commit.Message, 80))
				}
				continue
			}
			report.AddSuspicious(commit.Repo, commit.SHA, commit.Message, string(classifications[i]))
			if cfg.Debug {
				log.Printf("  SUSPICIOUS: %s @ %s — %s", commit.Repo, shortSHA(commit.SHA), truncate(commit.Message, 100))
			} else {
				log.Printf("  SUSPICIOUS: %s @ %s", commit.Repo, shortSHA(commit.SHA))
			}
			suspicious = append(suspicious, suspiciousJob{commit: commit, idx: i})
		}

		if !cfg.SkipDiffs && len(suspicious) > 0 {
			results := internal.RunWorkerPool(suspicious, func(job suspiciousJob) []internal.Finding {
				if cfg.Debug {
					log.Printf("  Fetching diff for %s @ %s", job.commit.Repo, shortSHA(job.commit.SHA))
				}
				parts := strings.SplitN(job.commit.Repo, "/", 2)
				if len(parts) != 2 {
					return nil
				}
				diff, err := gh.FetchDiff(parts[0], parts[1], job.commit.SHA)
				if err != nil || diff == "" {
					if cfg.Debug {
						log.Printf("  Diff fetch failed for %s @ %s: %v", job.commit.Repo, shortSHA(job.commit.SHA), err)
					}
					return nil
				}
				return scanner.ScanDiff(diff)
			}, 20)

			for i, findings := range results {
				for _, f := range findings {
					report.AddFinding(f)
					if f.Verified {
						c := suspicious[i].commit
						log.Printf("  VERIFIED: [%s] %s in %s", f.DetectorName, c.Repo, f.File)
					}
				}
			}
		}

		if cfg.MaxCommits > 0 && len(report.SuspiciousCommits) >= cfg.MaxCommits {
			log.Printf("Reached max-commits limit (%d)", cfg.MaxCommits)
			break
		}
	}

	report.ClassifierStats = classifier.Stats()
	gh.Close()
	report.Finish()

	log.Printf("Summary: %d hours, %d events, %d resolved, %d suspicious, %d verified",
		report.HoursScanned, totalPushes, report.CommitsSeen,
		len(report.SuspiciousCommits), report.VerifiedCount)

	internal.OutputReport(report, cfg.OutputFormat, cfg.OutputFile)
	return 0
}

// RunMonitor executes continuous monitoring with concurrent processing.
func RunMonitor(cfg ScanConfig) int {
	interval := cfg.MonitorIntervalMinutes
	if interval < 1 {
		interval = 60
	}
	log.Printf("Starting monitor (interval=%d min)", interval)
	llm := initLLM(cfg.LLMProvider, cfg.LLMEndpoint, cfg.LLMKey, cfg.LLMModel)

	var entFilter *internal.CorporateTargetFilter
	if cfg.EnterpriseOnly {
		entFilter = internal.NewCorporateTargetFilter(true)
	}

	runCount := 0
	for {
		runCount++
		log.Printf("Monitor cycle #%d", runCount)
		report := internal.NewReport()
		classifier := internal.NewBatchClassifier(llm)
		scanner := internal.NewTruffleHogScanner(false)
		gh := internal.NewGitAPIClient(cfg.GitHubToken, cfg.GitAPIBase, cfg.ForgeType)

		for events := range internal.StreamHours(1, entFilter) {
			report.IncHoursScanned()
			commits := internal.ResolveCommitMessagesConcurrent(events, gh, 20)

			messages := make([]string, len(commits))
			for i, c := range commits {
				messages[i] = c.Message
			}

			classifications := classifier.ClassifyBatch(messages)

			var suspicious []suspiciousJob
			for i, commit := range commits {
				report.IncCommitsSeen()
				if classifications[i] != internal.Suspicious {
					continue
				}
				report.AddSuspicious(commit.Repo, commit.SHA, commit.Message, string(classifications[i]))
				if cfg.Debug {
					log.Printf("  SUSPICIOUS: %s @ %s — %s", commit.Repo, shortSHA(commit.SHA), truncate(commit.Message, 100))
				}
				suspicious = append(suspicious, suspiciousJob{commit: commit, idx: i})
			}

			if len(suspicious) > 0 {
				results := internal.RunWorkerPool(suspicious, func(job suspiciousJob) []internal.Finding {
					if cfg.Debug {
						log.Printf("  Fetching diff for %s @ %s", job.commit.Repo, shortSHA(job.commit.SHA))
					}
					parts := strings.SplitN(job.commit.Repo, "/", 2)
					if len(parts) != 2 {
						return nil
					}
					diff, err := gh.FetchDiff(parts[0], parts[1], job.commit.SHA)
					if err != nil || diff == "" {
						return nil
					}
					return scanner.ScanDiff(diff)
				}, 20)

				for i, findings := range results {
					for _, f := range findings {
						report.AddFinding(f)
						if f.Verified {
							c := suspicious[i].commit
							log.Printf("  LIVE SECRET: [%s] %s @ %s -- %s",
								f.DetectorName, c.Repo, shortSHA(c.SHA), f.File)
						}
					}
				}
			}
		}

		report.ClassifierStats = classifier.Stats()
		gh.Close()
		report.Finish()

		if report.VerifiedCount > 0 {
			log.Printf("Cycle #%d: %d verified secrets found!", runCount, report.VerifiedCount)
			internal.OutputReport(report, cfg.OutputFormat, cfg.OutputFile)
		}

		log.Printf("Sleeping %d min...", interval)
		time.Sleep(time.Duration(interval) * time.Minute)
	}
}

func initLLM(provider, endpoint, apiKey, model string) internal.LLMBackend {
	if provider == "" {
		return nil
	}
	return internal.BuildLLMBackend(provider, endpoint, apiKey, model)
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func Scan(cfg ScanConfig) int {
	return RunScan(cfg)
}

func Monitor(cfg ScanConfig) int {
	return RunMonitor(cfg)
}
