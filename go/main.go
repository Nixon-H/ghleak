package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"github.com/nixon/ghleak/go/cmd"

	"github.com/nixon/ghleak/go/internal"
)

func main() {
	fs := flag.NewFlagSet("ghleak", flag.ExitOnError)

	debug := fs.Bool("debug", false, "Enable debug logging")
	enterpriseOnly := fs.Bool("enterprise-only", false, "Only process Fortune 500 / big-tech targets")

	gitHubToken := fs.String("github-token", "", "Git forge API token (env: GITHUB_TOKEN, GH_TOKEN)")
	token := fs.String("token", "", "Alias for --github-token")
	gitAPIBase := fs.String("git-api-base", "", "Custom git forge API base URL (env: GIT_API_BASE)")
	forgeType := fs.String("forge-type", "", "Forge type: "+strings.Join(internal.ForgeTypes, ", ")+" (env: FORGE_TYPE)")

	llmProvider := fs.String("llm-provider", "", "LLM provider: "+strings.Join(internal.LLMProviders, ", ")+" (env: LLM_PROVIDER)")
	llmEndpoint := fs.String("llm-endpoint", "", "LLM API endpoint (env: LLM_ENDPOINT)")
	llmKey := fs.String("llm-key", "", "LLM API key (env: LLM_API_KEY, LLM_KEY)")
	llmModel := fs.String("llm-model", "", "LLM model name (env: LLM_MODEL)")

	// Parse global flags (stops at first non-flag arg = subcommand)
	fs.Parse(os.Args[1:])
	args := fs.Args()
	if len(args) < 1 {
		printUsage(fs)
		os.Exit(1)
	}

	subcommand := args[0]
	subArgs := args[1:]

	if *debug {
		log.SetFlags(log.Ltime | log.Lmicroseconds)
	}

	// ── Resolve values with env var fallbacks ──

	// GitHub token: flag > --token > GITHUB_TOKEN > GH_TOKEN
	gitHubTokenVal := *gitHubToken
	if gitHubTokenVal == "" {
		gitHubTokenVal = *token
	}
	if gitHubTokenVal == "" {
		gitHubTokenVal = os.Getenv("GITHUB_TOKEN")
	}
	if gitHubTokenVal == "" {
		gitHubTokenVal = os.Getenv("GH_TOKEN")
	}

	// Forge type: flag > FORGE_TYPE > "github"
	forgeTypeVal := *forgeType
	if forgeTypeVal == "" {
		forgeTypeVal = getEnv("FORGE_TYPE", "github")
	}

	// Git API base: flag > GIT_API_BASE > ""
	gitAPIBaseVal := *gitAPIBase
	if gitAPIBaseVal == "" {
		gitAPIBaseVal = os.Getenv("GIT_API_BASE")
	}

	// LLM key: flag > LLM_API_KEY > LLM_KEY
	llmKeyVal := *llmKey
	if llmKeyVal == "" {
		llmKeyVal = os.Getenv("LLM_API_KEY")
	}
	if llmKeyVal == "" {
		llmKeyVal = os.Getenv("LLM_KEY")
	}

	// LLM provider: flag > LLM_PROVIDER > auto-detect from key > ""
	llmProviderVal := *llmProvider
	if llmProviderVal == "" {
		llmProviderVal = os.Getenv("LLM_PROVIDER")
	}
	if llmProviderVal == "" && llmKeyVal != "" {
		llmProviderVal = internal.DetectLLMProvider(llmKeyVal)
	}

	// LLM endpoint: flag > LLM_ENDPOINT > ""
	llmEndpointVal := *llmEndpoint
	if llmEndpointVal == "" {
		llmEndpointVal = os.Getenv("LLM_ENDPOINT")
	}

	// LLM model: flag > LLM_MODEL > ""
	llmModelVal := *llmModel
	if llmModelVal == "" {
		llmModelVal = os.Getenv("LLM_MODEL")
	}

	switch subcommand {
	case "scan":
		scanFS := flag.NewFlagSet("scan", flag.ExitOnError)
		hours := scanFS.Int("hours", 2, "Hours to look back")
		sample := scanFS.Float64("sample", 1.0, "Sample fraction (0.0-1.0)")
		skipDiffs := scanFS.Bool("skip-diffs", false, "Skip diff fetching (classification only)")
		onlyVerified := scanFS.Bool("only-verified", true, "Only report verified secrets")
		maxCommits := scanFS.Int("max-commits", 0, "Stop after N suspicious commits")
		output := scanFS.String("output", "text", "Output format: text, json, csv, md")
		outputFile := scanFS.String("output-file", "", "Write output to file")

		scanFS.Parse(subArgs)

		os.Exit(cmd.Scan(cmd.ScanConfig{
			Hours:          *hours,
			Sample:         *sample,
			SkipDiffs:      *skipDiffs,
			OnlyVerified:   *onlyVerified,
			MaxCommits:     *maxCommits,
			EnterpriseOnly: *enterpriseOnly,
			OutputFormat:   *output,
			OutputFile:     *outputFile,
			Debug:          *debug,
			LLMProvider:    llmProviderVal,
			LLMEndpoint:    llmEndpointVal,
			LLMKey:         llmKeyVal,
			LLMModel:       llmModelVal,
			GitHubToken:    gitHubTokenVal,
			GitAPIBase:     gitAPIBaseVal,
			ForgeType:      forgeTypeVal,
		}))

	case "monitor":
		monFS := flag.NewFlagSet("monitor", flag.ExitOnError)
		interval := monFS.Int("interval", 60, "Poll interval in minutes")
		output := monFS.String("output", "text", "Output format: text, json, csv, md")
		outputFile := monFS.String("output-file", "", "Write output to file")

		monFS.Parse(subArgs)

		os.Exit(cmd.Monitor(cmd.ScanConfig{
			Hours:                  1,
			EnterpriseOnly:         *enterpriseOnly,
			OutputFormat:           *output,
			OutputFile:             *outputFile,
			Debug:                  *debug,
			LLMProvider:            llmProviderVal,
			LLMEndpoint:            llmEndpointVal,
			LLMKey:                 llmKeyVal,
			LLMModel:               llmModelVal,
			GitHubToken:            gitHubTokenVal,
			GitAPIBase:             gitAPIBaseVal,
			ForgeType:              forgeTypeVal,
			MonitorIntervalMinutes: *interval,
		}))

	case "commit":
		if len(subArgs) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: ghleak commit <owner/repo> <sha>\n")
			os.Exit(1)
		}
		repo := subArgs[0]
		sha := subArgs[1]

		parts := strings.SplitN(repo, "/", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Invalid repo format: %s (expected owner/repo)\n", repo)
			os.Exit(1)
		}

		gh := internal.NewGitAPIClient(gitHubTokenVal, gitAPIBaseVal, forgeTypeVal)
		scanner := internal.NewTruffleHogScanner(false)
		report := internal.NewReport()
		report.CommitsSeen = 1

		diff, err := gh.FetchDiff(parts[0], parts[1], sha)
		if err != nil {
			log.Fatalf("Could not fetch diff: %v", err)
		}
		for _, f := range scanner.ScanDiff(diff) {
			report.AddFinding(f)
			if f.Verified {
				log.Printf("VERIFIED: [%s] %s — %s", f.DetectorName, f.File, shortSHA(sha))
			}
		}
		report.HoursScanned = 1
		gh.Close()
		report.Finish()
		internal.OutputReport(report, "text", "")

	case "update-corporate":
		cachePath := internal.DefaultCorporateCachePath()
		if err := internal.UpdateCorporateCache(cachePath); err != nil {
			log.Fatalf("Failed to update corporate cache: %v", err)
		}
		fmt.Printf("Corporate targets cache updated at %s\n", cachePath)

	case "url":
		if len(subArgs) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: ghleak url <git-url> <sha>\n")
			os.Exit(1)
		}
		repoURL := subArgs[0]
		sha := subArgs[1]

		scanner := internal.NewTruffleHogScanner(false)
		report := internal.NewReport()
		report.CommitsSeen = 1

		diff, err := internal.FetchDiffFromURL(repoURL, sha, gitHubTokenVal)
		if err != nil {
			log.Fatalf("Could not fetch diff: %v", err)
		}
		for _, f := range scanner.ScanDiff(diff) {
			report.AddFinding(f)
			if f.Verified {
				log.Printf("VERIFIED: [%s] %s — %s", f.DetectorName, f.File, shortSHA(sha))
			}
		}
		report.HoursScanned = 1
		report.Finish()
		internal.OutputReport(report, "text", "")

	default:
		printUsage(fs)
		os.Exit(1)
	}
}

func printUsage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `ghleak — Multi-forge secret leak scanner (Go port)

Usage:
  ghleak [global flags] scan [flags]
  ghleak [global flags] monitor [flags]
  ghleak commit <owner/repo> <sha>
  ghleak url <git-url> <sha>
  ghleak update-corporate

Global flags:
`)
	fs.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Commands:
  scan              Scan recent GH Archive hours
  monitor           Continuous monitoring mode (polls hourly)
  commit            Scan a specific commit from a forge
  url               Scan from any git forge URL
  update-corporate  Fetch Fortune 500 domains and cache locally

Examples:
  ghleak scan
  ghleak --enterprise-only scan --hours 4
  ghleak --llm-key sk-... scan
  ghleak commit google/test-repo abc123
  ghleak url https://github.com/owner/repo.git abc123
`)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
