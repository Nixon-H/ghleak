package internal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	DefaultCorporateSourceURL = "https://raw.githubusercontent.com/gigasheetco/fortune-500-domains/main/fortune-500-domains.csv"
)

var freemailBlacklist = map[string]bool{
	"gmail.com": true, "yahoo.com": true, "hotmail.com": true,
	"outlook.com": true, "icloud.com": true, "aol.com": true,
	"mail.com": true, "protonmail.com": true, "proton.me": true,
}

var domainRe = regexp.MustCompile(`\b([a-z0-9-]+\.[a-z]{2,}(?:\.[a-z]{2,})?)\b`)

func FetchCorporateDomains(url string) ([]string, error) {
	if url == "" {
		url = DefaultCorporateSourceURL
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if line == "" || strings.Contains(line, "domain") {
			continue
		}
		for _, match := range domainRe.FindAllString(line, -1) {
			if !freemailBlacklist[match] && !seen[match] {
				seen[match] = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	domains := make([]string, 0, len(seen))
	for d := range seen {
		domains = append(domains, d)
	}
	log.Printf("Fetched %d unique corporate domains", len(domains))
	return domains, nil
}

func UpdateCorporateCache(cachePath string) error {
	domains, err := FetchCorporateDomains(DefaultCorporateSourceURL)
	if err != nil {
		return fmt.Errorf("fetch domains: %w", err)
	}
	if len(domains) == 0 {
		return fmt.Errorf("no domains fetched — preserving existing cache")
	}

	sorted := make([]string, len(domains))
	copy(sorted, domains)
	sortStrings(sorted)

	cache := map[string]interface{}{
		"source":  DefaultCorporateSourceURL,
		"count":   len(sorted),
		"domains": sorted,
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(cachePath, data, 0644); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	log.Printf("Wrote %d domains to %s", len(sorted), cachePath)
	return nil
}

func DefaultCorporateCachePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "corporate_targets.json"
	}
	return filepath.Join(filepath.Dir(exe), "corporate_targets.json")
}

func sortStrings(s []string) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[i] > s[j] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}
