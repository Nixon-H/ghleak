package cmd

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Nixon-H/ghleak/go/internal"
)

// RunUsage prints the cumulative LLM usage ledger.
func RunUsage(path string, asJSON bool) int {
	if path == "" {
		path = internal.DefaultUsagePath()
	}
	ledger := internal.LoadUsage(path)
	records := ledger.Snapshot()
	requests, errors, input, cached, output := ledger.Totals()

	if asJSON {
		payload := map[string]any{
			"path":    path,
			"records": records,
			"totals": map[string]any{
				"requests":      requests,
				"errors":        errors,
				"input_tokens":  input,
				"cached_tokens": cached,
				"output_tokens": output,
				"hit_rate_pct":  hitRate(input, cached),
			},
		}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return 1
		}
		fmt.Println(string(data))
		return 0
	}

	fmt.Print(internal.FormatUsage(records, [5]int64{requests, errors, input, cached, output}, path))
	return 0
}

func hitRate(input, cached int64) float64 {
	if input == 0 {
		return 0
	}
	return float64(cached) / float64(input) * 100
}

// RunProviders prints the provider preset table (endpoint/model/auth/cache).
func RunProviders() int {
	names := append([]string(nil), internal.LLMProviders...)
	sort.Strings(names)
	fmt.Printf("%-20s %-58s %-26s %s\n", "PROVIDER", "DEFAULT ENDPOINT", "DEFAULT MODEL", "AUTH / CACHE")
	for _, n := range names {
		p := internal.LLMProviderPresets[n]
		ep := p.Endpoint
		if ep == "" {
			ep = "(built from model+key, or required)"
		}
		model := p.Model
		if model == "" {
			model = "(required)"
		}
		fmt.Printf("%-20s %-58s %-26s %s\n", n, ep, model, internal.LLMProviderNotes[n])
	}
	return 0
}
