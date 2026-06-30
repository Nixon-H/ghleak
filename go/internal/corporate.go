package internal

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type CorporateTargetFilter struct {
	EnterpriseOnly bool
	targetDomains  map[string]bool
	targetOrgs     map[string]bool
}

func NewCorporateTargetFilter(enterpriseOnly bool) *CorporateTargetFilter {
	f := &CorporateTargetFilter{
		EnterpriseOnly: enterpriseOnly,
		targetDomains:  make(map[string]bool),
		targetOrgs:     make(map[string]bool),
	}
	for _, d := range baselineDomains() {
		f.targetDomains[d] = true
	}
	for _, o := range baselineOrgs() {
		f.targetOrgs[o] = true
	}
	f.loadCache()
	return f
}

func baselineDomains() []string {
	return []string{
		"google.com", "microsoft.com", "amazon.com", "amzn.com", "apple.com",
		"meta.com", "fb.com", "netflix.com", "oracle.com", "salesforce.com",
		"ibm.com", "cisco.com", "intel.com", "amd.com", "nvidia.com",
		"adobe.com", "vmware.com", "sap.com", "hpe.com", "hp.com",
		"cloudflare.com", "fastly.com", "akamai.com", "datadoghq.com", "dynatrace.com",
		"atlassian.com", "github.com", "gitlab.com", "hashicorp.com", "redhat.com",
		"suse.com", "canonical.com", "digitalocean.com", "linode.com",
		"openai.com", "anthropic.com", "cohere.com", "huggingface.co", "snowflake.com",
		"databricks.com", "confluent.io", "elastic.co", "mongodb.com", "redis.com",
		"jpmorganchase.com", "jpmc.com", "goldmansachs.com", "morganstanley.com",
		"bankofamerica.com", "bofa.com", "citigroup.com", "citi.com", "wellsfargo.com",
		"stripe.com", "paypal.com", "squareups.com", "block.xyz", "visa.com", "mastercard.com",
		"att.com", "verizon.com", "t-mobile.com", "vodafone.com", "uber.com", "lyft.com",
		"lockheedmartin.com", "boeing.com", "raytheon.com", "rtx.com", "ge.com", "siemens.com",
	}
}

func baselineOrgs() []string {
	return []string{
		"google", "googlecloudplatform", "googlesamples", "firebase",
		"microsoft", "microsoftresearch", "azure", "azure-samples",
		"amzn", "awslabs", "aws", "aws-samples",
		"apple", "swiftlang",
		"facebook", "facebookresearch", "meta", "meta-llama",
		"netflix", "netflixoss",
		"oracle", "graalvm",
		"salesforce", "forcedotcom",
		"ibm", "open-power",
		"cisco", "ciscodevnet",
		"intel", "openvinotoolkit",
		"amd", "rocmsoftwareplatform",
		"nvidia", "nv-mira",
		"adobe",
		"vmware", "spring-projects",
		"hashicorp",
		"redhat", "redhat-developer", "ansible",
		"cloudflare",
		"datadog",
		"atlassian",
		"elastic",
		"mongodb",
		"stripe",
		"paypal",
		"uber",
		"airbnb",
		"spotify",
	}
}

func (f *CorporateTargetFilter) loadCache() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cacheFile := filepath.Join(filepath.Dir(exe), "corporate_targets.json")
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return
	}
	var cached struct {
		Domains []string `json:"domains"`
	}
	if json.Unmarshal(data, &cached) != nil {
		return
	}
	for _, d := range cached.Domains {
		f.targetDomains[d] = true
	}
	log.Printf("Loaded %d additional domains from cache", len(cached.Domains))
}

func (f *CorporateTargetFilter) extractDomain(email string) string {
	if email == "" || !strings.Contains(email, "@") {
		return ""
	}
	parts := strings.SplitN(email, "@", 2)
	return strings.ToLower(strings.TrimSpace(parts[1]))
}

func (f *CorporateTargetFilter) AnalyzeEvent(event map[string]interface{}) (bool, string, map[string]interface{}) {
	repoRaw, _ := event["repo"].(map[string]interface{})
	repoName := getString(repoRaw, "name")

	if !strings.Contains(repoName, "/") {
		return !f.EnterpriseOnly, "unknown", nil
	}

	parts := strings.SplitN(repoName, "/", 2)
	orgHandle := strings.ToLower(parts[0])

	meta := map[string]interface{}{
		"is_corporate": false,
		"matched_via":  nil,
		"matched_value": nil,
		"org_handle":   orgHandle,
	}

	// Check org handle
	if f.targetOrgs[orgHandle] {
		meta["is_corporate"] = true
		meta["matched_via"] = "org_handle"
		meta["matched_value"] = orgHandle
		return true, "Org: " + orgHandle, meta
	}

	// Check commit author/committer emails
	payload, _ := event["payload"].(map[string]interface{})
	commits, _ := payload["commits"].([]interface{})
	for _, c := range commits {
		cm, _ := c.(map[string]interface{})
		if cm == nil {
			continue
		}
		for _, field := range []string{"author", "committer"} {
			person, _ := cm[field].(map[string]interface{})
			email := getString(person, "email")
			domain := f.extractDomain(email)
			if domain != "" && f.targetDomains[domain] {
				meta["is_corporate"] = true
				meta["matched_via"] = field + "_domain"
				meta["matched_value"] = domain
				return true, "Domain: " + domain, meta
			}
		}
	}

	if f.EnterpriseOnly {
		return false, "non-enterprise", meta
	}
	return true, "general-stream", meta
}
