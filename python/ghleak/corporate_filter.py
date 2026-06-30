"""Corporate target attribution filter — O(1) hash-set lookups against Fortune 500 / big tech."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Set, Tuple

log = logging.getLogger("ghleak.corporate")


class CorporateTargetFilter:
    def __init__(self, enterprise_only: bool = False):
        self.enterprise_only = enterprise_only
        self.cache_file = Path(__file__).parent / "corporate_targets.json"

        self.target_domains: Set[str] = {
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

        self.target_orgs: Set[str] = {
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

        self._load_dynamic_cache()

    def _load_dynamic_cache(self) -> None:
        if not self.cache_file.exists():
            return
        try:
            data = json.loads(self.cache_file.read_text())
            fetched = set(data.get("domains", []))
            if fetched:
                self.target_domains.update(fetched)
                log.info("Loaded %d additional domains from cache", len(fetched))
        except Exception:
            pass

    def _extract_domain(self, email: str) -> str:
        if not email or "@" not in email:
            return ""
        return email.strip().split("@")[-1].lower()

    def analyze_event(self, event: dict[str, Any]) -> tuple[bool, str, dict[str, Any]]:
        """Check if a raw GH Archive event targets an enterprise.

        Returns (passes_filter, match_label, enrichment_metadata).
        """
        repo_name = event.get("repo", {}).get("name", "")
        if "/" not in repo_name:
            return (not self.enterprise_only), "unknown", {}

        org_handle, _ = repo_name.split("/", 1)
        org_handle_lower = org_handle.lower()

        metadata: dict[str, Any] = {
            "is_corporate": False,
            "matched_via": None,
            "matched_value": None,
            "org_handle": org_handle,
        }

        if org_handle_lower in self.target_orgs:
            metadata["is_corporate"] = True
            metadata["matched_via"] = "org_handle"
            metadata["matched_value"] = org_handle
            return True, f"Org: {org_handle}", metadata

        payload = event.get("payload", {})
        for commit in payload.get("commits", []):
            for field in ("author", "committer"):
                email = commit.get(field, {}).get("email", "")
                domain = self._extract_domain(email)
                if domain in self.target_domains:
                    metadata["is_corporate"] = True
                    metadata["matched_via"] = f"{field}_domain"
                    metadata["matched_value"] = domain
                    return True, f"Domain: {domain}", metadata

        if self.enterprise_only:
            return False, "non-enterprise", metadata
        return True, "general-stream", metadata
