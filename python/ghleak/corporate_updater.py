#!/usr/bin/env python3
"""Corporate target updater — fetch Fortune 500 domains and cache locally."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import httpx

log = logging.getLogger("ghleak.updater")

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/gigasheetco/fortune-500-domains/"
    "main/fortune-500-domains.csv"
)
CACHE_FILE = Path(__file__).parent / "corporate_targets.json"

FREEMAIL_BLACKLIST = frozenset({
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "icloud.com", "aol.com", "mail.com", "protonmail.com", "proton.me",
})


def fetch_domains(url: str = DEFAULT_SOURCE_URL) -> set[str]:
    log.info("Fetching corporate domains from %s", url)
    domains: set[str] = set()

    try:
        resp = httpx.get(url, timeout=30, follow_redirects=True)
        resp.raise_for_status()

        for line in resp.text.splitlines():
            line = line.strip().lower()
            if not line or "domain" in line:
                continue
            matches = re.findall(
                r'\b([a-z0-9-]+\.[a-z]{2,}(?:\.[a-z]{2,})?)\b', line
            )
            for d in matches:
                if d not in FREEMAIL_BLACKLIST:
                    domains.add(d)

        log.info("Extracted %d unique domains", len(domains))
    except Exception as exc:
        log.error("Failed to fetch/parse domains: %s", exc)

    return domains


def update_cache() -> None:
    domains = fetch_domains()
    if not domains:
        log.warning("No domains fetched — preserving existing cache")
        return

    cache_data = {
        "source": DEFAULT_SOURCE_URL,
        "count": len(domains),
        "domains": sorted(domains),
    }
    CACHE_FILE.write_text(json.dumps(cache_data, indent=2))
    log.info("Wrote %d domains to %s", len(domains), CACHE_FILE)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    update_cache()
