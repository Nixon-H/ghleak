#!/usr/bin/env python3
"""Test the ghleak pipeline end-to-end with a small sample."""

import logging
import random
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)

from ghleak.fetcher import fetch_archive, archive_hour_url, extract_pushevents, find_latest_archive_hour
from ghleak.classifier import CommitClassifier

# Find latest available hour
latest = find_latest_archive_hour()
print(f"Latest archive hour: {latest}")

if not latest:
    print("No archive data available")
    sys.exit(1)

# Download one hour
url = archive_hour_url(latest)
print(f"Fetching: {url}")
events = fetch_archive(url)
print(f"Got {len(events)} events")

# Extract PushEvents
pushes = extract_pushevents(events)
print(f"Got {len(pushes)} PushEvents")

# Test classifier
classifier = CommitClassifier()
suspicious_found = 0
for pe in pushes[:5000]:
    # We can't resolve messages without API, but we can test the flow
    # Just simulate with the ref name
    msg = pe.get("ref", "")
    result = classifier.classify(msg)
    if result == "suspicious":
        suspicious_found += 1

print(f"Suspicious (from ref names in 5000 sample): {suspicious_found}")
print(f"Classifier stats: {classifier.stats()}")

# Test known patterns
print("\n--- Known pattern tests ---")
test_msgs = [
    "remove leaked api key",
    "fix: expose secret token",
    "revoke aws credentials",
    "update readme",
    "fix keyboard shortcut",
    "remove hard coded api key from config",
    "security fix: remove hardcoded credentials",
    "rotate database password",
    "chore: clean up env file",
    "replace actual api key placeholder",
    "this is not a real key",
    "credentials leak fixed",
    "add new feature",
]
for msg in test_msgs:
    result = classifier.classify(msg)
    print(f"  {'⚠' if result == 'suspicious' else ' '}  {result:>12}: {msg}")

print(f"\nFinal classifier stats: {classifier.stats()}")
print("\nPipeline test: OK")
