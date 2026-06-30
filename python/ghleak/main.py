#!/usr/bin/env python3
"""ghleak CLI — secret leak pipeline runner."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path

from .classifier import BatchClassifier, CommitClassifier, build_llm_backend
from .corporate_filter import CorporateTargetFilter
from .fetcher import (
    GitAPIClient,
    fetch_diff_from_url,
    resolve_commit_messages,
    stream_hours,
)
from .reporter import Report
from .scanner import TruffleHogScanner
from . import config

log = logging.getLogger("ghleak")

FORGE_CHOICES = sorted(config.FORGE_TYPES)
LLM_CHOICES = sorted(config.LLM_PROVIDERS)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ghleak",
        description="Scan GitHub Archive for leaked secrets and verify with TruffleHog",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  ghleak scan                                          # Scan last 2 hours\n"
            "  ghleak --llm-key sk-... --llm-provider openai scan    # OpenAI fallback\n"
            "  ghleak --llm-key AIza... --llm-provider gemini scan   # Gemini SDK fallback\n"
            "  ghleak --llm-provider openai --llm-endpoint http://localhost:11434/v1/chat/completions --llm-model llama3.2 scan\n"
            "  ghleak --forge-type gitea --git-api-base https://gitea.internal.example.com/api/v1 scan\n"
            "  ghleak commit owner/repo <sha>\n"
            "  ghleak url <git-url> <sha>\n"
        ),
    )
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    p.add_argument("--enterprise-only", action="store_true",
                    help="Only process events from Fortune 500 / big-tech orgs and domains")

    # Git forge options
    p.add_argument("--github-token", type=str, default=os.getenv("GITHUB_TOKEN"),
                    help="Git forge API token (env: GITHUB_TOKEN)")
    p.add_argument("--git-api-base", type=str, default=os.getenv("GIT_API_BASE"),
                    help="Custom git forge API base URL (env: GIT_API_BASE)")
    p.add_argument("--forge-type", type=str, default=os.getenv("FORGE_TYPE", "github"),
                    choices=FORGE_CHOICES,
                    help=f"Forge type. Choices: {', '.join(FORGE_CHOICES)} (env: FORGE_TYPE)")

    # LLM fallback options
    p.add_argument("--llm-provider", type=str, default=os.getenv("LLM_PROVIDER"),
                    choices=LLM_CHOICES,
                    help=f"LLM provider. Choices: {', '.join(LLM_CHOICES)} (env: LLM_PROVIDER)")
    p.add_argument("--llm-endpoint", type=str, default=os.getenv("LLM_ENDPOINT"),
                    help="LLM API endpoint (for openai/custom providers)")
    p.add_argument("--llm-key", type=str, default=os.getenv("LLM_API_KEY"),
                    help="LLM API key (optional for Ollama/local)")
    p.add_argument("--llm-model", type=str, default=os.getenv("LLM_MODEL"),
                    help="LLM model name")

    sub = p.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan recent GH Archive hours")
    scan_p.add_argument("--hours", type=int, default=2, help="Hours to look back (default: 2)")
    scan_p.add_argument("--output", "-o", type=str, choices=["text", "json", "csv", "md"], default="text")
    scan_p.add_argument("--output-file", type=str, help="Write output to file")
    scan_p.add_argument("--skip-diffs", action="store_true", help="Skip diff fetching (classification only)")
    scan_p.add_argument("--only-verified", action="store_true", default=True, help="Only report verified secrets")
    scan_p.add_argument("--max-commits", type=int, help="Stop after N suspicious commits")
    scan_p.add_argument("--sample", type=float, default=1.0,
                        help="Sample fraction of PushEvents (0.0-1.0)")

    mon_p = sub.add_parser("monitor", help="Continuous monitoring mode")
    mon_p.add_argument("--interval", type=int, default=60, help="Poll interval in minutes (default: 60)")
    mon_p.add_argument("--output", "-o", type=str, default="text")

    commit_p = sub.add_parser("commit", help="Scan a specific forge commit")
    commit_p.add_argument("repo", help="owner/repo_name")
    commit_p.add_argument("sha", help="Commit SHA")

    url_p = sub.add_parser("url", help="Scan a commit from any git forge")
    url_p.add_argument("url", help="Git remote URL (https:// or git@)")
    url_p.add_argument("sha", help="Commit SHA")
    url_p.add_argument("--token", type=str, help="API token for the forge")

    return p


def _init_git_client(args: argparse.Namespace) -> GitAPIClient:
    return GitAPIClient(
        token=args.github_token,
        api_base=args.git_api_base,
        forge_type=args.forge_type,
    )


def _init_llm(args: argparse.Namespace):
    provider = args.llm_provider
    if not provider:
        # Auto-detect from key format or endpoint
        if args.llm_key and args.llm_key.startswith("sk-"):
            provider = "openai"
        elif args.llm_key and args.llm_key.startswith("AIza"):
            provider = "gemini"
        elif args.llm_key and args.llm_key.startswith("sk-ant-"):
            provider = "anthropic"
        elif args.llm_endpoint:
            provider = "openai"
        else:
            log.info("No --llm-provider set. AI fallback disabled.")
            return None

    backend = build_llm_backend(
        provider=provider,
        endpoint=args.llm_endpoint,
        api_key=args.llm_key,
        model=args.llm_model,
    )
    if backend:
        log.info("LLM fallback: provider=%s model=%s key=%s endpoint=%s",
                 provider, args.llm_model or "default",
                 "yes" if args.llm_key else "no",
                 args.llm_endpoint or "default")
    return backend


def cmd_scan(args: argparse.Namespace) -> int:
    report = Report()
    llm = _init_llm(args)
    classifier_inst = BatchClassifier(llm_backend=llm)
    scanner_inst = TruffleHogScanner(only_verified=args.only_verified)
    gh = _init_git_client(args)

    ent_filter = CorporateTargetFilter(enterprise_only=args.enterprise_only) if args.enterprise_only else None
    if ent_filter:
        log.info("Enterprise-only mode enabled — filtering to Fortune 500 / big-tech targets")

    log.info("Scanning last %d hour(s) of GH Archive...", args.hours)
    total_pushes = 0

    for pushes in stream_hours(hours_back=args.hours, enterprise_filter=ent_filter):
        report.hours_scanned += 1

        if args.sample < 1.0:
            import random
            pushes = [p for p in pushes if random.random() < args.sample]

        total_pushes += len(pushes)
        log.info("Resolving commit messages for %d PushEvents...", len(pushes))
        commits = resolve_commit_messages(pushes, git_client=gh)

        messages = [commit["message"] for commit in commits]
        classifications = classifier_inst.classify_batch(messages)

        for commit, result in zip(commits, classifications):
            report.commits_seen += 1
            message = commit["message"]
            sha = commit["sha"]
            repo = commit["repo"]

            if result != "suspicious":
                continue

            report.add_suspicious(repo, sha, message, result)
            log.info("  SUSPICIOUS: %s @ %s — %s", repo, sha[:12], message[:100])

            if args.skip_diffs:
                continue

            repo_parts = repo.split("/")
            if len(repo_parts) == 2:
                diff = gh.fetch_diff(repo_parts[0], repo_parts[1], sha)
                if diff:
                    findings = scanner_inst.scan_diff(diff)
                    for f in findings:
                        report.add_finding(f)
                        if f.verified:
                            log.warning("  VERIFIED: [%s] %s in %s", f.detector, repo, f.file)

            if args.max_commits and len(report.suspicious_commits) >= args.max_commits:
                log.info("Reached max-commits limit (%d)", args.max_commits)
                break

        if args.max_commits and len(report.suspicious_commits) >= args.max_commits:
            break

    report.classifier_stats = classifier_inst.stats()
    gh.close()
    report.finish()

    log.info("Summary: %d hours, %d events, %d resolved, %d suspicious, %d verified",
             report.hours_scanned, total_pushes, report.commits_seen,
             len(report.suspicious_commits), report.verified_count)
    _output_report(report, args)
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    log.info("Starting monitor (interval=%d min)", args.interval)
    llm = _init_llm(args)
    run_count = 0

    ent_filter = CorporateTargetFilter(enterprise_only=args.enterprise_only) if args.enterprise_only else None

    while True:
        run_count += 1
        log.info("Monitor cycle #%d", run_count)
        report = Report()
        classifier_inst = BatchClassifier(llm_backend=llm)
        scanner_inst = TruffleHogScanner()
        gh = _init_git_client(args)

        for pushes in stream_hours(hours_back=1, enterprise_filter=ent_filter):
            report.hours_scanned += 1
            commits = resolve_commit_messages(pushes, git_client=gh)

            messages = [commit["message"] for commit in commits]
            classifications = classifier_inst.classify_batch(messages)

            for commit, result in zip(commits, classifications):
                report.commits_seen += 1
                if result != "suspicious":
                    continue
                report.add_suspicious(commit["repo"], commit["sha"], commit["message"], result)
                repo_parts = commit["repo"].split("/")
                if len(repo_parts) == 2:
                    diff = gh.fetch_diff(repo_parts[0], repo_parts[1], commit["sha"])
                    if diff:
                        for f in scanner_inst.scan_diff(diff):
                            report.add_finding(f)
                            if f.verified:
                                log.warning(" LIVE SECRET: [%s] %s @ %s — %s",
                                            f.detector, commit["repo"], commit["sha"][:12], f.file)

        report.classifier_stats = classifier_inst.stats()
        gh.close()
        report.finish()

        if report.verified_count > 0:
            log.warning("Cycle #%d: %d verified secrets found!", run_count, report.verified_count)
            _output_report(report, args)

        log.info("Sleeping %d min...", args.interval)
        time.sleep(args.interval * 60)


def cmd_commit(args: argparse.Namespace) -> int:
    report = Report()
    scanner_inst = TruffleHogScanner()
    gh = _init_git_client(args)
    report.commits_seen = 1
    owner, repo = args.repo.split("/")
    diff = gh.fetch_diff(owner, repo, args.sha)
    if not diff:
        log.error("Could not fetch diff for %s/%s@%s", owner, repo, args.sha)
        gh.close()
        return 1
    for f in scanner_inst.scan_diff(diff):
        report.add_finding(f)
        if f.verified:
            log.warning("VERIFIED: [%s] %s — %s", f.detector, f.file, f.commit[:12])
    report.hours_scanned = 1
    gh.close()
    report.finish()
    _output_report(report, args)
    return 0


def cmd_url(args: argparse.Namespace) -> int:
    report = Report()
    scanner_inst = TruffleHogScanner()
    report.commits_seen = 1
    diff = fetch_diff_from_url(args.url, args.sha, token=args.token)
    if not diff:
        log.error("Could not fetch diff from %s @ %s", args.url, args.sha)
        return 1
    for f in scanner_inst.scan_diff(diff):
        report.add_finding(f)
        if f.verified:
            log.warning("VERIFIED: [%s] %s — %s", f.detector, f.file, f.commit[:12])
    report.hours_scanned = 1
    report.finish()
    _output_report(report, args)
    return 0


def _output_report(report: Report, args: argparse.Namespace) -> None:
    fmt = getattr(args, "output", "text")
    out_file = getattr(args, "output_file", None)

    if fmt == "text":
        output = report.summary_text()
    elif fmt == "json":
        output = report.to_json()
    elif fmt == "csv":
        output = ""
        report.to_csv(out_file and open(out_file, "w") or sys.stdout)
    elif fmt == "md":
        output = report.to_markdown()
    else:
        output = report.summary_text()

    if out_file:
        Path(out_file).write_text(output)
        log.info("Report written to %s", out_file)
    else:
        print(output)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "monitor":
        return cmd_monitor(args)
    elif args.command == "commit":
        return cmd_commit(args)
    elif args.command == "url":
        return cmd_url(args)
    else:
        build_parser().print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
