#!/usr/bin/env python3
"""Operator-side release gate for a nominated, owner-approved candidate.

The operator gate validates the exact reviewed PR and its full CI evidence.
GitHub also enforces the required checks through protected main.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from urllib.parse import quote

REPO = "xdr-labs/parser-studio"
SHA = re.compile(r"[a-f0-9]{40}\Z")
REQUIRED_JOBS = frozenset(
    ["native-isolated-synthetic", "web-quality", "release-eligibility"] +
    [f"Browser regression (shard {i}/6)" for i in range(1, 7)]
)
REQUIRED_ARTIFACTS = frozenset(
    ["parser-studio-native-evidence", "parser-studio-h2-isolated-native-evidence"]
)


def validate_release_evidence(run: dict, jobs: dict, artifacts: dict,
                              pr: dict, *, expected_sha: str) -> None:
    """Refuse stale/missing/ambiguous CI and any non-main, Draft candidate."""
    if (not SHA.fullmatch(expected_sha) or
            run.get("head_sha") != expected_sha or
            pr.get("head", {}).get("sha") != expected_sha):
        raise ValueError("H4_HEAD_SHA")
    if (run.get("event") != "pull_request" or
            run.get("status") != "completed" or
            run.get("conclusion") != "success"):
        raise ValueError("H4_RUN_NOT_SUCCESS")
    if (pr.get("state") != "open" or pr.get("draft") is not False):
        raise ValueError("H4_PR_NOT_REVIEWABLE")
    if pr.get("base", {}).get("ref") != "main":
        raise ValueError("H4_MAIN_BASE")
    entries = jobs.get("jobs", [])
    names = [item.get("name") for item in entries]
    if (jobs.get("total_count") != len(REQUIRED_JOBS) or len(entries) != len(REQUIRED_JOBS) or
            len(set(names)) != len(REQUIRED_JOBS) or set(names) != REQUIRED_JOBS or
            any(item.get("status") != "completed" or
                item.get("conclusion") != "success" for item in entries)):
        raise ValueError("H4_REQUIRED_JOBS")
    if (any(item.get("head_sha", expected_sha) != expected_sha
            for item in entries)):
        raise ValueError("H4_HEAD_SHA")
    valid_artifacts = {entry.get("name") for entry in
                       artifacts.get("artifacts", [])
                       if entry.get("expired") is False and
                       entry.get("size_in_bytes", 1) > 0}
    if not REQUIRED_ARTIFACTS.issubset(valid_artifacts):
        raise ValueError("H4_NATIVE_ARTIFACTS")


def validate_work_packet(work: dict, blockers: list[dict]) -> None:
    """Do not convert successful CI into owner release authorization."""
    body = work.get('body')
    if (work.get('state') != 'closed' or not isinstance(body, str) or
            not body.strip() or re.search(r'(?mi)^\s*-\s*\[\s\]', body)):
        raise ValueError('H4_ACTIVE_WORK_PACKET_INCOMPLETE')
    for result in blockers:
        if (not isinstance(result.get('total_count'), int) or
                result['total_count'] != 0 or
                result.get('incomplete_results') is True):
            raise ValueError('H4_OPEN_P0_P1')


def fetch(endpoint: str) -> dict:
    result = subprocess.run(
        ["gh", "api", "--method", "GET", endpoint],
        text=True, capture_output=True, timeout=20, check=False,
    )
    if result.returncode != 0:
        # Never echo GitHub stderr or API responses; they can expose app data.
        raise ValueError("H4_GITHUB_API_UNAVAILABLE")
    try:
        obj = json.loads(result.stdout)
    except (ValueError, TypeError):
        raise ValueError("H4_INVALID_GITHUB_JSON") from None
    if not isinstance(obj, dict):
        raise ValueError("H4_INVALID_GITHUB_JSON")
    return obj


def main() -> int:
    parser = argparse.ArgumentParser(description="Exact-HEAD offline PR CI release gate.")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--work-issue", required=True, type=int,
                        help="Owner-reviewed, closed ACTIVE Work Packet")
    args = parser.parse_args()
    if (args.repo != REPO or args.pr < 1 or args.run_id < 1 or
            args.work_issue < 1 or not SHA.fullmatch(args.sha)):
        raise ValueError("H4_INVALID_SCOPE")
    root = f"repos/{REPO}"
    run = fetch(f"{root}/actions/runs/{args.run_id}")
    jobs = fetch(f"{root}/actions/runs/{args.run_id}/jobs?per_page=100")
    artifacts = fetch(f"{root}/actions/runs/{args.run_id}/artifacts?per_page=100")
    pr = fetch(f"{root}/pulls/{args.pr}")
    validate_release_evidence(run, jobs, artifacts, pr, expected_sha=args.sha)
    work = fetch(f'{root}/issues/{args.work_issue}')
    severity = [fetch('search/issues?q='+quote(
        f'repo:{REPO} is:issue is:open label:{label}',safe=''))
        for label in ('P0','P1')]
    validate_work_packet(work, severity)
    print("H4_OWNER_RELEASE_GATE_PASS exact_head=" + args.sha +
          " jobs=9 native_artifacts=2 work_packet_closed=1 open_p0_p1=0")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print("H4_OWNER_RELEASE_GATE_BLOCKED " +
              (str(error) if isinstance(error, ValueError) else "H4_RUNTIME_ERROR"))
        raise SystemExit(1) from None
