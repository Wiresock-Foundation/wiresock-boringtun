#!/usr/bin/env python3
"""Resolve immutable artifacts for read-only candidate retries, never releases."""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import sys
from urllib.request import Request, urlopen

REPOSITORY = "Wiresock-Foundation/wiresock-boringtun"
WORKFLOW = ".github/workflows/boringtun-platform-validation.yml"
LABELS = {"linux-x86_64": "linux-x86_64", "linux-aarch64": "linux-aarch64",
          "linux-armv7": "linux-armv7-cross", "macos-x86_64": "macos-x86_64",
          "macos-aarch64": "macos-aarch64"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def positive(value):
    return type(value) is int and value > 0


def timestamp(value):
    require(type(value) is str, "missing producer/artifact timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "timestamp has no timezone")
    return result


def validate_run(run, context):
    require(context["repository"] == REPOSITORY and positive(context["run_id"]) and
            positive(context["attempt"]) and re.fullmatch(r"[0-9a-f]{40}", context["head"]),
            "invalid candidate caller identity")
    require(run["id"] == context["run_id"] and run["run_attempt"] == context["attempt"] and
            run["head_sha"] == context["head"] and run["event"] == "pull_request" and
            run["path"] == WORKFLOW and run["repository"]["full_name"] == REPOSITORY and
            positive(run["repository"]["id"]) and positive(run["head_repository"]["id"]),
            "current run is not this exact candidate workflow/source/attempt")


def select_artifact(run, jobs, artifacts, context, kind, target=None):
    """Use the latest producer execution, not the consumer's attempt number."""
    validate_run(run, context)
    require((kind == "notices" and target is None) or (kind == "archive" and target in LABELS),
            "unknown candidate artifact kind or platform")
    producer_name = ("Candidate licenses and source checks" if kind == "notices" else
                     f"Candidate build ({LABELS[target]})")
    producers = [job for job in jobs if job["name"] == producer_name]
    require(producers, "candidate producer job is missing")
    for job in producers:
        require(positive(job["id"]) and job["run_id"] == context["run_id"] and
                job["head_sha"] == context["head"] and positive(job["run_attempt"]) and
                job["run_attempt"] <= context["attempt"], "producer identity/attempt mismatch")
    origin = max(job["run_attempt"] for job in producers)
    latest = [job for job in producers if job["run_attempt"] == origin]
    require(len(latest) == 1, "ambiguous candidate producer execution")
    producer = latest[0]
    require(producer["status"] == "completed" and producer["conclusion"] == "success",
            "latest candidate producer did not succeed; older attempts cannot substitute")
    prefix = "candidate-notices" if kind == "notices" else f"candidate-archive-{target}"
    name = f"{prefix}-{context['run_id']}-{origin}"
    matches = [item for item in artifacts if item["name"] == name]
    require(len(matches) == 1, "exact producer artifact is missing or ambiguous")
    item = matches[0]
    identity = item["workflow_run"]
    require(positive(item["id"]) and item["expired"] is False and
            type(item["digest"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"]),
            "artifact is expired or lacks immutable identity/digest")
    require(identity["id"] == context["run_id"] and identity["head_sha"] == context["head"] and
            identity["repository_id"] == run["repository"]["id"] and
            identity["head_repository_id"] == run["head_repository"]["id"],
            "artifact belongs to another run, source or repository")
    require(timestamp(producer["started_at"]) <= timestamp(item["created_at"]) <=
            timestamp(producer["completed_at"]), "artifact was not created during the producer job")
    return {"artifact_id": item["id"], "name": name, "digest": item["digest"],
            "producer_job_id": producer["id"], "producer_attempt": origin,
            "run_id": context["run_id"], "consumer_attempt": context["attempt"], "source": context["head"]}


def list_pages(get, path, key):
    items, expected = [], None
    separator = "&" if "?" in path else "?"
    for page in range(1, 101):
        response = get(f"{path}{separator}per_page=100&page={page}")
        count = response["total_count"]
        require(type(count) is int and count >= 0 and (expected is None or count == expected),
                "metadata count is invalid or changed during pagination")
        expected = count
        batch = response[key]
        require(type(batch) is list and len(batch) <= 100, "invalid metadata page")
        items.extend(batch)
        require(len(items) <= expected and all(positive(item["id"]) for item in items) and
                len({item["id"] for item in items}) == len(items), "duplicate or invalid metadata records")
        if len(items) == expected:
            return items
        require(len(batch) == 100, "metadata pagination is incomplete")
    raise ValueError("candidate metadata pagination limit exceeded")


def resolve_artifact(get, context, kind, target=None):
    path = f"actions/runs/{context['run_id']}"
    run = get(path)
    validate_run(run, context)
    jobs = list_pages(get, path + "/jobs?filter=all", "jobs")
    artifacts = list_pages(get, path + "/artifacts", "artifacts")
    selected = select_artifact(run, jobs, artifacts, context, kind, target)
    validate_run(get(path), context)  # A concurrent new attempt invalidates this selection.
    return selected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("notices", "archive"))
    parser.add_argument("--target", choices=tuple(LABELS))
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--github-output", required=True)
    args = parser.parse_args(argv)
    try:
        context = {"repository": os.environ["GITHUB_REPOSITORY"], "run_id": int(os.environ["GITHUB_RUN_ID"]),
                   "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "head": args.expected_head}
        token = os.environ["GH_TOKEN"]
        require(token, "read-only GitHub token is required")

        def get(path):
            request = Request(f"https://api.github.com/repos/{REPOSITORY}/{path}", headers={
                "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"})
            with urlopen(request, timeout=30) as response:
                return json.load(response)

        result = resolve_artifact(get, context, args.kind, args.target)
        with Path(args.github_output).open("a", encoding="utf-8") as output:
            output.write(f"artifact-id={result['artifact_id']}\n")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"Candidate artifact blocked: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
