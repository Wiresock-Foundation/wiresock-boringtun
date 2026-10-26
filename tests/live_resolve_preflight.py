#!/usr/bin/env python3
"""Opt-in public-GET replay of the full resolver; never produces CI artifacts.

Run from a reviewed client checkout, pointing --source-checkout at the actual
merged source and --event at a captured or explicitly reconstructed push event.
This is diagnostic evidence only, not an installed-workflow or signing proof.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import boringtun_release as release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-checkout", type=Path, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--attempt", type=int, required=True)
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--context-kind", choices=("captured", "reconstructed"), required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    # Reserve a new local receipt, never overwrite earlier evidence. No token
    # goes to the public API and no GitHub output file is populated.
    with args.receipt.open("x", encoding="utf-8") as receipt:
        for key in ("GH_TOKEN", "GITHUB_TOKEN", "GITHUB_OUTPUT"):
            os.environ.pop(key, None)
        requests = []
        original = release.GitHub

        class ReadOnlyGitHub(original):
            def request(self, method, path, body=None, **options):
                if method != "GET" or body is not None or options.get("upload"):
                    raise AssertionError("Live preflight permits public GET only")
                result = super().request(method, path, body, **options)
                requests.append({"method": method, "path": path,
                                 "response_sha256": release.digest(release.json_bytes(result))})
                return result

        release.GitHub = ReadOnlyGitHub
        # Only the source-checkout git check moves to C; the reviewed client's
        # code and POLICY_FILE stay at their original location.
        release.ROOT = args.source_checkout.resolve()
        api = ReadOnlyGitHub()
        run = api.get(api.prefix + f"/actions/runs/{args.run_id}/attempts/{args.attempt}")
        os.environ.update(GITHUB_EVENT_NAME=run["event"], GITHUB_REPOSITORY=run["repository"]["full_name"],
                          GITHUB_REF="refs/heads/" + run["head_branch"], GITHUB_SHA=run["head_sha"],
                          GITHUB_WORKFLOW_SHA=run["head_sha"], GITHUB_EVENT_PATH=str(args.event.resolve()),
                          GITHUB_RUN_ID=str(args.run_id), GITHUB_RUN_ATTEMPT=str(args.attempt))
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "diagnostic-only"
            status = release.main(["resolve", "--run-id", str(args.run_id), "--attempt", str(args.attempt),
                                   "--output", str(output)])
            # Temporary REQUEST.json/pin.env are deleted, never uploaded or
            # offered as inputs to the promotion/attestation/release workflow.
            result = {"diagnostic_only": True, "context_kind": args.context_kind,
                      "time_utc": datetime.now(timezone.utc).isoformat(), "exit_code": status,
                      "source": run["head_sha"], "run_id": args.run_id, "attempt": args.attempt,
                      "client_sha256": release.digest(Path(release.__file__).read_bytes()),
                      "event_sha256": release.digest(args.event.read_bytes()), "requests": requests}
            json.dump(result, receipt, sort_keys=True, indent=2)
            receipt.write("\n")
        return status


if __name__ == "__main__":
    sys.exit(main())
