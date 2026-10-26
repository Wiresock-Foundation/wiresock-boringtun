#!/usr/bin/env python3
"""Opt-in GET-only replay of complete preparation using real GitHub artifacts.

This diagnostic reconstructs workflow_run context from retained API metadata.
It is not CI/signing evidence. Supply an existing read credential on stdin;
no credential, downloaded artifact or prepared release is retained in output.
Run on Linux with a clean Git checkout of the actual publisher recipe.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import boringtun_release as release


def require_clean_checkout(path):
    status = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all", "--ignored"],
                            cwd=path, env=release.local_environment(), check=True, capture_output=True)
    release.require(not status.stdout, "diagnostic source checkout is not clean, including ignored files")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-checkout", type=Path, required=True)
    parser.add_argument("--build-run", type=int, required=True)
    parser.add_argument("--publisher-run", type=int, required=True)
    parser.add_argument("--gh-archive", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    with args.receipt.open("x", encoding="utf-8") as receipt:
        for key in (*release.AUTH_ENV_VARS, "GITHUB_OUTPUT"):
            os.environ.pop(key, None)
        release.ROOT = args.source_checkout.resolve()
        require_clean_checkout(release.ROOT)
        credential = sys.stdin.readline(8192).strip()
        release.require(credential and len(credential) < 8191, "missing or oversized stdin credential")
        os.environ["GH_TOKEN"] = credential
        config = release.policy.load_json(release.POLICY_FILE.read_bytes())
        release.require(config["enabled"] is False, "diagnostic requires publication disabled")
        requests = []
        original = release.GitHub

        class ReadOnlyGitHub(original):
            def request(self, method, path, body=None, **options):
                release.require(method == "GET" and body is None and not options.get("upload"),
                                "preflight permits GET only")
                result = super().request(method, path, body, **options)
                raw = result if isinstance(result, bytes) else release.json_bytes(result)
                requests.append({"method": method, "path": path, "binary": bool(options.get("binary")),
                                 "response_sha256": release.digest(raw), "size": len(raw)})
                return result

        release.GitHub = ReadOnlyGitHub
        api = ReadOnlyGitHub()
        build = api.get(api.prefix + f"/actions/runs/{args.build_run}/attempts/1")
        publisher = api.get(api.prefix + f"/actions/runs/{args.publisher_run}/attempts/1")
        release.require(publisher["event"] == "workflow_run" and publisher["head_branch"] == "master" and
                        publisher["repository"]["full_name"] == release.policy.REPOSITORY,
                        "wrong retained publisher context")
        with tempfile.TemporaryDirectory(prefix="boringtun-live-prepare-") as directory:
            root = Path(directory)
            event = root / "reconstructed-event.json"
            event.write_bytes(release.json_bytes({"action": "completed", "repository": publisher["repository"],
                                                  "workflow_run": build}))
            os.environ.update(GITHUB_EVENT_NAME=publisher["event"], GITHUB_REPOSITORY=publisher["repository"]["full_name"],
                              GITHUB_REF="refs/heads/" + publisher["head_branch"], GITHUB_SHA=publisher["head_sha"],
                              GITHUB_WORKFLOW_SHA=publisher["head_sha"], GITHUB_EVENT_PATH=str(event),
                              GITHUB_RUN_ID=str(args.publisher_run), GITHUB_RUN_ATTEMPT="1")
            gh = root / "gh"
            require_clean_checkout(release.ROOT)
            status = release.main(["install-gh", "--archive", str(args.gh_archive), "--output", str(gh)])
            if status == 0:
                status = release.main(["prepare", "--build-run", str(args.build_run), "--attempt", "1",
                                       "--gh", str(gh), "--gh-archive", str(args.gh_archive),
                                       "--output", str(root / "prepared")])
            result = {"diagnostic_only": True, "context_kind": "reconstructed", "exit_code": status,
                      "time_utc": datetime.now(timezone.utc).isoformat(), "source": build["head_sha"],
                      "recipe": publisher["head_sha"], "build_run": args.build_run, "build_attempt": 1,
                      "publisher_run": args.publisher_run, "publisher_attempt": 1,
                      "client_sha256": release.digest(Path(release.__file__).read_bytes()),
                      "publication_enabled": False, "requests": requests}
            json.dump(result, receipt, indent=2, sort_keys=True)
            receipt.write("\n")
        os.environ.pop("GH_TOKEN", None)
        return status


if __name__ == "__main__":
    sys.exit(main())
