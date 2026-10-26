#!/usr/bin/env python3
"""Derive a temporary production-helper pin for read-only PR validation.

This is candidate evidence only. It does not resolve a merged PR, create a
release request/descriptor, call GitHub, or authorize attestation/publication.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

REPOSITORY = "https://github.com/Wiresock-Foundation/wiresock-boringtun"
RUST_TOOLCHAIN = "1.98.1"
PIN_KEYS = {"BORINGTUN_REPOSITORY", "BORINGTUN_COMMIT", "BORINGTUN_VERSION",
            "BORINGTUN_RUST_TOOLCHAIN", "BORINGTUN_ARTIFACT_FORMAT"}
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_pin(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        require("=" in line, "invalid source pin")
        key, value = line.split("=", 1)
        require(key in PIN_KEYS and key not in values, "unknown or duplicate source pin key")
        values[key] = value
    require(set(values) == PIN_KEYS, "incomplete source pin")
    require(values["BORINGTUN_REPOSITORY"] == REPOSITORY and
            COMMIT.fullmatch(values["BORINGTUN_COMMIT"]) and VERSION.fullmatch(values["BORINGTUN_VERSION"]),
            "source pin identity is invalid")
    require(values["BORINGTUN_RUST_TOOLCHAIN"] == RUST_TOOLCHAIN and
            values["BORINGTUN_ARTIFACT_FORMAT"] == "1", "unreviewed toolchain or archive format")
    return values


def write_candidate_pin(source, expected_head, output, temporary_root):
    """Require a clean exact checkout; create one pin below RUNNER_TEMP."""
    require(type(expected_head) is str and COMMIT.fullmatch(expected_head), "expected PR head must be a full SHA")
    source = Path(source).resolve(strict=True)
    temporary_root = Path(temporary_root).resolve(strict=True)
    output = Path(output)
    require(source.is_dir() and temporary_root.is_dir(), "source or RUNNER_TEMP is missing")
    require(not output.exists() and not output.is_symlink(), "candidate pin output already exists")
    destination = output.resolve()
    require(destination.is_relative_to(temporary_root) and not destination.is_relative_to(source),
            "candidate pin must be below RUNNER_TEMP and outside the source checkout")

    def git(*arguments):
        return subprocess.run(["git", "-C", str(source), *arguments], check=True,
                              capture_output=True, text=True).stdout.strip()

    require(Path(git("rev-parse", "--show-toplevel")).resolve() == source, "source is not a checkout root")
    head = git("rev-parse", "HEAD")
    require(head == expected_head, "checked-out HEAD differs from the PR head")
    require(not git("status", "--porcelain=v1", "--untracked-files=all"), "candidate source checkout is dirty")
    read_pin(source / "packaging/boringtun/pin.env")
    manifest = tomllib.loads((source / "boringtun-cli/Cargo.toml").read_text(encoding="utf-8"))
    version = manifest["package"]["version"]
    require(type(version) is str and VERSION.fullmatch(version), "CLI version must be a literal release version")
    content = (f"BORINGTUN_REPOSITORY={REPOSITORY}\nBORINGTUN_COMMIT={head}\nBORINGTUN_VERSION={version}\n"
               f"BORINGTUN_RUST_TOOLCHAIN={RUST_TOOLCHAIN}\nBORINGTUN_ARTIFACT_FORMAT=1\n")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    return {"candidate": True, "source": head, "version": version, "rust_toolchain": RUST_TOOLCHAIN}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        temporary_root = os.environ.get("RUNNER_TEMP")
        require(temporary_root, "RUNNER_TEMP is required")
        result = write_candidate_pin(args.source, args.expected_head, args.output, temporary_root)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"Candidate validation blocked: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
