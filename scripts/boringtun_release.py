#!/usr/bin/env python3
"""Trusted orchestration for merged-PR releases; defaults to read-only dry run.

Never import or execute a script, restore a cache, or execute a binary from a
downloaded build. This program and its static archive helper run from the
promoter workflow's pinned default-branch revision R. Source builds use C only
in separate read-only jobs. Enabling requires clearing reviewed policy blockers.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import boringtun_release_policy as policy

ROOT = Path(__file__).resolve().parents[1]
POLICY_FILE = ROOT / "packaging/boringtun/release-policy.json"
VALIDATION_FILE = ROOT / "packaging/boringtun/attestation-validation.json"
REQUIRED_JOBS = {"Resolve merged PR", "License and dependency gate", "Release request bundle",
                 "Build (linux-x86_64)", "Build (linux-aarch64)", "Build (linux-armv7-cross)",
                 "Build (macos-x86_64)", "Build (macos-aarch64)",
                 "Interop (linux-x86_64)", "Interop (linux-aarch64)", "Interop (linux-armv7-emulated)",
                 "Utun (macos-x86_64)", "Utun (macos-aarch64)"}
MAX_TOTAL = 256 * 1024 * 1024
MANIFEST_KEYS = ("artifact_format name version source_repository source_commit source_date_epoch target os arch libc "
                 "linkage rust_toolchain rustc cargo build_command build_profile rustflags binary binary_sha256 license third_party_licenses").split()
AUTH_ENV_VARS = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
                 "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN")


def require(value, message):
    if not value:
        raise policy.PolicyError(message)


def local_environment():
    """Keep network credentials out of Git and static verification subprocesses."""
    return {key: value for key, value in os.environ.items() if key not in AUTH_ENV_VARS}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(data):
    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()


def publication_gate(config):
    """No environment variable or CLI switch bypasses repository activation."""
    policy._keys(config, "schema repository enabled attribution_status activation_blockers activation build_workflow_id publish_workflow_id gh retirement", "release policy")
    require(type(config["schema"]) is int and config["schema"] == 1, "unknown policy schema")
    require(config["repository"] == policy.REPOSITORY, "wrong policy repository")
    require(config["enabled"] is True, "publication disabled in reviewed release-policy.json")
    require(config["attribution_status"] == "reviewed", "ownership attribution unresolved")
    require(type(config["activation_blockers"]) is list and not config["activation_blockers"], "activation evidence incomplete")
    policy._keys(config["activation"], "after_commit generation", "activation boundary")
    policy._sha(config["activation"]["after_commit"])
    generation = config["activation"]["generation"]
    require(type(generation) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", generation),
            "invalid activation generation")
    for key in ("build_workflow_id", "publish_workflow_id"):
        policy._int(config[key], key)
    policy._keys(config["gh"], "version linux_amd64_sha256", "gh policy")
    require(config["gh"]["version"] == "2.100.0", "wrong gh version")
    policy._digest(config["gh"]["linux_amd64_sha256"])
    retirement = config["retirement"]
    policy._keys(retirement, "repository commit files workflow_ids owner_audit", "legacy retirement")
    policy._repo(retirement["repository"])
    policy._sha(retirement["commit"])
    require(type(retirement["owner_audit"]) is str and retirement["owner_audit"], "owner-side retirement audit missing")
    require(type(retirement["files"]) is dict and len(retirement["files"]) >= 2, "retired workflow and script hashes required")
    for name, value in retirement["files"].items():
        require(type(name) is str and name and ".." not in name and not name.startswith("/"), "unsafe retirement path")
        policy._digest(value)
    require(type(retirement["workflow_ids"]) is list and retirement["workflow_ids"], "retired workflow IDs missing")
    for value in retirement["workflow_ids"]:
        policy._int(value, "legacy workflow ID")


def check_zip_directory(raw, expected_count, max_total=MAX_TOTAL):
    require(type(raw) is bytes and len(raw) <= max_total, "oversized artifact ZIP")
    # Bound central-directory entries before ZipFile allocates ZipInfo objects.
    end = raw.rfind(b"PK\x05\x06", max(0, len(raw) - 65557))
    require(end >= 0 and end + 22 <= len(raw), "missing ZIP directory footer")
    footer = struct.unpack_from("<4s4H2LH", raw, end)
    require(footer[1] == footer[2] == 0 and footer[3] == footer[4] == expected_count
            and end + 22 + footer[7] == len(raw), "unexpected ZIP directory entries")


def safe_zip(raw, expected_names, max_total=MAX_TOTAL):
    """Read only exact flat regular files, without extracting paths to disk."""
    check_zip_directory(raw, len(expected_names), max_total)
    files = {}
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            require(len(archive.infolist()) == len(expected_names), "unexpected artifact member count")
            for member in archive.infolist():
                name = member.filename
                mode = member.external_attr >> 16
                require(name in expected_names and name not in files and "/" not in name and "\\" not in name,
                        "unexpected, duplicate or unsafe ZIP member")
                require(not member.is_dir() and not member.flag_bits & 1, "nonregular or encrypted ZIP member")
                require(stat.S_IFMT(mode) in (0, stat.S_IFREG), "ZIP links and special files forbidden")
                total += member.file_size
                require(0 <= member.file_size <= max_total and total <= max_total, "oversized ZIP contents")
                limit = {"REQUEST.json": 65536, "RELEASE.json": 65536, "SHA256SUMS": 4096}.get(name, max_total)
                require(member.file_size <= limit, "oversized metadata ZIP member")
                with archive.open(member) as source:
                    content = source.read(member.file_size + 1)
                require(len(content) == member.file_size, "ZIP member size mismatch")
                files[name] = content
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise policy.PolicyError("invalid artifact ZIP") from exc
    require(set(files) == set(expected_names), "missing artifact files")
    return files


def check_jobs(jobs, run_id):
    """jobs must come from /runs/B/attempts/N/jobs, including every API page."""
    require(type(jobs) is list and len(jobs) == len(REQUIRED_JOBS), "missing or extra build jobs")
    found = set()
    for job in jobs:
        policy._keys(job, "name run_id status conclusion", "attempt job projection")
        policy._int(job["run_id"], "job run ID")
        require(job["run_id"] == run_id and job["name"] in REQUIRED_JOBS and job["name"] not in found,
                "wrong or duplicate attempt job")
        require(job["status"] == "completed" and job["conclusion"] == "success", "build gate did not succeed")
        found.add(job["name"])


def descriptor_marker(descriptor):
    raw = policy.canonical_bytes(descriptor)
    return "descriptor_sha256=" + digest(raw) + "\nRELEASE.json(base64)=" + base64.b64encode(raw).decode("ascii")


def recorded_descriptor(body):
    """Recover signed bytes atomically recorded on create; NOT trusted prose.

    Callers must cryptographically verify these exact bytes before using any
    claims. This makes an empty draft recoverable across P/attempt changes.
    """
    require(type(body) is str and len(body) < 64 * 1024, "invalid recorded descriptor")
    lines = body.splitlines()
    require(len(lines) == 2 and lines[1].startswith("RELEASE.json(base64)="), "draft lacks recoverable signed descriptor")
    try:
        raw = base64.b64decode(lines[1].split("=", 1)[1], validate=True)
    except ValueError as exc:
        raise policy.PolicyError("invalid recorded descriptor encoding") from exc
    descriptor = policy.check_descriptor(policy.load_json(raw))
    require(raw == policy.canonical_bytes(descriptor) and body == descriptor_marker(descriptor), "recorded descriptor digest mismatch")
    return descriptor, raw


def _check_files(descriptor, files, complete=True):
    require(type(files) is dict, "asset readback must be a mapping")
    expected = policy.release_assets(descriptor)
    require(set(files) <= set(expected), "unexpected release asset")
    if complete:
        require(set(files) == set(expected), "missing release asset")
    for name, content in files.items():
        require(type(content) is bytes and digest(content) == expected[name], "release asset hash conflict")


def _check_state(state, descriptor):
    policy._keys(state, "id tag target_commit draft body assets", "destination readback")
    policy._int(state["id"], "release ID")
    require(type(state["draft"]) is bool, "invalid release state")
    require(state["tag"] == descriptor["tag"] and state["target_commit"] == descriptor["source_commit"],
            "destination tag/source conflict")
    require(state["body"] == descriptor_marker(descriptor), "draft descriptor marker conflict")
    _check_files(descriptor, state["assets"], complete=not state["draft"])


def publish_release(destination, desired, files, verify, gate, *, dry_run=True):
    """Plan or perform immutable publication through a narrow destination API.

    verify independently verifies descriptor/archives' signatures, original B/P
    metadata, notices and hashes. gate rereads enablement/migration evidence.
    An exception after a mutation is uncertain: always read back; never blindly
    retry. No interface for deleting tags or replacing assets exists.
    """
    desired = policy.check_descriptor(desired)
    _check_files(desired, files)
    gate()
    state = destination.read_release(desired["tag"])
    action = "create"
    if state is not None:
        if "RELEASE.json" in state["assets"]:
            original_bytes = state["assets"]["RELEASE.json"]
            original = policy.check_descriptor(policy.load_json(original_bytes))
            require(original_bytes == policy.canonical_bytes(original), "noncanonical original descriptor")
            _check_state(state, original)
            verify(original, state["assets"])
            normalized = {key: state[key] for key in ("tag", "target_commit", "draft")}
            normalized.update(descriptor=original, assets={k: digest(v) for k, v in state["assets"].items()},
                              provenance_verified=True)
            # Compare desired content using published semantics, then retain the
            # exact verified original descriptor for resumable drafts as well.
            comparison = dict(normalized, draft=False, assets=policy.release_assets(original))
            policy.publication_action(comparison, desired)
            if not state["draft"]:
                return "already-published"
            desired = original
            files = dict(files, **{"RELEASE.json": original_bytes})
            _check_files(desired, files)
            action = "resume"
        else:
            original, original_bytes = recorded_descriptor(state["body"])
            _check_state(state, original)
            require(state["draft"] is True and not state["assets"], "unproven draft identity")
            verify(original, {"RELEASE.json": original_bytes})
            comparison = {"tag": state["tag"], "target_commit": state["target_commit"], "draft": False,
                          "descriptor": original, "assets": policy.release_assets(original), "provenance_verified": True}
            policy.publication_action(comparison, desired)
            desired = original
            files = dict(files, **{"RELEASE.json": original_bytes})
            _check_files(desired, files)
            action = "resume"
    if dry_run:
        return action
    verify(desired, files)
    gate()
    if state is None:
        try:
            destination.create_draft(desired["tag"], desired["source_commit"], descriptor_marker(desired))
        except (OSError, policy.PolicyError):
            pass  # Outcome is uncertain until readback, including HTTP errors.
        state = destination.read_release(desired["tag"])
        require(state is not None, "draft creation outcome unresolved; inspect destination before retry")
        _check_state(state, desired)
    release_id = state["id"]
    for name in ["RELEASE.json", *sorted(k for k in files if k != "RELEASE.json")]:
        _check_state(state, desired)
        if name in state["assets"]:
            continue
        gate()
        try:
            destination.upload_asset(state["id"], name, files[name])
        except (OSError, policy.PolicyError):
            pass
        state = destination.read_release(desired["tag"])
        require(state is not None and name in state["assets"], "asset upload outcome unresolved; inspect before retry")
        require(state["id"] == release_id, "release ID changed during upload readback")
        _check_state(state, desired)
    _check_files(desired, state["assets"])
    verify(desired, state["assets"])
    gate()
    try:
        destination.publish(state["id"])
    except (OSError, policy.PolicyError):
        pass
    state = destination.read_release(desired["tag"])
    require(state is not None and state["id"] == release_id, "release ID changed during publication readback")
    require(state is not None, "publish outcome unresolved")
    _check_state(state, desired)
    require(state["draft"] is False, "release remains draft; publication failed or outcome unresolved")
    return "published"


def projection(data, fields):
    require(type(data) is dict and all(key in data for key in fields.split()), "missing GitHub API evidence")
    return {key: deepcopy(data[key]) for key in fields.split()}


def project_repository(data):
    """REST run associations contain id/url/name, not always full_name."""
    require(type(data) is dict, "missing repository evidence")
    policy._int(data.get("id"), "repository ID")
    url = data.get("url")
    require(type(url) is str, "missing repository API URL")
    match = re.fullmatch(r"https://api\.github\.com/repos/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", url)
    require(match is not None, "noncanonical repository API URL")
    full_name = match.group(1)
    policy._repo(full_name)
    require(data.get("name") == full_name.split("/")[1] and
            ("full_name" not in data or data["full_name"] == full_name), "repository identity fields disagree")
    return {"full_name": full_name}


def project_base(data):
    return {"ref": data["ref"], "repo": project_repository(data["repo"])}


def project_head(data):
    return {"sha": data["sha"], "repo": project_repository(data["repo"])}


def project_pr(data, association=None, canonical_repository_id=None):
    """Use retained run identity for deleted/renamed contributor repositories.

    Fresh canonical PR metadata remains authoritative for H and C. Retained
    repository names come only from the exact build attempt, bound by PR number,
    H and numeric repository identities; no lookup by an old name is performed.
    """
    try:
        result = projection(data, "number state merged merge_commit_sha merged_at")
        result["base"] = project_base(data["base"])
        if association is None:
            result["head"] = project_head(data["head"])
        else:
            policy._int(canonical_repository_id, "canonical repository ID")
            policy._int(association["number"], "retained PR")
            require(association["number"] == data["number"] and
                    association["head"]["sha"] == data["head"]["sha"], "retained PR or head differs")
            retained_base = project_base(association["base"])
            retained_head = project_head(association["head"])
            require(retained_base == result["base"] and
                    association["base"]["repo"]["id"] == data["base"]["repo"]["id"] == canonical_repository_id,
                    "retained base repository identity differs")
            if data["head"].get("repo") is not None:
                project_repository(data["head"]["repo"])
                require(data["head"]["repo"]["id"] == association["head"]["repo"]["id"],
                        "renamed contributor repository identity differs")
            result["head"] = {"sha": data["head"]["sha"], "repo": retained_head["repo"]}
        return result
    except (KeyError, TypeError) as exc:
        raise policy.PolicyError("missing PR API evidence") from exc


def project_run(data):
    try:
        result = projection(data, "id run_attempt workflow_id path event status conclusion head_sha head_branch created_at")
        result["repository"] = projection(data["repository"], "full_name")
        require(type(data["pull_requests"]) is list, "missing run PR associations")
        result["pull_requests"] = [{"number": pr["number"], "head": project_head(pr["head"]),
                                    "base": project_base(pr["base"])} for pr in data["pull_requests"]]
        return result
    except (KeyError, TypeError) as exc:
        raise policy.PolicyError("missing run API evidence") from exc


def check_ancestry(comparison, source):
    policy._sha(source)
    require(type(comparison) is dict and comparison.get("status") in ("ahead", "identical") and
            comparison.get("merge_base_commit", {}).get("sha") == source, "C is not an ancestor of current master")


def toolchain_digest(provenance_bytes):
    data = policy.load_json(provenance_bytes)
    selected = projection(data, "rust_toolchain rust_commit llvm_commit inputs")
    require(selected["rust_toolchain"] == "1.98.1", "unreviewed Rust toolchain")
    policy._sha(selected["rust_commit"])
    policy._sha(selected["llvm_commit"])
    require(type(selected["inputs"]) is dict and selected["inputs"], "toolchain input provenance missing")
    return digest(json.dumps(selected, sort_keys=True, separators=(",", ":")).encode("ascii"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    """REST adapter. Only exact allowed repositories; redirects lose all auth."""
    def __init__(self, token=None, legacy_repository=None):
        self.token = token or os.environ.get("GH_TOKEN", "")
        self.allowed = {policy.REPOSITORY}
        if legacy_repository:
            policy._repo(legacy_repository)
            self.allowed.add(legacy_repository)
        self.opener = urllib.request.build_opener(NoRedirect())
        self.prefix = "/repos/" + policy.REPOSITORY

    def request(self, method, path, body=None, *, binary=False, upload=False, absent=False):
        require(method in ("GET", "POST", "PATCH"), "unsupported mutation")
        require(type(path) is str and re.fullmatch(r"[\x21-\x7e]+", path) and
                "#" not in path and "\\" not in path, "unsafe API path")
        resource, query_separator, _query = path.partition("?")
        repository = next((repo for repo in self.allowed if resource == "/repos/" + repo or
                           resource.startswith("/repos/" + repo + "/")), None)
        require(repository is not None, "API target outside allowlist")
        # All supported endpoints use literal URL-safe path components. Reject
        # encoded separators/dots (including nested encodings) before HTTP can
        # normalize them; URL-encoded query values remain independent of paths.
        require(re.fullmatch(r"(?:/[A-Za-z0-9_.-]+)+", resource) and
                all(part not in (".", "..") for part in resource.split("/")[1:]), "unsafe API path")
        suffix = resource[len("/repos/" + repository):]
        if suffix.startswith("/compare/"):
            branch = "(?:master|[0-9a-f]{40})" if repository == policy.REPOSITORY else "main"
            require(re.fullmatch(r"/compare/[0-9a-f]{40}\.\.\." + branch, suffix) and
                    method == "GET" and not query_separator and body is None and not binary and not upload,
                    "unsafe ancestry comparison")
        else:
            require(".." not in path, "unsafe API path")
        host = "uploads.github.com" if upload else "api.github.com"
        # Actions ZIP downloads negotiate the JSON API before redirecting to
        # storage. Only release-asset downloads require octet-stream; binary
        # controls response decoding independently of the endpoint's media type.
        release_asset = binary and re.fullmatch(r"/releases/assets/[1-9][0-9]*", suffix)
        headers = {"Accept": "application/octet-stream" if release_asset else "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "boringtun-release-policy/1"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        payload = None
        if body is not None:
            payload = body if type(body) is bytes else json_bytes(body)
            headers["Content-Type"] = "application/octet-stream" if type(body) is bytes else "application/json"
        request = urllib.request.Request("https://" + host + path, data=payload, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=60) as response:
                raw = response.read(MAX_TOTAL + 1)
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code == 404 and absent and method == "GET":
                return None
            if exc.code in (301, 302, 303, 307, 308) and method == "GET" and binary:
                location = exc.headers.get("Location", "")
                parsed = urllib.parse.urlsplit(location)
                require(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password and
                        parsed.port in (None, 443) and
                        (parsed.hostname.endswith(".githubusercontent.com") or parsed.hostname.endswith(".blob.core.windows.net")),
                        "artifact redirect outside trusted HTTPS storage")
                with self.opener.open(urllib.request.Request(location, headers={"User-Agent": headers["User-Agent"]}), timeout=60) as response:
                    raw = response.read(MAX_TOTAL + 1)
            else:
                raise policy.PolicyError(f"GitHub {method} failed (HTTP {exc.code}); no fallback") from exc
        except (OSError, urllib.error.URLError) as exc:
            raise policy.PolicyError("GitHub API outcome unavailable") from exc
        require(len(raw) <= MAX_TOTAL, "API response exceeds size bound")
        return raw if binary else policy.load_json(raw)

    def get(self, path):
        return self.request("GET", path)

    def pages(self, path, key=None):
        result = []
        expected_count = None
        for page in range(1, 101):
            suffix = "&" if "?" in path else "?"
            data = self.get(path + suffix + f"per_page=100&page={page}")
            if key and "total_count" in data:
                count = data["total_count"]
                require(type(count) is int and count >= 0, "invalid pagination count")
                require(expected_count in (None, count), "inventory changed during pagination; rerun read-only inventory")
                expected_count = count
            entries = data[key] if key else data
            require(type(entries) is list, "invalid paginated API response")
            result.extend(entries)
            if len(entries) < 100:
                require(expected_count is None or expected_count == len(result),
                        "truncated API inventory; use a narrower explicit time interval")
                return result
        raise policy.PolicyError("API pagination bound exceeded")

    def contents(self, path, ref, repository=policy.REPOSITORY):
        require(repository in self.allowed, "repository outside allowlist")
        data = self.get(f"/repos/{repository}/contents/{urllib.parse.quote(path, safe='/')}?ref={urllib.parse.quote(ref, safe='')}")
        require(data.get("type") == "file" and data.get("encoding") == "base64", "expected regular GitHub file")
        try:
            return base64.b64decode(data["content"].replace("\n", ""), validate=True)
        except (KeyError, ValueError) as exc:
            raise policy.PolicyError("invalid GitHub file encoding") from exc

    def read_release(self, tag):
        # /releases/tags/{tag} only finds published releases. A successful draft
        # POST can therefore be followed by a 404 there. Use the authenticated
        # inventory, reject ambiguous/changing identity, then read by numeric ID.
        # Absence is visibility-scoped: authentication alone does not prove push
        # access. Read-only preparation may not see drafts. Publication uses its
        # contents:write job token; operator recovery must require the known ID.
        require(self.token, "authenticated release inventory required")
        inventory = self.pages(self.prefix + "/releases")
        seen, matches = set(), []
        for item in inventory:
            require(type(item) is dict, "invalid release inventory entry")
            release_id = policy._int(item.get("id"), "inventory release ID")
            require(release_id not in seen, "duplicate release inventory ID")
            seen.add(release_id)
            require(type(item.get("tag_name")) is str, "invalid release inventory tag")
            if item["tag_name"] == tag:
                matches.append(item)
        require(len(matches) <= 1, "ambiguous release tag in inventory")
        release = None
        if matches:
            candidate = matches[0]
            release = self.get(self.prefix + f"/releases/{candidate['id']}")
            require(type(release) is dict and type(release.get("draft")) is bool,
                    "invalid release ID readback")
            policy._int(release.get("id"), "release ID readback")
            require(all(release.get(key) == candidate.get(key)
                        for key in ("id", "tag_name", "target_commitish", "draft", "body")),
                    "release identity changed after inventory")
        tag_ref = self.request("GET", self.prefix + "/git/ref/tags/" + urllib.parse.quote(tag, safe=""), absent=True)
        if release is None:
            require(tag_ref is None, "tag already exists without a verified release")
            return None
        if tag_ref is None:
            require(release["draft"] is True, "published release tag missing")
            target = policy._sha(release["target_commitish"])
        else:
            require(tag_ref["object"]["type"] == "commit", "release tag must directly identify a commit")
            target = policy._sha(tag_ref["object"]["sha"])
        assets = {}
        for item in self.pages(self.prefix + f"/releases/{release['id']}/assets"):
            name = item["name"]
            require(type(name) is str and name not in assets and "/" not in name and "\\" not in name, "duplicate or unsafe release asset")
            require(item["state"] == "uploaded" and item["size"] <= MAX_TOTAL, "incomplete or oversized asset")
            assets[name] = self.request("GET", self.prefix + f"/releases/assets/{item['id']}", binary=True)
        return {"id": release["id"], "tag": release["tag_name"], "target_commit": target,
                "draft": release["draft"], "body": release["body"], "assets": assets}

    def create_draft(self, tag, commit, body):
        return self.request("POST", self.prefix + "/releases", {"tag_name": tag, "target_commitish": commit,
                            "name": tag, "body": body, "draft": True, "prerelease": False, "make_latest": "false"})

    def upload_asset(self, release_id, name, content):
        policy._int(release_id, "release ID")
        return self.request("POST", self.prefix + f"/releases/{release_id}/assets?name=" + urllib.parse.quote(name, safe=""),
                            content, upload=True)

    def publish(self, release_id):
        policy._int(release_id, "release ID")
        return self.request("PATCH", self.prefix + f"/releases/{release_id}", {"draft": False, "make_latest": "false"})


def resolve_request(api, number, retained_run=None):
    policy._int(number, "PR")
    raw = api.get(api.prefix + f"/pulls/{number}")
    association, repository_id = None, None
    if retained_run is not None:
        associations = retained_run.get("pull_requests")
        require(type(associations) is list and len(associations) <= 1, "ambiguous retained PR identities")
        association = associations[0] if associations else None
        repository = api.get(api.prefix)
        repository_id = policy._int(repository["id"], "canonical repository ID")
        policy._int(retained_run["repository"]["id"], "build repository ID")
        require(repository["full_name"] == policy.REPOSITORY and
                retained_run["repository"]["id"] == repository_id and
                retained_run["repository"]["full_name"] == policy.REPOSITORY, "build repository identity differs")
    request = policy.merged_request(project_pr(raw, association, repository_id), number)
    if retained_run is not None:
        require(raw["base"]["repo"]["id"] == repository_id, "PR base repository identity differs")
        policy._check_build_identity(project_run(retained_run), request, retained_run["workflow_id"])
    check_ancestry(api.get(api.prefix + "/compare/" + request["source_commit"] + "...master"), request["source_commit"])
    return request


def resolve_build_request(api, raw_run):
    """Resolve server push C through paginated commit association and fresh PR.

    Titles, Actions PR associations and REQUEST.json do not select the source.
    This proves merged-source eligibility, not that this push caused the merge.
    Replayed eligible C retains the same immutable release identity.
    """
    require(raw_run.get("event") == "push" and raw_run.get("head_branch") == "master",
            "release build must be a master push")
    source = policy._sha(raw_run.get("head_sha"))
    number = policy.merged_pr_number(api.pages(api.prefix + f"/commits/{source}/pulls"), source)
    return resolve_request(api, number, raw_run)


def check_push_context(request, event, context, checkout):
    """Defense in depth after the workflow's pre-checkout push guard."""
    source = request["source_commit"]
    require(context.get("GITHUB_EVENT_NAME") == "push" and
            context.get("GITHUB_REPOSITORY") == policy.REPOSITORY and
            context.get("GITHUB_REF") == policy.MASTER_REF and
            context.get("GITHUB_SHA") == context.get("GITHUB_WORKFLOW_SHA") == checkout == source,
            "push context or checkout differs from merged source C")
    require(type(event) is dict and event.get("ref") == policy.MASTER_REF and
            event.get("repository", {}).get("full_name") == policy.REPOSITORY and
            event.get("after") == source and
            all(event.get(key) is False for key in ("created", "deleted", "forced")),
            "push must be an ordinary canonical master update")
    before = policy._sha(event.get("before"))
    require(before != "0" * 40 and before != source, "push has no prior distinct commit")


def check_retirement(api, config):
    """Public reads supplement the owner audit; cannot discover hidden drafts."""
    publication_gate(config)
    old = config["retirement"]
    repository = old["repository"]
    prefix = "/repos/" + repository
    check_ancestry(api.get(prefix + "/compare/" + old["commit"] + "...main"), old["commit"])
    for path, expected in old["files"].items():
        require(digest(api.contents(path, old["commit"], repository)) == expected and
                digest(api.contents(path, "main", repository)) == expected, "legacy publisher changed since retirement")
    for workflow in old["workflow_ids"]:
        require(api.get(prefix + f"/actions/workflows/{workflow}")["state"] == "disabled_manually", "legacy workflow is not owner-disabled")
        runs = api.pages(prefix + f"/actions/workflows/{workflow}/runs", "workflow_runs")
        require(all(run["status"] == "completed" for run in runs), "legacy publisher still has active runs")
    # owner_audit is a reviewed immutable evidence reference. A public release
    # listing cannot prove absence of drafts. The default activation blockers
    # explicitly require owner-side evidence before this reference is populated.
    require(not any(item["draft"] for item in api.pages(prefix + "/releases")), "legacy draft release remains")


def source_metadata(api, request, *, trusted=True):
    source = request["source_commit"]
    manifest = tomllib.loads(api.contents("boringtun-cli/Cargo.toml", source).decode("utf-8"))
    version = manifest["package"]["version"]
    policy.release_tag(version, source, request["pr"])
    provenance = api.contents("packaging/boringtun/runtime-provenance.json", source)
    if trusted:
        require(provenance == (ROOT / "packaging/boringtun/runtime-provenance.json").read_bytes(),
                "source runtime provenance differs from reviewed promoter policy")
    return {"version": version, "rust_toolchain": "1.98.1", "toolchain_sha256": toolchain_digest(provenance),
            "notice_provenance_sha256": digest(provenance)}


def pin_text(request, version):
    policy.release_tag(version, request["source_commit"], request["pr"])
    return (f"BORINGTUN_REPOSITORY=https://github.com/{policy.REPOSITORY}\n"
            f"BORINGTUN_COMMIT={request['source_commit']}\nBORINGTUN_VERSION={version}\n"
            "BORINGTUN_RUST_TOOLCHAIN=1.98.1\nBORINGTUN_ARTIFACT_FORMAT=1\n")


def inspect_archive(name, raw, source, version, expected_license):
    """Inspect bounded regular tar members in memory; never run the binary."""
    target = next((target for target in policy.TARGETS if name == policy.archive_name(version, source, target)), None)
    require(target is not None and type(raw) is bytes and len(raw) <= MAX_TOTAL, "wrong archive identity or size")
    stem = name[:-7]
    expected = {stem + "/" + item for item in ("MANIFEST", "LICENSE", "THIRD-PARTY-LICENSES", "boringtun-cli")}
    files = {}
    seen = set()
    total = 0
    try:
        # tarfile parses PAX/GNU metadata before yielding members. Bound the
        # entire decompressed tar stream first so metadata cannot bypass limits.
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
            unpacked = compressed.read(MAX_TOTAL + 1)
        require(len(unpacked) <= MAX_TOTAL, "oversized decompressed archive including metadata")
        with tarfile.open(fileobj=io.BytesIO(unpacked), mode="r|") as archive:
            for member in archive:
                require(not member.pax_headers, "PAX archive metadata is not format1")
                require(member.name not in seen and len(seen) < 5, "duplicate or extra archive member")
                seen.add(member.name)
                require(member.uid == member.gid == 0, "archive ownership differs")
                if member.name == stem:
                    require(member.isdir() and member.mode == 0o755, "invalid archive root")
                    continue
                require(member.name in expected and member.isfile() and not member.islnk() and not member.issym(),
                        "archive traversal/link/special member")
                require(member.mode == (0o755 if member.name.endswith("/boringtun-cli") else 0o644), "unexpected archive mode")
                total += member.size
                require(0 < member.size <= MAX_TOTAL and total <= MAX_TOTAL, "oversized archive contents")
                handle = archive.extractfile(member)
                require(handle is not None, "archive member has no data")
                content = handle.read(member.size + 1)
                require(len(content) == member.size, "archive member size mismatch")
                files[member.name[len(stem) + 1:]] = content
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise policy.PolicyError("invalid archive") from exc
    require(seen == expected | {stem}, "archive must have exactly four regular members and one root")
    require(files["LICENSE"] == expected_license, "archive license differs from source C")
    try:
        manifest = {}
        for line in files["MANIFEST"].decode("utf-8").splitlines():
            key, value = line.split("=", 1)
            require(key not in manifest and key in MANIFEST_KEYS, "duplicate or unknown manifest field")
            manifest[key] = value
    except (UnicodeError, ValueError) as exc:
        raise policy.PolicyError("invalid MANIFEST") from exc
    require(set(manifest) == set(MANIFEST_KEYS), "missing manifest fields")
    expected_manifest = {"artifact_format": "1", "name": "boringtun-cli", "version": version,
                         "source_repository": "https://github.com/" + policy.REPOSITORY, "source_commit": source,
                         "target": target, "binary": "boringtun-cli", "binary_sha256": digest(files["boringtun-cli"]),
                         "rust_toolchain": "1.98.1", "os": "macos" if "apple" in target else "linux",
                         "arch": target.split("-")[0], "libc": "libSystem" if "apple" in target else "musl",
                         "linkage": "dynamic-system" if "apple" in target else "static"}
    require(all(manifest[key] == value for key, value in expected_manifest.items()), "manifest identity or binary hash mismatch")
    return {"target": target, "name": name, "sha256": digest(raw),
            "binary_sha256": digest(files["boringtun-cli"]),
            "notice_sha256": digest(files["THIRD-PARTY-LICENSES"])}, files["THIRD-PARTY-LICENSES"]


def static_archive_gate(files, request, version):
    """Invoke only the trusted R helper's explicitly nonexecuting verifier."""
    with tempfile.TemporaryDirectory(prefix="boringtun-static-") as directory:
        root = Path(directory)
        pin = root / "pin.env"
        pin.write_text(pin_text(request, version), encoding="utf-8", newline="\n")
        environment = dict(local_environment(), BORINGTUN_PIN_FILE=str(pin))
        # Verify each archive independently. The helper reads only trusted R
        # packaging configuration; it must never be loaded from files/artifacts.
        for index, (name, raw) in enumerate(sorted(files.items())):
            if name.endswith(".tar.gz"):
                path = root / name
                path.write_bytes(raw)
                subprocess.run(["bash", str(ROOT / "scripts/boringtun-artifact.sh"),
                                "verify-archive-static", str(path), str(root / f"extract-{index}")],
                               env=environment, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def check_build_evidence(request, raw_run, artifacts, jobs, run_id, attempt, workflow_id):
    policy._int(run_id, "requested run")
    policy._int(attempt, "requested attempt")
    run = policy.check_build_run(project_run(raw_run), request, workflow_id)
    require(run["id"] == run_id and run["run_attempt"] == attempt, "API returned wrong run or attempt")
    check_jobs([projection(job, "name run_id status conclusion") for job in jobs], run_id)
    name = f"boringtun-{run_id}-{attempt}"
    selected = [artifact for artifact in artifacts if artifact.get("name") == name]
    require(len(selected) == 1, "expected one immutable artifact for build attempt")
    selected = selected[0]
    require(policy._date(raw_run["run_started_at"]) <= policy._date(selected["created_at"]) <=
            policy._date(raw_run["updated_at"]), "artifact is outside requested attempt interval")
    artifact = projection(selected, "id name digest size_in_bytes expired")
    artifact["workflow_run"] = projection(selected["workflow_run"], "id head_sha")
    policy._artifact(artifact, run)
    require(artifact["size_in_bytes"] <= MAX_TOTAL, "oversized artifact")
    return run, artifact


def check_request_envelope(envelope, request, run_id, attempt, metadata):
    policy._keys(envelope, "schema request run_id run_attempt version rust_toolchain toolchain_sha256 notice_provenance_sha256", "build request envelope")
    require(type(envelope["schema"]) is int and envelope["schema"] == 1, "unknown request envelope schema")
    policy._int(envelope["run_id"], "request run ID")
    policy._int(envelope["run_attempt"], "request attempt")
    require(envelope["request"] == request and envelope["run_id"] == run_id and envelope["run_attempt"] == attempt,
            "downloaded request source or attempt differs from GitHub")
    require(all(envelope[key] == value for key, value in metadata.items()), "downloaded request metadata differs from source")


def build_run_evidence(api, request, run_id, attempt, config):
    """Durable run/job proof; intentionally independent of artifact retention.

    Historical signed releases retain artifact identity/digest in RELEASE.json.
    GitHub must still retain the original run and attempt job metadata; missing
    metadata fails closed until a reviewed archival evidence scheme exists.
    """
    policy._int(run_id, "requested run")
    policy._int(attempt, "requested attempt")
    workflow = api.get(api.prefix + "/actions/workflows/" + policy.BUILD_WORKFLOW.split("/")[-1])
    expected_id = config["build_workflow_id"] or workflow["id"]
    require(workflow["id"] == expected_id and workflow["path"] == policy.BUILD_WORKFLOW, "build workflow ID/path changed")
    raw_run = api.get(api.prefix + f"/actions/runs/{run_id}/attempts/{attempt}")
    jobs = api.pages(api.prefix + f"/actions/runs/{run_id}/attempts/{attempt}/jobs", "jobs")
    run = policy.check_build_run(project_run(raw_run), request, expected_id)
    require(run["id"] == run_id and run["run_attempt"] == attempt, "API returned wrong run or attempt")
    check_jobs([projection(job, "name run_id status conclusion") for job in jobs], run_id)
    # Push head_sha identifies the executed workflow C. Never compare to moving
    # master; incompatible historical recipes remain explicitly blocked.
    require(api.contents(policy.BUILD_WORKFLOW, request["source_commit"]) == (ROOT / policy.BUILD_WORKFLOW).read_bytes(),
            "build workflow at C differs from trusted master-push recipe")
    return run


def build_evidence(api, request, run_id, attempt, config):
    """Fresh promotion additionally requires a live exact artifact."""
    run = build_run_evidence(api, request, run_id, attempt, config)
    raw_run = api.get(api.prefix + f"/actions/runs/{run_id}/attempts/{attempt}")
    jobs = api.pages(api.prefix + f"/actions/runs/{run_id}/attempts/{attempt}/jobs", "jobs")
    artifacts = api.pages(api.prefix + f"/actions/runs/{run_id}/artifacts", "artifacts")
    return check_build_evidence(request, raw_run, artifacts, jobs, run_id, attempt, run["workflow_id"])


def check_trigger(event):
    """Bind preparation to the actual trusted workflow_run event payload."""
    require(type(event) is dict and event.get("action") == "completed" and
            event.get("repository", {}).get("full_name") == policy.REPOSITORY,
            "wrong promotion trigger")
    run = event.get("workflow_run")
    require(type(run) is dict and run.get("repository", {}).get("full_name") == policy.REPOSITORY and
            run.get("event") == "push" and run.get("head_branch") == "master" and run.get("status") == "completed" and
            run.get("conclusion") == "success" and run.get("path") == policy.BUILD_WORKFLOW,
            "trigger is not a successful canonical build")
    return policy._int(run.get("id"), "trigger run"), policy._int(run.get("run_attempt"), "trigger attempt")


def triggered_build():
    path = Path(os.environ["GITHUB_EVENT_PATH"])
    require(path.is_file() and path.stat().st_size <= 1024 * 1024, "missing or oversized workflow event")
    return check_trigger(policy.load_json(path.read_bytes()))


def trusted_context(api, config):
    require(os.environ.get("GITHUB_REPOSITORY") == policy.REPOSITORY and
            os.environ.get("GITHUB_EVENT_NAME") == "workflow_run" and os.environ.get("GITHUB_REF") == policy.MASTER_REF,
            "promotion requires canonical master workflow_run context")
    triggered_build()
    recipe = policy._sha(os.environ.get("GITHUB_WORKFLOW_SHA"))
    require(os.environ.get("GITHUB_SHA") == recipe, "workflow recipe and OIDC source digest differ")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, env=local_environment(),
                          check=True, capture_output=True, text=True).stdout.strip()
    require(head == recipe, "trusted checkout is not workflow revision R")
    run_id, attempt = int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])
    workflow = api.get(api.prefix + "/actions/workflows/" + policy.PUBLISH_WORKFLOW.split("/")[-1])
    expected_id = config["publish_workflow_id"] or workflow["id"]
    require(workflow["id"] == expected_id and workflow["path"] == policy.PUBLISH_WORKFLOW, "publisher workflow changed")
    return {"repository": policy.REPOSITORY, "workflow_id": expected_id,
            "workflow_path": policy.PUBLISH_WORKFLOW, "ref": policy.MASTER_REF,
            "recipe_commit": recipe, "run_id": run_id, "run_attempt": attempt}


def verify_release(api, descriptor, files, config, gh, verification_output=None):
    _check_files(descriptor, files, complete=False)
    build = descriptor["build_run"]
    retained = api.get(api.prefix + f"/actions/runs/{build['id']}/attempts/{build['run_attempt']}")
    request = resolve_build_request(api, retained)
    require(request["pr"] == descriptor["pr"], "signed PR differs from independently discovered merged source")
    require(request["source_commit"] == descriptor["source_commit"], "signed source differs from merged PR")
    metadata = source_metadata(api, request)
    require(all(descriptor[key] == value for key, value in metadata.items()), "signed source metadata mismatch")
    run = build_run_evidence(api, request, descriptor["build_run"]["id"], descriptor["build_run"]["run_attempt"], config)
    require(run["workflow_id"] == descriptor["build_run"]["workflow_id"], "signed build workflow differs from GitHub")
    publisher = descriptor["publisher"]
    raw = api.get(api.prefix + f"/actions/runs/{publisher['run_id']}/attempts/{publisher['run_attempt']}")
    jobs = api.pages(api.prefix + f"/actions/runs/{publisher['run_id']}/attempts/{publisher['run_attempt']}/jobs", "jobs")
    expected_workflow = config["publish_workflow_id"] or api.get(
        api.prefix + "/actions/workflows/" + policy.PUBLISH_WORKFLOW.split("/")[-1])["id"]
    require(publisher["workflow_id"] == expected_workflow, "publisher workflow ID is not allowlisted")
    check_publisher_evidence(raw, jobs, publisher)
    license_bytes = api.contents("LICENSE.md", request["source_commit"])
    for name, raw_archive in files.items():
        if name.endswith(".tar.gz"):
            evidence, notices = inspect_archive(name, raw_archive, request["source_commit"], metadata["version"], license_bytes)
            require(evidence in descriptor["archives"], "signed archive platform/content/notice mismatch")
    static_archive_gate(files, request, metadata["version"])
    expected_subjects = policy.release_assets(descriptor)
    del expected_subjects["SHA256SUMS"]
    with tempfile.TemporaryDirectory(prefix="boringtun-attestation-") as directory:
        root = Path(directory)
        environment = dict(os.environ, GH_HOST="github.com", GH_CONFIG_DIR=str(root / "gh-config"))
        for name in expected_subjects:
            if name not in files:
                continue  # A partial draft: signed descriptor still covers absent asset hashes.
            path = root / name
            path.write_bytes(files[name])
            process = subprocess.run([gh, *policy.attestation_arguments(str(path), descriptor)],
                                     check=False, capture_output=True, env=environment)
            # Preserve the original stdout even if a real certificate shape is
            # unexpected; never include stderr or authentication environment.
            if verification_output is not None:
                with (Path(verification_output) / (name + ".verification.json")).open("xb") as evidence:
                    evidence.write(process.stdout)
            require(process.returncode == 0, "pinned gh cryptographic verification failed")
            results = policy.load_json(process.stdout)
            require(type(results) is list and results, "no verified attestation results")
            matches = 0
            for item in results:
                policy._keys(item, "attestation verificationResult", "gh result envelope")
                try:
                    policy.check_verified_attestation(item["verificationResult"], descriptor, expected_subjects)
                    matches += 1
                except policy.PolicyError:
                    continue
            require(matches > 0, "no attestation matches exact original publisher invocation and subjects")


def check_publisher_evidence(raw, jobs, publisher):
    """Successful signing gates remain valid if later publication fails."""
    for key in ("id", "run_attempt", "workflow_id"):
        policy._int(raw.get(key), "publisher " + key)
    require(raw["id"] == publisher["run_id"] and raw["run_attempt"] == publisher["run_attempt"] and
            raw["workflow_id"] == publisher["workflow_id"] and raw["path"] == policy.PUBLISH_WORKFLOW and
            raw["event"] == "workflow_run" and raw["head_sha"] == publisher["recipe_commit"] and
            raw["repository"]["full_name"] == policy.REPOSITORY and raw["head_branch"] == "master",
            "signed publisher invocation differs from GitHub")
    require(type(jobs) is list, "publisher attempt jobs unavailable")
    for name in ("Validate completed build", "Attest verified content"):
        matches = [job for job in jobs if job.get("name") == name]
        require(len(matches) == 1 and type(matches[0].get("run_id")) is int and
                matches[0]["run_id"] == publisher["run_id"] and matches[0]["status"] == "completed" and
                matches[0]["conclusion"] == "success", "original publisher validation/signing job did not succeed")


def prepare_release(api, run_id, attempt, publisher, config, gh):
    raw = api.get(api.prefix + f"/actions/runs/{run_id}/attempts/{attempt}")
    request = resolve_build_request(api, raw)
    metadata = source_metadata(api, request)
    build_run_evidence(api, request, run_id, attempt, config)
    # Fully recorded releases and complete drafts remain verifiable after the
    # Actions ZIP expires. Signature and original B/P job proof remain required.
    tag = policy.release_tag(metadata["version"], request["source_commit"], request["pr"])
    existing = api.read_release(tag)
    if existing is not None and "RELEASE.json" in existing["assets"]:
        original_bytes = existing["assets"]["RELEASE.json"]
        original = policy.check_descriptor(policy.load_json(original_bytes))
        require(original_bytes == policy.canonical_bytes(original), "noncanonical original descriptor")
        _check_state(existing, original)
        require(original["pr"] == request["pr"] and original["source_commit"] == request["source_commit"] and
                all(original[key] == value for key, value in metadata.items()), "recorded release request differs")
        same_build = (run_id, attempt) == (original["build_run"]["id"], original["build_run"]["run_attempt"])
        if same_build and set(existing["assets"]) == set(policy.release_assets(original)):
            verify_release(api, original, existing["assets"], config, gh)
            return original, existing["assets"], "resume" if existing["draft"] else "already-published", False
    run, artifact = build_evidence(api, request, run_id, attempt, config)
    names = {policy.archive_name(metadata["version"], request["source_commit"], target) for target in policy.TARGETS}
    raw_zip = api.request("GET", api.prefix + f"/actions/artifacts/{artifact['id']}/zip", binary=True)
    require(len(raw_zip) == artifact["size_in_bytes"] and digest(raw_zip) == artifact["digest"][7:], "artifact ZIP API digest/size mismatch")
    contents = safe_zip(raw_zip, names | {"REQUEST.json", "SHA256SUMS"})
    check_request_envelope(policy.load_json(contents.pop("REQUEST.json")), request, run_id, attempt, metadata)
    license_bytes = api.contents("LICENSE.md", request["source_commit"])
    archives = []
    for name in sorted(names):
        evidence, notices = inspect_archive(name, contents[name], request["source_commit"], metadata["version"], license_bytes)
        archives.append(evidence)
    static_archive_gate(contents, request, metadata["version"])
    descriptor = policy.make_descriptor(request, run, artifact,
        dict(publisher, **metadata), archives)
    contents["RELEASE.json"] = policy.canonical_bytes(descriptor)
    _check_files(descriptor, contents)
    verify = lambda original, present: verify_release(api, original, present, config, gh)
    action = publish_release(api, descriptor, contents, verify, lambda: None, dry_run=True)
    existing = api.read_release(descriptor["tag"])
    needs_attestation = existing is None
    if existing is not None:
        contents["RELEASE.json"] = (existing["assets"]["RELEASE.json"] if "RELEASE.json" in existing["assets"]
                                    else recorded_descriptor(existing["body"])[1])
        descriptor = policy.check_descriptor(policy.load_json(contents["RELEASE.json"]))
        _check_files(descriptor, contents)
    return descriptor, contents, action, needs_attestation


def write_new(directory, files):
    root = Path(directory)
    require(not root.is_symlink() and (not root.exists() or (root.is_dir() and not any(root.iterdir()))), "output directory must be new or empty")
    root.mkdir(parents=True, exist_ok=True)
    for name, raw in files.items():
        require(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.-]+", name), "unsafe output name")
        with (root / name).open("xb") as handle:
            handle.write(raw)


def read_prepared(directory):
    root = Path(directory)
    require(root.is_dir() and not root.is_symlink(), "prepared directory missing")
    paths = list(root.iterdir())
    require(len(paths) == len(policy.TARGETS) + 2 and all(path.is_file() and not path.is_symlink() for path in paths), "prepared files must be seven regular assets")
    files = {}
    total = 0
    for path in paths:
        size = path.stat().st_size
        limit = {"RELEASE.json": 65536, "SHA256SUMS": 4096}.get(path.name, MAX_TOTAL)
        total += size
        require(size <= limit and total <= MAX_TOTAL, "oversized prepared assets or metadata")
        files[path.name] = path.read_bytes()
    require("RELEASE.json" in files, "prepared descriptor missing")
    descriptor = policy.check_descriptor(policy.load_json(files["RELEASE.json"]))
    require(files["RELEASE.json"] == policy.canonical_bytes(descriptor), "noncanonical prepared descriptor")
    _check_files(descriptor, files)
    return descriptor, files


def prepared_zip(raw):
    """Bound the directory before discovering descriptor-derived filenames."""
    check_zip_directory(raw, len(policy.TARGETS) + 2)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(len(entries) == len(policy.TARGETS) + 2 and
                sum(entry.filename == "RELEASE.json" for entry in entries) == 1, "wrong preparation ZIP directory")
        entry = archive.getinfo("RELEASE.json")
        require(entry.file_size <= 65536, "oversized descriptor")
        descriptor = policy.check_descriptor(policy.load_json(archive.read(entry)))
    files = safe_zip(raw, set(policy.release_assets(descriptor)))
    _check_files(descriptor, files)
    return files


def gh_binary(archive_path, config):
    raw = Path(archive_path).read_bytes()
    expected = config["gh"]["linux_amd64_sha256"]
    policy._digest(expected)
    require(config["gh"]["version"] == "2.100.0" and digest(raw) == expected, "gh distribution checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        member = archive.getmember("gh_2.100.0_linux_amd64/bin/gh")
        require(member.isfile() and 0 < member.size < MAX_TOTAL, "invalid pinned gh binary")
        handle = archive.extractfile(member)
        require(handle is not None, "pinned gh binary missing")
        return handle.read(member.size + 1)


def pinned_gh(path, archive, config):
    candidate = Path(path)
    require(candidate.is_file() and not candidate.is_symlink() and candidate.read_bytes() == gh_binary(archive, config),
            "gh executable differs from pinned distribution")
    return str(candidate.resolve())


def reconcile(api, since, config, gh):
    """Read-only inventory with explicit gaps; never dispatch or publish.

    The caller supplies an inclusive UTC activation/history boundary. Every
    merged master PR in that interval receives a result, including missing runs
    and historical recipes that current R cannot authorize. This is detection,
    not a recovery mechanism for merges that never emitted a usable event.
    """
    boundary = policy._date(since)
    pulls = api.pages(api.prefix + "/pulls?state=closed&base=master&sort=updated&direction=asc")
    runs = api.pages(api.prefix + "/actions/workflows/" + policy.BUILD_WORKFLOW.split("/")[-1] +
                     "/runs?event=push&created=" + urllib.parse.quote(">=" + since, safe=""), "workflow_runs")
    results = []
    for pull in sorted(pulls, key=lambda value: value["number"]):
        if pull.get("merged_at") is None or policy._date(pull["merged_at"]) < boundary:
            continue
        number = policy._int(pull["number"], "reconciliation PR")
        candidates = [run for run in runs if run.get("head_sha") == pull.get("merge_commit_sha")]
        candidates.sort(key=lambda value: (value["id"], value["run_attempt"]), reverse=True)
        row = {"pr": number, "source_commit": None, "tag": None, "status": "blocked_request", "reason": ""}
        try:
            # A run association retains a deleted/renamed contributor's original
            # identity. The full exact attempt and canonical PR still bind H/C.
            retained = None
            if candidates:
                candidate = candidates[0]
                retained = api.get(api.prefix + f"/actions/runs/{candidate['id']}/attempts/{candidate['run_attempt']}")
            request = resolve_request(api, number, retained)
            row["source_commit"] = request["source_commit"]
            metadata = source_metadata(api, request)
            row["tag"] = policy.release_tag(metadata["version"], request["source_commit"], number)
            existing = api.read_release(row["tag"])
            if existing is not None:
                present = existing["assets"]
                if "RELEASE.json" in present:
                    original = policy.check_descriptor(policy.load_json(present["RELEASE.json"]))
                    require(present["RELEASE.json"] == policy.canonical_bytes(original), "noncanonical original descriptor")
                else:
                    original, raw = recorded_descriptor(existing["body"])
                    present = dict(present, **{"RELEASE.json": raw})
                _check_state(existing, original)
                verify_release(api, original, present, config, gh)
                row.update(status="draft_verified" if existing["draft"] else "published_verified",
                           reason="original signed descriptor and present assets verified; no writes")
            else:
                row.update(status="blocked_missing_build", reason="no associated build run; reviewed missed-event recovery is unavailable")
                failures = []
                for candidate in candidates:
                    try:
                        if candidate.get("status") in ("queued", "in_progress", "waiting", "requested", "pending"):
                            workflow = api.get(api.prefix + "/actions/workflows/" + policy.BUILD_WORKFLOW.split("/")[-1])
                            expected_id = config["build_workflow_id"] or workflow["id"]
                            require(workflow["id"] == expected_id and workflow["path"] == policy.BUILD_WORKFLOW,
                                    "active build workflow changed")
                            current = project_run(api.get(api.prefix + f"/actions/runs/{candidate['id']}/attempts/{candidate['run_attempt']}"))
                            policy._check_build_identity(current, request, expected_id)
                            require((current["id"], current["run_attempt"]) == (candidate["id"], candidate["run_attempt"]),
                                    "active run attempt differs")
                            if current["status"] in ("queued", "in_progress", "waiting", "requested", "pending"):
                                require(current["conclusion"] is None, "active build already has a conclusion")
                                row.update(status="active_build", reason=f"build {current['id']}/{current['run_attempt']} is active; exclude from missed-event recovery")
                                break
                        build_evidence(api, request, candidate["id"], candidate["run_attempt"], config)
                        row.update(status="build_evidence_present", reason="run and artifact metadata pass; signing/publication and manual recovery remain gated")
                        break
                    except (policy.PolicyError, KeyError, TypeError, ValueError) as exc:
                        failures.append(f"{candidate.get('id')}/{candidate.get('run_attempt')}: {exc}")
                else:
                    if failures:
                        row.update(status="blocked_build", reason="; ".join(failures))
        except (policy.PolicyError, OSError, KeyError, TypeError, ValueError, subprocess.CalledProcessError) as exc:
            row["reason"] = str(exc)
        modes = {"active_build": "wait-existing-run", "blocked_missing_build": "missing-event-no-release-route",
                 "blocked_build": "review-existing-attempts", "blocked_request": "review-source-evidence",
                 "draft_verified": "review-original-signed-draft", "published_verified": "none",
                 "build_evidence_present": "review-promotion-gates"}
        # Diagnostic preparation only: never turn a dispatch into eligible push
        # evidence or emit commands which could mutate tags/branches/releases.
        row["recovery"] = {"automatic": False, "mode": modes[row["status"]],
                           "attempts": [{"id": item["id"], "attempt": item["run_attempt"]} for item in candidates]}
        results.append(row)
    return {"schema": 1, "repository": policy.REPOSITORY, "since": since, "writes_performed": False,
            "publication_enabled": config.get("enabled") is True,
            "activation_blockers": config.get("activation_blockers", []), "requests": results}


def output_values(values):
    for name, value in values.items():
        require(re.fullmatch(r"[a-z_]+", name) is not None and "\n" not in str(value), "unsafe workflow output")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as handle:
            handle.write("".join(f"{name}={str(value).lower() if type(value) is bool else value}\n" for name, value in values.items()))
    print(json.dumps(values, sort_keys=True))


def output_subject_paths(directory, descriptor):
    """Emit the six validated subjects, excluding derived SHA256SUMS.

    Called only after attest-ready rechecks the live gates and compares every
    prepared byte against the exact triggering build. No glob can add a file.
    """
    root = Path(directory).resolve()
    names = set(policy.release_assets(descriptor)) - {"SHA256SUMS"}
    require(len(names) == len(policy.TARGETS) + 1, "wrong signing subject count")
    paths = [str(root / name) for name in sorted(names)]
    require(all("\n" not in path and "\r" not in path for path in paths), "unsafe attestation subject path")
    output = os.environ.get("GITHUB_OUTPUT")
    require(output, "attestation subject output file is unavailable")
    with open(output, "a", encoding="utf-8", newline="\n") as handle:
        handle.write("paths<<boringtun_signed_subjects\n" + "\n".join(paths) + "\nboringtun_signed_subjects\n")


def live_gate(api, config, descriptor):
    publication_gate(config)
    require(api.contents("packaging/boringtun/release-policy.json", "master") == POLICY_FILE.read_bytes(),
            "current master enablement differs from trusted recipe")
    trusted_context(api, config)
    # Master enablement alone must never retroactively authorize a source built
    # while publication was disabled. Read the immutable source's own policy.
    source = policy._sha(descriptor["source_commit"])
    baseline = config["activation"]["after_commit"]
    require(source != baseline, "source is the excluded activation baseline")
    source_config = policy.load_json(api.contents("packaging/boringtun/release-policy.json", source))
    publication_gate(source_config)
    require(source_config["activation"] == config["activation"], "source activation generation differs")
    comparison = api.get(api.prefix + "/compare/" + baseline + "..." + source)
    require(type(comparison) is dict and comparison.get("status") == "ahead" and
            comparison.get("merge_base_commit", {}).get("sha") == baseline,
            "source does not descend from activation baseline")
    check_retirement(api, config)


def validation_gate(api, config, context, descriptor):
    """Authorize only the selected merged PR's first ordinary signing attempt.

    This is not publication enablement or recovery. Latest run reads reject
    ordinary reruns even though historical /attempts/1 records remain readable.
    Inventories include every status; ambiguous/duplicate events fail closed.
    """
    require(config.get("enabled") is False and config.get("attribution_status") == "reviewed",
            "attestation validation requires disabled publication and reviewed notices")
    selection_bytes = VALIDATION_FILE.read_bytes()
    selection = policy.load_json(selection_bytes)
    policy._keys(selection, "schema pr", "attestation validation selection")
    require(type(selection["schema"]) is int and selection["schema"] == 1, "unknown validation selection schema")
    policy._int(selection["pr"], "selected validation PR")
    descriptor = policy.check_descriptor(descriptor)
    require(descriptor["pr"] == selection["pr"], "merged PR is not the selected validation")
    expected_context = {"repository": policy.REPOSITORY, **descriptor["publisher"]}
    require(context == expected_context, "validation descriptor differs from current publisher context")
    source = descriptor["source_commit"]
    require(context["recipe_commit"] == source, "validation must execute the selected source recipe C == R")
    build = descriptor["build_run"]
    require((build["id"], build["run_attempt"]) == triggered_build() and
            build["run_attempt"] == context["run_attempt"] == 1,
            "validation requires the exact triggering build and first build/publisher attempts")
    require(api.contents("packaging/boringtun/attestation-validation.json", "master") == selection_bytes and
            api.contents("packaging/boringtun/release-policy.json", "master") == POLICY_FILE.read_bytes(),
            "live validation selection or release policy changed")
    for recorded, id_key, config_key, workflow, event in (
            (build, "id", "build_workflow_id", policy.BUILD_WORKFLOW, "push"),
            (context, "run_id", "publish_workflow_id", policy.PUBLISH_WORKFLOW, "workflow_run")):
        workflow_id = policy._int(config.get(config_key), config_key)
        run_id = policy._int(recorded[id_key], "validation run ID")
        require(recorded["workflow_id"] == workflow_id, "validation workflow ID differs")
        path = api.prefix + f"/actions/workflows/{workflow_id}/runs?event={event}&head_sha={source}"
        inventory = api.pages(path, "workflow_runs")
        require(type(inventory) is list and len(inventory) == 1,
                "validation requires exactly one total invocation per workflow at C")
        latest = api.get(api.prefix + f"/actions/runs/{run_id}")
        fields = {"id": run_id, "run_attempt": 1, "workflow_id": workflow_id, "path": workflow,
                  "event": event, "head_sha": source, "head_branch": "master"}
        for run in (inventory[0], latest):
            require(type(run) is dict and all(run.get(k) == v and type(run.get(k)) is type(v) for k, v in fields.items()),
                    "validation invocation or latest attempt differs")
            require(type(run.get("repository")) is dict and run["repository"].get("full_name") == policy.REPOSITORY,
                    "validation run is not in the canonical repository")
            if event == "push":
                require(run.get("status") == "completed" and run.get("conclusion") == "success", "validation build is not successful")


def validation_prepared(api, config, context, descriptor, files, gh):
    validation_gate(api, config, context, descriptor)
    rebuilt, expected, action, attest = prepare_release(api, *triggered_build(), context, config, gh)
    require(action == "create" and attest is True and rebuilt == descriptor and expected == files,
            "validation requires new unchanged prepared content, not release recovery")
    # A second fresh gate catches revocation/rerun during expensive inspection.
    validation_gate(api, config, context, descriptor)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("gate", help="read-only activation check; disabled by default")
    reconciliation = commands.add_parser("reconcile", help="read-only merged-PR inventory including blocked recovery gaps")
    reconciliation.add_argument("--since", required=True, help="inclusive UTC boundary, e.g. 2026-10-26T00:00:00Z")
    reconciliation.add_argument("--gh", required=True)
    reconciliation.add_argument("--gh-archive", required=True)
    resolve = commands.add_parser("resolve", help="read-only merged-PR request and temporary pin")
    resolve.add_argument("--pr", type=int, help="explicit merged PR for maintenance dry runs only")
    resolve.add_argument("--run-id", type=int, required=True)
    resolve.add_argument("--attempt", type=int, required=True)
    resolve.add_argument("--output", required=True)
    bundle = commands.add_parser("bundle", help="assemble seven-file build request artifact (five archives, request, checksums)")
    bundle.add_argument("--request", required=True)
    bundle.add_argument("--archives", required=True)
    bundle.add_argument("--output", required=True)
    install = commands.add_parser("install-gh", help="extract only verified pinned gh binary")
    install.add_argument("--archive", required=True)
    install.add_argument("--output", required=True)
    for command in ("prepare", "attest-ready", "validation-attest-ready", "verify-validation", "publish"):
        sub = commands.add_parser(command)
        sub.add_argument("--gh", required=True)
        sub.add_argument("--gh-archive", required=True)
        if command == "prepare":
            sub.add_argument("--build-run", type=int, required=True)
            sub.add_argument("--attempt", type=int, required=True)
            sub.add_argument("--output", required=True)
        else:
            sub.add_argument("--directory", required=True)
        if command == "publish":
            sub.add_argument("--execute", action="store_true", help="publish only after every live gate; default is dry run")
        if command == "verify-validation":
            sub.add_argument("--evidence", required=True, help="new local directory for unmodified gh verification output")
    fetch = commands.add_parser("fetch-prepared", help="fetch immutable trusted preparation artifact safely")
    fetch.add_argument("--artifact-id", type=int, required=True)
    fetch.add_argument("--artifact-digest", required=True)
    fetch.add_argument("--output", required=True)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        config = policy.load_json(POLICY_FILE.read_bytes())
        if args.command == "gate":
            publication_gate(config)
            return 0
        if args.command == "install-gh":
            binary = gh_binary(args.archive, config)
            output = Path(args.output)
            require(not output.exists() and not output.is_symlink(), "gh output already exists")
            with output.open("xb") as handle:
                handle.write(binary)
            output.chmod(0o755)
            return 0
        api = GitHub(legacy_repository=config["retirement"]["repository"])
        if args.command == "reconcile":
            gh = pinned_gh(args.gh, args.gh_archive, config)
            print(json.dumps(reconcile(api, args.since, config, gh), indent=2, sort_keys=True))
            return 0
        if args.command == "resolve":
            require(os.environ.get("GITHUB_REPOSITORY") == policy.REPOSITORY and
                    os.environ.get("GITHUB_EVENT_NAME") in ("push", "workflow_dispatch"), "wrong build context")
            if os.environ.get("GITHUB_EVENT_NAME") == "push":
                require(args.pr is None, "automatic source cannot be selected by a CLI PR argument")
                retained = api.get(api.prefix + f"/actions/runs/{args.run_id}/attempts/{args.attempt}")
                require(retained["id"] == args.run_id and retained["run_attempt"] == args.attempt,
                        "resolver received wrong run or attempt")
                request = resolve_build_request(api, retained)
                event_path = Path(os.environ["GITHUB_EVENT_PATH"])
                require(event_path.stat().st_size <= 1024 * 1024, "oversized push event")
                checkout = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, env=local_environment(), check=True,
                                          capture_output=True, text=True).stdout.strip()
                check_push_context(request, policy.load_json(event_path.read_bytes()), os.environ, checkout)
            else:
                request = resolve_request(api, args.pr)
            metadata = source_metadata(api, request, trusted=False)
            envelope = dict(schema=1, request=request, run_id=args.run_id, run_attempt=args.attempt, **metadata)
            check_request_envelope(envelope, request, args.run_id, args.attempt, metadata)
            write_new(args.output, {"REQUEST.json": json_bytes(envelope), "pin.env": pin_text(request, metadata["version"]).encode()})
            output_values({"source": request["source_commit"], "pr": request["pr"], "version": metadata["version"]})
            return 0
        if args.command == "bundle":
            envelope = policy.load_json(Path(args.request).read_bytes())
            retained = (api.get(api.prefix + f"/actions/runs/{envelope['run_id']}/attempts/{envelope['run_attempt']}")
                        if os.environ.get("GITHUB_EVENT_NAME") == "push" else None)
            request = (resolve_build_request(api, retained) if retained is not None
                       else resolve_request(api, envelope["request"]["pr"]))
            metadata = source_metadata(api, request, trusted=False)
            check_request_envelope(envelope, request, int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"]), metadata)
            expected = {policy.archive_name(metadata["version"], request["source_commit"], target) for target in policy.TARGETS}
            paths = list(Path(args.archives).iterdir())
            require({path.name for path in paths} == expected and all(path.is_file() and not path.is_symlink() for path in paths), "wrong final archive set")
            files = {path.name: path.read_bytes() for path in paths}
            license_bytes = api.contents("LICENSE.md", request["source_commit"])
            for name, raw in files.items():
                inspect_archive(name, raw, request["source_commit"], metadata["version"], license_bytes)
            files["SHA256SUMS"] = "".join(f"{digest(raw)}  {name}\n" for name, raw in sorted(files.items())).encode("ascii")
            files["REQUEST.json"] = json_bytes(envelope)
            write_new(args.output, files)
            return 0
        context = trusted_context(api, config)
        if args.command == "fetch-prepared":
            policy._int(args.artifact_id, "preparation artifact ID")
            expected_digest = args.artifact_digest.removeprefix("sha256:")
            policy._digest(expected_digest)
            artifact = api.get(api.prefix + f"/actions/artifacts/{args.artifact_id}")
            require(artifact["id"] == args.artifact_id and artifact["expired"] is False and
                    artifact["name"] == f"promotion-{context['run_id']}-{context['run_attempt']}" and
                    artifact["workflow_run"]["id"] == context["run_id"] and
                    artifact["workflow_run"]["head_sha"] == context["recipe_commit"] and
                    artifact["digest"] == "sha256:" + expected_digest, "wrong preparation artifact identity")
            raw = api.request("GET", api.prefix + f"/actions/artifacts/{args.artifact_id}/zip", binary=True)
            require(digest(raw) == expected_digest, "preparation artifact digest mismatch")
            files = prepared_zip(raw)
            write_new(args.output, files)
            return 0
        gh = pinned_gh(args.gh, args.gh_archive, config)
        if args.command == "prepare":
            require((args.build_run, args.attempt) == triggered_build(), "requested build differs from triggering event")
            descriptor, files, action, attest = prepare_release(api, args.build_run, args.attempt, context, config, gh)
            write_new(args.output, files)
            publishable = True
            reason = "ready"
            try:
                live_gate(api, config, descriptor)
            except policy.PolicyError as exc:
                publishable, reason = False, str(exc)
            validation = False
            if not publishable and action == "create" and attest is True:
                try:
                    validation_gate(api, config, context, descriptor)
                    validation, reason = True, "selected attestation-only validation; publication disabled"
                except policy.PolicyError as exc:
                    reason += "; validation unavailable: " + str(exc)
            output_values({"tag": descriptor["tag"], "pr": descriptor["pr"], "action": action,
                           "attest": attest, "publishable": publishable, "validation": validation, "reason": reason})
            return 0
        descriptor, files = read_prepared(args.directory)
        if args.command in ("validation-attest-ready", "verify-validation"):
            validation_prepared(api, config, context, descriptor, files, gh)
            if args.command == "validation-attest-ready":
                output_subject_paths(args.directory, descriptor)
            else:
                # Available raw stdout files survive strict schema rejection;
                # all six are retained on success. Never rerun signing to debug.
                write_new(args.evidence, {})
                verify_release(api, descriptor, files, config, gh, verification_output=args.evidence)
                validation_gate(api, config, context, descriptor)
                output_values({"validation_verified": True, "tag": descriptor["tag"]})
            return 0
        if args.command == "attest-ready":
            live_gate(api, config, descriptor)
            rebuilt, expected, _action, attest = prepare_release(api, *triggered_build(), context, config, gh)
            require(attest and rebuilt == descriptor and expected == files, "prepared data changed before signing")
            output_subject_paths(args.directory, descriptor)
            return 0
        action = publish_release(api, descriptor, files,
            lambda original, present: verify_release(api, original, present, config, gh),
            lambda: live_gate(api, config, descriptor), dry_run=not args.execute)
        output_values({"action": action, "tag": descriptor["tag"]})
        return 0
    except (policy.PolicyError, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError,
            tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"Release blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
