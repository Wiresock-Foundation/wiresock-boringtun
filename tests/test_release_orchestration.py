"""Offline orchestration tests: no GitHub writes and no build execution."""
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
from unittest.mock import patch
import warnings
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import boringtun_release_policy as policy
import test_release_policy as fixtures
X86, ARM, C = fixtures.X86, fixtures.ARM, fixtures.C


def api_run_fixture():
    raw = fixtures.run_fixture()
    for pr in raw["pull_requests"]:
        for key in ("head", "base"):
            full_name = pr[key]["repo"]["full_name"]
            pr[key]["repo"] = {"id": 1328564271, "url": "https://api.github.com/repos/" + full_name,
                               "name": full_name.split("/")[1]}
    return raw

implementation = ROOT / "scripts/boringtun_release.py"
release = None
if implementation.exists():
    spec = importlib.util.spec_from_file_location("release_orchestration", implementation)
    release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release)


class MemoryDestination:
    """Represents the actual destination state, including uncertain responses."""
    def __init__(self, state=None, uncertain=None):
        self.state = copy.deepcopy(state)
        self.writes = []
        self.uncertain = uncertain
        self.reads = 0

    def read_release(self, tag):
        self.reads += 1
        return copy.deepcopy(self.state)

    def maybe_fail(self, operation):
        if self.uncertain == operation:
            self.uncertain = None
            raise OSError("connection lost after server accepted mutation")

    def create_draft(self, tag, commit, body):
        self.writes.append("create")
        if self.state is not None:
            raise AssertionError("would overwrite release")
        self.state = {"id": 20, "tag": tag, "target_commit": commit, "draft": True,
                      "body": body, "assets": {}}
        self.maybe_fail("create")

    def upload_asset(self, release_id, name, content):
        if name in self.state["assets"]:
            raise AssertionError("would overwrite asset")
        self.writes.append("upload:" + name)
        self.state["assets"][name] = content
        self.maybe_fail("upload:" + name)

    def publish(self, release_id):
        self.writes.append("publish")
        self.state["draft"] = False
        self.maybe_fail("publish")


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(release, "trusted release orchestrator is not implemented")
        self.descriptor = fixtures.PolicyTests().descriptor()
        self.files = {name: (name + " archive").encode() for name in fixtures.TARGET_NAMES.values()}
        for item in self.descriptor["archives"]:
            item["sha256"] = hashlib.sha256(self.files[item["name"]]).hexdigest()
        self.files["RELEASE.json"] = policy.canonical_bytes(self.descriptor)
        self.files["SHA256SUMS"] = b"".join(
            (hashlib.sha256(data).hexdigest() + "  " + name + "\n").encode()
            for name, data in sorted(self.files.items()) if name.endswith(".tar.gz"))
        self.verifications = []

    def verified(self, descriptor, files):
        self.verifications.append(descriptor["publisher"]["run_id"])
        self.assertEqual(hashlib.sha256(files["RELEASE.json"]).hexdigest(),
                         policy.release_assets(descriptor)["RELEASE.json"])

    def ready(self):
        return None

    def existing(self, draft=False):
        return {"id": 20, "tag": self.descriptor["tag"], "target_commit": C,
                "draft": draft, "body": release.descriptor_marker(self.descriptor),
                "assets": copy.deepcopy(self.files)}

    def test_default_policy_blocks_publication(self):
        config = policy.load_json((ROOT / "packaging/boringtun/release-policy.json").read_bytes())
        with self.assertRaises(policy.PolicyError):
            release.publication_gate(config)
        self.assertIs(config["enabled"], False)
        self.assertEqual(config["attribution_status"], "unresolved")

    def test_gate_failure_and_failed_verification_cause_zero_writes(self):
        destination = MemoryDestination()
        def denied():
            raise policy.PolicyError("ownership review unresolved")
        with self.assertRaises(policy.PolicyError):
            release.publish_release(destination, self.descriptor, self.files, self.verified, denied, dry_run=False)
        self.assertEqual(destination.writes, [])
        def bad_signature(*_args):
            raise policy.PolicyError("wrong signature")
        with self.assertRaises(policy.PolicyError):
            release.publish_release(destination, self.descriptor, self.files, bad_signature, self.ready, dry_run=False)
        self.assertEqual(destination.writes, [])

    def test_complete_read_only_dry_run_never_mutates(self):
        destination = MemoryDestination()
        self.assertEqual(release.publish_release(destination, self.descriptor, self.files,
                         self.verified, self.ready, dry_run=True), "create")
        self.assertEqual(destination.writes, [])

    def test_draft_records_descriptor_digest_and_uploads_descriptor_first(self):
        destination = MemoryDestination()
        self.assertEqual(release.publish_release(destination, self.descriptor, self.files,
                         self.verified, self.ready, dry_run=False), "published")
        self.assertEqual(destination.writes[:2], ["create", "upload:RELEASE.json"])
        self.assertEqual(destination.writes[-1], "publish")
        self.assertEqual(destination.state["body"].splitlines()[0], "descriptor_sha256=" +
                         hashlib.sha256(self.files["RELEASE.json"]).hexdigest())
        self.assertEqual(destination.state["assets"], self.files)

    def test_partial_draft_reuses_original_and_only_uploads_absent_assets(self):
        state = self.existing(True)
        del state["assets"][ARM]
        destination = MemoryDestination(state)
        self.assertEqual(release.publish_release(destination, self.descriptor, self.files,
                         self.verified, self.ready, dry_run=False), "published")
        self.assertEqual(destination.writes, ["upload:" + ARM, "publish"])

    def test_published_retry_verifies_original_provenance_and_never_mutates(self):
        destination = MemoryDestination(self.existing())
        desired = copy.deepcopy(self.descriptor)
        desired["publisher"]["run_id"] = 900
        files = dict(self.files, **{"RELEASE.json": policy.canonical_bytes(desired)})
        result = release.publish_release(destination, desired, files, self.verified, self.ready, dry_run=False)
        self.assertEqual(result, "already-published")
        self.assertIn(500, self.verifications)
        self.assertEqual(destination.writes, [])

    def test_uncertain_mutations_are_read_back_and_not_repeated(self):
        for operation in ["create", "upload:RELEASE.json", "upload:" + ARM, "publish"]:
            destination = MemoryDestination(uncertain=operation)
            with self.subTest(operation=operation):
                self.assertEqual(release.publish_release(destination, self.descriptor, self.files,
                                 self.verified, self.ready, dry_run=False), "published")
                self.assertEqual(destination.writes.count(operation), 1)
                self.assertGreaterEqual(destination.reads, 6)

    def test_uncertain_create_without_readback_success_stops(self):
        destination = MemoryDestination()
        def fail(*_args):
            destination.writes.append("create")
            raise OSError("request might not have reached server")
        destination.create_draft = fail
        with self.assertRaises(policy.PolicyError):
            release.publish_release(destination, self.descriptor, self.files,
                                    self.verified, self.ready, dry_run=False)
        self.assertEqual(destination.writes, ["create"])

    def test_conflicting_asset_or_tag_or_marker_refuses_all_writes(self):
        for mutation in ["asset", "tag", "marker"]:
            state = self.existing(True)
            if mutation == "asset":
                state["assets"][X86] = b"changed"
            elif mutation == "tag":
                state["target_commit"] = "f" * 40
            else:
                state["body"] = "looks fine"
            destination = MemoryDestination(state)
            with self.subTest(mutation=mutation), self.assertRaises(policy.PolicyError):
                release.publish_release(destination, self.descriptor, self.files,
                                        self.verified, self.ready, dry_run=False)
            self.assertEqual(destination.writes, [])

    def test_empty_draft_with_exact_recorded_digest_can_resume_descriptor_upload(self):
        state = self.existing(True)
        state["assets"] = {}
        destination = MemoryDestination(state)
        self.assertEqual(release.publish_release(destination, self.descriptor, self.files,
                         self.verified, self.ready, dry_run=False), "published")
        self.assertEqual(destination.writes[0], "upload:RELEASE.json")

    def test_new_attempt_recovers_original_signed_descriptor_from_empty_draft(self):
        state = self.existing(True)
        state["assets"] = {}
        destination = MemoryDestination(state)
        desired = copy.deepcopy(self.descriptor)
        desired["publisher"]["run_id"] = 900
        desired["publisher"]["run_attempt"] = 1
        files = dict(self.files, **{"RELEASE.json": policy.canonical_bytes(desired)})
        self.assertEqual(release.publish_release(destination, desired, files, self.verified, self.ready,
                                                dry_run=False), "published")
        self.assertEqual(destination.state["assets"]["RELEASE.json"], self.files["RELEASE.json"])
        self.assertIn(500, self.verifications)

    def zip(self, entries):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as archive:
            for name, content, mode in entries:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = mode << 16
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive.writestr(info, content)
        return raw.getvalue()

    def test_safe_zip_accepts_only_bounded_flat_regular_expected_files(self):
        raw = self.zip([("REQUEST.json", b"{}", stat.S_IFREG | 0o644)])
        self.assertEqual(release.safe_zip(raw, {"REQUEST.json"}), {"REQUEST.json": b"{}"})
        for entries in [[("../REQUEST.json", b"{}", stat.S_IFREG | 0o644)],
                        [("REQUEST.json", b"target", stat.S_IFLNK | 0o777)],
                        [("REQUEST.json", b"a", stat.S_IFREG | 0o644), ("REQUEST.json", b"b", stat.S_IFREG | 0o644)],
                        [("REQUEST.json", b"x" * 20, stat.S_IFREG | 0o644)]]:
            with self.assertRaises(policy.PolicyError):
                release.safe_zip(self.zip(entries), {"REQUEST.json"}, max_total=1024 if len(entries[0][1]) < 20 else 10)

    def test_attempt_jobs_require_all_gates_and_no_failed_or_skipped_jobs(self):
        jobs = [{"name": name, "run_id": 100, "status": "completed", "conclusion": "success"}
                for name in release.REQUIRED_JOBS]
        release.check_jobs(jobs, 100)
        for mutation in ["missing", "failed", "skipped", "other-run", "duplicate"]:
            changed = copy.deepcopy(jobs)
            if mutation == "missing":
                changed.pop()
            elif mutation in ("failed", "skipped"):
                changed[0]["conclusion"] = mutation
            elif mutation == "other-run":
                changed[0]["run_id"] = 101
            else:
                changed.append(changed[0])
            with self.subTest(mutation=mutation), self.assertRaises(policy.PolicyError):
                release.check_jobs(changed, 100)

    def test_source_toolchain_projection_is_explicit_and_matches_raw_provenance(self):
        self.assertTrue(hasattr(release, "toolchain_digest"), "toolchain digest interface missing")
        data = {"rust_toolchain": "1.98.1", "rust_commit": "a" * 40,
                "llvm_commit": "b" * 40, "inputs": {"compiler.tar.xz": {"sha256": "c" * 64}},
                "other_notice_metadata": "not a toolchain input"}
        raw = json.dumps(data).encode()
        expected = {"rust_toolchain": "1.98.1", "rust_commit": "a" * 40,
                    "llvm_commit": "b" * 40, "inputs": {"compiler.tar.xz": {"sha256": "c" * 64}}}
        self.assertEqual(release.toolchain_digest(raw),
                         hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()).hexdigest())

    def test_api_projection_requires_actual_fields_and_never_substitutes_source_sha(self):
        self.assertTrue(hasattr(release, "project_run"), "API projection missing")
        raw = api_run_fixture()
        raw["irrelevant_api_field"] = "ignored by explicit projection"
        self.assertEqual(release.project_run(raw), fixtures.run_fixture())
        raw["head_sha"] = fixtures.H
        self.assertEqual(release.project_run(raw)["head_sha"], fixtures.H)
        del raw["created_at"]
        with self.assertRaises(policy.PolicyError):
            release.project_run(raw)

    def test_ancestry_requires_merge_base_equal_full_source(self):
        self.assertTrue(hasattr(release, "check_ancestry"), "ancestry gate missing")
        release.check_ancestry({"status": "ahead", "merge_base_commit": {"sha": C}}, C)
        for status, base in [("diverged", C), ("behind", C), ("ahead", "f" * 40)]:
            with self.assertRaises(policy.PolicyError):
                release.check_ancestry({"status": status, "merge_base_commit": {"sha": base}}, C)

    def test_draft_readback_does_not_require_tag_before_publication(self):
        class Api(release.GitHub):
            def request(self, method, path, *args, **kwargs):
                if "/git/ref/" in path:
                    return None
                return {"id": 20, "tag_name": "release", "target_commitish": C,
                        "draft": True, "body": "marker"}
            def pages(self, *_args, **_kwargs):
                return []
        self.assertEqual(Api().read_release("release")["target_commit"], C)

    def tar_archive(self, additions=(), pax=None, target="x86_64-unknown-linux-musl", notices=b"notices", fields=None):
        contents = {"boringtun-cli": b"binary", "LICENSE": b"license",
                    "THIRD-PARTY-LICENSES": notices}
        manifest = {key: "unused" for key in release.MANIFEST_KEYS}
        manifest.update(artifact_format="1", name="boringtun-cli", version="0.7.1",
                        source_repository="https://github.com/" + policy.REPOSITORY,
                        source_commit=C, target=target, os="macos" if "apple" in target else "linux",
                        arch=target.split("-")[0], libc="libSystem" if "apple" in target else "musl",
                        linkage="dynamic-system" if "apple" in target else "static",
                        binary="boringtun-cli", binary_sha256=hashlib.sha256(b"binary").hexdigest(),
                        rust_toolchain="1.98.1")
        manifest.update(fields or {})
        contents["MANIFEST"] = "".join(f"{k}={v}\n" for k, v in manifest.items()).encode()
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            root = fixtures.TARGET_NAMES[target][:-7]
            directory = tarfile.TarInfo(root)
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            if pax:
                directory.pax_headers = pax
            archive.addfile(directory)
            for name, content in contents.items():
                entry = tarfile.TarInfo(root + "/" + name)
                entry.size = len(content)
                entry.mode = 0o755 if name == "boringtun-cli" else 0o644
                archive.addfile(entry, io.BytesIO(content))
            for entry in additions:
                archive.addfile(entry)
        return output.getvalue()

    def test_archive_inspection_binds_four_members_manifest_binary_and_notices(self):
        self.assertTrue(hasattr(release, "inspect_archive"), "static archive inspection missing")
        result, notices = release.inspect_archive(X86, self.tar_archive(), C, "0.7.1", b"license")
        self.assertEqual(result["binary_sha256"], hashlib.sha256(b"binary").hexdigest())
        self.assertEqual(result["target"], "x86_64-unknown-linux-musl")
        self.assertEqual(notices, b"notices")
        with self.assertRaises(policy.PolicyError):
            release.inspect_archive(X86, self.tar_archive(), C, "0.7.1", b"different license")
        for path, kind in [("../escape", tarfile.REGTYPE), (X86[:-7] + "/link", tarfile.SYMTYPE)]:
            entry = tarfile.TarInfo(path)
            entry.type = kind
            with self.assertRaises(policy.PolicyError):
                release.inspect_archive(X86, self.tar_archive([entry]), C, "0.7.1", b"license")

    def test_build_evidence_pins_requested_run_attempt_and_artifact_window(self):
        self.assertTrue(hasattr(release, "check_build_evidence"), "build evidence validator missing")
        request = policy.merged_request(fixtures.pr_fixture(), 42)
        raw = api_run_fixture()
        raw.update(run_started_at="2026-10-25T12:01:00Z", updated_at="2026-10-25T12:04:00Z")
        artifact = fixtures.artifact_fixture()
        artifact["created_at"] = "2026-10-25T12:03:00Z"
        jobs = [{"name": name, "run_id": 100, "status": "completed", "conclusion": "success"}
                for name in release.REQUIRED_JOBS]
        _, chosen = release.check_build_evidence(request, raw, [artifact], jobs, 100, 2, 200)
        self.assertEqual(chosen["id"], 300)
        for mutation in ["run", "attempt", "time", "duplicate"]:
            run = copy.deepcopy(raw)
            artifacts = [copy.deepcopy(artifact)]
            if mutation == "run":
                run["id"] = 999
            elif mutation == "attempt":
                run["run_attempt"] = 1
            elif mutation == "time":
                artifacts[0]["created_at"] = "2026-10-25T12:00:00Z"
            else:
                artifacts.append(copy.deepcopy(artifact))
            with self.subTest(mutation=mutation), self.assertRaises(policy.PolicyError):
                release.check_build_evidence(request, run, artifacts, jobs, 100, 2, 200)

    def test_request_envelope_rejects_source_or_attempt_substitution(self):
        self.assertTrue(hasattr(release, "check_request_envelope"), "request envelope gate missing")
        request = policy.merged_request(fixtures.pr_fixture(), 42)
        metadata = {"version": "0.7.1", "rust_toolchain": "1.98.1", "toolchain_sha256": "2" * 64,
                    "notice_provenance_sha256": "4" * 64}
        envelope = {"schema": 1, "request": request, "run_id": 100, "run_attempt": 2, **metadata}
        release.check_request_envelope(envelope, request, 100, 2, metadata)
        for key, value in [("run_id", 101), ("run_attempt", True), ("schema", True),
                           ("version", "0.7.2"), ("unknown", "x")]:
            changed = copy.deepcopy(envelope)
            changed[key] = value
            with self.assertRaises(policy.PolicyError):
                release.check_request_envelope(changed, request, 100, 2, metadata)

    def test_cli_default_gate_reports_disabled_without_network(self):
        self.assertTrue(hasattr(release, "main"), "CLI missing")
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(release.main(["gate"]), 2)
        self.assertIn("publication disabled", output.getvalue())

    def test_signed_original_publisher_can_fail_after_successful_signing_gate(self):
        self.assertTrue(hasattr(release, "check_publisher_evidence"), "publisher recovery gate missing")
        publisher = self.descriptor["publisher"]
        raw = {"id": 500, "run_attempt": 3, "workflow_id": 400, "path": policy.PUBLISH_WORKFLOW,
               "event": "workflow_run", "head_sha": fixtures.R, "head_branch": "master",
               "repository": {"full_name": policy.REPOSITORY}, "status": "completed", "conclusion": "failure"}
        jobs = [{"name": name, "run_id": 500, "status": "completed", "conclusion": "success"}
                for name in ("Validate completed build", "Attest verified content")]
        release.check_publisher_evidence(raw, jobs, publisher)
        raw["conclusion"] = "cancelled"
        release.check_publisher_evidence(raw, jobs, publisher)
        jobs[1]["conclusion"] = "failure"
        with self.assertRaises(policy.PolicyError):
            release.check_publisher_evidence(raw, jobs, publisher)

    def test_tar_metadata_expansion_is_bounded_before_tar_parser(self):
        raw = self.tar_archive(pax={"comment": "x" * 200000})
        with patch.object(release, "MAX_TOTAL", 16384), self.assertRaises(policy.PolicyError):
            release.inspect_archive(X86, raw, C, "0.7.1", b"license")

    def test_trigger_requires_completed_canonical_exact_run_attempt(self):
        event = {"action": "completed", "repository": {"full_name": policy.REPOSITORY},
                 "workflow_run": dict(fixtures.run_fixture())}
        self.assertEqual(release.check_trigger(event), (100, 2))
        for field, value in [("id", True), ("run_attempt", 0), ("event", "push"),
                             ("conclusion", "failure"), ("status", "in_progress")]:
            changed = copy.deepcopy(event)
            changed["workflow_run"][field] = value
            with self.subTest(field=field), self.assertRaises(policy.PolicyError):
                release.check_trigger(changed)
        event["action"] = "requested"
        with self.assertRaises(policy.PolicyError):
            release.check_trigger(event)

    def test_historical_build_proof_does_not_fetch_expiring_artifacts(self):
        class Api:
            prefix = "/repos/" + policy.REPOSITORY
            def get(self, path):
                if "/workflows/" in path:
                    return {"id": 200, "path": policy.BUILD_WORKFLOW}
                return api_run_fixture()
            def pages(self, path, key):
                if "/artifacts" in path:
                    raise AssertionError("historical proof must not query ephemeral artifacts")
                return [{"name": name, "run_id": 100, "status": "completed", "conclusion": "success"}
                        for name in release.REQUIRED_JOBS]
            def contents(self, path, ref):
                return (ROOT / path).read_bytes()
        request = policy.merged_request(fixtures.pr_fixture(), 42)
        result = release.build_run_evidence(Api(), request, 100, 2, {"build_workflow_id": 200})
        self.assertEqual(result["id"], 100)
        with self.assertRaises(policy.PolicyError):
            release.build_run_evidence(Api(), request, 100, 3, {"build_workflow_id": 200})

    def test_published_prepare_reuses_signed_assets_without_ephemeral_artifact(self):
        test = self
        class Api:
            prefix = "/repos/" + policy.REPOSITORY
            def get(self, path):
                return api_run_fixture()
            def read_release(self, tag):
                test.assertEqual(tag, test.descriptor["tag"])
                return test.existing()
        request = policy.merged_request(fixtures.pr_fixture(), 42)
        with patch.object(release, "resolve_request", return_value=request), \
             patch.object(release, "source_metadata", return_value={"version": "0.7.1"}), \
             patch.object(release, "build_run_evidence", return_value=fixtures.run_fixture()), \
             patch.object(release, "verify_release") as verify, \
             patch.object(release, "build_evidence", side_effect=AssertionError("artifact expired")):
            descriptor, files, action, attest = release.prepare_release(Api(), 100, 2, {}, {}, "gh")
        self.assertEqual(descriptor, self.descriptor)
        self.assertEqual(files, self.files)
        self.assertEqual(action, "already-published")
        self.assertFalse(attest)
        verify.assert_called_once()

    def test_real_minimal_api_repository_shape_uses_canonical_url(self):
        # Captured REST shape: canonical run 40239937252/attempts/1, 2026-10-26.
        raw = {"id": 1328564271, "url": "https://api.github.com/repos/" + policy.REPOSITORY,
               "name": "wiresock-boringtun"}
        self.assertEqual(release.project_repository(raw), {"full_name": policy.REPOSITORY})
        for key, value in [("id", True), ("name", "different"),
                           ("url", "https://api.github.com.evil/repos/" + policy.REPOSITORY),
                           ("url", "https://api.github.com/repos/" + policy.REPOSITORY + "?x=1"),
                           ("full_name", "someone/else")]:
            changed = dict(raw, **{key: value})
            with self.subTest(key=key), self.assertRaises(policy.PolicyError):
                release.project_repository(changed)

    def test_request_and_checksum_zip_members_have_small_preparse_bounds(self):
        for name, size in [("REQUEST.json", 65537), ("RELEASE.json", 65537), ("SHA256SUMS", 4097)]:
            raw = self.zip([(name, b"x" * size, stat.S_IFREG | 0o644)])
            with self.subTest(name=name), self.assertRaises(policy.PolicyError):
                release.safe_zip(raw, {name})

    def test_reconciliation_reports_missing_build_and_recipe_failure_without_writes(self):
        class Api:
            prefix = "/repos/" + policy.REPOSITORY
            def get(self, _path):
                return api_run_fixture()
            def pages(self, path, key=None):
                if "/pulls?" in path:
                    return [{"number": 42, "merged_at": "2026-10-25T12:00:00Z"},
                            {"number": 43, "merged_at": "2026-10-25T12:00:00Z"}]
                return [api_run_fixture()]
            def read_release(self, tag):
                return None
        def resolve(_api, number, _retained=None):
            request = policy.merged_request(fixtures.pr_fixture(), 42)
            request["pr"] = number
            return request
        with patch.object(release, "resolve_request", side_effect=resolve), \
             patch.object(release, "source_metadata", return_value={"version": "0.7.1"}), \
             patch.object(release, "build_evidence", side_effect=policy.PolicyError("historical recipe differs")):
            result = release.reconcile(Api(), "2026-10-25T00:00:00Z", {}, "gh")
        self.assertEqual([item["status"] for item in result["requests"]], ["blocked_build", "blocked_missing_build"])
        self.assertIn("historical recipe differs", result["requests"][0]["reason"])
        self.assertFalse(result["writes_performed"])

    def test_prepared_zip_bounds_member_count_before_descriptor_read(self):
        raw = self.zip([("RELEASE.json", self.files["RELEASE.json"], stat.S_IFREG | 0o644),
                        *[(f"extra-{index}", b"x", stat.S_IFREG | 0o644) for index in range(10)]])
        with self.assertRaises(policy.PolicyError):
            release.prepared_zip(raw)
        valid = self.zip([(name, content, stat.S_IFREG | 0o644) for name, content in self.files.items()])
        self.assertEqual(release.prepared_zip(valid), self.files)

    def test_new_build_attempt_compares_archive_bytes_with_published_release(self):
        for item in self.descriptor["archives"]:
            item["notice_sha256"] = release.digest(b"notices")
        self.files["RELEASE.json"] = policy.canonical_bytes(self.descriptor)
        test = self
        run = fixtures.run_fixture()
        run["run_attempt"] = 3
        artifact = fixtures.artifact_fixture()
        artifact.update(name="boringtun-100-3", size_in_bytes=3, digest="sha256:" + release.digest(b"zip"))
        request = policy.merged_request(fixtures.pr_fixture(), 42)
        metadata = {key: self.descriptor[key] for key in
                    ("version", "rust_toolchain", "toolchain_sha256", "notice_provenance_sha256")}
        fresh = {name: self.files[name] for name in fixtures.TARGET_NAMES.values()}
        fresh[X86] = b"different reproducible output"
        fresh["SHA256SUMS"] = "".join(f"{release.digest(data)}  {name}\n" for name, data in sorted(fresh.items())).encode()
        fresh["REQUEST.json"] = release.json_bytes(dict(schema=1, request=request, run_id=100, run_attempt=3, **metadata))
        class Api:
            prefix = "/repos/" + policy.REPOSITORY
            def get(self, path):
                return dict(api_run_fixture(), run_attempt=3)
            def read_release(self, tag):
                return test.existing()
            def request(self, *_args, **_kwargs):
                return b"zip"
            def contents(self, *_args):
                return b"license"
        def archive(name, raw, *_args):
            original = next(item for item in test.descriptor["archives"] if item["name"] == name)
            return dict(original, sha256=release.digest(raw)), b"notices"
        publisher = fixtures.publisher_fixture()
        for key in metadata:
            publisher.pop(key)
        with patch.object(release, "resolve_request", return_value=request), \
             patch.object(release, "source_metadata", return_value=metadata), \
             patch.object(release, "build_run_evidence", return_value=run), \
             patch.object(release, "build_evidence", return_value=(run, artifact)) as evidence, \
             patch.object(release, "safe_zip", return_value=fresh), \
             patch.object(release, "inspect_archive", side_effect=archive), \
             patch.object(release, "static_archive_gate"), patch.object(release, "verify_release"):
            with self.assertRaises(policy.PolicyError):
                release.prepare_release(Api(), 100, 3, publisher, {}, "gh")
            evidence.assert_called_once()

    def test_pagination_refuses_partial_filtered_run_inventory(self):
        class Api(release.GitHub):
            def get(self, path):
                return {"total_count": 1001, "workflow_runs": [api_run_fixture()]}
        with self.assertRaises(policy.PolicyError):
            Api().pages("/actions/runs?created=test", "workflow_runs")

    def test_reconciliation_keeps_active_build_separate_from_recovery_gaps(self):
        run = dict(api_run_fixture(), status="in_progress", conclusion=None)
        class Api:
            prefix = "/repos/" + policy.REPOSITORY
            def pages(self, path, key=None):
                return ([{"number": 42, "merged_at": "2026-10-25T12:00:00Z"}]
                        if "/pulls?" in path else [run])
            def get(self, path):
                return {"id": 200, "path": policy.BUILD_WORKFLOW} if "/workflows/" in path else run
            def read_release(self, _tag):
                return None
        request = policy.merged_request(fixtures.pr_fixture(), 42)
        with patch.object(release, "resolve_request", return_value=request), \
             patch.object(release, "source_metadata", return_value={"version": "0.7.1"}), \
             patch.object(release, "build_evidence", side_effect=AssertionError("active build must not enter promotion")):
            result = release.reconcile(Api(), "2026-10-25T00:00:00Z", {"build_workflow_id": 200}, "gh")
        self.assertEqual(result["requests"][0]["status"], "active_build")

    def test_all_five_archive_manifests_bind_platform_and_individual_notices(self):
        hashes = set()
        for target, name in fixtures.TARGET_NAMES.items():
            notices = ("notice for " + target).encode()
            record, actual = release.inspect_archive(name, self.tar_archive(target=target, notices=notices), C, "0.7.1", b"license")
            self.assertEqual(actual, notices)
            self.assertEqual(record["notice_sha256"], release.digest(notices))
            hashes.add(record["notice_sha256"])
            for key in ("os", "arch", "libc", "linkage"):
                with self.subTest(target=target, field=key), self.assertRaises(policy.PolicyError):
                    release.inspect_archive(name, self.tar_archive(target=target, fields={key: "wrong"}), C, "0.7.1", b"license")
        self.assertEqual(len(hashes), 5)

    def test_prepared_directory_requires_exact_seven_regular_assets(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as directory:
            root = Path(directory)
            for name, raw in self.files.items():
                (root / name).write_bytes(raw)
            self.assertEqual(release.read_prepared(root), (self.descriptor, self.files))
            (root / fixtures.MAC_ARM).unlink()
            with self.assertRaises(policy.PolicyError):
                release.read_prepared(root)

    def test_fresh_preparation_accepts_five_distinct_platform_notice_bundles(self):
        request = policy.merged_request(fixtures.pr_fixture(), 42)
        metadata = {key: self.descriptor[key] for key in
                    ("version", "rust_toolchain", "toolchain_sha256", "notice_provenance_sha256")}
        files = {name: self.tar_archive(target=target, notices=target.encode())
                 for target, name in fixtures.TARGET_NAMES.items()}
        files["SHA256SUMS"] = "".join(f"{release.digest(raw)}  {name}\n" for name, raw in sorted(files.items())).encode()
        files["REQUEST.json"] = release.json_bytes(dict(schema=1, request=request, run_id=100, run_attempt=2, **metadata))
        raw_zip = self.zip([(name, raw, stat.S_IFREG | 0o644) for name, raw in files.items()])
        artifact = fixtures.artifact_fixture()
        artifact.update(digest="sha256:" + release.digest(raw_zip), size_in_bytes=len(raw_zip))
        publisher = fixtures.publisher_fixture()
        for key in metadata:
            publisher.pop(key)
        class Api:
            prefix = "/repos/" + policy.REPOSITORY
            def get(self, _path):
                return api_run_fixture()
            def request(self, *_args, **_kwargs):
                return raw_zip
            def contents(self, *_args):
                return b"license"
            def read_release(self, _tag):
                return None
        with patch.object(release, "resolve_request", return_value=request), \
             patch.object(release, "source_metadata", return_value=metadata), \
             patch.object(release, "build_run_evidence", return_value=fixtures.run_fixture()), \
             patch.object(release, "build_evidence", return_value=(fixtures.run_fixture(), artifact)), \
             patch.object(release, "static_archive_gate"):
            descriptor, prepared, action, attest = release.prepare_release(Api(), 100, 2, publisher, {}, "gh")
        self.assertEqual(len(prepared), 7)
        self.assertEqual(action, "create")
        self.assertTrue(attest)
        self.assertNotIn("notice_sha256", descriptor)
        self.assertEqual({item["target"]: item["notice_sha256"] for item in descriptor["archives"]},
                         {target: release.digest(target.encode()) for target in fixtures.TARGET_NAMES})

    def test_prepared_metadata_is_bounded_before_json_parsing(self):
        for name, limit in (("RELEASE.json", 65536), ("SHA256SUMS", 4096)):
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=ROOT / "tests") as directory:
                root = Path(directory)
                for filename, raw in self.files.items():
                    (root / filename).write_bytes(raw)
                (root / name).write_bytes(b" " * (limit + 1))
                with patch.object(policy, "load_json", side_effect=AssertionError("must reject before parsing")), \
                     self.assertRaises(policy.PolicyError):
                    release.read_prepared(root)


class RepositoryIdentityTests(unittest.TestCase):
    """Independent regressions; no release-schema fixture required."""
    def pr(self):
        value = fixtures.pr_fixture()
        run = api_run_fixture()
        value["base"] = copy.deepcopy(run["pull_requests"][0]["base"])
        value["head"] = copy.deepcopy(run["pull_requests"][0]["head"])
        value["head"]["repo"]["id"] = 900
        return value

    def test_deleted_contributor_uses_exact_run_identity_without_looking_up_old_name(self):
        pr = self.pr()
        association = {key: copy.deepcopy(pr[key]) for key in ("number", "base", "head")}
        pr["head"]["repo"] = None
        checked = release.project_pr(pr, association, 1328564271)
        self.assertEqual(checked["head"], fixtures.pr_fixture()["head"])
        self.assertEqual(policy.merged_request(checked, 42)["source_commit"], C)

    def test_rename_requires_same_repository_id_and_current_pr_head_sha(self):
        pr = self.pr()
        association = {key: copy.deepcopy(pr[key]) for key in ("number", "base", "head")}
        pr["head"]["repo"].update(name="renamed", url="https://api.github.com/repos/new-owner/renamed")
        self.assertEqual(release.project_pr(pr, association, 1328564271)["head"], fixtures.pr_fixture()["head"])
        for mutation in ("id", "sha", "pr", "base"):
            changed = copy.deepcopy(pr)
            old = copy.deepcopy(association)
            if mutation == "id":
                changed["head"]["repo"]["id"] = 901
            elif mutation == "sha":
                changed["head"]["sha"] = "f" * 40
            elif mutation == "pr":
                old["number"] = 43
            else:
                old["base"]["repo"]["id"] = 900
            with self.subTest(mutation=mutation), self.assertRaises(policy.PolicyError):
                release.project_pr(changed, old, 1328564271)

    def test_resolve_retained_identity_checks_canonical_numeric_id_and_ancestry(self):
        pr = self.pr()
        run = api_run_fixture()
        run["pull_requests"][0]["head"] = copy.deepcopy(pr["head"])
        run["repository"]["id"] = 1328564271
        pr["head"]["repo"] = None
        class Api:
            prefix = "/repos/" + policy.REPOSITORY
            def get(self, path):
                if "/pulls/" in path:
                    return pr
                if "/compare/" in path:
                    return {"status": "ahead", "merge_base_commit": {"sha": C}}
                return {"id": 1328564271, "full_name": policy.REPOSITORY}
        request = release.resolve_request(Api(), 42, run)
        self.assertEqual(request["pr_head_repository"], "contributor/fork")
        self.assertEqual(request["source_commit"], C)
        run["repository"]["id"] = 1
        with self.assertRaises(policy.PolicyError):
            release.resolve_request(Api(), 42, run)


if __name__ == "__main__":
    unittest.main()
