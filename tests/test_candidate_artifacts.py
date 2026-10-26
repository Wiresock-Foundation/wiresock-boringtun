"""Candidate retry metadata policy and bounded APT behavior, without network."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts/boringtun_candidate_artifact.py"
resolver = None
if MODULE.exists():
    spec = importlib.util.spec_from_file_location("candidate_artifacts", MODULE)
    resolver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(resolver)

C = "a" * 40
REPO = "Wiresock-Foundation/wiresock-boringtun"
WORKFLOW = ".github/workflows/boringtun-platform-validation.yml"


def job(attempt=1, name="Candidate licenses and source checks", conclusion="success"):
    return {"id": 100 + attempt, "run_id": 10, "run_attempt": attempt,
            "head_sha": C, "name": name, "status": "completed", "conclusion": conclusion,
            "started_at": "2026-10-26T15:00:00Z", "completed_at": "2026-10-26T15:05:00Z"}


def artifact(attempt=1, kind="notices", target=None):
    prefix = "candidate-notices" if kind == "notices" else "candidate-archive-" + target
    return {"id": 200 + attempt, "name": f"{prefix}-10-{attempt}", "expired": False,
            "digest": "sha256:" + "b" * 64, "created_at": "2026-10-26T15:04:59Z",
            "workflow_run": {"id": 10, "head_sha": C, "repository_id": 1000, "head_repository_id": 1001}}


class CandidateArtifactTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(resolver, "candidate artifact resolver is missing")
        self.run = {"id": 10, "run_attempt": 2, "head_sha": C, "event": "pull_request",
                    "path": WORKFLOW, "repository": {"id": 1000, "full_name": REPO},
                    "head_repository": {"id": 1001}}
        self.context = {"repository": REPO, "run_id": 10, "attempt": 2, "head": C}

    def select(self, jobs=None, artifacts=None, **kwargs):
        return resolver.select_artifact(self.run, jobs if jobs is not None else [job()],
                                        artifacts if artifacts is not None else [artifact()],
                                        self.context, "notices", **kwargs)

    def test_partial_retry_uses_successful_originating_attempt(self):
        selected = self.select()
        self.assertEqual(selected["artifact_id"], 201)
        self.assertEqual(selected["producer_job_id"], 101)
        self.assertEqual(selected["producer_attempt"], 1)
        self.assertEqual(selected["consumer_attempt"], 2)
        self.assertEqual(selected["digest"], "sha256:" + "b" * 64)

    def test_recorded_github_producer_metadata_survives_consumer_retry(self):
        fixture = json.loads((ROOT / "tests/fixtures/candidate-retry-metadata.json").read_text())
        run = fixture["run"]
        run["run_attempt"] = 2  # Retry the failed consumer; the captured producer is unchanged.
        context = {"repository": REPO, "run_id": run["id"], "attempt": 2, "head": run["head_sha"]}
        selected = resolver.select_artifact(run, fixture["jobs"], fixture["artifacts"], context, "notices")
        self.assertEqual(selected["artifact_id"], 12665186712)
        self.assertEqual(selected["producer_job_id"], 121676867759)
        self.assertEqual(selected["producer_attempt"], 1)

    def test_all_jobs_rerun_uses_new_producer_not_old_artifact(self):
        selected = self.select([job(), job(2)], [artifact(), artifact(2)])
        self.assertEqual(selected["artifact_id"], 202)
        self.assertEqual(selected["producer_job_id"], 102)

    def test_mixed_matrix_retry_resolves_each_platform_producer(self):
        for target, label in [("linux-x86_64", "linux-x86_64"), ("linux-aarch64", "linux-aarch64"),
                              ("linux-armv7", "linux-armv7-cross"), ("macos-x86_64", "macos-x86_64"),
                              ("macos-aarch64", "macos-aarch64")]:
            with self.subTest(target=target):
                selected = resolver.select_artifact(
                    self.run, [job(name=f"Candidate build ({label})"), job(2)],
                    [artifact(kind="archive", target=target)], self.context, "archive", target)
                self.assertEqual(selected["producer_attempt"], 1)
                self.assertEqual(selected["artifact_id"], 201)

    def test_new_failed_or_running_producer_never_falls_back(self):
        for status, conclusion in [("completed", "failure"), ("completed", "cancelled"),
                                   ("in_progress", None), ("completed", "skipped")]:
            newer = job(2, conclusion=conclusion)
            newer["status"] = status
            with self.subTest(status=status, conclusion=conclusion), self.assertRaises(ValueError):
                self.select([job(), newer], [artifact(), artifact(2)])

    def test_missing_new_artifact_never_falls_back_to_older_success(self):
        with self.assertRaises(ValueError):
            self.select([job(), job(2)], [artifact()])

    def test_missing_or_ambiguous_producer_and_artifact_fail_closed(self):
        for jobs, artifacts in [([], [artifact()]), ([job(), job()], [artifact()]),
                                ([job()], []), ([job()], [artifact(), artifact()])]:
            with self.subTest(jobs=jobs, artifacts=artifacts), self.assertRaises(ValueError):
                self.select(jobs, artifacts)

    def test_stale_expired_or_invalid_artifact_is_rejected(self):
        for key, value in [("created_at", "2026-10-26T14:59:59Z"),
                           ("created_at", "2026-10-26T15:05:01Z"), ("created_at", "invalid"),
                           ("expired", True), ("digest", None), ("id", True)]:
            bad = artifact()
            bad[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.select(artifacts=[bad])

    def test_artifact_cannot_substitute_another_run_source_or_repository(self):
        for key, value in [("id", 11), ("head_sha", "c" * 40),
                           ("repository_id", 999), ("head_repository_id", 999)]:
            bad = artifact()
            bad["workflow_run"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.select(artifacts=[bad])

    def test_job_cannot_substitute_another_run_source_or_future_attempt(self):
        for key, value in [("run_id", 11), ("head_sha", "c" * 40),
                           ("run_attempt", 3), ("run_attempt", True), ("id", 0)]:
            bad = job()
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.select(jobs=[bad])

    def test_run_and_caller_identity_must_match_current_candidate_workflow(self):
        for key, value in [("id", 11), ("run_attempt", 1), ("event", "push"),
                           ("path", ".github/workflows/boringtun-artifacts.yml"), ("head_sha", "c" * 40)]:
            original = self.run[key]
            self.run[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.select()
            self.run[key] = original
        self.context["repository"] = "another/repository"
        with self.assertRaises(ValueError):
            self.select()

    def test_unknown_artifact_kind_or_platform_is_rejected(self):
        for kind, target in [("release", None), ("archive", "../other"), ("notices", "linux-x86_64")]:
            with self.subTest(kind=kind, target=target), self.assertRaises(ValueError):
                resolver.select_artifact(self.run, [job()], [artifact()], self.context, kind, target)

    def test_pagination_reaches_origin_and_rechecks_current_run(self):
        unrelated = [dict(job(name="unrelated"), id=1000 + i) for i in range(100)]
        calls = []
        def get(path):
            calls.append(path)
            if path == "actions/runs/10":
                return copy.deepcopy(self.run)
            if path == "actions/runs/10/jobs?filter=all&per_page=100&page=1":
                return {"total_count": 101, "jobs": unrelated}
            if path == "actions/runs/10/jobs?filter=all&per_page=100&page=2":
                return {"total_count": 101, "jobs": [job()]}
            if path == "actions/runs/10/artifacts?per_page=100&page=1":
                return {"total_count": 1, "artifacts": [artifact()]}
            self.fail("unexpected request: " + path)
        selected = resolver.resolve_artifact(get, self.context, "notices")
        self.assertEqual(selected["artifact_id"], 201)
        self.assertEqual(calls.count("actions/runs/10"), 2)

    def test_pagination_missing_or_repeated_records_is_rejected(self):
        for items, count in [([], 1), ([artifact(), artifact()], 2)]:
            with self.subTest(count=count), self.assertRaises(ValueError):
                resolver.list_pages(lambda _: {"total_count": count, "artifacts": items},
                                    "actions/runs/10/artifacts", "artifacts")

    def test_a_new_retry_during_resolution_invalidates_result(self):
        reads = 0
        def get(path):
            nonlocal reads
            if path == "actions/runs/10":
                reads += 1
                return dict(self.run, run_attempt=2 if reads == 1 else 3)
            if "/jobs?" in path:
                return {"total_count": 1, "jobs": [job()]}
            return {"total_count": 1, "artifacts": [artifact()]}
        with self.assertRaises(ValueError):
            resolver.resolve_artifact(get, self.context, "notices")


@unittest.skipIf(os.name == "nt", "APT helper behavior runs under Linux/WSL")
class AptSetupTests(unittest.TestCase):
    def invoke(self, packages, update_failure=False, install_failure=False):
        helper = ROOT / "scripts/boringtun-ci-apt.sh"
        self.assertTrue(helper.is_file(), "bounded candidate APT helper is missing")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            record = base / "calls.jsonl"
            sudo = base / "sudo"
            sudo.write_text("#!/usr/bin/env python3\nimport json, os, sys\n"
                            "with open(os.environ['APT_TEST_RECORD'], 'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                            "sys.exit(73 if 'update' in sys.argv and os.environ.get('APT_UPDATE_FAIL') else "
                            "74 if 'install' in sys.argv and os.environ.get('APT_INSTALL_FAIL') else 0)\n")
            sudo.chmod(0o755)
            env = dict(os.environ, PATH=str(base) + os.pathsep + os.environ["PATH"],
                       APT_TEST_RECORD=str(record), APT_UPDATE_FAIL="1" if update_failure else "",
                       APT_INSTALL_FAIL="1" if install_failure else "")
            result = subprocess.run(["bash", str(helper), *packages], env=env, capture_output=True, text=True)
            calls = [json.loads(line) for line in record.read_text().splitlines()] if record.exists() else []
            return result, calls

    def test_update_and_install_have_bounded_network_and_lock_waits(self):
        result, calls = self.invoke(["musl-tools", "clang-18"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertEqual(call[0], "apt-get")
            for option in ("Acquire::Retries=2", "Acquire::http::Timeout=30", "Acquire::https::Timeout=30",
                           "DPkg::Lock::Timeout=60"):
                self.assertIn(option, call)
        self.assertIn("APT::Update::Error-Mode=any", calls[0])
        self.assertIn("update", calls[0])
        self.assertEqual(calls[1][-2:], ["musl-tools", "clang-18"])

    def test_update_failure_stops_install_and_install_failure_propagates(self):
        result, calls = self.invoke(["musl-tools"], update_failure=True)
        self.assertEqual(result.returncode, 73)
        self.assertEqual(len(calls), 1)
        result, calls = self.invoke(["musl-tools"], install_failure=True)
        self.assertEqual(result.returncode, 74)
        self.assertEqual(len(calls), 2)

    def test_missing_or_option_like_package_does_not_call_apt(self):
        for packages in ([], ["--allow-unauthenticated"], ["bad;command"]):
            with self.subTest(packages=packages):
                result, calls = self.invoke(packages)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
