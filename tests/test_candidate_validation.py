"""Candidate validation boundaries; no network, builds, or repository writes."""
import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts/boringtun_candidate.py"
candidate = None
if MODULE.exists():
    spec = importlib.util.spec_from_file_location("candidate_validation", MODULE)
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)

C = "a" * 40


class CandidatePinTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(candidate, "candidate pin helper is missing")
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / "tests")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.source = self.base / "source"
        (self.source / "boringtun-cli").mkdir(parents=True)
        (self.source / "packaging/boringtun").mkdir(parents=True)
        (self.source / "boringtun-cli/Cargo.toml").write_text('[package]\nversion = "0.7.2"\n')
        (self.source / "packaging/boringtun/pin.env").write_text(
            "BORINGTUN_REPOSITORY=https://github.com/Wiresock-Foundation/wiresock-boringtun\n"
            "BORINGTUN_COMMIT=" + "b" * 40 + "\nBORINGTUN_VERSION=0.7.1\n"
            "BORINGTUN_RUST_TOOLCHAIN=1.98.1\nBORINGTUN_ARTIFACT_FORMAT=1\n")
        self.temp = self.base / "runner-temp"
        self.temp.mkdir()
        self.output = self.temp / "candidate/pin.env"
        self.dirty = ""

    def git(self, argv, **kwargs):
        self.assertEqual(argv[:3], ["git", "-C", str(self.source)])
        if argv[3:] == ["rev-parse", "--show-toplevel"]:
            value = str(self.source)
        elif argv[3:] == ["rev-parse", "HEAD"]:
            value = C
        elif argv[3:] == ["status", "--porcelain=v1", "--untracked-files=all"]:
            value = self.dirty
        else:
            self.fail("unexpected Git mutation or command: " + repr(argv))
        return subprocess.CompletedProcess(argv, 0, value + ("\n" if value else ""), "")

    def derive(self, expected=C, output=None):
        with patch.object(candidate.subprocess, "run", side_effect=self.git):
            return candidate.write_candidate_pin(self.source, expected, output or self.output, self.temp)

    def test_pin_uses_exact_candidate_head_and_current_cargo_version(self):
        result = self.derive()
        self.assertEqual(result, {"candidate": True, "source": C, "version": "0.7.2", "rust_toolchain": "1.98.1"})
        self.assertIn("BORINGTUN_COMMIT=" + C + "\n", self.output.read_text())
        self.assertIn("BORINGTUN_VERSION=0.7.2\n", self.output.read_text())
        self.assertIn("BORINGTUN_ARTIFACT_FORMAT=1\n", self.output.read_text())
        self.assertNotIn("REQUEST.json", [path.name for path in self.temp.rglob("*")])

    def test_dirty_or_wrong_head_cannot_create_candidate_pin(self):
        for expected, dirty in [("c" * 40, ""), (C, " M boringtun-cli/Cargo.toml"), (C, "?? injected")]:
            self.dirty = dirty
            with self.subTest(expected=expected, dirty=dirty), self.assertRaises(ValueError):
                self.derive(expected)
            self.assertFalse(self.output.exists())

    def test_outputs_must_be_new_and_inside_runner_temp_outside_source(self):
        for output in (self.source / "pin.env", self.base / "escape.env"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                self.derive(output=output)
            self.assertFalse(output.exists())
        self.derive()
        original = self.output.read_bytes()
        with self.assertRaises((ValueError, FileExistsError)):
            self.derive()
        self.assertEqual(self.output.read_bytes(), original)

    def test_pinned_toolchain_and_literal_versions_are_required(self):
        pin = self.source / "packaging/boringtun/pin.env"
        original = pin.read_text()
        for bad in (original.replace("1.98.1", "stable"), original + "EXTRA=unsafe\n",
                    original + "BORINGTUN_VERSION=0.7.1\n"):
            pin.write_text(bad)
            with self.assertRaises(ValueError):
                self.derive()
        pin.write_text(original)
        (self.source / "boringtun-cli/Cargo.toml").write_text('[package]\nversion = "0.7.2;echo bad"\n')
        with self.assertRaises(ValueError):
            self.derive()


class CandidateWorkflowTests(unittest.TestCase):
    def read(self):
        path = ROOT / ".github/workflows/boringtun-platform-validation.yml"
        self.assertTrue(path.is_file(), "candidate platform workflow is missing")
        return path.read_text()

    def test_candidate_workflow_has_no_publication_or_privileged_trigger(self):
        text = self.read()
        self.assertIn("name: BoringTun candidate platform validation", text)
        self.assertIn("types: [opened, synchronize, reopened]", text)
        for forbidden in ("pull_request_target:", "workflow_run:", "id-token:", "attestations:",
                          "contents: write", "secrets.", "boringtun_release.py", "RELEASE.json", "REQUEST.json"):
            self.assertNotIn(forbidden, text)
        self.assertNotIn("pull_request.draft", text)
        self.assertEqual(text.count("permissions:\n"), text.count("contents: read"))
        self.assertNotIn("actions/cache", text)
        self.assertIn("cache: false", text)
        publisher = (ROOT / ".github/workflows/boringtun-release.yml").read_text()
        self.assertNotIn("BoringTun candidate platform validation", publisher)

    def test_exact_head_five_targets_production_helpers_and_candidate_artifacts(self):
        text = self.read()
        self.assertEqual(text.count("ref: ${{ github.event.pull_request.head.sha }}"), 3)
        self.assertEqual(text.count("persist-credentials: false"), 4)
        self.assertIn("--expected-head \"$EXPECTED_HEAD\"", text)
        for target in ("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl", "armv7-unknown-linux-musleabihf",
                       "x86_64-apple-darwin", "aarch64-apple-darwin"):
            self.assertIn("target: " + target, text)
        for runner in ("ubuntu-24.04", "ubuntu-24.04-arm", "macos-15-intel", "macos-15"):
            self.assertIn("runner: " + runner, text)
        for command in ("licenses source", "build source", "package", "verify-archive", "device-smoke"):
            self.assertIn("boringtun-artifact.sh " + command, text)
        self.assertIn("cmp \"$RUNNER_TEMP/build-1/boringtun-cli\" \"$RUNNER_TEMP/build-2/boringtun-cli\"", text)
        self.assertIn("cmp \"$RUNNER_TEMP\"/dist/*.tar.gz \"$RUNNER_TEMP\"/package-2/*.tar.gz", text)
        self.assertIn("linux-armv7-emulated", text)
        self.assertIn("/usr/bin/qemu-arm", text)
        self.assertIn("scripts/awg-go-interop.sh", text)
        self.assertIn("scripts/awg31-interop.sh", text)
        for name in re.findall(r"^\s+name: (.+\$\{\{ github.run_id \}\}.+)$", text, re.M):
            self.assertTrue(name.startswith("candidate-"), name)

    def test_actions_are_immutable_and_downloads_stay_in_this_run(self):
        text = self.read()
        actions = re.findall(r"\buses: ([^\s#]+)", text)
        self.assertTrue(actions)
        for action in actions:
            self.assertRegex(action, r"^actions/[a-z-]+@[0-9a-f]{40}$")
        self.assertNotIn("run-id:", text)
        self.assertNotIn("github-token:", text)
        self.assertNotIn("overwrite:", text)


if __name__ == "__main__":
    unittest.main()
