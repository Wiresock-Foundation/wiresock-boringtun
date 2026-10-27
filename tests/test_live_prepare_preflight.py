"""Diagnostic source cleanliness and local subprocess credential boundaries."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import live_prepare_preflight as preflight
import boringtun_release as release


@unittest.skipUnless(shutil.which("git"), "Git is required for real checkout tests")
class CleanCheckoutTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.git("init", "--quiet")
        (self.root / "helper.sh").write_text("original\n")
        (self.root / ".gitignore").write_text("ignored.tmp\n")
        self.git("add", "helper.sh", ".gitignore")
        self.git("-c", "user.name=Preflight Test", "-c", "user.email=preflight@example.invalid",
                 "commit", "--quiet", "-m", "fixture")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)

    def test_clean_checkout_accepts_then_rejects_tracked_edit_at_same_head(self):
        preflight.require_clean_checkout(self.root)
        original_head = self.git("rev-parse", "HEAD").stdout
        (self.root / "helper.sh").write_text("modified\n")
        self.assertEqual(self.git("rev-parse", "HEAD").stdout, original_head)
        with self.assertRaises(release.policy.PolicyError):
            preflight.require_clean_checkout(self.root)

    def test_staged_change_rejected(self):
        (self.root / "helper.sh").write_text("modified\n")
        self.git("add", "helper.sh")
        with self.assertRaises(release.policy.PolicyError):
            preflight.require_clean_checkout(self.root)

    def test_untracked_and_ignored_files_rejected(self):
        for name in ("untracked.py", "ignored.tmp"):
            with self.subTest(name=name):
                path = self.root / name
                path.write_text("unreviewed\n")
                with self.assertRaises(release.policy.PolicyError):
                    preflight.require_clean_checkout(self.root)
                path.unlink()


class LocalCredentialTests(unittest.TestCase):
    def test_static_verifier_gets_source_pin_without_network_credentials(self):
        tokens = {name: "secret-" + name for name in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN",
                  "GITHUB_ENTERPRISE_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN")}
        def child(_arguments, *, env, **_options):
            self.assertFalse(set(tokens).intersection(env))
            self.assertIn("BORINGTUN_COMMIT=" + "a" * 40, Path(env["BORINGTUN_PIN_FILE"]).read_text())
            self.assertEqual(os.environ["GH_TOKEN"], tokens["GH_TOKEN"], "API credential was changed globally")
        with patch.dict(os.environ, tokens), patch.object(release.subprocess, "run", side_effect=child) as run:
            release.static_archive_gate({"fixture.tar.gz": b"archive"}, {"source_commit": "a" * 40, "pr": 99}, "0.7.1")
            run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
