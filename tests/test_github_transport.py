"""Exercise the real REST adapter; replace only its network opener."""
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import boringtun_release as release
import boringtun_release_policy as policy

SOURCE = "4145b2d954e60e9a1d1b5f547b7f4552756beab0"
LEGACY = "wiresock/awg-server-tools"


class GitHubTransportTests(unittest.TestCase):
    def setUp(self):
        self.api = release.GitHub(token="test-token", legacy_repository=LEGACY)
        self.api.opener = Mock()
        self.api.opener.open.side_effect = lambda *a, **kw: io.BytesIO(b'{"ok":true}')

    def assert_rejected(self, path, method="GET", **kwargs):
        self.api.opener.reset_mock()
        with self.assertRaises(policy.PolicyError):
            self.api.request(method, path, **kwargs)
        self.api.opener.open.assert_not_called()

    def test_compare_full_source_to_expected_branch_reaches_transport(self):
        for repository, branch in ((policy.REPOSITORY, "master"), (LEGACY, "main")):
            path = f"/repos/{repository}/compare/{SOURCE}...{branch}"
            with self.subTest(repository=repository):
                self.assertEqual(self.api.get(path), {"ok": True})
                request = self.api.opener.open.call_args.args[0]
                self.assertEqual(request.full_url, "https://api.github.com" + path)
                self.assertEqual(request.get_method(), "GET")
                self.assertEqual(request.get_header("Authorization"), "Bearer test-token")

    def test_compare_cannot_select_arbitrary_refs_or_delimiters(self):
        tails = ("master...master", SOURCE[:12] + "...master", SOURCE.upper() + "...master",
                 SOURCE + "...main", SOURCE + "..master", SOURCE + "....master",
                 SOURCE + "...refs/heads/master", SOURCE + "...other:master",
                 SOURCE + "...master/extra", SOURCE + "...master?ref=other",
                 SOURCE + "...master?", SOURCE + "...master#ignored",
                 SOURCE + "%2e%2e%2emaster", SOURCE + "...master;ignored")
        for tail in tails:
            with self.subTest(tail=tail):
                self.assert_rejected(self.api.prefix + "/compare/" + tail)
        self.assert_rejected(f"/repos/{LEGACY}/compare/{SOURCE}...master")

    def test_compare_is_read_only_and_not_an_upload_or_download_route(self):
        path = self.api.prefix + f"/compare/{SOURCE}...master"
        for method in ("POST", "PATCH", "DELETE"):
            with self.subTest(method=method):
                self.assert_rejected(path, method)
        for options in ({"upload": True}, {"body": {}}, {"binary": True}):
            with self.subTest(options=options):
                self.assert_rejected(path, **options)

    def test_path_traversal_and_ambiguous_encodings_never_reach_transport(self):
        tails = ("../other", "./contents/LICENSE.md", "contents/../releases", "contents/./LICENSE.md",
                 "contents//LICENSE.md", "contents/%2e%2e/releases", "contents/%2E%2E/releases",
                 "contents/.%2e/releases", "contents/%252e%252e/releases",
                 "contents/%2f../releases", "contents/%252f../releases", "contents/%5c../releases",
                 "contents/\\other", "contents/LICENSE.md#other", "contents/LICENSE.md\r\nX: y",
                 "contents/LICENSE.md\t", "contents/LICENSE.md%00", "contents/LICENSE.md;other")
        for tail in tails:
            with self.subTest(tail=tail):
                self.assert_rejected(self.api.prefix + "/" + tail)

    def test_wrong_repository_or_origin_never_receives_credentials(self):
        for path in ("https://api.github.com" + self.api.prefix,
                     "https://evil.example" + self.api.prefix, "//evil.example" + self.api.prefix,
                     self.api.prefix + "-evil/releases", "/repos/other/repository/releases",
                     self.api.prefix + "@evil.example/releases", self.api.prefix + "/../../other"):
            with self.subTest(path=path):
                self.assert_rejected(path)

    def test_existing_read_and_release_routes_keep_their_exact_host_and_query(self):
        cases = (("GET", self.api.prefix, {}),
                 ("GET", self.api.prefix + "/contents/.github/workflows/boringtun-release.yml?ref=" + SOURCE, {}),
                 ("GET", self.api.prefix + "/actions/runs/123/jobs?per_page=100&page=2", {}),
                 ("GET", self.api.prefix + "/actions/workflows/build.yml/runs?event=push&created=%3E%3D2026-10-26", {}),
                 ("GET", self.api.prefix + "/releases/tags/v0.7.1-pr97-" + SOURCE, {}),
                 ("POST", self.api.prefix + "/releases", {"body": {"draft": True}}),
                 ("PATCH", self.api.prefix + "/releases/123", {"body": {"draft": False}}),
                 ("POST", self.api.prefix + "/releases/123/assets?name=RELEASE.json", {"body": b"{}", "upload": True}))
        for method, path, options in cases:
            with self.subTest(method=method, path=path):
                self.assertEqual(self.api.request(method, path, **options), {"ok": True})
                request = self.api.opener.open.call_args.args[0]
                host = "uploads.github.com" if options.get("upload") else "api.github.com"
                self.assertEqual(request.full_url, "https://" + host + path)
                self.assertEqual(request.get_method(), method)


if __name__ == "__main__":
    unittest.main()
