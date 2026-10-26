"""Exercise the real REST adapter; replace only its network opener."""
import io
from pathlib import Path
import sys
import unittest
import urllib.error
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

    def test_actions_zip_negotiates_json_but_returns_unparsed_binary(self):
        payload = b"PK\x03\x04\xff\x00archive"
        def serve(request, **_options):
            if request.get_header("Accept") != "application/vnd.github+json":
                raise urllib.error.HTTPError(request.full_url, 415, "Unsupported Accept header", {}, io.BytesIO())
            return io.BytesIO(payload)
        self.api.opener.open.side_effect = serve
        self.assertEqual(self.api.request("GET", self.api.prefix + "/actions/artifacts/12681307359/zip",
                                          binary=True), payload)

    def test_actions_zip_redirect_keeps_json_api_header_and_strips_auth_at_storage(self):
        payload = b"PK\x03\x04\xffarchive"
        destination = "https://example.blob.core.windows.net/artifacts/archive.zip?sig=test"
        def serve(request, **_options):
            if request.full_url == destination:
                self.assertIsNone(request.get_header("Authorization"))
                self.assertIsNone(request.get_header("Accept"))
                return io.BytesIO(payload)
            self.assertEqual(request.get_header("Accept"), "application/vnd.github+json")
            self.assertEqual(request.get_header("Authorization"), "Bearer test-token")
            raise urllib.error.HTTPError(request.full_url, 302, "Found", {"Location": destination}, io.BytesIO())
        self.api.opener.open.side_effect = serve
        self.assertEqual(self.api.request("GET", self.api.prefix + "/actions/artifacts/123/zip", binary=True), payload)
        self.assertEqual(self.api.opener.open.call_count, 2)

    def test_release_asset_retains_octet_stream_for_direct_and_redirected_downloads(self):
        payload = b"\xffrelease-asset"
        for redirect in (False, True):
            with self.subTest(redirect=redirect):
                destination = "https://release-assets.githubusercontent.com/asset"
                def serve(request, **_options):
                    if request.full_url == destination:
                        self.assertIsNone(request.get_header("Authorization"))
                        return io.BytesIO(payload)
                    self.assertEqual(request.get_header("Accept"), "application/octet-stream")
                    if redirect:
                        raise urllib.error.HTTPError(request.full_url, 302, "Found", {"Location": destination}, io.BytesIO())
                    return io.BytesIO(payload)
                self.api.opener.open.side_effect = serve
                self.assertEqual(self.api.request("GET", self.api.prefix + "/releases/assets/123", binary=True), payload)

    def test_binary_redirect_does_not_broaden_storage_authority(self):
        for destination in ("http://example.blob.core.windows.net/file", "https://evil.example/file",
                            "https://release-assets.githubusercontent.com.evil.example/file",
                            "https://user:pass@example.blob.core.windows.net/file",
                            "https://example.blob.core.windows.net:444/file"):
            with self.subTest(destination=destination):
                self.api.opener.reset_mock()
                self.api.opener.open.side_effect = urllib.error.HTTPError(
                    "https://api.github.com" + self.api.prefix, 302, "Found", {"Location": destination}, io.BytesIO())
                with self.assertRaises(policy.PolicyError):
                    self.api.request("GET", self.api.prefix + "/actions/artifacts/123/zip", binary=True)
                self.assertEqual(self.api.opener.open.call_count, 1)

    def test_upload_accept_and_body_content_type_remain_independent(self):
        self.api.request("POST", self.api.prefix + "/releases/123/assets?name=RELEASE.json", b"{}", upload=True)
        request = self.api.opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Accept"), "application/vnd.github+json")
        self.assertEqual(request.get_header("Content-type"), "application/octet-stream")

    def test_api_error_response_is_closed_on_absence_and_redirect(self):
        for code in (404, 302):
            with self.subTest(code=code):
                body = io.BytesIO(b"API response")
                error = urllib.error.HTTPError("https://api.github.com" + self.api.prefix, code, "response",
                                               {"Location": "https://example.blob.core.windows.net/file"}, body)
                self.addCleanup(error.close)
                self.api.opener.open.side_effect = [error, io.BytesIO(b"artifact")]
                self.api.request("GET", self.api.prefix + "/actions/artifacts/123/zip", binary=True, absent=True)
                self.assertTrue(body.closed)


if __name__ == "__main__":
    unittest.main()
