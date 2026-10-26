"""Real REST/publisher boundary with GitHub's published-only tag semantics.

Replace only HTTPS. The captured empty draft is the actual result of the first
publisher run, which succeeded in creating it then failed its tag readback.
"""
import copy
import io
import json
from pathlib import Path
import sys
import unittest
import urllib.error
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import boringtun_release as release
import boringtun_release_policy as policy
import test_release_orchestration as orchestration_fixtures

CAPTURE = Path(__file__).parent / "fixtures/draft-424839667/release.json"
TAG = "boringtun-cli-0.7.1-ga92909c49920-b101"
SOURCE = "a92909c49920e12de11fb0e066192b8f39b5b212"


class ReleaseService:
    """Server state survives a lost response, independently of the REST client."""
    def __init__(self, state=None, files=None):
        self.state = copy.deepcopy(state)
        self.files = dict(files or {})
        self.prefix = "/repos/" + policy.REPOSITORY
        self.requests, self.writes = [], []
        self.before = []
        self.after = []
        self.uncertain = None
        self.id_override = None
        self.denied_inventory = False
        self.unavailable_id = False
        self.replace_id_on_upload = False
        self.reject_create = False
        self.hide_drafts = False

    def error(self, request, code):
        raise urllib.error.HTTPError(request.full_url, code, "fixture response", {}, io.BytesIO(b"{}"))

    def open(self, request, **_kwargs):
        parsed = urllib.parse.urlsplit(request.full_url)
        path, query, method = parsed.path, urllib.parse.parse_qs(parsed.query), request.get_method()
        if parsed.scheme != "https" or parsed.netloc not in ("api.github.com", "uploads.github.com"):
            raise AssertionError("wrong transport destination")
        if request.get_header("Authorization") != "Bearer owner-token":
            raise AssertionError("owner credential absent")
        self.requests.append((method, path))
        resource = path.removeprefix(self.prefix)
        result = None
        operation = None
        if method == "GET" and resource == "/releases":
            if self.denied_inventory:
                self.error(request, 403)
            inventory = self.before + ([self.state] if self.state else []) + self.after
            if self.hide_drafts:
                inventory = [item for item in inventory if not item["draft"]]
            page, limit = int(query["page"][0]), int(query["per_page"][0])
            result = inventory[(page - 1) * limit:page * limit]
        elif method == "GET" and resource.startswith("/releases/tags/"):
            if not self.state or self.state["draft"]:
                self.error(request, 404)
            result = self.state
        elif method == "GET" and resource.startswith("/git/ref/tags/"):
            if not self.state or self.state["draft"]:
                self.error(request, 404)
            result = {"object": {"type": "commit", "sha": self.state["target_commitish"]}}
        elif method == "GET" and resource == f"/releases/{self.state['id'] if self.state else 0}":
            if self.unavailable_id:
                self.error(request, 404)
            result = self.id_override if self.id_override is not None else self.state
        elif method == "GET" and self.state and resource == f"/releases/{self.state['id']}/assets":
            result = [{"id": i, "name": name, "state": "uploaded", "size": len(raw)}
                      for i, (name, raw) in enumerate(self.files.items(), 1)]
        elif method == "GET" and resource.startswith("/releases/assets/"):
            if request.get_header("Accept") != "application/octet-stream":
                self.error(request, 415)
            result = list(self.files.values())[int(resource.rsplit("/", 1)[1]) - 1]
        elif method == "POST" and resource == "/releases":
            if self.reject_create:
                self.writes.append("create")
                raise urllib.error.URLError("outcome unavailable; request was not accepted")
            if self.state:
                self.error(request, 422)
            self.state = dict(json.loads(request.data), id=20)
            operation, result = "create", self.state
        elif method == "POST" and self.state and resource == f"/releases/{self.state['id']}/assets":
            name = query["name"][0]
            if name in self.files:
                self.error(request, 422)
            self.files[name] = request.data
            if self.replace_id_on_upload:
                self.state["id"] += 1
            operation, result = "upload:" + name, {"state": "uploaded"}
        elif method == "PATCH" and self.state and resource == f"/releases/{self.state['id']}":
            self.state.update(json.loads(request.data))
            operation, result = "publish", self.state
        else:
            raise AssertionError("unexpected endpoint: " + method + " " + resource)
        if operation:
            self.writes.append(operation)
            if operation == self.uncertain:
                self.uncertain = None
                raise urllib.error.URLError("connection lost after server accepted mutation")
        return io.BytesIO(result if isinstance(result, bytes) else json.dumps(result).encode())


class DraftReadbackTests(unittest.TestCase):
    def setUp(self):
        self.draft = json.loads(CAPTURE.read_bytes())
        self.service = ReleaseService(self.draft)
        self.api = release.GitHub(token="owner-token")
        self.api.opener = self.service

    def test_actual_empty_draft_is_found_without_a_git_tag(self):
        state = self.api.read_release(TAG)
        self.assertIsNotNone(state)
        self.assertEqual((state["id"], state["tag"], state["target_commit"], state["draft"], state["assets"]),
                         (424839667, TAG, SOURCE, True, {}))
        self.assertEqual(state["body"], self.draft["body"])

    def test_lookup_requires_authentication_before_claiming_absence(self):
        self.api.token = ""
        with self.assertRaises(policy.PolicyError):
            self.api.read_release(TAG)
        self.assertEqual(self.service.requests, [])

    def test_denied_inventory_does_not_mean_no_draft_exists(self):
        self.service.denied_inventory = True
        with self.assertRaises(policy.PolicyError):
            self.api.read_release(TAG)

    def test_authenticated_observer_cannot_prove_a_hidden_draft_absent(self):
        self.service.hide_drafts = True
        self.assertIsNone(self.api.read_release(TAG))
        # A filtered inventory is valid GitHub behavior. Authentication alone
        # cannot distinguish it from an empty repository: recovery must require
        # the expected ID using a principal with actual draft visibility.
        self.assertEqual(self.service.state["id"], 424839667)
        self.assertIs(self.service.state["draft"], True)
        self.assertEqual(self.service.writes, [])

    def test_draft_after_first_page_is_found(self):
        self.service.before = [dict(self.draft, id=i + 1, tag_name="older-" + str(i)) for i in range(100)]
        state = self.api.read_release(TAG)
        self.assertIsNotNone(state)
        self.assertEqual(state["id"], 424839667)

    def test_same_tag_ambiguity_across_pages_rejects_drafts_and_published(self):
        self.service.before = [dict(self.draft, id=i + 1, tag_name="older-" + str(i)) for i in range(99)]
        for draft in (True, False):
            with self.subTest(draft=draft):
                self.service.after = [dict(self.draft, id=424839668, draft=draft)]
                with self.assertRaises(policy.PolicyError):
                    self.api.read_release(TAG)
                self.assertEqual(self.service.writes, [])

    def test_duplicate_inventory_id_is_not_an_authoritative_absence(self):
        self.service.after = [dict(self.draft, tag_name="renamed")]
        with self.assertRaises(policy.PolicyError):
            self.api.read_release(TAG)

    def test_id_readback_must_match_inventory_identity(self):
        for changes in ({"id": 424839668}, {"tag_name": "other"}, {"draft": False},
                        {"target_commitish": "f" * 40}, {"body": "changed marker"}):
            with self.subTest(changes=changes):
                self.service.id_override = dict(self.draft, **changes)
                with self.assertRaises(policy.PolicyError):
                    self.api.read_release(TAG)

    def test_malformed_inventory_identity_cannot_be_used_as_an_api_path(self):
        for value in ("../assets/1", True, 0):
            with self.subTest(value=value):
                self.service.state = dict(self.draft, id=value)
                with self.assertRaises(policy.PolicyError):
                    self.api.read_release(TAG)

    def test_published_release_is_read_by_id_and_checks_git_tag(self):
        self.service.state["draft"] = False
        state = self.api.read_release(TAG)
        self.assertEqual((state["id"], state["target_commit"], state["draft"]), (424839667, SOURCE, False))
        self.assertIn(("GET", self.api.prefix + "/releases/424839667"), self.service.requests)

    def test_partial_draft_assets_are_read_from_the_exact_release(self):
        self.service.files = {"RELEASE.json": b"original signed descriptor"}
        state = self.api.read_release(TAG)
        self.assertIsNotNone(state)
        self.assertEqual(state["assets"], {"RELEASE.json": b"original signed descriptor"})

    def test_inaccessible_known_draft_stops_instead_of_becoming_absent(self):
        self.service.unavailable_id = True
        with self.assertRaises(policy.PolicyError):
            self.api.read_release(TAG)

    def test_no_release_and_no_tag_returns_absent(self):
        self.service.state = None
        self.assertIsNone(self.api.read_release(TAG))

    def publishing_fixture(self, empty=False):
        fixture = orchestration_fixtures.OrchestrationTests()
        fixture.setUp()
        descriptor, files = fixture.descriptor, fixture.files
        self.service.state = dict(self.draft, id=20, tag_name=descriptor["tag"],
                                  target_commitish=descriptor["source_commit"],
                                  body=release.descriptor_marker(descriptor))
        self.service.files = {} if empty else {"RELEASE.json": files["RELEASE.json"]}
        return fixture, descriptor, files

    def test_partial_draft_resume_never_recreates_or_replaces_existing_assets(self):
        fixture, descriptor, files = self.publishing_fixture()
        result = release.publish_release(self.api, descriptor, files, fixture.verified, fixture.ready, dry_run=False)
        self.assertEqual(result, "published")
        self.assertNotIn("create", self.service.writes)
        self.assertNotIn("upload:RELEASE.json", self.service.writes)
        self.assertEqual(self.service.files, files)

    def test_lost_mutation_responses_read_back_same_release_without_duplicate_writes(self):
        fixture, descriptor, files = self.publishing_fixture(empty=True)
        for uncertain in ("create", "upload:RELEASE.json", "publish"):
            with self.subTest(uncertain=uncertain):
                self.service = ReleaseService()
                self.service.uncertain = uncertain
                self.api.opener = self.service
                result = release.publish_release(self.api, descriptor, files, fixture.verified, fixture.ready, dry_run=False)
                self.assertEqual(result, "published")
                self.assertEqual(self.service.writes.count(uncertain), 1)
                self.assertEqual(self.service.files, files)

    def test_uncertain_create_without_state_is_not_retried(self):
        fixture, descriptor, files = self.publishing_fixture(empty=True)
        self.service.state = None
        self.service.reject_create = True
        with self.assertRaises(policy.PolicyError):
            release.publish_release(self.api, descriptor, files, fixture.verified, fixture.ready, dry_run=False)
        self.assertEqual(self.service.writes, ["create"])

    def test_release_id_cannot_change_during_partial_draft_resume(self):
        fixture, descriptor, files = self.publishing_fixture()
        self.service.replace_id_on_upload = True
        with self.assertRaises(policy.PolicyError):
            release.publish_release(self.api, descriptor, files, fixture.verified, fixture.ready, dry_run=False)
        self.assertEqual(len(self.service.writes), 1)
        self.assertNotIn("publish", self.service.writes)


if __name__ == "__main__":
    unittest.main()
