"""Offline policy regressions; fixtures are API/gh projections, never signatures."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


MODULE = Path(__file__).resolve().parents[1] / "scripts/boringtun_release_policy.py"
policy = None
if MODULE.exists():
    spec = importlib.util.spec_from_file_location("release_policy", MODULE)
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)

REPO = "Wiresock-Foundation/wiresock-boringtun"
C, H, R = "c" * 40, "a" * 40, "e" * 40
BUILD_PATH = ".github/workflows/boringtun-artifacts.yml"
PUBLISH_PATH = ".github/workflows/boringtun-release.yml"
X86 = "boringtun-cli-0.7.1-gcccccccccccc-linux-x86_64-musl.tar.gz"
ARM = "boringtun-cli-0.7.1-gcccccccccccc-linux-aarch64-musl.tar.gz"
ARM32 = "boringtun-cli-0.7.1-gcccccccccccc-linux-armv7-musleabihf.tar.gz"
MAC_X86 = "boringtun-cli-0.7.1-gcccccccccccc-macos-x86_64.tar.gz"
MAC_ARM = "boringtun-cli-0.7.1-gcccccccccccc-macos-aarch64.tar.gz"
TARGET_NAMES = {"x86_64-unknown-linux-musl": X86, "aarch64-unknown-linux-musl": ARM,
                "armv7-unknown-linux-musleabihf": ARM32, "x86_64-apple-darwin": MAC_X86,
                "aarch64-apple-darwin": MAC_ARM}


def pr_fixture():
    return {"number": 42, "state": "closed", "merged": True,
            "merge_commit_sha": C, "merged_at": "2026-10-25T12:00:00Z",
            "base": {"ref": "master", "repo": {"full_name": REPO}},
            "head": {"sha": H, "repo": {"full_name": "contributor/fork"}}}


def run_fixture():
    pr = pr_fixture()
    return {"id": 100, "run_attempt": 2, "workflow_id": 200,
            "path": BUILD_PATH, "event": "pull_request", "status": "completed",
            "conclusion": "success", "repository": {"full_name": REPO},
            "head_sha": C, "created_at": "2026-10-25T12:00:01Z",
            "pull_requests": [{"number": 42, "head": pr["head"], "base": pr["base"]}]}


def artifact_fixture():
    return {"id": 300, "name": "boringtun-100-2", "digest": "sha256:" + "1" * 64,
            "size_in_bytes": 1000, "expired": False,
            "workflow_run": {"id": 100, "head_sha": C}}


def publisher_fixture():
    return {"repository": REPO, "workflow_id": 400, "workflow_path": PUBLISH_PATH,
            "ref": "refs/heads/master", "recipe_commit": R,
            "run_id": 500, "run_attempt": 3, "version": "0.7.1",
            "rust_toolchain": "1.98.1", "toolchain_sha256": "2" * 64,
            "notice_provenance_sha256": "4" * 64}


def archives_fixture():
    return [{"target": "x86_64-unknown-linux-musl", "name": X86,
             "sha256": "5" * 64, "binary_sha256": "6" * 64, "notice_sha256": "1" * 64},
            {"target": "aarch64-unknown-linux-musl", "name": ARM,
             "sha256": "7" * 64, "binary_sha256": "8" * 64, "notice_sha256": "2" * 64},
            {"target": "armv7-unknown-linux-musleabihf", "name": ARM32,
             "sha256": "9" * 64, "binary_sha256": "a" * 64, "notice_sha256": "3" * 64},
            {"target": "x86_64-apple-darwin", "name": MAC_X86,
             "sha256": "b" * 64, "binary_sha256": "c" * 64, "notice_sha256": "4" * 64},
            {"target": "aarch64-apple-darwin", "name": MAC_ARM,
             "sha256": "d" * 64, "binary_sha256": "e" * 64, "notice_sha256": "5" * 64}]


def attestation_fixture(subjects):
    """Schema fixture derived from gh 2.100.0 / sigstore-go 1.3.0 sources.

    This is not a live signed fixture and must never be used as crypto evidence.
    Upstream types: pkg/verify/signed_entity.go, certificate_identity.go and
    pkg/fulcio/certificate/{summarize,extensions}.go; predicate from
    actions/toolkit packages/attest/src/provenance.ts.
    """
    repo_url = "https://github.com/" + REPO
    signer = repo_url + "/" + PUBLISH_PATH + "@refs/heads/master"
    invocation = repo_url + "/actions/runs/500/attempts/3"
    cert = {"certificateIssuer": "CN=sigstore-intermediate,O=sigstore.dev",
            "subjectAlternativeName": signer,
            "issuer": "https://token.actions.githubusercontent.com",
            "buildSignerURI": signer, "buildSignerDigest": R,
            "runnerEnvironment": "github-hosted", "sourceRepositoryURI": repo_url,
            "sourceRepositoryDigest": R, "sourceRepositoryRef": "refs/heads/master",
            "sourceRepositoryIdentifier": "1234",
            "sourceRepositoryOwnerURI": "https://github.com/Wiresock-Foundation",
            "sourceRepositoryOwnerIdentifier": "5678", "buildConfigURI": signer,
            "buildConfigDigest": R, "buildTrigger": "workflow_run",
            "runInvocationURI": invocation, "sourceRepositoryVisibilityAtSigning": "public"}
    return {"mediaType": "application/vnd.dev.sigstore.verificationresult+json;version=0.1",
            "signature": {"certificate": cert},
            "verifiedTimestamps": [{"type": "Tlog", "uri": "https://rekor.sigstore.dev",
                                    "timestamp": "2026-10-25T12:03:00Z"}],
            "verifiedIdentity": {"subjectAlternativeName": {"subjectAlternativeName": signer},
                                 "issuer": {"issuer": "", "regexp": ".*"},
                                 "runnerEnvironment": "github-hosted"},
            "statement": {"_type": "https://in-toto.io/Statement/v1",
                          "predicateType": "https://slsa.dev/provenance/v1",
                          "subject": [{"name": name, "digest": {"sha256": digest}}
                                      for name, digest in subjects.items()],
                          "predicate": {"buildDefinition": {
                              "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                              "externalParameters": {"workflow": {"ref": "refs/heads/master",
                                                                     "repository": repo_url, "path": PUBLISH_PATH}},
                              "internalParameters": {"github": {"event_name": "workflow_run",
                                  "repository_id": "1234", "repository_owner_id": "5678",
                                  "runner_environment": "github-hosted"}},
                              "resolvedDependencies": [{"uri": "git+" + repo_url + "@refs/heads/master",
                                                        "digest": {"gitCommit": R}}]},
                              "runDetails": {"builder": {"id": signer},
                                             "metadata": {"invocationId": invocation}}}}}


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(policy, "release policy module is not implemented")

    def descriptor(self):
        request = policy.merged_request(pr_fixture(), 42)
        run = policy.check_build_run(run_fixture(), request, 200)
        return policy.make_descriptor(request, run, artifact_fixture(),
                                      publisher_fixture(), archives_fixture())

    def test_merge_strategy_uses_post_merge_sha_not_pr_head(self):
        for strategy, sha in [("merge", "b" * 40), ("squash", "c" * 40),
                              ("rebase", "d" * 40)]:
            with self.subTest(strategy=strategy):
                pr = pr_fixture()
                pr["merge_commit_sha"] = sha
                self.assertEqual(policy.merged_request(pr, 42)["source_commit"], sha)

    def test_request_rejects_unmerged_foreign_base_and_invalid_identity(self):
        cases = [("number", True), ("number", 41), ("state", "open"),
                 ("merged", 1), ("merged", False), ("merge_commit_sha", H[:12]),
                 ("merged_at", None), ("merged_at", "tomorrow"), ("unknown", "x")]
        for key, value in cases:
            pr = pr_fixture()
            pr[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(policy.PolicyError):
                policy.merged_request(pr, 42)
        for field, value in [("ref", "main"), ("repo", {"full_name": "attacker/fork"})]:
            pr = pr_fixture()
            pr["base"][field] = value
            with self.assertRaises(policy.PolicyError):
                policy.merged_request(pr, 42)
        with self.assertRaises(policy.PolicyError):
            policy.merged_request(pr_fixture(), True)

    def test_identity_and_archives_keep_legacy_filename_contract(self):
        self.assertEqual(policy.release_tag("0.7.1", C, 42),
                         "boringtun-cli-0.7.1-gcccccccccccc-b42")
        self.assertEqual(set(policy.TARGETS), set(TARGET_NAMES))
        for target, expected in TARGET_NAMES.items():
            self.assertEqual(policy.archive_name("0.7.1", C, target), expected)
        for version, sha, pr in [("0.7.1;echo", C, 42), ("01.7.1", C, 42),
                                 ("0.7.1", H[:12], 42), ("0.7.1", C, True)]:
            with self.assertRaises(policy.PolicyError):
                policy.release_tag(version, sha, pr)

    def test_run_rejects_wrong_workflow_event_attempt_and_pr_association(self):
        request = policy.merged_request(pr_fixture(), 42)
        cases = [("workflow_id", 201), ("path", PUBLISH_PATH), ("event", "push"),
                 ("run_attempt", True), ("run_attempt", 0), ("conclusion", "failure"),
                 ("status", "in_progress"), ("pull_requests", []),
                 ("created_at", "2026-10-25T11:59:59Z"),
                 ("repository", {"full_name": "attacker/fork"}), ("unexpected", 1)]
        for key, value in cases:
            run = run_fixture()
            run[key] = value
            with self.subTest(key=key), self.assertRaises(policy.PolicyError):
                policy.check_build_run(run, request, 200)
        run = run_fixture()
        run["pull_requests"][0]["head"]["sha"] = "f" * 40
        with self.assertRaises(policy.PolicyError):
            policy.check_build_run(run, request, 200)

    def test_descriptor_records_separate_build_and_promoter_recipes(self):
        data = self.descriptor()
        self.assertEqual(data["source_commit"], C)
        self.assertEqual(data["build_run"]["recipe_commit"], C)
        self.assertEqual(data["publisher"]["recipe_commit"], R)
        self.assertEqual(data["build"], 42)
        self.assertEqual(data["build_run"]["run_attempt"], 2)
        self.assertEqual(data["publisher"]["run_attempt"], 3)
        self.assertEqual(data["artifact"]["sha256"], "1" * 64)
        self.assertEqual(data["schema"], 2)
        self.assertNotIn("notice_sha256", data)
        self.assertEqual(len({archive["notice_sha256"] for archive in data["archives"]}), 5)
        self.assertEqual(policy.check_descriptor(data), data)
        self.assertNotIn("timestamp", data)

    def test_artifact_binding_rejects_other_attempt_or_run(self):
        request = policy.merged_request(pr_fixture(), 42)
        run = policy.check_build_run(run_fixture(), request, 200)
        for key, value in [("id", True), ("name", "boringtun-100-1"),
                           ("expired", True), ("digest", "1" * 64),
                           ("size_in_bytes", 0), ("size_in_bytes", True),
                           ("workflow_run", {"id": 101, "head_sha": C})]:
            artifact = artifact_fixture()
            artifact[key] = value
            with self.subTest(key=key), self.assertRaises(policy.PolicyError):
                policy.make_descriptor(request, run, artifact, publisher_fixture(), archives_fixture())

    def test_descriptor_rejects_unknown_keys_schema_and_invalid_fields(self):
        for key, value in [("schema", 1), ("schema", 3), ("schema", True), ("build", True),
                           ("build", 41), ("artifact_format", 2),
                           ("tag", "boringtun-cli-0.7.1-gcccccccccccc-b41"),
                           ("repository", "attacker/fork"), ("latest", True),
                           ("notice_sha256", "z" * 64)]:
            data = self.descriptor()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(policy.PolicyError):
                policy.check_descriptor(data)
        for key in ["build_run", "publisher", "artifact"]:
            data = self.descriptor()
            data[key]["unknown"] = 1
            with self.assertRaises(policy.PolicyError):
                policy.check_descriptor(data)

    def test_archive_targets_names_and_digest_set_are_exact(self):
        for mutation in ["duplicate", "missing", "path", "name", "hash", "notice", "extra"]:
            data = self.descriptor()
            if mutation == "duplicate":
                data["archives"][1] = copy.deepcopy(data["archives"][0])
            elif mutation == "missing":
                data["archives"].pop()
            elif mutation == "path":
                data["archives"][0]["name"] = "../" + data["archives"][0]["name"]
            elif mutation == "name":
                data["archives"][0]["name"] += "-b42"
            elif mutation == "hash":
                data["archives"][0]["binary_sha256"] = "x"
            elif mutation == "notice":
                data["archives"][0]["notice_sha256"] = True
            else:
                data["archives"][0]["unknown"] = "x"
            with self.subTest(mutation=mutation), self.assertRaises(policy.PolicyError):
                policy.check_descriptor(data)

    def test_serialization_and_seven_asset_hashes_are_deterministic(self):
        data = self.descriptor()
        encoded = policy.canonical_bytes(data)
        self.assertEqual(encoded, (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode())
        assets = policy.release_assets(data)
        expected = {item["name"]: item["sha256"] for item in archives_fixture()}
        checksums = "".join(f"{value}  {name}\n" for name, value in sorted(expected.items())).encode()
        self.assertEqual(len(assets), 7)
        self.assertEqual(assets, {**expected,
                                 "RELEASE.json": hashlib.sha256(encoded).hexdigest(),
                                 "SHA256SUMS": hashlib.sha256(checksums).hexdigest()})

    def existing(self, draft=False):
        data = self.descriptor()
        return {"tag": data["tag"], "target_commit": C, "draft": draft,
                "descriptor": data, "assets": policy.release_assets(data),
                "provenance_verified": True}

    def test_publication_create_resume_and_published_idempotence(self):
        data = self.descriptor()
        self.assertEqual(policy.publication_action(None, data), "create")
        state = self.existing(True)
        state["assets"].pop(X86)
        self.assertEqual(policy.publication_action(state, data), "resume")
        self.assertEqual(policy.publication_action(self.existing(), data), "already-published")

    def test_published_original_provenance_survives_new_run_identity(self):
        data = self.descriptor()
        data["publisher"]["run_id"] = 900
        data["publisher"]["run_attempt"] = 1
        data["build_run"]["id"] = 901
        data["build_run"]["run_attempt"] = 1
        data["artifact"]["name"] = "boringtun-901-1"
        data["artifact"]["id"] = 902
        data["artifact"]["sha256"] = "f" * 64
        self.assertEqual(policy.publication_action(self.existing(), data), "already-published")
        with self.assertRaises(policy.PolicyError):
            policy.publication_action(self.existing(True), data)

    def test_publication_conflicts_never_become_success(self):
        for mutation in ["hash", "extra", "missing", "unverified", "wrong-tag", "wrong-source", "legacy"]:
            state = self.existing()
            if mutation == "hash":
                state["assets"][X86] = "f" * 64
            elif mutation == "extra":
                state["assets"]["extra"] = "f" * 64
            elif mutation == "missing":
                state["assets"].pop(X86)
            elif mutation == "unverified":
                state["provenance_verified"] = False
            elif mutation == "wrong-tag":
                state["tag"] += "0"
            elif mutation == "wrong-source":
                state["target_commit"] = H
            else:
                state["descriptor"] = None
            with self.subTest(mutation=mutation), self.assertRaises(policy.PolicyError):
                policy.publication_action(state, self.descriptor())
        state = self.existing(True)
        state["assets"].pop("RELEASE.json")
        with self.assertRaises(policy.PolicyError):
            policy.publication_action(state, self.descriptor())

    def test_same_tag_different_desired_archive_is_conflict(self):
        desired = self.descriptor()
        desired["archives"][0]["sha256"] = "f" * 64
        with self.assertRaises(policy.PolicyError):
            policy.publication_action(self.existing(), desired)

    def test_strict_json_rejects_duplicate_keys_and_nonfinite_values(self):
        for raw in ['{"a":1,"a":2}', '{"n":NaN}', '{"n":Infinity}', '{"n":1e999}', '{']:
            with self.assertRaises(policy.PolicyError):
                policy.load_json(raw)
        self.assertEqual(policy.load_json('{"a": [1, false]}'), {"a": [1, False]})

    def test_attestation_certificate_and_statement_bind_exact_invocation(self):
        self.assertTrue(hasattr(policy, "check_verified_attestation"), "attestation policy missing")
        data = self.descriptor()
        subjects = policy.release_assets(data)
        subjects.pop("SHA256SUMS")
        self.assertEqual(len(subjects), 6)
        result = policy.check_verified_attestation(attestation_fixture(subjects), data, subjects)
        self.assertEqual(result, {"invocation": "https://github.com/" + REPO + "/actions/runs/500/attempts/3",
                                  "subjects": subjects, "recipe_commit": R})

    def test_same_bytes_wrong_certificate_run_attempt_signer_or_source_rejected(self):
        self.assertTrue(hasattr(policy, "check_verified_attestation"), "attestation policy missing")
        cases = [("runInvocationURI", "https://github.com/" + REPO + "/actions/runs/500/attempts/2"),
                 ("runInvocationURI", "https://github.com/" + REPO + "/actions/runs/501/attempts/3"),
                 ("subjectAlternativeName", "https://github.com/attacker/repo/workflow@refs/heads/master"),
                 ("sourceRepositoryDigest", C), ("buildSignerDigest", C),
                 ("sourceRepositoryRef", "refs/pull/42/merge"),
                 ("runnerEnvironment", "self-hosted"), ("buildTrigger", "pull_request"),
                 ("issuer", "https://attacker.invalid"), ("unknown", "x")]
        for key, value in cases:
            evidence = attestation_fixture({X86: "5" * 64})
            evidence["signature"]["certificate"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(policy.PolicyError):
                policy.check_verified_attestation(evidence, self.descriptor(), {X86: "5" * 64})

    def test_attestation_subjects_reject_missing_extra_duplicate_or_wrong_digest(self):
        self.assertTrue(hasattr(policy, "check_verified_attestation"), "attestation policy missing")
        for mutation in ["missing", "extra", "duplicate", "hash", "algorithm", "name"]:
            evidence = attestation_fixture({X86: "5" * 64})
            subjects = evidence["statement"]["subject"]
            if mutation == "missing":
                subjects.clear()
            elif mutation in ("extra", "duplicate"):
                subjects.append(copy.deepcopy(subjects[0]))
                if mutation == "extra":
                    subjects[-1]["name"] = "other"
            elif mutation == "hash":
                subjects[0]["digest"]["sha256"] = "f" * 64
            elif mutation == "algorithm":
                subjects[0]["digest"]["sha512"] = "f" * 128
            else:
                subjects[0]["name"] = "../" + X86
            with self.subTest(mutation=mutation), self.assertRaises(policy.PolicyError):
                policy.check_verified_attestation(evidence, self.descriptor(), {X86: "5" * 64})

    def test_attestation_rejects_unknown_schema_and_forged_predicate_invocation(self):
        self.assertTrue(hasattr(policy, "check_verified_attestation"), "attestation policy missing")
        for mutation in ["media", "statement", "predicate", "invocation", "dependency", "timestamp", "identity"]:
            evidence = attestation_fixture({X86: "5" * 64})
            if mutation == "media":
                evidence["mediaType"] += "2"
            elif mutation == "statement":
                evidence["statement"]["_type"] += "2"
            elif mutation == "predicate":
                evidence["statement"]["predicate"]["unrecognized"] = True
            elif mutation == "invocation":
                evidence["statement"]["predicate"]["runDetails"]["metadata"]["invocationId"] += "0"
            elif mutation == "dependency":
                evidence["statement"]["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = C
            elif mutation == "timestamp":
                evidence["verifiedTimestamps"] = []
            else:
                evidence["verifiedIdentity"]["subjectAlternativeName"] = {"regexp": ".*"}
            with self.subTest(mutation=mutation), self.assertRaises(policy.PolicyError):
                policy.check_verified_attestation(evidence, self.descriptor(), {X86: "5" * 64})

    def test_attestation_argv_pins_exact_signer_recipe_and_hosted_runners(self):
        self.assertTrue(hasattr(policy, "attestation_arguments"), "attestation command policy missing")
        argv = policy.attestation_arguments("/tmp/RELEASE.json", self.descriptor())
        for flag, expected in [("--repo", REPO), ("--source-digest", R), ("--signer-digest", R),
                               ("--source-ref", "refs/heads/master"), ("--format", "json"),
                               ("--cert-identity", "https://github.com/" + REPO + "/" + PUBLISH_PATH + "@refs/heads/master")]:
            self.assertEqual(argv[argv.index(flag) + 1], expected)
        self.assertIn("--deny-self-hosted-runners", argv)
        self.assertEqual(argv[-2:], ["--", "/tmp/RELEASE.json"])

    def test_pinned_gh_issuer_matcher_shape_does_not_relax_certificate_issuer(self):
        evidence = attestation_fixture({X86: "5" * 64})
        result = policy.check_verified_attestation(evidence, self.descriptor(), {X86: "5" * 64})
        self.assertEqual(result["recipe_commit"], R)
        evidence["signature"]["certificate"]["issuer"] = "https://attacker.invalid"
        with self.assertRaises(policy.PolicyError):
            policy.check_verified_attestation(evidence, self.descriptor(), {X86: "5" * 64})


if __name__ == "__main__":
    unittest.main()
