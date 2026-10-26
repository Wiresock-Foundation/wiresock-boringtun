"""Semantic replay of the one approved trial, never a signing/crypto rerun."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import boringtun_release_policy as policy

FIXTURE = ROOT / 'tests/fixtures/attestation-40401950322-1'


class LiveAttestationFixtureTests(unittest.TestCase):
    def setUp(self):
        self.raw = (FIXTURE / 'gh-verification.json').read_bytes()
        self.result = json.loads(self.raw)[0]['verificationResult']
        self.descriptor = policy.load_json((FIXTURE / 'RELEASE.json').read_bytes())
        self.receipt = json.loads((FIXTURE / 'receipt.json').read_bytes())
        self.subjects = policy.release_assets(self.descriptor)
        del self.subjects['SHA256SUMS']

    def test_untouched_real_output_matches_each_of_six_recorded_reads(self):
        expected = '5c64aae36e1281173993c11b12e4115f714225c3be83e2dad27cc46afc04adb0'
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), expected)
        self.assertEqual(len(self.receipt['subjects']), 6)
        for subject in self.receipt['subjects']:
            self.assertEqual(subject['verification_json_sha256'], expected)
            self.assertEqual(subject['sha256'], self.subjects[subject['subject']])

    def test_all_six_real_subjects_and_installed_identity_pass(self):
        result = policy.check_verified_attestation(self.result, self.descriptor, self.subjects)
        self.assertEqual(result['subjects'], self.subjects)
        self.assertEqual(result['recipe_commit'], '1cee1afadd6be4251d6a19273b1882090bd2038e')
        self.assertEqual(result['invocation'], 'https://github.com/Wiresock-Foundation/wiresock-boringtun/actions/runs/40401950322/attempts/1')
        self.assertEqual(self.descriptor['build_run']['id'], 40398953473)
        self.assertEqual(self.descriptor['build_run']['run_attempt'], 1)
        self.assertEqual(policy.canonical_bytes(self.descriptor), (FIXTURE / 'RELEASE.json').read_bytes())

    def test_altered_publisher_run_attempt_or_recipe_is_rejected(self):
        for key, value in [('run_id', 40401950323), ('run_attempt', 2), ('recipe_commit', 'd' * 40)]:
            descriptor = copy.deepcopy(self.descriptor)
            descriptor['publisher'][key] = value
            with self.subTest(key=key), self.assertRaises(policy.PolicyError):
                policy.check_verified_attestation(self.result, descriptor, self.subjects)

    def test_signed_descriptor_cannot_substitute_source_or_build_attempt(self):
        for section, key, value in [(None, 'source_commit', 'd' * 40),
                                    ('build_run', 'run_attempt', 2), ('build_run', 'id', 40398953474)]:
            descriptor = copy.deepcopy(self.descriptor)
            (descriptor if section is None else descriptor[section])[key] = value
            with self.subTest(section=section, key=key), self.assertRaises(policy.PolicyError):
                subjects = dict(self.subjects, **{'RELEASE.json': hashlib.sha256(policy.canonical_bytes(descriptor)).hexdigest()})
                policy.check_verified_attestation(self.result, descriptor, subjects)

    def test_wrong_archive_digest_or_extra_subject_is_rejected(self):
        for name in self.subjects:
            changed = dict(self.subjects, **{name: 'f' * 64})
            with self.subTest(name=name), self.assertRaises(policy.PolicyError):
                policy.check_verified_attestation(self.result, self.descriptor, changed)
        with self.assertRaises(policy.PolicyError):
            policy.check_verified_attestation(self.result, self.descriptor, dict(self.subjects, extra='f' * 64))


if __name__ == '__main__':
    unittest.main()
