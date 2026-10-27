"""Old disabled sources must not become publishable when master is enabled."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import boringtun_release as release
import boringtun_release_policy as policy
from test_attestation_validation import BytesFile
import test_release_policy as fixtures

BASE = '1cee1afadd6be4251d6a19273b1882090bd2038e'


class ActivationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads(release.POLICY_FILE.read_bytes())
        self.config.update(enabled=True, activation_blockers=[],
                           activation={'after_commit': BASE, 'generation': 'fork-v1'})
        self.source_config = copy.deepcopy(self.config)
        self.descriptor = fixtures.PolicyTests().descriptor()
        self.comparison = {'status': 'ahead', 'merge_base_commit': {'sha': BASE}}
        self.api = self
        self.prefix = '/repos/' + policy.REPOSITORY
        self.live_config = self.config
        self.addCleanup(patch.stopall)
        patch.object(release, 'POLICY_FILE', BytesFile(json.dumps(self.config).encode())).start()
        patch.object(release, 'trusted_context', return_value={}).start()
        patch.object(release, 'check_retirement').start()

    def contents(self, path, ref):
        self.assertEqual(path, 'packaging/boringtun/release-policy.json')
        if ref == 'master':
            return json.dumps(self.live_config).encode()
        self.assertEqual(ref, fixtures.C)
        return json.dumps(self.source_config).encode()

    def get(self, path):
        self.assertEqual(path, self.prefix + '/compare/' + BASE + '...' + fixtures.C)
        return self.comparison

    def gate(self):
        release.live_gate(self.api, self.config, self.descriptor)

    def test_future_source_with_same_enabled_generation_passes(self):
        self.gate()

    def test_late_disabled_source_does_not_inherit_new_master_permission(self):
        self.source_config['enabled'] = False
        with self.assertRaisesRegex(policy.PolicyError, 'disabled'):
            self.gate()

    def test_source_with_unresolved_gates_is_ineligible(self):
        self.source_config['activation_blockers'] = ['unresolved']
        with self.assertRaisesRegex(policy.PolicyError, 'evidence incomplete'):
            self.gate()

    def test_baseline_itself_is_not_a_future_release(self):
        self.descriptor['source_commit'] = BASE
        with self.assertRaisesRegex(policy.PolicyError, 'activation baseline'):
            self.gate()

    def test_unrelated_or_older_history_is_rejected(self):
        for comparison in ({'status': 'behind', 'merge_base_commit': {'sha': BASE}},
                           {'status': 'diverged', 'merge_base_commit': {'sha': BASE}},
                           {'status': 'ahead', 'merge_base_commit': {'sha': 'd' * 40}}):
            self.comparison = comparison
            with self.subTest(comparison=comparison), self.assertRaises(policy.PolicyError):
                self.gate()

    def test_changed_generation_or_boundary_cannot_backfill(self):
        for key, value in [('generation', 'fork-v2'), ('after_commit', 'd' * 40)]:
            self.source_config = copy.deepcopy(self.config)
            self.source_config['activation'][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(policy.PolicyError, 'activation generation'):
                self.gate()

    def test_missing_or_invalid_boundary_fails_closed(self):
        for value in (None, {}, {'after_commit': BASE[:12], 'generation': 'fork-v1'},
                      {'after_commit': BASE, 'generation': ''}):
            self.config['activation'] = value
            with self.subTest(value=value), self.assertRaises(policy.PolicyError):
                self.gate()

    def test_live_revocation_still_blocks_inflight_source(self):
        self.live_config = copy.deepcopy(self.config)
        self.live_config['enabled'] = False
        with self.assertRaisesRegex(policy.PolicyError, 'current master enablement'):
            self.gate()


if __name__ == '__main__':
    unittest.main()
