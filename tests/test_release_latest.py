"""Latest reconciliation runs under one workflow lock, independent of PR order."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import boringtun_release as release
import boringtun_release_policy as policy
from test_release_notes import modern_fixture, PROSE


def release_fixture(value, release_id):
    descriptor, files = modern_fixture()
    descriptor['version'] = value
    descriptor['tag'] = descriptor['tag'].replace('0.8.0', value)
    for item in descriptor['archives']:
        item['name'] = item['name'].replace('0.8.0', value)
    files = {name.replace('0.8.0', value): raw for name, raw in files.items()}
    files['RELEASE.json'] = policy.canonical_bytes(descriptor)
    files['SHA256SUMS'] = files['SHA256SUMS'].replace(b'0.8.0', value.encode())
    return dict(id=release_id, tag=descriptor['tag'], target_commit=descriptor['source_commit'], draft=False,
                body=release.render_body(PROSE, descriptor, 'b' * 40), assets=files)


class Inventory:
    prefix = '/repos/' + policy.REPOSITORY
    def __init__(self):
        self.states = [release_fixture('0.8.0', 10), release_fixture('0.8.2', 12), release_fixture('0.8.1', 11)]
        self.latest = {'id': 10, 'tag_name': self.states[0]['tag']}
        self.writes = []
        self.uncertain = False
        self.fail_write = False
        self.extra = []

    def pages(self, path):
        assert path == self.prefix + '/releases'
        return [dict(id=s['id'], tag_name=s['tag'], draft=s['draft'], prerelease=False) for s in self.states] + self.extra

    def read_release(self, tag, *, release_id=None):
        return copy.deepcopy(next(s for s in self.states if s['tag'] == tag and s['id'] == release_id))

    def request(self, method, path, body=None, **kwargs):
        if method == 'GET' and path == self.prefix + '/releases/latest':
            return copy.deepcopy(self.latest)
        assert method == 'PATCH' and body == {'make_latest': 'true'}
        release_id = int(path.rsplit('/', 1)[1])
        self.writes.append(release_id)
        if not self.fail_write:
            self.latest = {'id': release_id, 'tag_name': next(s['tag'] for s in self.states if s['id'] == release_id)}
        if self.uncertain or self.fail_write:
            raise release.MutationOutcomeUnknown('response lost')
        return copy.deepcopy(self.latest)


class LatestTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(release, 'reconcile_latest', None)), 'Latest reconciler is missing')
        self.api = Inventory()
        self.checked = []

    def reconcile(self, dry_run=False, verify=None):
        return release.reconcile_latest(self.api, verify or (lambda d, f: self.checked.append(d['version'])),
                                        lambda d: None, dry_run=dry_run,
                                        body_for=lambda d: release.render_body(PROSE, d, 'b' * 40))

    def test_out_of_order_inventory_and_old_retries_pick_numeric_highest(self):
        self.assertEqual(self.reconcile(), 'updated-latest')
        self.assertEqual(self.api.writes, [12])
        self.api.states.append(release_fixture('0.8.10', 20))
        self.assertEqual(self.reconcile(), 'updated-latest')
        self.api.states.reverse()
        self.assertEqual(self.reconcile(), 'already-latest')
        self.assertEqual(self.api.writes, [12, 20])
        self.assertIn('0.8.10', self.checked)

    def test_coalesced_jobs_use_full_inventory_and_ignore_drafts_prereleases(self):
        self.api.extra = [dict(id=99, tag_name='boringtun-cli-9.0.0-g' + 'a' * 12 + '-b999', draft=True, prerelease=False),
                          dict(id=100, tag_name='boringtun-cli-10.0.0-g' + 'a' * 12 + '-b1000', draft=False, prerelease=True)]
        self.assertEqual(self.reconcile(dry_run=True), 'would-update-latest')
        self.assertEqual(self.api.writes, [])
        self.assertEqual(self.reconcile(), 'updated-latest')
        self.assertEqual(self.api.latest['id'], 12)

    def test_duplicate_versions_and_higher_current_latest_fail_closed(self):
        duplicate = release_fixture('0.8.2', 90)
        self.api.states.append(duplicate)
        with self.assertRaises(policy.PolicyError):
            self.reconcile()
        self.api.states.pop()
        self.api.latest = {'id': 99, 'tag_name': 'boringtun-cli-1.0.0-g' + 'a' * 12 + '-b999'}
        with self.assertRaises(policy.PolicyError):
            self.reconcile()
        self.assertEqual(self.api.writes, [])

    def test_invalid_highest_never_falls_back_to_lower(self):
        def reject(descriptor, files):
            raise policy.PolicyError('signature invalid')
        with self.assertRaises(policy.PolicyError):
            self.reconcile(verify=reject)
        self.assertEqual(self.api.writes, [])
        self.api.states[1]['body'] = self.api.states[1]['body'].replace('Readable summary.', 'Altered')
        with self.assertRaises(policy.PolicyError):
            self.reconcile()
        self.assertEqual(self.api.writes, [])

    def test_uncertain_patch_is_read_back_never_blindly_repeated(self):
        self.api.uncertain = True
        self.assertEqual(self.reconcile(), 'updated-latest')
        self.assertEqual(self.api.writes, [12])
        self.api.latest = {'id': 10, 'tag_name': self.api.states[0]['tag']}
        self.api.fail_write = True
        with self.assertRaises(policy.PolicyError):
            self.reconcile()
        self.assertEqual(self.api.writes, [12, 12])


if __name__ == '__main__':
    unittest.main()
