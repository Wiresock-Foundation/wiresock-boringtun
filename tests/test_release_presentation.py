"""A reviewed published-body amendment is not general whitespace tolerance."""
import copy
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import boringtun_release as release
import boringtun_version as version
from test_release_notes import modern_fixture
from test_release_orchestration import MemoryDestination


class ActualPresentationTests(unittest.TestCase):
    def setUp(self):
        self.original = (Path(__file__).parent / 'fixtures/release-0.8.0-original-body.md').read_text(encoding='utf-8')
        self.descriptor, self.raw = release.recorded_descriptor(self.original)
        prose = version.notes(lambda p: (release.ROOT / p).read_bytes(), '0.8.0')
        self.amended = release.render_body(prose, self.descriptor, version.BASELINE)

    def test_actual_reviewed_wrap_variant_preserves_content_structure_links_and_signed_bytes(self):
        self.assertEqual(release.digest(self.original.encode()), 'c399060ac8860b5b494c7d49ab193aebba48705610ba0d064b454b71b1ca89e7')
        self.assertEqual(release.digest(self.amended.encode()), '84172db7d08d1c91ec12f5e4d246fe863de1b3a55b67386bc799a63e8bccd792')
        self.assertTrue(release.published_body_matches(self.original, self.original))
        self.assertTrue(release.published_body_matches(self.amended, self.original))
        self.assertEqual(''.join(self.original.split()), ''.join(self.amended.split()))
        for pattern in [r'^#+ .+$', r'\[[^\]]+\]\([^\n)]+\)', r'`[^`]+`', r'^- ']:
            self.assertEqual(re.findall(pattern, self.original, re.M), re.findall(pattern, self.amended, re.M))
        self.assertEqual(release.recorded_descriptor(self.amended), (self.descriptor, self.raw))
        self.assertEqual(self.original.split('<!--')[1], self.amended.split('<!--')[1])
        self.assertEqual(release.digest(self.raw), '52a3f22cbc87b9ab8a25d61bc55a0a207cf35a8d706c6e60c2a04208da8765b8')

    def test_unreviewed_text_links_structure_whitespace_and_metadata_remain_rejected(self):
        for bad in [self.amended + '\n', self.amended.replace('explicit version', 'different version'),
                    self.amended.replace('/pull/8)', '/pull/9)'), self.amended.replace('## New', '### New'),
                    self.amended.replace('PacketQueueFull', 'Packet Queue Full'),
                    self.amended.replace('metadata:v1', 'metadata:v2'),
                    self.amended.replace('descriptor_sha256=', 'descriptor_sha256=0'),
                    self.amended + '\n' + self.amended, self.amended.replace('WireSock fork', 'WireSock  fork')]:
            with self.subTest(body=bad[:60]):
                self.assertNotEqual(bad, self.amended)
                self.assertFalse(release.published_body_matches(bad, self.original))
        self.assertFalse(release.published_body_matches(self.amended, self.original.replace('0.8.0', '0.8.1')))


class PresentationStateTests(unittest.TestCase):
    def setUp(self):
        self.descriptor, self.files = modern_fixture()
        self.original = release.render_body('A readable\nsummary.\n\n## Compatibility & upgrade notes\n\nNo changes.', self.descriptor, 'b' * 40)
        self.amended = self.original.replace('readable\nsummary', 'readable summary')
        self.body_for = lambda d: self.original
        self.amendments = patch.dict(release.REVIEWED_BODY_AMENDMENTS,
                                     {release.digest(self.original.encode()): release.digest(self.amended.encode())})
        self.amendments.start()
        self.addCleanup(self.amendments.stop)
        self.state = dict(id=20, tag=self.descriptor['tag'], target_commit=self.descriptor['source_commit'],
                          draft=False, body=self.amended, assets=self.files)

    def verify(self, descriptor, files):
        self.assertEqual(descriptor, self.descriptor)
        self.assertEqual(files, self.files)

    def test_published_retry_retains_amended_body_and_original_assets_without_writes(self):
        for body in [self.original, self.amended]:
            destination = MemoryDestination(dict(self.state, body=body))
            self.assertEqual(release.publish_release(destination, self.descriptor, self.files, self.verify,
                                                    lambda: None, dry_run=False, body_for=self.body_for), 'already-published')
            self.assertEqual(destination.writes, [])
            self.assertEqual(destination.state['body'], body)

    def test_draft_recovery_does_not_accept_presentation_amendments(self):
        for assets in [{}, self.files]:
            destination = MemoryDestination(dict(self.state, draft=True, assets=assets))
            with self.assertRaisesRegex(ValueError, 'release notes or descriptor marker conflict'):
                release.publish_release(destination, self.descriptor, self.files, self.verify,
                                        lambda: None, dry_run=False, body_for=self.body_for)
            self.assertEqual(destination.writes, [])

    def test_amendment_does_not_bypass_descriptor_or_asset_validation(self):
        bad = copy.deepcopy(self.state)
        bad['assets']['SHA256SUMS'] += b'tampered'
        with self.assertRaisesRegex(ValueError, 'asset hash conflict'):
            release._check_state(bad, self.descriptor, self.body_for)
        changed_descriptor = copy.deepcopy(self.descriptor)
        changed_descriptor['publisher']['run_id'] += 1
        with self.assertRaisesRegex(ValueError, 'descriptor marker conflict'):
            release._check_state(self.state, changed_descriptor, self.body_for)

    def test_latest_accepts_reviewed_body_but_rejects_other_edits_before_mutation(self):
        test = self
        class Api:
            prefix = '/repos/' + release.policy.REPOSITORY
            def pages(self, path):
                return [dict(id=20, tag_name=test.descriptor['tag'], draft=False, prerelease=False)]
            def read_release(self, tag, release_id=None):
                return test.state
            def request(self, method, path, **kwargs):
                test.assertEqual(method, 'GET')
                return dict(id=20, tag_name=test.descriptor['tag'])
        self.assertEqual(release.reconcile_latest(Api(), self.verify, lambda d: None,
                                                 dry_run=False, body_for=self.body_for), 'already-latest')
        self.state['body'] = self.amended.replace('A readable summary.', 'An unreviewed claim.')
        with self.assertRaisesRegex(ValueError, 'release notes or descriptor marker conflict'):
            release.reconcile_latest(Api(), self.verify, lambda d: None, dry_run=False, body_for=self.body_for)


if __name__ == '__main__':
    unittest.main()
