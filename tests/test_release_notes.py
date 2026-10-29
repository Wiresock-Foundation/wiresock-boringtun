"""Human presentation retains exact signed bytes and immutable retry behavior."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import boringtun_release as release
import boringtun_release_policy as policy
import test_release_orchestration as fixtures
from test_draft_readback import ReleaseService

PROSE = 'Readable summary.\n\n## Fixed\n\n- Slow clients no longer block traffic.\n\n## Compatibility & upgrade notes\n\nRestart the service.'


def modern_fixture():
    fixture = fixtures.OrchestrationTests()
    fixture.setUp()
    descriptor = fixture.descriptor
    descriptor['version'] = '0.8.0'
    descriptor['tag'] = descriptor['tag'].replace('0.7.1', '0.8.0')
    files = {name.replace('0.7.1', '0.8.0'): data for name, data in fixture.files.items()}
    for archive in descriptor['archives']:
        archive['name'] = archive['name'].replace('0.7.1', '0.8.0')
    files['RELEASE.json'] = policy.canonical_bytes(descriptor)
    files['SHA256SUMS'] = files['SHA256SUMS'].replace(b'0.7.1', b'0.8.0')
    return descriptor, files


class NotesTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(release, 'render_body', None)), 'human release renderer is missing')
        self.descriptor, self.files = modern_fixture()
        self.body_for = lambda d: release.render_body(PROSE, d, 'b' * 40)

    def verify(self, descriptor, files):
        self.assertEqual(files['RELEASE.json'], policy.canonical_bytes(descriptor))

    def test_legacy_and_new_metadata_recover_exact_bytes(self):
        for body in [release.descriptor_marker(self.descriptor), self.body_for(self.descriptor)]:
            descriptor, raw = release.recorded_descriptor(body)
            self.assertEqual(raw, self.files['RELEASE.json'])
            self.assertEqual(descriptor, self.descriptor)
        body = self.body_for(self.descriptor)
        visible = body.split('<!--')[0]
        self.assertTrue(visible.startswith('Readable summary.'))
        self.assertNotIn('base64', visible)
        self.assertIn('/pull/42', visible)
        self.assertIn('/compare/' + 'b' * 40 + '...', visible)
        self.assertIn('/releases/download/', visible)

    def test_parser_rejects_duplicate_malformed_tampered_and_unbounded_blocks(self):
        body = self.body_for(self.descriptor)
        marker = release.descriptor_marker(self.descriptor)
        for bad in [body + '\n' + body, body + '\n' + marker, body.replace('metadata:v1', 'metadata:v2'),
                    body.replace('descriptor_sha256=', 'descriptor_sha256=0'), body + '\ntrailer',
                    body.replace('<!--', '<!-- extra <!--'), 'x' * 65536 + body,
                    body.replace('RELEASE.json(base64)=', 'RELEASE.json(base64)=!')]:
            with self.subTest(bad=bad[:60]), self.assertRaises(policy.PolicyError):
                release.recorded_descriptor(bad)

    def test_human_body_survives_uncertain_creation_upload_and_publish(self):
        for operation in ['create', 'upload:RELEASE.json', 'publish']:
            destination = fixtures.MemoryDestination(uncertain=operation)
            self.assertEqual(release.publish_release(destination, self.descriptor, self.files, self.verify,
                                                    lambda: None, dry_run=False, body_for=self.body_for), 'published')
            self.assertEqual(destination.state['body'], self.body_for(self.descriptor))
            self.assertEqual(len(destination.state['assets']), 7)
            self.assertEqual(destination.writes.count(operation), 1)

    def test_empty_draft_and_published_retry_keep_original_signed_bytes(self):
        state = dict(id=20, tag=self.descriptor['tag'], target_commit=self.descriptor['source_commit'],
                     draft=True, body=self.body_for(self.descriptor), assets={})
        desired = copy.deepcopy(self.descriptor)
        desired['publisher']['run_id'] = 900
        files = dict(self.files, **{'RELEASE.json': policy.canonical_bytes(desired)})
        destination = fixtures.MemoryDestination(state)
        self.assertEqual(release.publish_release(destination, desired, files, self.verify, lambda: None,
                                                dry_run=False, body_for=self.body_for), 'published')
        self.assertEqual(destination.state['assets']['RELEASE.json'], self.files['RELEASE.json'])
        writes = list(destination.writes)
        self.assertEqual(release.publish_release(destination, desired, files, self.verify, lambda: None,
                                                dry_run=False, body_for=self.body_for), 'already-published')
        self.assertEqual(destination.writes, writes)

    def test_changed_prose_or_legacy_body_for_new_release_is_rejected(self):
        for body in [self.body_for(self.descriptor).replace('Readable summary.', 'Unreviewed claim.'),
                     release.descriptor_marker(self.descriptor)]:
            state = dict(id=20, tag=self.descriptor['tag'], target_commit=self.descriptor['source_commit'],
                         draft=True, body=body, assets={})
            destination = fixtures.MemoryDestination(state)
            with self.assertRaises(policy.PolicyError):
                release.publish_release(destination, self.descriptor, self.files, self.verify, lambda: None,
                                        dry_run=False, body_for=self.body_for)
            self.assertEqual(destination.writes, [])

    def test_rest_create_uses_human_title_and_keeps_latest_disabled(self):
        service = ReleaseService()
        api = release.GitHub(token='owner-token')
        api.opener = service
        result = api.create_draft(self.descriptor['tag'], self.descriptor['source_commit'], self.body_for(self.descriptor))
        self.assertEqual(result['name'], 'WireSock BoringTun 0.8.0')
        self.assertEqual(result['make_latest'], 'false')


if __name__ == '__main__':
    unittest.main()
