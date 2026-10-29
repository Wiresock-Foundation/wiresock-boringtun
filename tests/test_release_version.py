"""Version intent is a source transition, never a counter advanced by a retry."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import tempfile
import os


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import boringtun_release as release
try:
    import boringtun_version as version
except ImportError:
    version = None

INTENT = 'packaging/boringtun/release-intent.json'


def snapshot(value, bump=None, base='0.8.0'):
    result = {
        'boringtun/Cargo.toml': f'[package]\nname="boringtun"\nversion="{value}"\n'.encode(),
        'boringtun-cli/Cargo.toml': (f'[package]\nname="boringtun-cli"\nversion="{value}"\n'
                                   f'[dependencies.boringtun]\npath="../boringtun"\nversion="{value}"\n').encode(),
        'Cargo.lock': (f'version=4\n[[package]]\nname="boringtun"\nversion="{value}"\n'
                       f'[[package]]\nname="boringtun-cli"\nversion="{value}"\n').encode(),
    }
    result['packaging/boringtun/notice-policy.json'] = json.dumps({
        'source_lock_sha256': [hashlib.sha256(result['Cargo.lock']).hexdigest()]
    }).encode()
    if bump:
        result[INTENT] = json.dumps(dict(schema=1, bump=bump, base_version=base,
                                        version=value, reason='Explain this reviewed change.')).encode()
        result[f'docs/releases/{value}.md'] = b'This release improves reliability.\n\n## Fixed\n\n- A fix.\n\n## Compatibility & upgrade notes\n\nNo configuration changes.\n'
    return result


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(version, 'version intent validator is missing')

    def check(self, base, source, changed=None):
        if changed is None:
            changed = ['boringtun/src/lib.rs', INTENT, *[p for p in source if p.startswith('docs/releases/')]]
        return version.check_transition(base.get, source.get, list(changed))

    def test_reviewed_minor_and_patch_are_repeatable(self):
        for before, after, bump in [('0.7.1', '0.8.0', 'minor'), ('0.8.0', '0.8.1', 'patch'),
                                    ('0.8.9', '0.9.0', 'minor')]:
            base, source = snapshot(before), snapshot(after, bump, before)
            self.assertEqual(self.check(base, source)['version'], after)
            self.assertEqual(self.check(base, source)['version'], after)

    def test_stale_concurrent_pr_and_wrong_bump_fail(self):
        for before, after, bump, declared in [('0.8.1', '0.8.1', 'patch', '0.8.0'),
                                            ('0.8.0', '0.9.0', 'patch', '0.8.0'),
                                            ('0.8.0', '0.7.1', 'minor', '0.8.0')]:
            with self.subTest(after=after), self.assertRaises(ValueError):
                self.check(snapshot(before), snapshot(after, bump, declared))

    def test_none_accepts_docs_tests_but_refuses_product_or_workflow_changes(self):
        base, source = snapshot('0.8.0'), snapshot('0.8.0', 'none')
        self.assertEqual(self.check(base, source, ['docs/guide.md', 'tests/test_fix.py', INTENT])['bump'], 'none')
        for path in ['boringtun/src/lib.rs', '.github/workflows/on-push.yaml', 'Cargo.lock']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.check(base, source, [path, INTENT])
        with self.assertRaises(ValueError):
            self.check(base, snapshot('0.8.1', 'none'), ['README.md', INTENT])

    def test_every_pr_needs_fresh_intent_and_versioned_notes(self):
        source = snapshot('0.8.1', 'patch')
        base = snapshot('0.8.0')
        for missing in [INTENT, 'docs/releases/0.8.1.md']:
            bad = copy.deepcopy(source)
            bad.pop(missing)
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                self.check(base, bad)
        same = snapshot('0.8.0', 'none')
        with self.assertRaises(ValueError):
            self.check(same, same, ['README.md'])

    def test_manifests_dependency_and_lock_must_agree(self):
        good = snapshot('0.8.1', 'patch')
        for path in ['boringtun/Cargo.toml', 'boringtun-cli/Cargo.toml', 'Cargo.lock']:
            bad = copy.deepcopy(good)
            bad[path] = bad[path].replace(b'0.8.1', b'0.7.1', 1)
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.check(snapshot('0.8.0'), bad)

        bad = copy.deepcopy(good)
        bad['Cargo.lock'] += b'[[package]]\nname="boringtun"\nversion="0.8.1"\n'
        with self.assertRaises(ValueError):
            self.check(snapshot('0.8.0'), bad)

    def test_notes_reject_machine_markers_html_and_unbounded_content(self):
        for prose in [b'<!-- injected -->', b'descriptor_sha256=x', b'RELEASE.json(base64)=x',
                      b'x' * 20001, b'<script>alert(1)</script>']:
            bad = snapshot('0.8.1', 'patch')
            bad['docs/releases/0.8.1.md'] = prose
            with self.subTest(prose=prose[:20]), self.assertRaises(ValueError):
                self.check(snapshot('0.8.0'), bad)

    def test_version_bump_requires_reviewed_notice_lock_checksum(self):
        base, source = snapshot('0.8.0'), snapshot('0.8.1', 'patch')
        path = 'packaging/boringtun/notice-policy.json'
        for unreviewed in [base[path], b'{}', b'{"source_lock_sha256":[]}', b'[]', b'null']:
            with self.subTest(policy=unreviewed):
                source[path] = unreviewed
                with self.assertRaisesRegex(ValueError, 'notice policy'):
                    self.check(base, source)


class SourceTransitionTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(release, 'source_intent', None)), 'trusted source intent gate is missing')
        self.source = 'a' * 40
        self.parent = 'b' * 40
        self.direct_parent = self.parent
        self.rebase = False
        self.base = snapshot('0.8.0')
        self.head = snapshot('0.8.1', 'patch')
        self.changed = [INTENT, 'boringtun/src/lib.rs', 'docs/releases/0.8.1.md']
        self.final_changed = [INTENT, 'docs/guide.md']
        test = self
        class Api:
            prefix = '/repos/Wiresock-Foundation/wiresock-boringtun'
            def get(self, path):
                if path.endswith('/compare/' + version.BASELINE + '...' + test.source):
                    return {'status': 'ahead', 'merge_base_commit': {'sha': version.BASELINE}}
                if path.endswith('/commits/' + test.source):
                    parents = [{'sha': test.direct_parent}]
                    if not test.rebase:
                        parents.append({'sha': 'c' * 40})
                    return {'sha': test.source, 'parents': parents}
                if path.endswith('/pulls/115'):
                    return {'number': 115, 'state': 'closed', 'merged': True, 'merge_commit_sha': test.source,
                            'base': {'sha': test.parent, 'ref': 'master', 'repo': {'full_name': release.policy.REPOSITORY}}}
                if path.endswith('/compare/' + test.parent + '...' + test.source):
                    return {'status': 'ahead', 'merge_base_commit': {'sha': test.parent},
                            'files': [{'filename': p} for p in test.changed]}
                if path.endswith('/compare/' + test.direct_parent + '...' + test.source):
                    return {'status': 'ahead', 'merge_base_commit': {'sha': test.direct_parent},
                            'files': [{'filename': p} for p in test.final_changed]}
                raise AssertionError(path)
            def contents(self, path, ref):
                return (test.head if ref == test.source else test.intermediate if ref == test.direct_parent and test.rebase else test.base)[path]
            def optional_contents(self, path, ref):
                return (test.head if ref == test.source else test.intermediate if ref == test.direct_parent and test.rebase else test.base).get(path)
        self.api = Api()

    def test_merge_base_drives_version_gate(self):
        self.assertEqual(release.source_intent(self.api, self.source, 115)['version'], '0.8.1')
        self.base = snapshot('0.8.1')
        with self.assertRaises(ValueError):
            release.source_intent(self.api, self.source, 115)

    def test_squash_merge_uses_recorded_base(self):
        self.rebase = True  # one parent, but it is the recorded base
        self.intermediate = self.base
        self.assertEqual(release.source_intent(self.api, self.source, 115)['version'], '0.8.1')

    def test_boundary_requires_matching_merged_pr_and_merge_parent(self):
        original_get = self.api.get
        for change in [{'merged': False}, {'merge_commit_sha': 'f' * 40}, {'number': 116}]:
            with self.subTest(change=change), patch.object(self.api, 'get', side_effect=lambda path:
                    dict(original_get(path), **change) if '/pulls/' in path else original_get(path)):
                with self.assertRaises(ValueError):
                    release.source_intent(self.api, self.source, 115)
        self.direct_parent = 'd' * 40
        with self.assertRaises(ValueError):
            release.source_intent(self.api, self.source, 115)

    def test_bounded_full_path_inventory_rejects_none_rename_or_truncation(self):
        self.head = snapshot('0.8.0', 'none')
        self.changed = [INTENT, 'docs/guide.md']
        original_get = self.api.get
        for entries in [[{'filename': INTENT}, {'filename': 'docs/code.txt', 'previous_filename': 'boringtun/src/lib.rs'}],
                        [{'filename': INTENT}] * 300]:
            with self.subTest(size=len(entries)), patch.object(self.api, 'get', side_effect=lambda path:
                    dict(original_get(path), files=entries) if '/compare/' + self.parent in path else original_get(path)):
                with self.assertRaises(ValueError):
                    release.source_intent(self.api, self.source, 115)

    def test_multi_commit_rebase_uses_full_pr_boundary(self):
        self.rebase = True
        self.direct_parent = 'd' * 40
        self.intermediate = copy.deepcopy(self.head)
        self.final_changed = ['docs/guide.md']
        self.assertEqual(release.source_intent(self.api, self.source, 115)['version'], '0.8.1')

    def test_none_cannot_hide_product_changes_in_earlier_rebased_commit(self):
        self.rebase = True
        self.direct_parent = 'd' * 40
        self.intermediate = snapshot('0.8.0')
        self.head = snapshot('0.8.0', 'none')
        self.changed = [INTENT, 'boringtun/src/lib.rs', 'docs/guide.md']
        with self.assertRaises(ValueError):
            release.source_intent(self.api, self.source, 115)

    def test_missing_intent_or_downgrade_after_baseline_is_not_legacy(self):
        for head in [snapshot('0.7.1'), snapshot('0.7.1', 'minor', '0.8.0')]:
            self.head = head
            with self.assertRaises(ValueError):
                release.source_intent(self.api, self.source, 115)

    def test_none_resolve_emits_no_request_or_artifact(self):
        self.head = snapshot('0.8.0', 'none')
        self.changed = [INTENT, 'docs/guide.md']
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'request'
            with patch.object(release, 'GitHub', return_value=self.api), \
                 patch.object(release, 'resolve_request', return_value={'source_commit': self.source, 'pr': 115}), \
                 patch.dict(os.environ, GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REPOSITORY=release.policy.REPOSITORY):
                result = release.main(['resolve', '--pr', '115', '--run-id', '1', '--attempt', '1', '--output', str(output)])
            self.assertEqual(result, 0)
            self.assertFalse(output.exists())

    def test_none_build_completion_skips_promotion_without_failure(self):
        self.head = snapshot('0.8.0', 'none')
        self.changed = [INTENT, 'docs/guide.md']
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'prepared'
            with patch.object(release, 'GitHub', return_value=self.api), \
                 patch.object(release, 'trusted_context', return_value={}), \
                 patch.object(release, 'triggered_build', return_value=(1, 1)), \
                 patch.object(release, 'pinned_gh', return_value='gh'), \
                 patch.object(release, 'resolve_build_request', return_value={'source_commit': self.source, 'pr': 115}), \
                 patch.object(self.api, 'get', side_effect=lambda path: {} if '/actions/runs/' in path else original_get(path)):
                original_get = type(self.api).get.__get__(self.api)
                result = release.main(['prepare', '--build-run', '1', '--attempt', '1', '--output', str(output),
                                       '--gh', 'gh', '--gh-archive', 'gh.tar.gz'])
            self.assertEqual(result, 0)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
