"""Version intent is a source transition, never a counter advanced by a retry."""
import copy
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


class SourceTransitionTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(release, 'source_intent', None)), 'trusted source intent gate is missing')
        self.source = 'a' * 40
        self.parent = 'b' * 40
        self.base = snapshot('0.8.0')
        self.head = snapshot('0.8.1', 'patch')
        self.changed = [INTENT, 'boringtun/src/lib.rs', 'docs/releases/0.8.1.md']
        test = self
        class Api:
            prefix = '/repos/Wiresock-Foundation/wiresock-boringtun'
            def get(self, path):
                if path.endswith('/compare/' + version.BASELINE + '...' + test.source):
                    return {'status': 'ahead', 'merge_base_commit': {'sha': version.BASELINE}}
                if path.endswith('/commits/' + test.source):
                    return {'sha': test.source, 'parents': [{'sha': test.parent}, {'sha': 'c' * 40}]}
                if path.endswith('/compare/' + test.parent + '...' + test.source):
                    return {'status': 'ahead', 'merge_base_commit': {'sha': test.parent},
                            'files': [{'filename': p} for p in test.changed]}
                raise AssertionError(path)
            def contents(self, path, ref):
                return (test.head if ref == test.source else test.base)[path]
            def optional_contents(self, path, ref):
                return (test.head if ref == test.source else test.base).get(path)
        self.api = Api()

    def test_actual_first_parent_drives_version_gate(self):
        self.assertEqual(release.source_intent(self.api, self.source)['version'], '0.8.1')
        self.base = snapshot('0.8.1')
        with self.assertRaises(ValueError):
            release.source_intent(self.api, self.source)

    def test_missing_intent_or_downgrade_after_baseline_is_not_legacy(self):
        for head in [snapshot('0.7.1'), snapshot('0.7.1', 'minor', '0.8.0')]:
            self.head = head
            with self.assertRaises(ValueError):
                release.source_intent(self.api, self.source)

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


if __name__ == '__main__':
    unittest.main()
