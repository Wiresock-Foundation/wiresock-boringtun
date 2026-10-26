"""A single selected validation may sign, but cannot authorize publication."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import boringtun_release as release
import boringtun_release_policy as policy
import test_release_policy as fixtures


class BytesFile:
    def __init__(self, raw):
        self.raw = raw

    def read_bytes(self):
        return self.raw


class TrialApi:
    prefix = '/repos/' + policy.REPOSITORY

    def __init__(self, config_raw, trial_raw):
        self.contents_by_path = {release.POLICY_FILE.name: config_raw, 'attestation-validation.json': trial_raw}
        self.build = dict(fixtures.run_fixture(), run_attempt=1)
        self.publisher = dict(self.build, id=500, workflow_id=400, path=policy.PUBLISH_WORKFLOW,
                              event='workflow_run', status='in_progress', conclusion=None)
        self.duplicates = False

    def contents(self, path, ref):
        if ref != 'master':
            raise AssertionError(ref)
        return self.contents_by_path[path.rsplit('/', 1)[1]]

    def get(self, path):
        if path == self.prefix + '/actions/runs/100':
            return copy.deepcopy(self.build)
        if path == self.prefix + '/actions/runs/500':
            return copy.deepcopy(self.publisher)
        raise AssertionError(path)

    def pages(self, path, key):
        if key != 'workflow_runs' or 'head_sha=' + fixtures.C not in path:
            raise AssertionError(path)
        item = self.build if '/workflows/200/' in path else self.publisher
        values = [copy.deepcopy(item)]
        if self.duplicates:
            values.append(dict(item, id=item['id'] + 1, status='queued', conclusion=None))
        return values


class AttestationValidationTests(unittest.TestCase):
    def setUp(self):
        self.config = dict(enabled=False, attribution_status='reviewed', build_workflow_id=200, publish_workflow_id=400)
        self.trial = {'schema': 1, 'pr': 42}
        self.config_raw = json.dumps(self.config).encode()
        self.trial_raw = json.dumps(self.trial).encode()
        self.api = TrialApi(self.config_raw, self.trial_raw)
        self.descriptor = fixtures.PolicyTests().descriptor()
        self.descriptor['build_run']['run_attempt'] = 1
        self.descriptor['artifact']['name'] = 'boringtun-100-1'
        self.descriptor['publisher'].update(recipe_commit=fixtures.C, run_attempt=1)
        self.context = dict(repository=policy.REPOSITORY, **self.descriptor['publisher'])
        self.addCleanup(patch.stopall)
        patch.object(release, 'POLICY_FILE', BytesFile(self.config_raw)).start()
        patch.object(release, 'VALIDATION_FILE', BytesFile(self.trial_raw), create=True).start()
        patch.object(release, 'triggered_build', return_value=(100, 1)).start()

    def gate(self):
        return release.validation_gate(self.api, self.config, self.context, self.descriptor)

    def test_selected_first_attempt_and_exact_recipe_are_eligible(self):
        self.gate()

    def test_publication_must_remain_explicitly_disabled(self):
        for value in (True, None, 0):
            self.config['enabled'] = value
            with self.subTest(value=value), self.assertRaises(policy.PolicyError):
                self.gate()

    def test_dormant_or_wrong_pr_selection_cannot_sign(self):
        for value in (None, 0, True, 43):
            patch.object(release, 'VALIDATION_FILE', BytesFile(json.dumps(dict(schema=1, pr=value)).encode())).start()
            with self.subTest(value=value), self.assertRaises(policy.PolicyError):
                self.gate()

    def test_later_recipe_or_foreign_descriptor_publisher_is_rejected(self):
        for key, value in [('recipe_commit', fixtures.R), ('run_id', 501), ('run_attempt', 2)]:
            changed = copy.deepcopy(self.descriptor)
            changed['publisher'][key] = value
            with self.subTest(key=key), self.assertRaises(policy.PolicyError):
                release.validation_gate(self.api, self.config, self.context, changed)

    def test_build_must_be_the_exact_trigger_and_first_attempt(self):
        for value in ((101, 1), (100, 2)):
            with patch.object(release, 'triggered_build', return_value=value), self.assertRaises(policy.PolicyError):
                self.gate()

    def test_latest_run_attempt_rejects_retained_first_attempt_after_rerun(self):
        for field in ('build', 'publisher'):
            current = getattr(self.api, field)
            current['run_attempt'] = 2
            with self.subTest(run=field), self.assertRaises(policy.PolicyError):
                self.gate()
            current['run_attempt'] = 1

    def test_fresh_get_rejects_rerun_even_when_inventory_is_stale(self):
        original = self.api.get
        for ident in (100, 500):
            def latest(path):
                run = original(path)
                if path.endswith('/' + str(ident)):
                    run['run_attempt'] = 2
                return run
            with patch.object(self.api, 'get', side_effect=latest), self.subTest(run=ident), self.assertRaises(policy.PolicyError):
                self.gate()

    def test_duplicate_inventory_counts_queued_and_failed_runs(self):
        self.api.duplicates = True
        with self.assertRaises(policy.PolicyError):
            self.gate()

    def test_live_selection_or_policy_change_revokes_trial(self):
        for name in self.api.contents_by_path:
            original = self.api.contents_by_path[name]
            self.api.contents_by_path[name] = b'{}'
            with self.subTest(name=name), self.assertRaises(policy.PolicyError):
                self.gate()
            self.api.contents_by_path[name] = original

    def test_publisher_metadata_cannot_change_workflow_event_source_or_branch(self):
        for key, value in [('event', 'workflow_dispatch'), ('head_sha', fixtures.H),
                           ('head_branch', 'other'), ('path', policy.BUILD_WORKFLOW), ('workflow_id', 999)]:
            original = self.api.publisher[key]
            self.api.publisher[key] = value
            with self.subTest(key=key), self.assertRaises(policy.PolicyError):
                self.gate()
            self.api.publisher[key] = original

    def test_prepared_validation_rejects_recovered_or_changed_content(self):
        files = {'RELEASE.json': b'original'}
        for action, attest, returned in [('resume', True, files), ('create', False, files),
                                          ('create', True, {'RELEASE.json': b'changed'})]:
            with patch.object(release, 'prepare_release', return_value=(self.descriptor, returned, action, attest)), \
                 self.subTest(action=action, attest=attest), self.assertRaises(policy.PolicyError):
                release.validation_prepared(self.api, self.config, self.context, self.descriptor, files, 'gh')

    def test_revocation_during_preparation_is_checked_again(self):
        def prepare(*_args):
            self.api.contents_by_path['attestation-validation.json'] = b'{}'
            return self.descriptor, {}, 'create', True
        with patch.object(release, 'prepare_release', side_effect=prepare), self.assertRaises(policy.PolicyError):
            release.validation_prepared(self.api, self.config, self.context, self.descriptor, {}, 'gh')

    def test_verification_keeps_raw_stdout_before_schema_rejection(self):
        descriptor = self.descriptor
        files = {'RELEASE.json': policy.canonical_bytes(descriptor)}
        request = dict(pr=42, source_commit=fixtures.C)
        metadata = {key: descriptor[key] for key in ('version', 'rust_toolchain', 'toolchain_sha256', 'notice_provenance_sha256')}
        raw = b'{"new-live-gh-shape":true}\n'
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(release, 'resolve_build_request', return_value=request), \
             patch.object(release, 'source_metadata', return_value=metadata), \
             patch.object(release, 'build_run_evidence', return_value={'workflow_id': 200}), \
             patch.object(release, 'check_publisher_evidence'), patch.object(release, 'static_archive_gate'), \
             patch.object(release.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=raw, stderr=b'never-save-stderr')):
            class Api:
                prefix = TrialApi.prefix
                def get(self, _path): return {}
                def pages(self, *_args): return []
                def contents(self, *_args): return b'license'
            with self.assertRaises(policy.PolicyError):
                release.verify_release(Api(), descriptor, files, self.config, 'gh', verification_output=directory)
            entries = list(Path(directory).iterdir())
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].read_bytes(), raw)


class ValidationWorkflowTests(unittest.TestCase):
    def test_retirement_evidence_records_disabled_workflow_without_enabling_publication(self):
        config = json.loads((ROOT / 'packaging/boringtun/release-policy.json').read_text())
        audit = json.loads((ROOT / config['retirement']['owner_audit']).read_text())
        self.assertIs(config['enabled'], False)
        self.assertEqual(audit['workflow']['state'], 'disabled_manually')
        self.assertEqual(config['retirement']['workflow_ids'], [audit['workflow']['id']])
        self.assertEqual(config['retirement']['files'], audit['files'])
        self.assertEqual(audit['draft_count'], 0)
        self.assertTrue(all(item['status'] == 'completed' for item in audit['runs']))
        self.assertTrue(audit['requires_recheck_before_activation'])

    def test_signing_mode_cannot_reach_content_write_job(self):
        workflow = (ROOT / '.github/workflows/boringtun-release.yml').read_text()
        attest = workflow.split('  attest:\n')[1].split('  publish:\n')[0]
        publish = workflow.split('  publish:\n')[1].split('  verify-validation:\n')[0]
        verify = workflow.split('  verify-validation:\n')[1]
        self.assertIn("needs.prepare.outputs.validation == 'true'", attest)
        self.assertIn("needs.prepare.outputs.validation != 'true'", publish)
        self.assertIn("needs.prepare.outputs.publishable == 'true'", publish)
        self.assertIn('validation-attest-ready', attest)
        self.assertIn('cancel-in-progress: false', attest)
        self.assertNotIn('contents: write', attest)
        self.assertIn('id-token: write', attest)
        self.assertIn('attestations: write', attest)
        self.assertNotIn(': write', verify)
        self.assertNotIn('--execute', verify)
        self.assertIn('verify-validation', verify)
        self.assertIn('if: always()', verify)


if __name__ == '__main__':
    unittest.main()
