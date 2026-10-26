"""Captured GitHub API boundaries; synthetic changes are explicitly labelled."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import boringtun_release as release
import boringtun_release_policy as policy

FIXTURES = ROOT / 'tests/fixtures/github'
H = 'a535ac169c268c9c45f0e4f1b17db8ef4536199c'
C = 'd33fa41ad1917846a5a722ff3bfb64830b650941'


class MergedRunBindingTests(unittest.TestCase):
    def setUp(self):
        self.pr_event = json.loads((FIXTURES / 'merged-pr-96-attempt-1.json').read_text())
        self.push = json.loads((FIXTURES / 'master-push-attempt-1.json').read_text())
        self.pr = json.loads((FIXTURES / 'merged-pr-96.json').read_text())
        self.request = policy.merged_request(release.project_pr(self.pr), 96)

    def build_run(self):
        # Only workflow path/ID change: this records a successful real master push.
        return dict(self.push, workflow_id=397187760, path=policy.BUILD_WORKFLOW)

    def test_recorded_events_distinguish_pr_head_from_executed_source(self):
        self.assertEqual(self.pr_event['head_sha'], H)
        self.assertEqual(self.pr_event['pull_requests'], [])
        self.assertEqual(self.push['head_sha'], C)
        self.assertEqual(self.push['head_branch'], 'master')
        self.assertEqual(self.push['pull_requests'], [])
        self.assertEqual(self.pr['merge_commit_sha'], C)

    def test_master_push_accepts_empty_associations_and_uses_c(self):
        result = policy.check_build_run(release.project_run(self.build_run()), self.request, 397187760)
        self.assertEqual(result['head_sha'], C)
        self.assertEqual(result['pull_requests'], [])

    def test_closed_pr_run_cannot_be_reinterpreted_as_push(self):
        with self.assertRaises(policy.PolicyError):
            policy.check_build_run(release.project_run(self.pr_event), self.request, 397187760)

    def test_push_rejects_wrong_head_event_branch_attempt_and_time(self):
        for key, value in [('head_sha', H), ('event', 'pull_request'), ('event', 'workflow_dispatch'),
                           ('head_branch', 'other'), ('run_attempt', True), ('conclusion', 'failure'),
                           ('created_at', '2026-10-26T14:54:24Z'), ('workflow_id', 397049721),
                           ('path', policy.PUBLISH_WORKFLOW), ('pull_requests', None)]:
            raw = self.build_run()
            raw[key] = value
            with self.subTest(key=key), self.assertRaises(policy.PolicyError):
                policy.check_build_run(release.project_run(raw), self.request, 397187760)

    def test_commit_lookup_requires_unique_exact_canonical_merged_pr(self):
        self.assertEqual(policy.merged_pr_number([self.pr], C), 96)
        for entries in [[], [dict(self.pr, state='open')], [dict(self.pr, merged_at=None)],
                        [dict(self.pr, merge_commit_sha=H)], [self.pr, dict(self.pr, number=97)],
                        [self.pr, self.pr], [dict(self.pr, base=dict(self.pr['base'], ref='other'))]]:
            with self.subTest(entries=len(entries)), self.assertRaises(policy.PolicyError):
                policy.merged_pr_number(entries, C)

    def test_commit_lookup_ignores_unrelated_associated_prs(self):
        unrelated = [dict(self.pr, number=97, merge_commit_sha=H),
                     dict(self.pr, number=98, state='open'),
                     dict(self.pr, number=99, base=dict(self.pr['base'], ref='other'))]
        self.assertEqual(policy.merged_pr_number(unrelated + [self.pr], C), 96)
        with self.assertRaises(policy.PolicyError):
            policy.merged_pr_number([self.pr, dict(self.pr, base=None)], C)

    def test_merge_squash_rebase_use_postmerge_source_without_parent_assumptions(self):
        # Synthetic strategy cases exercise REST's documented postmerge C;
        # the stored real PR96 fixture is a normal merge, not live rebase proof.
        for label, head in [('merge', H), ('squash', 'b'*40), ('rebase', 'f'*40), ('identity', C)]:
            pr = copy.deepcopy(self.pr)
            pr['head']['sha'] = head
            request = policy.merged_request(release.project_pr(pr), 96)
            with self.subTest(strategy=label):
                self.assertEqual(policy.merged_pr_number([pr], C), 96)
                self.assertEqual(policy.check_build_run(release.project_run(self.build_run()), request, 397187760)['head_sha'], C)

    def test_commit_discovery_reads_all_pages_before_selecting(self):
        test = self
        class Api(release.GitHub):
            def get(self, path):
                if path.endswith('page=1'):
                    return [dict(test.pr, number=n, merge_commit_sha=H) for n in range(100, 200)]
                test.assertTrue(path.endswith('page=2'))
                return [test.pr]
        self.assertEqual(policy.merged_pr_number(Api().pages('/repos/' + policy.REPOSITORY + '/commits/' + C + '/pulls'), C), 96)

    def test_discovery_rechecks_fresh_pr_and_ancestry(self):
        test = self
        class Api:
            prefix = '/repos/' + policy.REPOSITORY
            fresh = None
            def pages(self, path, key=None):
                if path != self.prefix + '/commits/' + C + '/pulls':
                    raise AssertionError(path)
                return [copy.deepcopy(test.pr)]
            def get(self, path):
                values = {
                    self.prefix: test.push['repository'],
                    self.prefix + '/pulls/96': self.fresh or test.pr,
                    self.prefix + '/compare/' + C + '...master':
                        {'status': 'identical', 'merge_base_commit': {'sha': C}},
                }
                return copy.deepcopy(values[path])
        api = Api()
        self.assertEqual(release.resolve_build_request(api, self.build_run()), self.request)
        api.fresh = dict(self.pr, merged=False)
        with self.assertRaises(policy.PolicyError):
            release.resolve_build_request(api, self.build_run())

    def test_push_context_rejects_forced_created_deleted_and_wrong_checkout(self):
        event = {'ref': 'refs/heads/master', 'before': H, 'after': C,
                 'created': False, 'deleted': False, 'forced': False,
                 'repository': self.push['repository']}
        context = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REPOSITORY': policy.REPOSITORY,
                   'GITHUB_REF': 'refs/heads/master', 'GITHUB_SHA': C, 'GITHUB_WORKFLOW_SHA': C}
        release.check_push_context(self.request, event, context, C)
        for key, value in [('forced', True), ('created', True), ('deleted', True), ('forced', 0),
                           ('before', '0' * 40), ('before', C), ('after', H), ('ref', 'refs/heads/other')]:
            with self.subTest(key=key, value=value), self.assertRaises(policy.PolicyError):
                release.check_push_context(self.request, dict(event, **{key: value}), context, C)
        for key in ['forced', 'created', 'deleted', 'before']:
            changed = dict(event)
            del changed[key]
            with self.assertRaises(policy.PolicyError):
                release.check_push_context(self.request, changed, context, C)
        for key, value in [('GITHUB_SHA', H), ('GITHUB_WORKFLOW_SHA', H),
                           ('GITHUB_REF', 'refs/pull/96/merge'), ('GITHUB_EVENT_NAME', 'pull_request')]:
            with self.assertRaises(policy.PolicyError):
                release.check_push_context(self.request, event, dict(context, **{key: value}), C)
        with self.assertRaises(policy.PolicyError):
            release.check_push_context(self.request, event, context, H)


if __name__ == '__main__':
    unittest.main()
