# Candidate retry repair implementation plan

> **For agentic workers:** Execute inline with test-driven development, followed by independent review.

**Goal:** Make read-only candidate validation safe to retry without waiting 90 minutes for a stalled APT mirror.

**Architecture:** Resolve an artifact by the exact latest successful producer job and its originating attempt within the current candidate run. Keep immutable run/attempt artifact names and download the selected artifact ID. Release and signing paths do not consume this helper.

**Tech stack:** Python standard library, Bash, GitHub Actions REST metadata and pinned artifact actions.

**Spec:** The parent-authorized repair requires partial and full reruns; failed, missing, stale and cross-run inputs must fail closed. Preserve signing/release provenance binding, all five platforms, and normal non-force updates to PR97 and stacked PR98. No merge, signing or publication.

## Constraints and review focus

- An attempt-2 consumer may use a successful attempt-1 producer only from the same run and exact source.
- A newer failed producer must block fallback to an older successful producer.
- Full reruns select the new producer attempt, not a stale artifact.
- Missing, ambiguous, expired, wrong-source or wrong-run artifacts must block download.
- Every paginated metadata response must be checked; artifact creation must fall within the producer job.
- APT errors must propagate; network retries, socket timeouts, lock waiting and workflow setup duration must be bounded.

## Task 1: Candidate artifact resolution

- [x] Add `tests/test_candidate_artifacts.py` regressions for the cases above and observe failures.
- [x] Implement `scripts/boringtun_candidate_artifact.py`: metadata resolver returning exact artifact ID, digest, producer job ID and attempt. Use only read-only APIs scoped to the current canonical candidate run.
- [x] Wire notice/archive downloads in `boringtun-platform-validation.yml` to the resolver with job-scoped `actions: read`; keep uploads immutable and attempt-scoped.
- [x] Run candidate tests and full Python release suites.

## Task 2: Bound setup and integrate

- [x] Add behavioral tests for `scripts/boringtun-ci-apt.sh`: bounded update/install arguments, nonzero update propagation and invalid package rejection.
- [x] Implement the helper and ten-minute setup-step limits; make APT update fail on any repository error.
- [x] Run affected suites and actionlint; request independent review of both tasks.
- [ ] Commit on PR97; merge that branch normally into stacked PR98 without rewriting history. Re-run both final local suites, push both branches and monitor fresh nonpublishing CI.

## Execution record

Initial evidence: PR97 run 40352730902 attempt 1 stalled inside `apt-get update` after Ubuntu mirror failures and ended cancelled at its 90-minute job limit. PR98's identical setup completed in roughly 20 seconds. Failed-only retry would request attempt-2 artifacts although successful producer jobs retained attempt-1 artifacts. Original logs are preserved in the task's provenance directory.

Plan self-review: all requested input classes map to Task 1; APT termination and error propagation map to Task 2. Existing isolated worktrees are clean. Implementation and pushing are already authorized; no additional planning approval is needed.

RED: 17 new tests ran and failed because the two helpers did not exist (19 reported assertion failures including package-name subtests). GREEN: all candidate tests passed under WSL. A captured GitHub metadata fixture and workflow wiring regression were added afterward and included in the final verification below.

Independent review by a fresh reviewer found no findings or code blockers. It independently checked real API job/artifact metadata and the pinned download action's ID, extraction and digest behavior. Its final Windows candidate run passed 23 tests with 3 Linux-only skips; WSL was unavailable to that reviewer, so the main executor ran those tests under WSL.

Final local verification before integration: 116 Python release/candidate tests, 16 notice tests and 16 binary-format tests passed under WSL; all nine applicable workflows passed actionlint 1.7.12. Attribution checks passed for 39 files with existing dates preserved. These fixture checks do not claim a live partial rerun has executed; fresh exact-head native candidate CI is required after pushing.
