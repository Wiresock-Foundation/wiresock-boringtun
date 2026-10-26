# Attestation-only validation implementation plan

> **For agentic workers:** Use executing-plans for the implementation and an independent security reviewer for the final diff.

**Goal:** Validate the real publisher's six-subject attestations once, while release publication remains disabled.

**Architecture:** Reuse the trusted workflow_run preparation/signing machinery. A separate, reviewed trial selection names one merged PR; only its first exact source build and publisher attempt, with source C equal to publisher recipe R, can sign. A read-only verification job preserves actual pinned-gh output. No release-write job is reachable in trial mode.

**Tech stack:** Existing Python policy/orchestrator, GitHub Actions and checksum-pinned gh2.100.0.

**Spec:** ../../BORINGTUN_ACTIVATION_AUDIT.md, proposed attestation-only permission request; owner approved the specified one-run permission and public metadata effect on 26 October 2026. Review and CI must be reported before merge/execution.

## Constraints

- Keep release-policy enabled:false; do not change credentials, settings or tags.
- Signing permissions are contents:read, actions:read, id-token:write and attestations:write. Verification jobs are read-only.
- Require canonical workflow_run/master identity, reviewed workflow IDs, source C, exact B/P run IDs and first attempts, complete build gates and all six verified subjects.
- Live trial selection must equal the checked-out reviewed selection. R must equal C, preventing a later recipe from authorizing this old trial.
- A disabled selection, unrelated source, rerun, duplicate invocation or changed policy must produce no signing or publication authority.

## Review focus

Wrong selected PR/source; later run attempts or duplicate invocations; live selection revocation; prepared-byte substitution; signing success accidentally enabling a content-write job.

## Task 1: Narrow trial gate and retained verification evidence

Files: scripts/boringtun_release.py, packaging/boringtun/attestation-validation.json, tests/test_attestation_validation.py.

- [x] Add failing tests for trial selection, enabled publication rejection, C/R disagreement, wrong B/P attempts, duplicate run inventory, changed live policy and altered prepared bytes.
- [x] Implement validation_gate(api, config, context, descriptor), returning only after all trial invariants hold; reuse preparation and static archive verification.
- [x] Add validation-attest-ready and verify-validation commands. The latter requires successful exact signing jobs and saves six actual gh JSON results locally; neither command exposes release mutation.
- [x] Run full producer tests and preserve existing publication behavior.

## Task 2: Workflow isolation, independent review and draft PR

Files: .github/workflows/boringtun-release.yml, tests/test_attestation_validation.py, docs/BORINGTUN_ACTIVATION_AUDIT.md.

- [x] Expose a separate validation output from preparation. Signing can use this output, but publish must explicitly reject it and still require publishable:true.
- [x] Add a read-only post-signing verification/evidence job; pin actions and use exact prepared artifact ID/digest.
- [x] Test the workflow boundary, exact permissions and absence of mutation commands in trial paths; run actionlint.
- [ ] Obtain independent security review, fix concrete findings, commit and open a scoped draft stacked on the identity repair.
- [ ] Keep selection dormant until the concrete PR number is known, then select only that PR in a reviewed update. Report exact-head checks before parent decides whether to merge. No signing run occurs during PR CI.

Self-review: each authority boundary has a negative regression; existing build and attestation verification functions remain the source of truth. This adds no automatic release recovery or general publisher activation.


Independent design check: use all-status inventories and fresh latest-run reads,
require action=create and attest=true, bind descriptor publisher to current
trusted context, save raw gh stdout before parsing and upload it on failure.
Signing-job concurrency serializes duplicate trial invocations. Inventory reads
are not claimed to be a transactional once-only ledger under deleted history.
