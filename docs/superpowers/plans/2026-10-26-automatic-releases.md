# Automatic BoringTun releases implementation plan

> **For agentic workers:** Use executing-plans for integration, with independently
> scoped work delegated under dispatching-parallel-agents and fresh security/final review.

**Goal:** Prepare fork-owned automatic releases for every merged PR and explicit AWG adoption, locally only.
**Architecture:** Read-only merged-PR build; independently validating default-branch promotion; signed release descriptor; idempotent publisher. Reuse existing AWG packaging without changing archive format.
**Tech Stack:** Bash, Python3, GitHub Actions/REST, gh 2.100.0, Rust, musl, pinned macOS SDK/compiler and ARMv7 cross-linker/QEMU.
**Spec:** ../specs/2026-10-26-automatic-releases.md

## Local handoff status

Completed implementation covers reviewed notice profiles/runtime inventories,
strict five-target policy/orchestration, the read-only build workflow, and AWG
adoption/ARMv7 selection. Independent code and notice reviews found no blocking
defect in those completed portions. The publisher workflow file is absent after
an automatic approval review denial; do not interpret this plan as a completed
publisher or as permission to retry its creation. Local-file approval, subsequent
publisher review, real platform/GitHub evidence and historical attribution gates
remain outstanding. The checklist below retains the full intended plan; tasks
that include missing publisher work or live activation are not marked complete.

## Global constraints

- No remote publication, workflow dispatch, merge, credentials, settings or production changes.
- Every merged PR remains eligible; no branch-wide replace/cancel queue and no direct-push releases.
- No pull_request_target, PR-head execution with write credentials, approval-PR recursion or mutable latest adoption.
- Four-member binary archives preserved. RELEASE.json is an additional signed release asset.
- Five target archives: Linux x86_64/ARM64/ARMv7 hard-float and macOS Intel/Apple Silicon. Seven release assets and six attested subjects; schema 2 records per-target notice hashes.
- Unverified 2024 attribution and activation both block publication until reviewed resolution.

## Review focus

- Squash/rebase/merge identity and rapid consecutive merges must remain exact.
- Successful-looking untrusted artifacts must not cross the promotion boundary unchecked.
- Same-byte wrong-run attestations and stale/duplicate API events must fail or be idempotent.
- Partial/uncertain publication retries must never overwrite content.
- Legacy AWG cache identities, rollback and old release verification must remain valid.

## Task 1: Notice completeness and provenance

Files: artifact script, runtime notice generator/config/bundle, required-notices,
fork attribution files, artifact/release regression suites, licensing docs/REUSE.
Interface: `check-notices THIRD-PARTY-LICENSES LICENSE`; generation and package
gates require exact reviewed platform bundle, matching Rust/native input coverage and full fork license. Distribution SHA-256 and exact installed-runtime inventories cover all five targets.
- [ ] Add deletion/tampering/toolchain/source/symlink regression cases; run and observe intended failures.
- [ ] Finish checksum-bound generation and all production gates; keep test-only bypass isolated.
- [ ] Run artifact/release/licensing suites, deterministic refresh and feasible real generation/build checks; commit notice changes.

## Task 2: Pure release identity/provenance policy

Create `scripts/boringtun_release_policy.py` and `tests/test_release_policy.py`.
Interfaces: `merged_request(pr, expected_number) -> dict`; `check_build_run(run,
request, workflow_id) -> dict`; `make_descriptor(request, run, artifact, publisher,
archives) -> dict`; `check_descriptor(data) -> dict`; `publication_action(existing,
desired) -> str` (create/resume/already-published or reject). Inputs JSON, no shell evaluation.
- [ ] Test all three merge strategies, unmerged/foreign/base/head mismatch, wrong workflow/event/attempt/artifact, unknown keys and same tag/different bytes.
- [ ] Observe red; implement strict parsing and deterministic identities with build=PR number; green unittest suite.
- [ ] Validate exact verified attestation invocation/subjects and schema using recorded fixtures; test wrong-attempt/same-byte rejection. Commit.

## Task 3: Trusted orchestration and fork workflows

Create/adapt `scripts/boringtun-artifact.sh`, `scripts/boringtun-platform.py`,
`scripts/boringtun_release.py` (prepare, verify/publish and reconcile commands), `.github/workflows/boringtun-artifacts.yml`,
`.github/workflows/boringtun-release.yml`, `packaging/boringtun/release-policy.json`,
tests for workflow boundaries and mocked REST mutation ordering.
Consume Task2 policy; artifact tooling consumes Task1 notices.
- [ ] Write failing tests for no publish on gate failure, per-PR queue identity, missing/forked request, traversal/duplicate archives, missing attestation, partial draft/resume, uncertain write readback and conflicting tags/assets.
- [ ] Reuse/adapt AWG tools; read-only build trigger on merged closed PR; workflow_run promoter revalidates GitHub evidence and never executes artifact content. Add signed RELEASE.json, exact CLI pin and idempotent mutation sequence.
- [ ] Preserve two-build equality for every target, Linux TUN/interop and native macOS utun gates; label ARMv7 cross-build/QEMU explicitly. Enforce activation=false and attribution=blocked, pinned AWG retirement conditions.
- [ ] Add read-only reconciliation with exact missed/failed PR recovery output; no dispatch permissions.
- [ ] Run all policy/workflow/mock integration tests and lint; commit. No remote run.

## Task 4: AWG consumer integration

Create `scripts/boringtun-adopt.py`; update explicit URL/identity contract helpers,
consumer CI and tests; retire active AWG publisher locally while preserving legacy verifier.
Interface: `boringtun-adopt.py --tag TAG --output PATCH` verifies signed descriptor
and emits a diff/evidence only; does not modify installer implicitly or send a PR.
- [ ] Test wrong tag/repository/signer/source/hash, old-cache collision, legacy owner selection, failed-verification no-diff and exact replacement of all embedded release constants.
- [ ] Implement read-only fetch/verification and patch generation; rewire producer tests without weakening legacy checks.
- [ ] Verify the complete five-target release, adopt only three Linux targets, add bounded ARMv7 installer support and preserve legacy/mixed-bitness rollback. Leave public constants unchanged before a separate adoption PR.
- [ ] Run consumer/public contract/runtime regression suites and feasible upgrade/rollback checks; record unrun live/CI gates. Commit.

## Task 5: Final verification and independent review

- [ ] Fresh security/design review of automatic promotion boundary before architecture integration; address material findings.
- [ ] Run combined relevant suites, shell/Python/workflow validation and source/bundle reproducibility. Record passed vs unavailable native/remote gates.
- [ ] Fresh final patch review across both branches; fix material findings with regression evidence.
- [ ] Report exact branch/commit IDs, activation/attribution/publication gates and remaining decisions. Do not merge, push, publish or deploy.

## Self-review

Task1 owns archive notices; Task2 owns pure release identity; Task3 consumes both;
Task4 consumes signed descriptor and explicit identities. Shared interfaces above
are fixed before parallel implementation. No automatic per-release approval
commit remains. Release metadata extension is outside format1 archive boundaries.
