# Activation audit: 26 October 2026

Publication remains disabled. This records evidence and remaining work, not
permission to enable release jobs. AWG177 merged at
514ea073c904a90cfeccda06ad1ea78553273c59; fork96 merged at
d33fa41ad1917846a5a722ff3bfb64830b650941. Existing release assets, installer pins
and production are unchanged.

## What the original eleven blockers actually require

| Gate | Evidence and remaining action |
| --- | --- |
| Date provenance | Notice-preservation review completed; exact owner testimony is in ATTRIBUTION.md. Existing dates are retained, not independently verified. No new date question is needed. |
| Merged-event identity | Real closed-PR run40344057429 had H as head_sha, empty pull_requests, and executed C. The repair uses canonical master-push C with independent exact merged-PR discovery. A successful installed repair run is still required. |
| Workflow identity | Build397187760 and publisher397187761 are known and pinned. |
| Live attestation fixture | Pending explicit attestation-only approval. Requiring publication enablement to collect this fixture is circular; use a separate narrow validation path before enabling publication. |
| Legacy retirement | AWG YAML is retired. Owner-access audit found zero drafts, four published releases and nine completed historical publisher runs. Workflow369920301 remains active; owner approval to disable it is pending. Re-audit immediately before activation. |
| Missed merges | Reconciliation enumerates every merged PR since an explicit boundary, including missing or failed runs. Diagnostic recovery plans do not dispatch or publish. GITHUB_TOKEN-triggered merges may emit no usable push run. No release recovery route for such a missing run is implemented. |
| Historical tags | Conditional on publishing older C. GitHub may require more than contents:write when historical workflow files differ. Do not broaden credentials; report the blocked PR/tag and obtain a reviewed recovery decision. |
| Actions/native tools | Build actions now use immutable SHA pins. Coverage and limits are below; source binding does not make host tools hermetic. |
| Historical recipes | C's build workflow must equal trusted R. Older incompatible C remains visibly blocked. An explicit activation boundary and reviewed recovery policy are required, not an unbounded recipe allowlist. |
| Five-platform checks | Candidate40331516759 passed four native lanes plus ARMv7 cross-build/QEMU, two identical builds/archives per target, native TUN/utun, and all three Linux interop lanes. Physical Pi/full ARM32 web stack remain unvalidated. Repair CI must be recorded separately. |
| Bash/compiler provenance | Same native-tool coverage decision as above, not a second independent implementation gate. GNU Bash source and twenty patches are pinned; native receipts are supplemental. |

## Source and tool coverage

The signed source C binds Cargo.lock, runtime-provenance.json, the build scripts
and bash-toolchain.json. Runtime provenance pins Rust1.98.1 distribution/source,
LLVM/compiler-builtins/native notice inputs for all five targets; distribution
and source hashes are checked. The descriptor's toolchain_sha256 is only the
documented Rust/LLVM/input projection, not a digest of every host executable.

The Bash manifest pins GNU5.3 source plus twenty ordered patches. Native macOS
builds select Xcode16.4/16F6, SDK15.5 and deployment target11.0. Compiler, SDK,
Bash and packaging receipts describe the executing runner; their bytes remain
supplemental CI artifacts and are not signed subjects. GitHub-hosted image and
system-tool provenance are therefore trusted platform inputs, not independently
reproduced toolchains. Review acceptance of that documented boundary before
activation; stronger receipt attestation would be a separate contract change.

Checkout, upload, download and setup-go in the release builder are SHA-pinned.
Version-pinned rustup/Cargo tool installations and Go inputs retain their
existing checksum/lockfile checks; this repair does not promise a hermetic
runner or a new toolchain bootstrap proof.

## Recovery preparation

Run the read-only `reconcile --since <UTC boundary>` command with pinned gh.
Each row identifies the exact source/tag, existing attempts and a diagnostic
recovery mode. Wait for active attempts. For a failed ordinary push run, inspect
its exact failure and original workflow before proposing a rerun; never change
signed identities or overwrite assets. A missing run cannot be recovered by
rerunning it. Manual dispatch is maintenance validation only and remains
ineligible for publication. Do not reset master or manufacture a push to hide
the gap. Bring a concrete missing PR/source to review before designing recovery.

Normal merge, squash and rebase use GitHub's documented postmerge
merge_commit_sha. Captured live evidence covers normal merge; strategy tests for
squash/rebase are synthetic. Merge queues/batched updates and automation merges
which suppress push events are not yet claimed to deliver every PR. They must
remain visible in reconciliation and need a reviewed recovery/activation scope.

## Proposed attestation-only permission request

Approve one validation run in Wiresock-Foundation/wiresock-boringtun using the
canonical `.github/workflows/boringtun-release.yml` installed on master at a
reviewed immutable recipe revision. Add a separately gated validation mode with
a signing job limited to `contents: read`, `actions: read`, `id-token: write`
and `attestations: write`; verification jobs remain read-only. The validation
path must have no reachable `contents: write` publication job. Keep enabled:false.

It would sign exactly six verified subjects: the five archive digests and
RELEASE.json, binding source, build run/attempt, workflow revision and validation
run/attempt. GitHub artifact attestations and public Sigstore transparency
records expose those digests and repository/workflow/source/run metadata. No
release, tag, asset publication, new credential, signing key or repository
security-setting change is requested. Preserve the real pinned-gh verification
JSON as evidence. This mode is a proposal, not implemented or run by this repair.

Use a workflow_run-origin validation invocation so its verified identity matches
the eventual publisher contract; a workflow_dispatch certificate would not
validate the existing workflow_run requirement. Exact selected build and
validation run gates must be reviewed before this path executes.
