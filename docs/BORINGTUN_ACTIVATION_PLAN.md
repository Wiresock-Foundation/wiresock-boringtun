# Automatic release activation

Status: owner approved ordinary merged-PR activation on 26 October 2026 after
independent review and green CI. The approval includes first publication, ongoing
ordinary-path releases and hosted-toolchain trust; it excludes an actions:write
recovery dispatcher, new credentials, repository settings and old-asset changes.
The completed trial and trust limits are in [the audit](BORINGTUN_ACTIVATION_AUDIT.md).

## First eligible source

Exclude baseline `1cee1afadd6be4251d6a19273b1882090bd2038e` and all sources
whose own policy is disabled. Generation `fork-v1` must match in source C,
trusted publisher policy and current master. C must strictly descend from the
baseline. The first eligible source is the eventual reviewed activation PR's
merge commit, not the trial source, a rerun of PR98 or an old release. Its stable
tag is `boringtun-cli-<Cargo version>-g<C first12>-b<activation PR number>`.
The activation PR itself should start its first release after the gates pass.
Later policy disablement revokes inflight publication. No approval PR per release
or recursive approval scheme is introduced.

The implementation adds that boundary, clears the consumed trial selection to
null and records real evidence. The enabling change sets enabled:true after the
owner explicitly accepted narrower ordinary-event coverage and hosted-toolchain
trust. Missing-event recovery remains a separate unimplemented capability.

## Recovery required for every merged PR

The current push-only path cannot meet the complete request. It handles distinct
ordinary pushes without cancelling earlier PRs, but not missing push events,
batched merges whose sources are not the pushed tip, or GITHUB_TOKEN merges.
Read-only reconciliation identifies gaps but does not repair them. GitHub
documents [token-triggered event suppression](https://docs.github.com/actions/using-workflows/trigger-a-workflow)
and [schedule delay/drop behavior](https://docs.github.com/en/actions/how-tos/troubleshoot-workflows).
No scheduler can guarantee an immediate run during an outage; durable catch-up
must prevent silent loss when service resumes.

Recommended minimal addition, reusing the existing builder and publisher:

1. A metadata-only reconciler on a periodic schedule and ordinary master push
   inventories **all** merged canonical master PRs since the activation boundary,
   with pagination and fresh PR/C ancestry checks. It never executes source C.
   Each row remains pending, inflight, verified-published, or blocked with an
   explicit reason. Dispatch is not completion. Failures stay visible; permanent
   build failures require a fix, not weakened gates or endless retries.
   Inventory missing/failed promoters and incomplete drafts as well as builders.
2. Dispatch missing eligible work to the same read-only builder with canonical
   PR number, full C and generation. Use only the built-in token, an allowlisted
   workflow and master ref. The dispatch job needs contents:read and actions:write.
   This is repository-wide Actions authority, constrained to that endpoint by
   reviewed code rather than a narrower GitHub permission. Serialize dispatchers
   with cancel-in-progress:false; use the deterministic generation/PR/C work key.
   It has no signing/content-write permissions. Periodic scans revisit missed
   wakes and token-suppressed/batched merges. Duplicate wakes select existing
   exact active attempts; ambiguous dispatch outcomes are read back before retry.
   Bound each dispatch batch; later runs rescan the complete durable backlog,
   so no oldest/newest cutoff silently loses earlier merges.
3. Preserve distinct source C, executed builder recipe Rb, and publisher recipe Rp.
   workflow_dispatch head_sha is Rb, not C. The trusted resolver at Rb validates
   PR/C/generation independently of caller text. It must bind those values into
   a fixed-format downstream job name evaluated from its outputs by GitHub.
   The publisher reads that required successful job through B's exact-attempt
   server jobs API and compares it to REQUEST.json and the signed descriptor.
   The exact reviewed workflow at Rb fixes the output-to-name mapping. This is
   not trust in an arbitrary workflow display name or run title. Source build
   code cannot replace C merely by rewriting its bundled REQUEST.json.
4. Introduce an explicit shared descriptor/envelope version for dispatched
   semantics and synchronize AWG verification. Never reinterpret schema2's
   recipe_commit=C contract as Rb. Keep existing schema2 push releases readable.
   Require exact workflow IDs, Rb/Rp, B/P run and attempt, all required jobs and
   artifact hashes. Older recipe incompatibility remains blocked with a reason;
   no broad historical recipe allowlist or pre-activation backfill is proposed.
5. Keep one immutable release identity per PR/C. A source-scoped signing/publish
   lock plus existing-release readback prevents concurrent candidates replacing
   signed descriptors/assets. Pending-job cancellation must leave the PR in the
   backlog. A verified existing release is a no-op; conflicts are errors. Partial
   publication resumes only original signed bytes. Never overwrite old assets.

GitHub supports needs outputs in [job names](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability).
The [dispatch API](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event)
requires Actions write and a branch/tag ref. Pin the chosen API version and test
its actual response; do not assume a raw SHA ref or response shape. A same-run
binding avoids a new cross-run receipt service or credential. This recovery route
is **designed, not implemented** in this local preparation.

Before enabling recovery, add regressions for pagination, normal/squash/rebase
source selection, batched/token-suppressed/missing events, duplicate and uncertain
dispatch, failed and partial reruns, generation revocation, substituted C/Rb/Rp,
and pipeline changes with older pending C. Validate one build-only dispatch's
actual server job metadata using installed reviewed code; no new signing trial
is needed. Existing live evidence covers normal merge; squash/rebase recovery
and the new dispatch route must not be advertised as live-proven until checked.

## Exact permissions and approval request

Repository: `Wiresock-Foundation/wiresock-boringtun`. No repository security
setting, stored credential, signing key, Apple notarization or external service
is proposed. Job-scoped permissions would be:

| Job | Permissions |
| --- | --- |
| Source builds/tests | contents:read; actions:read where artifact reads require it |
| Reconcile/dispatch (new) | contents:read, actions:write |
| Prepare/verify | contents:read, actions:read, attestations:read |
| Sign (existing dormant path) | contents:read, actions:read, id-token:write, attestations:write |
| Publish (existing dormant path) | contents:write, actions:read, attestations:read |

Approved scope: merge the reviewed fork-v1 activation after green checks, enabling
the existing job-scoped id-token:write, attestations:write and contents:write
normal-push publisher. Its fresh merge publishes the first verified release;
later ordinary merges publish automatically. Public outputs are tags, five
archives, RELEASE.json, SHA256SUMS and GitHub/Sigstore provenance. No stored
credentials are created and existing assets stay immutable. The owner accepted
the hosted compiler/SDK trust boundary and narrower initial event coverage.

The proposed actions:write dispatcher row above is **not approved or implemented**.
It remains separate from the normal-path activation. AWG adoption and Lisbon
deployment remain subsequent reviewed stages after actual release verification.

## First release, adoption and Lisbon

1. Proceed with the explicitly accepted ordinary-push scope. Keep recovery design
   separate and old AWG workflow 369920301 disabled; no actions:write is added.
2. Refresh owner-side retirement audit, independently review the enabling diff
   and merge normally after required exact-head checks pass. This fresh activation
   merge becomes the first eligible C; queued older disabled sources stay out.
3. Observe its complete five-platform build, same-target two-build byte equality,
   runtime/interoperability checks, exact six-subject attestation verification,
   then immutable seven-asset release publication. Verify the public release and
   retry state without rebuilding or changing its identity. No release is ready
   merely because preparation or signing passed.
4. On Linux run AWG's existing `boringtun-adopt.py` for the explicit published tag
   with checksum-pinned gh 2.100.0. Verify all five targets, source/recipe/run/attempt,
   notices and hashes; prepare a reviewed AWG PR pinning the Linux x86_64/aarch64/
   ARMv7 assets. No latest lookup, unpublished pin or automatic server upgrade.
5. Before Lisbon deployment, preserve root-only backups of configuration, units,
   installer, current/previous binary store and symlinks, ownership/modes, and
   nonsecret version/hash/health inventory. Recheck healthy services, available
   disk, backend and explicit rollback compatibility; keep old verified binaries
   and an independent administrative session. No sensitive backup content enters
   GitHub artifacts or chat. Test the supported upgrade transaction after the
   reviewed adoption. If service/tunnel/web health regresses, use the supported
   rollback transaction and verify restored health; do not change network/VPN
   settings or silently switch backend to make a failed upgrade pass.
6. Close issue175 only after the corrected release is published and adopted and
   its stated acceptance criteria are met. Physical Pi/full ARM32 stack testing
   remains a separate limitation, not implied by ARMv7 cross-build/QEMU success.

Lisbon's prior read-only baseline: Debian 13.7 x86_64, healthy services, AWG tools
3.1.20260812, userspace BoringTun0.7.1 source e94c04f3f4fdb8b392f9586db07a269ea0bf7575,
binary SHA256 7c717357554a4d8022154fbdb1c40c92de8174ee064e81878fdf5f610651fb79,
prior ae2ab44 store, approximately 87 GB free. This is planning evidence, not a
backup, rollback rehearsal or deployment; all must be refreshed at rollout time.
