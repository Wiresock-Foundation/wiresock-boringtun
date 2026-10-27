# Recovery of the first signed release

## Completed first recovery

The first draft was recovered with explicit owner approval and published as
[`ga92909c49920-b101`](https://github.com/Wiresock-Foundation/wiresock-boringtun/releases/tag/boringtun-cli-0.7.1-ga92909c49920-b101)
on 2026-10-27 at 06:07:35 UTC. All seven public files and six original signatures
were independently verified. Its source/build/publisher identities below remain
unchanged. The historical plan is retained as a record, not permission to recover
another draft. Existing releases are immutable.

The first normal publisher run `40412814028/1` created draft `424839667`
successfully, then stopped because the tag-name API only finds published releases.
Owner-authenticated inventory and ID reads on 2026-10-26 confirmed the draft has
no assets, no published timestamp and no Git tag. The captured API response in
`tests/fixtures/draft-424839667/release.json` is regression evidence, not a current
authorization or substitute for fresh readback.

Original identities must remain unchanged:

- Tag: `boringtun-cli-0.7.1-ga92909c49920-b101`.
- Source and signing recipe: `a92909c49920e12de11fb0e066192b8f39b5b212`.
- Build: `40409966150/1`; all 13 build/gate jobs succeeded.
- Publisher: `40412814028/1`; preparation and attestation succeeded, publication failed.
- Exactly five archives, `RELEASE.json` and `SHA256SUMS`.

## Historical first-recovery sequence (completed)

1. Keep master and the draft unchanged while the local repair is reviewed and
   tested. Do not rerun the old publisher: it checks out its old buggy recipe.
2. Download the original prepared artifact by immutable ID/digest, compare its
   canonical descriptor byte-for-byte with the descriptor in the draft body,
   and independently verify all six signed subjects with pinned gh. Check the
   original source, build, publisher, attempts, workflow identities and successful
   build/preparation/signing jobs. Preserve raw verification evidence.
3. Obtain approval for an operator-controlled resume using the existing connected
   account. The operation must require existing ID `424839667`, the exact original
   descriptor digest and seven verified files. If that draft is inaccessible or
   ambiguous, stop. No create, delete, replacement, retag, rebuild or signing action
   is permitted. Never fabricate a workflow_run environment to call the CI CLI.
4. Recheck current activation, source generation and legacy retirement. Upload
   only missing assets to that ID, read back each write, reverify the complete set,
   then publish the same ID. Read uncertain outcomes before any retry. Record the
   operator and recovery-code revision separately from original signing provenance.
5. Verify the public tag, seven assets and six attestations independently. Only
   then prepare AWG adoption. Lisbon remains unchanged pending its separate
   backup/rollback and interruption review.
6. Decide explicitly when to merge this repair: current enablement means its merge
   will automatically build and publish a separate release of the repair source.
   Deferring the merge avoids that effect during original-draft recovery. If
   installation must happen first, use the existing `enabled:false` policy gate
   in the reviewed merge and review reactivation separately; do not bypass it.

## Credential visibility limit

Authenticated inventory plus fresh numeric-ID readback fixes draft discovery for
a credential with draft visibility. A read-only preparation/signing token is not
proven to have that visibility merely because the endpoint accepts contents:read.
Its absence result is not proof that no private draft exists. Such retries remain
manual; this patch does not promise automatic retry without additional signing.
Publication credentials are not broadened. The proposed recovery needs the exact
existing draft to be visible and never falls back to creating another release.

## Successful creation must retain its returned ID

After PR #102, canonical build
[`40459788478/1`](https://github.com/Wiresock-Foundation/wiresock-boringtun/actions/runs/40459788478)
passed all 13 jobs. Publisher
[`40461864091/1`](https://github.com/Wiresock-Foundation/wiresock-boringtun/actions/runs/40461864091)
validated and signed, then stopped with `draft creation outcome unresolved`.
Owner readback found draft `425104516`, source/recipe
`39d7bfc14f13a11a35122287ecdfa58c5ec1f218`, without assets or a Git tag.
The code had discarded the create response and immediately searched inventory
again. The log does not establish whether that response reached the job, or why
its inventory omitted the draft; neither caching nor a permission failure is
established.

The repair validates a successful response's numeric ID, tag, full source commit,
descriptor marker and empty stable-draft state. It reads that ID directly and
retains it for every upload and publication readback. A malformed successful
response stops before uploads. An uncertain create response has no trusted ID:
it still reconciles once through authenticated inventory and stops if unresolved.
No code path repeats an uncertain creation or replaces an existing asset.

On 2026-10-27 at 06:51 UTC the repaired adapter completed a real GET-only
owner-authenticated read of ID `425104516`, its missing tag and empty assets.
The descriptor digest was
`a6b92792cec75887bea086ed07e6e9348b7b176a136a778a97347affb2560325`.
This proves the ID endpoint was readable by that owner at that time. It is not
evidence about the expired Actions token or immediate post-create visibility.
Offline transport tests cover successful creation omitted from inventory,
conflicting/malformed responses, inaccessible IDs, pre-existing drafts and lost
mutation responses without duplicate writes.

Draft `425104516` remains untouched. This repair does not recover it or authorize
a retry. A publish-only rerun changes the current attempt while its retained
preparation belongs to attempt 1; a full rerun uses the old recipe and may sign
again. Neither is the preserve-original-signatures recovery route. Merging this
repair will request a separate new-source release under the active policy, so
merge timing remains an explicit rollout decision.
