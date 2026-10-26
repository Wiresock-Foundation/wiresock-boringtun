# Recovery of the first signed release

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

## Proposed sequence, pending explicit recovery authorization

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
