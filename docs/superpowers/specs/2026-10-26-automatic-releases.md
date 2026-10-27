# Automatic fork releases after merged pull requests

The user approved implementation on 2026-10-26. Implement locally; do not merge,
dispatch publication, create releases/credentials, change security settings or
touch production. First enablement requires a reviewed PR and user authorization.

## Ownership and trigger

The fork is the sole new release producer. Reuse AWG's tested artifact tooling;
retain old AWG releases and a legacy verifier, retire its publication path before
enabling the new publisher. The migration gate checks a pinned retirement commit,
current AWG main's retired workflow/script hashes, disabled workflow state and
no active legacy release runs. A separate owner-side audit must establish draft
disposition: public/cross-repository API access cannot prove no drafts exist.
Historical workflow disabling requires a later owner action. Read/API uncertainty
blocks publication; code changes alone do not establish retirement.

Use `pull_request: types: [closed], branches: [master]` for read-only builds,
requiring merged=true and the canonical base repository. No push/tag trigger and
no pull_request_target. Read the PR again from GitHub: closed, merged, base master,
canonical repository. C is its post-merge merge_commit_sha (merge commit, squash
commit, or rebase's final base commit). Require full SHA and ancestry in current
master. Build C, never the PR head or refs/pull/*/merge. A manual maintenance
dispatch defaults to dry-run for an explicit merged PR; it cannot auto-publish.

Trigger privileged promotion with `workflow_run: completed` for the exact build
workflow, then independently validate its canonical repository, immutable workflow
ID/path, successful run/attempt, event=pull_request, source C and PR association.
Treat every downloaded field as untrusted data until matched against GitHub and
the merged PR. Privileged jobs never run scripts/binaries or restore caches from
the downloaded source/build artifact. Their verifier comes from the trusted default
branch workflow revision R, explicitly recorded; checkout credentials are disabled.

## Versions, queue and retries

Keep CLI semantic version V from C's manifest. Each merged PR gets deterministic
release identity `boringtun-cli-V-g<C12>-b<PR-number>`; the full C and PR repository/
number are verified. The numeric PR number is the build identity, not a claim of
semantic version progression. Refuse existing legacy identities with different
bytes. Keep archive format1 and its four members. Preserve existing Linux
filenames; add `linux-armv7-musleabihf` and `macos-x86_64`/`macos-aarch64` suffixes.
Platform-specific manifest values distinguish Linux static musl from macOS
dynamic system libraries.

No branch-wide cancel/replace concurrency. Build runs have independent identities;
promotion serializes only an already-validated PR/release key. Different PRs all
remain eligible even if master advances, and may finish out of order. Set
make_latest=false; do not let finishing order alter adoption. Duplicate deliveries
for one PR may collapse only if the surviving run handles the same release identity.
A read-only reconciliation command lists merged PRs after a pinned activation
boundary without a verified release or active build, including failed/cancelled
runs, and emits explicit blocked states. It does not dispatch or publish.
Missing events caused by GITHUB_TOKEN merges cannot be repaired by rerunning a
nonexistent run. The corresponding recovery route must be reviewed and proven
before activation. Historical workflow/provenance changes can also block an
older queued merge; never relax provenance checks or silently skip it.

Existing published release: independently reverify its complete content and
original provenance; identical desired content is an idempotent success, conflict
fails without mutation. A partial draft can resume only after matching its recorded
source/PR/run/attempt/digests and every present asset; upload only absent assets.
Never delete or overwrite a tag/asset. An uncertain mutation is read back before
retry. A failed gate yields no published release and a visible failure/recovery
record; it never falls back to old artifacts or skips to a newer PR.

## Builds and attestation

At C, derive a temporary strict pin naming C, repository, CLI version, exact Rust
version and format1. No source self-hash commit and no later approval commit/PR.
Normal validation plus all five builds, binary/archive comparison from two
independent directories and target-specific notice checks must pass. Linux
x86_64/ARM64 and macOS Intel/Apple Silicon use native runners. ARMv7 hard-float
uses a pinned cross-linker and QEMU; it is not physical Pi validation. Linux
requires static ELF/TUN/interop gates, macOS Mach-O/system-library/utun gates.
No signing or notarization credential is introduced. Preserve existing fork CI. Cargo/toolchain/native sources are pinned;
complete source-derived notice bundle and its provenance are hash-bound.

Build workflow uploads five archives, SHA256SUMS and a small request descriptor.
Promotion selects an immutable artifact ID with API digest and exact build run B/
attempt. Safely extract bounded regular files; reject traversal/symlinks/duplicates.

Generate `RELEASE.json` in trusted promotion, containing schema, repo, PR, C, V,
build, tag, Rust/toolchain/notice digests, B/run-attempt/artifact ID+digest, trusted
promoter recipe R, promotion run P/attempt and five archive/binary/notice hashes.
Schema 2 permits Linux and macOS notice profiles and retains one unified source
provenance digest. It has no timestamp or mutable latest field. Seven release
assets comprise five archives, SHA256SUMS and RELEASE.json; the four-member binary
archives remain unchanged. Sign RELEASE.json and all five
archive byte hashes with GitHub attestations from the canonical promotion workflow
on master. RELEASE.json avoids trusting mutable release prose for provenance.

Pin gh 2.100.0 and its distribution checksum. Verify cryptographic JSON output,
exact certificate identity, source digest R and ref master, hosted runners,
invocation P/attempt and subjects. Validate B's attempt-specific metadata and
artifact identity separately against the signed descriptor. Missing/unknown
schemas fail; test same bytes from wrong run/attempt/signer.

No per-release A approval mechanism. Merging the PR after review is the release
authorization once the pipeline is explicitly enabled and all gates pass.

## Publication and adoption

Promotion first performs the complete read-only dry run and eligibility gates.
Only then attest and run an isolated publish job. Recheck the same immutable
descriptor, signed artifacts, migration/enablement and destination state there.
Draft, upload/readback/hash, then publish. No rebuilding. Enabling defaults false.
Current ownership-year audit status defaults blocked; no automatic publication
until owner evidence/correction is reviewed. Do not bypass this in tests or docs.

AWG adoption accepts an explicit tag. Verify signed RELEASE.json using only the
allowlisted fork promotion workflow/master identity, then exact descriptor run,
source, the complete five-target matrix, hashes and archive notices. Reject
missing expected assets and arbitrary extras. Generate a reviewed local diff/PR
selecting only Linux x86_64, ARM64 and ARMv7 hard-float, with explicit URLs and
hashes; never latest or automatic installed-server upgrade.
Rewire AWG producer-dependent CI/tests to consumer validation and retain versioned
legacy verification. Test upgrade/rollback from ge94c04f3f4fd-b1; preserve cache
identity and reject same key/different bytes across owners. Servers use embedded
hashes and need no GitHub credentials or live attestation calls.

ARMv7 requires ARMv7-A/VFPv3-D16 or later, excluding Pi 1 and original Pi Zero.
Installer selection considers armhf userspace and supported CPU/kernel identity;
existing compatible ARM64 stores remain valid on mixed-bitness hosts and rollback
does not depend on unpublished ARMv7 fields. Full ARM32 web/proxy stack validation
and physical Pi acceptance remain separate from BoringTun artifact support.

## Permissions

Defaults read-only. Build/license/test jobs contents:read. Promotion validation
contents:read, actions:read, attestations:read. Trusted attestation adds only
id-token:write and attestations:write. Only publication has contents:write plus
actions:read and attestations:read. Job-level canonical-repository/master/event/
enabled conditions and script-level checks both apply. No write token during
source execution, no PR metadata interpolation into shell, no persistent checkout
credentials or shared privileged caches. Public PR reads require no new secret.
Local adoption may use existing gh auth, otherwise a read-only AWG verification
workflow with ephemeral GITHUB_TOKEN. No new credentials/settings in this task.

## Evidence

GitHub's Get a pull request API documents post-merge SHA semantics for all three
merge methods. Ordinary concurrency groups replace pending runs (even with
cancel-in-progress:false); per-release groups avoid cross-PR loss. See
https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request and
https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency.
