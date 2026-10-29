# Readable, explicitly versioned releases

## Intent and approved scope

Keep automatic publication after each meaningful merged PR, starting the human
version line at **0.8.0**. The user approved this approach and preparation of a
draft PR only. This task must not publish, merge, change existing releases or
tags, or modify awg-server-tools.

## Approach

The selected approach is reviewed version intent and notes in each PR, with
versions committed in both Cargo manifests, their dependency and Cargo.lock.
An automated release PR would batch changes and change the approved process;
deriving versions from commit titles would not make intent reliably reviewed.

Implementation choice: a small JSON intent file records `base_version`,
`version`, `bump` (`patch`, `minor`, `none`) and a reason. Markdown notes live at
`docs/releases/<version>.md`. A read-only PR gate compares against the base;
trusted promotion repeats validation against the actual merge first parent.
Stale concurrent changes fail closed and must be refreshed in a PR. Retries
read the same source version and never generate a new commit or bump.
`none` requires unchanged versions and only documentation/tests changes plus
the intent file; it emits no build request. Maintainers choose patch for fixes,
minor for features/significant contract changes. No automatic major policy.

## Publication and compatibility

Use `WireSock BoringTun <version>` as title. Preserve technical tags, archives,
descriptor schema 2 and exactly seven assets. New bodies combine reviewed
Markdown, deterministic PR/compare/verification links and one bounded HTML
comment containing the existing canonical signed descriptor marker. Accept
legacy exact two-line bodies only for historical versions below 0.8.0. Reject
duplicate or malformed metadata and prose differing from the immutable source.
Never rewrite historical bodies. Empty drafts still atomically retain the
exact signed descriptor bytes, and uncertain writes still require readback.

The initial notes distinguish accumulated changes since 0.7.1 from changes
since b114 (release engineering only). They retain the limits of peer teardown,
inherited UAPI failure handling, UDP sharing and fwmark documentation.

## Latest

Keep publication per PR concurrent and `make_latest:false`. Add one serialized
Latest reconciliation job after publication or an already-published retry.
It selects the highest stable semantic version >=0.8.0 across the inventory,
rejects duplicate semantic identities, verifies its assets, source, provenance,
notes and live gates, then updates only Latest and reads it back. Ordering and
replacement of pending reconciliation jobs are harmless: each examines the
whole inventory, not its triggering PR. Never move below an existing higher
semantic Latest. Historical workflows have no Latest mutation path.

## Validation and limits

Test stale and concurrent version intent, none, package/lock mismatches,
source binding, strict metadata parsing, tampering, uncertain writes, empty
draft recovery, immutable retries and out-of-order Latest reconciliation.
Prove 0.8.0 descriptors/identities with the unchanged AWG consumer policy.
Run release/security suites and available Rust checks; rely on exact-head CI
for platform builds unavailable locally. Require fresh independent review
before pushing/opening the draft PR. Updating protected-branch requirements
is outside scope: the merged-source gate remains mandatory even if a PR gate
is not configured as a required GitHub status check.
