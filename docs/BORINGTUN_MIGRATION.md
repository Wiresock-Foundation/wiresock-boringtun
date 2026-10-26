# Fork-owned BoringTun releases

## Current implementation status

The implementation includes a read-only five-platform builder, strict release
policy, publisher workflow and separate AWG adoption tooling. The owner approved
normal merged-PR-push activation after independent review and green CI, including
the first fresh merge-source release. `release-policy.json` enables generation
fork-v1 with an immutable excluded baseline and source-side enablement checks.
Signing and publication independently recheck live policy and exact provenance.
The existing job permissions are unchanged; no actions:write recovery dispatcher
is added. Old release assets and production remain unchanged.

The sections below describe the implemented contract and remaining live
validation/activation gates. Local fixture tests do not establish successful
GitHub publication, native macOS acceptance or resolution of historical dates.

`BoringTun candidate platform validation` runs on opened, synchronized and
reopened PRs, including drafts. It checks out the exact PR head and derives a
temporary pin without a merged-PR or release identity. Its read-only jobs use
the production notice, runtime, compiler, archive and device helpers for native
Linux x86_64/ARM64 and macOS Intel/Apple Silicon; ARMv7 is cross-built and
QEMU-emulated. Each target compares two binaries and archives, and three Linux
lanes run both existing interoperability harnesses. The seven-day `candidate-*`
artifacts are validation evidence, carry no attestations and are not releases.
The publisher does not accept this workflow. Passing candidate CI does not
authorize publication; only eligible canonical master sources pass live gates.

The canonical producer moves to `Wiresock-Foundation/wiresock-boringtun`.
Each merged PR targeting its master branch has a distinct source-based tag:
`boringtun-cli-<CLI version>-g<source SHA first 12>-b<PR number>`. The complete
40-character source SHA is retained in MANIFEST and signed RELEASE.json.
The PR's merged result identifies the source for merge, squash and rebase
strategies; the PR head alone is not the release source. The read-only master-push builder admits only a commit that independently
identifies exactly one merged master PR. Unmerged direct pushes cannot release;
a replay of an eligible source retains its immutable identity. AWG adoption remains an explicit, reviewed version/hash patch.

## Phased activation

1. Both initial repository changes are merged with publication disabled.
   Retained attribution notices now have a documented preservation review;
   see ATTRIBUTION.md and BORINGTUN_ACTIVATION_AUDIT.md. The source binding
   repair passed independent review and installed canonical build40398953473/1;
   see the activation audit for the completed six-subject attestation trial.
2. Merge the AWG retirement change only with owner approval. Its current Release
   workflow has no publisher, and its Artifacts workflow runs consumer checks.
   The Runtime workflow tests the exact published installer release rather than
   building a separate artifact with placeholder notices. Historical releases,
   assets, tags and installer defaults remain unchanged.
3. With the owner's AWG access, audit all existing drafts and queued/running
   legacy publishers, record their disposition, and **disable the historical
   publishing workflow through GitHub**. A fork token or anonymous release list
   cannot prove drafts are absent. A current-YAML edit cannot prevent historical
   reruns. This repository does not change those settings or create credentials.
4. Normal-merge canonical identity and pinned-gh verification are proven by
   build40398953473/1 and promoter40401950322/1. Squash/rebase strategy tests are
   synthetic; recovery's new dispatch semantics still require implementation,
   review and live read-only metadata evidence. Do not repeat the completed
   signing trial or treat it as evidence of the unimplemented recovery route.
   Obtain specific activation permission before enabling the fork publisher.
5. Review the first eligible fork release and use `scripts/boringtun-adopt.py`
   to generate a local adoption patch. Review its exact tag, source, toolchain,
   notices, all five archive/binary hashes and the three Linux installer
   selections in a separate AWG PR.
   See the AWG repository's `docs/BORINGTUN_ADOPTION.md`.

## Artifact and trust contract

Five targets each compile/package twice and require identical bytes: Linux
x86_64/ARM64, Linux ARMv7 hard-float, and macOS Intel/Apple Silicon. Linux
x86_64/ARM64 and both Apple lanes are native; ARMv7 is cross-built and exercised
through QEMU, explicitly separate from physical Raspberry Pi validation.
Linux uses static ELF/TUN/interop gates; macOS uses Mach-O/system-library and
native utun gates. Binary archives keep four members. The seven release assets
are five archives, SHA256SUMS and schema-2 RELEASE.json; six subjects (the five
archives and descriptor) are attested. The descriptor binds source PR/commit, recipe commit, successful
build run/attempt and artifact digest, publisher workflow/run/attempt, toolchain
and notice provenance, including a per-archive notice hash. The promoter checks the exact selected attempt and
verified certificate/invocation identity. Downloaded binaries are never executed
in signing or publication jobs.

The descriptor's `toolchain_sha256` binds the reviewed Rust version, Rust/LLVM
source commits and pinned input manifest. Compiler/SDK receipts from each build
are supplemental CI artifacts; their bytes are not included in that digest.
Native compiler/SDK/packaging-tool and Bash source-build provenance remains an
explicit activation gate. Do not describe this digest as attesting every host
tool or as establishing a fully hermetic build.

Builds have `contents: read`. Signing receives only the necessary OIDC and
attestation writes; publication receives content writes separately. Trusted
scripts come from the promoter's fixed workflow revision; source C executes
only in isolated read-only jobs. Existing maintainers' authentication can be
used for read-only local adoption; no new credentials are introduced.

The publisher accepts only successful completed runs of the merged-PR build
workflow, then validates the exact event, repository, workflow ID, source and
attempt. It has no manual publication trigger; the eligible build must be a canonical
master push independently bound to one merged PR, not an arbitrary direct push. A manually
dispatched maintenance build remains a dry run because its triggering event is
not eligible for promotion. Checkout, preparation upload and attestation actions
in the privileged workflow use immutable commit pins. Attestation receives the
descriptor and five archive paths derived from the revalidated prepared files.
Publication is serialized by validated PR number, leaving distinct merged PRs
in independent queues.

Retries recover and verify the original signed descriptor rather than changing
its run IDs. The descriptor is uploaded first and its digest recorded in draft
metadata. Existing asset names are never overwritten. Conflicts and uncertain
writes require read-back and fail closed. Per-PR concurrency avoids replacing
unrelated pending merge runs; reconciliation exposes missing releases.

## Explicit platform limitations

GitHub can suppress merge-triggered workflows for merges made using
GITHUB_TOKEN. Reconciliation must expose the missing build; rerunning a
nonexistent run is not recovery. A reviewed recovery route and real event
fixtures remain activation prerequisites, not claimed implementation proof.

Creating a tag at an older merged commit whose workflow files differ from the
current default branch may require authorization beyond `contents: write`.
Such a publication remains blocked and visible. The owner must choose a
reviewed recovery procedure or authorize a changed tagging model. This change
does not broaden credentials, retarget the tag silently or skip that merge.

## Compatibility and rollback

The installer continues embedding its existing published AWG release,
`boringtun-cli-0.7.1-ge94c04f3f4fd-b1`, until a later adoption PR. Old AWG and
renamed-repository URLs remain accepted alongside the exact canonical fork URL.
The source repository, archive naming and four-member format stay compatible.
The installed cache key includes source/build but not publisher: adoption must
reject reuse of an existing source/build identity for different binary bytes.
Rollback uses the installed prior immutable release and configuration checks;
neither migration nor a fork release automatically upgrades production.

Publisher retries retain the trusted workflow revision R. The live gate compares
current master policy bytes with that revision's policy; a code-only security fix
does not itself revoke an older R if the policy is unchanged. Future publisher
security fixes must also change the reviewed policy or introduce explicit recipe
revocation. Keep verification of an original signed release separate from
permission to execute an obsolete publisher.

ARMv7 support requires ARMv7-A or later with VFPv3-D16 hard-float; original Pi 1
and original Pi Zero ARMv6 CPUs are excluded. AWG selects the ARMv7 archive for
compatible armhf hosts only after a reviewed adoption populates the currently
empty ARMv7 release fields. Existing runnable ARM64 stores on mixed-bitness
hosts remain valid rollback candidates. This does not establish ARM32 support
for the full web/proxy stack or validate a physical Pi.

Installed canonical build40398953473/1 passed both native Linux and macOS lanes,
ARMv7 QEMU and all three Linux interoperability lanes; promoter40401950322/1
completed six-subject attestation verification with publication skipped. New
dispatched recovery metadata still needs live read-only validation. Host upgrade/
rollback waits for an actual verified release and reviewed adoption. Local fixture
tests are not substitutes for those remaining checks.

### Exact Bash for native macOS validation

Both macOS architectures build GNU Bash 5.3.20 below `RUNNER_TEMP` using
`scripts/boringtun-bash.py`. The reviewed
[`bash-toolchain.json`](../packaging/boringtun/bash-toolchain.json) pins the GNU
5.3 source archive and all twenty ordered upstream patches by SHA-256, with
checksums traced to the [immutable Homebrew formula](https://github.com/Homebrew/homebrew-core/blob/9d390e8ea5618fde14eeb084d0da3eb5a4cce53c/Formula/b/bash.rb).
Its canonical JSON digest is
`3bb13ba2ffc3096bbe7fe348a85f98e143c61c68072fd8b09be66b324543c73d`.
The build selects Xcode 16.4/16F6, SDK 15.5 and deployment target 11.0, and
disables readline and NLS so this shell needs no floating Homebrew libraries.
It installs no global files. The shared verifier checks both the version banner
and `BASH_VERSION`, the resulting executable hash, and the source receipt.

The original candidate job installed Homebrew Bash 5.3.15 and later failed the
production 5.3.20 gate. Its setup check ran under the macOS system Bash and did
not log either version representation. GNU Bash's shipped `CHANGES` records that
`[[` became subject to `set -e` after Bash 3.2; an unguarded comparison was
therefore insufficient there. Installation and verification now have explicit
failure exits and print the verified receipt. The local GNU-source verification
build was Linux-only; it is not native macOS validation.

`BASH-TOOLCHAIN.json` is copied into each `NATIVE-TOOLCHAIN.json` as supplemental
CI provenance. These receipt bytes and the Bash input manifest are not included
in the release descriptor's existing `toolchain_sha256` projection. This change
does not clear the native host/tool provenance activation gate or enable
publication. Both native macOS lanes passed in canonical build40398953473/1;
subsequent source changes still require their own exact-head CI.
