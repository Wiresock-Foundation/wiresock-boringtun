# Activation audit: 26 October 2026

The owner approved normal-path activation on 26 October 2026: push and merge
this change after independent review and green CI, then publish its first fresh
merge-source release and later ordinary merged-PR releases. The approval covers
job-scoped OIDC, attestation and release writes, accepts the hosted compiler/SDK
trust boundary, and explicitly accepts narrower initial ordinary-event coverage.
No actions:write dispatcher, new credential or repository setting is authorized.
No release, tag or deployment was performed during the earlier trial/preparation.

## Installed evidence

PR98 merged as `1cee1afadd6be4251d6a19273b1882090bd2038e`. Its tree equals
the independently reviewed PR head `05e16c9696d629bb7b8423872e11da9b8d09938d`.

| Check | Observed result |
| --- | --- |
| [Canonical build 40398953473](https://github.com/Wiresock-Foundation/wiresock-boringtun/actions/runs/40398953473), attempt1 | 13/13 jobs succeeded: real master-push source/merged-PR resolution, notices, five reproducible archives, three Linux interoperability lanes and two macOS utun lanes. |
| [Standard40398953497](https://github.com/Wiresock-Foundation/wiresock-boringtun/actions/runs/40398953497) | 16/16 succeeded. Semgrep40398953403 also succeeded. |
| [Promoter40401950322](https://github.com/Wiresock-Foundation/wiresock-boringtun/actions/runs/40401950322), attempt1 | Prepare, attest and verify succeeded; publication job 121850247293 was skipped. Policy was enabled:false; selected PR98 alone was eligible for the approved trial. |
| [Public attestation60103716](https://github.com/Wiresock-Foundation/wiresock-boringtun/attestations/60103716) | Six subjects: five archives and RELEASE.json. Signing occurred 21:10:12–21:10:18 UTC. Verification job 121850244631 reported validation_verified:true at 21:11:06 UTC. |

Pinned gh 2.100.0 performed cryptographic verification in the installed CI job.
The certificate binds publisher workflow `.github/workflows/boringtun-release.yml`
at `refs/heads/master`, GitHub OIDC issuer, GitHub-hosted runner, source and signer
digest `1cee1afadd6be4251d6a19273b1882090bd2038e`, and invocation
`https://github.com/Wiresock-Foundation/wiresock-boringtun/actions/runs/40401950322/attempts/1`.
The signed descriptor independently binds build 40398953473/1 and workflow 397187760;
publisher workflow 397187761 is pinned. No second validation run is authorized.

The fixture under `tests/fixtures/attestation-40401950322-1/` retains an untouched
gh JSON output, the exact descriptor and the receipt for all six reads. All six
raw outputs were byte-identical and contained the combined six-subject statement.
Full originals and prepared archives were downloaded and digest-checked locally.
The fixture tests replay semantic policy only; JSON cannot independently prove
signature verification. The linked installed CI supplies that evidence.

| Archived artifact | ID | SHA-256 |
| --- | --- | --- |
| promotion-40401950322-1 | 12688842832 | 8f3472e2a46beb602652b9fffb59889ddae15581655c14850305cd5938fc304e |
| attestation-validation-40401950322-1 | 12689855439 | 84bee65f190ab9d3a1b6ca34cd12c280fcf76c2603773d38d5dbc44ce6b040bd |

The prepared artifact expires 2 November 2026; the verification artifact expires
25 November 2026. Repository fixtures preserve the public verification evidence;
local archival copies preserve exact ZIPs and all prepared bytes beyond expiry.

## Retirement and attribution

The refreshed owner-authenticated, paginated read-only audit at
2026-10-26T21:45:42Z still found workflow 369920301 **disabled_manually**, nine
completed successful historical runs, zero active runs, zero drafts and four
published prereleases. `packaging/boringtun/legacy-retirement-evidence.json`
contains the IDs and source-file hashes at retired AWG commit
`514ea073c904a90cfeccda06ad1ea78553273c59`. The earlier approved disable was not
repeated. Fresh read-only contents checks also confirmed both files on current
AWG main still match those retired hashes. Recheck immediately before activation;
public fork tokens cannot prove
absence of private drafts, so preserve the fresh owner-side audit too.

Cloudflare's original notice and other-author notices remain intact. Existing
WireSock 2024–2026 assertions are retained as adaptation notices, not independently
verified creation dates. Owner testimony that wgbooster/netlib predate 2022 is
recorded in ATTRIBUTION.md. The date-only blocker is resolved by notice
preservation; no invented start year or further broad history demand is needed.

## Hosted toolchain trust and signed coverage

Signed source C binds Cargo.lock, runtime-provenance.json, build scripts and
bash-toolchain.json. Checksums cover pinned Rust 1.98.1 distributions and source,
LLVM/compiler-builtins/native notice inputs for all five targets, GNU Bash 5.3
source and twenty ordered patches. macOS selects Xcode 16.4/16F6, SDK 15.5 and
deployment target 11.0. Checkout/upload/download/setup-go actions are SHA-pinned.

The descriptor's toolchain_sha256 covers its documented Rust/LLVM/input
projection; it is not a digest of every executing host tool. GitHub-hosted runner
images, distribution APT tools, host compiler/linker and Apple SDK are trusted
platform inputs. Version/executable/compiler/SDK/Bash/packaging receipts are
supplemental CI artifacts, **not signed subjects**. Reproducible outputs from two
builds on a host do not establish a hermetic bootstrap or independent-host
reproducibility. Approval must accept this explicit boundary; stronger receipt
attestation is a separate contract change, not evidence already obtained.

Linux x86_64/aarch64 and macOS Intel/Apple Silicon ran natively. ARMv7 hard-float
musl was cross-built and exercised with QEMU. Physical Pi testing and the full
ARM32 AWG panel/proxy stack remain unvalidated. No Apple signing/notarization
credential is configured or proposed.

## Approved activation and remaining recovery work

The owner chose the narrower initial ordinary-push path, with automatic catch-up
separate. Missing, batched and token-suppressed events remain visible diagnostic
gaps; there is no automatic recovery implementation or authorization for an
actions:write dispatcher. A concrete exceptional source requires reviewed manual
recovery, never a blind signing retry or an invented push. This initial scope is
not a claim that every merged PR is automatically covered.

The owner accepted the hosted-toolchain trust boundary and existing job-scoped
publication permissions. The remaining installation prerequisites are exact-head
CI, unchanged independent-review coverage, fresh retirement readback and a normal
merge. Actual first-release completion must be observed and verified separately.

The boundary guard excludes source 1cee itself and all sources whose own
policy remains disabled, even if their promoters run after master enablement.
An eligible source must descend from 1cee and contain the same enabled activation
generation (`fork-v1`), with no source blockers. Current-master policy must still
equal trusted publisher policy before signing/publication; revocation remains
effective. The completed validation selection is null. This approved change sets
enabled:true and clears the resolved activation decisions; workflow job
permissions are unchanged. The source's own enabled policy means the activation
PR's fresh merge is the first eligible source; old disabled sources remain out.

Historical tag permission and incompatible historical recipes are conditional
backfill limitations, not reasons to repeat the completed trial. No pre-activation
backfill is proposed. Post-activation queued sources must remain visible through
pipeline changes; unresolved recovery cannot be called successful coverage.
See [activation and recovery design](BORINGTUN_ACTIVATION_PLAN.md) for the exact
approval request and first-release/adoption/Lisbon sequence.
