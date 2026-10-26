# Fork attribution evidence

The WireSock trade name identifies Vadim Smirnov, as documented by the maintainer
in [AWG issue 175](https://github.com/wiresock/awg-server-tools/issues/175) and
[AWG CONTRIBUTING.md](https://github.com/wiresock/awg-server-tools/blob/18d56572f688803e3221572819895cfa89b0d1b2/CONTRIBUTING.md).
The ownership-name correction preserves all 39 existing notice year ranges.
It does not assign other contributors' rights to him. Cloudflare's original
LICENSE.md is preserved verbatim, followed by the fork notice and the same BSD
terms. The fork notice's range preserves the existing source claims; **2024
has not been independently verified and is a release gate requiring the owner's
source evidence or explicit correction**.

## Evidence and limits

The audit on 2026-10-26 covered all five branches and 30 preserved pull-request
heads in the archived [wiresock/boringtun](https://github.com/wiresock/boringtun)
repository: 370 reachable commits and 728 source blobs. Eighteen of the 33 files
below have matching implementations in that history. The other fifteen first
appear later in the current fork; searches for renamed or split code found no
earlier archived implementation. The search cannot exclude rewritten code or
code originating in a separate client repository. The new fork's creation date
is not the origin date of the code it imported.

Earlier WireSock fork work is recorded in
[1425e4f (2022-08-07)](https://github.com/wiresock/boringtun/commit/1425e4f306b343e4fbcf22d6f205b95bafaa9044),
which added Windows static-library configuration and changed handshake-index
handling, and
[835e2e5 (2025-01-29)](https://github.com/wiresock/boringtun/commit/835e2e5f8f579cd3cd698e4e4e454f157efb2cfc),
which added fixed Amnezia message-type obfuscation tags. Comparing both 2024
merges,
[aa424d3 (2024-01-12)](https://github.com/wiresock/boringtun/commit/aa424d3a16d2d829c9b25e7894809506d9d394de)
and
[8bd0e1c (2024-10-16)](https://github.com/wiresock/boringtun/commit/8bd0e1ca2a934b4e40337db84d8ad909986ab1b7),
with their Cloudflare parents shows only the earlier Windows configuration and
handshake-index changes. Those changes are outside the 33 files below. The
archive therefore confirms earlier work but does not substantiate any of these
33 files' 2024 start claims.

The preserved protocol-imitation implementation commits start on **2026-06-28**:
[Amnezia extensions](https://github.com/wiresock/boringtun/commit/f17e9f95d3c448a077b165821dde702487ea7e9a),
[QUIC framing and crypto](https://github.com/wiresock/boringtun/commit/9056007a2e778f3ea0220761cd848cc46d91435e),
and
[DNS/SIP/STUN](https://github.com/wiresock/boringtun/commit/c61f83f86d15ec716c902f167b4e9f2b406302de).
The combined import
[5e402bd](https://github.com/wiresock/boringtun/commit/5e402bd32cf12178ebcdae9e0f57d2a1fd4602cb)
was committed on 2026-06-29. Its 2026-02-21 author timestamp matches the earlier
[H1-H4 range change](https://github.com/wiresock/boringtun/commit/89fbf75eef28801791fd820b58f0553f88959366);
it is not evidence that the protocol-imitation modules existed in February.
These dates establish the recorded Rust lineage, not the origin date of client
code it ports or copyright ownership.

## Origin of the existing year claims

Seventeen of the eighteen archived files already carried
`Copyright (c) 2024 BoringTun contributors. All rights reserved.` at their first
addition. `amnezia.rs` initially had no notice;
[433fbef (2026-06-29)](https://github.com/wiresock/boringtun/commit/433fbef02b3029aeaa1268dc0f7f31811f9ced90)
added the same header for licensing-metadata consistency, without supplying
2024 source evidence.

The current fork's
[identity correction 01afef5 (2026-08-09)](https://github.com/Wiresock-Foundation/wiresock-boringtun/commit/01afef5d5743fcf67cda810d3db5f3c82cd0f5d3)
changed exactly those eighteen headers to `2024-2026 WireSock`. Its explanation
says the earlier notices credited the wrong project and deliberately preserves
the upstream Cloudflare notices. This records the intended ownership-name
correction; it neither verifies the starting year nor assigns other
contributors' rights. All fifteen later files entered the current fork already
carrying `2024-2026 WireSock`.

## Files with an unresolved 2024 start

Each link identifies the exact file at its earliest recorded implementation
found in the audited history. **Archived** means code matched in the preserved
old fork; **Current** means first addition in the current fork, with no earlier
archived implementation found. Dates are committer dates; the archived entries
also have matching author dates. They do not prove the absence of earlier
external source. All 33 existing ranges and the six 2026-only notices remain
unchanged.

| File | Earliest recorded implementation | Lineage |
| --- | --- | --- |
| `boringtun/src/device/imitation_auto.rs` | [2026-10-06 (b94943906b11)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/b94943906b11641e274b3c950cc905aaf1631c59/boringtun/src/device/imitation_auto.rs) | Current |
| `boringtun/src/device/probe_budget.rs` | [2026-08-05 (0f703e4873ee)](https://github.com/wiresock/boringtun/blob/0f703e4873ee31821289c469a07d090b43bd507a/boringtun/src/device/probe_budget.rs) | Archived |
| `boringtun/src/device/probe_reply.rs` | [2026-08-06 (dfb376f844f3)](https://github.com/wiresock/boringtun/blob/dfb376f844f3a717a3e219f2b27f82c86f27c36d/boringtun/src/device/probe_reply.rs) | Archived |
| `boringtun/src/device/reply_policy.rs` | [2026-08-06 (627759a0870f)](https://github.com/wiresock/boringtun/blob/627759a0870ffc3c8c34fbb8a9031c4c34eaccbb/boringtun/src/device/reply_policy.rs) | Archived |
| `boringtun/src/device/udp_diagnostics.rs` | [2026-10-02 (ae2ab44e9a68)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/ae2ab44e9a68ca1a3232d2e8b13f9db30a9b9dcf/boringtun/src/device/udp_diagnostics.rs) | Current |
| `boringtun/src/noise/amnezia.rs` | [2026-06-28 (f17e9f95d3c4)](https://github.com/wiresock/boringtun/blob/f17e9f95d3c448a077b165821dde702487ea7e9a/boringtun/src/noise/amnezia.rs) | Archived |
| `boringtun/src/noise/auto_imitation_fixtures.rs` | [2026-10-12 (e94c04f3f4fd)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/e94c04f3f4fdb8b392f9586db07a269ea0bf7575/boringtun/src/noise/auto_imitation_fixtures.rs) | Current |
| `boringtun/src/noise/auto_imitation_tests.rs` | [2026-10-06 (b94943906b11)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/b94943906b11641e274b3c950cc905aaf1631c59/boringtun/src/noise/auto_imitation_tests.rs) | Current |
| `boringtun/src/noise/disable_cookies_tests.rs` | [2026-09-24 (f4115f9006fb)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/f4115f9006fb313f38be7c19f85cddf4bef401ba/boringtun/src/noise/disable_cookies_tests.rs) | Current |
| `boringtun/src/noise/header_protection.rs` | [2026-08-17 (c7710f18e8bc)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/c7710f18e8bc279b240575436153c27b7edc4ad6/boringtun/src/noise/header_protection.rs) | Current |
| `boringtun/src/noise/hp_imitation_policy_tests.rs` | [2026-09-27 (59b736221274)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/59b73622127457b41a94aade5fa8e32a00579bff/boringtun/src/noise/hp_imitation_policy_tests.rs) | Current |
| `boringtun/src/noise/imitation/auto.rs` | [2026-10-06 (b94943906b11)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/b94943906b11641e274b3c950cc905aaf1631c59/boringtun/src/noise/imitation/auto.rs) | Current |
| `boringtun/src/noise/imitation/detect.rs` | [2026-08-05 (aaf154d5b183)](https://github.com/wiresock/boringtun/blob/aaf154d5b1838433593a1bdc3acdc0c965cce94e/boringtun/src/noise/imitation/detect.rs) | Archived |
| `boringtun/src/noise/imitation/dns.rs` | [2026-06-28 (c61f83f86d15)](https://github.com/wiresock/boringtun/blob/c61f83f86d15ec716c902f167b4e9f2b406302de/boringtun/src/noise/imitation/dns.rs) | Archived |
| `boringtun/src/noise/imitation/mod.rs` | [2026-06-28 (c61f83f86d15)](https://github.com/wiresock/boringtun/blob/c61f83f86d15ec716c902f167b4e9f2b406302de/boringtun/src/noise/imitation/mod.rs) | Archived |
| `boringtun/src/noise/imitation/sip.rs` | [2026-06-28 (c61f83f86d15)](https://github.com/wiresock/boringtun/blob/c61f83f86d15ec716c902f167b4e9f2b406302de/boringtun/src/noise/imitation/sip.rs) | Archived |
| `boringtun/src/noise/imitation/stun.rs` | [2026-06-28 (c61f83f86d15)](https://github.com/wiresock/boringtun/blob/c61f83f86d15ec716c902f167b4e9f2b406302de/boringtun/src/noise/imitation/stun.rs) | Archived |
| `boringtun/src/noise/inbound.rs` | [2026-09-23 (62f046d64cd1)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/62f046d64cd16d4b3773eb1c8b4ec5b4b2495143/boringtun/src/noise/inbound.rs) | Current |
| `boringtun/src/noise/live_reframe_tests.rs` | [2026-09-24 (e83bac689b98)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/e83bac689b987c66605ffafa75dd05734808e184/boringtun/src/noise/live_reframe_tests.rs) | Current |
| `boringtun/src/noise/quic/crypto.rs` | [2026-06-28 (9056007a2e77)](https://github.com/wiresock/boringtun/blob/9056007a2e778f3ea0220761cd848cc46d91435e/boringtun/src/noise/quic/crypto.rs) | Archived |
| `boringtun/src/noise/quic/fingerprint.rs` | [2026-06-28 (17ca48dafa9d)](https://github.com/wiresock/boringtun/blob/17ca48dafa9d18ee5dfb674bd8b82dd8df8533ce/boringtun/src/noise/quic/fingerprint.rs) | Archived |
| `boringtun/src/noise/quic/generator.rs` | [2026-06-28 (f2c3d183384f)](https://github.com/wiresock/boringtun/blob/f2c3d183384f35030cd46f5abac3eecc83072d28/boringtun/src/noise/quic/generator.rs) | Archived |
| `boringtun/src/noise/quic/initial.rs` | [2026-06-28 (9056007a2e77)](https://github.com/wiresock/boringtun/blob/9056007a2e778f3ea0220761cd848cc46d91435e/boringtun/src/noise/quic/initial.rs) | Archived |
| `boringtun/src/noise/quic/mod.rs` | [2026-06-28 (9056007a2e77)](https://github.com/wiresock/boringtun/blob/9056007a2e778f3ea0220761cd848cc46d91435e/boringtun/src/noise/quic/mod.rs) | Archived |
| `boringtun/src/noise/quic/profiles.rs` | [2026-06-28 (77948a2b2a5f)](https://github.com/wiresock/boringtun/blob/77948a2b2a5f25c129d68b370a4d32617d7b89eb/boringtun/src/noise/quic/profiles.rs) | Archived |
| `boringtun/src/noise/quic/tls.rs` | [2026-06-28 (77948a2b2a5f)](https://github.com/wiresock/boringtun/blob/77948a2b2a5f25c129d68b370a4d32617d7b89eb/boringtun/src/noise/quic/tls.rs) | Archived |
| `boringtun/src/noise/quic/varint.rs` | [2026-06-28 (9056007a2e77)](https://github.com/wiresock/boringtun/blob/9056007a2e778f3ea0220761cd848cc46d91435e/boringtun/src/noise/quic/varint.rs) | Archived |
| `boringtun/src/noise/quic/version_negotiation.rs` | [2026-08-06 (4b786919b3a8)](https://github.com/wiresock/boringtun/blob/4b786919b3a8c4ae1ca4962645d204deff0ccbfb/boringtun/src/noise/quic/version_negotiation.rs) | Archived |
| `boringtun/src/noise/random_trailers_tests.rs` | [2026-09-23 (80fd82c2b971)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/80fd82c2b971d705e6ca6010d07274dbbf4096d3/boringtun/src/noise/random_trailers_tests.rs) | Current |
| `boringtun/src/noise/upstream_collision_tests.rs` | [2026-09-24 (61a93a3eb9ae)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/61a93a3eb9ae1821799436f974a2e1f623c26477/boringtun/src/noise/upstream_collision_tests.rs) | Current |
| `boringtun/tests/jni/com/cloudflare/app/boringtun/BoringTunJNI.java` | [2026-08-10 (ab720b1783c1)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/ab720b1783c1105e83e8c52a45e1c82620c021c6/boringtun/tests/jni/com/cloudflare/app/boringtun/BoringTunJNI.java) | Current |
| `scripts/ffi-header-cpp-check.cpp` | [2026-08-20 (fadae9dd9746)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/fadae9dd9746761ca867a83d915ee56e4c819945/scripts/ffi-header-cpp-check.cpp) | Current |
| `scripts/ffi-layout-check.c` | [2026-08-20 (fadae9dd9746)](https://github.com/Wiresock-Foundation/wiresock-boringtun/blob/fadae9dd9746761ca867a83d915ee56e4c819945/scripts/ffi-layout-check.c) | Current |

## Remaining attribution question

The unresolved evidence is the original WireSock client history for the ported
components. Source comments identify `wgbooster` protocol-aware padding,
`netlib/src/wireguard/pre_handshake.h`, `simulate_browser_dns_resolution`,
`build_stun_binding_request_packet` / `simulate_stun_request`, and
`netlib/src/quic/quic_sni_generator.h`. Those client implementation paths are
absent from the archived BoringTun history. `noise/imitation/detect.rs` instead
names the AWG proxy responder.

The owner can resolve the remaining question with client source history or a
dated source snapshot supporting the 2024 start for the ported components, or
an explicit correction if that year was carried from a header template. The
archived BoringTun lineage is now accounted for; separate per-file explanations
are unnecessary. Existing notices remain preserved. Release remains blocked until this evidence
or correction settles the year claims.

## Other contributors

Commit ab4ff30621fce56fd5cf1a5812f02bfd4b994cfe (PR #90), authored by
Ya'Slav (`cargo-build`, GitHub numeric ID 106316728), is co-authored by Vadim
Smirnov. It adds authenticated receive metadata and regression coverage in
`noise/receive_metadata_tests.rs`, and changes `noise/handshake.rs`,
`noise/inbound.rs`, `noise/mod.rs`, `noise/op_report.rs`,
`ffi/metadata_tests.rs` and `CHANGELOG.md`. Its new test file carries only
`SPDX-License-Identifier: BSD-3-Clause`; this change leaves it that way and
does not invent a copyright attribution for it. In shared files, the corrected
pre-existing WireSock notice covers its holder's contributions, not every
contribution to the file. Git history retains the authorship evidence.

Vadim's 2021 contribution to upstream Cloudflare BoringTun remains upstream
code under the preserved upstream notice. Dependabot dependency updates do
not justify claiming ownership of the dependency authors' code.

## Check

Run `python3 scripts/check-attribution.py`. It checks the original Cloudflare
license bytes, fork distribution notice and BSD terms, and rejects the old
trade-name-only source notice. It verifies preservation, not historical title
to copyright or the unverified 2024 start.
