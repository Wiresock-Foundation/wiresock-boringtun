# Imitation Auto collisions: execution record

**Goal:** an Auto responder learns from a recognizable prelude datagram whose bytes also fit an AmneziaWG packet shape, when every reading of it is refused for a reason that established nothing.

**Spec (accepted plan, revision 3):** ../specs/2026-10-12-imitation-auto-collisions-design.md

**Base:** master b94943906b11641e274b3c950cc905aaf1631c59, branch `codex/imitation-auto-collisions`.

## Constraints

- Rust 1.75 APIs; no dependency or tracked Cargo.lock change; C ABI and public errors unchanged.
- Fixed modes, cryptographic settings, hint lifetimes, source isolation and socket-lifetime guards unchanged.
- No insertion logging, no probe reply for a colliding datagram.

## Red evidence (unchanged base)

`auto_imitation_learns_from_a_prelude_that_fits_a_transport_reading` run on b949439 with only the test, its fixtures and the `cfg(test)` accessor widening applied:

- Preconditions held: recorded datagrams #1/#2 detect as STUN, read as transport at offset 36 under the colliding H4 and at none under the control H4; #3-#5 detect as nothing and fit nothing; #1/#2 returned `Err(NoCurrentSession)`.
- Failed at "pending evidence before the initiation (colliding H4)": `None` vs `Some(Stun)`.
- Consequence variant (hint assertion replaced by a print): no pending hint, learned `None`, response not STUN-shaped.
- Control-only variant (control H4 and the no-prelude control): passed.

## Progress

1. Core policy and receive hook: `allows_imitation_hint`, `inbound::Refusal`, accumulation at every refusal site, `Tunn::decapsulate` hint-only observation. Tests 1-10 and the inbound policy tests.
2. Device listener: `ImitationHints::observe_refused` behind `Refused` with `allows_imitation_hint`, after the receive and before any send; the successful-selection discard is unchanged. `Roaming::with_layout`, eligibility-gated refusal handling and the production discard in the harness. Tests 11-15.
3. Live coverage: `auto_device_with`, `AutoClient::with` (configuration, H ranges, bind address, an allowed IP inside the tunnel), `prelude_raw`, `exchange`. Tests 16-19, with the retired-callback races as shared bodies run with a generated and with the recorded colliding prelude (loopback kept).

## Live probe setup

Checked before writing test 18: the existing `site_coverage_probe_and_cookie_replies` passed in WSL as root, so a UDP socket bound to the TUN-assigned `wg.addr_v4` reaches the listener at that address and receives a probe reply. The dummy-interface fallback was not needed.

## Deviations and fixture notes

- Test 7 (core slot): once the first initiation has created a session, the recorded bytes' receiver index can name an occupied slot, so the transport reading is refused `WrongIndex` instead of `NoCurrentSession`. Both are allowlisted routing refusals; the helper accepts either and prints the actual outcome. Policy unchanged.
- Test 1: CI on 0aa0d3b (`cargo hack test`, `--features ffi-bindings`) failed one run because the genuine STUN client's initiation had S1 filler whose bytes at 36 fell in the colliding H4, giving readings `[110, 36]` instead of `[110]`. The precondition now asserts that the initiation reading is the first, which is what makes it the one accepted; the filler is random. Fixture only.
- `is_shaped` is a plain predicate beside the existing asserting `shaped`.
- Device harness: `Roaming::listener` authenticated into a scratch buffer and committed from a second, zeroed one, so an accepted transport could never be delivered. Production authenticates and commits through the one `dst_buf`; the harness now does the same. Needed for the bidirectional plaintext checks; no production change.
- Device harness: `Roaming` records tunnel plaintext from either door (`take_delivered`) and gains `listener_with` (probe responder), `receive` (the decision without a commit), `send` and `has_tunnel_hint`.
- Live harness: the device's writes to its TUN are not otherwise observable, so "plaintext both ways" uses a new AF_PACKET capture (`TunCapture`) for client to device and the existing `TunInjector` for device to client; `exchange` brings the link up first. `AutoClient` now always configures an allowed IP for itself, so the device has a route for it.
- Test 19 is `auto_imitation_live_fixed_mode_colliding_request_stays_silent`; tests 16 and 18 also run their no-prelude and control cases inside the one test.

## Mutation checks

Each mutant applied to a fresh copy and rebuilt; unit suites (`device,mock-instant`) and the live Auto tests run against it. All six were killed:

| Mutant | Killed by |
|---|---|
| M1 production listener records nothing | live: colliding prelude learned, probe replies silent (the unit harness has its own copy, so only live tests can see this) |
| M2 core hook off | 8 unit tests (core and connected-socket) and both colliding retired-callback races |
| M3 eligibility flag ignored at both doors | accumulation, stale initiation, accepted packets, cookie/load; live replayed-transport veto |
| M4 `DestinationBufferTooSmall` allowed | accumulation and the per-variant policy test |
| M5 accepted packets observed | accepted packets, accumulation, stale initiation, the Auto runs of the three later-reading regressions |
| M6 socket-lifetime check removed | all four retired-callback races (plain and colliding) and the tunnel-state race |

## Validation

Local validation and release binary at 373fbc6; subsequent changes are documentation and the test-only precondition correction at 7bd49ef. Production build inputs are unchanged.

- Windows (stable 1.98.1, at 83c4c60, code-identical apart from a one-line test fix): `cargo test -p boringtun --lib auto_imitation` 16/0; `--features ffi-bindings,mock-instant` 413/0; `cargo check --features ffi-bindings,jni-bindings,mock-instant` ok; `cargo test -p boringtun` 310/0; `cargo fmt --check` and `git diff --check` clean; MSRV lint `cargo +stable clippy --all-targets --features=ffi-bindings -- -D clippy::incompatible_msrv` ok (stable lint, not a 1.75 build).
- Rust 1.75 builds (CI win7-msrv procedure, throwaway `git archive` copy, tracked Cargo.lock untouched): x86_64 and i686 `--features=ffi-bindings --locked` pass. The first attempt failed in ring's `cl.exe` step on an over-long object path under the scratch directory; a short `CARGO_TARGET_DIR` fixed it.
- Linux (WSL, rustup 1.97.1): workspace `--features device,ffi-bindings,mock-instant` 668/0; live Auto 12/0; whole ignored suite 66/0; clippy per feature with no warnings in changed files after 373fbc6.
- Release `boringtun-cli` from `git archive 373fbc6`, fresh target: sha256 `40660f6199a9a901d4bf88db62ccadac85bca8f2104b5a8859f7c3d10ad93ecc`.

## Recorded reproductions (installer tree 0aaaa63 via git archive, unchanged)

| Run | Published b949439 (`1210a3c6…`) | New (`40660f61…`) |
|---|---|---|
| `test-boringtun-auto-hint-live.sh` | 158/0 | 154/4: exactly `collision` (247-byte SIP probe, now SIP) and `stun-replay-colliding` (recorded STUN burst, now STUN), and their two cross-controls. `hint`, `hp-hint` (random, refusal warning), `hp-none` (random, no warning), `stun-replay-clear`, genuine dns/quic/sip/stun and reviewed-stun 1-3 pass. |
| `repro-stun.sh`, 16 genuine STUN clients, S 110,57,133,25 | 5 of 16 unresolved | 0 of 16 |
| `test-boringtun-sip-wire-live.sh` | 159/0 | 159/0 |

The four failures are the expectation flips the plan defers to the installer, done atomically with a pinned build; the installer was not changed.

## Final-head CI and independent review (7bd49ef)

CI on 7bd49ef: PR Status Checks 15/15 jobs succeeded ([run 38240014024](https://github.com/Wiresock-Foundation/wiresock-boringtun/actions/runs/38240014024)), Semgrep OSS scan succeeded (run 38240013940). The merge-ref logs name base b949439 and head 7bd49ef, report the 66 ignored integration tests passing and build Rust 1.75 x86_64/i686.

An independent review of `b949439..7bd49ef` closed with no production correctness or security blocker and two P3 documentation findings, both addressed in the commit after 7bd49ef (wording only: the counter-refusal explanation in `auto.rs`/README, and this section's heading). The reviewer's own reruns on exact-head disposable copies under Linux/WSL reported core/noise 365 passed, device Auto unit tests 12 passed, root/TUN Auto live tests 12 passed, the expected red failure on the base, and reproductions of mutants M1, M3 and M6; the reviewer independently hashed the recorded binary as the 373fbc6 build (`40660f61…`). Those runs are the reviewer's, not part of the validation above; the reviewer's script and logs are kept at `C:/Users/vadim/.codex/visualizations/2026/10/12/01a12f3f-c629-76e1-b0ee-a4ed3722e1c9/pr82-review/` (`probes.py`, `logs/`, exact base/head archives). The reviewer inspected rather than reran the installer campaigns and the Windows/MSRV builds.
