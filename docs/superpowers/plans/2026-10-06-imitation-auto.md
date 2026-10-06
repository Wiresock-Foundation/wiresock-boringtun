# Imitation Auto Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Learn and retain each authenticated client's imitation protocol on an auto-mode server.

**Architecture:** Keep requested Auto configuration separate from the effective outbound mode. Temporary bounded source hints feed a per-tunnel choice at authenticated initiation commit; reuse the existing protocol detector and fillers.

**Tech Stack:** Rust, existing noise/device/FFI layers; Windows and WSL Linux tests.

**Spec:** ../specs/2026-10-06-imitation-auto-design.md

## Global Constraints

- Rust 1.75-compatible APIs; no new dependencies.
- Preserve protocol enum values 0–4; Auto = 5; C ABI layout unchanged.
- Preserve WireGuard-first classification, authentication, replay checks, and reply budgets.
- 30-second hints; at most 1024 unverified source endpoints; no lifetime refresh.

## Review Focus

- Forged or replayed traffic must not change a learned peer mode.
- Same IP with different UDP ports must not share pending hints.
- Short output buffers must not pin a provisional mode.
- Live updates and roaming must preserve learned modes but clear stale hints.
- Header protection and cookie amplification policies must apply after selection.

## Task 1: Core selection and configuration

Files: noise/amnezia.rs, noise/imitation/detect.rs, new noise/imitation/auto.rs, noise/mod.rs, new noise/auto_imitation_tests.rs, wireguard_ffi.h, ffi/mod.rs.

Interfaces: Auto = 5; Probe::protocol() -> AmneziaImitationProtocol; Tunn::imitation_protocol() -> AmneziaImitationProtocol exposes effective mode; Tunn::commit_with_imitation(packet, datagram, hint, dst) applies provisional selection with rollback; AmneziaConfig::resolve_imitation(protocol) -> Cow<'_, AmneziaConfig> preserves all framing fields and checks existing header-protection policy before activation.

- [x] Add failing real-handshake tests through numeric/string parsing and Tunn::decapsulate; assert mode-specific response bytes and data round trips for DNS/QUIC/SIP/STUN.
- [x] Run `cargo test -p boringtun auto_imitation --features ffi-bindings` and observe missing-mode failures.
- [x] Implement enum/parser, temporary hint, per-tunnel state and framing; add tests for forgery, stale hints, fixed mode, short-buffer rollback, live reconfiguration and header protection.
- [x] Run focused core tests and Windows FFI suite; expect all pass.

## Task 2: Device integration

Files: new device/imitation_auto.rs, device/mod.rs, device/probe_reply.rs, CLI main.rs.

Interfaces: ImitationHints::observe(from, datagram), get(from), discard(from), clear(), backed by a mutex on Device; source identity is SocketAddr. Anonymous commit supplies the hint to Tunn::commit_with_imitation. Existing core ingress handles connected sockets.

- [x] Add tests for simultaneous peers, identical-IP source separation, TTL and capacity, auto probes and fixed-mode restrictions, anonymous handshake response and cookie framing.
- [x] Run focused Linux tests before implementation and inspect expected failures.
- [x] Wire cache observation only after no AmneziaWG candidates; use hints at authenticated commit and cookie framing; clear on framing changes; expose CLI auto through enum-derived value list.
- [x] Run Linux `cargo test --workspace --features device,ffi-bindings,mock-instant`; expect all nonignored tests pass.

## Task 3: Documentation and verification

Files: README.md, CLI help, Rust/C API documentation, this plan.

- [x] Document per-client auto semantics, explicit framing requirements, unresolved fallback and header-protection restrictions.
- [x] Run formatting, Linux and Windows suites, clippy, C/C++ header checks, and CLI help smoke check.
- [x] Request independent whole-change review, address actionable findings, and report verified behavior and limitations.

## Execution record

- Planning: clean master at ae2ab44; isolated native worktree on codex/imitation-auto. User authorized planning and implementation together; proceeding inline without redundant permission rounds.
- Shared interfaces: core effective mode and provisional commit are consumed by the device cache; fixed framing remains device-wide.
- Red/green: core and device tests failed before implementation; all focused tests passed after implementation. Fixed modes retained their existing short-buffer behavior.
- Independent review: one stale device-hint lifecycle issue (Important) and one missing warning on live header-protection updates (originally Minor). The warning was treated as Important because preserving the existing nonce-strength warning policy is an explicit requirement. Both fixes were preceded by failing regressions; both now pass. No remaining actionable findings.
- Hint lifecycle fix: consume hints after a successful authenticated selection; clear the removed peer's endpoint hint and all hints on replace-peers. The live regression removes/readds a peer on the same UDP socket and verifies a different protocol is selected immediately.
- Final Linux workspace suite: `cargo test --workspace --features device,ffi-bindings,mock-instant` — 650 passed, 55 ignored, 0 failed. Baseline: 635 passed, 54 ignored.
- Final Windows library suite: `cargo test -p boringtun --features ffi-bindings,mock-instant` — 402 passed, 0 failed. `cargo check -p boringtun --features ffi-bindings,jni-bindings,mock-instant` passed. The Unix device/CLI features cannot be built on Windows and were tested under WSL.
- Live WSL Linux test: `cargo test -p boringtun --features device auto_imitation_live_listener_and_connected_sockets -- --ignored --nocapture` passed, including four clients sharing an IP with distinct ports, DNS/QUIC/SIP/STUN, rekeys, shared and connected sockets, and endpoint reuse after peer replacement. This test needs a usable TUN device and is ignored in the ordinary suite.
- Verification: `cargo fmt --all -- --check`, `git diff --check`, Linux `cargo clippy --workspace --all-targets --all-features -- -D clippy::incompatible_msrv`, 32/64-bit C and C++ header compile probes, and built CLI `--help` all passed. Clippy reports existing unrelated warnings. Clippy checked API MSRV compatibility; the complete dependency graph was not rebuilt on Rust 1.75.
- Scope limits: the tests verify wire format and interoperability within this implementation, not real-world DPI classification. Runtime JNI behavior was not separately exercised; the shared FFI configuration adapter accepts Auto=5 and JNI bindings compile.
- Delivery: keep the completed feature on `codex/imitation-auto` in its attached worktree; no merge or push requested.

### Review follow-up: three P2 findings (on 19846e2)

Each fix was preceded by a regression that was run and failed for the reported reason. The fixes are in a separate commit after 19846e2, which was not amended.

- **P2-1: pending tunnel hints crossed source ports.** `Tunn` binds its one pending hint only to the caller's source IP. After a STUN prelude on a connected peer's endpoint A, an authenticated roam to B on the same IP left the hint in place, so a rekey on B's connected socket selected STUN. A configured `endpoint=` move had the same effect.
  - Regressions:
    - `device::imitation_auto` `auto_imitation_pending_tunnel_hint_does_not_follow_a_roam` (unit; listener plus connected-socket paths). Before the fix it failed with "A's prelude must not select the imitation on B". It now asserts random → random → random on A/B, that B's own prelude then teaches STUN, and that STUN survives a roam back to A even with a DNS prelude there.
    - Live `auto_imitation_live_roam_does_not_carry_pending_hint` and `auto_imitation_live_configured_endpoint_drops_pending_hint`. Both failed with the same message before the fix.
    - `auto_imitation_rejected_roams_keep_pending_tunnel_hint` guards that a forged initiation from B, and an authenticated one whose commit fails (short buffer), neither move the endpoint nor discard A's evidence. As a guard it passed before the fix too.
  - Fix: `Tunn::discard_imitation_hint` (device only) clears pending evidence and keeps the learned mode. It is called in two places:
    - in `commit_anonymous`, only after a successful commit from a new address, the same point where the UDP-window rollback decision is made;
    - in `merge_peer`, when a configured endpoint actually changes.

  The connected-socket handler never changes the endpoint. The device cache was already keyed by full `SocketAddr`.
- **P2-2: peer removal left hints at earlier endpoints.** `remove_peer` discarded only the current endpoint's device hint. Sequence: learn STUN on A, repopulate A with a second STUN prelude, roam to B, then remove and re-add the peer. A DNS prelude and initiation from A then inherited STUN.
  - Regression: live `auto_imitation_live_replacement_ignores_previous_endpoint_hint`. Before the fix it failed with `left: Stun, right: Dns`.
  - Fix: removing an existing peer clears the whole bounded device cache. This is documented in code and README: it also discards other peers' unverified hints, while learned modes are kept. The regression asserts both for a second peer (its pending hint is cleared; QUIC stays learned and its rekey is still QUIC-shaped).
  - Test change: the original live test sent all four preludes up front. Removing the first client's peer now cleared the others' unconsumed hints, so it failed (QUIC received random). Each client now resends its prelude before its first initiation, as a real client does.
- **P2-3: default Rust builds omitted DNS/STUN warnings.** `warn_header_protection_nonce` and both `Tunn` call sites were gated on `device`/`ffi-bindings`. The complaint text was gated on `test`/`device`/`ffi-bindings`.
  - Regression: `auto_imitation_reports_learned_nonce_warning_in_every_build` replaces the feature-gated test. It runs with no features and covers DNS and STUN in three cases: header protection on before learning, a live update enabling it after learning, and repeated identical updates. Each case expects exactly one warning naming the protocol. It also checks that a fixed-mode `Tunn` stays silent, since its door warns. Before the fix it failed in a default build with `masking enabled before learning Dns: left 0, right 1`.
  - Fix: removed the gates on the helper chain and both call sites. Updated the comments that said only the doors, not `Tunn`, emit these warnings. Fixed-mode door warnings and the SIP refusal are unchanged.
- **Results (all run on the final tree):**
  - Default library, Windows: `cargo test -p boringtun --lib auto_imitation` passed, 7 tests. Non-test `cargo check -p boringtun` passed with 4 dead-code warnings (UAPI key helpers). A `git archive` build of 19846e2 shows the same 4 warnings.
  - Windows: `cargo test -p boringtun --features ffi-bindings,mock-instant` passed, 402 tests, 0 failed. The count is unchanged because one gated test was replaced by one ungated test. `cargo check -p boringtun --features ffi-bindings,jni-bindings,mock-instant` passed.
  - WSL Linux, rustup cargo 1.97.1: `cargo test --workspace --features device,ffi-bindings,mock-instant` passed 652, failed 0, ignored 58. Previously 650/55: +2 unit regressions, +3 ignored live tests.
  - Live WSL: `cargo test -p boringtun --lib --features device auto_imitation_live -- --ignored` passed 4/4, both serially and in parallel. The parallel run was repeated 10× before the final comment-only edits, 10/10 passing.
  - Verification: `cargo fmt --all -- --check` and `git diff --check` passed. Linux `cargo clippy --workspace --all-targets --all-features -- -D clippy::incompatible_msrv` exited 0. Its warnings are pre-existing and none are in changed files.
- **Not performed:** C/C++ header probes (the header is unchanged), CLI `--help` smoke test, and a full Rust 1.75 build. The Rust 1.75 build has the known lockfile limitation; Cargo.lock and dependencies are unchanged.

### Review follow-up: stale connected-socket callbacks (on 9e4e370)

Findings 2 and 3 above are resolved. This change addresses only the remaining P2 race in finding 1.

- **Race.** The connected handler received a datagram first, then took the peer lock and decapsulated it. Nothing checked that its socket was still the peer's. Failing sequence:
  1. A worker receives A's STUN prelude on A's connected socket and pauses before the peer lock.
  2. Another worker completes an authenticated roam to B. This clears pending evidence and shuts down A's socket.
  3. The retired callback resumes, calls `Tunn::decapsulate` and restores the IP-bound hint.
  4. B's next rekey on its connected socket pins STUN.

  The generation checks in `udp_diagnostics` covered only receive and send errors.
- **Identity and lifetime.** `peer::ConnLifetime` wraps an `Arc<()>` and is compared with `Arc::ptr_eq`.
  - **Commit:** one is allocated for each socket committed to `endpoint.conn`, under the same peer lock as `commit_connected_socket`, before the handler is registered.
  - **Hand-off:** it is passed to `register_conn_handler`, and the handler keeps its own clone.
  - **Uniqueness:** a live allocation's address cannot be reused, so no later token can equal a token that a handler still holds. There is no counter to exhaust or wrap.
  - **Not `DiagGen`:** `DiagGen::Untracked` is shared once the generation allocator is spent, so it is not a lifetime identity. Its diagnostic fallback is unchanged.
  - **Not address equality:** after A → B → A, a replacement socket sits at the retired socket's address.

  `Peer::is_current_connection` requires all three: `conn` present, `endpoint.addr` equal to the socket's endpoint, and the token identical.
- **Fix.** After acquiring the peer lock, and before any decapsulation, the handler checks `is_current_connection` under that same lock. A retired callback drops the datagram and ends the batch. It does not mutate the tunnel, deliver packets, reply or flush, and this applies to every connected datagram. No busy loop is added: retiring a socket always shuts it down first (`move_endpoint` and `shutdown_endpoint`). Once the handler returns, the existing EPOLLHUP → EoF → `cancel` path frees it. Receive-error diagnostics still run before the check, unchanged.
- **Test hook.** A `#[cfg(test)]` `Device::conn_recv_hook` is called by the production handler at two points: after a datagram is received (before the peer lock), and after it has been handled or dropped. `PausedCallback` drives it with channels to force receive → pause → successful roam → resume deterministically. There are no sleeps or retry loops. Every wait is bounded, and dropping the helper releases a held worker at once.
- **A kernel detail the test works around.** While a callback holds its fd, the shut-down socket stays hashed with A's 4-tuple and outranks the listener, so A's datagrams to the device address queue on it. The A → B → A tests therefore send the return keepalive to `127.0.0.2`, which only the wildcard listener matches. They then wait, bounded, on `/proc/net/udp` until the retired socket has closed before using A's replacement socket.
- **Regressions.** These are live tests (root and TUN, `--ignored`), each red before the fix:
  - `auto_imitation_live_retired_callback_cannot_restore_hint` (A → B). Red: "a retired callback restored A's evidence". Green: no pending hint; random → random → random (A, then B twice); B's own prelude then teaches STUN.
  - `auto_imitation_live_retired_callback_at_reused_endpoint_is_dropped` (A → B → A, replacement socket at the retired socket's endpoint). Red: "the retired socket's evidence predates two endpoint changes". Green: no hint; random on the replacement; its prelude teaches STUN.
  - `auto_imitation_live_retired_callback_keeps_tunnel_state`. A learned-STUN peer's authenticated initiation is held across A → B → A. Red: resending it on the current socket got no answer (`WouldBlock`), because the retired callback had consumed it. Green: learned STUN survives, and the same initiation is answered STUN-shaped.
- **Results (final tree):**
  - Live WSL `auto_imitation_live` (7 tests): 7/7 passed serially (three runs) and in parallel (10/10 runs).
  - WSL `cargo test -p boringtun --lib --features device -- --ignored --test-threads=1`: all 61 ignored tests passed. This includes connected-socket lifecycle (`a_retired_connected_handler_reports_teardown_not_a_defect`, `a_connected_recv_error_keeps_the_socket_and_its_handler`, `a_refused_connected_socket_registration_returns_the_peer_to_the_shared_socket`, `a_peer_whose_upgrade_cannot_succeed_does_not_retry_it_per_datagram`), UDP diagnostics site coverage, the kernel ICMP tests and the `test_wg_*` tests.
  - WSL `cargo test --workspace --features device,ffi-bindings,mock-instant`: 652 passed, 0 failed, 61 ignored (+3 live).
  - Windows `cargo test -p boringtun --features ffi-bindings,mock-instant`: 402 passed, 0 failed.
  - Default build: `cargo test -p boringtun --lib auto_imitation` passed 7; `cargo check -p boringtun` showed the same 4 pre-existing warnings.
  - `cargo fmt --all -- --check` and `git diff --check` passed. Linux `cargo clippy --workspace --all-targets --all-features -- -D clippy::incompatible_msrv` exited 0, with the same pre-existing warning locations and none in changed files.
- **Limitations:**
  - A datagram that a socket received just before it was retired is now dropped rather than processed; WireGuard retransmits.
  - The regressions need root and TUN, so they are ignored in the ordinary suite.
  - The test's `127.0.0.2` routing and `/proc/net/udp` wait are Linux-specific.
  - JNI was not rerun because this change is device-only.
  - Not performed: a full Rust 1.75 build (known lockfile limitation), C header probes and the CLI smoke test.
