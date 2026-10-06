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
