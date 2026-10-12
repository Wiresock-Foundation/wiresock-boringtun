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

## Deviations and fixture notes

- Test 7 (core slot): once the first initiation has created a session, the recorded bytes' receiver index can name an occupied slot, so the transport reading is refused `WrongIndex` instead of `NoCurrentSession`. Both are allowlisted routing refusals; the helper accepts either and prints the actual outcome. Policy unchanged.
- `is_shaped` is a plain predicate beside the existing asserting `shaped`.
