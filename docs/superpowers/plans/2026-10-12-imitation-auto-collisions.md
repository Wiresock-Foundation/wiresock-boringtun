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

## Deviations and fixture notes

- Test 7 (core slot): once the first initiation has created a session, the recorded bytes' receiver index can name an occupied slot, so the transport reading is refused `WrongIndex` instead of `NoCurrentSession`. Both are allowlisted routing refusals; the helper accepts either and prints the actual outcome. Policy unchanged.
- `is_shaped` is a plain predicate beside the existing asserting `shaped`.
- Device harness: `Roaming::listener` authenticated into a scratch buffer and committed from a second, zeroed one, so an accepted transport could never be delivered. Production authenticates and commits through the one `dst_buf`; the harness now does the same. Needed for the bidirectional plaintext checks; no production change.
- Device harness: `Roaming` records tunnel plaintext from either door (`take_delivered`) and gains `listener_with` (probe responder), `receive` (the decision without a commit), `send` and `has_tunnel_hint`.
