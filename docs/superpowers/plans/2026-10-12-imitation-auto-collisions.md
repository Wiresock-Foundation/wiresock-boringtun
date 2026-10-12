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
- `is_shaped` is a plain predicate beside the existing asserting `shaped`.
- Device harness: `Roaming::listener` authenticated into a scratch buffer and committed from a second, zeroed one, so an accepted transport could never be delivered. Production authenticates and commits through the one `dst_buf`; the harness now does the same. Needed for the bidirectional plaintext checks; no production change.
- Device harness: `Roaming` records tunnel plaintext from either door (`take_delivered`) and gains `listener_with` (probe responder), `receive` (the decision without a commit), `send` and `has_tunnel_hint`.
- Live harness: the device's writes to its TUN are not otherwise observable, so "plaintext both ways" uses a new AF_PACKET capture (`TunCapture`) for client to device and the existing `TunInjector` for device to client; `exchange` brings the link up first. `AutoClient` now always configures an allowed IP for itself, so the device has a route for it.
- Test 19 is `auto_imitation_live_fixed_mode_colliding_request_stays_silent`; tests 16 and 18 also run their no-prelude and control cases inside the one test.
