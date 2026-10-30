# DPLPMTUD for BoringTun: reviewed proposal

Date: 2026-10-30. Source baseline: `ea0f5f85946ed69fcb0ad2f4dadfb46a672e1c0d` (master, verified against GitHub).

**Status: proposal, not approved for implementation.** The owner requested a plan, independent review, and repository documentation, with DPLPMTUD as the primary mechanism. Neither a wire extension nor deployment to both ends has been approved. The implementation plan is conditional on the decisions below. No runtime change is part of this documentation work.

## Recommendation and decisions for the owner

Build a platform-independent DPLPMTUD controller. For the first complete implementation, recommend an explicitly enabled, authenticated probe/acknowledgment extension between cooperating BoringTun endpoints. Keep legacy peers usable in a separately reported configured-limit mode. OS/ICMP signals can accelerate discovery but are not a prerequisite. Generic keepalives, successful `send`, and received application traffic never confirm a particular outbound size.

The owner must choose before implementation:

1. **Endpoint extension or compatible responder?** Recommended: opt-in endpoint extension, requiring an upgraded peer at both ends. Alternative: unchanged WG/AWG wire format plus a configured, cooperating responder inside the tunnel. The latter needs a service/address/route contract and is not transparent support for arbitrary legacy peers.
2. **Initial product coverage?** Recommended: shared core and additive FFI contract together with Linux CLI as the first fully verified socket adapter. macOS CLI and Windows DLL hosts require their own transport qualification; no promise that all OS versions support the same socket controls. Preserve Rust 1.75 and Windows 7 build compatibility for the core/FFI.
3. **Paths too small for inner IPv6?** Recommended initial scope: explicitly report the affected peer/path as unable to carry inner IPv6 when a 1280-byte inner packet cannot fit. Do not claim transparent IPv6 support there. Supporting those paths would require a separately approved encapsulation fragmentation/reassembly facility or a carefully qualified outer-fragmentation data mode, beyond this proposal.

The exact control carrier, capability format, C ABI, timer defaults, and legacy fallback configuration below are engineering proposals. Approving this document should explicitly resolve these three product choices; it does not implicitly authorize release or rollout.

## Existing code and reusable pieces

Paths and line anchors refer to the baseline above; lines will move during implementation.

| Area | Evidence | Consequence |
| --- | --- | --- |
| Per-call output admission | `boringtun/src/noise/budget.rs:4-116`; `noise/mod.rs:1047-1159` | `OutputBudget` includes S prefixes, content padding and trailers, excludes outer IP/UDP/SOCKS. Mandatory oversize is rejected before nonce/state consumption. Reuse this, not a second size limiter. |
| C surface | `boringtun/src/ffi/mod.rs:2027-2126`; `ffi/packet_info.rs`; `wireguard_ffi.h` | `_ex` calls already convey separate transport/control ceilings; zero is unbounded. They do not discover a path or know the socket result. |
| CLI output | `device/mod.rs:1617,2381`; `device/peer.rs:169` | Timer and encapsulation callers use unbounded wrappers. Receive replies, drains, handshake/junk paths also need an explicit budget audit. |
| Padding MTU | `noise/mod.rs:910`; `ffi/mod.rs:2150-2216`; `device/mod.rs:1080`; `device/tun_linux.rs`, `tun_darwin.rs` | This is the TUN/plaintext padding clamp, not the path UDP limit. Keep the units and settings separate. |
| AWG 3.1 window | `noise/mod.rs:1122-1137,1925-1931`; `device/peer.rs:220-249` | Send-side growth happens before actual UDP send and receive-side growth is inbound. Neither proves outbound PMTU. Preserve AWG compatibility; never promote this window into discovery evidence. |
| Send diagnostics | `device/udp_diagnostics.rs:4-25` | Existing single-attempt boundaries/fault injection are useful. Current errors, including EMSGSIZE, only produce diagnostics and lose the datagram. Keep diagnostic observers free of tunnel mutation. |
| Receive validation | `noise/mod.rs:1559,1668,1915,2283`; `noise/session.rs:334` | Authenticate/replay-check before control dispatch; the current plaintext validator recognizes IP/keepalive, not DPLPMTUD control. |
| Existing probes | `device/probe_reply.rs`, `probe_budget.rs`; `noise/imitation/` | QUIC/DNS/STUN cover traffic and unauthenticated responder budgets are not MTU discovery. Do not feed these replies to the new controller. |

No `AGENTS.md` or `.agents` directory was present in this checkout or its applicable checked workspace ancestors. Existing `docs/superpowers/specs` and `plans` conventions are used.

## Standards basis and limits of inference

[RFC 8899 sections 3-6](https://www.rfc-editor.org/rfc/rfc8899.html#section-3) supplies the framework: explicit size probes with matched feedback, no probe fragmentation, a confirmed working size, search/reconfirmation, and optional validated PTB hints. It does not specify a WireGuard acknowledgment protocol. Its suggested values include three attempts and a 600-second upward recheck; probe timeout must be at least one second, with a preference above 15 seconds. The proposal below chooses a 16-second initial timeout and independently chosen policies for this implementation.

The [WireGuard protocol](https://www.wireguard.com/protocol/) has authenticated transport counters and replay checks but no per-data acknowledgment. An authenticated small return packet establishes neither receipt of a particular large packet nor a symmetric PMTU. All mechanisms below are proposed additions, not claims about upstream behavior.

## Approaches considered

| Approach | What it can establish | Cost / limitation |
| --- | --- | --- |
| **Cooperating endpoint extension (recommended)** | Exact forward UDP size, with a small authenticated ACK; independent discovery in each direction | Both endpoints must implement and explicitly enable it. Requires a reviewed protocol contract and AWG compatibility vectors. |
| Configured in-tunnel request/response service | Receipt of a particular request protected by WG plus application authentication; useful with a legacy WG implementation | Needs a controlled responder at the peer host, allowed IPs, routes, and service deployment. Arbitrary hosts behind the peer measure extra paths. All size-bearing bytes must survive to the responder. |
| Configured limit plus optional OS hints | A bounded operational fallback | Does not discover a size under blocked ICMP and must never be labeled DPLPMTUD or "confirmed". |

For the compatible option, use an application request containing a nonce and requested length, filled to the candidate size, and a small authenticated response. A full-size ICMP echo reply conflates the reverse path with the forward path and is not the default method. TCP ACK observation is not a substitute: inner segmentation, retransmissions and ACK coalescing are not a one-to-one outer UDP receipt. The responder option remains a distinct adapter, not an automatic fallback that probes arbitrary internal addresses.

## Proposed endpoint protocol (decision 1 dependent)

Use the existing encrypted transport envelope and session replay protection; do not repurpose handshake reserved bits, add an unauthenticated UDP echo responder, or borrow WireGuard key material for an ad hoc MAC. Proposed control plaintext has a non-IP discriminator (for example first nibble `0xF`), version, kind, fixed-width length fields, and bounded body. The exact discriminator/encoding is to be frozen with byte-level vectors and a separate protocol/security review in plan task 0. No production code may be written from the example discriminator alone.

* Modes: `disabled` (default, existing behavior), `configured_limit` (explicit safe budget, no discovery claim), `endpoint_v1` (explicit opt-in), and a future separately configured responder adapter. Merely enabling AWG must not enable DPLPMTUD.
* `endpoint_v1` sends capability messages only after an authenticated WG session and explicit per-peer local opt-in. The remote must independently opt in and return an authenticated capability acknowledgment with supported version, receive maximum and nonce. Until this completes, use the configured fallback; do not send padded discovery probes or assume support because traffic continues. Unsupported capabilities expire after three attempts and are retried only on configuration/session restart, not per data packet.
* Proposed message kinds: capability request/ack, padded probe, small probe ack. Never deliver control plaintext to the TUN. Unknown control versions/types are dropped without response. With the feature disabled, preserve the existing plaintext validation behavior.
* Each local path epoch gets a fresh 128-bit random nonce and monotonic 64-bit probe sequence. A pending record binds `(peer identity, path epoch, sending session generation, sequence, target UDP length, wire-profile generation, send handle)`. Only one probe is outstanding per direction. IDs are never reused within the process; a random epoch prevents reuse across restart. Sequence exhaustion rotates the epoch. Retain no unbounded history.
* A receiver ACKs only after AEAD authentication, replay acceptance, complete plaintext structure/length validation, and capability validation. The ACK echoes the epoch nonce, sequence, sending session generation, requested size and **observed original UDP datagram length**. Match all fields to the pending record; validate peer and local path metadata too. Expired, duplicate, wrong-size, old-epoch, wrong-session, wrong-peer and unsolicited replies have no state effect.
* Generate the size-bearing filler inside the authenticated plaintext. For probes, disable random content padding and optional trailers; use a deterministic serializer to reach the requested final size with any mandatory S4 prefix included. Capture UDP length before prefix/trailer removal. Never claim the requested size if a formatter shortened it. Unauthenticated appended bytes, AWG `udp_window`, and an ACK without length matching cannot increase the estimate.
* ACKs use minimal padding and the responder's conservative control ceiling. They never echo the large filler. Accept a small reverse ACK as evidence only for the original forward probe. Each direction has its own controller. A missing ACK is ambiguous (forward loss, reverse loss, outage or MTU); it is never proof of MTU by itself.
* A session change cancels pending requests, repeats capability confirmation and makes cached size tentative for fresh confirmation. Keys/counters are never reused or rolled back. A pre-send budget refusal preserves current no-consumption behavior; an actual send failure occurs after serialization and must not undo cryptographic state.
* Discovery traffic does not mark a peer application-active, indefinitely refresh application-idle state, or cause its own perpetual handshakes. Give it distinct operation metadata and define its WireGuard timer effects alongside keepalive/control semantics in the wire contract. Suppress idle discovery; resumed real traffic triggers revalidation.
* Responses go to the authenticated peer's validated current path. A new authenticated source first follows existing endpoint-adoption rules and starts a new path epoch; a probe from the old path cannot elicit a large response or move new-path discovery. Send at most one small ACK per accepted probe, subject to byte and packet budgets.

## Units, packet shaping, and path identity

The controller stores **`U`: bytes of the complete BoringTun UDP payload**, excluding IP, UDP and any external proxy envelope. This matches `OutputBudget`; do not call it an IP MTU in APIs. Keep distinct types for `UdpPayloadBytes`, `IpPacketBytes`, and `InnerIpBytes`. For a direct path:

`outer_ip_packet_bytes = actual_ip_header_bytes + 8 + U`

For the host-to-SOCKS-relay leg, additionally include the actual SOCKS UDP header (address-family/domain dependent). For the relay-to-peer leg that header is absent. A path description identifies both legs and their policies; subtracting the first-leg header alone is insufficient. Initial support is **direct UDP only**. With SOCKS or another relay, report `unsupported_transport` and use an explicit configured limit unless the owner supplies and qualifies no-fragment behavior for every leg. An endpoint ACK cannot reveal reassembly performed at an invisible relay. A TCP relay exposes stream behavior, not this datagram PMTU.

For ordinary data, compute the maximum inner IP length through the existing serializer/admission arithmetic using `U`, mandatory transport overhead (currently 32 bytes), S4 and the active wire profile. Optional padding/trailers shrink before user data is refused. Do not hardcode "subtract 80", confuse TUN MTU with UDP payload, or subtract headers twice. Probes may use a larger one-shot candidate ceiling than ordinary data, but no other output may inherit it. Apply ceilings to every output producer, including replies, queued drains, keepalives, handshake and imitation/junk. Do not use `ordinary_junk_only` as an escape from a real network ceiling. If a mandatory handshake/imitation item cannot fit, report an incompatible bootstrap profile instead of silently sending over budget or retrying forever. DPLPMTUD cannot fix a session that cannot be established at its bootstrap limit.

Path identity includes peer public identity, endpoint IP/port and address family, local source/socket generation, selected interface/routing generation and fwmark, proxy chain, and wire-profile generation. Keep flow label/DSCP and path-affecting attributes consistent between probes and data. Reset to base on known route/source/endpoint/profile change; do not share a discovered size across peers or unrelated sockets. Where OS route notifications are unavailable, confirmation probes bound stale state. Rekey alone is not physical path evidence, but cancels pending ACK identity as above. Peer deletion/config replacement destroys all discovery state. Socket handover gets a new generation even if the address is unchanged.

## Prevent fragmented probes and cached-PMTU interference

The socket owner must guarantee IPv4 DF and no local fragmentation, IPv6 no source fragmentation, and transmission of candidates above a stale cached PMTU while respecting the local interface limit. Verify these properties with packet capture on each supported adapter. Merely observing a send succeed is insufficient. [Linux `ip(7)`](https://man7.org/linux/man-pages/man7/ip.7.html) documents `IP_PMTUDISC_PROBE` as DF plus ignoring cached PMTU for probing; Linux IPv6 behavior and Windows/macOS equivalents need adapter-specific qualification, including shared and connected sockets. Do not globally change network settings or toggle a shared socket around one send with a race.

No UDP segmentation/coalescing or GSO may turn a nominal probe into several smaller datagrams. Receive truncation invalidates the sample. If transport cannot guarantee these properties, discovery stays disabled with a reason; a fragmented-delivery result cannot be called a larger confirmed size. Capture establishes host behavior, not a universal claim about hidden networks. Repeated inconsistent size outcomes trigger conservative operation and diagnostics.

## Controller proposal

Pure state machine: injected monotonic time and random epoch, events in, bounded actions out. It owns no sockets, TUN descriptors, OS-specific errno interpretation, threads, global route changes or unsafe platform code. The transport adapter is responsible for supplying truthful, path-bound evidence.

Proposed default profile, subject to task-0 approval and measurement:

| Setting | Proposed value / rule |
| --- | --- |
| Initial direct IPv4 base U | 1200; recovery floor 548 unless mandatory control needs more. Neither is universally guaranteed on IPv4. |
| Direct IPv6 minimum/base U | `1280 - actual IPv6 headers - 8` (1232 for a 40-byte header); do not silently probe below it. |
| Upper search bound | Minimum of local interface allowance, configured maximum, known peer receive maximum and serializer/buffer limit. Default deployment cap is a 1500-byte outer packet; no jumbo promise. |
| Probe timeout T | Initially 16 s; after unambiguous RTT samples, `max(16 s, 3 * SRTT)`. Exponential backoff in outage; no fixed 1 s aggressive profile. |
| Attempts | Three actually sent attempts per candidate, each with a fresh ID. Backpressure does not consume an attempt. |
| Confirmation | Every 30 s while active; after inactivity >=30 s, reconfirm before resuming use of a cached size above base. |
| Upward rediscovery | Every 600 s while active; jitter deadlines by 0-10% without shortening the minimum. |
| Search granularity | 8 bytes; stop with confirmed lower bound within 7 bytes of effective ceiling. Never round an upper bound upward. |
| Resource limits | One pending probe and one scheduled candidate per peer; at most one initiated probe per `max(1 s, SRTT)`, global 10 probes/s and 16 KiB/s (bursts 10 packets/16 KiB), fair round-robin scheduling. ACKs: per-peer 2/s, burst 2; global 100/s and 64 KiB/s, burst 100 packets/64 KiB. |

All arithmetic is checked. Invalid bounds (base below protocol minimum, maximum below minimum/mandatory frame, unsupported header sizes) yield explicit configuration errors; zero must not accidentally map to `OutputBudget::UNBOUNDED`.

Distinguish the configured initial base from the **recovery target**. On the same path, the recovery target is the minimum of configured base, last confirmed U (if any), and the current hard cap. Recovery, stale-evidence expiry, idle resume and rekey must never increase the operational ceiling. If a smaller IPv4 size has been confirmed, use that size for recovery, not the original 1200. A new path discards old path evidence and starts at its own provisional base. A hard cap below the minimum/mandatory frame means unavailable, not a zero/unbounded budget. In the transitions below, BASE uses this recovery target after a failure and the initial base only for a genuinely new path.

For a new path, clamp the actual initial probe/provisional budget to the current maximum bound: `initial_target = min(configured_base, current_maximum)`. If this is below the selected family's minimum or mandatory control-frame length, fail activation explicitly. Thus an IPv4 maximum U=1000 starts at 1000, not an impossible 1200. Its failure can still reach the 548-byte recovery floor when that floor can carry control. A maximum below the floor is unavailable under this profile; lower IPv4 floors require a separate explicit configuration. Re-evaluate this rule when a capability supplies a smaller receive maximum.

States and transitions:

| State | Event | Result |
| --- | --- | --- |
| DISABLED / LEGACY | No opt-in/capability/qualified transport | No active discovery; report configured or unknown size, not confirmed. |
| BASE | Matching base probe ACK | Mark that size confirmed; enter SEARCH. Before confirmation, report only the configured provisional budget. |
| BASE | Three base attempts expire | IPv4: try the configured recovery floor once as a new three-attempt cycle. IPv6: no below-minimum rescue. If no floor ACK, ERROR. This is connectivity failure, not a discovered tiny MTU. |
| SEARCH | Matching candidate ACK | Raise confirmed lower bound to exact candidate; continue within upper bound. |
| SEARCH | Three candidate attempts expire | Keep the lower working size; reconfirm it. Only after that succeeds bound this search epoch below the failed candidate and continue. If lower confirmation fails, enter recovery rather than blaming the candidate alone. |
| SEARCH | No gap >=8 bytes | COMPLETE; preserve confirmed lower size and schedule confirmation/raise timers. |
| COMPLETE | Confirmation ACK | Renew confirmation age. Small unrelated traffic never renews size evidence. |
| COMPLETE | Three full-size confirmations expire | Set operational ceiling to recovery target (label provisional), cancel larger pending work and enter BASE; never raise the limit or keep sending at the suspect size. |
| Any active | Validated path-specific PTB/local hard size refusal | Cancel impossible candidate and schedule smaller confirmation. Never raise from a hint or label the hinted size confirmed. A local interface hard cap updates the bound; a cached route error must not become a permanent ceiling. |
| ERROR | Base/floor retry succeeds | Resume SEARCH from newly confirmed size. Otherwise back off 16, 32, 64, 128, 256, 600 s (cap); report unconfirmed/unavailable status. |
| Any | Path/profile generation changes | Cancel pending sends and ACK identities, clear path-derived bounds, BASE at new conservative profile. |

Proposed search: first probe the bounded maximum after base success; if unsuccessful after the above lower-bound reconfirmation, binary search the remaining interval on the 8-byte grid. A failed candidate gives only a temporary search bound, not a permanent physical MTU assertion. Reset failed upper bounds on the raise timer or a path change. Repeated contradictions (larger success then smaller failure) suspend upward search for 600 s and recover from base. Global scheduler deferral is visible and is excluded from RTT/loss accounting.

Every confirmed size has an evidence deadline in **SEARCH as well as COMPLETE**, measured from its latest matching full-size or larger successful probe ACK. Schedule reconfirmation 30 s plus jitter after that evidence. Capability exchange, rekey, small inbound packets and failed upward candidates do not extend it. When reconfirmation becomes due, start no new upward candidate. An already accepted candidate may finish its current attempt only if its timeout is no later than the evidence-expiry deadline (confirmation due + 3T); otherwise cancel it. Cancel any upward request not yet accepted. Then prioritize the current-size confirmation and resume search after it succeeds. At the evidence-expiry deadline, cancel any remaining candidate and apply fallback, irrespective of attempt count. Carry the evidence deadline across rekey, even while capability confirmation is pending. Thus perpetual search/rekey cannot keep a black-holed high limit alive.

Preserve completed timeouts for the same candidate within the current path/search epoch across inserted maintenance confirmations and rekey. A canceled attempt contributes no failure; a successful lower-size confirmation does not reset the larger candidate's failure count. A matching candidate ACK succeeds and clears its failures; an actual path change or new upward-search epoch clears the old candidate history. This avoids restarting forever at the too-large maximum when confirmation interleaves the three-attempt search. Keep only this one candidate's bounded progress alongside the one pending probe.

Handing a probe to `WriteToNetwork` does not start its network timer. Track planned, serialized and locally accepted states. Start timeout only on matching `Sent`; a reply racing the send completion is retained in one bounded pending slot and applied only after matching acceptance. `WouldBlock` is local backpressure; a refused/abandoned buffer is not packet loss. Unknown completion expires as `send_outcome_unknown` and cannot confirm PMTU. Ordinary packets are never retransmitted by this controller. Recovered MTU does not imply recovery of already lost application data.

Bound local pending work separately: cancel an unsent/unknown probe after T, and retry only when the adapter becomes writable or the fair scheduler grants a turn. Do not interpret cancellation as path loss. If a due confirmation cannot complete within `3T` after its scheduled deadline, expire the size evidence and use the provisional recovery ceiling with reason `confirmation_deferred`; report scheduler pressure separately from MTU failure. This bounds stale high limits even when many peers exceed the global probe budget. Qualification must measure how many active peers the chosen budget can sustain; do not promise a 30-second confirmation cadence for 1000 peers under a 10-probes/s cap.

Time origins and precedence are explicit: local-work T starts when `ProbeRequest` is emitted; network T starts at the adapter-reported actual acceptance timestamp, checked to lie between request time and event time. A late completion never restarts an expired request. A deadline is expired at `now >= deadline`. Process path/session invalidation and expired deadlines before applying ACK/send events with that timestamp; an ACK received exactly at expiry cannot revive the old request. Evidence-lease expiry can precede a third network timeout because of scheduling/pacing; record `evidence_expired` rather than inventing a third loss. Preserve the last size value for recovery arithmetic after its confirmed status expires. Define and test this ordering in the task-0 API contract.

A one-way application still sends maintenance probes; the remote control responder works without reverse application traffic. If the reverse ACK path is unavailable, size remains unconfirmed or falls back: there is no claim of reliable discovery without any return channel. Random loss may yield a temporarily smaller working size; it must not produce unbounded descent or retry storms.

## Core, CLI and FFI ownership

Proposed modules: `boringtun/src/pmtu/{mod.rs,controller.rs,types.rs,tests.rs}` for the pure controller, `pmtu/inner.rs` for portable inner-packet parsing, feedback serialization and IPv4 fragment generation, `noise/pmtu_control.rs` for the selected protocol, and `device/{pmtu.rs,pmtu_socket.rs,inner_mtu.rs}` for orchestration, socket policy and local feedback injection. The pure inner helpers have no Device feature/Unix dependency; both Windows FFI and Device reuse them with supplied address/context. These are proposed files, not existing features.

* `Tunn` still owns cryptographic/session state and wire encoding. A separate per-peer controller owns path estimates and pending probes. Reuse bounded noise calls; expose a deliberate bounded Rust surface if consumers outside the crate need it. Keep legacy APIs unchanged by default.
* Device coordinates the controller and output budgets across TUN reads, timer ticks, receive-generated replies and queue drains. Feed actual send results from the existing boundary to the orchestrator; preserve diagnostic observer purity. Audit shared-listener and connected-socket transitions atomically under the existing peer lock.
* FFI host owns routing identity, address-family/header/proxy overhead, no-fragment socket behavior, clocks/scheduling, actual send completion and injecting inner feedback. It supplies valid local source-address context and consumes packets/fragments from the portable helper through the additive API; it does not need to link the Unix Device layer or duplicate packet parsers. It may supply opaque path-generation tokens, but cannot simply mark an unauthenticated received packet as an ACK. The library verifies control plaintext and matching identity.
* The host retains original inner packet bytes until the call has returned a fitting output or produced the required feedback/fragment iteration. Any longer-lived quote is an explicitly bounded copy with an owned lifetime; no raw borrowed pointer survives a call. The host owns output storage and injection, with no success claim until it handles the result. Freeze cancellation and partial-fragment-drain semantics in task 0.
* Use new opt-in entry points and versioned `struct_size` records for configuration, poll/event input, status and output/send handles. Do not enlarge old structs in place, renumber existing operation/error enums, or reinterpret old `_ex` ceilings. Existing `_ex` budgets remain hard caller caps; effective cap is the minimum of the host cap and controller cap, with a separately authorized candidate cap only for probes. Callers draining output must obtain a fresh cap for every call.
* FFI must distinguish `oversized_inner(required, allowed)`, `bootstrap_profile_too_large`, `transport_not_qualified`, `no_return_evidence`, and `send_outcome_unknown`. Host-side ability to handle these is part of enabling the feature, not an optional log message. No callback into a host while holding a tunnel lock; poll/action APIs should retain current ownership discipline.

## Oversized inner traffic is part of delivery

Calculate per-peer effective inner MPS before encryption. Never silently truncate. Keep a bounded quote of the original packet for local feedback; never reconstruct plaintext from a failed ciphertext. Update the next packet's limit immediately when the controller reduces its operational ceiling. Do not change one global TUN MTU on behalf of one small peer.

* IPv4 DF=1: produce correctly checksummed ICMP Destination Unreachable / fragmentation-needed with the effective inner next-hop MTU, quote the triggering packet, inject toward its source. See [RFC 1191 section 4](https://www.rfc-editor.org/rfc/rfc1191.html#section-4).
* IPv4 DF=0: recommended initial adapter behavior is bounded **inner IPv4 fragmentation before encryption**, following header/options/offset/MF/checksum rules, with reassembly by the final IP destination. This is not outer probe fragmentation. If a host cannot provide this, it must explicitly reject this feature combination and expose the drop reason; it cannot advertise transparent DF=0 support. Do not invent a second tunnel fragmentation protocol.
* IPv6: never fragment a forwarded inner packet in the tunnel router. When effective inner MPS >=1280, inject ICMPv6 Packet Too Big with that MPS, valid pseudoheader checksum and bounded quote, following [RFC 4443 sections 2.2-2.4 and 3.2](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.2). At MPS <1280, follow owner decision 3: signal unsupported inner-IPv6 path to the host/control plane, do not set TUN MTU below 1280 or imply that merely advertising a smaller MTU resolves the encapsulation problem. IPv6 minimum-link requirements are in [RFC 8200 section 5](https://www.rfc-editor.org/rfc/rfc8200.html#section-5).

Feedback suppression must implement the protocol-specific rules (errors responding to errors, source validity, fragment restrictions, and the ICMPv6 PTB multicast exception), rather than one blanket multicast drop rule. Choose a valid local source address in Device/host context, never fabricate a remote router identity. Rate-limit generated feedback per peer/source and globally; use 10 packets/s per peer and 100 packets/s globally with the same one-second burst allowance as an initial proposal. Malformed inner headers produce no response. Do not create recursive feedback loops. The [tunnel MTU analysis in RFC 4459](https://www.rfc-editor.org/rfc/rfc4459.html) motivates treating packetization and inner feedback as part of the implementation, not just measuring a number.

## Observability and qualification

Expose state/mode, path generation, transport qualification, provisional versus confirmed U, effective inner MPS, upper bound and its provenance, last confirmation age, next deadline, attempt count, send failures/unknowns, valid/ignored ACK counts, reason for a change and IPv6 unsupported status. Aggregate per-peer counters; log state transitions with throttling. Do not log keys, plaintext, raw probe nonces or arbitrary endpoint labels at high cardinality. A successful local send must remain labeled local acceptance.

Deterministic tests use fake time, fixed epoch seeds, scripted packet loss/reordering and socket outcomes; no sleeps, root, network or wall-clock dependence. Integration tests need independent real endpoints and packet capture, plus tests against unmodified WG/AWG peers. Specific cases and quantitative acceptance criteria are in the [implementation plan](../plans/2026-10-30-dplpmtud.md).

## Delivery and review

Order: owner decisions / frozen protocol contract; pure controller; exact-size authenticated codec and budgets; inner feedback; qualified Linux adapter; additive FFI contract and host examples; cross-platform/legacy/security qualification. Work may be split into independently reviewed PRs, but the public claim "DPLPMTUD supported" waits for blocked-ICMP end-to-end tests and inner packet feedback. ICMP ingestion is an optional later optimization, not phase one of the algorithm.

Review findings, resolutions and documentation checks are recorded in [the review record](2026-10-30-dplpmtud-review.md). No implementation, privileged network test, push, PR, release, merge or deployment is authorized by this proposal.
