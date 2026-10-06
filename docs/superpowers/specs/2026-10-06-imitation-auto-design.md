# Server imitation auto mode

The server must support concurrent clients using different imitation protocols on one listener. Add the opt-in `auto` protocol (numeric value 5); preserve values 0–4 and fixed-mode behavior. Existing S1–S4, H1–H4, keys and padding settings remain explicitly configured.

## Behavior

Recognize the existing DNS, QUIC, SIP and STUN pre-handshake datagrams. Keep the first recognized hint per source IP and UDP port for 30 seconds, with at most 1024 unverified sources per device. At capacity, evict the oldest hint. Repeated packets do not extend a hint's lifetime. Hints are camouflage metadata, not proof of identity: the outer imitation bytes are not authenticated.

On an authenticated initiation, use the source's live hint (or the datagram's recognized complete protocol shape) to choose outbound imitation for that peer before formatting its response. Pin this choice for the peer's lifetime in auto mode; unsolicited packets cannot repin it. Keep it across endpoint roaming and unrelated configuration updates. Clear it when entering or leaving auto, changing the local private key, or replacing the peer. Failed commit must not pin a mode. Without recognizable evidence, use ordinary random S padding and remain unresolved; do not guess QUIC from a random short-header byte. Auto sends no standalone pre-handshake burst, even if Jc is configured.

The core `Tunn` supports the same behavior for embedders and connected sockets, remembering one temporary hint for its peer, bound to the optional source IP supplied by the caller. A caller multiplexing sources must route each source to the appropriate tunnel. Device hints are scoped to full SocketAddr, shared across workers and both listeners, consumed after successful selection, and cleared on peer removal or framing configuration changes.

Auto probe replies use the detected protocol and existing reply budget and source checks. SIP remains silent, as today. AmneziaWG classification still precedes all probe handling. Cookie replies may use a temporary hint for shaping but never promote it to peer state and retain all existing amplification checks.

Header-protection policy remains binding: a learned SIP mode incompatible with configured prefix sizes is not activated; the tunnel stays unresolved with random padding and logs the refusal once per tunnel. DNS/STUN warnings are reported when learned and when a live update enables header protection. No header-protection setting or cryptographic parameter is weakened automatically. Rust/C Auto ignores an imitation domain and browser profile; the CLI rejects an explicit domain with Auto. Learned responder prefixes use the existing generated-domain defaults.

## Scope and validation

Add CLI/env, Rust and C/JNI numeric-enum support without changing the C struct layout. Document use and the need for recognizable prelude packets (especially QUIC/STUN with small prefixes). Verify real handshakes and bidirectional data for all four protocols, fixed-mode stability, independent peers including identical IP/different ports, forged inputs, expiry/eviction, roaming, live updates, cookie replies, and header-protection refusal. Use Rust 1.75-compatible APIs and no new dependencies. Run Linux device tests under WSL plus Windows library/FFI tests, formatting, clippy, and C header checks.
