# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- A cookie reply no longer moves the peer's endpoint. Its key is derived from the peer's public key and it is bound only to the mac1 of our last handshake message, which is sent in clear, so anyone who observed that message could send a valid reply from another address and redirect the peer's traffic and connected socket there. Authenticated handshake and transport packets still roam, as in Linux and wireguard-go.
- A cookie reply is accepted once per handshake message we send, as in Linux and wireguard-go; a captured reply can no longer be replayed. A second copy is refused with `UnexpectedPacket` (C/JNI: `WIREGUARD_ERROR`, code 2) where it used to return `Done`; like any refused datagram, it can be dropped.
- The Reject-After-Messages limit (2^64 - 2^13 - 1) is enforced on both directions. A session whose sending counter reaches it is not used again: the write is queued and a handshake is started, so the AEAD nonce cannot repeat even if the session timers never fire. A received counter at or above it is refused as `InvalidCounter` before decryption (a forged frame carrying one was `InvalidAeadTag`). Rekey-After-Messages (2^60), which would rekey well before that, is still not implemented; it is practically unreachable within Reject-After-Time.

### Changed
- Breaking (Rust): `noise::errors::WireGuardError` gains `PacketQueueFull`; exhaustive `match`es need an arm. All discriminants are now explicit and the existing values 0-16 are unchanged; C and JNI callers see the new error as code 17 through the existing `WIREGUARD_ERROR` result, with no ABI change.

### Fixed
- A cookie reply no longer counts as a received packet for the timers, so it cannot defer the new-handshake attempt that follows unanswered traffic.
- A decapsulated IPv4 packet whose IHL is below 5, or whose total length does not cover the header length IHL declares, is refused as `InvalidPacket` instead of being delivered shorter than its own header. Fragments and header checksums are still passed through unchanged to the receiving stack.
- `Tunn::encapsulate` / `wireguard_write` without a session no longer queue the packet when they return an error, so retrying after `DestinationBufferTooSmall` cannot deliver it twice; the handshake-initiation capacity (148 bytes plus S1) and the junk-packet maximum are checked before any handshake state changes.
- A full queue of packets waiting for a handshake is reported as `PacketQueueFull` instead of a silent drop reported as `Done`.
- Draining queued packets (`decapsulate` with an empty datagram / `wireguard_read` with size 0) no longer re-admits them: without a session the queue is left as it is, and with a session a packet that does not fit stays at the head and the call reports `DestinationBufferTooSmall` instead of `Done`.
- A pending pre-handshake burst no longer suspends the absolute handshake and key-lifetime bounds, so a destination buffer that never fits cannot keep queued packets alive indefinitely.
- Auto imitation learns from a recognizable prelude whose bytes also fit an AmneziaWG packet shape (such as a STUN request whose bytes at S4 fall in H4) when every reading of it is refused with `InvalidMac`, `WrongKey`, `WrongIndex`, `NoCurrentSession`, `UnexpectedPacket` or `InvalidAeadTag`, on the device listener and in `Tunn::decapsulate` alike. Previously such a client stayed unresolved with random padding. The reported error, fixed modes, probe replies (none for these datagrams), hint lifetimes and source binding are unchanged; any other refusal, an accepted packet, and cookie or load dispositions record nothing.

## [0.7.1] - 2026-05-01

### Security
- use a 64-bit nonce counter on 32-bit platforms to avoid the possibility of nonce re-use with large REKEY_AFTER_TIME
- CLI only: remove vulnerable dependency: `atty`

### Fixed
- use portable-atomic to support targets without native 64-bit atomics

## [0.7.0] - 2026-01-09

### Changes

- Breaking: make `noise::Tunn::new` infallible
- Upgrade vulnerable dependencies: ring, x25519-dalek
- Fix a compilation error on freebsd
- Fix incorrect socket type in `device::Peer::connect_endpoint`