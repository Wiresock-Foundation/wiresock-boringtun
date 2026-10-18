# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- The handshake rate limiter accounts per source as well as in aggregate. A source (an IPv4 address, or an IPv6 /64; never a port) that sends more than its share of the limit in a second -- a fifth, but at least `min(limit, 5)`: 20 of the device's 100 -- is asked for a cookie on its own, and those messages no longer count toward the aggregate, so one flooding address cannot put every peer into cookie mode. Sources that each stay inside their share, as a spoofed flood does, still reach the aggregate limit, which then applies to everyone as before. The per-source counts live in a fixed 16 KiB table indexed by a randomly keyed hash and expire every second on their own.
- The under-load cookie is bound to the source's address and UDP port (whitepaper section 5.4.7) wherever the port is known: the device's listener and connected sockets, and the new `Tunn::decapsulate_from`. A cookie issued to one client behind a NAT no longer validates another client's handshake from the same address. `Tunn::decapsulate(Some(addr))` binds it to the address alone, and a caller with no source (C `wireguard_read`, JNI) still cannot be issued a cookie: under load its handshake messages are refused as `UnderLoad`, as before. The cookie input now tags IPv4, IPv6, address-only and endpoint forms apart; the old encoding zero-padded IPv4 and so gave `a.b.c.d` and `ab:cd::` the same cookie. IPv4-mapped IPv6 sources are treated as the IPv4 address. Cookies outstanding at upgrade are invalidated once; the initiator simply receives a new one.

### Added
- `Tunn::decapsulate_from`, which takes the datagram's whole `SocketAddr`.

### Changed
- Breaking (Rust): `noise::errors::WireGuardError` gains `PacketQueueFull`; exhaustive `match`es need an arm. All discriminants are now explicit and the existing values 0-16 are unchanged; C and JNI callers see the new error as code 17 through the existing `WIREGUARD_ERROR` result, with no ABI change.

### Fixed
- A peer added after the device's private key was set got a private rate limiter (10 a second, its own cookie secret) instead of the device's; its connected socket then rated it apart from the listener, and a cookie the listener issued failed mac2 there. Every peer now shares the device's limiter.
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