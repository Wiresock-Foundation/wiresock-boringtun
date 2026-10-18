# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Breaking (Rust): `noise::errors::WireGuardError` gains `PacketQueueFull`; exhaustive `match`es need an arm. All discriminants are now explicit and the existing values 0-16 are unchanged; C and JNI callers see the new error as code 17 through the existing `WIREGUARD_ERROR` result, with no ABI change.

### Fixed
- Timers follow the Linux and wireguard-go (and amneziawg-go) state machine:
  - The passive keepalive is owed only to received *data* -- a received keepalive no longer arms it -- and is due `KEEPALIVE_TIMEOUT` after that data, not after whatever was last sent, so a tunnel idle for minutes no longer answers the first packet at once.
  - The new-handshake deadline (`KEEPALIVE_TIMEOUT + REKEY_TIMEOUT`) is armed only by sent data, and runs from that send rather than from the last packet received, so the first packet after a quiet spell no longer starts a handshake at once.
  - The persistent keepalive is due one interval after the last authenticated packet in either direction, so it is no longer sent while traffic flows.
  - A persistent keepalive is sent at the first timer tick when the interval is configured at construction or turned on later (not when an existing interval changes), instead of one full interval later. Without a session this starts the handshake, as in Linux and wireguard-go.
  - Handshake retransmissions and the new-handshake deadline carry 0-333 ms of jitter, on top of a configured AmneziaWG range as amneziawg-go adds it; the untuned 90-second absolute bound is widened by the most that jitter can add over its retransmissions (to about 96 s), so the attempt count still ends the cycle.
  - A clock that steps backwards no longer underflows the timer arithmetic, which panicked (and aborted the process under the C and JNI bindings).
- The anti-replay window holds 8192 counters instead of 1024, as in Linux and wireguard-go, so more reordering is tolerated before legitimate packets are dropped. This costs 7 KiB more per tunnel (eight session slots).
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