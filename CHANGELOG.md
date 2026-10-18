# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Breaking (Rust): `noise::errors::WireGuardError` gains `PacketQueueFull`; exhaustive `match`es need an arm. All discriminants are now explicit and the existing values 0-16 are unchanged; C and JNI callers see the new error as code 17 through the existing `WIREGUARD_ERROR` result, with no ABI change.

### Fixed
- The device starts, and keeps running, on a host without IPv6 (a kernel booted with `ipv6.disable=1`, built without IPv6, or a sandbox refusing the family): only an IPv6 `socket()` refused for its family is taken as that, and the device then listens on IPv4 alone and logs a warning. It used to fail to start with `EAFNOSUPPORT`, and a `listen_port=` set failed the same way. Every other IPv6 failure still fails the bind as a whole, as before. Without an IPv6 listener, a send to an IPv6 endpoint fails as `EAFNOSUPPORT` and is reported through the usual UDP send diagnostics.
- The UAPI socket is bound at `/var/run/wireguard/<name>.sock`, and the AmneziaWG symlink at `/var/run/amneziawg/<name>.sock` points there, without a doubled `/` in either path; the kernel reported the doubled form as the socket's bound name, which broke exact-path lookups such as `lsof` and `ss -x`.
- A zero-length UDP datagram arriving on a peer's connected socket is ignored. It was passed to `Tunn::decapsulate`, which reads an empty datagram as its caller's request to drain the tunnel, so anyone able to forge the 4-tuple could release queued packets, advance a pending Jc or imitation burst, or start the handshake the queue was waiting for. The C/JNI `wireguard_read` keeps its documented `src_size == 0` drain.
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