// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! AmneziaWG 3.1 RandomTrailers, end to end through `Tunn`: the per-tunnel UDP
//! window, transport padding inside the AEAD, trailer-extended handshake
//! messages on both sides of the wire, and the cookie reply's bounded trailer.
//!
//! The arithmetic helpers have their own unit tests in `amnezia`; these drive
//! real handshakes and real ciphertext, so what they pin is what a peer sees.

use super::amnezia::{AmneziaConfig, DEFAULT_UDP_WINDOW};
use super::errors::WireGuardError;
use super::inbound::fixtures::*;
use super::{Tunn, TunnResult};

const KEY: [u8; 32] = [0x5a; 32];

/// An IPv4 packet of exactly `len` bytes whose total-length field says so.
fn ipv4_packet(len: usize) -> Vec<u8> {
    assert!(len >= 20);
    let mut packet = vec![0u8; len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
    packet
}

/// A handshaken pair under `amnezia`.
fn connected(amnezia: &AmneziaConfig) -> (Tunn, Tunn) {
    let (mut mine, mut theirs) = pair(amnezia, None);
    handshake(&mut mine, &mut theirs);
    (mine, theirs)
}

fn delivered(result: TunnResult) -> Vec<u8> {
    match result {
        TunnResult::WriteToTunnelV4(p, _) => p.to_vec(),
        other => panic!("expected a delivered packet, got {:?}", other),
    }
}

fn keys() -> [Option<[u8; 32]>; 2] {
    [None, Some(KEY)]
}

/// Every tunnel starts at the default window, whatever its configuration.
#[test]
fn a_tunnel_starts_at_the_default_window() {
    for rt in [false, true] {
        let (mine, theirs) = pair(&colliding(None).with_random_trailers(rt), None);
        assert_eq!(mine.udp_window(), DEFAULT_UDP_WINDOW);
        assert_eq!(theirs.udp_window(), DEFAULT_UDP_WINDOW);
    }
}

/// Sending a transport frame grows the sender's window to the frame's unpadded
/// wire size, and receiving it grows the receiver's to sixteen bytes less than
/// the padded datagram -- the reference's receive measure, pinned end to end.
/// Observed with RandomTrailers off as well, so turning it on later draws
/// against what the tunnel has already carried.
#[test]
fn transport_grows_each_end_by_the_reference_measures() {
    for rt in [false, true] {
        let amnezia = colliding(None).with_random_trailers(rt);
        let (mut mine, mut theirs) = connected(&amnezia);
        let packet = ipv4_packet(1000);
        let mut buf = vec![0u8; 4096];
        let wire = network(mine.encapsulate(&packet, &mut buf));

        assert_eq!(
            mine.udp_window(),
            (DATA_AT + 32 + 1000) as u32,
            "rt={}: S4 + 32 + the unpadded plaintext",
            rt
        );
        let mut out = vec![0u8; 4096];
        assert_eq!(delivered(theirs.decapsulate(SRC, &wire, &mut out)), packet);
        assert_eq!(
            theirs.udp_window(),
            (wire.len() - 16) as u32,
            "rt={}: S4 + 16 + the padded plaintext, the AEAD tag not counted",
            rt
        );
    }
}

/// Nothing unauthenticated grows the window: not a forged transport frame, and
/// not a datagram that is merely large.
#[test]
fn only_authenticated_transport_grows_the_window() {
    for key in keys() {
        let amnezia = colliding(key).with_random_trailers(true);
        let (mut mine, mut theirs) = connected(&amnezia);
        let before = theirs.udp_window();
        let mut buf = vec![0u8; 4096];
        let mut forged = network(mine.encapsulate(&ipv4_packet(1200), &mut buf));
        *forged.last_mut().unwrap() ^= 1;
        let mut out = vec![0u8; 4096];
        assert!(matches!(
            theirs.decapsulate(SRC, &forged, &mut out),
            TunnResult::Err(WireGuardError::InvalidAeadTag)
        ));
        assert!(matches!(
            theirs.decapsulate(SRC, &[0x77; 1400], &mut out),
            TunnResult::Err(_)
        ));
        assert_eq!(theirs.udp_window(), before);
    }
}

/// One tunnel's traffic does not widen another's window.
#[test]
fn the_window_is_per_tunnel() {
    let amnezia = colliding(None).with_random_trailers(true);
    let (mut a, mut b) = connected(&amnezia);
    let (c, d) = connected(&amnezia);
    let mut buf = vec![0u8; 4096];
    let wire = network(a.encapsulate(&ipv4_packet(1300), &mut buf));
    delivered(b.decapsulate(SRC, &wire, &mut vec![0u8; 4096]));
    assert!(a.udp_window() > DEFAULT_UDP_WINDOW);
    assert!(b.udp_window() > DEFAULT_UDP_WINDOW);
    assert_eq!(c.udp_window(), DEFAULT_UDP_WINDOW);
    assert_eq!(d.udp_window(), DEFAULT_UDP_WINDOW);
}

/// With RandomTrailers on, transport grows only inside its AEAD: every frame
/// is at most the window, carries its packet intact, and a byte appended after
/// the tag is a forgery, not a trailer.
#[test]
fn transport_trailers_are_padding_inside_the_aead() {
    for key in keys() {
        let amnezia = colliding(key).with_random_trailers(true);
        let (mut mine, mut theirs) = connected(&amnezia);
        let mut sizes = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let packet = ipv4_packet(60);
            let mut buf = vec![0u8; 4096];
            let wire = network(mine.encapsulate(&packet, &mut buf));
            assert!(wire.len() <= mine.udp_window() as usize);
            sizes.insert(wire.len());
            let mut out = vec![0u8; 4096];
            assert_eq!(delivered(theirs.decapsulate(SRC, &wire, &mut out)), packet);
        }
        assert!(sizes.len() > 8, "the addition must vary: {:?}", sizes);

        let mut buf = vec![0u8; 4096];
        let mut extended = network(mine.encapsulate(&ipv4_packet(60), &mut buf));
        extended.extend_from_slice(&[0u8; 7]);
        assert!(matches!(
            theirs.decapsulate(SRC, &extended, &mut vec![0u8; 4096]),
            TunnResult::Err(WireGuardError::InvalidAeadTag)
        ));
    }
}

/// A keepalive under RandomTrailers is padded like any frame and still read as
/// a keepalive; an empty one is observed too.
#[test]
fn a_padded_keepalive_is_still_a_keepalive() {
    let amnezia = colliding(None).with_random_trailers(true);
    let (mut mine, mut theirs) = connected(&amnezia);
    let mut saw_padding = false;
    for _ in 0..32 {
        let mut buf = vec![0u8; 4096];
        let wire = network(mine.encapsulate(&[], &mut buf));
        saw_padding |= wire.len() > DATA_AT + 32;
        assert!(wire.len() <= DEFAULT_UDP_WINDOW as usize);
        assert!(matches!(
            theirs.decapsulate(SRC, &wire, &mut vec![0u8; 4096]),
            TunnResult::Done
        ));
    }
    assert!(saw_padding, "keepalives must draw padding too");
}

/// Turning RandomTrailers on or off on a live tunnel changes framing only: the
/// session carries on, and so does the window.
#[test]
fn toggling_random_trailers_keeps_the_session_and_the_window() {
    let off = colliding(Some(KEY));
    let (mut mine, mut theirs) = connected(&off);
    let mut buf = vec![0u8; 4096];
    let wire = network(mine.encapsulate(&ipv4_packet(900), &mut buf));
    delivered(theirs.decapsulate(SRC, &wire, &mut vec![0u8; 4096]));
    let (mine_window, their_window) = (mine.udp_window(), theirs.udp_window());

    for rt in [true, false, true] {
        let cfg = off.clone().with_random_trailers(rt);
        let obf = mine.handshake.obf;
        mine.set_obfuscation(obf, cfg.clone());
        theirs.set_obfuscation(obf, cfg);
        assert_eq!(mine.udp_window(), mine_window);
        assert_eq!(theirs.udp_window(), their_window);
        let packet = ipv4_packet(80);
        let wire = network(mine.encapsulate(&packet, &mut buf));
        assert_eq!(
            delivered(theirs.decapsulate(SRC, &wire, &mut vec![0u8; 4096])),
            packet,
            "rt={}: the session must survive the toggle",
            rt
        );
    }
}
