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
use std::convert::TryInto;

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

/// A new initiation from `tunn`, with the clock moved on first.
///
/// A responder refuses an initiation whose TAI64N timestamp is not newer than
/// the last it accepted -- replay protection -- and under `mock-instant` the
/// clock only moves when told to, so back-to-back initiations would carry the
/// same timestamp and all but the first would be refused as replays.
fn fresh_initiation(tunn: &mut Tunn, buf: &mut [u8]) -> Vec<u8> {
    #[cfg(feature = "mock-instant")]
    mock_instant::thread_local::MockClock::advance(std::time::Duration::from_millis(5));
    network(tunn.format_handshake_initiation(buf, true))
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

/// S1..S4 chosen unequal, so a response's whole 92-byte core fits inside a
/// transport packet's junk prefix (24 + 92 <= 160): a false response can be
/// written in full -- correct receiver index, valid mac1 -- ahead of a genuine
/// transport packet. Exact 3.0 sizes never allowed that, because every
/// handshake reading then ended at the datagram's end, on the genuine
/// packet's own bytes.
const UNEQUAL: [u16; 4] = [40, 24, 32, 160];

fn unequal(key: Option<[u8; 32]>) -> AmneziaConfig {
    let amnezia = AmneziaConfig::new(UNEQUAL[0], UNEQUAL[1], UNEQUAL[2], UNEQUAL[3])
        .with_random_trailers(true);
    match key {
        Some(key) => amnezia.with_header_protection(key),
        None => amnezia,
    }
}

/// The sender index a handshake datagram carries, read through its first
/// candidate.
fn sender_idx(tunn: &Tunn, wire: &[u8]) -> u32 {
    let message = first_message(tunn, wire);
    u32::from_le_bytes(message[4..8].try_into().unwrap())
}

/// A canonical handshake response, as it reads unmasked, that names
/// `receiver_idx` and carries a valid mac1 for `to` -- and whose Noise payload
/// is garbage, so it can only fail at the AEAD.
fn forged_response(receiver_idx: u32, to: &crate::x25519::PublicKey) -> Vec<u8> {
    use super::handshake::{b2s_hash, b2s_keyed_mac_16, LABEL_MAC1};
    let mut core = vec![0u8; super::HANDSHAKE_RESP_SZ];
    core[..4].copy_from_slice(&2u32.to_le_bytes());
    core[4..8].copy_from_slice(&0x0bad_0003u32.to_le_bytes());
    core[8..12].copy_from_slice(&receiver_idx.to_le_bytes());
    core[12..44].fill(0xab);
    core[44..60].fill(0xcd);
    let mac1 = b2s_keyed_mac_16(&b2s_hash(LABEL_MAC1, to.as_bytes()), &core[..60]);
    core[60..76].copy_from_slice(&mac1);
    core
}

/// The regression Astra asked for on #51, constructible now: a false response
/// that gets all the way to Noise -- its receiver index names a pending
/// initiation, its mac1 is valid -- and fails there, must leave that initiation
/// pending, and must not stop the genuine transport packet behind it being
/// delivered. The genuine response that follows still completes the handshake.
///
/// Both slots: `state` (the initiation in flight) and `previous` (the one a
/// retransmission displaced), which `authenticate_response` searches
/// separately.
#[test]
fn a_response_that_fails_noise_leaves_its_initiation_pending() {
    for key in keys() {
        for previous_slot in [false, true] {
            let amnezia = unequal(key);
            let (mut mine, mut theirs, my_public) = keyed_pair(&amnezia, None);
            handshake(&mut mine, &mut theirs);

            // A rekey in flight: one initiation, or two with the target in
            // the `previous` slot.
            let mut buf = vec![0u8; 4096];
            let target = fresh_initiation(&mut mine, &mut buf);
            if previous_slot {
                fresh_initiation(&mut mine, &mut buf);
            }
            let target_idx = sender_idx(&mine, &target);

            // Genuine transport from the peer, with the false response written
            // over its junk prefix at S2.
            let packet = ipv4_packet(120);
            let mut wire = network(theirs.encapsulate(&packet, &mut buf));
            let s2 = UNEQUAL[1] as usize;
            plant_core(
                &mut wire,
                &amnezia,
                s2,
                &forged_response(target_idx, &my_public),
            );

            // Preconditions: the false reading passes mac1 and fails at Noise,
            // not at the index -- otherwise this proves less than it claims.
            let obf = mine.handshake.obf;
            let candidates = amnezia.inbound_candidates(obf, &wire);
            let response = *candidates
                .iter()
                .find(|c| c.offset() == s2)
                .expect("the false response is a candidate");
            let mut scratch = Vec::new();
            let message = amnezia
                .candidate_message(&wire, &response, &mut scratch)
                .unwrap()
                .to_vec();
            assert!(matches!(
                mine.rate_limiter.gate_handshake(
                    None,
                    &message,
                    0,
                    &mut super::rate_limiter::LoadDecision::default()
                ),
                super::rate_limiter::HandshakeGate::Pass
            ));
            let parsed = Tunn::parse_incoming_packet(obf, &message).unwrap();
            assert!(matches!(
                mine.authenticate(parsed, &mut [0u8; 4096]),
                Err(WireGuardError::InvalidAeadTag)
            ));

            // The datagram is delivered as the transport it is.
            let mut out = vec![0u8; 4096];
            assert_eq!(
                delivered(mine.decapsulate(SRC, &wire, &mut out)),
                packet,
                "key={} previous={}",
                key.is_some(),
                previous_slot
            );
            assert!(
                mine.handshake.is_in_progress(),
                "the initiation was consumed"
            );

            // And the genuine response to the targeted initiation completes it.
            let genuine = network(theirs.decapsulate(SRC, &target, &mut buf));
            let keepalive = network(mine.decapsulate(SRC, &genuine, &mut out));
            assert!(matches!(
                theirs.decapsulate(SRC, &keepalive, &mut out),
                TunnResult::Done
            ));
        }
    }
}

/// The same false response on its own -- nothing behind it to fall through
/// to -- is refused for the reason that is true, Noise, and still leaves the
/// initiation pending.
#[test]
fn a_lone_response_that_fails_noise_is_refused_by_noise() {
    for key in keys() {
        let amnezia = unequal(key);
        let (mut mine, mut theirs, my_public) = keyed_pair(&amnezia, None);
        handshake(&mut mine, &mut theirs);
        let mut buf = vec![0u8; 4096];
        let target = fresh_initiation(&mut mine, &mut buf);
        let target_idx = sender_idx(&mine, &target);

        let s2 = UNEQUAL[1] as usize;
        let mut wire = vec![0x5c; s2 + super::HANDSHAKE_RESP_SZ + 33];
        plant_core(
            &mut wire,
            &amnezia,
            s2,
            &forged_response(target_idx, &my_public),
        );
        assert!(matches!(
            mine.decapsulate(SRC, &wire, &mut [0u8; 4096]),
            TunnResult::Err(WireGuardError::InvalidAeadTag)
        ));
        assert!(mine.handshake.is_in_progress());
        let genuine = network(theirs.decapsulate(SRC, &target, &mut buf));
        network(mine.decapsulate(SRC, &genuine, &mut [0u8; 4096]));
    }
}

/// `wire` with `n` bytes of suffix appended.
fn with_suffix(wire: &[u8], n: usize) -> Vec<u8> {
    let mut extended = wire.to_vec();
    extended.extend((0..n).map(|i| (i * 31 + 7) as u8));
    extended
}

/// A handshake message with a suffix is a candidate only for a receiver with
/// RandomTrailers on; the canonical message is its fixed size either way, and
/// a zero-length suffix is the 3.0 message itself.
#[test]
fn a_trailer_extends_a_handshake_message_only_where_it_is_enabled() {
    for key in keys() {
        let on = unequal(key);
        let off = on.clone().with_random_trailers(false);
        let obf = super::handshake::ObfuscationRanges::default();
        let (mut mine, _) = pair(&off, None);
        let mut buf = vec![0u8; 4096];
        let init = network(mine.format_handshake_initiation(&mut buf, false));
        let s1 = UNEQUAL[0] as usize;
        assert_eq!(
            init.len(),
            s1 + super::HANDSHAKE_INIT_SZ,
            "a 3.0 sender: no suffix"
        );

        for n in [0usize, 1, 37, 400] {
            let wire = with_suffix(&init, n);
            let found = on.inbound_candidates(obf, &wire);
            let reading = *found
                .iter()
                .find(|c| c.offset() == s1)
                .unwrap_or_else(|| panic!("suffix {}: no initiation reading", n));
            let mut scratch = Vec::new();
            assert_eq!(
                on.candidate_message(&wire, &reading, &mut scratch)
                    .unwrap()
                    .len(),
                super::HANDSHAKE_INIT_SZ,
                "the canonical extent excludes the suffix"
            );
            assert_eq!(
                off.inbound_candidates(obf, &wire).offsets().contains(&s1),
                n == 0,
                "RandomTrailers off: exact size only (suffix {})",
                n
            );
        }
        // One byte short of the canonical message is nothing, either way.
        let short = &init[..init.len() - 1];
        assert!(!on.inbound_candidates(obf, short).offsets().contains(&s1));
    }
}

/// The suffix is outside everything that authenticates: rewriting it changes
/// nothing, and rewriting the core it follows is refused. Initiation,
/// response and cookie reply, with and without header protection.
#[test]
fn the_suffix_is_unauthenticated_and_the_core_is_not() {
    for key in keys() {
        let amnezia = unequal(key);

        // Initiation: a suffix rewritten in transit is still accepted...
        let (mut mine, mut theirs) = pair(&amnezia, None);
        let mut buf = vec![0u8; 4096];
        let init = network(mine.format_handshake_initiation(&mut buf, false));
        let mut wire = with_suffix(&init, 50);
        let end = wire.len();
        wire[end - 50..].fill(0xee);
        let response = network(theirs.decapsulate(SRC, &wire, &mut buf));

        // ...a response the same...
        let mut wire = with_suffix(&response, 21);
        let end = wire.len();
        wire[end - 1] ^= 0xff;
        let keepalive = network(mine.decapsulate(SRC, &wire, &mut buf));
        assert!(matches!(
            theirs.decapsulate(SRC, &keepalive, &mut buf),
            TunnResult::Done
        ));

        // ...while a flipped core byte is not.
        let init = fresh_initiation(&mut mine, &mut buf);
        let mut wire = with_suffix(&init, 9);
        wire[UNEQUAL[0] as usize + 100] ^= 1;
        assert!(matches!(
            theirs.decapsulate(SRC, &wire, &mut buf),
            TunnResult::Err(_)
        ));

        // A cookie reply: suffix rewritten, cookie stored.
        let (mut mine, mut theirs) = pair(&amnezia, Some(0));
        let init = network(mine.format_handshake_initiation(&mut buf, false));
        let cookie = network(theirs.decapsulate(SRC, &init, &mut buf));
        let mut wire = with_suffix(&cookie, 12);
        let end = wire.len();
        wire[end - 12..].fill(0);
        assert!(matches!(
            mine.decapsulate(SRC, &wire, &mut buf),
            TunnResult::Done
        ));
        assert!(mine.handshake.has_cookie());
    }
}

/// Initiations and responses carry a suffix drawn below the tunnel's window --
/// exact 3.0 sizes with RandomTrailers off -- and a wider window lets them grow
/// past the default.
#[test]
fn handshake_messages_draw_their_suffix_below_the_tunnel_window() {
    for key in keys() {
        let on = unequal(key);
        let (s1, s2) = (UNEQUAL[0] as usize, UNEQUAL[1] as usize);
        let init_base = s1 + super::HANDSHAKE_INIT_SZ;
        let resp_base = s2 + super::HANDSHAKE_RESP_SZ;

        // A budget past the loop, so every initiation earns a response and
        // none a cookie reply.
        let (mut mine, mut theirs) = pair(&on, Some(10_000));
        let mut buf = vec![0u8; 4096];
        let (mut inits, mut resps) = (Vec::new(), Vec::new());
        for _ in 0..48 {
            let init = fresh_initiation(&mut mine, &mut buf);
            let resp = network(theirs.decapsulate(SRC, &init, &mut buf));
            inits.push(init.len());
            resps.push(resp.len());
        }
        let window = DEFAULT_UDP_WINDOW as usize;
        assert!(
            inits.iter().all(|&n| n >= init_base && n < window),
            "{:?}",
            inits
        );
        assert!(
            resps.iter().all(|&n| n >= resp_base && n < window),
            "{:?}",
            resps
        );
        assert!(
            inits.iter().any(|&n| n > init_base),
            "initiations must vary"
        );
        assert!(resps.iter().any(|&n| n > resp_base), "responses must vary");

        // The window governs: widened, the suffix follows it.
        mine.set_udp_window(1400);
        let widest = (0..64)
            .map(|_| fresh_initiation(&mut mine, &mut buf).len())
            .max()
            .unwrap();
        assert!(widest > window && widest < 1400, "{}", widest);

        // Off: the 3.0 sizes, exactly.
        let off = on.clone().with_random_trailers(false);
        let (mut mine, mut theirs) = pair(&off, None);
        let init = network(mine.format_handshake_initiation(&mut buf, false));
        assert_eq!(init.len(), init_base);
        assert_eq!(
            network(theirs.decapsulate(SRC, &init, &mut buf)).len(),
            resp_base
        );
    }
}

/// A pair whose responder is starved, so every initiation it sees draws a
/// cookie reply.
fn cookie_pair(amnezia: &AmneziaConfig) -> (Tunn, Tunn) {
    pair(amnezia, Some(0))
}

/// The cookie reply's suffix is drawn against the fixed default window, not
/// the tunnel's -- and never makes the reply larger than the datagram that
/// provoked it. Equality is allowed; strictly larger is not, whatever the
/// window, the buffer or the draw.
#[test]
fn a_cookie_reply_suffix_is_bounded_by_the_request() {
    for key in keys() {
        // S1 > S3: the reply has room to grow, but only up to the request.
        let amnezia = AmneziaConfig::new(100, 40, 20, 160).with_random_trailers(true);
        let amnezia = match key {
            Some(k) => amnezia.with_header_protection(k),
            None => amnezia,
        };
        let (mut mine, mut theirs) = cookie_pair(&amnezia);
        theirs.set_udp_window(60_000);
        let mut buf = vec![0u8; 4096];
        let mut grew = false;
        for _ in 0..64 {
            let init = fresh_initiation(&mut mine, &mut buf);
            let reply = network(theirs.decapsulate(SRC, &init, &mut buf));
            assert!(reply.len() >= 20 + 64);
            assert!(
                reply.len() <= init.len(),
                "a {}-byte reply to a {}-byte request",
                reply.len(),
                init.len()
            );
            assert!(
                reply.len() < DEFAULT_UDP_WINDOW as usize,
                "the fixed window, not the tunnel's 60000"
            );
            grew |= reply.len() > 20 + 64;
        }
        assert!(grew, "the reply must draw a suffix when there is room");
    }
}

/// At exact parity there is no room: the reply is sent at its base size,
/// equal to the request. Where the base alone already amplifies, the reply is
/// suppressed, as before 3.1.
#[test]
fn a_cookie_reply_at_parity_carries_no_suffix_and_an_amplifying_one_is_suppressed() {
    // The request is an exact 3.0 initiation (148 bytes, S1 = 0), sent by a
    // peer with RandomTrailers off; the responder has it on.
    let parity = AmneziaConfig::new(0, 0, 84, 0);
    let (mut mine, mut theirs) = cookie_pair(&parity);
    let obf = theirs.handshake.obf;
    theirs.set_obfuscation(obf, parity.clone().with_random_trailers(true));
    let mut buf = vec![0u8; 4096];
    for _ in 0..32 {
        let init = fresh_initiation(&mut mine, &mut buf);
        assert_eq!(init.len(), 148);
        let reply = network(theirs.decapsulate(SRC, &init, &mut buf));
        assert_eq!(reply.len(), 148, "parity: sent, and with no suffix");
    }

    let amplifying = AmneziaConfig::new(0, 0, 100, 0);
    let (mut mine, mut theirs) = cookie_pair(&amplifying);
    let obf = theirs.handshake.obf;
    theirs.set_obfuscation(obf, amplifying.with_random_trailers(true));
    let init = fresh_initiation(&mut mine, &mut buf);
    assert!(matches!(
        theirs.decapsulate(SRC, &init, &mut buf),
        TunnResult::Done
    ));
}

/// The cookie reply's destination buffer: exactly the mandatory frame sends it
/// with no suffix, one byte less is an error rather than a panic, a few bytes
/// more bound the suffix. A large S3 whose base alone passes the fixed window
/// draws nothing and does not underflow.
#[test]
fn a_cookie_reply_respects_its_buffer_and_a_large_s3() {
    let amnezia = AmneziaConfig::new(200, 40, 20, 160).with_random_trailers(true);
    let base = 20 + 64;
    let (mut mine, mut theirs) = cookie_pair(&amnezia);
    let mut buf = vec![0u8; 4096];

    let init = fresh_initiation(&mut mine, &mut buf);
    assert_eq!(
        network(theirs.decapsulate(SRC, &init, &mut vec![0u8; base])).len(),
        base
    );
    let init = fresh_initiation(&mut mine, &mut buf);
    assert!(matches!(
        theirs.decapsulate(SRC, &init, &mut vec![0u8; base - 1]),
        TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
    ));
    for _ in 0..16 {
        let init = fresh_initiation(&mut mine, &mut buf);
        assert!(
            network(theirs.decapsulate(SRC, &init, &mut vec![0u8; base + 3])).len() <= base + 3
        );
    }

    let large = AmneziaConfig::new(1200, 40, 1000, 160).with_random_trailers(true);
    let (mut mine, mut theirs) = cookie_pair(&large);
    for _ in 0..8 {
        let init = fresh_initiation(&mut mine, &mut buf);
        let reply = network(theirs.decapsulate(SRC, &init, &mut buf));
        assert_eq!(reply.len(), 1000 + 64, "no room below the fixed window");
    }
}
