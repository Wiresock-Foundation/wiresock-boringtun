// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! AmneziaWG 3.1 DisableCookies, end to end through `Tunn` and the shared
//! candidate driver.
//!
//! The flag bypasses the whole under-load cookie-defense branch once mac1
//! holds -- the load decision, mac2, the need for a source address and the
//! cookie reply -- and nothing else. Load is forced deterministically, never
//! by flooding: a limiter with a budget of zero is under load from its first
//! counted message, so a test sees exactly which messages were counted.

use super::amnezia::{AmneziaConfig, AwgTimers};
use super::errors::WireGuardError;
use super::handshake::{b2s_hash, b2s_keyed_mac_16, ObfuscationRanges, LABEL_MAC1};
use super::inbound::fixtures::*;
use super::inbound::{receive, Inbound};
use super::rate_limiter::{CookieDefense, HandshakeGate, LoadDecision, RateLimiter};
use super::{Packet, Tunn, TunnResult, COOKIE_REPLY_SZ, HANDSHAKE_INIT_SZ, HANDSHAKE_RESP_SZ};
use crate::x25519;
use rand_core::OsRng;
use std::convert::TryInto;
use std::sync::Arc;

const KEY: [u8; 32] = [0x5a; 32];

fn keys() -> [Option<[u8; 32]>; 2] {
    [None, Some(KEY)]
}

/// Header protection on or off, RandomTrailers on or off, DisableCookies as
/// given, over sizes where every kind has its own length.
fn config(key: Option<[u8; 32]>, trailers: bool, disable: bool) -> AmneziaConfig {
    let amnezia = AmneziaConfig::new(40, 24, 32, 160)
        .with_random_trailers(trailers)
        .with_disable_cookies(disable);
    match key {
        Some(key) => amnezia.with_header_protection(key),
        None => amnezia,
    }
}

/// Every combination the tests below sweep: (key, RandomTrailers).
fn profiles() -> Vec<(Option<[u8; 32]>, bool)> {
    let mut all = Vec::new();
    for key in keys() {
        for trailers in [false, true] {
            all.push((key, trailers));
        }
    }
    all
}

/// Two tunnels and their static public keys, each with its own limiter of the
/// given budget (`None` for the default).
struct Ends {
    mine: Tunn,
    theirs: Tunn,
    my_public: x25519::PublicKey,
    their_public: x25519::PublicKey,
    my_limiter: Option<Arc<RateLimiter>>,
    their_limiter: Option<Arc<RateLimiter>>,
}

fn ends(
    mine: &AmneziaConfig,
    theirs: &AmneziaConfig,
    my_budget: Option<u64>,
    their_budget: Option<u64>,
) -> Ends {
    let my_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let my_public = x25519::PublicKey::from(&my_secret);
    let their_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let their_public = x25519::PublicKey::from(&their_secret);
    let my_limiter = my_budget.map(|b| Arc::new(RateLimiter::new(&my_public, b)));
    let their_limiter = their_budget.map(|b| Arc::new(RateLimiter::new(&their_public, b)));
    let mine = Tunn::new_with_obfuscation(
        my_secret,
        their_public,
        None,
        None,
        0x0000_1234,
        my_limiter.clone(),
        ObfuscationRanges::default(),
        mine.clone(),
    )
    .unwrap();
    let theirs = Tunn::new_with_obfuscation(
        their_secret,
        my_public,
        None,
        None,
        0x0000_5678,
        their_limiter.clone(),
        ObfuscationRanges::default(),
        theirs.clone(),
    )
    .unwrap();
    Ends {
        mine,
        theirs,
        my_public,
        their_public,
        my_limiter,
        their_limiter,
    }
}

/// A new initiation from `tunn`, with the clock moved on first, so that under
/// `mock-instant` a second initiation is not refused as a replay of the first.
fn fresh_initiation(tunn: &mut Tunn, buf: &mut [u8]) -> Vec<u8> {
    #[cfg(feature = "mock-instant")]
    mock_instant::thread_local::MockClock::advance(std::time::Duration::from_millis(5));
    network(tunn.format_handshake_initiation(buf, true))
}

/// The packet kind of our own datagram `wire`, as `tunn` reads it.
fn kind_of(tunn: &Tunn, wire: &[u8]) -> &'static str {
    match Tunn::parse_incoming_packet(tunn.handshake.obf, &first_message(tunn, wire)) {
        Ok(Packet::HandshakeInit(_)) => "initiation",
        Ok(Packet::HandshakeResponse(_)) => "response",
        Ok(Packet::PacketCookieReply(_)) => "cookie",
        Ok(Packet::PacketData(_)) => "data",
        Err(e) => panic!("not a packet of ours: {:?}", e),
    }
}

/// An IPv4 packet of exactly `len` bytes whose total-length field says so.
fn ipv4_packet(len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
    packet
}

/// A canonical initiation, as it reads unmasked, whose mac1 is valid for `to`
/// and whose Noise payload is garbage: it gets past the limiter and can only
/// fail at Noise.
fn forged_initiation(to: &x25519::PublicKey) -> Vec<u8> {
    let mut core = vec![0u8; HANDSHAKE_INIT_SZ];
    core[..4].copy_from_slice(&1u32.to_le_bytes());
    core[4..8].copy_from_slice(&0x0bad_0001u32.to_le_bytes());
    core[8..116].fill(0xab);
    let mac1 = b2s_keyed_mac_16(&b2s_hash(LABEL_MAC1, to.as_bytes()), &core[..116]);
    core[116..132].copy_from_slice(&mac1);
    core
}

/// [`forged_initiation`]'s response counterpart, naming `receiver_idx`.
fn forged_response(receiver_idx: u32, to: &x25519::PublicKey) -> Vec<u8> {
    let mut core = vec![0u8; HANDSHAKE_RESP_SZ];
    core[..4].copy_from_slice(&2u32.to_le_bytes());
    core[4..8].copy_from_slice(&0x0bad_0002u32.to_le_bytes());
    core[8..12].copy_from_slice(&receiver_idx.to_le_bytes());
    core[12..60].fill(0xab);
    let mac1 = b2s_keyed_mac_16(&b2s_hash(LABEL_MAC1, to.as_bytes()), &core[..60]);
    core[60..76].copy_from_slice(&mac1);
    core
}

/// A datagram under `amnezia` carrying `core` as its one message: its S
/// prefix, then the core masked the way a sender masks it.
fn framed(amnezia: &AmneziaConfig, s: usize, core: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x11u8; s + core.len()];
    plant_core(&mut wire, amnezia, s, core);
    wire
}

// ---------------------------------------------------------------------------
// The gate itself.

/// Past mac1, `Bypassed` skips the whole under-load branch: a starved limiter
/// that would demand a cookie (with an address) or refuse `UnderLoad` (without
/// one) passes the message on, takes no load decision and counts nothing.
#[test]
fn the_bypassed_gate_passes_a_valid_mac1_without_deciding_load() {
    let public = x25519::PublicKey::from(&x25519::StaticSecret::random_from_rng(OsRng));
    let message = forged_initiation(&public);
    let starved = RateLimiter::new(&public, 0);

    for src in [SRC, None] {
        let mut load = LoadDecision::default();
        assert!(matches!(
            starved.gate_handshake(src, &message, 7, CookieDefense::Bypassed, &mut load),
            HandshakeGate::Pass
        ));
        assert!(!load.is_decided(), "the load decision was taken");
    }
    assert_eq!(starved.load_events(), 0, "a bypassed message was counted");

    // The same message with the defense armed: the starved limiter's answers.
    match starved.gate_handshake(
        SRC,
        &message,
        7,
        CookieDefense::Armed,
        &mut LoadDecision::default(),
    ) {
        HandshakeGate::CookieDemanded(_) => {}
        _ => panic!("armed, under load, without mac2: a cookie is owed"),
    }
    assert!(matches!(
        starved.gate_handshake(
            None,
            &message,
            7,
            CookieDefense::Armed,
            &mut LoadDecision::default()
        ),
        HandshakeGate::UnderLoad
    ));
    assert_eq!(starved.load_events(), 2);
}

/// mac1 is never bypassed: a bad one is `BadMac` whichever the policy, and is
/// not counted either way.
#[test]
fn the_bypassed_gate_still_requires_mac1() {
    let public = x25519::PublicKey::from(&x25519::StaticSecret::random_from_rng(OsRng));
    let mut message = forged_initiation(&public);
    message[116] ^= 1;
    let limiter = RateLimiter::new(&public, 0);
    for defense in [CookieDefense::Bypassed, CookieDefense::Armed] {
        for src in [SRC, None] {
            assert!(matches!(
                limiter.gate_handshake(src, &message, 7, defense, &mut LoadDecision::default()),
                HandshakeGate::BadMac
            ));
        }
    }
    assert_eq!(limiter.load_events(), 0);
}

/// Bypassed messages spend none of the budget, so an armed receiver sharing
/// the limiter is not pushed under load by them.
#[test]
fn bypassed_messages_spend_none_of_the_budget() {
    let public = x25519::PublicKey::from(&x25519::StaticSecret::random_from_rng(OsRng));
    let message = forged_initiation(&public);
    let limiter = RateLimiter::new(&public, 1);
    for _ in 0..100 {
        limiter.gate_handshake(
            None,
            &message,
            0,
            CookieDefense::Bypassed,
            &mut LoadDecision::default(),
        );
    }
    assert!(
        matches!(
            limiter.gate_handshake(
                None,
                &message,
                0,
                CookieDefense::Armed,
                &mut LoadDecision::default()
            ),
            HandshakeGate::Pass
        ),
        "the budget of one was spent by messages that bypassed it"
    );
}

// ---------------------------------------------------------------------------
// The behaviour matrix, through `Tunn::decapsulate`.

/// DisableCookies off, not under load: the handshake completes, as always.
#[test]
fn cookies_on_and_not_under_load_is_a_normal_handshake() {
    for (key, trailers) in profiles() {
        let amnezia = config(key, trailers, false);
        let mut e = ends(&amnezia, &amnezia, None, None);
        let mut buf = vec![0u8; 4096];
        let init = fresh_initiation(&mut e.mine, &mut buf);
        let response = network(e.theirs.decapsulate(SRC, &init, &mut buf));
        assert_eq!(kind_of(&e.mine, &response), "response");
        let keepalive = network(e.mine.decapsulate(SRC, &response, &mut buf));
        assert!(matches!(
            e.theirs.decapsulate(SRC, &keepalive, &mut buf),
            TunnResult::Done
        ));
    }
}

/// DisableCookies off, under load, no mac2: a cookie reply to an address, and
/// `UnderLoad` without one. The handshake does not proceed: the initiation's
/// timestamp is not consumed, so it is still accepted once load lifts.
#[test]
fn cookies_on_under_load_without_mac2_demands_a_cookie_or_refuses() {
    for (key, trailers) in profiles() {
        let amnezia = config(key, trailers, false);
        let mut e = ends(&amnezia, &amnezia, None, Some(0));
        let mut buf = vec![0u8; 4096];
        let init = fresh_initiation(&mut e.mine, &mut buf);

        let cookie = network(e.theirs.decapsulate(SRC, &init, &mut buf));
        assert_eq!(kind_of(&e.mine, &cookie), "cookie");
        if !trailers {
            assert_eq!(cookie.len(), 32 + COOKIE_REPLY_SZ);
        }
        assert!(matches!(
            e.theirs.decapsulate(None, &init, &mut buf),
            TunnResult::Err(WireGuardError::UnderLoad)
        ));
        assert!(!e.theirs.handshake.is_in_progress());

        // Load lifted: the same initiation is fresh, so nothing was consumed.
        e.theirs.rate_limiter = Arc::new(RateLimiter::new(&e.their_public, 100));
        let response = network(e.theirs.decapsulate(SRC, &init, &mut buf));
        assert_eq!(kind_of(&e.mine, &response), "response");
    }
}

/// DisableCookies off, under load, valid mac2: the initiator stores the cookie
/// it is sent, its next initiation carries a mac2 that holds, and that one is
/// answered. The existing defense, unchanged.
#[test]
fn cookies_on_under_load_with_a_valid_mac2_proceeds() {
    for (key, trailers) in profiles() {
        let amnezia = config(key, trailers, false);
        let mut e = ends(&amnezia, &amnezia, None, Some(0));
        let mut buf = vec![0u8; 4096];
        let init = fresh_initiation(&mut e.mine, &mut buf);
        let cookie = network(e.theirs.decapsulate(SRC, &init, &mut buf));
        assert!(matches!(
            e.mine.decapsulate(SRC, &cookie, &mut buf),
            TunnResult::Done
        ));
        let init = fresh_initiation(&mut e.mine, &mut buf);
        let response = network(e.theirs.decapsulate(SRC, &init, &mut buf));
        assert_eq!(kind_of(&e.mine, &response), "response");
    }
}

/// DisableCookies on, under load, no mac2: the handshake goes on to Noise and
/// completes -- with an address and, as the FFI and connected-socket callers
/// pass, without one. No cookie reply, and nothing counted.
#[test]
fn cookies_off_under_load_without_mac2_completes_the_handshake() {
    for (key, trailers) in profiles() {
        for src in [SRC, None] {
            let amnezia = config(key, trailers, true);
            let mut e = ends(&amnezia, &amnezia, None, Some(0));
            let mut buf = vec![0u8; 4096];
            let init = fresh_initiation(&mut e.mine, &mut buf);
            let response = network(e.theirs.decapsulate(src, &init, &mut buf));
            assert_eq!(kind_of(&e.mine, &response), "response");
            let keepalive = network(e.mine.decapsulate(src, &response, &mut buf));
            assert!(matches!(
                e.theirs.decapsulate(src, &keepalive, &mut buf),
                TunnResult::Done
            ));
            assert_eq!(
                e.their_limiter.as_ref().unwrap().load_events(),
                0,
                "key={} trailers={} src={:?}",
                key.is_some(),
                trailers,
                src
            );
        }
    }
}

/// DisableCookies on never bypasses mac1: a damaged mac1 is refused as one,
/// under load or not.
#[test]
fn cookies_off_still_refuses_a_bad_mac1() {
    for (key, trailers) in profiles() {
        let amnezia = config(key, trailers, true);
        for budget in [None, Some(0)] {
            let mut e = ends(&amnezia, &amnezia, None, budget);
            let mut buf = vec![0u8; 4096];
            let mut init = fresh_initiation(&mut e.mine, &mut buf);
            // mac1 sits 116 bytes into the canonical initiation, behind S1.
            init[40 + 116] ^= 1;
            for src in [SRC, None] {
                assert!(matches!(
                    e.theirs.decapsulate(src, &init, &mut buf),
                    TunnResult::Err(WireGuardError::InvalidMac)
                ));
            }
        }
    }
}

/// DisableCookies on is not an authentication bypass: an initiation whose mac1
/// holds and whose Noise payload does not is refused by Noise, answered with
/// nothing, and leaves the responder able to accept the genuine initiation.
#[test]
fn cookies_off_still_refuses_an_initiation_that_fails_noise() {
    for (key, trailers) in profiles() {
        let amnezia = config(key, trailers, true);
        let mut e = ends(&amnezia, &amnezia, None, Some(0));
        let forged = framed(&amnezia, 40, &forged_initiation(&e.their_public));
        let mut buf = vec![0u8; 4096];
        for src in [SRC, None] {
            match e.theirs.decapsulate(src, &forged, &mut buf) {
                TunnResult::Err(WireGuardError::InvalidMac)
                | TunnResult::Err(WireGuardError::UnderLoad) => {
                    panic!("refused before Noise")
                }
                TunnResult::Err(_) => {}
                other => panic!("a forged initiation was answered: {:?}", other),
            }
        }
        assert!(!e.theirs.handshake.is_in_progress());
        let init = fresh_initiation(&mut e.mine, &mut buf);
        let response = network(e.theirs.decapsulate(SRC, &init, &mut buf));
        assert_eq!(kind_of(&e.mine, &response), "response");
    }
}

/// Timestamp replay protection is untouched: the same initiation twice is
/// refused the second time, under load and with cookies off.
#[test]
fn cookies_off_still_refuses_a_replayed_initiation() {
    for (key, trailers) in profiles() {
        let amnezia = config(key, trailers, true);
        let mut e = ends(&amnezia, &amnezia, None, Some(0));
        let mut buf = vec![0u8; 4096];
        let init = fresh_initiation(&mut e.mine, &mut buf);
        network(e.theirs.decapsulate(None, &init, &mut buf));
        assert!(matches!(
            e.theirs.decapsulate(None, &init, &mut buf),
            TunnResult::Err(WireGuardError::WrongTai64nTimestamp)
        ));
    }
}

// ---------------------------------------------------------------------------
// Cookie replies from the peer, and RandomTrailers.

/// DisableCookies is local responder policy, not a statement that cookies no
/// longer exist: a tunnel with it on still decrypts and stores the cookie
/// reply its peer sends -- RandomTrailers-extended when the profile says so --
/// and its next initiation carries the mac2 that cookie earns, which the
/// peer's armed, starved limiter accepts.
#[test]
fn a_tunnel_with_cookies_off_still_takes_and_uses_its_peers_cookie() {
    for (key, trailers) in profiles() {
        let mine = config(key, trailers, true);
        let theirs = config(key, trailers, false);
        let mut e = ends(&mine, &theirs, None, Some(0));
        let mut buf = vec![0u8; 4096];
        let init = fresh_initiation(&mut e.mine, &mut buf);
        let cookie = network(e.theirs.decapsulate(SRC, &init, &mut buf));
        assert_eq!(kind_of(&e.mine, &cookie), "cookie");
        assert!(!e.mine.handshake.has_cookie());
        assert!(matches!(
            e.mine.decapsulate(SRC, &cookie, &mut buf),
            TunnResult::Done
        ));
        assert!(
            e.mine.handshake.has_cookie(),
            "the peer's cookie was not stored"
        );

        let init = fresh_initiation(&mut e.mine, &mut buf);
        let response = network(e.theirs.decapsulate(SRC, &init, &mut buf));
        assert_eq!(
            kind_of(&e.mine, &response),
            "response",
            "key={} trailers={}: the stored cookie did not earn a mac2",
            key.is_some(),
            trailers
        );
    }
}

/// The four RandomTrailers x DisableCookies combinations against a starved
/// responder. Cookies on: every initiation draws a cookie reply, bounded by the
/// request, with a suffix only under RandomTrailers. Cookies off: every one
/// draws a response instead -- trailer-extended exactly when RandomTrailers is
/// on -- and never a cookie. The flags do not reach into each other.
#[test]
fn random_trailers_and_disable_cookies_compose_independently() {
    for key in keys() {
        for trailers in [false, true] {
            for disable in [false, true] {
                let amnezia = config(key, trailers, disable);
                let mut e = ends(&amnezia, &amnezia, None, Some(0));
                let mut buf = vec![0u8; 4096];
                let mut sizes = std::collections::BTreeSet::new();
                for _ in 0..24 {
                    let init = fresh_initiation(&mut e.mine, &mut buf);
                    if !trailers {
                        assert_eq!(init.len(), 40 + HANDSHAKE_INIT_SZ);
                    }
                    let reply = network(e.theirs.decapsulate(SRC, &init, &mut buf));
                    let kind = kind_of(&e.mine, &reply);
                    if disable {
                        assert_eq!(kind, "response");
                        assert!(reply.len() >= 24 + HANDSHAKE_RESP_SZ);
                    } else {
                        assert_eq!(kind, "cookie");
                        assert!(reply.len() <= init.len());
                    }
                    sizes.insert(reply.len());
                }
                assert_eq!(
                    sizes.len() > 1,
                    trailers,
                    "key={} trailers={} disable={}: {:?}",
                    key.is_some(),
                    trailers,
                    disable,
                    sizes
                );
                // Transport keeps RandomTrailers' padding with cookies off too:
                // complete one handshake and look at the frames.
                if disable {
                    let init = fresh_initiation(&mut e.mine, &mut buf);
                    let response = network(e.theirs.decapsulate(SRC, &init, &mut buf));
                    let keepalive = network(e.mine.decapsulate(SRC, &response, &mut buf));
                    e.theirs.decapsulate(SRC, &keepalive, &mut buf);
                    let mut frames = std::collections::BTreeSet::new();
                    for _ in 0..24 {
                        let wire = network(e.mine.encapsulate(&ipv4_packet(60), &mut buf));
                        frames.insert(wire.len());
                    }
                    assert_eq!(frames.len() > 1, trailers, "{:?}", frames);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Candidate fallback.

/// Sizes at which a whole initiation fits inside a transport packet's junk
/// prefix (16 + 148 <= 200), so a false one can be written in full -- valid
/// mac1 and all -- ahead of a genuine transport packet. A reading shorter than
/// the datagram exists only under RandomTrailers.
const ROOMY: [u16; 4] = [16, 24, 32, 200];

fn roomy(key: Option<[u8; 32]>, disable: bool) -> AmneziaConfig {
    let amnezia = AmneziaConfig::new(ROOMY[0], ROOMY[1], ROOMY[2], ROOMY[3])
        .with_random_trailers(true)
        .with_disable_cookies(disable);
    match key {
        Some(key) => amnezia.with_header_protection(key),
        None => amnezia,
    }
}

/// A false initiation cannot preempt genuine transport because the receiver is
/// under load. Cookies on, the initiation reading earns only a held-back cookie
/// (or `UnderLoad`); cookies off, it goes to Noise and fails there. Either way
/// the transport behind it is delivered -- once -- and with cookies off nothing
/// is counted. When the transport does not authenticate either, cookies on
/// answers as the challenged reading would, and cookies off answers nothing.
#[test]
fn a_false_initiation_does_not_preempt_transport_under_load() {
    for key in keys() {
        for disable in [false, true] {
            for src in [SRC, None] {
                let amnezia = roomy(key, disable);
                let mut e = ends(&amnezia, &amnezia, None, None);
                handshake(&mut e.mine, &mut e.theirs);
                // Starve the receiver only now, so the handshake was ordinary.
                let starved = Arc::new(RateLimiter::new(&e.their_public, 0));
                e.theirs.rate_limiter = Arc::clone(&starved);

                let packet = ipv4_packet(60);
                let mut buf = vec![0u8; 4096];
                let mut wire = network(e.mine.encapsulate(&packet, &mut buf));
                plant_core(
                    &mut wire,
                    &amnezia,
                    ROOMY[0] as usize,
                    &forged_initiation(&e.their_public),
                );
                let offsets = amnezia
                    .inbound_candidates(e.theirs.handshake.obf, &wire)
                    .offsets();
                assert_eq!(offsets.first(), Some(&(ROOMY[0] as usize)));
                assert_eq!(offsets.last(), Some(&(ROOMY[3] as usize)));

                let mut out = vec![0u8; 4096];
                match e.theirs.decapsulate(src, &wire, &mut out) {
                    TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, &packet[..]),
                    other => panic!(
                        "key={} disable={} src={:?}: {:?}",
                        key.is_some(),
                        disable,
                        src,
                        other
                    ),
                }
                assert_eq!(starved.load_events(), if disable { 0 } else { 1 });
                assert!(!e.theirs.handshake.is_in_progress());

                // The same datagram again: the transport's counter is spent.
                let again = e.theirs.decapsulate(src, &wire, &mut out);
                match (disable, src, again) {
                    (true, _, TunnResult::Err(e)) => {
                        assert!(!matches!(e, WireGuardError::UnderLoad))
                    }
                    (false, Some(_), TunnResult::WriteToNetwork(_)) => {}
                    (false, None, TunnResult::Err(WireGuardError::UnderLoad)) => {}
                    (d, s, other) => panic!("disable={} src={:?}: {:?}", d, s, other),
                }
            }
        }
    }
}

/// A false response -- valid mac1, naming our pending initiation -- ahead of
/// genuine transport, received under load with cookies off: it goes to Noise,
/// fails there, the initiation stays pending, and the transport is delivered.
/// The genuine response then completes the handshake.
#[test]
fn a_false_response_does_not_preempt_transport_under_load() {
    for key in keys() {
        let amnezia = config(key, true, true);
        let mut e = ends(&amnezia, &amnezia, Some(0), None);
        handshake(&mut e.mine, &mut e.theirs);
        let mut buf = vec![0u8; 4096];
        let target = fresh_initiation(&mut e.mine, &mut buf);
        let target_idx =
            u32::from_le_bytes(first_message(&e.mine, &target)[4..8].try_into().unwrap());

        let packet = ipv4_packet(120);
        let mut wire = network(e.theirs.encapsulate(&packet, &mut buf));
        plant_core(
            &mut wire,
            &amnezia,
            24,
            &forged_response(target_idx, &e.my_public),
        );
        assert!(amnezia
            .inbound_candidates(e.mine.handshake.obf, &wire)
            .offsets()
            .contains(&24));

        let mut out = vec![0u8; 4096];
        for src in [None] {
            match e.mine.decapsulate(src, &wire, &mut out) {
                TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, &packet[..]),
                other => panic!("key={}: {:?}", key.is_some(), other),
            }
        }
        assert_eq!(e.my_limiter.as_ref().unwrap().load_events(), 0);
        assert!(
            e.mine.handshake.is_in_progress(),
            "the initiation was consumed"
        );

        let genuine = network(e.theirs.decapsulate(SRC, &target, &mut buf));
        let keepalive = network(e.mine.decapsulate(None, &genuine, &mut out));
        assert!(matches!(
            e.theirs.decapsulate(SRC, &keepalive, &mut out),
            TunnResult::Done
        ));
    }
}

/// The shared driver under a starved limiter: with the defense armed, a
/// datagram whose only handshake reading fails is owed a cookie; bypassed, the
/// same reading reaches its trial, and a trial that authenticates wins exactly
/// as it would unloaded.
#[test]
fn the_driver_hands_a_bypassed_reading_to_its_trial() {
    let amnezia = colliding(None).with_disable_cookies(true);
    let armed = colliding(None);
    let public = x25519::PublicKey::from(&x25519::StaticSecret::random_from_rng(OsRng));
    let obf = ObfuscationRanges::default();
    let mut wire = vec![0xeeu8; WIRE];
    plant_core(&mut wire, &amnezia, INIT_AT, &forged_initiation(&public));
    let candidates = amnezia.inbound_candidates(obf, &wire);
    assert_eq!(candidates.offsets(), vec![INIT_AT]);

    let starved = RateLimiter::new(&public, 0);
    let mut tried = 0;
    let outcome = receive(&amnezia, obf, &starved, None, &candidates, &wire, |p| {
        tried += 1;
        match p {
            Packet::HandshakeInit(_) => Ok(()),
            _ => Err(WireGuardError::InvalidAeadTag),
        }
    });
    assert!(matches!(outcome, Inbound::Accepted(())));
    assert_eq!(tried, 1);
    assert_eq!(starved.load_events(), 0);

    let fails =
        |_: Packet<'_>| -> Result<(), WireGuardError> { Err(WireGuardError::InvalidAeadTag) };
    assert!(matches!(
        receive(&amnezia, obf, &starved, SRC, &candidates, &wire, fails),
        Inbound::Refused(WireGuardError::InvalidAeadTag)
    ));
    assert!(matches!(
        receive(&armed, obf, &starved, SRC, &candidates, &wire, fails),
        Inbound::Cookie(_)
    ));
}

// ---------------------------------------------------------------------------
// Live toggling.

/// Toggling DisableCookies on an established tunnel keeps its session, its UDP
/// window, its RandomTrailers setting and its drawn timers; what changes is how
/// the next initiation is met under load.
#[test]
fn toggling_disable_cookies_keeps_the_session_window_and_timers() {
    for (key, trailers) in profiles() {
        let timers = AwgTimers {
            rekey_after_time: (100, 100_000),
            keepalive_timeout: (10, 100_000),
            ..AwgTimers::default()
        };
        let on = config(key, trailers, true).with_tunable_timers(timers);
        let mut e = ends(&on, &on, None, Some(0));
        handshake(&mut e.mine, &mut e.theirs);
        e.theirs.set_udp_window(1234);
        let drawn = |t: &Tunn| {
            (
                t.timers.rekey_after_current,
                t.timers.keepalive_current,
                t.timers.retransmit_current,
            )
        };
        let obf = e.theirs.handshake.obf;
        let mut buf = vec![0u8; 4096];
        let mut out = vec![0u8; 4096];

        for disable in [false, true, false, true] {
            // Compared across the toggle alone: traffic and a completed
            // handshake re-arm these draws by design.
            let before = drawn(&e.theirs);
            e.theirs
                .set_obfuscation(obf, on.clone().with_disable_cookies(disable));
            assert_eq!(e.theirs.amnezia.disable_cookies, disable);
            assert_eq!(e.theirs.amnezia.random_trailers, trailers);
            assert_eq!(e.theirs.udp_window(), 1234, "the window moved");
            assert_eq!(drawn(&e.theirs), before, "the timers were redrawn");

            // The session carries traffic both ways.
            let packet = ipv4_packet(60);
            let wire = network(e.mine.encapsulate(&packet, &mut buf));
            assert!(matches!(
                e.theirs.decapsulate(SRC, &wire, &mut out),
                TunnResult::WriteToTunnelV4(..)
            ));
            let wire = network(e.theirs.encapsulate(&packet, &mut buf));
            assert!(matches!(
                e.mine.decapsulate(SRC, &wire, &mut out),
                TunnResult::WriteToTunnelV4(..)
            ));

            // And the next initiation meets the policy now in force.
            let init = fresh_initiation(&mut e.mine, &mut buf);
            let reply = network(e.theirs.decapsulate(SRC, &init, &mut out));
            assert_eq!(
                kind_of(&e.mine, &reply),
                if disable { "response" } else { "cookie" }
            );
            if disable {
                // Finish the handshake so the next round starts established.
                let keepalive = network(e.mine.decapsulate(SRC, &reply, &mut buf));
                e.theirs.decapsulate(SRC, &keepalive, &mut out);
                e.theirs.set_udp_window(1234);
            }
        }
    }
}

/// The public entry point `verify_packet` keeps the armed defense: it has no
/// configuration to consult, so a starved limiter still demands a cookie of a
/// mac1-valid initiation with an address and refuses one without.
#[test]
fn verify_packet_keeps_the_armed_defense() {
    let public = x25519::PublicKey::from(&x25519::StaticSecret::random_from_rng(OsRng));
    let init = forged_initiation(&public);
    let starved = RateLimiter::new(&public, 0);
    let obf = ObfuscationRanges::default();
    let mut buf = vec![0u8; 4096];
    assert!(matches!(
        starved.verify_packet(obf, &mut OsRng, SRC, &init, &mut buf),
        Err(TunnResult::WriteToNetwork(_))
    ));
    assert!(matches!(
        starved.verify_packet(obf, &mut OsRng, None, &init, &mut buf),
        Err(TunnResult::Err(WireGuardError::UnderLoad))
    ));
}

// ---------------------------------------------------------------------------
// Live toggles before a session exists.

/// The pre-handshake burst the pending-work tests run: three 64-byte junk
/// datagrams, 100 ms apart, then the initiation. No persistent keepalive.
const BURST: u16 = 3;
const JUNK: usize = 64;
const JD_MS: u64 = 100;

fn bursting(trailers: bool, disable: bool) -> AmneziaConfig {
    config(None, trailers, disable).with_pre_handshake_junk(
        BURST,
        JUNK as u16,
        JUNK as u16,
        JD_MS as u16,
    )
}

/// Let `ms` pass: the mocked clock under `mock-instant`, real time otherwise.
fn pass(ms: u64) {
    #[cfg(feature = "mock-instant")]
    mock_instant::thread_local::MockClock::advance(std::time::Duration::from_millis(ms));
    #[cfg(not(feature = "mock-instant"))]
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

/// Poll `tunn`'s timers, one pacing interval apart, until it emits a
/// datagram that is not burst junk, or `polls` run out. Returns everything
/// emitted, the last one being the initiation if it came.
fn poll_until_initiation(tunn: &mut Tunn, polls: usize) -> Vec<Vec<u8>> {
    let mut emitted = Vec::new();
    let mut buf = vec![0u8; 4096];
    for _ in 0..polls {
        pass(JD_MS + 10);
        if let TunnResult::WriteToNetwork(d) = tunn.update_timers(&mut buf) {
            let done = d.len() != JUNK;
            emitted.push(d.to_vec());
            if done {
                break;
            }
        }
    }
    emitted
}

fn lengths(datagrams: &[Vec<u8>]) -> Vec<usize> {
    datagrams.iter().map(Vec::len).collect()
}

/// Complete the handshake `init` starts and deliver whatever `mine` had
/// queued: the payload must arrive at `theirs` without being sent again.
fn complete_and_deliver(mine: &mut Tunn, theirs: &mut Tunn, init: &[u8], payload: &[u8]) {
    let mut buf = vec![0u8; 4096];
    let mut out = vec![0u8; 4096];
    let response = network(theirs.decapsulate(SRC, init, &mut buf));
    assert_eq!(kind_of(mine, &response), "response");
    let mut to_them = vec![network(mine.decapsulate(SRC, &response, &mut buf))];
    while let TunnResult::WriteToNetwork(d) = mine.decapsulate(SRC, &[], &mut buf) {
        to_them.push(d.to_vec());
    }
    let delivered: Vec<Vec<u8>> = to_them
        .iter()
        .filter_map(|wire| match theirs.decapsulate(SRC, wire, &mut out) {
            TunnResult::WriteToTunnelV4(p, _) => Some(p.to_vec()),
            _ => None,
        })
        .collect();
    assert_eq!(delivered, vec![payload.to_vec()], "the queued payload");
}

/// Start `mine`'s first handshake by queueing `payload`, and let `sent` junk
/// datagrams of the burst go out.
fn first_payload_behind(mine: &mut Tunn, payload: &[u8], sent: usize) {
    let mut buf = vec![0u8; 4096];
    assert_eq!(network(mine.encapsulate(payload, &mut buf)).len(), JUNK);
    let more = poll_until_initiation(mine, sent - 1);
    assert_eq!(lengths(&more), vec![JUNK; sent - 1], "precondition");
    assert!(mine.pending_amnezia_junk.is_some(), "precondition");
}

/// A DisableCookies-only live toggle while the first payload waits behind the
/// pre-handshake burst must not cancel the burst: the remaining junk and then
/// the initiation follow at their pacing, the handshake completes, and the
/// payload queued before the toggle is delivered -- with no second payload,
/// no externally forced initiation, and no new tunnel.
///
/// Toggled after each of the three junk datagrams (after the last, only the
/// initiation is still due), in both directions, with RandomTrailers off and
/// on.
#[test]
fn a_disable_cookies_toggle_keeps_the_pending_first_handshake() {
    for trailers in [false, true] {
        for from in [false, true] {
            for sent in 1..=BURST as usize {
                let case = format!(
                    "trailers={} dc {}->{} after {} junk",
                    trailers, from, !from, sent
                );
                let cfg = bursting(trailers, from);
                let mut e = ends(&cfg, &cfg, None, None);
                let obf = e.mine.handshake.obf;
                let payload = ipv4_packet(60);
                first_payload_behind(&mut e.mine, &payload, sent);

                e.mine
                    .set_obfuscation(obf, cfg.clone().with_disable_cookies(!from));
                assert_eq!(e.mine.amnezia.disable_cookies, !from, "{}", case);

                let rest = poll_until_initiation(&mut e.mine, BURST as usize + 3);
                let sizes = lengths(&rest);
                assert_eq!(
                    sizes.len(),
                    BURST as usize - sent + 1,
                    "{}: the burst stalled after the toggle: {:?}",
                    case,
                    sizes
                );
                assert!(
                    sizes[..sizes.len() - 1].iter().all(|&l| l == JUNK),
                    "{}",
                    case
                );
                let init = rest.last().unwrap();
                assert_eq!(kind_of(&e.mine, init), "initiation", "{}", case);
                if !trailers {
                    assert_eq!(init.len(), 40 + HANDSHAKE_INIT_SZ, "{}", case);
                }
                assert!(e.mine.pending_amnezia_junk.is_none(), "{}", case);

                complete_and_deliver(&mut e.mine, &mut e.theirs, init, &payload);
            }
        }
    }
}

/// Keeping the burst does not postpone the policy. With the first handshake
/// pending and the receiver starved, the toggle takes effect on the very next
/// handshake message received: the peer's own initiation is answered with
/// cookies now off, and owed a cookie with them now on.
///
/// Either way the payload queued before the toggle gets through. Cookies off,
/// the answered initiation establishes a session and the payload goes over
/// it. Cookies on, the burst carries on to our own initiation, and the peer
/// -- which took the cookie -- answers it with a mac2 that holds under load.
#[test]
fn a_toggle_with_the_first_handshake_pending_applies_at_the_next_message() {
    for trailers in [false, true] {
        for from in [false, true] {
            let to = !from;
            let case = format!("trailers={} dc {}->{}", trailers, from, to);
            let mine_cfg = bursting(trailers, from);
            let theirs_cfg = config(None, trailers, false);
            let mut e = ends(&mine_cfg, &theirs_cfg, Some(0), None);
            let obf = e.mine.handshake.obf;
            let payload = ipv4_packet(60);
            first_payload_behind(&mut e.mine, &payload, 1);

            e.mine
                .set_obfuscation(obf, mine_cfg.clone().with_disable_cookies(to));
            assert!(e.mine.pending_amnezia_junk.is_some(), "{}", case);

            let mut buf = vec![0u8; 4096];
            let mut out = vec![0u8; 4096];
            let their_init = fresh_initiation(&mut e.theirs, &mut buf);
            let reply = network(e.mine.decapsulate(SRC, &their_init, &mut buf));
            let load = e.my_limiter.as_ref().unwrap().load_events();
            if to {
                assert_eq!(kind_of(&e.theirs, &reply), "response", "{}", case);
                assert_eq!(load, 0, "{}", case);
                let keepalive = network(e.theirs.decapsulate(SRC, &reply, &mut out));
                assert!(matches!(
                    e.mine.decapsulate(SRC, &keepalive, &mut out),
                    TunnResult::Done
                ));
                let mut delivered = Vec::new();
                while let TunnResult::WriteToNetwork(d) = e.mine.decapsulate(SRC, &[], &mut buf) {
                    if let TunnResult::WriteToTunnelV4(p, _) =
                        e.theirs.decapsulate(SRC, d, &mut out)
                    {
                        delivered.push(p.to_vec());
                    }
                }
                assert_eq!(delivered, vec![payload.clone()], "{}", case);
            } else {
                assert_eq!(kind_of(&e.theirs, &reply), "cookie", "{}", case);
                assert_eq!(load, 1, "{}", case);
                assert!(e.mine.pending_amnezia_junk.is_some(), "{}", case);
                assert!(matches!(
                    e.theirs.decapsulate(SRC, &reply, &mut out),
                    TunnResult::Done
                ));
                let rest = poll_until_initiation(&mut e.mine, BURST as usize + 3);
                assert_eq!(
                    lengths(&rest[..rest.len() - 1]),
                    vec![JUNK; BURST as usize - 1],
                    "{}",
                    case
                );
                let init = rest.last().unwrap();
                assert_eq!(kind_of(&e.mine, init), "initiation", "{}", case);
                complete_and_deliver(&mut e.mine, &mut e.theirs, init, &payload);
            }
        }
    }
}

/// The distinction is DisableCookies alone. A change that reframes what this
/// end sends -- here S1 -- still drops a pending burst, exactly as before: the
/// behaviour of every other field is left as it was.
#[test]
fn a_send_side_change_still_drops_the_pending_burst() {
    let cfg = bursting(false, false);
    let mut e = ends(&cfg, &cfg, None, None);
    let obf = e.mine.handshake.obf;
    first_payload_behind(&mut e.mine, &ipv4_packet(60), 1);
    let mut s1 = cfg.clone().with_disable_cookies(true);
    s1.init_packet_junk_size += 4;
    e.mine.set_obfuscation(obf, s1);
    assert!(e.mine.pending_amnezia_junk.is_none());

    // And identical settings keep it: nothing was reframed.
    let mut e = ends(&cfg, &cfg, None, None);
    first_payload_behind(&mut e.mine, &ipv4_packet(60), 1);
    e.mine.set_obfuscation(obf, cfg.clone());
    assert!(e.mine.pending_amnezia_junk.is_some());
    // Nor does a change of magic headers count as policy.
    let moved = ObfuscationRanges::new(5, 5, 6, 6, 7, 7, 8, 8).unwrap();
    e.mine
        .set_obfuscation(moved, cfg.clone().with_disable_cookies(true));
    assert!(e.mine.pending_amnezia_junk.is_none());
}
