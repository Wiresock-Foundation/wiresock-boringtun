// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Header protection under protocol imitation: the per-protocol policy.
//!
//! Header protection nonces each datagram with the first 12 bytes of its S
//! prefix, and imitation shapes that prefix. `AmneziaConfig::
//! header_protection_nonce` classifies what is left, and every configuration
//! door acts on that one classification: QUIC (and no imitation) loads
//! silently, STUN and DNS load with a warning, and SIP whose request line
//! reaches the prefix -- any S of 31 bytes or more -- is refused. These tests
//! pin the classification, its boundaries, the wording, and the `Tunn` doors:
//! the constructors and the live setter. The UAPI and C doors are pinned in
//! `device::api`, `device::integration_tests` and `ffi`.

use super::amnezia::{
    AmneziaConfig, AmneziaImitationProtocol, HeaderProtectionNonce, TrailerRoom, DEFAULT_UDP_WINDOW,
};
use super::handshake::ObfuscationRanges;
use super::{Tunn, TunnResult};
use crate::x25519;
use rand_chacha::ChaCha8Rng;
use rand_core::{OsRng, SeedableRng};

const KEY: [u8; 32] = [0x6b; 32];

/// Every imitation protocol, spelled out rather than taken from
/// `AmneziaImitationProtocol::ALL`, so the expectations below are a table a
/// reader can check and not a restatement of the classifier.
const PROTOCOLS: [AmneziaImitationProtocol; 5] = [
    AmneziaImitationProtocol::None,
    AmneziaImitationProtocol::Quic,
    AmneziaImitationProtocol::Stun,
    AmneziaImitationProtocol::Dns,
    AmneziaImitationProtocol::Sip,
];

fn imitating(protocol: AmneziaImitationProtocol, s: [u16; 4], key: bool) -> AmneziaConfig {
    let cfg = AmneziaConfig::new(s[0], s[1], s[2], s[3]).with_protocol_imitation(protocol, None);
    if key {
        cfg.with_header_protection(KEY)
    } else {
        cfg
    }
}

/// The stock amneziawg-install sizes: every one past the SIP threshold but S4.
const INSTALLER: [u16; 4] = [136, 59, 149, 16];

// ---------------------------------------------------------------------------
// Classification.
// ---------------------------------------------------------------------------

/// With a key: no imitation and QUIC are random, STUN is bounded to ~2^32,
/// DNS to 2^16, and SIP is random below the request-line threshold and
/// degenerate from it. Without a key there is no nonce to classify.
#[test]
fn each_imitation_protocol_has_its_header_protection_nonce_class() {
    use HeaderProtectionNonce::*;
    let expected = |p: AmneziaImitationProtocol, s: [u16; 4]| match p {
        AmneziaImitationProtocol::None | AmneziaImitationProtocol::Quic => Full,
        AmneziaImitationProtocol::Stun => Bounded32,
        AmneziaImitationProtocol::Dns => Weak16,
        AmneziaImitationProtocol::Sip if s.iter().all(|&s| s <= 30) => Full,
        AmneziaImitationProtocol::Sip => Degenerate,
    };
    for protocol in PROTOCOLS {
        for s in [[12; 4], [30; 4], [31; 4], INSTALLER, [30, 30, 30, 31]] {
            assert_eq!(
                imitating(protocol, s, true).header_protection_nonce(),
                Some(expected(protocol, s)),
                "{:?} {:?}",
                protocol,
                s
            );
            assert_eq!(
                imitating(protocol, s, false).header_protection_nonce(),
                None,
                "{:?} {:?} without a key",
                protocol,
                s
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The one refusal: SIP with a request line in the prefix.
// ---------------------------------------------------------------------------

/// SIP with header protection: every S at 30 loads, and 31 in any single
/// field is refused, naming that field. The refusal says what is configured,
/// why header protection is void, and the three ways out -- and does not claim
/// anything about payload confidentiality.
#[test]
fn sip_with_header_protection_is_refused_from_31_bytes_in_any_s_field() {
    let sip = AmneziaImitationProtocol::Sip;
    imitating(sip, [30; 4], true)
        .validate()
        .expect("every S at 30: the SIP prefix is random");
    imitating(sip, [12; 4], true)
        .validate()
        .expect("the smallest header-protection sizes");

    for (field, label) in ["S1", "S2", "S3", "S4"].iter().enumerate() {
        let mut s = [30; 4];
        s[field] = 31;
        let cfg = imitating(sip, s, true);
        let err = cfg
            .check_header_protection_nonce()
            .expect_err(&format!("{} = 31 must be refused", label));
        assert_eq!(
            cfg.validate().expect_err("and by validate"),
            err,
            "validate refuses through the same check"
        );
        for needle in [
            "SIP imitation",
            "header protection",
            &format!("{} is 31 bytes", label)[..],
            "from 31 bytes",
            "at 30 or below",
            "another imitation protocol",
            "disable header protection",
        ] {
            assert!(err.contains(needle), "{:?} missing from: {}", needle, err);
        }
        for claim in ["plaintext", "confidential", "decrypt", "authentic"] {
            assert!(
                !err.to_lowercase().contains(claim),
                "the refusal is about header masking, not {:?}: {}",
                claim,
                err
            );
        }
    }

    for s in [[31; 4], INSTALLER, [150, 150, 150, 150]] {
        assert!(
            imitating(sip, s, true).validate().is_err(),
            "{:?} is refused",
            s
        );
    }
}

/// Only SIP, and only with a key: every other protocol loads at S = 31 and at
/// the installer sizes, and SIP without header protection loads whatever S.
#[test]
fn nothing_else_is_refused_by_the_sip_rule() {
    for protocol in PROTOCOLS {
        for s in [[31; 4], INSTALLER, [150; 4]] {
            if protocol != AmneziaImitationProtocol::Sip {
                imitating(protocol, s, true)
                    .validate()
                    .unwrap_or_else(|e| panic!("{:?} {:?}: {}", protocol, s, e));
            }
            imitating(protocol, s, false)
                .validate()
                .unwrap_or_else(|e| panic!("{:?} {:?} without a key: {}", protocol, s, e));
        }
    }
}

/// The policy's threshold is the generator's: at 30 bytes the SIP filler
/// leaves the prefix random, at 31 it writes a request line. Framed through
/// the production path without header protection, so the prefix is on the
/// wire as drawn.
#[test]
fn the_sip_threshold_is_where_the_sip_filler_starts_a_request_line() {
    let starts_a_request_line = |wire: &[u8]| {
        [&b"OPTIONS sip:"[..], b"REGISTER sip", b"MESSAGE sip:"].contains(&&wire[..12])
    };
    // A transport message: type 4, then stand-in header and ciphertext.
    let mut message = vec![0x5au8; 64];
    message[..4].copy_from_slice(&4u32.to_le_bytes());
    let mut rng = ChaCha8Rng::seed_from_u64(0x5195);
    for (s4, shaped) in [(30u16, false), (31, true)] {
        let cfg = imitating(AmneziaImitationProtocol::Sip, [s4; 4], false);
        for _ in 0..64 {
            let mut buf = message.clone();
            buf.resize(4096, 0);
            let wire = cfg
                .prepend_outbound_with_trailer(
                    ObfuscationRanges::default(),
                    &mut buf,
                    message.len(),
                    Some(TrailerRoom::window(DEFAULT_UDP_WINDOW)),
                    &mut rng,
                )
                .unwrap()
                .to_vec();
            assert_eq!(starts_a_request_line(&wire), shaped, "S4 = {}", s4);
        }
    }
}

// ---------------------------------------------------------------------------
// The warnings: STUN and DNS load, and the accepting door says why it worries.
// ---------------------------------------------------------------------------

/// STUN's warning names STUN and a bounded nonce space that repeats; DNS's is
/// stronger, naming the 16-bit transaction-ID space, quick reuse and weakened
/// masking. No imitation, QUIC and random-prefix SIP earn none, nor does any
/// configuration without a key. Shaped SIP earns none either: it is refused,
/// not warned about.
#[test]
fn stun_and_dns_are_warned_about_and_nothing_else_is() {
    let stun = imitating(AmneziaImitationProtocol::Stun, INSTALLER, true)
        .header_protection_nonce_complaint()
        .expect("STUN with header protection is warned about");
    for needle in ["STUN", "header-protection nonce", "2^32", "repeat", "mask"] {
        assert!(stun.contains(needle), "{:?} missing from: {}", needle, stun);
    }

    let dns = imitating(AmneziaImitationProtocol::Dns, INSTALLER, true)
        .header_protection_nonce_complaint()
        .expect("DNS with header protection is warned about");
    for needle in [
        "DNS",
        "16-bit",
        "65,536",
        "Nonce reuse is quick",
        "header-protection mask",
        "substantially weakens header masking",
    ] {
        assert!(dns.contains(needle), "{:?} missing from: {}", needle, dns);
    }
    assert!(
        !stun.contains("DNS") && !dns.contains("STUN"),
        "one protocol each"
    );

    for warning in [&stun, &dns] {
        assert!(
            warning.contains("payload encryption and authentication are unaffected")
                || warning.contains("Payload encryption and authentication are unaffected"),
            "says what is not at stake: {}",
            warning
        );
        assert!(!warning.to_lowercase().contains("plaintext"), "{}", warning);
    }

    for (protocol, s) in [
        (AmneziaImitationProtocol::None, INSTALLER),
        (AmneziaImitationProtocol::Quic, INSTALLER),
        (AmneziaImitationProtocol::Quic, [31; 4]),
        (AmneziaImitationProtocol::Sip, [30; 4]),
        (AmneziaImitationProtocol::Sip, [31; 4]),
    ] {
        assert_eq!(
            imitating(protocol, s, true).header_protection_nonce_complaint(),
            None,
            "{:?} {:?}",
            protocol,
            s
        );
    }
    for protocol in PROTOCOLS {
        assert_eq!(
            imitating(protocol, INSTALLER, false).header_protection_nonce_complaint(),
            None,
            "{:?} without a key",
            protocol
        );
    }
}

/// `validate` says only what is valid: STUN and DNS pass it, and the warning
/// is the door's to log.
#[test]
fn validate_accepts_stun_and_dns_with_header_protection() {
    for protocol in [
        AmneziaImitationProtocol::Stun,
        AmneziaImitationProtocol::Dns,
    ] {
        let cfg = imitating(protocol, INSTALLER, true);
        cfg.validate().expect("valid, if weaker");
        assert!(cfg.header_protection_nonce_complaint().is_some());
    }
}

// ---------------------------------------------------------------------------
// The `Tunn` doors.
// ---------------------------------------------------------------------------

struct Pair {
    a: Tunn,
    b: Tunn,
}

fn build(cfg: &AmneziaConfig) -> Result<Pair, String> {
    let a_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let b_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let (a_public, b_public) = (
        x25519::PublicKey::from(&a_secret),
        x25519::PublicKey::from(&b_secret),
    );
    let obf = ObfuscationRanges::default();
    let a = Tunn::new_with_obfuscation(a_secret, b_public, None, None, 1, None, obf, cfg.clone())?;
    let b = Tunn::new_with_obfuscation(b_secret, a_public, None, None, 2, None, obf, cfg.clone())?;
    Ok(Pair { a, b })
}

/// Handshake, then one packet each way, all under the tunnels' current
/// configuration. The initiation is formatted directly, past any imitation
/// burst, which paces itself on timers and is not what is tested here.
fn round_trip(p: &mut Pair) {
    let (mut abuf, mut bbuf) = (vec![0u8; 4096], vec![0u8; 4096]);
    let init = match p.a.format_handshake_initiation_now(&mut abuf, false) {
        TunnResult::WriteToNetwork(d) => d.to_vec(),
        other => panic!("initiation: {:?}", other),
    };
    let response = match p.b.decapsulate(None, &init, &mut bbuf) {
        TunnResult::WriteToNetwork(d) => d.to_vec(),
        other => panic!("response: {:?}", other),
    };
    let keepalive = match p.a.decapsulate(None, &response, &mut abuf) {
        TunnResult::WriteToNetwork(d) => d.to_vec(),
        other => panic!("keepalive: {:?}", other),
    };
    assert!(matches!(
        p.b.decapsulate(None, &keepalive, &mut bbuf),
        TunnResult::Done
    ));
    send(&mut p.a, &mut p.b);
    send(&mut p.b, &mut p.a);
}

fn send(from: &mut Tunn, to: &mut Tunn) {
    let mut packet = vec![0x11u8; 120];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&120u16.to_be_bytes());
    packet[9] = 17;
    let (mut fbuf, mut tbuf) = (vec![0u8; 4096], vec![0u8; 4096]);
    let wire = match from.encapsulate(&packet, &mut fbuf) {
        TunnResult::WriteToNetwork(d) => d.to_vec(),
        other => panic!("encapsulate: {:?}", other),
    };
    match to.decapsulate(None, &wire, &mut tbuf) {
        TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, &packet[..]),
        other => panic!("decapsulate: {:?}", other),
    }
}

/// The constructors: shaped SIP with a key is refused with the policy's error;
/// QUIC, STUN, DNS and random-prefix SIP build and carry traffic.
#[test]
fn the_tunn_constructors_apply_the_policy() {
    let err = match build(&imitating(AmneziaImitationProtocol::Sip, INSTALLER, true)) {
        Ok(_) => panic!("shaped SIP with header protection must not build"),
        Err(e) => e,
    };
    assert!(
        err.contains("SIP imitation with header protection"),
        "{}",
        err
    );
    assert!(err.contains("S1 is 136 bytes"), "{}", err);

    for (protocol, s) in [
        (AmneziaImitationProtocol::Quic, INSTALLER),
        (AmneziaImitationProtocol::Stun, INSTALLER),
        (AmneziaImitationProtocol::Dns, INSTALLER),
        (AmneziaImitationProtocol::Sip, [30, 30, 30, 16]),
    ] {
        let mut pair = build(&imitating(protocol, s, true))
            .unwrap_or_else(|e| panic!("{:?} {:?}: {}", protocol, s, e));
        round_trip(&mut pair);
    }
}

/// The live setter is not a way around the refusal. From a working DNS tunnel,
/// a switch to shaped SIP -- with new H ranges, timers and junk as well, so a
/// partial application would show -- is refused as a whole by
/// `try_set_obfuscation`, and by `set_obfuscation`, which cannot report it:
/// the configuration, the H ranges and the session are what they were, and
/// traffic still flows under the old configuration. A switch to random-prefix
/// SIP is then accepted and applied.
#[test]
fn the_live_setter_refuses_shaped_sip_without_applying_any_of_it() {
    let safe = imitating(AmneziaImitationProtocol::Dns, INSTALLER, true);
    let mut pair = build(&safe).expect("DNS with header protection builds");
    round_trip(&mut pair);
    let obf_before = pair.a.handshake.obf;
    let current_before = pair.a.current;

    let other_obf = ObfuscationRanges::new(10, 19, 20, 29, 30, 39, 40, 49).unwrap();
    let shaped = imitating(AmneziaImitationProtocol::Sip, INSTALLER, true)
        .with_pre_handshake_junk(3, 40, 60, 0)
        .with_tunable_timers(super::amnezia::AwgTimers {
            keepalive_timeout: (20, 25),
            ..Default::default()
        });
    assert_ne!(shaped, safe);

    let err = pair
        .a
        .try_set_obfuscation(other_obf, shaped.clone())
        .expect_err("refused");
    assert!(
        err.contains("SIP imitation with header protection"),
        "{}",
        err
    );
    pair.a.set_obfuscation(other_obf, shaped);
    assert_eq!(pair.a.amnezia, safe, "no part of the refused configuration");
    assert_eq!(pair.a.handshake.obf, obf_before, "nor its H ranges");
    assert_eq!(pair.a.current, current_before, "the session is kept");
    send(&mut pair.a, &mut pair.b);
    send(&mut pair.b, &mut pair.a);

    let short = imitating(AmneziaImitationProtocol::Sip, [30, 30, 30, 16], true);
    for t in [&mut pair.a, &mut pair.b] {
        t.try_set_obfuscation(obf_before, short.clone())
            .expect("random-prefix SIP is accepted");
        assert_eq!(t.amnezia, short);
    }
    send(&mut pair.a, &mut pair.b);
}
