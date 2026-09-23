// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Live AmneziaWG reconfiguration while the first handshake is still behind
//! its pre-handshake burst.
//!
//! The first payload waits in the queue while the burst (imitation sequence,
//! Jc junk) goes out ahead of the initiation. Until that initiation is sent
//! the burst is the only record that one is due -- there is no handshake in
//! progress to retransmit and no session to rekey -- so a live change must
//! never drop it. It is kept when the change touches only what is read as
//! each datagram goes out, and rebuilt when it touches what the burst
//! captured (`AmneziaConfig::pending_burst_change`).
//!
//! The matrix runs under the mocked clock, where pacing is exact; a smoke set
//! runs under the real one.

use super::amnezia::{AmneziaConfig, AmneziaImitationProtocol, AwgTimers};
use super::handshake::ObfuscationRanges;
use super::inbound::fixtures::SRC;
use super::{Packet, Tunn, TunnResult, HANDSHAKE_INIT_SZ};
use crate::x25519;
use rand_core::OsRng;
use std::convert::TryInto;

/// Pre-handshake pacing, and the burst every test starts from: three 64-byte
/// junk datagrams, then the initiation.
const JD: u64 = 100;
const JC: u16 = 3;
const JUNK: usize = 64;
const S: [u16; 4] = [40, 24, 32, 160];

fn base() -> AmneziaConfig {
    AmneziaConfig::new(S[0], S[1], S[2], S[3]).with_pre_handshake_junk(
        JC,
        JUNK as u16,
        JUNK as u16,
        JD as u16,
    )
}

/// Let `ms` pass: the mocked clock under `mock-instant`, real time otherwise.
fn pass(ms: u64) {
    #[cfg(feature = "mock-instant")]
    mock_instant::thread_local::MockClock::advance(std::time::Duration::from_millis(ms));
    #[cfg(not(feature = "mock-instant"))]
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

/// Two tunnels under `cfg`, and what a key-change test needs to rebuild the
/// peer.
struct Pair {
    mine: Tunn,
    theirs: Tunn,
    their_secret: x25519::StaticSecret,
    cfg: AmneziaConfig,
}

fn pair(cfg: &AmneziaConfig) -> Pair {
    let my_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let my_public = x25519::PublicKey::from(&my_secret);
    let their_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let their_public = x25519::PublicKey::from(&their_secret);
    let obf = ObfuscationRanges::default();
    Pair {
        mine: Tunn::new_with_obfuscation(
            my_secret,
            their_public,
            None,
            None,
            0x100,
            None,
            obf,
            cfg.clone(),
        )
        .unwrap(),
        theirs: Tunn::new_with_obfuscation(
            their_secret.clone(),
            my_public,
            None,
            None,
            0x200,
            None,
            obf,
            cfg.clone(),
        )
        .unwrap(),
        their_secret,
        cfg: cfg.clone(),
    }
}

impl Pair {
    /// A live change applied to both ends, as the interface-wide AmneziaWG
    /// settings are.
    fn reconfigure(&mut self, obf: ObfuscationRanges, cfg: &AmneziaConfig) {
        self.mine.set_obfuscation(obf, cfg.clone());
        self.theirs.set_obfuscation(obf, cfg.clone());
    }
}

/// An IPv4 packet of `len` bytes tagged with `tag`, so a test can tell which
/// queued payload arrived.
fn payload(tag: u8) -> Vec<u8> {
    let len = 60usize;
    let mut p = vec![0u8; len];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 0, 0, 2]);
    p[16..20].copy_from_slice(&[10, 0, 0, 1]);
    p[20] = tag;
    p
}

/// Queue `payloads`, the first of which starts the burst; returns what the
/// first call emitted.
fn queue(t: &mut Tunn, payloads: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let first = match t.encapsulate(&payloads[0], &mut buf) {
        TunnResult::WriteToNetwork(d) => d.to_vec(),
        other => panic!("the first payload should start the burst: {:?}", other),
    };
    for p in &payloads[1..] {
        // Queued; the burst is paced, so nothing is due yet.
        assert!(matches!(t.encapsulate(p, &mut buf), TunnResult::Done));
    }
    first
}

/// What `t` emits over `polls` pacing intervals, stopping at the initiation:
/// the datagram whose emission ends the burst.
struct Drained {
    junk: Vec<Vec<u8>>,
    init: Option<Vec<u8>>,
}

fn drain(t: &mut Tunn, polls: usize) -> Drained {
    let mut junk = Vec::new();
    let mut buf = vec![0u8; 4096];
    for _ in 0..polls {
        pass(JD + 5);
        if let TunnResult::WriteToNetwork(d) = t.update_timers(&mut buf) {
            let d = d.to_vec();
            if t.pending_amnezia_junk.is_none() {
                return Drained {
                    junk,
                    init: Some(d),
                };
            }
            junk.push(d);
        }
    }
    Drained { junk, init: None }
}

/// Let `n` more datagrams of the burst out, one pacing interval apart.
fn emit(t: &mut Tunn, n: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    while out.len() < n {
        pass(JD + 5);
        if let TunnResult::WriteToNetwork(d) = t.update_timers(&mut buf) {
            out.push(d.to_vec());
        }
    }
    assert!(t.pending_amnezia_junk.is_some(), "the burst ended early");
    out
}

/// Whether `wire` reads as a handshake initiation under `(obf, cfg)`.
fn reads_as_initiation(obf: ObfuscationRanges, cfg: &AmneziaConfig, wire: &[u8]) -> bool {
    let candidates = cfg.inbound_candidates(obf, wire);
    let mut scratch = Vec::new();
    let mut found = false;
    for candidate in candidates.iter() {
        if let Some(message) = cfg.candidate_message(wire, candidate, &mut scratch) {
            if let Ok(Packet::HandshakeInit(_)) = Tunn::parse_incoming_packet(obf, message) {
                found = true;
            }
        }
    }
    found
}

/// Complete the handshake `init` starts; returns the payloads `theirs`
/// received from what `mine` had queued, in order.
fn complete(p: &mut Pair, init: &[u8]) -> Vec<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let mut out = vec![0u8; 4096];
    let response = match p.theirs.decapsulate(SRC, init, &mut buf) {
        TunnResult::WriteToNetwork(r) => r.to_vec(),
        other => panic!("the peer refused the initiation: {:?}", other),
    };
    let mut to_them = match p.mine.decapsulate(SRC, &response, &mut buf) {
        TunnResult::WriteToNetwork(k) => vec![k.to_vec()],
        other => panic!("the response was refused: {:?}", other),
    };
    while let TunnResult::WriteToNetwork(d) = p.mine.decapsulate(SRC, &[], &mut buf) {
        to_them.push(d.to_vec());
    }
    to_them
        .iter()
        .filter_map(|w| match p.theirs.decapsulate(SRC, w, &mut out) {
            TunnResult::WriteToTunnelV4(d, _) => Some(d.to_vec()),
            _ => None,
        })
        .collect()
}

fn lengths(datagrams: &[Vec<u8>]) -> Vec<usize> {
    datagrams.iter().map(Vec::len).collect()
}

// ---------------------------------------------------------------------------
// Keep.

/// One Keep-class change: the framing it touches, and whether the old
/// framing still reads the initiation (it must not, for a framing change).
struct KeepCase {
    name: &'static str,
    obf: ObfuscationRanges,
    cfg: AmneziaConfig,
    reframes_the_initiation: bool,
    junk_len: usize,
}

fn keep_cases() -> Vec<KeepCase> {
    let d = ObfuscationRanges::default();
    let b = base();
    let mut s1 = b.clone();
    s1.init_packet_junk_size += 8;
    let mut s4 = b.clone();
    s4.transport_packet_junk_size += 8;
    let case = |name, obf, cfg, reframes, junk_len| KeepCase {
        name,
        obf,
        cfg,
        reframes_the_initiation: reframes,
        junk_len,
    };
    vec![
        case("no change", d, b.clone(), false, JUNK),
        case("s1", d, s1, true, JUNK),
        case("s4", d, s4, false, JUNK),
        case(
            "h1-h4",
            ObfuscationRanges::new(100, 199, 200, 299, 300, 399, 400, 499).unwrap(),
            b.clone(),
            true,
            JUNK,
        ),
        case(
            "header protection",
            d,
            b.clone().with_header_protection([0x77; 32]),
            true,
            JUNK,
        ),
        case(
            "random trailers",
            d,
            b.clone().with_random_trailers(true),
            true,
            JUNK,
        ),
        case(
            "jmin/jmax",
            d,
            b.clone().with_pre_handshake_junk(JC, 80, 80, JD as u16),
            false,
            80,
        ),
        case(
            "jd",
            d,
            b.clone().with_pre_handshake_junk(JC, 64, 64, 50),
            false,
            JUNK,
        ),
        case(
            "padding",
            d,
            b.clone().with_content_padding_addition(8, 24, 1420),
            false,
            JUNK,
        ),
        case(
            "padding mtu",
            d,
            b.clone().with_content_padding_addition(0, 0, 1280),
            false,
            JUNK,
        ),
        case(
            "timers",
            d,
            b.clone().with_tunable_timers(AwgTimers {
                rekey_after_time: (30, 40),
                rekey_timeout: (3, 4),
                ..AwgTimers::default()
            }),
            false,
            JUNK,
        ),
        case(
            "disable cookies",
            d,
            b.clone().with_disable_cookies(true),
            false,
            JUNK,
        ),
    ]
}

/// A Keep-class change mid-burst -- after each of the three junk datagrams,
/// the last leaving only the initiation due -- keeps the burst: only what was
/// still owed goes out (junk sized by the new Jmin/Jmax where those changed),
/// then an initiation framed under the new configuration and unreadable under
/// the old where the change is to its framing, and the queued payload arrives
/// once. The UDP window is untouched.
#[cfg(feature = "mock-instant")]
#[test]
fn a_keep_class_change_keeps_the_burst_and_reframes_what_is_left() {
    let old_obf = ObfuscationRanges::default();
    for c in keep_cases() {
        for sent in 1..=JC as usize {
            let case = format!("{} after {} junk", c.name, sent);
            let mut p = pair(&base());
            let first = queue(&mut p.mine, &[payload(1)]);
            assert_eq!(first.len(), JUNK, "{}", case);
            emit(&mut p.mine, sent - 1);
            p.mine.set_udp_window(1234);

            p.reconfigure(c.obf, &c.cfg);
            assert!(p.mine.pending_amnezia_junk.is_some(), "{}: dropped", case);
            assert_eq!(p.mine.udp_window(), 1234, "{}: window moved", case);

            let rest = drain(&mut p.mine, 12);
            assert_eq!(
                lengths(&rest.junk),
                vec![c.junk_len; JC as usize - sent],
                "{}: only what was still owed, no replay",
                case
            );
            let init = rest.init.unwrap_or_else(|| panic!("{}: stalled", case));
            assert!(reads_as_initiation(c.obf, &c.cfg, &init), "{}", case);
            assert_eq!(
                reads_as_initiation(old_obf, &base(), &init),
                !c.reframes_the_initiation,
                "{}: old framing",
                case
            );
            assert_eq!(complete(&mut p, &init), vec![payload(1)], "{}", case);
        }
    }
}

/// RandomTrailers both ways mid-burst: kept, window untouched, and the
/// initiation carries a trailer exactly when it ends up on. Once the session
/// is up, transport follows the setting in force.
#[cfg(feature = "mock-instant")]
#[test]
fn random_trailers_toggled_mid_burst_keeps_the_burst_and_the_window() {
    let obf = ObfuscationRanges::default();
    for on in [true, false] {
        let from = base().with_random_trailers(!on);
        let to = base().with_random_trailers(on);
        let mut lengths_seen = std::collections::BTreeSet::new();
        for _ in 0..8 {
            let mut p = pair(&from);
            queue(&mut p.mine, &[payload(1)]);
            emit(&mut p.mine, 1);
            p.mine.set_udp_window(900);
            p.reconfigure(obf, &to);
            let rest = drain(&mut p.mine, 12);
            assert_eq!(lengths(&rest.junk), vec![JUNK], "rt->{}", on);
            assert_eq!(p.mine.udp_window(), 900);
            let init = rest.init.expect("stalled");
            if !on {
                assert_eq!(init.len(), S[0] as usize + HANDSHAKE_INIT_SZ);
            }
            lengths_seen.insert(init.len());
            assert_eq!(complete(&mut p, &init), vec![payload(1)]);

            // Transport under the setting in force.
            let mut buf = vec![0u8; 4096];
            let mut out = vec![0u8; 4096];
            let wire = match p.mine.encapsulate(&payload(2), &mut buf) {
                TunnResult::WriteToNetwork(w) => w.to_vec(),
                other => panic!("{:?}", other),
            };
            assert!(matches!(
                p.theirs.decapsulate(SRC, &wire, &mut out),
                TunnResult::WriteToTunnelV4(..)
            ));
        }
        assert_eq!(lengths_seen.len() > 1, on, "{:?}", lengths_seen);
    }
}

/// A new header-protection key mid-burst: the burst holds no masked control
/// message, so the initiation is masked with the new key only -- the old key
/// cannot read it, the new one can, and the peer holding the new key accepts
/// it.
#[cfg(feature = "mock-instant")]
#[test]
fn a_new_header_protection_key_masks_the_initiation_with_the_new_key_only() {
    let obf = ObfuscationRanges::default();
    let key_a = base().with_header_protection([0xaa; 32]);
    let key_b = base().with_header_protection([0xbb; 32]);
    let mut p = pair(&key_a);
    queue(&mut p.mine, &[payload(1)]);
    emit(&mut p.mine, 1);
    p.reconfigure(obf, &key_b);
    let rest = drain(&mut p.mine, 12);
    assert_eq!(lengths(&rest.junk), vec![JUNK; 1]);
    let init = rest.init.expect("stalled");
    assert!(reads_as_initiation(obf, &key_b, &init));
    assert!(!reads_as_initiation(obf, &key_a, &init));
    assert_eq!(complete(&mut p, &init), vec![payload(1)]);
}

/// The magic headers mid-burst: H1 is written when the initiation is
/// formatted, under its mac1, so the peer's new ranges both classify it and
/// verify it.
#[cfg(feature = "mock-instant")]
#[test]
fn new_magic_headers_mid_burst_frame_the_initiation_with_a_valid_mac1() {
    let old = ObfuscationRanges::default();
    let new = ObfuscationRanges::new(1000, 1999, 2000, 2999, 3000, 3999, 4000, 4999).unwrap();
    let mut p = pair(&base());
    queue(&mut p.mine, &[payload(1)]);
    emit(&mut p.mine, 1);
    p.reconfigure(new, &base());
    let init = drain(&mut p.mine, 12).init.expect("stalled");
    let tag = u32::from_le_bytes(init[S[0] as usize..S[0] as usize + 4].try_into().unwrap());
    assert!(
        (1000..=1999).contains(&tag),
        "H1 {} outside the new range",
        tag
    );
    assert!(!reads_as_initiation(old, &base(), &init));
    // The peer verifies mac1 over the new tag before anything else.
    assert_eq!(complete(&mut p, &init), vec![payload(1)]);
}

/// A new Jd applies at the next pacing check of the kept burst: 100 ms to
/// the 200 ms maximum, so at 105 ms nothing is due and at 205 ms it is.
#[cfg(feature = "mock-instant")]
#[test]
fn a_new_junk_delay_paces_the_rest_of_the_kept_burst() {
    let slow = base().with_pre_handshake_junk(JC, JUNK as u16, JUNK as u16, 200);
    let mut p = pair(&base());
    queue(&mut p.mine, &[payload(1)]);
    p.reconfigure(ObfuscationRanges::default(), &slow);
    let mut buf = vec![0u8; 4096];
    pass(JD + 5);
    assert!(
        matches!(p.mine.update_timers(&mut buf), TunnResult::Done),
        "the old delay no longer governs"
    );
    pass(100);
    match p.mine.update_timers(&mut buf) {
        TunnResult::WriteToNetwork(d) => assert_eq!(d.len(), JUNK),
        other => panic!("the new delay has passed: {:?}", other),
    }
}

/// A true no-op keeps everything as it was: the same burst, the same
/// pacing, the same timer draws, and no delay to the initiation.
#[cfg(feature = "mock-instant")]
#[test]
fn an_identical_configuration_changes_nothing() {
    let cfg = base().with_tunable_timers(AwgTimers {
        rekey_after_time: (100, 100_000),
        ..AwgTimers::default()
    });
    let mut p = pair(&cfg);
    queue(&mut p.mine, &[payload(1)]);
    emit(&mut p.mine, 1);
    let before = p
        .mine
        .pending_amnezia_junk
        .as_ref()
        .map(|b| (b.remaining, b.last_packet_at));
    let draws = (
        p.mine.timers.rekey_after_current,
        p.mine.timers.retransmit_current,
    );
    p.reconfigure(ObfuscationRanges::default(), &cfg);
    let after = p
        .mine
        .pending_amnezia_junk
        .as_ref()
        .map(|b| (b.remaining, b.last_packet_at));
    assert_eq!(before, after);
    assert_eq!(
        (
            p.mine.timers.rekey_after_current,
            p.mine.timers.retransmit_current
        ),
        draws
    );
    let rest = drain(&mut p.mine, 12);
    assert_eq!(lengths(&rest.junk), vec![JUNK]);
    assert_eq!(
        complete(&mut p, &rest.init.expect("stalled")),
        vec![payload(1)]
    );
}

// ---------------------------------------------------------------------------
// Restart.

/// Jc 3 -> 5 after two junk datagrams: the burst is rebuilt with the full new
/// count -- five more junk, not the two of the old burst, nor a mix -- then
/// the initiation, and the payload arrives once.
#[cfg(feature = "mock-instant")]
#[test]
fn a_new_junk_count_restarts_the_burst_with_the_full_new_count() {
    let five = base().with_pre_handshake_junk(5, JUNK as u16, JUNK as u16, JD as u16);
    let mut p = pair(&base());
    queue(&mut p.mine, &[payload(1)]);
    emit(&mut p.mine, 1);
    p.reconfigure(ObfuscationRanges::default(), &five);
    assert_eq!(p.mine.pending_amnezia_junk.as_ref().unwrap().remaining, 5);
    let rest = drain(&mut p.mine, 12);
    assert_eq!(lengths(&rest.junk), vec![JUNK; 5]);
    assert_eq!(
        complete(&mut p, &rest.init.expect("stalled")),
        vec![payload(1)]
    );
}

/// Jc -> 0 mid-burst: no junk is owed any more, but the initiation still is.
/// No zero-length datagram goes out; the next pacing check sends the
/// initiation.
#[cfg(feature = "mock-instant")]
#[test]
fn a_junk_count_of_zero_leaves_the_initiation_due() {
    let none = base().with_pre_handshake_junk(0, JUNK as u16, JUNK as u16, JD as u16);
    for sent in 1..=JC as usize {
        let mut p = pair(&base());
        queue(&mut p.mine, &[payload(1)]);
        emit(&mut p.mine, sent - 1);
        p.reconfigure(ObfuscationRanges::default(), &none);
        let marker = p.mine.pending_amnezia_junk.as_ref().expect("dropped");
        assert_eq!(marker.remaining, 0);
        assert!(marker.imitation_datagrams.is_empty());
        let rest = drain(&mut p.mine, 3);
        assert!(
            rest.junk.is_empty(),
            "after {}: {:?}",
            sent,
            lengths(&rest.junk)
        );
        let init = rest.init.expect("stalled");
        assert_eq!(init.len(), S[0] as usize + HANDSHAKE_INIT_SZ);
        assert_eq!(complete(&mut p, &init), vec![payload(1)]);
    }
}

/// Switching to responder mode mid-burst suppresses the rest of it -- no more
/// junk -- but not the initiation it was deferring.
#[cfg(feature = "mock-instant")]
#[test]
fn switching_to_responder_mid_burst_keeps_the_initiation_due() {
    let mut p = pair(&base());
    queue(&mut p.mine, &[payload(1)]);
    emit(&mut p.mine, 1);
    p.reconfigure(ObfuscationRanges::default(), &base().as_responder());
    let rest = drain(&mut p.mine, 3);
    assert!(rest.junk.is_empty(), "{:?}", lengths(&rest.junk));
    assert_eq!(
        complete(&mut p, &rest.init.expect("stalled")),
        vec![payload(1)]
    );
}

/// A new imitation configuration mid-sequence: none of the old sequence's
/// remaining datagrams go out after the change, the new sequence goes out
/// whole, then the new configuration's Jc junk and the initiation.
#[cfg(feature = "mock-instant")]
#[test]
fn a_new_imitation_restarts_the_sequence_with_nothing_left_of_the_old() {
    let dns = base().with_protocol_imitation(AmneziaImitationProtocol::Dns, None);
    for (name, next) in [
        (
            "stun",
            base().with_protocol_imitation(AmneziaImitationProtocol::Stun, None),
        ),
        ("off", base()),
    ] {
        let mut p = pair(&dns);
        queue(&mut p.mine, &[payload(1)]);
        let stale: Vec<Vec<u8>> = p
            .mine
            .pending_amnezia_junk
            .as_ref()
            .unwrap()
            .imitation_datagrams
            .iter()
            .map(|(_, d)| d.clone())
            .collect();
        assert!(!stale.is_empty(), "precondition: DNS datagrams still owed");

        p.reconfigure(ObfuscationRanges::default(), &next);
        let fresh: Vec<Vec<u8>> = p
            .mine
            .pending_amnezia_junk
            .as_ref()
            .unwrap()
            .imitation_datagrams
            .iter()
            .map(|(_, d)| d.clone())
            .collect();
        let rest = drain(&mut p.mine, 20);
        for d in &rest.junk {
            assert!(
                !stale.contains(d),
                "{}: a stale imitation datagram went out",
                name
            );
        }
        assert_eq!(
            rest.junk[..fresh.len()],
            fresh[..],
            "{}: the new sequence, whole",
            name
        );
        assert_eq!(rest.junk.len(), fresh.len() + JC as usize, "{}", name);
        assert_eq!(
            complete(&mut p, &rest.init.expect("stalled")),
            vec![payload(1)]
        );
    }
}

/// A restarted burst keeps the pacing clock of the one it replaces: the
/// change itself sends nothing, and the replacement's first junk datagram is
/// still a full Jd after the last one that went out.
#[cfg(feature = "mock-instant")]
#[test]
fn a_restarted_burst_keeps_the_pacing_clock() {
    let five = base().with_pre_handshake_junk(5, JUNK as u16, JUNK as u16, JD as u16);
    let mut p = pair(&base());
    queue(&mut p.mine, &[payload(1)]);
    let at = p.mine.pending_amnezia_junk.as_ref().unwrap().last_packet_at;
    pass(JD / 2);
    p.reconfigure(ObfuscationRanges::default(), &five);
    assert_eq!(
        p.mine.pending_amnezia_junk.as_ref().unwrap().last_packet_at,
        at
    );
    let mut buf = vec![0u8; 4096];
    assert!(
        matches!(p.mine.update_timers(&mut buf), TunnResult::Done),
        "the replacement went out early"
    );
    pass(JD / 2 + 5);
    match p.mine.update_timers(&mut buf) {
        TunnResult::WriteToNetwork(d) => assert_eq!(d.len(), JUNK),
        other => panic!("a full Jd has passed: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Repeated changes, the queue, and after the initiation.

/// Changes in quick succession before the initiation -- S1 (keep), imitation
/// (restart), RT (keep), Jc (restart), header protection (keep) -- converge
/// on the last configuration. No datagram of a replaced imitation sequence
/// goes out after its replacement, the initiation is framed by the final
/// configuration alone, and three payloads queued before any of it arrive
/// once each, in order.
#[cfg(feature = "mock-instant")]
#[test]
fn repeated_changes_converge_and_deliver_the_queue_once_in_order() {
    let obf = ObfuscationRanges::default();
    let mut cfg = base();
    let mut p = pair(&cfg);
    let payloads = vec![payload(1), payload(2), payload(3)];
    queue(&mut p.mine, &payloads);

    let steps: Vec<Box<dyn Fn(&AmneziaConfig) -> AmneziaConfig>> = vec![
        Box::new(|c| {
            let mut c = c.clone();
            c.init_packet_junk_size += 8;
            c
        }),
        Box::new(|c| {
            c.clone()
                .with_protocol_imitation(AmneziaImitationProtocol::Dns, None)
        }),
        Box::new(|c| c.clone().with_random_trailers(true)),
        Box::new(|c| {
            c.clone()
                .with_protocol_imitation(AmneziaImitationProtocol::Stun, None)
                .with_pre_handshake_junk(2, 70, 70, JD as u16)
        }),
        Box::new(|c| c.clone().with_header_protection([0x33; 32])),
    ];
    let mut replaced: Vec<Vec<u8>> = Vec::new();
    let mut emitted: Vec<Vec<u8>> = Vec::new();
    for step in steps {
        let next = step(&cfg);
        let restarts =
            cfg.pending_burst_change(&next) == super::amnezia::PendingBurstChange::Restart;
        if restarts {
            // What this restart abandons must never go out afterwards.
            replaced.extend(
                p.mine
                    .pending_amnezia_junk
                    .as_ref()
                    .unwrap()
                    .imitation_datagrams
                    .iter()
                    .map(|(_, d)| d.clone()),
            );
        }
        cfg = next;
        p.reconfigure(obf, &cfg);
        emitted.extend(emit(&mut p.mine, 1));
        for d in &emitted {
            assert!(
                !replaced.contains(d),
                "a replaced imitation datagram went out"
            );
        }
        emitted.clear();
    }
    let rest = drain(&mut p.mine, 20);
    for d in &rest.junk {
        assert!(
            !replaced.contains(d),
            "a replaced imitation datagram went out"
        );
    }
    let init = rest.init.expect("stalled");
    assert!(reads_as_initiation(obf, &cfg, &init));
    assert!(!reads_as_initiation(obf, &base(), &init));
    assert_eq!(complete(&mut p, &init), payloads);
}

/// After the initiation is out there is no burst: a framing change leaves the
/// Noise handshake alone, and the retransmission -- itself a fresh burst and
/// a fresh initiation -- goes out under the new configuration. The attempt
/// count is the retransmission's, not reset by the change.
#[cfg(feature = "mock-instant")]
#[test]
fn a_change_after_the_initiation_reaches_its_retransmission() {
    let d = ObfuscationRanges::default();
    let mut s1 = base();
    s1.init_packet_junk_size += 8;
    let cases: Vec<(&str, ObfuscationRanges, AmneziaConfig)> = vec![
        ("s1", d, s1),
        (
            "h1-h4",
            ObfuscationRanges::new(100, 199, 200, 299, 300, 399, 400, 499).unwrap(),
            base(),
        ),
        (
            "header protection",
            d,
            base().with_header_protection([0x44; 32]),
        ),
        ("random trailers", d, base().with_random_trailers(true)),
    ];
    for (name, obf, cfg) in cases {
        let mut p = pair(&base());
        queue(&mut p.mine, &[payload(1)]);
        let first = drain(&mut p.mine, 12).init.expect("the first initiation");
        assert!(p.mine.handshake.is_in_progress());
        assert_eq!(p.mine.timers.handshake_attempts, 0);
        drop(first); // lost

        p.reconfigure(obf, &cfg);
        assert!(
            p.mine.handshake.is_in_progress(),
            "{}: Noise state reset",
            name
        );
        assert_eq!(p.mine.timers.handshake_attempts, 0, "{}", name);

        pass(5_000);
        let retry = drain(&mut p.mine, 12);
        assert_eq!(lengths(&retry.junk), vec![JUNK; JC as usize], "{}", name);
        let init = retry.init.expect("no retransmission");
        assert!(reads_as_initiation(obf, &cfg, &init), "{}", name);
        assert!(!reads_as_initiation(d, &base(), &init), "{}", name);
        assert_eq!(p.mine.timers.handshake_attempts, 1, "{}", name);
        assert_eq!(complete(&mut p, &init), vec![payload(1)], "{}", name);
    }
}

/// A retransmission's own burst follows the same rule as the first one's:
/// restarted by a new Jc, then one fresh initiation, counted once.
#[cfg(feature = "mock-instant")]
#[test]
fn a_retransmission_burst_restarts_like_the_first() {
    let five = base().with_pre_handshake_junk(5, JUNK as u16, JUNK as u16, JD as u16);
    let mut p = pair(&base());
    queue(&mut p.mine, &[payload(1)]);
    drain(&mut p.mine, 12).init.expect("the first initiation");
    pass(5_000);
    emit(&mut p.mine, 1); // the retransmission's burst has begun
    assert_eq!(p.mine.timers.handshake_attempts, 0);
    p.reconfigure(ObfuscationRanges::default(), &five);
    let retry = drain(&mut p.mine, 12);
    assert_eq!(lengths(&retry.junk), vec![JUNK; 5]);
    let init = retry.init.expect("no retransmission");
    assert_eq!(p.mine.timers.handshake_attempts, 1);
    assert_eq!(complete(&mut p, &init), vec![payload(1)]);
}

/// On an established session a live change -- framing, trailers, padding,
/// junk shape -- keeps the session and the window, and transport goes out
/// under the new configuration.
#[cfg(feature = "mock-instant")]
#[test]
fn an_established_session_survives_every_class_of_change() {
    let d = ObfuscationRanges::default();
    let mut s4 = base();
    s4.transport_packet_junk_size += 8;
    let cases: Vec<(&str, ObfuscationRanges, AmneziaConfig)> = vec![
        ("s4", d, s4),
        (
            "h4",
            ObfuscationRanges::new(1, 1, 2, 2, 3, 3, 4000, 4999).unwrap(),
            base(),
        ),
        (
            "padding",
            d,
            base().with_content_padding_addition(8, 24, 1420),
        ),
        ("random trailers", d, base().with_random_trailers(true)),
        (
            "jc",
            d,
            base().with_pre_handshake_junk(5, 64, 64, JD as u16),
        ),
        (
            "imitation",
            d,
            base().with_protocol_imitation(AmneziaImitationProtocol::Dns, None),
        ),
    ];
    for (name, obf, cfg) in cases {
        let mut p = pair(&base());
        queue(&mut p.mine, &[payload(1)]);
        let init = drain(&mut p.mine, 12).init.expect("stalled");
        assert_eq!(complete(&mut p, &init), vec![payload(1)]);
        p.mine.set_udp_window(1111);
        let sessions = |t: &Tunn| t.sessions.iter().filter(|s| s.is_some()).count();
        let before = sessions(&p.mine);

        p.reconfigure(obf, &cfg);
        assert_eq!(sessions(&p.mine), before, "{}", name);
        assert!(
            p.mine.pending_amnezia_junk.is_none(),
            "{}: a burst appeared",
            name
        );

        let mut buf = vec![0u8; 4096];
        let mut out = vec![0u8; 4096];
        let wire = match p.mine.encapsulate(&payload(2), &mut buf) {
            TunnResult::WriteToNetwork(w) => w.to_vec(),
            other => panic!("{}: {:?}", name, other),
        };
        if name == "s4" {
            // The new S4 prefix in front of a 60-byte payload's frame.
            assert!(wire.len() >= S[3] as usize + 8 + 32 + 60, "{}", name);
        }
        assert!(
            matches!(
                p.theirs.decapsulate(SRC, &wire, &mut out),
                TunnResult::WriteToTunnelV4(..)
            ),
            "{}",
            name
        );
        assert!(
            p.mine.udp_window() >= 1111,
            "{}: the window was reset",
            name
        );
    }
}

// ---------------------------------------------------------------------------
// Real clock.

/// The same contract under the real clock, for one change of each class.
#[cfg(not(feature = "mock-instant"))]
#[test]
fn real_clock_smoke_keep_and_restart() {
    let d = ObfuscationRanges::default();
    let mut s1 = base();
    s1.init_packet_junk_size += 8;
    let five = base().with_pre_handshake_junk(5, JUNK as u16, JUNK as u16, JD as u16);
    let none = base().with_pre_handshake_junk(0, JUNK as u16, JUNK as u16, JD as u16);
    for (name, cfg, owed) in [("s1", s1, 1usize), ("jc 5", five, 5), ("jc 0", none, 0)] {
        let mut p = pair(&base());
        queue(&mut p.mine, &[payload(1)]);
        emit(&mut p.mine, 1);
        p.reconfigure(d, &cfg);
        let rest = drain(&mut p.mine, 12);
        assert_eq!(rest.junk.len(), owed, "{}", name);
        let init = rest.init.unwrap_or_else(|| panic!("{}: stalled", name));
        assert!(reads_as_initiation(d, &cfg, &init), "{}", name);
        assert_eq!(complete(&mut p, &init), vec![payload(1)], "{}", name);
    }
}

// ---------------------------------------------------------------------------
// Key changes.

/// A new pre-shared key mid-burst keeps the burst: it holds nothing derived
/// from a key, and the initiation behind it is formatted later. The
/// handshake then completes only with a peer holding the same new key --
/// the PSK is mixed in when the response is consumed -- and the payload
/// arrives once.
#[cfg(feature = "mock-instant")]
#[test]
fn a_new_preshared_key_mid_burst_keeps_the_first_handshake() {
    const PSK: [u8; 32] = [0x5c; 32];
    for peer_follows in [true, false] {
        let mut p = pair(&base());
        queue(&mut p.mine, &[payload(1)]);
        emit(&mut p.mine, 1);
        p.mine.set_preshared_key(Some(PSK));
        assert!(
            p.mine.pending_amnezia_junk.is_some(),
            "the burst was dropped"
        );
        if peer_follows {
            p.theirs.set_preshared_key(Some(PSK));
        }
        let rest = drain(&mut p.mine, 12);
        assert_eq!(lengths(&rest.junk), vec![JUNK; JC as usize - 2]);
        let init = rest.init.expect("stalled");
        if peer_follows {
            assert_eq!(complete(&mut p, &init), vec![payload(1)]);
        } else {
            // The old key cannot complete it: the response is refused.
            let mut buf = vec![0u8; 4096];
            let response = match p.theirs.decapsulate(SRC, &init, &mut buf) {
                TunnResult::WriteToNetwork(r) => r.to_vec(),
                other => panic!("{:?}", other),
            };
            assert!(matches!(
                p.mine.decapsulate(SRC, &response, &mut buf),
                TunnResult::Err(_)
            ));
        }
    }
}

/// A new static key mid-burst keeps the burst, and the initiation behind it
/// carries the new identity: a peer that knows only the old public key
/// refuses it, one configured with the new key accepts it, and the payload
/// arrives once.
#[cfg(feature = "mock-instant")]
#[test]
fn a_new_static_key_mid_burst_keeps_the_first_handshake() {
    let mut p = pair(&base());
    queue(&mut p.mine, &[payload(1)]);
    emit(&mut p.mine, 1);
    let new_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let new_public = x25519::PublicKey::from(&new_secret);
    p.mine.set_static_private(new_secret, new_public, None);
    assert!(
        p.mine.pending_amnezia_junk.is_some(),
        "the burst was dropped"
    );

    let rest = drain(&mut p.mine, 12);
    assert_eq!(lengths(&rest.junk), vec![JUNK; JC as usize - 2]);
    let init = rest.init.expect("stalled");

    let mut buf = vec![0u8; 4096];
    assert!(
        matches!(
            p.theirs.decapsulate(SRC, &init, &mut buf),
            TunnResult::Err(_)
        ),
        "a peer expecting the old identity accepted the initiation"
    );
    p.theirs = Tunn::new_with_obfuscation(
        p.their_secret.clone(),
        new_public,
        None,
        None,
        0x300,
        None,
        ObfuscationRanges::default(),
        p.cfg.clone(),
    )
    .unwrap();
    assert_eq!(complete(&mut p, &init), vec![payload(1)]);
}
