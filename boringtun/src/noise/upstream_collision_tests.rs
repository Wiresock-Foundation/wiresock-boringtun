// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Sender-side avoidance of upstream control collisions in transport framing.
//!
//! The AmneziaWG 3.1 kernel module (amneziawg-linux-kernel-module 4569c4c67f3a,
//! `receive.c` `awg_determine_type_and_padding`) and amneziawg-go (b5928efb6ca1,
//! `device/receive.go` `DeterminePacketTypeAndPadding`) take a datagram for the
//! first kind -- initiation, response, cookie reply, transport -- whose length
//! test passes and whose tag, read at that kind's S offset and XORed with four
//! header-protection mask bytes, falls in its H range, and never fall through.
//! A transport frame that also fits an earlier kind is dropped there.
//! `AmneziaConfig::avoid_upstream_control_collision` re-frames such a frame
//! under a new S4 prefix, 16 framings in total at most.
//!
//! The oracle below restates that upstream classifier independently of the
//! production predicate: the tests decide what upstream would do with it, not
//! with the code under test. Exact candidate sequences are forced with a
//! scripted RNG: every candidate's prefix is chosen by the test, and the tag a
//! control reading sees is planted in prefix bytes past the 12-byte nonce,
//! where it is raw on the wire and so fully determined by the prefix.
//! End to end through `Tunn`, whose framing draws from its own `ChaCha8Rng`,
//! the tests seed that RNG instead, in a layout where a send draws nothing but
//! its prefixes. Every candidate is then replayed from a clone and checked
//! against the oracle before the send, and the send's word consumption is
//! counted exactly.

use super::amnezia::{AmneziaConfig, AmneziaImitationProtocol, TrailerRoom, DEFAULT_UDP_WINDOW};
use super::handshake::ObfuscationRanges;
use super::timers::TimerName;
use super::{grown_window, Tunn, TunnResult, N_SESSIONS};
use crate::x25519;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand_chacha::ChaCha8Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use std::collections::VecDeque;
use std::convert::TryInto;
use std::time::Duration;

const KEY: [u8; 32] = [0x6b; 32];
const INIT: usize = 0;
const RESP: usize = 1;
const COOKIE: usize = 2;
const DATA: usize = 3;
const BASE: [usize; 4] = [148, 92, 64, 32];

// ---------------------------------------------------------------------------
// The independent upstream oracle.
// ---------------------------------------------------------------------------

/// Upstream's four header-protection keystream bytes for a datagram: ChaCha20
/// block 0 under the datagram's first 12 bytes as nonce.
fn keystream(key: [u8; 32], datagram: &[u8], n: usize) -> Vec<u8> {
    let mut ks = vec![0u8; n];
    ChaCha20::new(&key.into(), datagram[..12].into()).apply_keystream(&mut ks);
    ks
}

/// The kind an upstream receiver commits to, or `None` if it drops the
/// datagram as unknown. Restated from the two upstream sources named above,
/// in their order: first winner, nothing authenticated.
fn upstream_first_match(
    p: &[u8],
    s: [usize; 4],
    h: [(u32, u32); 4],
    key: Option<[u8; 32]>,
    rt: bool,
) -> Option<usize> {
    let hash = key.map(|k| keystream(k, p, 4)).unwrap_or(vec![0; 4]);
    for kind in [INIT, RESP, COOKIE, DATA] {
        let need = s[kind] + BASE[kind];
        let fits = if kind == DATA || rt {
            p.len() >= need
        } else {
            p.len() == need
        };
        if !fits {
            continue;
        }
        let raw = &p[s[kind]..s[kind] + 4];
        let tag = u32::from_le_bytes([
            raw[0] ^ hash[0],
            raw[1] ^ hash[1],
            raw[2] ^ hash[2],
            raw[3] ^ hash[3],
        ]);
        if h[kind].0 <= tag && tag <= h[kind].1 {
            return Some(kind);
        }
    }
    None
}

/// The tag an upstream receiver reads for `kind` at `offset` in `p`.
fn decoded(p: &[u8], offset: usize, key: [u8; 32]) -> u32 {
    let hash = keystream(key, p, 4);
    u32::from_le_bytes([
        p[offset] ^ hash[0],
        p[offset + 1] ^ hash[1],
        p[offset + 2] ^ hash[2],
        p[offset + 3] ^ hash[3],
    ])
}

/// A transport frame framed by hand: `prefix`, the canonical 16-byte header
/// masked under the prefix's nonce, the rest unchanged.
fn framed(prefix: &[u8], canonical: &[u8], key: Option<[u8; 32]>) -> Vec<u8> {
    let mut wire = prefix.to_vec();
    wire.extend_from_slice(canonical);
    if let Some(key) = key {
        let ks = keystream(key, &wire, 16);
        for i in 0..16 {
            wire[prefix.len() + i] ^= ks[i];
        }
    }
    wire
}

/// The canonical header of a framed transport datagram.
fn unmasked_header(wire: &[u8], s4: usize, key: [u8; 32]) -> Vec<u8> {
    let ks = keystream(key, wire, 16);
    wire[s4..s4 + 16]
        .iter()
        .zip(ks)
        .map(|(a, b)| a ^ b)
        .collect()
}

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// Layout A: every control offset inside the 64-byte S4 prefix, past the
/// nonce, so a test can plant exactly the tag each reading will see.
const S_A: [usize; 4] = [20, 28, 36, 64];
const H_A: [(u32, u32); 4] = [
    (0x1000_0000, 0x1000_00ff),
    (0x2000_0000, 0x2000_00ff),
    (0x3000_0000, 0x3000_00ff),
    (0x4000_0000, 0x4000_00ff),
];
const TRANSPORT_TAG: u32 = 0x4000_0010;
/// A decoded tag outside every H range of layout A.
const SAFE: u32 = 0x7777_7777;

fn ranges(h: [(u32, u32); 4]) -> ObfuscationRanges {
    ObfuscationRanges::new(
        h[0].0, h[0].1, h[1].0, h[1].1, h[2].0, h[2].1, h[3].0, h[3].1,
    )
    .unwrap()
}

fn config(s: [usize; 4], key: Option<[u8; 32]>, rt: bool) -> AmneziaConfig {
    let cfg = AmneziaConfig::new(s[0] as u16, s[1] as u16, s[2] as u16, s[3] as u16)
        .with_random_trailers(rt);
    match key {
        Some(k) => cfg.with_header_protection(k),
        None => cfg,
    }
}

/// A canonical transport message of `len` bytes: tag, receiver index,
/// counter, then stand-in ciphertext.
fn canonical(len: usize, tag: u32) -> Vec<u8> {
    let mut m = vec![0u8; len];
    m[..4].copy_from_slice(&tag.to_le_bytes());
    m[4..8].copy_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    m[8..16].copy_from_slice(&7u64.to_le_bytes());
    for (i, b) in m.iter_mut().enumerate().skip(16) {
        *b = (i * 31 + 7) as u8;
    }
    m
}

/// A `s4`-byte prefix whose readings at the given offsets decode, under
/// `key`, to the given tags.
fn prefix(seed: u8, s4: usize, plants: &[(usize, u32)], key: Option<[u8; 32]>) -> Vec<u8> {
    let mut p: Vec<u8> = (0..s4)
        .map(|i| {
            seed.wrapping_mul(37)
                .wrapping_add((i as u8).wrapping_mul(13))
                ^ 0x5c
        })
        .collect();
    let mask = key.map(|k| keystream(k, &p, 4)).unwrap_or(vec![0; 4]);
    for &(offset, tag) in plants {
        assert!(
            offset >= 12 && offset + 4 <= s4,
            "plant inside the prefix, past the nonce"
        );
        for (i, b) in tag.to_le_bytes().iter().enumerate() {
            p[offset + i] = b ^ mask[i];
        }
    }
    p
}

/// A layout-A prefix colliding on the given kinds and safe on the others.
fn prefix_a(seed: u8, colliding: &[usize]) -> Vec<u8> {
    let plants: Vec<(usize, u32)> = [INIT, RESP, COOKIE]
        .iter()
        .map(|&k| {
            let tag = if colliding.contains(&k) {
                H_A[k].0 + 0x42
            } else {
                SAFE
            };
            (S_A[k], tag)
        })
        .collect();
    prefix(seed, S_A[DATA], &plants, Some(KEY))
}

/// An RNG that hands out exactly the scripted words and fails the test if the
/// code under test asks for one more.
struct Script {
    words: VecDeque<u32>,
    drawn: usize,
}

impl Script {
    fn of(prefixes: &[Vec<u8>]) -> Self {
        let words = prefixes
            .iter()
            .flat_map(|p| {
                assert_eq!(p.len() % 4, 0);
                p.chunks(4)
                    .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                    .collect::<Vec<_>>()
            })
            .collect();
        Script { words, drawn: 0 }
    }
}

impl RngCore for Script {
    fn next_u32(&mut self) -> u32 {
        self.drawn += 1;
        self.words
            .pop_front()
            .expect("the framing drew more randomness than the test scripted")
    }
    fn next_u64(&mut self) -> u64 {
        u64::from(self.next_u32()) | (u64::from(self.next_u32()) << 32)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            let w = self.next_u32().to_le_bytes();
            chunk.copy_from_slice(&w[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Counts 32-bit words drawn from an inner RNG.
struct Counting<R> {
    inner: R,
    words: usize,
}

impl<R: RngCore> RngCore for Counting<R> {
    fn next_u32(&mut self) -> u32 {
        self.words += 1;
        self.inner.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.words += 2;
        self.inner.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.words += dest.len().div_ceil(4);
        self.inner.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Frame `message` for the wire as the transport send path does.
fn frame(
    cfg: &AmneziaConfig,
    obf: ObfuscationRanges,
    message: &[u8],
    rng: &mut impl RngCore,
) -> Vec<u8> {
    let mut buf = message.to_vec();
    buf.resize(message.len() + 4096, 0);
    cfg.prepend_outbound_with_trailer(
        obf,
        &mut buf,
        message.len(),
        Some(TrailerRoom::window(DEFAULT_UDP_WINDOW)),
        rng,
    )
    .unwrap()
    .to_vec()
}

const WORDS_A: usize = 64 / 4;

/// Frame a layout-A message of wire length `wire_len` under `script`.
fn frame_a(rt: bool, wire_len: usize, prefixes: &[Vec<u8>]) -> (Vec<u8>, usize, Vec<u8>) {
    let message = canonical(wire_len - S_A[DATA], TRANSPORT_TAG);
    let mut script = Script::of(prefixes);
    let wire = frame(
        &config(S_A, Some(KEY), rt),
        ranges(H_A),
        &message,
        &mut script,
    );
    (wire, script.drawn, message)
}

fn upstream_a(p: &[u8], rt: bool) -> Option<usize> {
    upstream_first_match(p, S_A, H_A, Some(KEY), rt)
}

// ---------------------------------------------------------------------------
// Retry behaviour and the 16-candidate bound.
// ---------------------------------------------------------------------------

/// Candidate 1 collides upstream, candidate 2 does not: candidate 2 goes out,
/// and it is the same datagram in every respect the peer authenticates.
#[test]
fn a_colliding_first_framing_is_redrawn_once_and_the_datagram_is_unchanged() {
    let (p1, p2) = (prefix_a(1, &[INIT]), prefix_a(2, &[]));
    let (wire, drawn, message) = frame_a(true, 400, &[p1.clone(), p2.clone()]);

    let candidate1 = framed(&p1, &message, Some(KEY));
    assert_eq!(
        upstream_a(&candidate1, true),
        Some(INIT),
        "candidate 1 really collides upstream"
    );
    assert_eq!(
        wire,
        framed(&p2, &message, Some(KEY)),
        "candidate 2 is what went out"
    );
    assert_eq!(
        upstream_a(&wire, true),
        Some(DATA),
        "and upstream takes it as transport"
    );
    assert_eq!(
        drawn,
        2 * WORDS_A,
        "one original prefix, one redraw, nothing else"
    );

    // Same length, header, counter, index, ciphertext; only the prefix and the
    // masked header differ.
    assert_eq!(wire.len(), candidate1.len());
    assert_eq!(unmasked_header(&wire, 64, KEY), message[..16]);
    assert_eq!(unmasked_header(&candidate1, 64, KEY), message[..16]);
    assert_eq!(
        wire[64 + 16..],
        candidate1[64 + 16..],
        "ciphertext and tag untouched"
    );
    assert_ne!(wire[..64], candidate1[..64], "a new prefix");
    assert_ne!(wire[64..80], candidate1[64..80], "so a newly masked header");
}

/// Fifteen colliding framings and a clean sixteenth: the sixteenth goes out.
#[test]
fn the_sixteenth_framing_is_still_tried() {
    let mut prefixes: Vec<Vec<u8>> = (1..=15).map(|s| prefix_a(s, &[RESP])).collect();
    prefixes.push(prefix_a(16, &[]));
    let (wire, drawn, message) = frame_a(true, 400, &prefixes);
    for p in &prefixes[..15] {
        assert_eq!(
            upstream_a(&framed(p, &message, Some(KEY)), true),
            Some(RESP)
        );
    }
    assert_eq!(wire, framed(&prefixes[15], &message, Some(KEY)));
    assert_eq!(upstream_a(&wire, true), Some(DATA));
    assert_eq!(drawn, 16 * WORDS_A);
}

/// Sixteen colliding framings: the sixteenth goes out anyway -- valid on the
/// wire, exactly what was sent before this existed -- and a seventeenth is
/// never drawn.
#[test]
fn sixteen_colliding_framings_send_the_sixteenth() {
    let prefixes: Vec<Vec<u8>> = (1..=17).map(|s| prefix_a(s, &[COOKIE])).collect();
    let (wire, drawn, message) = frame_a(true, 400, &prefixes);
    assert_eq!(
        drawn,
        16 * WORDS_A,
        "16 framings in total, the original included"
    );
    assert_eq!(wire, framed(&prefixes[15], &message, Some(KEY)));
    assert_eq!(
        upstream_a(&wire, true),
        Some(COOKIE),
        "still colliding: best effort"
    );
    assert_eq!(unmasked_header(&wire, 64, KEY), message[..16]);
    assert_eq!(wire[80..], message[16..]);
}

/// Each control kind on its own triggers a redraw, and so do several at once.
#[test]
fn every_control_kind_and_every_combination_triggers_a_redraw() {
    for colliding in [
        vec![INIT],
        vec![RESP],
        vec![COOKIE],
        vec![INIT, COOKIE],
        vec![RESP, COOKIE],
        vec![INIT, RESP, COOKIE],
    ] {
        let p1 = prefix_a(3, &colliding);
        let (wire, drawn, message) = frame_a(true, 400, &[p1.clone(), prefix_a(4, &[])]);
        assert_eq!(
            upstream_a(&framed(&p1, &message, Some(KEY)), true),
            Some(colliding[0]),
            "{:?}: upstream's first winner",
            colliding
        );
        assert_eq!(drawn, 2 * WORDS_A, "{:?}", colliding);
        assert_eq!(upstream_a(&wire, true), Some(DATA), "{:?}", colliding);
    }
}

/// H ranges are inclusive at both ends, upstream and here.
#[test]
fn h_ranges_collide_at_both_endpoints_and_not_one_past() {
    let (lo, hi) = H_A[INIT];
    for (tag, collides) in [(lo, true), (hi, true), (lo - 1, false), (hi + 1, false)] {
        let p1 = prefix(
            5,
            64,
            &[(S_A[INIT], tag), (S_A[RESP], SAFE), (S_A[COOKIE], SAFE)],
            Some(KEY),
        );
        let (wire, drawn, message) = frame_a(true, 400, &[p1.clone(), prefix_a(6, &[])]);
        assert_eq!(
            upstream_a(&framed(&p1, &message, Some(KEY)), true) == Some(INIT),
            collides,
            "{:#x}",
            tag
        );
        assert_eq!(drawn, if collides { 2 } else { 1 } * WORDS_A, "{:#x}", tag);
        if !collides {
            assert_eq!(
                wire,
                framed(&p1, &message, Some(KEY)),
                "the ordinary framing"
            );
        }
    }
}

/// The length test per kind: at least `S + base` with RandomTrailers, exactly
/// `S + base` without, one byte either side of each threshold.
#[test]
fn control_length_tests_follow_random_trailers() {
    for rt in [true, false] {
        for kind in [INIT, RESP, COOKIE] {
            let threshold = S_A[kind] + BASE[kind];
            for wire_len in [threshold - 1, threshold, threshold + 1] {
                let p1 = prefix_a(7, &[kind]);
                let (wire, drawn, message) = frame_a(rt, wire_len, &[p1.clone(), prefix_a(8, &[])]);
                let fits = if rt {
                    wire_len >= threshold
                } else {
                    wire_len == threshold
                };
                let first = framed(&p1, &message, Some(KEY));
                assert_eq!(
                    upstream_a(&first, rt) == Some(kind),
                    fits,
                    "rt={} kind={} len={}",
                    rt,
                    kind,
                    wire_len
                );
                assert_eq!(
                    drawn,
                    if fits { 2 } else { 1 } * WORDS_A,
                    "rt={} kind={} len={}",
                    rt,
                    kind,
                    wire_len
                );
                assert_eq!(
                    upstream_a(&wire, rt),
                    Some(DATA),
                    "rt={} kind={} len={}",
                    rt,
                    kind,
                    wire_len
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Where the misread tag comes from.
// ---------------------------------------------------------------------------

/// A control offset inside the transport header or the ciphertext, or across
/// the prefix/header boundary: the tag is read through the shared mask all
/// the same, a redraw changes it, and every read stays in bounds.
#[test]
fn control_offsets_in_the_header_the_ciphertext_and_across_the_boundary() {
    for (s1, label) in [
        (68, "transport header"),
        (62, "prefix/header boundary"),
        (88, "ciphertext"),
    ] {
        let s = [s1, S_A[RESP], S_A[COOKIE], 64];
        let plants = [(S_A[RESP], SAFE), (S_A[COOKIE], SAFE)];
        let message = canonical(400 - 64, TRANSPORT_TAG);
        // The first fixed seed whose tag at S1 can be a range of its own
        // (non-zero, clear of H2-H4), then the next seed, whose tag differs.
        let tag_at = |seed: u8| {
            decoded(
                &framed(&prefix(seed, 64, &plants, Some(KEY)), &message, Some(KEY)),
                s1,
                KEY,
            )
        };
        let usable = |d: u32| d != 0 && !(0x2000_0000..0x4000_0100).contains(&d);
        let seed1 = (9u8..).find(|&seed| usable(tag_at(seed))).unwrap();
        let (p1, p2) = (
            prefix(seed1, 64, &plants, Some(KEY)),
            prefix(seed1 + 1, 64, &plants, Some(KEY)),
        );
        // H1 is exactly what candidate 1 decodes to at S1.
        let (d1, d2) = (tag_at(seed1), tag_at(seed1 + 1));
        assert_ne!(d1, d2, "{}: the redraw moves the tag", label);
        let h = [(d1, d1), H_A[RESP], H_A[COOKIE], H_A[DATA]];
        let cfg = config(s, Some(KEY), true);
        let mut script = Script::of(&[p1.clone(), p2.clone()]);
        let wire = frame(&cfg, ranges(h), &message, &mut script);
        assert_eq!(
            upstream_first_match(&framed(&p1, &message, Some(KEY)), s, h, Some(KEY), true),
            Some(INIT),
            "{}",
            label
        );
        assert_eq!(wire, framed(&p2, &message, Some(KEY)), "{}", label);
        assert_eq!(script.drawn, 2 * WORDS_A, "{}", label);
    }
}

/// A control offset exactly at the transport type word reads the transport's
/// own tag through the mask that hid it -- an H4 value, never a control one.
#[test]
fn a_control_offset_at_the_transport_type_word_never_collides() {
    let s = [64, S_A[RESP], S_A[COOKIE], 64];
    let plants = [(S_A[RESP], SAFE), (S_A[COOKIE], SAFE)];
    let message = canonical(400 - 64, TRANSPORT_TAG);
    for seed in 11..14 {
        let p = prefix(seed, 64, &plants, Some(KEY));
        assert_eq!(
            decoded(&framed(&p, &message, Some(KEY)), 64, KEY),
            TRANSPORT_TAG
        );
        let mut script = Script::of(&[p.clone(), prefix(99, 64, &plants, Some(KEY))]);
        let wire = frame(
            &config(s, Some(KEY), true),
            ranges(H_A),
            &message,
            &mut script,
        );
        assert_eq!(wire, framed(&p, &message, Some(KEY)));
        assert_eq!(script.drawn, WORDS_A);
    }
}

// ---------------------------------------------------------------------------
// Exclusions: framing exactly as before, no extra randomness.
// ---------------------------------------------------------------------------

/// No header protection: upstream may well collide -- the tag is raw prefix
/// bytes -- but a redraw is not attempted.
#[test]
fn no_redraw_without_header_protection() {
    let p1 = prefix(20, 64, &[(S_A[INIT], H_A[INIT].0 + 1)], None);
    let message = canonical(400 - 64, TRANSPORT_TAG);
    let mut script = Script::of(&[p1.clone(), prefix(21, 64, &[], None)]);
    let wire = frame(&config(S_A, None, true), ranges(H_A), &message, &mut script);
    assert_eq!(
        upstream_first_match(&wire, S_A, H_A, None, true),
        Some(INIT)
    );
    assert_eq!(wire, framed(&p1, &message, None));
    assert_eq!(script.drawn, WORDS_A);
}

/// No control kind fits the length: nothing to check, nothing redrawn --
/// the keepalive and tiny-packet case.
#[test]
fn no_redraw_when_no_control_kind_fits_the_length() {
    // Below the smallest threshold (cookie: 36 + 64 = 100) with every reading
    // planted to collide.
    let p1 = prefix_a(22, &[INIT, RESP, COOKIE]);
    let (wire, drawn, message) = frame_a(true, 96, &[p1.clone(), prefix_a(23, &[])]);
    assert_eq!(upstream_a(&wire, true), Some(DATA));
    assert_eq!(wire, framed(&p1, &message, Some(KEY)));
    assert_eq!(drawn, WORDS_A);
}

/// Protocol imitation, every mode: the framing is exactly what it would be
/// with ranges that cannot collide, draw for draw, even though upstream would
/// misread it. Imitation prefixes carry little nonce entropy, so they are out
/// of scope until reviewed mode by mode.
#[test]
fn no_redraw_under_any_protocol_imitation() {
    // H1 covers almost the whole tag space, so a random tag at S1 collides.
    let wide = [
        (5, 0xffff_fe00),
        (0xffff_fe01, 0xffff_fe80),
        (0xffff_fe81, 0xffff_feff),
        (0xffff_ff00, 0xffff_ffff),
    ];
    let narrow = [
        (5, 5),
        (0xffff_fe01, 0xffff_fe80),
        (0xffff_fe81, 0xffff_feff),
        (0xffff_ff00, 0xffff_ffff),
    ];
    let s = [20, 28, 36, 200];
    let message = canonical(600, 0xffff_ff10);
    for protocol in [
        AmneziaImitationProtocol::Dns,
        AmneziaImitationProtocol::Quic,
        AmneziaImitationProtocol::Sip,
        AmneziaImitationProtocol::Stun,
    ] {
        let cfg = config(s, Some(KEY), true).with_protocol_imitation(protocol, None);
        let run = |h: [(u32, u32); 4]| {
            let mut rng = Counting {
                inner: ChaCha8Rng::seed_from_u64(77),
                words: 0,
            };
            let wire = frame(&cfg, ranges(h), &message, &mut rng);
            (wire, rng.words)
        };
        let (with_wide, words_wide) = run(wide);
        let (with_narrow, words_narrow) = run(narrow);
        assert_eq!(
            upstream_first_match(&with_wide, s, wide, Some(KEY), true),
            Some(INIT),
            "{:?}: an avoiding sender would have redrawn this",
            protocol
        );
        assert_eq!(with_wide, with_narrow, "{:?}: the same framing", protocol);
        assert_eq!(
            words_wide, words_narrow,
            "{:?}: the same randomness",
            protocol
        );
    }
}

// ---------------------------------------------------------------------------
// End to end through `Tunn`.
// ---------------------------------------------------------------------------

/// A handshaken pair under `cfg`/`h`; returns the initiator, the responder and
/// the handshake-confirmation keepalive the initiator sent.
fn tunnels(cfg: &AmneziaConfig, h: [(u32, u32); 4]) -> (Tunn, Tunn, Vec<u8>) {
    let a_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let b_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let a_public = x25519::PublicKey::from(&a_secret);
    let b_public = x25519::PublicKey::from(&b_secret);
    let obf = ranges(h);
    let mut a =
        Tunn::new_with_obfuscation(a_secret, b_public, None, None, 11, None, obf, cfg.clone())
            .unwrap();
    let mut b =
        Tunn::new_with_obfuscation(b_secret, a_public, None, None, 22, None, obf, cfg.clone())
            .unwrap();
    let (mut abuf, mut bbuf) = (vec![0u8; 4096], vec![0u8; 4096]);
    let init = match a.format_handshake_initiation(&mut abuf, false) {
        TunnResult::WriteToNetwork(d) => d.to_vec(),
        other => panic!("initiation: {:?}", other),
    };
    let response = match b.decapsulate(None, &init, &mut bbuf) {
        TunnResult::WriteToNetwork(d) => d.to_vec(),
        other => panic!("response: {:?}", other),
    };
    let keepalive = match a.decapsulate(None, &response, &mut abuf) {
        TunnResult::WriteToNetwork(d) => d.to_vec(),
        other => panic!("confirmation keepalive: {:?}", other),
    };
    assert!(
        matches!(b.decapsulate(None, &keepalive, &mut bbuf), TunnResult::Done),
        "the responder takes the confirmation keepalive"
    );
    (a, b, keepalive)
}

fn ipv4(len: usize, seq: u8) -> Vec<u8> {
    let mut p = vec![seq; len];
    p[0] = 0x45;
    p[1] = 0;
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 0, 0, 2]);
    p[16..20].copy_from_slice(&[10, 0, 0, 1]);
    p
}

/// Layout Q, for exact end-to-end runs. Every control offset sits inside the
/// 48-byte prefix, past the nonce (S1 = 16, S2 = 20, S3 = 12), so what an
/// upstream receiver reads for a control kind is a function of the prefix
/// alone. The cookie threshold (S3 + 64 = 76) is below every transport frame
/// (at least S4 + 32 = 80), so the cookie reading always applies, and H3
/// covers every tag but nine.
///
/// It is also pinned so that a send draws nothing but its S4 prefixes. H4 is
/// a single value, so the transport tag costs no draw. The padding range is a
/// single value, so padding costs no draw. The timer ranges are unset, so the
/// timer ticks cost none. Each framing candidate is therefore exactly
/// `WORDS_Q` consecutive words of the tunnel's RNG, and a test that seeds
/// that RNG knows every candidate before the send happens.
const S_Q: [usize; 4] = [16, 20, 12, 48];
const H_Q: [(u32, u32); 4] = [
    (0xffff_fffc, 0xffff_fffc),
    (0xffff_fffd, 0xffff_fffd),
    (5, 0xffff_fffb),
    (0xffff_ffff, 0xffff_ffff),
];
const PAD_Q: u32 = 16;
const WORDS_Q: usize = 48 / 4;
const CANDIDATES: usize = 16;

fn config_q() -> AmneziaConfig {
    config(S_Q, Some(KEY), true).with_content_padding_addition(PAD_Q, PAD_Q, 1420)
}

/// A handshaken layout-Q pair, the initiator drawing from a seeded RNG from
/// the moment it takes the response, which is when it frames the
/// handshake-confirmation keepalive. That keepalive is checked to exhaust all
/// sixteen framings (candidate 16 on the wire, transport counter 0) and to
/// change the initiator's timers exactly as the handshake-response path does,
/// and then the responder is given that exact datagram and must accept it.
fn seeded_tunnels(seed: u64) -> (Tunn, Tunn) {
    let cfg = config_q();
    let a_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let b_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let a_public = x25519::PublicKey::from(&a_secret);
    let b_public = x25519::PublicKey::from(&b_secret);
    let obf = ranges(H_Q);
    let mut a =
        Tunn::new_with_obfuscation(a_secret, b_public, None, None, 11, None, obf, cfg.clone())
            .unwrap();
    let mut b =
        Tunn::new_with_obfuscation(b_secret, a_public, None, None, 22, None, obf, cfg).unwrap();
    let (mut abuf, mut bbuf) = (vec![0u8; 4096], vec![0u8; 4096]);
    let init = match a.format_handshake_initiation(&mut abuf, false) {
        TunnResult::WriteToNetwork(d) => d.to_vec(),
        other => panic!("initiation: {:?}", other),
    };
    let response = match b.decapsulate(None, &init, &mut bbuf) {
        TunnResult::WriteToNetwork(d) => d.to_vec(),
        other => panic!("response: {:?}", other),
    };

    a.handshake.rng = ChaCha8Rng::seed_from_u64(seed);
    let now = set_now(&mut a, 1);
    let candidates = exhausting_candidates(&a);
    let (window_before, timers_before) = (a.udp_window(), timer_state(&a));
    let words_before = a.handshake.rng.get_word_pos();
    let confirmation = match a.decapsulate(None, &response, &mut abuf) {
        TunnResult::WriteToNetwork(d) => d.to_vec(),
        other => panic!("confirmation keepalive: {:?}", other),
    };
    assert_sent_candidate_sixteen(&a, words_before, &candidates, &confirmation, "confirmation");
    assert_eq!(counter_q(&confirmation), 0, "confirmation: counter 0");
    assert_eq!(a.tx_bytes, 0, "confirmation: no tx_bytes");
    assert_eq!(
        a.udp_window(),
        grown_window(window_before, a.amnezia.transport_window_observation(0)),
        "confirmation: one window observation"
    );
    // `commit_handshake_response`: the response counts as a packet received
    // and establishes the session (its slot's session timer too); it does
    // not tick the packet-sent or data-sent timers.
    let slot = a.current % N_SESSIONS;
    for (timer, what) in [
        (T_RECEIVED, "packet-received tick"),
        (T_ESTABLISHED, "session-established tick"),
    ] {
        assert_ne!(
            timers_before.named[timer], now,
            "fixture: {} observable",
            what
        );
        assert_eq!(timer_state(&a).named[timer], now, "confirmation: {}", what);
    }
    let mut expected = timers_before.clone();
    expected.named[T_RECEIVED] = now;
    expected.named[T_ESTABLISHED] = now;
    expected.sessions[slot] = now;
    assert_eq!(
        timer_state(&a),
        expected,
        "confirmation: no packet-sent or data-sent tick, nothing else moves"
    );

    // The responder takes candidate 16 through its ordinary receive path:
    // authenticated, counted as received, and counter 0 now spent.
    let b_now = set_now(&mut b, 5);
    assert!(
        matches!(
            b.decapsulate(None, &confirmation, &mut bbuf),
            TunnResult::Done
        ),
        "the responder accepts the confirmation keepalive"
    );
    assert_eq!(
        b.timers[TimerName::TimeLastPacketReceived],
        b_now,
        "the responder counted it as an authenticated packet"
    );
    // A replay is refused and counts as nothing received. (The error it
    // reports is not pinned: this frame is ambiguous by construction, so the
    // receiver tries its cookie reading after refusing the spent counter.)
    let later = set_now(&mut b, 6);
    assert!(
        matches!(
            b.decapsulate(None, &confirmation, &mut bbuf),
            TunnResult::Err(_)
        ),
        "the responder refuses a replay of it"
    );
    assert_ne!(b.timers[TimerName::TimeLastPacketReceived], later);
    assert_eq!(
        b.timers[TimerName::TimeLastPacketReceived],
        b_now,
        "counter 0 was spent by the first delivery"
    );
    (a, b)
}

/// The first `CANDIDATES` layout-Q framing prefixes `a` will draw from here,
/// computed from a clone of its RNG as the ordinary filler draws them (one
/// little-endian `next_u32` per 4 bytes), each checked against the
/// independent oracle before anything is sent: its cookie reading, under its
/// own nonce, falls in H3. So all sixteen are known to collide upstream
/// before the send, for every length a transport frame can have.
fn exhausting_candidates(a: &Tunn) -> Vec<Vec<u8>> {
    let mut replay = a.handshake.rng.clone();
    (1..=CANDIDATES)
        .map(|n| {
            let mut prefix = vec![0u8; S_Q[DATA]];
            for chunk in prefix.chunks_mut(4) {
                chunk.copy_from_slice(&replay.next_u32().to_le_bytes());
            }
            let tag = decoded(&prefix, S_Q[COOKIE], KEY);
            assert!(
                H_Q[COOKIE].0 <= tag && tag <= H_Q[COOKIE].1,
                "fixture: candidate {} of this seed must collide (cookie tag {:#x})",
                n,
                tag
            );
            prefix
        })
        .collect()
}

/// `wire` is candidate 16 of `candidates` and nothing else was drawn: the
/// send consumed exactly sixteen prefixes' worth of words from `before` (the
/// original framing plus fifteen redraws, no seventeenth), and the prefix on
/// the wire is the sixteenth. Each candidate, carrying the header recovered
/// from the wire, is misread by the independent upstream oracle, so the
/// sixteenth went out by exhaustion, not because it happened to be clean.
fn assert_sent_candidate_sixteen(
    a: &Tunn,
    before: u128,
    candidates: &[Vec<u8>],
    wire: &[u8],
    what: &str,
) {
    assert_eq!(
        a.handshake.rng.get_word_pos() - before,
        (CANDIDATES * WORDS_Q) as u128,
        "{}: exactly 16 framings drawn, the original included",
        what
    );
    assert!(
        wire.len() >= S_Q[COOKIE] + BASE[COOKIE],
        "{}: the cookie reading applies",
        what
    );
    assert_eq!(
        wire[..S_Q[DATA]],
        candidates[CANDIDATES - 1][..],
        "{}: candidate 16 is on the wire",
        what
    );
    let mut message = unmasked_header(wire, S_Q[DATA], KEY);
    message.extend_from_slice(&wire[S_Q[DATA] + 16..]);
    for (n, prefix) in candidates.iter().enumerate() {
        let candidate = framed(prefix, &message, Some(KEY));
        assert!(
            matches!(
                upstream_first_match(&candidate, S_Q, H_Q, Some(KEY), true),
                Some(kind) if kind != DATA
            ),
            "{}: candidate {} collides upstream",
            what,
            n + 1
        );
    }
}

/// The transport counter in a layout-Q datagram's canonical header.
fn counter_q(wire: &[u8]) -> u64 {
    let header = unmasked_header(wire, S_Q[DATA], KEY);
    assert_eq!(
        u32::from_le_bytes(header[..4].try_into().unwrap()),
        H_Q[DATA].0,
        "a transport frame"
    );
    u64::from_le_bytes(header[8..16].try_into().unwrap())
}

/// Stand in for `update_timers` having run at `secs` seconds. Every checked
/// send happens at its own distinct, nonzero time, so a tick that fires, is
/// missing, or fires twice is visible in the timer it writes.
fn set_now(t: &mut Tunn, secs: u64) -> Duration {
    let now = Duration::from_secs(secs);
    t.timers[TimerName::TimeCurrent] = now;
    now
}

const T_CURRENT: usize = 0;
const T_ESTABLISHED: usize = 1;
const T_RECEIVED: usize = 3;
const T_SENT: usize = 4;
const T_DATA_SENT: usize = 6;

/// Every timer a send could touch: the named timers (indexed by the `T_*`
/// constants), the per-session timers, the tunable deadlines and the
/// handshake attempt count.
#[derive(Clone, Debug, PartialEq)]
struct TimerState {
    named: Vec<Duration>,
    sessions: [Duration; N_SESSIONS],
    deadlines: [Duration; 5],
    handshake_attempts: u32,
}

fn timer_state(t: &Tunn) -> TimerState {
    use TimerName::*;
    let named = vec![
        TimeCurrent,
        TimeSessionEstablished,
        TimeLastHandshakeStarted,
        TimeLastPacketReceived,
        TimeLastPacketSent,
        TimeLastDataPacketReceived,
        TimeLastDataPacketSent,
        TimeCookieReceived,
        TimePersistentKeepalive,
    ];
    TimerState {
        named: named.into_iter().map(|n| t.timers[n]).collect(),
        sessions: t.timers.session_timers,
        deadlines: [
            t.timers.retransmit_current,
            t.timers.keepalive_current,
            t.timers.new_handshake_current,
            t.timers.rekey_after_current,
            t.timers.refresh_receive_current,
        ],
        handshake_attempts: t.timers.handshake_attempts,
    }
}

/// One ordinary send's timer transition, at `now`: the packet-sent tick; the
/// data-sent tick for data and not for a keepalive; and nothing else --
/// no other named timer, session timer, deadline or attempt count moves.
/// Each tick is asserted on its own first, so a missing, extra or repeated
/// tick fails on the timer it concerns.
fn assert_one_sends_timers(t: &Tunn, before: &TimerState, now: Duration, data: bool, what: &str) {
    assert_eq!(before.named[T_CURRENT], now, "fixture: {}: clock set", what);
    assert_ne!(
        before.named[T_SENT], now,
        "fixture: {}: packet-sent tick observable",
        what
    );
    assert_ne!(
        before.named[T_DATA_SENT], now,
        "fixture: {}: data-sent tick observable",
        what
    );
    let after = timer_state(t);
    assert_eq!(after.named[T_SENT], now, "{}: packet-sent tick", what);
    let data_sent = if data { now } else { before.named[T_DATA_SENT] };
    assert_eq!(
        after.named[T_DATA_SENT],
        data_sent,
        "{}: data-sent tick {}",
        what,
        if data {
            "on data"
        } else {
            "not on a keepalive"
        }
    );
    let mut expected = before.clone();
    expected.named[T_SENT] = now;
    expected.named[T_DATA_SENT] = data_sent;
    assert_eq!(after, expected, "{}: no other timer moves", what);
}

/// A send whose sixteen framings all collide -- known before the send, not
/// merely likely -- advances the tunnel exactly one send's worth: one
/// counter, from the confirmation keepalive's 0 on with no gap, one tx_bytes
/// update, one window observation, one send's timer ticks, the same session.
/// Candidate 16 goes out, and the peer decapsulates it to what was sent.
#[test]
fn an_exhausted_send_keeps_one_sends_worth_of_state_and_still_decapsulates() {
    let (mut a, mut b) = seeded_tunnels(0x5eed_0001);
    let (mut abuf, mut bbuf) = (vec![0u8; 4096], vec![0u8; 4096]);
    for (i, len) in [20usize, 84, 300, 700, 1392, 20, 1392, 576]
        .iter()
        .copied()
        .enumerate()
    {
        let packet = ipv4(len, i as u8);
        let now = set_now(&mut a, 2 + i as u64);
        let candidates = exhausting_candidates(&a);
        let (tx_before, window_before, current_before) = (a.tx_bytes, a.udp_window(), a.current);
        let (timers_before, words_before) = (timer_state(&a), a.handshake.rng.get_word_pos());
        let wire = match a.encapsulate(&packet, &mut abuf) {
            TunnResult::WriteToNetwork(d) => d.to_vec(),
            other => panic!("{}: {:?}", len, other),
        };
        assert_sent_candidate_sixteen(&a, words_before, &candidates, &wire, "application");
        assert_eq!(counter_q(&wire), 1 + i as u64, "{}: the next counter", len);
        assert_eq!(a.tx_bytes, tx_before + len, "{}: tx_bytes once", len);
        assert_eq!(
            a.udp_window(),
            grown_window(window_before, a.amnezia.transport_window_observation(len)),
            "{}: one window observation",
            len
        );
        assert_one_sends_timers(&a, &timers_before, now, true, "application");
        assert_eq!(a.current, current_before, "{}: same session", len);
        match b.decapsulate(None, &wire, &mut bbuf) {
            TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, &packet[..], "{}", len),
            other => panic!("{}: {:?}", len, other),
        }
    }
}

/// Keepalives go through the same framing and exhaust the same way. The
/// handshake-confirmation keepalive is counter 0 (and the responder accepts
/// it, see [`seeded_tunnels`]), the first application packet after it is 1,
/// an `encapsulate(&[])` keepalive 2 and the next packet 3: the retry loop
/// consumes no counter anywhere in that sequence. A keepalive adds no
/// tx_bytes and no data-sent tick, and the peer takes every one.
#[test]
fn keepalives_are_framed_the_same_way_and_still_arrive() {
    let (mut a, mut b) = seeded_tunnels(0x5eed_0002);
    let (mut abuf, mut bbuf) = (vec![0u8; 4096], vec![0u8; 4096]);

    for (counter, len) in [(1u64, Some(300usize)), (2, None), (3, Some(84))] {
        let packet = len.map(|l| ipv4(l, counter as u8)).unwrap_or_default();
        let what = if len.is_some() {
            "application"
        } else {
            "keepalive"
        };
        let now = set_now(&mut a, 1 + counter);
        let candidates = exhausting_candidates(&a);
        let (tx_before, window_before, current_before) = (a.tx_bytes, a.udp_window(), a.current);
        let (timers_before, words_before) = (timer_state(&a), a.handshake.rng.get_word_pos());
        let wire = match a.encapsulate(&packet, &mut abuf) {
            TunnResult::WriteToNetwork(d) => d.to_vec(),
            other => panic!("{}: {:?}", what, other),
        };
        assert_sent_candidate_sixteen(&a, words_before, &candidates, &wire, what);
        assert_eq!(counter_q(&wire), counter, "{}: no counter skipped", what);
        assert_eq!(a.tx_bytes, tx_before + packet.len(), "{}: tx_bytes", what);
        assert_eq!(
            a.udp_window(),
            grown_window(
                window_before,
                a.amnezia.transport_window_observation(packet.len())
            ),
            "{}: one window observation",
            what
        );
        assert_one_sends_timers(&a, &timers_before, now, len.is_some(), what);
        assert_eq!(a.current, current_before, "{}: same session", what);
        match (len, b.decapsulate(None, &wire, &mut bbuf)) {
            (Some(_), TunnResult::WriteToTunnelV4(p, _)) => assert_eq!(p, &packet[..]),
            (None, TunnResult::Done) => {}
            (_, other) => panic!("{}: {:?}", what, other),
        }
    }
}

/// The stock amneziawg-install profile, both RandomTrailers settings: tiny,
/// medium and near-MTU packets all decapsulate, and not one emitted frame is
/// misread upstream -- at about 5% per framing, a sixteen-framing exhaustion
/// has probability below 1e-18.
#[test]
fn the_stock_installer_profile_emits_no_upstream_collisions() {
    let s = [136, 59, 149, 16];
    let h = [
        (21806348, 121806347),
        (880390969, 980390968),
        (1131164401, 1231164400),
        (1662290386, 1762290385),
    ];
    for rt in [true, false] {
        let cfg = config(s, Some(KEY), rt).with_content_padding_addition(10, 100, 1420);
        let (mut a, mut b, _) = tunnels(&cfg, h);
        let (mut abuf, mut bbuf) = (vec![0u8; 4096], vec![0u8; 4096]);
        for i in 0..1500usize {
            let len = [20, 84, 300, 1000, 1392][i % 5];
            let packet = ipv4(len, i as u8);
            let wire = match a.encapsulate(&packet, &mut abuf) {
                TunnResult::WriteToNetwork(d) => d.to_vec(),
                other => panic!("{:?}", other),
            };
            assert_eq!(
                upstream_first_match(&wire, s, h, Some(KEY), rt),
                Some(DATA),
                "rt={} len={}: upstream would misread this frame",
                rt,
                len
            );
            match b.decapsulate(None, &wire, &mut bbuf) {
                TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, &packet[..]),
                other => panic!("rt={} len={}: {:?}", rt, len, other),
            }
        }
    }
}
