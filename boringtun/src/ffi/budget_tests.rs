// Copyright (c) 2026 Vadim Smirnov (doing business as WireSock). All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Output budgets of the `wireguard_*_ex` entry points, observed through the
//! exported C functions.
//!
//! `max_transport_output` bounds transport data and keepalives,
//! `max_control_output` initiations, responses, junk and imitation; 0 is
//! unbounded, per field and per call. A mandatory datagram over a finite
//! budget is error 18, which wins over a short `dst` (error 0); optional
//! padding shrinks to what both leave. Every success here is checked the way
//! a peer checks it -- by decrypting it, or by completing the handshake it
//! carries -- not by its opcode.
//!
//! Crate-internal reads are limited to what the tunnel holds and the C API
//! cannot show: the tick's spent and restored demands, the queue length, the
//! next imitation datagram, the generator position, and the UDP window. The
//! one write is the test-only optional-draw word (`amnezia::OPTIONAL_DRAW_WORD`),
//! which makes a capped RandomTrailers draw observable as a size.
//!
//! The recipes and their numbers are the accepted budget contract's (WRS-225
//! P1-prime budget V5, sections 4, 5.4 and 11), with the metadata contract's
//! restoration rules (V3 4.4/4.5).

use super::*;
use crate::noise::amnezia::OPTIONAL_DRAW_WORD;
use crate::noise::op_report::{event as ev, state as st, PacketKind, BURST_DUE_NONE};
use crate::noise::rate_limiter::RateLimiter;
use std::convert::TryInto;
use std::sync::Arc;
use std::time::Duration;

const DONE: u32 = 0;
const WTN: u32 = 1;
const ERR: u32 = 2;
const WTT4: u32 = 4;

/// `wireguard_result.size` of the two capacity refusals.
const STORAGE: usize = 0;
const BUDGET: usize = 18;

/// The header's values for the two budget events.
const QUEUE_HEAD_DROPPED: u32 = 0x0001_0000;
const BURST_ITEM_SKIPPED: u32 = 0x0002_0000;

type Tunnel = *mut Mutex<Tunn>;

/// A tunnel freed on drop.
struct Owned(Tunnel);

impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { tunnel_free(self.0) }
    }
}

impl Owned {
    /// A short lock for a crate-internal read; released before the next call.
    fn with<R>(&self, f: impl FnOnce(&Tunn) -> R) -> R {
        f(&unsafe { &*self.0 }.lock())
    }
}

struct Party {
    secret: StaticSecret,
    public: PublicKey,
}

fn party() -> Party {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    Party { secret, public }
}

fn b64(bytes: &[u8]) -> CString {
    CString::new(BASE64.encode(bytes)).unwrap()
}

fn built(t: Tunnel) -> Owned {
    if t.is_null() {
        let e = last_tunnel_error();
        let why = if e.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(e) }.to_string_lossy().into_owned()
        };
        panic!("constructor refused: {}", why);
    }
    Owned(t)
}

/// Plain WireGuard through the oldest constructor.
fn plain(me: &Party, peer: &Party, index: u32, keep_alive: u16) -> Owned {
    built(unsafe {
        new_tunnel(
            b64(&me.secret.to_bytes()).as_ptr(),
            b64(peer.public.as_bytes()).as_ptr(),
            ptr::null(),
            keep_alive,
            index,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    })
}

fn awg_with(
    me: &Party,
    peer: &Party,
    index: u32,
    keep_alive: u16,
    params: &wireguard_awg_params,
    domain: Option<&str>,
) -> Owned {
    let domain = domain.map(|d| CString::new(d).unwrap());
    built(unsafe {
        new_tunnel_with_awg_params(
            b64(&me.secret.to_bytes()).as_ptr(),
            b64(peer.public.as_bytes()).as_ptr(),
            ptr::null(),
            keep_alive,
            index,
            params,
            domain.as_ref().map_or(ptr::null(), |d| d.as_ptr()),
        )
    })
}

fn awg(me: &Party, peer: &Party, index: u32, params: &wireguard_awg_params) -> Owned {
    awg_with(me, peer, index, 0, params, None)
}

fn params() -> wireguard_awg_params {
    wireguard_awg_params {
        size: AWG_PARAMS_SIZE_VER2 as u32,
        ..Default::default()
    }
}

fn range(v: u32) -> wireguard_awg_range {
    wireguard_awg_range { lo: v, hi: v }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Res {
    op: u32,
    size: usize,
}

fn res(r: wireguard_result) -> Res {
    Res {
        op: r.op as u32,
        size: r.size,
    }
}

#[derive(Clone, Copy)]
enum Op<'a> {
    Write(&'a [u8]),
    Read(&'a [u8]),
    Tick,
    Force,
}

/// The drain input: empty, from a non-NULL pointer.
const EMPTY: &[u8] = &[];

unsafe fn raw_call(t: Tunnel, op: Op, dst: &mut [u8], info: *mut wireguard_packet_info) -> Res {
    let (d, dl) = (dst.as_mut_ptr(), dst.len() as u32);
    res(match op {
        Op::Write(s) => wireguard_write_ex(t, s.as_ptr(), s.len() as u32, d, dl, info),
        Op::Read(s) => wireguard_read_ex(t, s.as_ptr(), s.len() as u32, d, dl, info),
        Op::Tick => wireguard_tick_ex(t, d, dl, info),
        Op::Force => wireguard_force_handshake_ex(t, d, dl, info),
    })
}

/// A legacy call: the peer side of every exchange, and setup.
fn legacy(t: &Owned, op: Op, dst: &mut [u8]) -> Res {
    let (d, dl, t) = (dst.as_mut_ptr(), dst.len() as u32, t.0);
    res(unsafe {
        match op {
            Op::Write(s) => wireguard_write(t, s.as_ptr(), s.len() as u32, d, dl),
            Op::Read(s) => wireguard_read(t, s.as_ptr(), s.len() as u32, d, dl),
            Op::Tick => wireguard_tick(t, d, dl),
            Op::Force => wireguard_force_handshake(t, d, dl),
        }
    })
}

/// One `_ex` call with `max_transport_output = bt`, `max_control_output = bc`.
/// The call must have run -- metadata published, the inputs untouched -- and
/// this slice never reports a skipped burst item.
fn exb(t: &Owned, op: Op, dst: &mut [u8], bt: u32, bc: u32) -> (Res, wireguard_packet_info) {
    exf(t, op, dst, 0, bt, bc)
}

/// `exb` with `in_flags = flags`.
fn exf(
    t: &Owned,
    op: Op,
    dst: &mut [u8],
    flags: u32,
    bt: u32,
    bc: u32,
) -> (Res, wireguard_packet_info) {
    let mut info = wireguard_packet_info {
        size: WIREGUARD_PACKET_INFO_SIZE_V1,
        in_flags: flags,
        max_transport_output: bt,
        max_control_output: bc,
        ..Default::default()
    };
    let r = unsafe { raw_call(t.0, op, dst, &mut info) };
    assert_eq!(
        info.written_size, 48,
        "the call ran and published (flags {:#x}, bt {}, bc {}): got {:?}",
        flags, bt, bc, r
    );
    assert_eq!(
        (
            info.size,
            info.in_flags,
            info.max_transport_output,
            info.max_control_output
        ),
        (48, flags, bt, bc),
        "inputs are never written"
    );
    assert_eq!(
        info.events & BURST_ITEM_SKIPPED,
        0,
        "no item is ever skipped"
    );
    (r, info)
}

/// `exb` with both budgets 0.
fn ex(t: &Owned, op: Op, dst: &mut [u8]) -> (Res, wireguard_packet_info) {
    exb(t, op, dst, 0, 0)
}

/// (input_kind, output_kind, events, state) as reported.
fn facts(i: &wireguard_packet_info) -> (u32, u32, u32, u32) {
    (i.input_kind, i.output_kind, i.events, i.state)
}

fn k(kind: PacketKind) -> u32 {
    kind as u32
}

fn op_seq(i: &wireguard_packet_info) -> u64 {
    (u64::from(i.op_seq_hi) << 32) | u64::from(i.op_seq_lo)
}

/// A UDP/IPv4 packet carrying `tag`.
fn ipv4(tag: u32, len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 0, 0, 1]);
    p[16..20].copy_from_slice(&[10, 0, 0, 2]);
    p[20..24].copy_from_slice(&tag.to_be_bytes());
    p
}

fn tag_of(p: &[u8]) -> u32 {
    u32::from_be_bytes(p[20..24].try_into().unwrap())
}

/// The sending counter of an unprefixed (S4 0) transport frame.
fn counter_of(frame: &[u8]) -> u64 {
    u64::from_le_bytes(frame[8..16].try_into().unwrap())
}

fn tx_bytes(t: &Owned) -> usize {
    unsafe { wireguard_stats(t.0) }.tx_bytes
}

/// `peer` decrypts `datagram`: the plaintext's tag and length.
fn delivered(peer: &Owned, datagram: &[u8]) -> (u32, usize) {
    let mut buf = vec![0u8; 2048];
    let r = legacy(peer, Op::Read(datagram), &mut buf);
    assert_eq!(r.op, WTT4, "the peer authenticates and decrypts it");
    (tag_of(&buf[..r.size]), r.size)
}

/// `peer` reads `datagram` and returns the datagram it answers with.
fn answered(peer: &Owned, datagram: &[u8], dst_len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; dst_len];
    let r = legacy(peer, Op::Read(datagram), &mut buf);
    assert_eq!(r.op, WTN, "the peer accepts it and answers");
    buf[..r.size].to_vec()
}

fn read_done(peer: &Owned, datagram: &[u8]) {
    let mut buf = vec![0u8; 2048];
    assert_eq!(
        legacy(peer, Op::Read(datagram), &mut buf),
        Res { op: DONE, size: 0 }
    );
}

fn advance(d: Duration) {
    #[cfg(feature = "mock-instant")]
    mock_instant::thread_local::MockClock::advance(d);
    #[cfg(not(feature = "mock-instant"))]
    std::thread::sleep(d);
}

/// The thread-local mock clock, set absolutely.
#[cfg(feature = "mock-instant")]
fn at(t: Duration) {
    mock_instant::thread_local::MockClock::set_time(t);
}

#[cfg(feature = "mock-instant")]
fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

/// `client` initiates (no burst) and both ends end up with a current
/// session, through legacy calls.
fn establish(client: &Owned, server: &Owned) {
    let mut cb = vec![0u8; 2048];
    let r = legacy(client, Op::Force, &mut cb);
    assert_eq!(r.op, WTN);
    let resp = answered(server, &cb[..r.size], 2048);
    let keepalive = answered(client, &resp, 2048);
    read_done(server, &keepalive);
}

/// The client's want_handshake, want_keepalive and persistent-keepalive stamp.
#[cfg(feature = "mock-instant")]
fn demands(t: &Owned) -> (bool, bool, Duration) {
    t.with(|t| t.timer_demands())
}

// ---------------------------------------------------------------------------
// The two fields: admission, independence, no persistence
// ---------------------------------------------------------------------------

/// The header names the budget refusal 18, next to the 19 it is not.
#[test]
fn the_header_names_the_budget_refusal_18() {
    let header = include_str!("../wireguard_ffi.h");
    let define = header
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("#define WIREGUARD_ERROR_OUTPUT_BUDGET_EXCEEDED "))
        .expect("WIREGUARD_ERROR_OUTPUT_BUDGET_EXCEEDED is defined");
    assert!(
        define.split_whitespace().nth(2) == Some("18u"),
        "{}",
        define
    );
    assert!(header.contains("#define WIREGUARD_EV_QUEUE_HEAD_DROPPED 0x00010000u"));
    assert!(header.contains("#define WIREGUARD_EV_BURST_ITEM_SKIPPED 0x00020000u"));
}

/// A nonzero budget runs the operation; each field bounds only its own kinds;
/// and a call's budget is its own -- a zero, NULL or legacy call right after a
/// finite one is unbounded again. Every call takes one sequence number, the
/// refused one included.
#[test]
fn budgets_are_independent_and_belong_to_one_call() {
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let server = plain(&b, &a, 2, 0);
    establish(&client, &server);
    let mut dst = vec![0u8; 2048];
    // 1169 bytes: mandatory 1201, rounded to 1184 + 32 = 1216 when unbounded.
    let p = ipv4(1, 1169);

    let (r, i) = exb(&client, Op::Write(&p), &mut dst, 1200, 0);
    assert_eq!((r.op, r.size), (ERR, BUDGET));
    assert_eq!(facts(&i), (0, 0, 0, st::SESSION_CURRENT));
    assert_eq!(i.burst_due_ms, BURST_DUE_NONE);
    let seq = op_seq(&i);

    // Zero budgets: unbounded.
    let (r, i) = ex(&client, Op::Write(&p), &mut dst);
    assert_eq!((r.op, r.size), (WTN, 1216));
    assert_eq!(op_seq(&i), seq + 1);
    assert_eq!(delivered(&server, &dst[..r.size]), (1, 1169));
    // Legacy and NULL, after a finite call: unbounded.
    let r = legacy(&client, Op::Write(&p), &mut dst);
    assert_eq!((r.op, r.size), (WTN, 1216));
    delivered(&server, &dst[..r.size]);
    let r = unsafe { raw_call(client.0, Op::Write(&p), &mut dst, ptr::null_mut()) };
    assert_eq!((r.op, r.size), (WTN, 1216));
    delivered(&server, &dst[..r.size]);
    // A control budget does not bound transport.
    let (r, i) = exb(&client, Op::Write(&p), &mut dst, 0, 1);
    assert_eq!((r.op, r.size), (WTN, 1216));
    assert_eq!(op_seq(&i), seq + 4, "legacy and NULL calls are counted");
    delivered(&server, &dst[..r.size]);
    // A transport budget clips the optional padding, down to none at M.
    for (bt, out) in [(1216, 1216), (1215, 1215), (1201, 1201)] {
        let (r, i) = exb(&client, Op::Write(&p), &mut dst, bt, 0);
        assert_eq!((r.op, r.size), (WTN, out), "bt {}", bt);
        assert_eq!(i.output_kind, k(PacketKind::TransportData));
        assert_eq!(delivered(&server, &dst[..r.size]), (1, 1169));
    }
    let (r, _) = exb(&client, Op::Write(&p), &mut dst, 1200, 1200);
    assert_eq!((r.op, r.size), (ERR, BUDGET));

    // A transport budget does not bound control output.
    let (c, s) = (party(), party());
    let fresh = plain(&c, &s, 3, 0);
    let (r, i) = exb(&fresh, Op::Force, &mut dst, 1, 0);
    assert_eq!(
        (r.op, r.size, i.output_kind),
        (WTN, 148, k(PacketKind::HandshakeInitiation))
    );
}

const CANARY: u8 = 0xA5;

fn put(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_ne_bytes());
}

fn get(buf: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap())
}

/// Budgets ride the existing memory protocol unchanged: read unaligned, never
/// written, and a malformed record is still error 19 before anything runs --
/// no sequence number, no admission, no byte written -- whatever the budgets.
#[test]
fn budgets_keep_the_memory_protocol() {
    let (a, b) = (party(), party());
    let t = plain(&a, &b, 1, 0);
    let mut dst = vec![0u8; 2048];
    let seq_of = |t: &Owned| unsafe { (*t.0).lock().op_state_mut().op_seq() };
    for at in 0..4 {
        let mut buf = vec![CANARY; 1024 + 64];
        type Shape = fn(&mut [u8]);
        let refused: [(&str, Shape); 4] = [
            ("size 44", |m| {
                put(m, 0, 44);
                put(m, 8, 1400);
                put(m, 12, 200);
            }),
            ("in_flags", |m| {
                put(m, 0, 48);
                put(m, 4, 2);
                put(m, 8, 1400);
                put(m, 12, 200);
            }),
            ("tail byte", |m| {
                put(m, 0, 64);
                put(m, 4, 0);
                put(m, 8, 1400);
                put(m, 12, 200);
                m[48..64].fill(0);
                m[63] = 1;
            }),
            ("size max", |m| {
                put(m, 0, u32::MAX);
                put(m, 8, 1);
            }),
        ];
        for (name, shape) in refused {
            buf.fill(CANARY);
            shape(&mut buf[at..]);
            let before = buf.clone();
            let seq = seq_of(&t);
            let queued = t.with(|t| t.queued_len());
            let r = unsafe {
                raw_call(
                    t.0,
                    Op::Write(&ipv4(1, 40)),
                    &mut dst,
                    buf[at..].as_mut_ptr() as *mut wireguard_packet_info,
                )
            };
            assert_eq!((r.op, r.size), (ERR, 19), "offset {} {}", at, name);
            assert_eq!(buf, before, "offset {} {}: nothing written", at, name);
            assert_eq!(seq_of(&t), seq, "offset {} {}: no sequence", at, name);
            assert_eq!(t.with(|t| t.queued_len()), queued, "{}: not admitted", name);
        }

        for (size, bt, bc) in [
            (48u32, 1400u32, 0u32),
            (48, 0, 200),
            (64, 1, 1),
            (1024, u32::MAX, u32::MAX),
        ] {
            buf.fill(CANARY);
            put(&mut buf[at..], 0, size);
            put(&mut buf[at..], 4, 0);
            put(&mut buf[at..], 8, bt);
            put(&mut buf[at..], 12, bc);
            buf[at + 48..at + size as usize].fill(0);
            let before = buf.clone();
            let seq = seq_of(&t);
            let r = unsafe {
                raw_call(
                    t.0,
                    Op::Tick,
                    &mut dst,
                    buf[at..].as_mut_ptr() as *mut wireguard_packet_info,
                )
            };
            assert_eq!((r.op, r.size), (DONE, 0), "offset {} size {}", at, size);
            assert_eq!(&buf[..at + 16], &before[..at + 16], "inputs untouched");
            assert_eq!(&buf[at + 48..], &before[at + 48..], "tail untouched");
            let m = &buf[at..];
            assert_eq!(get(m, 16), 48, "written_size");
            assert_eq!((get(m, 8), get(m, 12)), (bt, bc));
            assert_eq!(
                (u64::from(get(m, 40)) << 32) | u64::from(get(m, 36)),
                seq + 1
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Transport: established writes, the response keepalive, decryption
// ---------------------------------------------------------------------------

/// Established writes against a finite transport budget of 1200 (BUD-ARITH-01,
/// BUD-WRITE-01): equality fits, one over is 18, 18 wins over a short `dst`,
/// a short `dst` alone is 0, and padding is clipped to what both leave. A
/// refusal consumes no nonce and counts no sent bytes: the counters of the
/// three outputs are contiguous.
#[test]
fn a_transport_budget_bounds_established_writes() {
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let server = plain(&b, &a, 2, 0);
    establish(&client, &server);
    let mut dst = vec![0u8; 2048];
    let mut counters = Vec::new();
    let mut tags = Vec::new();
    let tx0 = tx_bytes(&client);

    let steps: [(u32, usize, usize, Res); 6] = [
        (1, 100, 2048, Res { op: WTN, size: 144 }),
        (
            2,
            1168,
            2048,
            Res {
                op: WTN,
                size: 1200,
            },
        ),
        (
            3,
            1169,
            2048,
            Res {
                op: ERR,
                size: BUDGET,
            },
        ),
        (
            4,
            1170,
            1000,
            Res {
                op: ERR,
                size: BUDGET,
            },
        ),
        (
            5,
            1100,
            1100,
            Res {
                op: ERR,
                size: STORAGE,
            },
        ),
        (
            5,
            1100,
            1132,
            Res {
                op: WTN,
                size: 1132,
            },
        ),
    ];
    for (tag, len, d, want) in steps {
        let tx = tx_bytes(&client);
        let (r, i) = exb(&client, Op::Write(&ipv4(tag, len)), &mut dst[..d], 1200, 0);
        assert_eq!(r, want, "tag {} len {} dst {}", tag, len, d);
        if r.op == WTN {
            assert_eq!(
                facts(&i),
                (0, k(PacketKind::TransportData), 0, st::SESSION_CURRENT)
            );
            counters.push(counter_of(&dst[..r.size]));
            tags.push(delivered(&server, &dst[..r.size]).0);
        } else {
            assert_eq!(facts(&i), (0, 0, 0, st::SESSION_CURRENT));
            assert_eq!(tx_bytes(&client), tx, "a refusal sends nothing");
        }
    }
    assert_eq!(tags, [1, 2, 5]);
    assert_eq!(counters, [counters[0], counters[0] + 1, counters[0] + 2]);
    assert_eq!(tx_bytes(&client) - tx0, 100 + 1168 + 1100);
}

/// S4 counts: with S4 16 and a fixed 8-byte padding addition, a 100-byte
/// plaintext is 148 mandatory and 156 padded (BUD-PAD-01).
#[test]
fn the_transport_budget_counts_the_s4_prefix_and_clips_padding() {
    let (a, b) = (party(), party());
    let pad = wireguard_awg_params {
        s4_transport_junk: 16,
        content_padding_addition: range(8),
        content_padding_mtu: 1420,
        ..params()
    };
    let client = awg(&a, &b, 1, &pad);
    let server = awg(&b, &a, 2, &pad);
    establish(&client, &server);
    let mut dst = vec![0u8; 2048];
    for (bt, want) in [(156, WTN), (150, WTN), (148, WTN), (147, ERR)] {
        let (r, _) = exb(&client, Op::Write(&ipv4(7, 100)), &mut dst, bt, 0);
        if want == WTN {
            assert_eq!((r.op, r.size), (WTN, bt as usize), "bt {}", bt);
            assert_eq!(delivered(&server, &dst[..r.size]), (7, 100));
        } else {
            assert_eq!((r.op, r.size), (ERR, BUDGET), "bt {}", bt);
        }
    }
    let (r, _) = ex(&client, Op::Write(&ipv4(8, 100)), &mut dst);
    assert_eq!((r.op, r.size), (WTN, 156), "unbounded");
}

/// The keepalive a response produces (BUD-READ-03): with S4 100 it is 132
/// bytes; a transport budget of 131 refuses it before the response is
/// consumed, so the same response then goes through. A short `dst` alone is
/// 0, and both short is 18; each leaves the response retryable.
#[test]
fn the_response_keepalive_obeys_the_transport_budget_and_stays_retryable() {
    let s4 = wireguard_awg_params {
        s4_transport_junk: 100,
        ..params()
    };
    for (d, bt, want) in [(2048, 131, BUDGET), (131, 0, STORAGE), (131, 131, BUDGET)] {
        let (a, b) = (party(), party());
        let client = awg(&a, &b, 1, &s4);
        let server = awg(&b, &a, 2, &s4);
        let mut cb = vec![0u8; 2048];
        let r = legacy(&client, Op::Force, &mut cb);
        let resp = answered(&server, &cb[..r.size], 2048);

        let (r, i) = exb(&client, Op::Read(&resp), &mut cb[..d], bt, 0);
        assert_eq!((r.op, r.size), (ERR, want), "d {} bt {}", d, bt);
        assert_eq!(facts(&i), (0, 0, 0, st::INITIATION_PENDING));

        let (r, i) = exb(&client, Op::Read(&resp), &mut cb, 132, 0);
        assert_eq!((r.op, r.size), (WTN, 132), "the same response, retried");
        assert_eq!(
            facts(&i),
            (
                k(PacketKind::HandshakeResponse),
                k(PacketKind::TransportKeepalive),
                ev::INPUT_ACCEPTED
                    | ev::PEER_AUTHENTICATED
                    | ev::SESSION_STORED
                    | ev::CURRENT_SESSION_CHANGED,
                st::SESSION_CURRENT
            )
        );
        read_done(&server, &cb[..r.size]);
    }
}

/// Decrypted plaintext is not output to the network: tiny budgets do not
/// bound it (BUD-READ-01).
#[test]
fn decrypted_plaintext_is_never_budgeted() {
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let server = plain(&b, &a, 2, 0);
    establish(&client, &server);
    let mut sb = vec![0u8; 2048];
    let r = legacy(&server, Op::Write(&ipv4(9, 1400)), &mut sb);
    let data = sb[..r.size].to_vec();
    let mut cb = vec![0u8; 1500];
    let (r, i) = exb(&client, Op::Read(&data), &mut cb, 1, 1);
    assert_eq!((r.op, r.size), (WTT4, 1400));
    assert_eq!(tag_of(&cb[..r.size]), 9);
    assert_eq!(
        facts(&i),
        (
            k(PacketKind::TransportData),
            0,
            ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED,
            st::SESSION_CURRENT
        )
    );
}

// ---------------------------------------------------------------------------
// The plaintext queue: admission, and draining with a finite transport budget
// ---------------------------------------------------------------------------

/// A plain pair whose client queued `sizes` (tags 1..) before any session --
/// the first write returns the initiation, the rest DONE -- and then
/// completed the handshake without draining.
fn queued_pair(sizes: &[usize]) -> (Owned, Owned) {
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let server = plain(&b, &a, 2, 0);
    let mut cb = vec![0u8; 2048];
    let mut init = None;
    for (n, &len) in sizes.iter().enumerate() {
        let r = legacy(&client, Op::Write(&ipv4(n as u32 + 1, len)), &mut cb);
        if n == 0 {
            assert_eq!((r.op, r.size), (WTN, 148));
            init = Some(cb[..r.size].to_vec());
        } else {
            assert_eq!(r.op, DONE);
        }
    }
    let resp = answered(&server, &init.unwrap(), 2048);
    let keepalive = answered(&client, &resp, 2048);
    read_done(&server, &keepalive);
    assert_eq!(client.with(|t| t.queued_len()), sizes.len());
    (client, server)
}

/// One drain with these bounds: the result, the facts, and the delivered tag
/// when it emitted.
fn drain(
    client: &Owned,
    server: &Owned,
    d: usize,
    bt: u32,
    bc: u32,
) -> (Res, (u32, u32, u32, u32), Option<u32>) {
    let mut dst = vec![0u8; d];
    let (r, i) = exb(client, Op::Read(EMPTY), &mut dst, bt, bc);
    let tag = (r.op == WTN).then(|| delivered(server, &dst[..r.size]).0);
    (r, facts(&i), tag)
}

const DATA: u32 = PacketKind::TransportData as u32;
const CUR: u32 = st::SESSION_CURRENT;
const CUR_Q: u32 = st::SESSION_CURRENT | st::QUEUE_NONEMPTY;

/// BUD-QUEUE-02: (a) an oversized head is deleted and the next one emitted in
/// the same call; (b) its zero-budget twin keeps the head (storage only);
/// (c) deleting the only head returns DONE with the event, and the next
/// drain reports nothing. Deletion consumes no nonce and sends nothing.
#[test]
fn an_oversized_queue_head_is_deleted_and_reported() {
    // (a)
    let (client, server) = queued_pair(&[1400, 100]);
    let (r, f, tag) = drain(&client, &server, 1232, 1200, 0);
    assert_eq!(r, Res { op: WTN, size: 144 });
    assert_eq!(f, (0, DATA, QUEUE_HEAD_DROPPED, CUR));
    assert_eq!(tag, Some(2));
    let (r, f, _) = drain(&client, &server, 2048, 0, 0);
    assert_eq!((r.op, f), (DONE, (0, 0, 0, CUR)));

    // (b)
    let (client, server) = queued_pair(&[1400, 100]);
    let (r, f, _) = drain(&client, &server, 1232, 0, 0);
    assert_eq!(
        (r, f),
        (
            Res {
                op: ERR,
                size: STORAGE
            },
            (0, 0, 0, CUR_Q)
        )
    );
    let (r, _, tag) = drain(&client, &server, 2048, 0, 0);
    assert_eq!(
        (r, tag),
        (
            Res {
                op: WTN,
                size: 1440
            },
            Some(1)
        )
    );
    let (r, _, tag) = drain(&client, &server, 2048, 0, 0);
    assert_eq!((r, tag), (Res { op: WTN, size: 144 }, Some(2)));

    // (c)
    let (client, server) = queued_pair(&[1400]);
    let tx = tx_bytes(&client);
    let (r, f, _) = drain(&client, &server, 2048, 1200, 0);
    assert_eq!((r.op, f), (DONE, (0, 0, QUEUE_HEAD_DROPPED, CUR)));
    assert_eq!(client.with(|t| t.queued_len()), 0);
    assert_eq!(tx_bytes(&client), tx, "a deletion sends nothing");
    let (r, f, _) = drain(&client, &server, 2048, 1200, 0);
    assert_eq!((r.op, f), (DONE, (0, 0, 0, CUR)));
    // The response keepalive used counter 0; the deletion used none.
    let mut cb = vec![0u8; 2048];
    let r = legacy(&client, Op::Write(&ipv4(9, 40)), &mut cb);
    assert_eq!(counter_of(&cb[..r.size]), 1);
    assert_eq!(delivered(&server, &cb[..r.size]).0, 9);
}

/// BUD-QUEUE-03: the same D 1000 / B_t 1200 for every drain. Two deletions
/// then an emission, one deletion then an emission, then nothing -- tags 3
/// and 5 only, once each, with contiguous counters.
#[test]
fn several_deletions_then_one_emission_per_call() {
    let (client, server) = queued_pair(&[1400, 1400, 100, 1300, 50]);
    let (r, f, tag) = drain(&client, &server, 1000, 1200, 0);
    assert_eq!(
        (r, f, tag),
        (
            Res { op: WTN, size: 144 },
            (0, DATA, QUEUE_HEAD_DROPPED, CUR_Q),
            Some(3)
        )
    );
    let (r, f, tag) = drain(&client, &server, 1000, 1200, 0);
    assert_eq!(
        (r, f, tag),
        (
            Res { op: WTN, size: 96 },
            (0, DATA, QUEUE_HEAD_DROPPED, CUR),
            Some(5)
        )
    );
    let (r, f, _) = drain(&client, &server, 1000, 1200, 0);
    assert_eq!((r.op, f), (DONE, (0, 0, 0, CUR)));
}

/// BUD-QUEUE-04 and M-CE-3: a head equal to the budget is emitted, not
/// deleted; a fitting head short of storage stays queued with 0, after any
/// deletions in front of it, which the 0 still reports.
#[test]
fn storage_never_deletes_and_equality_fits() {
    let (client, server) = queued_pair(&[1168, 1100]);
    let (r, f, tag) = drain(&client, &server, 2048, 1200, 0);
    assert_eq!(
        (r, f, tag),
        (
            Res {
                op: WTN,
                size: 1200
            },
            (0, DATA, 0, CUR_Q),
            Some(1)
        )
    );
    let (r, f, _) = drain(&client, &server, 1100, 1200, 0);
    assert_eq!(
        (r, f),
        (
            Res {
                op: ERR,
                size: STORAGE
            },
            (0, 0, 0, CUR_Q)
        )
    );
    let (r, f, tag) = drain(&client, &server, 2048, 1200, 0);
    assert_eq!(
        (r, f, tag),
        (
            Res {
                op: WTN,
                size: 1136
            },
            (0, DATA, 0, CUR),
            Some(2)
        )
    );
    let (r, _, _) = drain(&client, &server, 2048, 1200, 0);
    assert_eq!(r.op, DONE);

    // M-CE-3, and the same with two deletions in front.
    for sizes in [&[1400, 1100][..], &[1400, 1400, 1100][..]] {
        let (client, server) = queued_pair(sizes);
        let (r, f, _) = drain(&client, &server, 1000, 1200, 0);
        assert_eq!(
            (r, f),
            (
                Res {
                    op: ERR,
                    size: STORAGE
                },
                (0, 0, QUEUE_HEAD_DROPPED, CUR_Q)
            )
        );
        assert_eq!(client.with(|t| t.queued_len()), 1);
        let (r, f, tag) = drain(&client, &server, 2048, 1200, 0);
        let last = sizes.len() as u32;
        assert_eq!(
            (r, f, tag),
            (
                Res {
                    op: WTN,
                    size: 1136
                },
                (0, DATA, 0, CUR),
                Some(last)
            )
        );
        let (r, _, _) = drain(&client, &server, 2048, 1200, 0);
        assert_eq!(r.op, DONE);
    }
}

/// Deletion needs a finite transport budget and a current session: a control
/// budget alone (BUD-MODE-02 b) or no session leaves every head where it is.
/// A full queue of oversized heads goes in one call.
#[test]
fn deletion_needs_a_transport_budget_and_a_session() {
    let (client, server) = queued_pair(&[1400]);
    let (r, f, _) = drain(&client, &server, 1232, 0, 1200);
    assert_eq!(
        (r, f),
        (
            Res {
                op: ERR,
                size: STORAGE
            },
            (0, 0, 0, CUR_Q)
        )
    );
    let (r, _, tag) = drain(&client, &server, 2048, 0, 1200);
    assert_eq!(
        (r, tag),
        (
            Res {
                op: WTN,
                size: 1440
            },
            Some(1)
        )
    );

    // No session: the drain drives the handshake and touches no head.
    let (a, b) = (party(), party());
    let lone = plain(&a, &b, 1, 0);
    let mut dst = vec![0u8; 2048];
    for (n, want) in [(1, WTN), (2, DONE)] {
        assert_eq!(legacy(&lone, Op::Write(&ipv4(n, 1400)), &mut dst).op, want);
    }
    let (r, i) = exb(&lone, Op::Read(EMPTY), &mut dst, 100, 0);
    assert_eq!(
        (r.op, facts(&i)),
        (DONE, (0, 0, 0, st::INITIATION_PENDING | st::QUEUE_NONEMPTY))
    );
    assert_eq!(lone.with(|t| t.queued_len()), 2);

    // 256 oversized heads, one call.
    let (client, server) = queued_pair(&[1400; 256]);
    let (r, f, _) = drain(&client, &server, 2048, 1200, 0);
    assert_eq!((r.op, f), (DONE, (0, 0, QUEUE_HEAD_DROPPED, CUR)));
    assert_eq!(client.with(|t| t.queued_len()), 0);
}

/// Without a session a write's output is control: a transport budget never
/// refuses the plaintext there (BUD-WRITE-02 a), and a control refusal admits
/// nothing -- the next accepted call admits it exactly once.
#[test]
fn without_a_session_only_the_driver_decides_admission() {
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let server = plain(&b, &a, 2, 0);
    let mut dst = vec![0u8; 2048];

    let (r, i) = exb(&client, Op::Write(&ipv4(1, 100)), &mut dst, 0, 147);
    assert_eq!((r.op, r.size), (ERR, BUDGET));
    assert_eq!(facts(&i), (0, 0, 0, 0));
    assert_eq!(client.with(|t| t.queued_len()), 0);

    let (r, i) = exb(&client, Op::Write(&ipv4(1, 100)), &mut dst, 100, 148);
    assert_eq!((r.op, r.size), (WTN, 148));
    assert_eq!(
        facts(&i),
        (
            0,
            k(PacketKind::HandshakeInitiation),
            ev::INITIATION_PRODUCED | ev::QUEUE_ADMITTED,
            st::INITIATION_PENDING | st::QUEUE_NONEMPTY
        )
    );
    let init = dst[..r.size].to_vec();
    let (r, i) = exb(&client, Op::Write(&ipv4(2, 1400)), &mut dst, 1, 1);
    assert_eq!((r.op, i.events), (DONE, ev::QUEUE_ADMITTED));
    assert_eq!(client.with(|t| t.queued_len()), 2);

    let resp = answered(&server, &init, 2048);
    let keepalive = answered(&client, &resp, 2048);
    read_done(&server, &keepalive);
    let mut tags = Vec::new();
    loop {
        let r = legacy(&client, Op::Read(EMPTY), &mut dst);
        if r.op == DONE {
            break;
        }
        tags.push(delivered(&server, &dst[..r.size]).0);
    }
    assert_eq!(tags, [1, 2], "each admitted exactly once");
}

/// A full queue is 17 before the driver runs, whatever the budgets: on a
/// frozen clock a STUN burst's second item is not yet due, so writes are
/// admitted with DONE until the queue is full; the next write is 17 although
/// its control budget would refuse that item -- which a drain then shows.
#[cfg(feature = "mock-instant")]
#[test]
fn queue_full_is_17_before_any_budget() {
    at(Duration::ZERO);
    let (a, b) = (party(), party());
    let client = awg(
        &a,
        &b,
        1,
        &wireguard_awg_params {
            imitation_protocol: AmneziaImitationProtocol::Stun as u32,
            ..params()
        },
    );
    let mut dst = vec![0u8; 2048];
    let (r, i) = ex(&client, Op::Write(&ipv4(0, 40)), &mut dst);
    assert_eq!((r.op, i.output_kind), (WTN, k(PacketKind::Imitation)));
    for n in 1..256 {
        let (r, i) = ex(&client, Op::Write(&ipv4(n, 40)), &mut dst);
        assert_eq!((r.op, i.events), (DONE, ev::QUEUE_ADMITTED), "packet {}", n);
    }
    let (r, i) = exb(&client, Op::Write(&ipv4(256, 40)), &mut dst, 1, 99);
    assert_eq!((r.op, r.size), (ERR, 17));
    assert_eq!(facts(&i), (0, 0, 0, st::QUEUE_NONEMPTY | st::BURST_PENDING));
    advance(Duration::from_millis(15));
    let (r, i) = exb(&client, Op::Read(EMPTY), &mut dst, 0, 99);
    assert_eq!(
        (r.op, r.size),
        (ERR, BUDGET),
        "the driver would have refused"
    );
    assert_eq!(facts(&i), (0, 0, 0, st::QUEUE_NONEMPTY | st::BURST_PENDING));
}

// ---------------------------------------------------------------------------
// Control: initiation, response (and AWG-R1-003), junk, imitation
// ---------------------------------------------------------------------------

/// A fresh force against the control budget (BUD-FORCE-01): 18 consumes
/// nothing -- no handshake state, no draw, no pending work -- and an
/// adequate budget later sends a genuine initiation. 18 wins over a short
/// `dst`; a short `dst` alone is 0; equality fits.
#[test]
fn the_initiation_obeys_the_control_budget() {
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let server = plain(&b, &a, 2, 0);
    let mut dst = vec![0u8; 2048];
    let pos = client.with(|t| t.rng_word_pos());

    let (r, i) = exb(&client, Op::Force, &mut dst, 0, 100);
    assert_eq!((r.op, r.size), (ERR, BUDGET));
    assert_eq!(
        (facts(&i), i.burst_due_ms, op_seq(&i)),
        ((0, 0, 0, 0), BURST_DUE_NONE, 1)
    );
    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 1200);
    assert_eq!((r.op, op_seq(&i)), (DONE, 2));
    let (r, _) = exb(&client, Op::Force, &mut dst[..100], 0, 147);
    assert_eq!((r.op, r.size), (ERR, BUDGET));
    let (r, i) = exb(&client, Op::Force, &mut dst[..147], 0, 0);
    assert_eq!((r.op, r.size, facts(&i)), (ERR, STORAGE, (0, 0, 0, 0)));
    assert_eq!(client.with(|t| t.rng_word_pos()), pos, "no refusal drew");

    let (r, i) = exb(&client, Op::Force, &mut dst, 1, 148);
    assert_eq!((r.op, r.size), (WTN, 148));
    assert_eq!(
        facts(&i),
        (
            0,
            k(PacketKind::HandshakeInitiation),
            ev::INITIATION_PRODUCED,
            st::INITIATION_PENDING
        )
    );
    assert_eq!(op_seq(&i), 5);
    let resp = answered(&server, &dst[..r.size], 2048);
    assert_eq!(resp.len(), 92);
}

/// S1 is mandatory: with S1 1100 an initiation is 1248 bytes whole.
#[test]
fn the_initiation_budget_counts_the_s1_prefix() {
    let s1 = wireguard_awg_params {
        s1_init_junk: 1100,
        ..params()
    };
    let (a, b) = (party(), party());
    let client = awg(&a, &b, 1, &s1);
    let server = awg(&b, &a, 2, &s1);
    let mut dst = vec![0u8; 2048];
    let (r, _) = exb(&client, Op::Force, &mut dst, 0, 1247);
    assert_eq!((r.op, r.size), (ERR, BUDGET));
    let (r, _) = exb(&client, Op::Force, &mut dst, 0, 1248);
    assert_eq!((r.op, r.size), (WTN, 1248));
    answered(&server, &dst[..r.size], 2048);
}

/// The response, preflighted before authentication (BUD-READ-02): with S2
/// 1200 it is 1292 bytes; 1210 refuses the initiation with nothing accepted,
/// and the same bytes then produce a genuine response. Storage alone is 0,
/// both short 18, each with nothing accepted and the retry succeeding.
#[test]
fn the_response_obeys_the_control_budget_before_authentication() {
    let s2 = wireguard_awg_params {
        s2_response_junk: 1200,
        ..params()
    };
    for (d, bc, want) in [
        (2048, 1210, BUDGET),
        (1291, 0, STORAGE),
        (1291, 1291, BUDGET),
    ] {
        let (a, b) = (party(), party());
        let client = awg(&a, &b, 1, &s2);
        let server = awg(&b, &a, 2, &s2);
        let (mut cb, mut sb) = (vec![0u8; 2048], vec![0u8; 2048]);
        let r = legacy(&client, Op::Force, &mut cb);
        let init = cb[..r.size].to_vec();

        let (r, i) = exb(&server, Op::Read(&init), &mut sb[..d], 0, bc);
        assert_eq!((r.op, r.size), (ERR, want), "d {} bc {}", d, bc);
        assert_eq!(facts(&i), (0, 0, 0, 0), "nothing accepted");

        let (r, i) = exb(&server, Op::Read(&init), &mut sb, 0, 1292);
        assert_eq!((r.op, r.size), (WTN, 1292));
        assert_eq!(
            facts(&i),
            (
                k(PacketKind::HandshakeInitiation),
                k(PacketKind::HandshakeResponse),
                ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED | ev::SESSION_STORED,
                0
            )
        );
        let keepalive = answered(&client, &sb[..r.size], 2048);
        let (r, i) = ex(&server, Op::Read(&keepalive), &mut sb);
        assert_eq!((r.op, i.state), (DONE, st::SESSION_CURRENT));
    }
}

/// AWG-R1-003, the one legacy change: with no budget at all, an initiation
/// whose response cannot fit `dst` is refused BEFORE authentication. Nothing
/// is accepted -- no timestamp, no session -- so the same initiation, offered
/// again with room, is answered, and only after that is it a replay. Same
/// through the legacy symbol, `_ex(NULL)` and `_ex` with zero budgets; and
/// with S2 28, where `dst` 100 fits 92 but not the 120-byte response.
#[test]
fn awg_r1_003_a_response_short_of_room_commits_nothing() {
    for (s2, d, resp_len) in [(0u32, 91usize, 92usize), (28, 100, 120)] {
        for api in 0..3 {
            let cfg = wireguard_awg_params {
                s2_response_junk: s2,
                ..params()
            };
            let (a, b) = (party(), party());
            let client = awg(&a, &b, 1, &cfg);
            let server = awg(&b, &a, 2, &cfg);
            let (mut cb, mut sb) = (vec![0u8; 2048], vec![0u8; 2048]);
            let r = legacy(&client, Op::Force, &mut cb);
            let init = cb[..r.size].to_vec();

            let r = match api {
                0 => legacy(&server, Op::Read(&init), &mut sb[..d]),
                1 => unsafe { raw_call(server.0, Op::Read(&init), &mut sb[..d], ptr::null_mut()) },
                _ => {
                    let (r, i) = ex(&server, Op::Read(&init), &mut sb[..d]);
                    assert_eq!(facts(&i), (0, 0, 0, 0), "s2 {}: nothing accepted", s2);
                    r
                }
            };
            assert_eq!((r.op, r.size), (ERR, STORAGE), "s2 {} api {}", s2, api);

            let (r, i) = ex(&server, Op::Read(&init), &mut sb);
            assert_eq!(
                (r.op, r.size),
                (WTN, resp_len),
                "s2 {} api {}: answered",
                s2,
                api
            );
            assert_eq!(
                facts(&i),
                (
                    k(PacketKind::HandshakeInitiation),
                    k(PacketKind::HandshakeResponse),
                    ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED | ev::SESSION_STORED,
                    0
                )
            );
            let resp = sb[..r.size].to_vec();
            let (r, _) = ex(&server, Op::Read(&init), &mut sb);
            assert_eq!((r.op, r.size), (ERR, 7), "now it is a replay");
            let keepalive = answered(&client, &resp, 2048);
            read_done(&server, &keepalive);
        }
    }
}

/// A datagram that is both a genuine initiation and a genuine transport
/// packet (BUD-READ-04): S4 148 with RandomTrailers, so an initiation
/// followed by a transport frame reads as either. When the initiation is
/// refused for response capacity -- by a control budget of 91, or with no
/// budget by a 91-byte `dst` -- the transport reading is still tried and
/// wins. With a budget of 92 the initiation wins.
#[test]
fn a_capacity_refused_initiation_does_not_hide_another_reading() {
    let rt148 = wireguard_awg_params {
        s4_transport_junk: 148,
        random_trailers: 1,
        ..params()
    };
    let (a, b) = (party(), party());
    let client = awg(&a, &b, 1, &rt148);
    let server = awg(&b, &a, 2, &rt148);
    establish(&client, &server);
    let mut cb = vec![0u8; 2048];
    // Two transport frames, each exactly its mandatory 148 + 32 + 64.
    let mut frames = Vec::new();
    for tag in [1, 2] {
        let r = legacy(&client, Op::Write(&ipv4(tag, 64)), &mut cb[..244]);
        assert_eq!((r.op, r.size), (WTN, 244));
        frames.push(cb[148..244].to_vec());
    }
    advance(Duration::from_millis(2));
    let r = legacy(&client, Op::Force, &mut cb[..148]);
    assert_eq!((r.op, r.size), (WTN, 148));
    let init = cb[..148].to_vec();
    let composite = |frame: &[u8]| [&init[..], frame].concat();
    let mut sb = vec![0u8; 2048];

    let (r, i) = exb(&server, Op::Read(&composite(&frames[0])), &mut sb, 0, 91);
    assert_eq!((r.op, r.size), (WTT4, 64));
    assert_eq!(tag_of(&sb[..64]), 1);
    assert_eq!(
        facts(&i),
        (
            k(PacketKind::TransportData),
            0,
            ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED,
            st::SESSION_CURRENT
        )
    );
    let (r, i) = ex(&server, Op::Read(&composite(&frames[1])), &mut sb[..91]);
    assert_eq!((r.op, r.size), (WTT4, 64));
    assert_eq!(tag_of(&sb[..64]), 2);
    assert_eq!(i.input_kind, k(PacketKind::TransportData));

    let (r, i) = exb(&server, Op::Read(&composite(&frames[0])), &mut sb, 0, 92);
    assert_eq!((r.op, r.size), (WTN, 92));
    assert_eq!(
        facts(&i),
        (
            k(PacketKind::HandshakeInitiation),
            k(PacketKind::HandshakeResponse),
            ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED | ev::SESSION_STORED,
            st::SESSION_CURRENT
        )
    );
    // A genuine response: the client completes the handshake it answers.
    let keepalive = answered(&client, &sb[..92], 2048);
    read_done(&server, &keepalive);
}

/// The rate limiter still decides first: a responder under load refuses a
/// genuine initiation with 16 (no source address for a cookie), whatever the
/// control budget or `dst` would have said.
#[test]
fn the_limiter_decides_before_response_capacity() {
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let server = Owned(Box::into_raw(Box::new(Mutex::new(
        Tunn::new_with_obfuscation(
            b.secret.clone(),
            a.public,
            None,
            None,
            2,
            Some(Arc::new(RateLimiter::new(&b.public, 0))),
            Default::default(),
            AmneziaConfig::default(),
        )
        .unwrap(),
    ))));
    let mut cb = vec![0u8; 2048];
    let r = legacy(&client, Op::Force, &mut cb);
    let init = cb[..r.size].to_vec();
    let mut sb = vec![0u8; 2048];
    for (d, bc) in [(2048, 91), (91, 0), (91, 91)] {
        let (r, i) = exb(&server, Op::Read(&init), &mut sb[..d], 0, bc);
        assert_eq!((r.op, r.size), (ERR, 16), "d {} bc {}", d, bc);
        assert_eq!(facts(&i), (0, 0, 0, 0));
    }
}

fn junk_profile(jc: u32, lo: u32, hi: u32) -> wireguard_awg_params {
    wireguard_awg_params {
        junk_packet_count: jc,
        junk_packet_size_min: lo,
        junk_packet_size_max: hi,
        ..params()
    }
}

/// Ordinary junk under a finite control budget C uses [min(Jmin, C),
/// min(Jmax, C)] (owner decision 1A, BUD-JUNK-01 j1-j7); `dst` never narrows
/// it -- a `dst` short of the working maximum is 0 before any draw -- and C 0
/// keeps the configured range. Jc and the stored configuration are untouched.
#[test]
fn ordinary_junk_is_clamped_at_both_ends_by_the_control_budget() {
    // (case, configured Jmin..=Jmax, d, bc, Ok(lo..=hi) | Err(code))
    type Case = (
        &'static str,
        (u32, u32),
        usize,
        u32,
        Result<(usize, usize), usize>,
    );
    let cases: [Case; 7] = [
        ("j1", (50, 1000), 2048, 100, Ok((50, 100))),
        ("j2", (50, 1000), 60, 100, Err(STORAGE)),
        ("j3", (50, 1000), 2048, 40, Ok((40, 40))),
        ("j4", (50, 1000), 100, 1000, Err(STORAGE)),
        ("j5", (1000, 1280), 2048, 572, Ok((572, 572))),
        ("j6", (100, 1280), 2048, 572, Ok((100, 572))),
        ("j7", (1000, 1280), 100, 0, Err(STORAGE)),
    ];
    for (name, (lo, hi), d, bc, want) in cases {
        let (a, b) = (party(), party());
        let client = awg(&a, &b, 1, &junk_profile(16, lo, hi));
        let server = plain(&b, &a, 2, 0);
        let mut dst = vec![0u8; 2048];
        let pos = client.with(|t| t.rng_word_pos());
        let (r, i) = exb(&client, Op::Force, &mut dst[..d], 0, bc);
        assert_eq!(i.events, ev::BURST_PREPARED, "{}", name);
        assert_eq!(i.state, st::BURST_PENDING, "{}", name);
        match want {
            Err(code) => {
                assert_eq!((r.op, r.size), (ERR, code), "{}", name);
                assert_eq!(i.burst_due_ms, 0, "{}: due but blocked", name);
                assert_eq!(
                    client.with(|t| t.rng_word_pos()),
                    pos,
                    "{}: nothing drawn",
                    name
                );
                assert_eq!(client.with(|t| t.pending_burst_shape()), Some((0, 16)));
            }
            Ok((wlo, whi)) => {
                // All 16 items, each from the working range; then the
                // initiation.
                let mut sizes = vec![r.size];
                assert_eq!(
                    (r.op, i.output_kind),
                    (WTN, k(PacketKind::Junk)),
                    "{}",
                    name
                );
                for left in (0..15).rev() {
                    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, bc);
                    assert_eq!(
                        (r.op, i.output_kind),
                        (WTN, k(PacketKind::Junk)),
                        "{}",
                        name
                    );
                    assert_eq!(client.with(|t| t.pending_burst_shape()), Some((0, left)));
                    sizes.push(r.size);
                }
                assert!(
                    sizes.iter().all(|s| (wlo..=whi).contains(s)),
                    "{}: {:?} outside {}..={}",
                    name,
                    sizes,
                    wlo,
                    whi
                );
                let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 148);
                assert_eq!(
                    (r.op, r.size, i.output_kind),
                    (WTN, 148, k(PacketKind::HandshakeInitiation))
                );
                answered(&server, &dst[..148], 2048);
            }
        }
        let cfg = client.with(|t| t.amnezia_config().pre_handshake_junk);
        assert_eq!(
            (cfg.packet_count, cfg.packet_size_min, cfg.packet_size_max),
            (16, lo as u16, hi as u16),
            "{}: the configuration is not rewritten",
            name
        );
    }
}

/// Protocol junk keeps its protocol lower bound (BUD-IMIT-02, BUD-JUNK-02):
/// STUN junk is 28..=100, so a control budget of 27 is 18 -- before any
/// draw, whatever `dst` -- and 50 gives 28..=50; a `dst` short of that 50 is
/// 0. QUIC junk is 1200..=1252: 1199 is 18, 1210 gives 1200..=1210. The
/// complete imitation datagrams before them are emitted unbounded.
#[test]
fn protocol_junk_keeps_its_lower_bound() {
    for (protocol, browser, steps) in [
        (
            AmneziaImitationProtocol::Stun,
            0u32,
            &[
                (2048, 27, Err(BUDGET)),
                (10, 27, Err(BUDGET)),
                (40, 50, Err(STORAGE)),
                (2048, 50, Ok((28, 50))),
            ][..],
        ),
        (
            AmneziaImitationProtocol::Quic,
            1,
            &[
                (2048, 1199, Err(BUDGET)),
                (2048, 1210, Ok((1200, 1210))),
                (2048, 1252, Ok((1200, 1252))),
            ][..],
        ),
    ] {
        let jc = steps.iter().filter(|s| s.2.is_ok()).count() as u32;
        let (a, b) = (party(), party());
        let client = awg(
            &a,
            &b,
            1,
            &wireguard_awg_params {
                imitation_protocol: protocol as u32,
                imitation_browser: browser,
                junk_packet_count: jc,
                ..params()
            },
        );
        let server = plain(&b, &a, 2, 0);
        let mut dst = vec![0u8; 2048];
        // The imitation datagrams, unbounded.
        let (r, i) = ex(&client, Op::Force, &mut dst);
        assert_eq!((r.op, i.output_kind), (WTN, k(PacketKind::Imitation)));
        while client.with(|t| t.pending_burst_shape()).unwrap().0 > 0 {
            advance(Duration::from_millis(20));
            let (r, i) = ex(&client, Op::Tick, &mut dst);
            assert_eq!((r.op, i.output_kind), (WTN, k(PacketKind::Imitation)));
        }
        for &(d, bc, want) in steps {
            let pos = client.with(|t| t.rng_word_pos());
            let (r, i) = exb(&client, Op::Tick, &mut dst[..d], 0, bc);
            match want {
                Err(code) => {
                    assert_eq!(
                        (r.op, r.size),
                        (ERR, code),
                        "{:?} d {} bc {}",
                        protocol,
                        d,
                        bc
                    );
                    assert_eq!(
                        (facts(&i), i.burst_due_ms),
                        ((0, 0, 0, st::BURST_PENDING), 0)
                    );
                    assert_eq!(client.with(|t| t.rng_word_pos()), pos, "nothing drawn");
                }
                Ok((lo, hi)) => {
                    assert_eq!((r.op, i.output_kind), (WTN, k(PacketKind::Junk)));
                    assert!(
                        (lo..=hi).contains(&r.size),
                        "{:?}: {} not in {}..={}",
                        protocol,
                        r.size,
                        lo,
                        hi
                    );
                }
            }
        }
        let (r, i) = ex(&client, Op::Tick, &mut dst);
        assert_eq!(
            (r.op, i.output_kind),
            (WTN, k(PacketKind::HandshakeInitiation))
        );
        answered(&server, &dst[..r.size], 2048);
    }
}

/// Imitation datagrams are indivisible (BUD-IMIT-01): each is compared whole
/// with the control budget, then with `dst`. A refusal keeps the item, its
/// bytes, its order and the pacing clock, draws nothing and skips nothing;
/// equality emits exactly the bytes that were refused. The initiation behind
/// the burst likewise waits for a fitting budget. DNS with a 242-byte name,
/// and STUN.
#[test]
fn a_whole_imitation_datagram_is_refused_and_kept() {
    let dns242 = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(50)
    );
    for (protocol, domain) in [
        (AmneziaImitationProtocol::Dns, Some(dns242.as_str())),
        (AmneziaImitationProtocol::Stun, None),
    ] {
        let (a, b) = (party(), party());
        let client = awg_with(
            &a,
            &b,
            1,
            0,
            &wireguard_awg_params {
                imitation_protocol: protocol as u32,
                ..params()
            },
            domain,
        );
        let server = plain(&b, &a, 2, 0);
        let mut dst = vec![0u8; 2048];

        // A one-byte budget refuses any item: the burst is prepared, kept.
        let (r, i) = exb(&client, Op::Force, &mut dst, 0, 1);
        assert_eq!((r.op, r.size), (ERR, BUDGET));
        assert_eq!(
            (facts(&i), i.burst_due_ms),
            ((0, 0, ev::BURST_PREPARED, st::BURST_PENDING), 0)
        );
        let total = client.with(|t| t.pending_burst_shape()).unwrap().0;
        assert!(total >= 2, "{:?}", protocol);

        for n in 0..total {
            let item = client.with(|t| t.pending_front_imitation()).unwrap();
            let len = item.len();
            if protocol == AmneziaImitationProtocol::Dns {
                assert!((250..=271).contains(&len), "DNS item {} is {}", n, len);
            }
            // Wait out this item's delay, then refuse it three ways.
            advance(Duration::from_millis(20));
            let pos = client.with(|t| t.rng_word_pos());
            for (d, bc, code) in [
                (2048, len as u32 - 1, BUDGET),
                (len - 1, 0, STORAGE),
                (len - 1, len as u32 - 1, BUDGET),
            ] {
                let (r, i) = exb(&client, Op::Tick, &mut dst[..d], 0, bc);
                assert_eq!(
                    (r.op, r.size),
                    (ERR, code),
                    "{:?} item {} d {} bc {}",
                    protocol,
                    n,
                    d,
                    bc
                );
                assert_eq!(
                    (facts(&i), i.burst_due_ms),
                    ((0, 0, 0, st::BURST_PENDING), 0)
                );
                assert_eq!(
                    client.with(|t| t.pending_burst_shape()).unwrap().0,
                    total - n
                );
                assert_eq!(client.with(|t| t.pending_front_imitation()).unwrap(), item);
            }
            assert_eq!(
                client.with(|t| t.rng_word_pos()),
                pos,
                "refusals draw nothing"
            );
            let (r, i) = exb(&client, Op::Tick, &mut dst[..len], 0, len as u32);
            assert_eq!(
                (r.op, r.size, i.output_kind),
                (WTN, len, k(PacketKind::Imitation))
            );
            assert_eq!(&dst[..len], &item[..], "the refused bytes, unchanged");
        }

        // The initiation behind the burst.
        let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 147);
        assert_eq!((r.op, r.size), (ERR, BUDGET));
        assert_eq!(
            (facts(&i), i.burst_due_ms),
            ((0, 0, 0, st::BURST_PENDING), 0)
        );
        let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 148);
        assert_eq!((r.op, r.size), (WTN, 148));
        assert_eq!(
            (facts(&i), i.burst_due_ms),
            (
                (
                    0,
                    k(PacketKind::HandshakeInitiation),
                    ev::INITIATION_PRODUCED,
                    st::INITIATION_PENDING
                ),
                BURST_DUE_NONE
            )
        );
        answered(&server, &dst[..148], 2048);
    }
}

// ---------------------------------------------------------------------------
// Tick: what a budget refusal spends and gives back (mock clock)
// ---------------------------------------------------------------------------

/// M-CE-4b(a): the handshake latch, no burst. A control budget of 100 refuses
/// the 148-byte initiation; the latch spent selecting it is restored, so the
/// next tick with room sends it. (Losing the latch would give DONE: there is
/// no InitSent and no rekey at 17 s.)
///
/// The deadline is KEEPALIVE + REKEY_TIMEOUT plus up to
/// `REKEY_TIMEOUT_JITTER_MAX_MS` of jitter, measured from the data sent at
/// 1 s (the reference timer state machine), so 17 s is past it whatever the
/// jitter drew.
#[cfg(feature = "mock-instant")]
#[test]
fn m_ce_4b_a_a_refused_handshake_demand_keeps_its_latch() {
    at(Duration::ZERO);
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let server = plain(&b, &a, 2, 0);
    establish(&client, &server);
    let mut dst = vec![0u8; 2048];
    at(secs(1));
    assert_eq!(legacy(&client, Op::Tick, &mut dst).op, DONE);
    assert_eq!(legacy(&client, Op::Write(&ipv4(1, 40)), &mut dst).op, WTN);
    assert!(demands(&client).0, "the latch armed");
    at(secs(17));
    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 100);
    assert_eq!((r.op, r.size), (ERR, BUDGET));
    assert_eq!(
        facts(&i),
        (0, 0, ev::TICK_DEMAND_REFUSED, st::SESSION_CURRENT)
    );
    assert!(demands(&client).0, "restored");
    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 1200);
    assert_eq!((r.op, r.size), (WTN, 148));
    assert_eq!(
        facts(&i),
        (
            0,
            k(PacketKind::HandshakeInitiation),
            ev::INITIATION_PRODUCED,
            st::SESSION_CURRENT | st::INITIATION_PENDING
        )
    );
    answered(&server, &dst[..148], 2048);
}

/// BUD-TICK-01: the same with S1 1100 on both ends, a 1248-byte initiation,
/// at the same 17 s.
#[cfg(feature = "mock-instant")]
#[test]
fn bud_tick_01_the_restored_latch_sends_the_whole_s1_initiation() {
    at(Duration::ZERO);
    let s1 = wireguard_awg_params {
        s1_init_junk: 1100,
        ..params()
    };
    let (a, b) = (party(), party());
    let client = awg(&a, &b, 1, &s1);
    let server = awg(&b, &a, 2, &s1);
    establish(&client, &server);
    let mut dst = vec![0u8; 2048];
    at(secs(1));
    assert_eq!(legacy(&client, Op::Tick, &mut dst).op, DONE);
    assert_eq!(legacy(&client, Op::Write(&ipv4(1, 40)), &mut dst).op, WTN);
    at(secs(17));
    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 1200);
    assert_eq!((r.op, r.size), (ERR, BUDGET));
    assert_eq!(
        facts(&i),
        (0, 0, ev::TICK_DEMAND_REFUSED, st::SESSION_CURRENT)
    );
    assert!(demands(&client).0);
    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 1300);
    assert_eq!((r.op, r.size), (WTN, 1248));
    assert_eq!(i.state, st::SESSION_CURRENT | st::INITIATION_PENDING);
    answered(&server, &dst[..1248], 2048);
}

/// M-CE-4b(b), as adapted to STUN by the budget contract (b-STUN): the
/// selected latch prepares a new STUN burst inside the producer, whose first
/// item exceeds a control budget of 99. The burst now owns the initiation, so
/// the latch is NOT restored; the burst itself completes later.
#[cfg(feature = "mock-instant")]
#[test]
fn b_stun_a_burst_prepared_by_the_demand_owns_it() {
    at(Duration::ZERO);
    let (a, b) = (party(), party());
    let client = awg(
        &a,
        &b,
        1,
        &wireguard_awg_params {
            imitation_protocol: AmneziaImitationProtocol::Stun as u32,
            ..params()
        },
    );
    let server = plain(&b, &a, 2, 0);
    let mut dst = vec![0u8; 2048];
    // b1-b3: the first burst, then its initiation; b4: the handshake, with
    // no tick (both tick clocks stay 0).
    let (r, i) = ex(&client, Op::Force, &mut dst);
    assert_eq!(
        (r.op, i.output_kind, i.burst_due_ms),
        (WTN, k(PacketKind::Imitation), 15)
    );
    at(Duration::from_millis(15));
    let (r, i) = ex(&client, Op::Force, &mut dst);
    assert_eq!(
        (r.op, i.output_kind, i.burst_due_ms),
        (WTN, k(PacketKind::Imitation), 0)
    );
    let (r, i) = ex(&client, Op::Force, &mut dst);
    assert_eq!(
        (r.op, i.output_kind),
        (WTN, k(PacketKind::HandshakeInitiation))
    );
    let resp = answered(&server, &dst[..r.size], 2048);
    let keepalive = answered(&client, &resp, 2048);
    read_done(&server, &keepalive);
    // b5-b6
    at(secs(1));
    assert_eq!(legacy(&client, Op::Tick, &mut dst).op, DONE);
    assert_eq!(legacy(&client, Op::Write(&ipv4(1, 40)), &mut dst).op, WTN);
    // b7, past the jittered deadline as in M-CE-4b(a)
    at(secs(17));
    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 99);
    assert_eq!((r.op, r.size), (ERR, BUDGET));
    assert_eq!(
        (facts(&i), i.burst_due_ms),
        (
            (
                0,
                0,
                ev::BURST_PREPARED | ev::TICK_DEMAND_REFUSED,
                st::SESSION_CURRENT | st::BURST_PENDING
            ),
            0
        )
    );
    assert!(!demands(&client).0, "exempt: the burst owns the initiation");
    // b8-b10
    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 1200);
    assert_eq!(
        (r.op, i.output_kind, i.burst_due_ms),
        (WTN, k(PacketKind::Imitation), 15)
    );
    at(secs(17) + Duration::from_millis(15));
    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 1200);
    assert_eq!(
        (r.op, i.output_kind, i.burst_due_ms),
        (WTN, k(PacketKind::Imitation), 0)
    );
    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 1200);
    assert_eq!(
        (r.op, r.size, i.events, i.burst_due_ms),
        (WTN, 148, ev::INITIATION_PRODUCED, BURST_DUE_NONE)
    );
}

/// M-CE-4b(c), (d), (e): the keepalive latch alone, the periodic keepalive
/// alone, and both at once, each refused by a transport budget of 16 against
/// the 32-byte keepalive. Exactly what was spent is restored -- the latch,
/// the stamp, or both -- so the next tick without a budget sends it. (A lost
/// demand would give DONE there.)
///
/// The passive keepalive is due KEEPALIVE after the data received at 1 s, and
/// that authenticated receive also restarts the periodic interval (the
/// reference timer state machine): both are due at 11 s in (c) and (e).
#[cfg(feature = "mock-instant")]
#[test]
fn m_ce_4b_cde_refused_keepalives_keep_what_they_spent() {
    // (case, client KA, peer data at 1 s, target time)
    for (case, ka, peer_data, target) in [
        ("c", 0u16, true, 11u64),
        ("d", 1, false, 1),
        ("e", 10, true, 11),
    ] {
        at(Duration::ZERO);
        let (a, b) = (party(), party());
        let client = plain(&a, &b, 1, ka);
        let server = plain(&b, &a, 2, 0);
        establish(&client, &server);
        let mut dst = vec![0u8; 2048];
        if peer_data {
            at(secs(1));
            assert_eq!(legacy(&client, Op::Tick, &mut dst).op, DONE, "{}", case);
            let mut sb = vec![0u8; 2048];
            let r = legacy(&server, Op::Write(&ipv4(1, 40)), &mut sb);
            assert_eq!(delivered(&client, &sb[..r.size]).0, 1);
        }
        let before = client.with(|t| t.timer_demand_state());
        at(secs(target));
        let (r, i) = exb(&client, Op::Tick, &mut dst, 16, 0);
        assert_eq!((r.op, r.size), (ERR, BUDGET), "{}", case);
        assert_eq!(
            facts(&i),
            (0, 0, ev::TICK_DEMAND_REFUSED, st::SESSION_CURRENT),
            "{}",
            case
        );
        assert_eq!(
            client.with(|t| t.timer_demand_state()),
            before,
            "{}: restored exactly",
            case
        );
        let (r, i) = ex(&client, Op::Tick, &mut dst);
        assert_eq!(
            (r.op, r.size, i.output_kind),
            (WTN, 32, k(PacketKind::TransportKeepalive)),
            "{}",
            case
        );
        read_done(&server, &dst[..32]);
        let (_, wk, tpk) = demands(&client);
        assert!(!wk, "{}", case);
        if ka > 0 {
            assert_eq!(tpk, secs(target), "{}: stamped now", case);
        }
    }
}

/// f0-STUN: a burst pending at entry is serviced before any demand is
/// selected. Its refused item adds no TICK_DEMAND_REFUSED and spends no
/// periodic stamp, although the keepalive is due.
#[cfg(feature = "mock-instant")]
#[test]
fn f0_stun_an_entry_pending_burst_refusal_selects_no_demand() {
    at(Duration::ZERO);
    let (a, b) = (party(), party());
    let client = awg_with(
        &a,
        &b,
        1,
        1,
        &wireguard_awg_params {
            imitation_protocol: AmneziaImitationProtocol::Stun as u32,
            ..params()
        },
        None,
    );
    let mut dst = vec![0u8; 2048];
    let (r, i) = ex(&client, Op::Force, &mut dst);
    assert_eq!(
        (r.op, i.output_kind, i.events),
        (WTN, k(PacketKind::Imitation), ev::BURST_PREPARED)
    );
    at(secs(1));
    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 99);
    assert_eq!((r.op, r.size), (ERR, BUDGET));
    assert_eq!(
        (facts(&i), i.burst_due_ms),
        ((0, 0, 0, st::BURST_PENDING), 0)
    );
    assert_eq!(demands(&client), (false, false, Duration::ZERO));
    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 1200);
    assert_eq!(
        (r.op, i.output_kind, i.burst_due_ms),
        (WTN, k(PacketKind::Imitation), 0)
    );
    assert_eq!(demands(&client).2, Duration::ZERO);
    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 1200);
    assert_eq!(
        (r.op, r.size, i.output_kind),
        (WTN, 148, k(PacketKind::HandshakeInitiation))
    );
}

/// f1-STUN, f2-STUN, f3-STUN: a responder whose session ages out while a
/// keepalive demand is due -- the latch (f1), the periodic stamp (f2) or both
/// (f3). With no session the empty keepalive goes to the no-session producer,
/// which prepares a STUN burst whose first item exceeds a control budget of
/// 99: the empty entry is not admitted, and exactly what was spent is
/// restored, at once (F8). Then the peer's next initiation is accepted
/// (F10-F11): that response clears the latch and cancels the burst. Under the
/// reference timer state machine the response is an authenticated send, so
/// it also restarts the periodic interval: the following tick (F12) is DONE
/// in all three cases, the stamp now the response's.
///
/// The data received at 1 s in f1/f3 restarts the periodic interval too, so
/// F8 is at 62 s, where f3's stamp (1 s) and f2's (0 s) are both due.
#[cfg(feature = "mock-instant")]
#[test]
fn f_stun_a_refused_no_session_keepalive_keeps_its_demand_until_contact() {
    for (case, ka) in [("f1", 0u16), ("f2", 61), ("f3", 61)] {
        at(Duration::ZERO);
        let timers = |p: wireguard_awg_params| wireguard_awg_params {
            rekey_after_time: range(40),
            reject_after_time: range(60),
            keepalive_timeout: range(50),
            ..p
        };
        let (a, b) = (party(), party());
        let client = awg_with(
            &a,
            &b,
            1,
            ka,
            &timers(wireguard_awg_params {
                imitation_protocol: AmneziaImitationProtocol::Stun as u32,
                ..params()
            }),
            None,
        );
        let peer = awg(&b, &a, 2, &timers(params()));
        let (mut cb, mut pb) = (vec![0u8; 2048], vec![0u8; 2048]);

        // F3-F5: the peer initiates; the client answers; the peer's
        // keepalive is withheld.
        let r = legacy(&peer, Op::Force, &mut pb);
        let r0 = answered(&client, &pb[..r.size], 2048);
        answered(&peer, &r0, 2048);
        if case != "f2" {
            // F6-F7: data from the peer selects the client's session.
            at(secs(1));
            assert_eq!(legacy(&client, Op::Tick, &mut cb).op, DONE);
            let r = legacy(&peer, Op::Write(&ipv4(1, 40)), &mut pb);
            assert_eq!(delivered(&client, &pb[..r.size]).0, 1);
        }
        let (_, wk_before, tpk_before) = demands(&client);
        let state_before = client.with(|t| t.timer_demand_state());
        assert_eq!(wk_before, case != "f2", "{}", case);
        assert_eq!(
            tpk_before,
            if case == "f2" {
                Duration::ZERO
            } else {
                secs(1)
            },
            "{}",
            case
        );

        // F8
        at(secs(62));
        let (r, i) = exb(&client, Op::Tick, &mut cb, 0, 99);
        assert_eq!((r.op, r.size), (ERR, BUDGET), "{}", case);
        let changed = if case == "f2" {
            0
        } else {
            ev::CURRENT_SESSION_CHANGED
        };
        assert_eq!(
            (facts(&i), i.burst_due_ms),
            (
                (
                    0,
                    0,
                    ev::SESSIONS_AGED_OUT | changed | ev::BURST_PREPARED | ev::TICK_DEMAND_REFUSED,
                    st::BURST_PENDING
                ),
                0
            ),
            "{}",
            case
        );
        let (_, wk, tpk) = demands(&client);
        assert_eq!(
            (wk, tpk),
            (wk_before, tpk_before),
            "{}: restored at once",
            case
        );
        assert_eq!(
            client.with(|t| t.timer_demand_state()),
            state_before,
            "{}: restored exactly",
            case
        );
        assert_eq!(client.with(|t| t.queued_len()), 0, "{}: not admitted", case);

        // F10-F11: the peer's next initiation, answered; the response is
        // discarded.
        let r = legacy(&peer, Op::Force, &mut pb);
        answered(&client, &pb[..r.size], 2048);
        let (_, wk, _) = demands(&client);
        assert!(!wk, "{}: contact clears the latch", case);
        assert_eq!(
            client.with(|t| t.pending_burst_shape()),
            None,
            "{}: burst cancelled",
            case
        );

        // F12
        let (r, i) = exb(&client, Op::Tick, &mut cb, 0, 1200);
        assert_eq!((r.op, facts(&i)), (DONE, (0, 0, 0, 0)), "{}", case);
        assert_eq!(
            demands(&client).2,
            secs(62),
            "{}: the response's stamp",
            case
        );
    }
}

// ---------------------------------------------------------------------------
// RandomTrailers: the optional addition is clipped, the mandatory frame not
// ---------------------------------------------------------------------------

/// Arms the optional-draw word and clears it on every exit.
struct Armed;

impl Armed {
    fn new(word: u64) -> Self {
        let guard = Armed;
        OPTIONAL_DRAW_WORD.with(|c| c.set(Some(word)));
        guard
    }

    fn consumed(&self) -> bool {
        OPTIONAL_DRAW_WORD.with(|c| c.get()).is_none()
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        OPTIONAL_DRAW_WORD.with(|c| c.set(None));
    }
}

fn rt() -> wireguard_awg_params {
    wireguard_awg_params {
        random_trailers: 1,
        ..params()
    }
}

fn window(t: &Owned) -> u32 {
    t.with(|t| t.udp_window())
}

/// H-RT: a real RandomTrailers handshake whose every setup output is clipped
/// to its exact size by `dst`: INIT 148, the peer's RESP 92 (at the peer's
/// own read), the response keepalive 32. Both windows stay at 500.
fn h_rt(client_ka: u16) -> (Owned, Owned) {
    let (a, b) = (party(), party());
    let client = awg_with(&a, &b, 1, client_ka, &rt(), None);
    let peer = awg(&b, &a, 2, &rt());
    let mut cb = vec![0u8; 2048];
    let (r, _) = ex(&client, Op::Force, &mut cb[..148]);
    assert_eq!((r.op, r.size), (WTN, 148));
    let resp = answered(&peer, &cb[..148], 92);
    assert_eq!(resp.len(), 92);
    let (r, _) = ex(&client, Op::Read(&resp), &mut cb[..32]);
    assert_eq!((r.op, r.size), (WTN, 32));
    read_done(&peer, &cb[..32]);
    assert_eq!((window(&client), window(&peer)), (500, 500));
    (client, peer)
}

/// W-DATA and W-DRAIN: a 100-byte plaintext is 132 mandatory; the armed word
/// 50 asks for 50 bytes of window padding (headroom 368). A transport budget
/// of 140 clips it to 8 -- 140, where unbounded gives 182 -- and at 132 to
/// none, the draw still made. The peer decrypts each.
#[test]
fn w_data_and_w_drain_clip_window_padding_to_the_budget() {
    for (bt, out) in [(140, 140), (0, 182), (132, 132)] {
        let (client, peer) = h_rt(0);
        let mut cb = vec![0u8; 2048];
        let armed = Armed::new(50);
        let (r, i) = exb(&client, Op::Write(&ipv4(3, 100)), &mut cb, bt, 0);
        assert_eq!(
            (r.op, r.size, i.output_kind),
            (WTN, out, k(PacketKind::TransportData)),
            "bt {}",
            bt
        );
        assert!(armed.consumed(), "bt {}: drawn", bt);
        drop(armed);
        assert_eq!(delivered(&peer, &cb[..r.size]), (3, 100));
    }

    for (bt, out) in [(140, 140), (0, 182)] {
        let (a, b) = (party(), party());
        let client = awg(&a, &b, 1, &rt());
        let peer = awg(&b, &a, 2, &rt());
        let mut cb = vec![0u8; 2048];
        let (r, i) = ex(&client, Op::Write(&ipv4(4, 100)), &mut cb[..148]);
        assert_eq!(
            (r.op, r.size, i.events),
            (WTN, 148, ev::INITIATION_PRODUCED | ev::QUEUE_ADMITTED)
        );
        let resp = answered(&peer, &cb[..148], 92);
        let (r, _) = ex(&client, Op::Read(&resp), &mut cb[..32]);
        read_done(&peer, &cb[..r.size]);
        assert_eq!(window(&client), 500);
        let armed = Armed::new(50);
        let (r, i) = exb(&client, Op::Read(EMPTY), &mut cb, bt, 0);
        assert_eq!(
            (r.op, r.size, i.output_kind),
            (WTN, out, k(PacketKind::TransportData)),
            "drain bt {}",
            bt
        );
        assert!(armed.consumed());
        drop(armed);
        assert_eq!(delivered(&peer, &cb[..r.size]), (4, 100));
        let (r, _) = ex(&client, Op::Read(EMPTY), &mut cb);
        assert_eq!(r.op, DONE);
    }
}

/// W-RKA: the response keepalive's padding (headroom 468, word 50) is
/// clipped by a transport budget of 40: 40, where unbounded gives 82. The
/// peer's response is clipped to exactly 92 at the peer's own read.
#[test]
fn w_rka_clips_the_response_keepalive_padding() {
    for (bt, out) in [(40, 40), (0, 82)] {
        let (a, b) = (party(), party());
        let client = awg(&a, &b, 1, &rt());
        let peer = awg(&b, &a, 2, &rt());
        let mut cb = vec![0u8; 2048];
        let (r, _) = ex(&client, Op::Force, &mut cb[..148]);
        let resp = answered(&peer, &cb[..r.size], 92);
        assert_eq!(window(&client), 500);
        let armed = Armed::new(50);
        let (r, i) = exb(&client, Op::Read(&resp), &mut cb, bt, 0);
        assert_eq!(
            (r.op, r.size, i.output_kind),
            (WTN, out, k(PacketKind::TransportKeepalive)),
            "bt {}",
            bt
        );
        assert!(armed.consumed());
        drop(armed);
        read_done(&peer, &cb[..r.size]);
    }
}

/// W-RESP: the response trailer (headroom 408, word 116) under a control
/// budget of 100 is 8 bytes -- 100, where unbounded gives 208 -- and the
/// peer accepts it. At a budget of exactly 92 there is nothing to draw: 92,
/// the word left armed.
#[test]
fn w_resp_clips_the_response_trailer() {
    for (bc, out, drawn) in [(100, 100, true), (0, 208, true), (92, 92, false)] {
        let (a, b) = (party(), party());
        let client = awg(&a, &b, 1, &rt());
        let peer = awg(&b, &a, 2, &rt());
        let mut pb = vec![0u8; 2048];
        let r = legacy(&peer, Op::Force, &mut pb[..148]);
        assert_eq!(r.size, 148);
        assert_eq!(window(&client), 500);
        let mut cb = vec![0u8; 2048];
        let armed = Armed::new(116);
        let (r, i) = exb(&client, Op::Read(&pb[..148]), &mut cb, 0, bc);
        assert_eq!(
            (r.op, r.size, i.output_kind),
            (WTN, out, k(PacketKind::HandshakeResponse)),
            "bc {}",
            bc
        );
        assert_eq!(armed.consumed(), drawn, "bc {}", bc);
        drop(armed);
        let keepalive = answered(&peer, &cb[..r.size], 32);
        assert_eq!(keepalive.len(), 32);
        read_done(&client, &keepalive);
    }
}

/// W-INIT: the initiation trailer (headroom 352, word 116) under a control
/// budget of 160 is 12 bytes -- 160, where unbounded gives 264 -- and the
/// peer answers it. At exactly 148: no draw.
#[test]
fn w_init_clips_the_initiation_trailer() {
    for (bc, out, drawn) in [(160, 160, true), (0, 264, true), (148, 148, false)] {
        let (a, b) = (party(), party());
        let client = awg(&a, &b, 1, &rt());
        let peer = awg(&b, &a, 2, &rt());
        assert_eq!(window(&client), 500);
        let mut cb = vec![0u8; 2048];
        let armed = Armed::new(116);
        let (r, i) = exb(&client, Op::Force, &mut cb, 0, bc);
        assert_eq!(
            (r.op, r.size, i.output_kind),
            (WTN, out, k(PacketKind::HandshakeInitiation)),
            "bc {}",
            bc
        );
        assert_eq!(armed.consumed(), drawn, "bc {}", bc);
        drop(armed);
        assert_eq!(answered(&peer, &cb[..r.size], 92).len(), 92);
    }
}

/// W-KA-TICK: the periodic keepalive at 1 s (headroom 468, word 50) under a
/// transport budget of 40: 40, where unbounded gives 82.
#[cfg(feature = "mock-instant")]
#[test]
fn w_ka_tick_clips_the_keepalive_padding() {
    for (bt, out) in [(40, 40), (0, 82)] {
        at(Duration::ZERO);
        let (client, peer) = h_rt(1);
        at(secs(1));
        assert_eq!(window(&client), 500);
        let mut cb = vec![0u8; 2048];
        let armed = Armed::new(50);
        let (r, i) = exb(&client, Op::Tick, &mut cb, bt, 0);
        assert_eq!(
            (r.op, r.size, i.output_kind),
            (WTN, out, k(PacketKind::TransportKeepalive)),
            "bt {}",
            bt
        );
        assert!(armed.consumed());
        drop(armed);
        read_done(&peer, &cb[..r.size]);
    }
}

// ---------------------------------------------------------------------------
// WIREGUARD_INFO_F_CONTROL_ORDINARY_JUNK_ONLY: C bounds ordinary Jc junk only
// ---------------------------------------------------------------------------

/// The header's value of `WIREGUARD_INFO_F_CONTROL_ORDINARY_JUNK_ONLY`.
const ORDINARY_JUNK_ONLY: u32 = 0x0000_0001;

/// The header defines the flag -- the one `WIREGUARD_INFO_F_*` bit -- and the
/// library's constant has the same value.
#[test]
fn the_header_defines_the_ordinary_junk_only_flag() {
    let header = include_str!("../wireguard_ffi.h");
    let defines: Vec<&str> = header
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("#define WIREGUARD_INFO_F_"))
        .collect();
    assert_eq!(defines.len(), 1, "{:?}", defines);
    let mut words = defines[0].split_whitespace().skip(1);
    assert_eq!(
        words.next(),
        Some("WIREGUARD_INFO_F_CONTROL_ORDINARY_JUNK_ONLY")
    );
    assert_eq!(words.next(), Some("0x00000001u"));
    assert_eq!(
        WIREGUARD_INFO_F_CONTROL_ORDINARY_JUNK_ONLY,
        ORDINARY_JUNK_ONLY
    );
}

/// Admission: the flag alone is accepted by all four `_ex` entry points,
/// with zero and finite budgets, at every alignment, with a zero tail up to
/// the largest size -- the call runs, writes `[16, 48)` and takes one
/// sequence number. Every other bit, alone or with the flag, and the flag
/// with a nonzero tail byte, are still 19 before anything runs: no byte
/// written, no sequence number, nothing admitted.
#[test]
fn the_flag_is_the_one_accepted_in_flags_bit() {
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let server = plain(&b, &a, 2, 0);
    establish(&client, &server);
    let mut dst = vec![0u8; 2048];
    let seq_of = |t: &Owned| unsafe { (*t.0).lock().op_state_mut().op_seq() };
    let p = ipv4(1, 100);
    let ops = [
        ("write", Op::Write(&p)),
        ("read", Op::Read(EMPTY)),
        ("tick", Op::Tick),
        ("force", Op::Force),
    ];
    let unknown = [
        0x0000_0002,
        0x0000_0004,
        0x8000_0000,
        ORDINARY_JUNK_ONLY | 0x0000_0002,
        ORDINARY_JUNK_ONLY | 0x8000_0000,
        u32::MAX,
    ];
    for at in 0..4 {
        let mut buf = vec![CANARY; 1024 + 64];
        for (name, op) in ops {
            let mut refused = Vec::new();
            for flags in unknown {
                for (bt, bc) in [(0, 0), (1400, 200)] {
                    refused.push((flags, 48u32, bt, bc, false));
                }
            }
            refused.push((ORDINARY_JUNK_ONLY, 64, 0, 0, true));
            refused.push((ORDINARY_JUNK_ONLY, 64, 1400, 200, true));
            for (flags, size, bt, bc, dirty_tail) in refused {
                buf.fill(CANARY);
                let m = &mut buf[at..];
                put(m, 0, size);
                put(m, 4, flags);
                put(m, 8, bt);
                put(m, 12, bc);
                if size > 48 {
                    m[48..size as usize].fill(0);
                }
                if dirty_tail {
                    m[size as usize - 1] = 1;
                }
                let before = buf.clone();
                let (seq, queued) = (seq_of(&client), client.with(|t| t.queued_len()));
                let r = unsafe {
                    raw_call(
                        client.0,
                        op,
                        &mut dst,
                        buf[at..].as_mut_ptr() as *mut wireguard_packet_info,
                    )
                };
                let case = format!("offset {} {} flags {:#x} size {}", at, name, flags, size);
                assert_eq!((r.op, r.size), (ERR, 19), "{}", case);
                assert_eq!(buf, before, "{}: nothing written", case);
                assert_eq!(seq_of(&client), seq, "{}: no sequence", case);
                assert_eq!(
                    client.with(|t| t.queued_len()),
                    queued,
                    "{}: not admitted",
                    case
                );
            }

            for (size, bt, bc) in [
                (48u32, 0u32, 0u32),
                (48, 1400, 0),
                (64, 0, 200),
                (1024, 1, 1),
                (1024, u32::MAX, u32::MAX),
            ] {
                buf.fill(CANARY);
                let m = &mut buf[at..];
                put(m, 0, size);
                put(m, 4, ORDINARY_JUNK_ONLY);
                put(m, 8, bt);
                put(m, 12, bc);
                m[48..size as usize].fill(0);
                let before = buf.clone();
                let seq = seq_of(&client);
                let r = unsafe {
                    raw_call(
                        client.0,
                        op,
                        &mut dst,
                        buf[at..].as_mut_ptr() as *mut wireguard_packet_info,
                    )
                };
                let case = format!("offset {} {} size {} bt {} bc {}", at, name, size, bt, bc);
                assert_ne!((r.op, r.size), (ERR, 19), "{}: accepted", case);
                assert_eq!(&buf[..at + 16], &before[..at + 16], "{}: inputs", case);
                assert_eq!(&buf[at + 48..], &before[at + 48..], "{}: tail", case);
                let m = &buf[at..];
                assert_eq!(get(m, 16), 48, "{}: written_size", case);
                assert_eq!(
                    (u64::from(get(m, 40)) << 32) | u64::from(get(m, 36)),
                    seq + 1,
                    "{}: one sequence number",
                    case
                );
            }
        }
    }
}

/// Ordinary Jc junk under the flag: each item is drawn from [min(Jmin, C),
/// min(Jmax, C)], as without it (decision 1A), with Jc and the configured
/// bounds untouched. A `dst` one byte short of the working maximum is 0
/// before the draw -- nothing drawn, the item still owed -- and the working
/// maximum fits whatever is drawn. The owner's 1000..=1280 at C 572 is 572,
/// item after item. The initiation behind the burst is not junk: under the
/// same C, 1 included, it is the whole 148 bytes and the peer answers it.
#[test]
fn flag_mode_ordinary_junk_is_clamped_at_both_ends() {
    // (case, configured Jmin..=Jmax, C, working lo..=hi)
    type Case = (&'static str, (u32, u32), u32, (usize, usize));
    let cases: [Case; 7] = [
        ("1000..1280 at 572", (1000, 1280), 572, (572, 572)),
        ("100..1280 at 572", (100, 1280), 572, (100, 572)),
        ("C equal to Jmax", (100, 572), 572, (100, 572)),
        ("C equal to Jmin", (572, 1280), 572, (572, 572)),
        ("C above the range", (100, 1000), 1200, (100, 1000)),
        ("C 1", (1000, 1280), 1, (1, 1)),
        ("C 0", (1000, 1280), 0, (1000, 1280)),
    ];
    for (name, (lo, hi), bc, (wlo, whi)) in cases {
        let (a, b) = (party(), party());
        let client = awg(&a, &b, 1, &junk_profile(3, lo, hi));
        let server = plain(&b, &a, 2, 0);
        let mut dst = vec![0u8; 2048];
        let mut sizes = Vec::new();
        for left in (0..3u16).rev() {
            // The force prepares the burst; ticks serve it.
            let op = if left == 2 { Op::Force } else { Op::Tick };
            let pos = client.with(|t| t.rng_word_pos());
            let (r, i) = exf(&client, op, &mut dst[..whi - 1], ORDINARY_JUNK_ONLY, 0, bc);
            assert_eq!((r.op, r.size), (ERR, STORAGE), "{}", name);
            assert_eq!(
                (i.events & !ev::BURST_PREPARED, i.state, i.burst_due_ms),
                (0, st::BURST_PENDING, 0),
                "{}: due but blocked",
                name
            );
            assert_eq!(client.with(|t| t.rng_word_pos()), pos, "{}: no draw", name);
            assert_eq!(
                client.with(|t| t.pending_burst_shape()),
                Some((0, left + 1)),
                "{}: nothing consumed",
                name
            );

            let (r, i) = exf(
                &client,
                Op::Tick,
                &mut dst[..whi],
                ORDINARY_JUNK_ONLY,
                0,
                bc,
            );
            assert_eq!(
                (r.op, i.output_kind),
                (WTN, k(PacketKind::Junk)),
                "{}",
                name
            );
            assert_eq!(client.with(|t| t.pending_burst_shape()), Some((0, left)));
            sizes.push(r.size);
        }
        assert!(
            sizes.iter().all(|s| (wlo..=whi).contains(s)),
            "{}: {:?} outside {}..={}",
            name,
            sizes,
            wlo,
            whi
        );
        let (r, i) = exf(&client, Op::Tick, &mut dst, ORDINARY_JUNK_ONLY, 0, bc);
        assert_eq!(
            (r.op, r.size, i.output_kind),
            (WTN, 148, k(PacketKind::HandshakeInitiation)),
            "{}",
            name
        );
        assert_eq!(answered(&server, &dst[..148], 2048).len(), 92);
        let cfg = client.with(|t| t.amnezia_config().pre_handshake_junk);
        assert_eq!(
            (cfg.packet_count, cfg.packet_size_min, cfg.packet_size_max),
            (3, lo as u16, hi as u16),
            "{}: the configuration is not rewritten",
            name
        );
    }
}

/// One operation stream under the flag: two ordinary junk items capped to
/// C 572, then the initiation -- 648 bytes with S1 500, over C -- produced
/// whole once `dst` holds it (one byte short is 0, the burst still owing
/// it). The responder answers it under the flag with C 1: one byte short of
/// the 192-byte S2 response is 0 with nothing accepted, then the whole
/// response; the initiator confirms it with C 1 and data then flows. The
/// flag-clear twin of the same stream refuses that initiation and that
/// response with 18 at C 572 and C 191, and sends them at C 648 and C 192.
#[test]
fn flag_mode_handshake_after_capped_junk_is_whole() {
    let client_cfg = wireguard_awg_params {
        s1_init_junk: 500,
        s2_response_junk: 100,
        ..junk_profile(2, 1000, 1280)
    };
    let server_cfg = wireguard_awg_params {
        s1_init_junk: 500,
        s2_response_junk: 100,
        ..params()
    };
    for flagged in [true, false] {
        let f = if flagged { ORDINARY_JUNK_ONLY } else { 0 };
        let (a, b) = (party(), party());
        let client = awg(&a, &b, 1, &client_cfg);
        let server = awg(&b, &a, 2, &server_cfg);
        let (mut cb, mut sb) = (vec![0u8; 2048], vec![0u8; 2048]);

        for op in [Op::Force, Op::Tick] {
            let (r, i) = exf(&client, op, &mut cb, f, 0, 572);
            assert_eq!(
                (r.op, r.size, i.output_kind),
                (WTN, 572, k(PacketKind::Junk)),
                "flag {}",
                flagged
            );
        }
        let init = if flagged {
            let (r, i) = exf(&client, Op::Tick, &mut cb[..647], f, 0, 572);
            assert_eq!((r.op, r.size), (ERR, STORAGE));
            assert_eq!(
                (facts(&i), i.burst_due_ms),
                ((0, 0, 0, st::BURST_PENDING), 0)
            );
            let (r, i) = exf(&client, Op::Tick, &mut cb, f, 0, 572);
            assert_eq!((r.op, r.size), (WTN, 648));
            assert_eq!(
                (facts(&i), i.burst_due_ms),
                (
                    (
                        0,
                        k(PacketKind::HandshakeInitiation),
                        ev::INITIATION_PRODUCED,
                        st::INITIATION_PENDING
                    ),
                    BURST_DUE_NONE
                )
            );
            cb[..648].to_vec()
        } else {
            let (r, i) = exb(&client, Op::Tick, &mut cb, 0, 572);
            assert_eq!((r.op, r.size), (ERR, BUDGET));
            assert_eq!(facts(&i), (0, 0, 0, st::BURST_PENDING));
            let (r, _) = exb(&client, Op::Tick, &mut cb, 0, 648);
            assert_eq!((r.op, r.size), (WTN, 648));
            cb[..648].to_vec()
        };

        let (short, bc) = if flagged { (191, 1) } else { (2048, 191) };
        let (r, i) = exf(&server, Op::Read(&init), &mut sb[..short], f, 0, bc);
        let want = if flagged { STORAGE } else { BUDGET };
        assert_eq!((r.op, r.size), (ERR, want), "flag {}", flagged);
        assert_eq!(facts(&i), (0, 0, 0, 0), "nothing accepted");
        let (r, i) = exf(
            &server,
            Op::Read(&init),
            &mut sb,
            f,
            0,
            if flagged { 1 } else { 192 },
        );
        assert_eq!((r.op, r.size), (WTN, 192), "flag {}", flagged);
        assert_eq!(
            facts(&i),
            (
                k(PacketKind::HandshakeInitiation),
                k(PacketKind::HandshakeResponse),
                ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED | ev::SESSION_STORED,
                0
            )
        );
        let resp = sb[..192].to_vec();

        let (r, i) = exf(&client, Op::Read(&resp), &mut cb, f, 0, 1);
        assert_eq!(
            (r.op, r.size, i.output_kind, i.state),
            (
                WTN,
                32,
                k(PacketKind::TransportKeepalive),
                st::SESSION_CURRENT
            )
        );
        let keepalive = cb[..32].to_vec();
        let (r, i) = exf(&server, Op::Read(&keepalive), &mut sb, f, 0, 1);
        assert_eq!((r.op, i.state), (DONE, st::SESSION_CURRENT));
        let (r, _) = exf(&client, Op::Write(&ipv4(7, 100)), &mut cb, f, 0, 1);
        assert_eq!(r.op, WTN);
        assert_eq!(delivered(&server, &cb[..r.size]), (7, 100));
    }
}

/// The optional bytes of excluded control are not clipped by C under the
/// flag: with the same armed RandomTrailers word, an initiation and a
/// response under the flag with C 1 have exactly the length of their C 0
/// twins -- 264 and 208, the word consumed -- and the peer completes each
/// handshake. Flag-clear C 1 refuses both with 18 before the draw.
#[test]
fn flag_mode_keeps_handshake_trailers_whole() {
    let modes = [
        (ORDINARY_JUNK_ONLY, 1u32, Ok(())),
        (ORDINARY_JUNK_ONLY, 0, Ok(())),
        (0, 0, Ok(())),
        (0, 1, Err(BUDGET)),
    ];
    for (f, bc, want) in modes {
        // W-INIT: headroom 352, word 116.
        let (a, b) = (party(), party());
        let client = awg(&a, &b, 1, &rt());
        let peer = awg(&b, &a, 2, &rt());
        let mut cb = vec![0u8; 2048];
        let armed = Armed::new(116);
        let (r, i) = exf(&client, Op::Force, &mut cb, f, 0, bc);
        match want {
            Ok(()) => {
                assert_eq!(
                    (r.op, r.size, i.output_kind),
                    (WTN, 264, k(PacketKind::HandshakeInitiation)),
                    "init flags {} bc {}",
                    f,
                    bc
                );
                assert!(armed.consumed());
                drop(armed);
                assert_eq!(answered(&peer, &cb[..r.size], 92).len(), 92);
            }
            Err(code) => {
                assert_eq!((r.op, r.size), (ERR, code));
                assert!(!armed.consumed(), "refused before the draw");
            }
        }

        // W-RESP: headroom 408, word 116.
        let (a, b) = (party(), party());
        let client = awg(&a, &b, 1, &rt());
        let peer = awg(&b, &a, 2, &rt());
        let mut pb = vec![0u8; 2048];
        assert_eq!(legacy(&peer, Op::Force, &mut pb[..148]).size, 148);
        let mut cb = vec![0u8; 2048];
        let armed = Armed::new(116);
        let (r, i) = exf(&client, Op::Read(&pb[..148]), &mut cb, f, 0, bc);
        match want {
            Ok(()) => {
                assert_eq!(
                    (r.op, r.size, i.output_kind),
                    (WTN, 208, k(PacketKind::HandshakeResponse)),
                    "resp flags {} bc {}",
                    f,
                    bc
                );
                assert!(armed.consumed());
                drop(armed);
                let keepalive = answered(&peer, &cb[..r.size], 32);
                read_done(&client, &keepalive);
            }
            Err(code) => {
                assert_eq!((r.op, r.size), (ERR, code));
                assert_eq!(facts(&i), (0, 0, 0, 0), "nothing accepted");
                assert!(!armed.consumed());
            }
        }
    }
}

/// Protocol-shaped Jc junk and whole imitation datagrams are not ordinary
/// junk. For DNS, QUIC, SIP and STUN, on one burst: a flag-clear call still
/// honours a finite C -- the imitation datagram at one byte under its length
/// and the Jc item at one byte under its protocol minimum are 18 -- while
/// under the flag the same imitation datagram goes out whole with C 1, the
/// bytes that were pending, and each Jc item is drawn from the whole
/// protocol range with C below its minimum: a `dst` one short of the
/// protocol maximum is 0 with nothing drawn, and the item lies in
/// [min, max]. The initiation then goes out at 148 under C 1.
#[test]
fn flag_mode_leaves_protocol_junk_and_imitation_whole() {
    for (protocol, browser, (pmin, pmax)) in [
        (AmneziaImitationProtocol::Dns, 0u32, (50usize, 200usize)),
        (AmneziaImitationProtocol::Quic, 1, (1200, 1252)),
        (AmneziaImitationProtocol::Sip, 0, (200, 1200)),
        (AmneziaImitationProtocol::Stun, 0, (28, 100)),
    ] {
        let (a, b) = (party(), party());
        let client = awg(
            &a,
            &b,
            1,
            &wireguard_awg_params {
                imitation_protocol: protocol as u32,
                imitation_browser: browser,
                junk_packet_count: 2,
                ..params()
            },
        );
        let server = plain(&b, &a, 2, 0);
        let mut dst = vec![0u8; 2048];

        // A flag-clear C 1 prepares the burst and refuses its first datagram.
        let (r, i) = exb(&client, Op::Force, &mut dst, 0, 1);
        assert_eq!((r.op, r.size), (ERR, BUDGET), "{:?}", protocol);
        assert_eq!(
            facts(&i),
            (0, 0, ev::BURST_PREPARED, st::BURST_PENDING),
            "{:?}",
            protocol
        );
        let total = client.with(|t| t.pending_burst_shape()).unwrap().0;
        assert!(total >= 1, "{:?}", protocol);
        for n in 0..total {
            if n > 0 {
                advance(Duration::from_millis(20));
            }
            let item = client.with(|t| t.pending_front_imitation()).unwrap();
            let len = item.len();
            let (r, i) = exb(&client, Op::Tick, &mut dst, 0, len as u32 - 1);
            assert_eq!(
                (r.op, r.size, facts(&i)),
                (ERR, BUDGET, (0, 0, 0, st::BURST_PENDING)),
                "{:?} item {}: flag clear",
                protocol,
                n
            );
            let (r, _) = exf(
                &client,
                Op::Tick,
                &mut dst[..len - 1],
                ORDINARY_JUNK_ONLY,
                0,
                1,
            );
            assert_eq!(
                (r.op, r.size),
                (ERR, STORAGE),
                "{:?} item {}: storage still decides",
                protocol,
                n
            );
            assert_eq!(client.with(|t| t.pending_front_imitation()).unwrap(), item);
            let (r, i) = exf(&client, Op::Tick, &mut dst[..len], ORDINARY_JUNK_ONLY, 0, 1);
            assert_eq!(
                (r.op, r.size, i.output_kind),
                (WTN, len, k(PacketKind::Imitation)),
                "{:?} item {}",
                protocol,
                n
            );
            assert_eq!(&dst[..len], &item[..], "the pending bytes, whole");
        }
        assert_eq!(client.with(|t| t.pending_burst_shape()), Some((0, 2)));

        let below = pmin as u32 - 1;
        let pos = client.with(|t| t.rng_word_pos());
        let (r, i) = exb(&client, Op::Tick, &mut dst, 0, below);
        assert_eq!(
            (r.op, r.size, facts(&i)),
            (ERR, BUDGET, (0, 0, 0, st::BURST_PENDING)),
            "{:?}: flag clear C {}",
            protocol,
            below
        );
        let (r, _) = exf(
            &client,
            Op::Tick,
            &mut dst[..pmax - 1],
            ORDINARY_JUNK_ONLY,
            0,
            below,
        );
        assert_eq!(
            (r.op, r.size),
            (ERR, STORAGE),
            "{:?}: the protocol maximum",
            protocol
        );
        assert_eq!(client.with(|t| t.rng_word_pos()), pos, "nothing drawn");
        for (bc, left) in [(below, 1u16), (1, 0)] {
            let (r, i) = exf(
                &client,
                Op::Tick,
                &mut dst[..pmax],
                ORDINARY_JUNK_ONLY,
                0,
                bc,
            );
            assert_eq!(
                (r.op, i.output_kind),
                (WTN, k(PacketKind::Junk)),
                "{:?} C {}",
                protocol,
                bc
            );
            assert!(
                (pmin..=pmax).contains(&r.size),
                "{:?} C {}: {} not in {}..={}",
                protocol,
                bc,
                r.size,
                pmin,
                pmax
            );
            assert_eq!(client.with(|t| t.pending_burst_shape()), Some((0, left)));
        }
        let (r, i) = exf(&client, Op::Tick, &mut dst, ORDINARY_JUNK_ONLY, 0, 1);
        assert_eq!(
            (r.op, r.size, i.output_kind),
            (WTN, 148, k(PacketKind::HandshakeInitiation)),
            "{:?}",
            protocol
        );
        answered(&server, &dst[..148], 2048);
    }
}

/// Storage, pending order and pacing under the flag (mock clock, Jd 10 ms,
/// C 572 for 1000..=1280). A `dst` below the working maximum is 0 with
/// nothing drawn and nothing consumed, and the next call with room sends
/// that item. A pre-due call is DONE with or without the flag -- no extra
/// item, no draw -- until Jd has passed; a due item short of storage is 0
/// with due 0. The initiation behind the burst keeps its pacing and its
/// storage refusal, under C 1.
#[cfg(feature = "mock-instant")]
#[test]
fn flag_mode_keeps_storage_order_and_pacing() {
    at(Duration::ZERO);
    let (a, b) = (party(), party());
    let client = awg(
        &a,
        &b,
        1,
        &wireguard_awg_params {
            junk_packet_delay_ms: 10,
            ..junk_profile(3, 1000, 1280)
        },
    );
    let server = plain(&b, &a, 2, 0);
    let mut dst = vec![0u8; 2048];
    let f = ORDINARY_JUNK_ONLY;
    let pos = client.with(|t| t.rng_word_pos());

    let (r, i) = exf(&client, Op::Force, &mut dst[..571], f, 0, 572);
    assert_eq!((r.op, r.size), (ERR, STORAGE));
    assert_eq!(
        (facts(&i), i.burst_due_ms),
        ((0, 0, ev::BURST_PREPARED, st::BURST_PENDING), 0)
    );
    assert_eq!(client.with(|t| t.rng_word_pos()), pos, "nothing drawn");
    assert_eq!(client.with(|t| t.pending_burst_shape()), Some((0, 3)));

    let (r, i) = exf(&client, Op::Tick, &mut dst[..572], f, 0, 572);
    assert_eq!(
        (r.op, r.size, i.output_kind),
        (WTN, 572, k(PacketKind::Junk))
    );
    assert_eq!(i.burst_due_ms, 10);
    assert_eq!(client.with(|t| t.pending_burst_shape()), Some((0, 2)));

    let pos = client.with(|t| t.rng_word_pos());
    for (flags, bc) in [(f, 572), (0, 572), (f, 1), (0, 0)] {
        let (r, i) = exf(&client, Op::Tick, &mut dst, flags, 0, bc);
        assert_eq!(
            (r.op, r.size, i.burst_due_ms),
            (DONE, 0, 10),
            "pre-due, flags {} bc {}",
            flags,
            bc
        );
    }
    at(Duration::from_millis(9));
    let (r, i) = exf(&client, Op::Tick, &mut dst, f, 0, 572);
    assert_eq!((r.op, i.burst_due_ms), (DONE, 1));
    assert_eq!(
        client.with(|t| t.rng_word_pos()),
        pos,
        "pre-due draws nothing"
    );
    assert_eq!(client.with(|t| t.pending_burst_shape()), Some((0, 2)));

    at(Duration::from_millis(10));
    let (r, i) = exf(&client, Op::Tick, &mut dst[..571], f, 0, 572);
    assert_eq!((r.op, r.size, i.burst_due_ms), (ERR, STORAGE, 0));
    assert_eq!(client.with(|t| t.rng_word_pos()), pos);
    assert_eq!(client.with(|t| t.pending_burst_shape()), Some((0, 2)));
    let (r, _) = exf(&client, Op::Tick, &mut dst[..572], f, 0, 572);
    assert_eq!((r.op, r.size), (WTN, 572));
    assert_eq!(client.with(|t| t.pending_burst_shape()), Some((0, 1)));

    at(Duration::from_millis(20));
    let (r, i) = exf(&client, Op::Tick, &mut dst, f, 0, 572);
    assert_eq!((r.op, r.size, i.burst_due_ms), (WTN, 572, 10));
    assert_eq!(client.with(|t| t.pending_burst_shape()), Some((0, 0)));

    at(Duration::from_millis(25));
    let (r, i) = exf(&client, Op::Tick, &mut dst, f, 0, 1);
    assert_eq!((r.op, i.burst_due_ms), (DONE, 5));
    at(Duration::from_millis(30));
    let (r, i) = exf(&client, Op::Tick, &mut dst[..147], f, 0, 1);
    assert_eq!(
        (r.op, r.size, facts(&i), i.burst_due_ms),
        (ERR, STORAGE, (0, 0, 0, st::BURST_PENDING), 0)
    );
    let (r, i) = exf(&client, Op::Tick, &mut dst[..148], f, 0, 1);
    assert_eq!(
        (r.op, r.size, i.output_kind, i.burst_due_ms),
        (WTN, 148, k(PacketKind::HandshakeInitiation), BURST_DUE_NONE)
    );
    answered(&server, &dst[..148], 2048);
}

/// No mode or limit outlives its call, on one tunnel or across two. One
/// burst (S1 500, Jc 4, 1000..=1280) served by alternating calls: flag C 572
/// is 572, flag-clear C 0 is in 1000..=1280, flag C 1 is 1, flag-clear C 700
/// is 700. A flag call on another tunnel changes nothing here: the
/// 648-byte initiation is then 18 for a flag-clear C 572 call -- the burst
/// keeping it -- and produced by the next call with the flag. Every call
/// takes one sequence number, the refused one included.
#[test]
fn the_flag_and_c_belong_to_one_call() {
    let cfg = wireguard_awg_params {
        s1_init_junk: 500,
        ..junk_profile(4, 1000, 1280)
    };
    let server_cfg = wireguard_awg_params {
        s1_init_junk: 500,
        ..params()
    };
    let (a, b, c) = (party(), party(), party());
    let client = awg(&a, &b, 1, &cfg);
    let other = awg(&c, &b, 3, &cfg);
    let server = awg(&b, &a, 2, &server_cfg);
    let mut dst = vec![0u8; 2048];
    let f = ORDINARY_JUNK_ONLY;

    let (r, i) = exf(&client, Op::Force, &mut dst, f, 0, 572);
    assert_eq!(
        (r.op, r.size, i.output_kind),
        (WTN, 572, k(PacketKind::Junk))
    );
    let seq = op_seq(&i);
    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 0);
    assert_eq!((r.op, i.output_kind), (WTN, k(PacketKind::Junk)));
    assert!((1000..=1280).contains(&r.size), "{}", r.size);
    let (r, _) = exf(&client, Op::Tick, &mut dst, f, 0, 1);
    assert_eq!((r.op, r.size), (WTN, 1));
    let (r, _) = exb(&client, Op::Tick, &mut dst, 0, 700);
    assert_eq!((r.op, r.size), (WTN, 700));
    assert_eq!(client.with(|t| t.pending_burst_shape()), Some((0, 0)));

    let (r, _) = exf(&other, Op::Force, &mut dst, f, 0, 1);
    assert_eq!((r.op, r.size), (WTN, 1));

    let (r, i) = exb(&client, Op::Tick, &mut dst, 0, 572);
    assert_eq!((r.op, r.size), (ERR, BUDGET));
    assert_eq!(
        (facts(&i), i.burst_due_ms, op_seq(&i)),
        ((0, 0, 0, st::BURST_PENDING), 0, seq + 4)
    );
    let (r, i) = exf(&client, Op::Tick, &mut dst, f, 0, 572);
    assert_eq!(
        (r.op, r.size, i.output_kind, op_seq(&i)),
        (WTN, 648, k(PacketKind::HandshakeInitiation), seq + 5)
    );
    assert_eq!(answered(&server, &dst[..648], 2048).len(), 92);
}

/// The flag never touches transport: with it set and C 1, a finite T still
/// refuses an over-budget write with 18 -- no nonce spent: the next frame
/// is counter 1 -- and clips data padding to T; the response keepalive's
/// padding is clipped by T (W-RKA's 40 against 82); and a drain deletes a
/// head whose mandatory frame exceeds T and emits the next one, while a
/// fitting head short of storage stays queued with 0.
#[test]
fn flag_mode_leaves_the_transport_budget_in_charge() {
    let f = ORDINARY_JUNK_ONLY;
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let server = plain(&b, &a, 2, 0);
    establish(&client, &server);
    let mut dst = vec![0u8; 2048];
    let p = ipv4(1, 1169);
    let (r, i) = exf(&client, Op::Write(&p), &mut dst, f, 1200, 1);
    assert_eq!((r.op, r.size, facts(&i)), (ERR, BUDGET, (0, 0, 0, CUR)));
    let (r, _) = exf(&client, Op::Write(&p), &mut dst, f, 0, 1);
    assert_eq!((r.op, r.size), (WTN, 1216));
    assert_eq!(counter_of(&dst[..r.size]), 1, "the refusal spent no nonce");
    assert_eq!(delivered(&server, &dst[..r.size]), (1, 1169));
    for (bt, out) in [(1216, 1216), (1201, 1201)] {
        let (r, i) = exf(&client, Op::Write(&p), &mut dst, f, bt, 1);
        assert_eq!(
            (r.op, r.size, i.output_kind),
            (WTN, out, k(PacketKind::TransportData))
        );
        assert_eq!(delivered(&server, &dst[..r.size]), (1, 1169));
    }

    // W-RKA under the flag.
    for (bt, out) in [(40, 40), (0, 82)] {
        let (a, b) = (party(), party());
        let client = awg(&a, &b, 1, &rt());
        let peer = awg(&b, &a, 2, &rt());
        let mut cb = vec![0u8; 2048];
        let (r, _) = ex(&client, Op::Force, &mut cb[..148]);
        let resp = answered(&peer, &cb[..r.size], 92);
        let armed = Armed::new(50);
        let (r, i) = exf(&client, Op::Read(&resp), &mut cb, f, bt, 1);
        assert_eq!(
            (r.op, r.size, i.output_kind),
            (WTN, out, k(PacketKind::TransportKeepalive)),
            "bt {}",
            bt
        );
        assert!(armed.consumed());
        drop(armed);
        read_done(&peer, &cb[..r.size]);
    }

    // The drain: an oversized head deleted, the next emitted.
    let (client, server) = queued_pair(&[1400, 100]);
    let mut d = vec![0u8; 1232];
    let (r, i) = exf(&client, Op::Read(EMPTY), &mut d, f, 1200, 1);
    assert_eq!(
        (r, facts(&i)),
        (
            Res { op: WTN, size: 144 },
            (0, DATA, QUEUE_HEAD_DROPPED, CUR)
        )
    );
    assert_eq!(delivered(&server, &d[..144]).0, 2);
    // A fitting head short of storage: kept, 0, then sent.
    let (client, server) = queued_pair(&[1100]);
    let mut d = vec![0u8; 1100];
    let (r, i) = exf(&client, Op::Read(EMPTY), &mut d, f, 1200, 1);
    assert_eq!((r.op, r.size, facts(&i)), (ERR, STORAGE, (0, 0, 0, CUR_Q)));
    let (r, i) = exf(&client, Op::Read(EMPTY), &mut dst, f, 1200, 1);
    assert_eq!((r.op, r.size, facts(&i)), (WTN, 1136, (0, DATA, 0, CUR)));
    assert_eq!(delivered(&server, &dst[..1136]).0, 1);
}

/// W-KA-TICK under the flag: the periodic keepalive's padding is clipped by
/// T, whatever C: 40 against 82.
#[cfg(feature = "mock-instant")]
#[test]
fn flag_mode_tick_keepalive_obeys_the_transport_budget() {
    for (bt, out) in [(40, 40), (0, 82)] {
        at(Duration::ZERO);
        let (client, peer) = h_rt(1);
        at(secs(1));
        let mut cb = vec![0u8; 2048];
        let armed = Armed::new(50);
        let (r, i) = exf(&client, Op::Tick, &mut cb, ORDINARY_JUNK_ONLY, bt, 1);
        assert_eq!(
            (r.op, r.size, i.output_kind),
            (WTN, out, k(PacketKind::TransportKeepalive)),
            "bt {}",
            bt
        );
        assert!(armed.consumed());
        drop(armed);
        read_done(&peer, &cb[..r.size]);
    }
}
