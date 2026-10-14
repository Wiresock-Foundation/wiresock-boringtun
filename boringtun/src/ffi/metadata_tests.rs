// Copyright (c) 2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! `wireguard_*_ex` metadata, observed through the exported C functions.
//!
//! Every fact asserted here comes out of the real Rust paths: real handshakes
//! between tunnels with synthetic keys, real bursts, real queues and real
//! forgeries. No fixture assigns a kind, an event or a state bit. The only
//! crate-internal reads are of what a tunnel actually prepared
//! (`pending_burst_shape`) and of the sequence seam, to check the reported
//! values against the source state they describe.
//!
//! Runs under `ffi-bindings` alone; with `mock-instant` as well, the pacing
//! assertions become exact (the clock does not move unless the test moves it).

use super::*;
use crate::noise::op_report::{event as ev, state as st, PacketKind, BURST_DUE_NONE};
use crate::noise::rate_limiter::RateLimiter;
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

const DONE: u32 = 0;
const WTN: u32 = 1;
const ERR: u32 = 2;
const WTT4: u32 = 4;

type Tunnel = *mut Mutex<Tunn>;

/// A tunnel freed on drop.
struct Owned(Tunnel);

impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { tunnel_free(self.0) }
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

/// An older AmneziaWG profile through the legacy junk constructor: S1-S4,
/// H1-H4 and a Jc burst with no pacing delay.
fn legacy_awg(me: &Party, peer: &Party, index: u32) -> Owned {
    built(unsafe {
        new_tunnel_with_amnezia_junk(
            b64(&me.secret.to_bytes()).as_ptr(),
            b64(peer.public.as_bytes()).as_ptr(),
            ptr::null(),
            0,
            index,
            1_000,
            1_999,
            2_000,
            2_999,
            3_000,
            3_999,
            4_000,
            4_999,
            24,
            32,
            16,
            8,
            2,
            40,
            70,
            0,
        )
    })
}

fn awg(me: &Party, peer: &Party, index: u32, params: &wireguard_awg_params) -> Owned {
    built(unsafe {
        new_tunnel_with_awg_params(
            b64(&me.secret.to_bytes()).as_ptr(),
            b64(peer.public.as_bytes()).as_ptr(),
            ptr::null(),
            0,
            index,
            params,
            ptr::null(),
        )
    })
}

fn params() -> wireguard_awg_params {
    wireguard_awg_params {
        size: AWG_PARAMS_SIZE_VER2 as u32,
        ..Default::default()
    }
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

fn new_info() -> wireguard_packet_info {
    wireguard_packet_info {
        size: WIREGUARD_PACKET_INFO_SIZE_V1,
        ..Default::default()
    }
}

/// How a call is made: the legacy symbol, `_ex` with NULL, or `_ex` with
/// metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Api {
    Legacy,
    Null,
    Info,
}

#[derive(Clone, Copy)]
enum Op<'a> {
    Write(&'a [u8]),
    Read(&'a [u8]),
    Tick,
    Force,
}

fn call(api: Api, t: &Owned, op: Op, dst: &mut [u8]) -> (Res, Option<wireguard_packet_info>) {
    let mut info = new_info();
    let p: *mut wireguard_packet_info = match api {
        Api::Info => &mut info,
        _ => ptr::null_mut(),
    };
    let (d, dl, t) = (dst.as_mut_ptr(), dst.len() as u32, t.0);
    let r = unsafe {
        match (api, op) {
            (Api::Legacy, Op::Write(s)) => wireguard_write(t, s.as_ptr(), s.len() as u32, d, dl),
            (Api::Legacy, Op::Read(s)) => wireguard_read(t, s.as_ptr(), s.len() as u32, d, dl),
            (Api::Legacy, Op::Tick) => wireguard_tick(t, d, dl),
            (Api::Legacy, Op::Force) => wireguard_force_handshake(t, d, dl),
            (_, Op::Write(s)) => wireguard_write_ex(t, s.as_ptr(), s.len() as u32, d, dl, p),
            (_, Op::Read(s)) => wireguard_read_ex(t, s.as_ptr(), s.len() as u32, d, dl, p),
            (_, Op::Tick) => wireguard_tick_ex(t, d, dl, p),
            (_, Op::Force) => wireguard_force_handshake_ex(t, d, dl, p),
        }
    };
    (res(r), (api == Api::Info).then_some(info))
}

/// One `_ex` call with metadata.
fn ex(t: &Owned, op: Op, dst: &mut [u8]) -> (Res, wireguard_packet_info) {
    let (r, info) = call(Api::Info, t, op, dst);
    let info = info.unwrap();
    assert_eq!(info.written_size, 48, "a conforming result writes 48");
    (r, info)
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

/// A UDP/IPv4 packet carrying `tag` -- distinct per packet, so a payload that
/// arrives twice or out of order is visible.
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

fn advance(d: Duration) {
    #[cfg(feature = "mock-instant")]
    mock_instant::thread_local::MockClock::advance(d);
    #[cfg(not(feature = "mock-instant"))]
    std::thread::sleep(d);
}

/// `client` initiates (no burst configured) and both ends end up with a
/// current session, through legacy calls.
fn establish(client: &Owned, server: &Owned) {
    let (mut cb, mut sb) = (vec![0u8; 2048], vec![0u8; 2048]);
    let (r, _) = call(Api::Legacy, client, Op::Force, &mut cb);
    assert_eq!(r.op, WTN);
    let init = cb[..r.size].to_vec();
    let (r, _) = call(Api::Legacy, server, Op::Read(&init), &mut sb);
    assert_eq!(r.op, WTN);
    let resp = sb[..r.size].to_vec();
    let (r, _) = call(Api::Legacy, client, Op::Read(&resp), &mut cb);
    assert_eq!(r.op, WTN);
    let keepalive = cb[..r.size].to_vec();
    let (r, _) = call(Api::Legacy, server, Op::Read(&keepalive), &mut sb);
    assert_eq!(r.op, DONE);
}

/// The drain input: empty, from a non-NULL pointer.
const EMPTY: &[u8] = &[];

// ---------------------------------------------------------------------------
// ABI
// ---------------------------------------------------------------------------

/// Size, alignment, every offset, and every published value, as literals --
/// the same literals `scripts/ffi-layout-check.c` asserts -- and the values
/// `wireguard_ffi.h` defines, read from the header text itself.
#[test]
fn packet_info_layout_and_values_are_pinned() {
    use std::mem::{align_of, size_of};
    assert_eq!(size_of::<wireguard_packet_info>(), 48);
    assert_eq!(align_of::<wireguard_packet_info>(), 4);
    let p = wireguard_packet_info::default();
    let base = ptr::addr_of!(p) as usize;
    let fields: [(&str, usize, usize); 12] = [
        ("size", ptr::addr_of!(p.size) as usize, 0),
        ("in_flags", ptr::addr_of!(p.in_flags) as usize, 4),
        (
            "max_transport_output",
            ptr::addr_of!(p.max_transport_output) as usize,
            8,
        ),
        (
            "max_control_output",
            ptr::addr_of!(p.max_control_output) as usize,
            12,
        ),
        ("written_size", ptr::addr_of!(p.written_size) as usize, 16),
        ("input_kind", ptr::addr_of!(p.input_kind) as usize, 20),
        ("output_kind", ptr::addr_of!(p.output_kind) as usize, 24),
        ("events", ptr::addr_of!(p.events) as usize, 28),
        ("state", ptr::addr_of!(p.state) as usize, 32),
        ("op_seq_lo", ptr::addr_of!(p.op_seq_lo) as usize, 36),
        ("op_seq_hi", ptr::addr_of!(p.op_seq_hi) as usize, 40),
        ("burst_due_ms", ptr::addr_of!(p.burst_due_ms) as usize, 44),
    ];
    // Twelve fields at distinct 4-byte steps in 48 bytes: every one is
    // exactly 4 wide.
    for (name, at, want) in fields {
        assert_eq!(at - base, want, "{} moved", name);
    }
    assert_eq!(WIREGUARD_PACKET_INFO_SIZE_V1, 48);
    assert_eq!(WIREGUARD_PACKET_INFO_SIZE_MAX, 1024);
    assert_eq!(WIREGUARD_PACKET_INFO_OUTPUT_START, 16);
    assert_eq!(BURST_DUE_NONE, 0xFFFF_FFFF);
    assert_eq!(
        crate::noise::errors::WireGuardError::InvalidPacketInfo as u32,
        19
    );

    let header = include_str!("../wireguard_ffi.h");
    // `#define NAME 0x...u` or the enum's `NAME = n,`.
    let value_of = |name: &str| -> u32 {
        let line = header
            .lines()
            .map(str::trim)
            .find(|l| {
                l.strip_prefix("#define ")
                    .unwrap_or(l)
                    .split(|c: char| c.is_whitespace() || c == '=')
                    .next()
                    == Some(name)
            })
            .unwrap_or_else(|| panic!("{} is not in wireguard_ffi.h", name));
        let value = line
            .strip_prefix("#define ")
            .unwrap_or(line)
            .trim_start_matches(name)
            .trim_start_matches([' ', '='])
            .split(|c: char| c.is_whitespace() || c == ',' || c == 'u')
            .next()
            .unwrap();
        match value.strip_prefix("0x") {
            Some(hex) => u32::from_str_radix(hex, 16).unwrap(),
            None => value.parse().unwrap(),
        }
    };
    let defines: [(&str, u32); 30] = [
        ("WIREGUARD_PACKET_INFO_SIZE_V1", 48),
        ("WIREGUARD_PACKET_INFO_SIZE_MAX", 1024),
        ("WIREGUARD_PACKET_INFO_OUTPUT_START", 16),
        ("WIREGUARD_BURST_DUE_NONE", BURST_DUE_NONE),
        ("WIREGUARD_ERROR_INVALID_PACKET_INFO", 19),
        ("WIREGUARD_EV_INPUT_ACCEPTED", ev::INPUT_ACCEPTED),
        ("WIREGUARD_EV_PEER_AUTHENTICATED", ev::PEER_AUTHENTICATED),
        ("WIREGUARD_EV_SESSION_STORED", ev::SESSION_STORED),
        (
            "WIREGUARD_EV_CURRENT_SESSION_CHANGED",
            ev::CURRENT_SESSION_CHANGED,
        ),
        ("WIREGUARD_EV_INITIATION_PRODUCED", ev::INITIATION_PRODUCED),
        ("WIREGUARD_EV_QUEUE_ADMITTED", ev::QUEUE_ADMITTED),
        ("WIREGUARD_EV_HANDSHAKE_EXPIRED", ev::HANDSHAKE_EXPIRED),
        ("WIREGUARD_EV_SESSIONS_AGED_OUT", ev::SESSIONS_AGED_OUT),
        ("WIREGUARD_EV_BURST_PREPARED", ev::BURST_PREPARED),
        ("WIREGUARD_EV_TICK_DEMAND_REFUSED", ev::TICK_DEMAND_REFUSED),
        ("WIREGUARD_EV_QUEUE_HEAD_DROPPED", 0x0001_0000),
        ("WIREGUARD_EV_BURST_ITEM_SKIPPED", 0x0002_0000),
        ("WIREGUARD_ST_SESSION_CURRENT", st::SESSION_CURRENT),
        ("WIREGUARD_ST_INITIATION_PENDING", st::INITIATION_PENDING),
        ("WIREGUARD_ST_HANDSHAKE_EXPIRED", st::HANDSHAKE_EXPIRED),
        ("WIREGUARD_ST_QUEUE_NONEMPTY", st::QUEUE_NONEMPTY),
        ("WIREGUARD_ST_BURST_PENDING", st::BURST_PENDING),
        ("WIREGUARD_ST_COOKIE_HELD", st::COOKIE_HELD),
        ("WIREGUARD_PACKET_NONE", k(PacketKind::None)),
        (
            "WIREGUARD_PACKET_HANDSHAKE_INITIATION",
            k(PacketKind::HandshakeInitiation),
        ),
        (
            "WIREGUARD_PACKET_HANDSHAKE_RESPONSE",
            k(PacketKind::HandshakeResponse),
        ),
        ("WIREGUARD_PACKET_COOKIE_REPLY", k(PacketKind::CookieReply)),
        (
            "WIREGUARD_PACKET_TRANSPORT_DATA",
            k(PacketKind::TransportData),
        ),
        (
            "WIREGUARD_PACKET_TRANSPORT_KEEPALIVE",
            k(PacketKind::TransportKeepalive),
        ),
        ("WIREGUARD_PACKET_JUNK", k(PacketKind::Junk)),
    ];
    for (name, want) in defines {
        assert_eq!(value_of(name), want, "{} in wireguard_ffi.h", name);
    }
    assert_eq!(value_of("WIREGUARD_PACKET_IMITATION"), 7);
    // The kinds are the published numbers, not merely whatever Rust assigns.
    let kinds = [
        PacketKind::None,
        PacketKind::HandshakeInitiation,
        PacketKind::HandshakeResponse,
        PacketKind::CookieReply,
        PacketKind::TransportData,
        PacketKind::TransportKeepalive,
        PacketKind::Junk,
        PacketKind::Imitation,
    ];
    for (n, kind) in kinds.iter().copied().enumerate() {
        assert_eq!(k(kind), n as u32, "{:?}", kind);
    }
    for name in [
        "wireguard_read_ex(",
        "wireguard_write_ex(",
        "wireguard_tick_ex(",
        "wireguard_force_handshake_ex(",
    ] {
        assert!(header.contains(name), "{} is not declared", name);
    }
}

// ---------------------------------------------------------------------------
// Compatibility
// ---------------------------------------------------------------------------

/// The same script through the legacy symbols, `_ex(NULL)` and `_ex` with
/// metadata: every result is the same, for plain WireGuard and for an older
/// AmneziaWG profile (S1-S4, H1-H4, Jc). Sizes are compared wherever they are
/// deterministic; junk sizes are drawn, so where the metadata says JUNK only
/// the operation is compared. Metadata exists only when asked for, and the
/// three clients count the same operations.
#[test]
fn legacy_null_and_metadata_calls_behave_identically() {
    for profile in ["plain", "legacy-awg"] {
        let mut runs = Vec::new();
        for api in [Api::Legacy, Api::Null, Api::Info] {
            let (a, b) = (party(), party());
            let build = |me: &Party, peer: &Party, index| match profile {
                "plain" => plain(me, peer, index, 0),
                _ => legacy_awg(me, peer, index),
            };
            let client = build(&a, &b, 1);
            let server = build(&b, &a, 2);
            let steps = script(api, &client, &server);
            let seq = unsafe { (*client.0).lock().op_state_mut().op_seq() };
            runs.push((api, steps, seq));
        }
        let (_, info_steps, info_seq) = &runs[2];
        assert!(info_steps.iter().all(|(_, m)| m.is_some()));
        for (api, steps, seq) in &runs[..2] {
            assert_eq!(steps.len(), info_steps.len(), "{} {:?}", profile, api);
            assert_eq!(seq, info_seq, "{} {:?}: operations counted", profile, api);
            assert!(steps.iter().all(|(_, m)| m.is_none()));
            for (i, ((r, _), (ri, info))) in steps.iter().zip(info_steps).enumerate() {
                assert_eq!(r.op, ri.op, "{} {:?} step {}", profile, api, i);
                let junk = info.is_some_and(|m| m.output_kind == k(PacketKind::Junk));
                if !junk {
                    assert_eq!(r.size, ri.size, "{} {:?} step {}", profile, api, i);
                }
            }
        }
        if profile == "legacy-awg" {
            let kinds: Vec<u32> = info_steps[..4]
                .iter()
                .map(|(_, m)| m.unwrap().output_kind)
                .collect();
            assert_eq!(
                kinds,
                [
                    k(PacketKind::Junk),
                    k(PacketKind::Junk),
                    k(PacketKind::HandshakeInitiation),
                    k(PacketKind::None)
                ]
            );
        }
    }
}

/// The compatibility script. The client's results are returned; the server
/// only answers, and every payload must arrive intact.
fn script(api: Api, client: &Owned, server: &Owned) -> Vec<(Res, Option<wireguard_packet_info>)> {
    let (mut cb, mut sb) = (vec![0u8; 2048], vec![0u8; 2048]);
    let mut steps = Vec::new();
    let p1 = ipv4(1, 60);

    // Up to a two-item burst and the initiation; the rest is DONE.
    let mut last_out = None;
    for op in [Op::Write(&p1), Op::Tick, Op::Tick, Op::Tick] {
        let (r, m) = call(api, client, op, &mut cb);
        if r.op == WTN {
            last_out = Some(cb[..r.size].to_vec());
        }
        steps.push((r, m));
    }
    let init = last_out.expect("an initiation");
    let (r, _) = call(api, server, Op::Read(&init), &mut sb);
    assert_eq!(r.op, WTN, "{:?}", api);
    let resp = sb[..r.size].to_vec();

    let (r, m) = call(api, client, Op::Read(&resp), &mut cb);
    steps.push((r, m));
    let keepalive = cb[..r.size].to_vec();
    let (r, _) = call(api, server, Op::Read(&keepalive), &mut sb);
    assert_eq!(r.op, DONE, "{:?}", api);

    // A drain too small for the head, then the drain proper.
    steps.push(call(api, client, Op::Read(EMPTY), &mut cb[..40]));
    let (r, m) = call(api, client, Op::Read(EMPTY), &mut cb);
    steps.push((r, m));
    let data = cb[..r.size].to_vec();
    steps.push(call(api, client, Op::Read(EMPTY), &mut cb));
    let (r, _) = call(api, server, Op::Read(&data), &mut sb);
    assert_eq!(r.op, WTT4, "{:?}", api);
    assert_eq!(&sb[..r.size], &p1[..]);

    // A write too small for its frame is refused; the same write then goes.
    let p2 = ipv4(2, 60);
    steps.push(call(api, client, Op::Write(&p2), &mut cb[..60]));
    let (r, m) = call(api, client, Op::Write(&p2), &mut cb);
    steps.push((r, m));
    let data = cb[..r.size].to_vec();
    let (r, _) = call(api, server, Op::Read(&data), &mut sb);
    assert_eq!((r.op, tag_of(&sb[..r.size])), (WTT4, 2));

    // And the other way.
    let p3 = ipv4(3, 60);
    let (r, _) = call(api, server, Op::Write(&p3), &mut sb);
    let data = sb[..r.size].to_vec();
    let (r, m) = call(api, client, Op::Read(&data), &mut cb);
    assert_eq!(&cb[..r.size], &p3[..]);
    steps.push((r, m));
    steps
}

// ---------------------------------------------------------------------------
// Output kinds and the write/drain contract
// ---------------------------------------------------------------------------

/// Imitation plus Jc, paced, with no session. The write returns the first
/// imitation datagram and is admitted once; every later item comes from
/// ticks, in the order imitation..., junk x3, initiation, each reported as
/// what it is, with a due hint on every pacing DONE. A second write made while
/// the burst runs is admitted once. Neither write is repeated, yet after the
/// response both payloads drain exactly once, in order -- and a drain too
/// small for the head keeps it.
#[test]
fn imitation_and_jc_report_each_kind_in_order_and_drain_once() {
    let (a, b) = (party(), party());
    let client = awg(
        &a,
        &b,
        1,
        &wireguard_awg_params {
            junk_packet_count: 3,
            junk_packet_size_min: 40,
            junk_packet_size_max: 70,
            junk_packet_delay_ms: 5,
            imitation_protocol: AmneziaImitationProtocol::Stun as u32,
            ..params()
        },
    );
    let server = plain(&b, &a, 2, 0);
    let mut dst = vec![0u8; 2048];
    let (t1, t2) = (ipv4(0x1111, 48), ipv4(0x2222, 48));

    // The write: the burst prepared, its first imitation datagram returned and
    // the packet admitted -- all in this one call.
    let (r, i) = ex(&client, Op::Write(&t1), &mut dst);
    assert_eq!(r.op, WTN);
    assert_eq!(
        facts(&i),
        (
            k(PacketKind::None),
            k(PacketKind::Imitation),
            ev::BURST_PREPARED | ev::QUEUE_ADMITTED,
            st::QUEUE_NONEMPTY | st::BURST_PENDING
        )
    );
    assert_eq!(op_seq(&i), 1);
    let (imitation_left, jc_left) =
        unsafe { (*client.0).lock().pending_burst_shape() }.expect("a burst");
    assert_eq!(jc_left, 3);
    let imitations = imitation_left + 1;
    let mut kinds = vec![i.output_kind];
    let mut admitted = 1;
    let mut seq = op_seq(&i);
    let mut wrote_second = false;
    let mut init = None;

    for _ in 0..64 {
        // The second packet goes in after the first junk item, mid-burst.
        let op = if !wrote_second && kinds.len() == imitations + 1 {
            wrote_second = true;
            Op::Write(&t2)
        } else {
            Op::Tick
        };
        let (r, i) = ex(&client, op, &mut dst);
        seq += 1;
        assert_eq!(op_seq(&i), seq, "one sequence number per call");
        assert_eq!(i.input_kind, k(PacketKind::None));
        assert_eq!(i.events & ev::BURST_PREPARED, 0, "prepared once");
        if i.events & ev::QUEUE_ADMITTED != 0 {
            admitted += 1;
        }
        match r.op {
            DONE => {
                // A pacing wait: the burst is still owed, and the hint says when.
                assert_eq!(i.output_kind, k(PacketKind::None));
                assert_ne!(i.state & st::BURST_PENDING, 0);
                assert_ne!(i.burst_due_ms, BURST_DUE_NONE);
                #[cfg(feature = "mock-instant")]
                assert!(i.burst_due_ms > 0, "a frozen clock waits the full delay");
                advance(Duration::from_millis(u64::from(i.burst_due_ms.max(1))));
            }
            WTN if i.output_kind == k(PacketKind::HandshakeInitiation) => {
                kinds.push(i.output_kind);
                assert_eq!(i.events, ev::INITIATION_PRODUCED);
                assert_eq!(i.state, st::INITIATION_PENDING | st::QUEUE_NONEMPTY);
                assert_eq!(i.burst_due_ms, BURST_DUE_NONE);
                init = Some(dst[..r.size].to_vec());
                break;
            }
            WTN => {
                kinds.push(i.output_kind);
                assert_eq!(i.events & ev::INITIATION_PRODUCED, 0);
                assert_ne!(i.state & st::BURST_PENDING, 0);
            }
            other => panic!("unexpected op {} ({})", other, r.size),
        }
    }
    assert!(wrote_second);
    assert_eq!(admitted, 2, "each packet admitted exactly once");
    let mut want = vec![k(PacketKind::Imitation); imitations];
    want.extend([k(PacketKind::Junk); 3]);
    want.push(k(PacketKind::HandshakeInitiation));
    assert_eq!(kinds, want);

    // The response: authenticated, a session stored and selected, its
    // keepalive returned. The queue is untouched.
    let mut sb = vec![0u8; 2048];
    let (r, _) = call(
        Api::Legacy,
        &server,
        Op::Read(&init.expect("an initiation")),
        &mut sb,
    );
    assert_eq!(r.op, WTN);
    let resp = sb[..r.size].to_vec();
    let (r, i) = ex(&client, Op::Read(&resp), &mut dst);
    assert_eq!(r.op, WTN);
    assert_eq!(
        facts(&i),
        (
            k(PacketKind::HandshakeResponse),
            k(PacketKind::TransportKeepalive),
            ev::INPUT_ACCEPTED
                | ev::PEER_AUTHENTICATED
                | ev::SESSION_STORED
                | ev::CURRENT_SESSION_CHANGED,
            st::SESSION_CURRENT | st::QUEUE_NONEMPTY
        )
    );
    assert_eq!(i.burst_due_ms, BURST_DUE_NONE);

    // A drain too small for the head: refused, nothing consumed.
    let (r, i) = ex(&client, Op::Read(EMPTY), &mut dst[..40]);
    assert_eq!((r.op, r.size), (ERR, 0));
    assert_eq!(
        facts(&i),
        (0, 0, 0, st::SESSION_CURRENT | st::QUEUE_NONEMPTY)
    );

    // The drain: both packets, once each, in order; then DONE, nothing left.
    let mut delivered = Vec::new();
    loop {
        let (r, i) = ex(&client, Op::Read(EMPTY), &mut dst);
        if r.op == DONE {
            assert_eq!(facts(&i), (0, 0, 0, st::SESSION_CURRENT));
            break;
        }
        assert_eq!(r.op, WTN);
        assert_eq!(i.output_kind, k(PacketKind::TransportData));
        assert_eq!(i.events, 0, "a drain admits nothing");
        let data = dst[..r.size].to_vec();
        let (r, _) = call(Api::Legacy, &server, Op::Read(&data), &mut sb);
        assert_eq!(r.op, WTT4);
        delivered.push(tag_of(&sb[..r.size]));
    }
    assert_eq!(delivered, [0x1111, 0x2222]);
}

/// The due hint against the gate it describes, on a frozen clock: Jd after
/// each junk item, counting down as the clock moves, and the item going out
/// exactly when it reaches 0.
#[cfg(feature = "mock-instant")]
#[test]
fn the_due_hint_matches_the_pacing_gate() {
    let (a, b) = (party(), party());
    let t = awg(
        &a,
        &b,
        1,
        &wireguard_awg_params {
            junk_packet_count: 2,
            junk_packet_size_min: 40,
            junk_packet_size_max: 70,
            junk_packet_delay_ms: 5,
            ..params()
        },
    );
    let mut dst = vec![0u8; 2048];
    let (r, i) = ex(&t, Op::Force, &mut dst);
    assert_eq!((r.op, i.output_kind), (WTN, k(PacketKind::Junk)));
    assert_eq!(i.burst_due_ms, 5);
    let (r, i) = ex(&t, Op::Tick, &mut dst);
    assert_eq!((r.op, i.events, i.burst_due_ms), (DONE, 0, 5));
    advance(Duration::from_millis(4));
    let (r, i) = ex(&t, Op::Tick, &mut dst);
    assert_eq!((r.op, i.burst_due_ms), (DONE, 1));
    advance(Duration::from_millis(1));
    let (r, i) = ex(&t, Op::Tick, &mut dst);
    assert_eq!(
        (r.op, i.output_kind, i.burst_due_ms),
        (WTN, k(PacketKind::Junk), 5)
    );
    advance(Duration::from_millis(5));
    let (r, i) = ex(&t, Op::Tick, &mut dst);
    assert_eq!(
        (r.op, i.output_kind, i.burst_due_ms),
        (WTN, k(PacketKind::HandshakeInitiation), BURST_DUE_NONE)
    );
}

/// A Jc write whose `dst` cannot hold the largest junk item is refused before
/// any draw: the burst is prepared and stays owed, but the packet is NOT
/// admitted -- the caller still owns it -- and repeating the call cannot
/// progress (due 0 with an error). With room, the same packet is admitted
/// once, with the first junk item. A plain WireGuard write without a session
/// is admitted with the initiation, then with DONE while the handshake is in
/// flight, and refused with 17 once the queue is full. With a session, a
/// write is encrypted on the spot -- accepted, not queued.
#[test]
fn write_admission_is_reported_and_refusals_admit_nothing() {
    let (a, b) = (party(), party());
    let client = awg(
        &a,
        &b,
        1,
        &wireguard_awg_params {
            junk_packet_count: 3,
            junk_packet_size_min: 40,
            junk_packet_size_max: 70,
            ..params()
        },
    );
    let mut dst = vec![0u8; 2048];
    let p = ipv4(7, 40);

    let (r, i) = ex(&client, Op::Write(&p), &mut dst[..60]);
    assert_eq!((r.op, r.size), (ERR, 0));
    assert_eq!(facts(&i), (0, 0, ev::BURST_PREPARED, st::BURST_PENDING));
    assert_eq!(i.burst_due_ms, 0, "due but blocked");
    let (r, i) = ex(&client, Op::Write(&p), &mut dst[..60]);
    assert_eq!((r.op, r.size), (ERR, 0));
    assert_eq!(facts(&i), (0, 0, 0, st::BURST_PENDING));
    assert_eq!(i.burst_due_ms, 0);

    let (r, i) = ex(&client, Op::Write(&p), &mut dst);
    assert_eq!(r.op, WTN);
    assert!((40..=70).contains(&r.size));
    assert_eq!(
        facts(&i),
        (
            0,
            k(PacketKind::Junk),
            ev::QUEUE_ADMITTED,
            st::BURST_PENDING | st::QUEUE_NONEMPTY
        )
    );

    // Plain WireGuard: the initiation and an admission, then DONE and an
    // admission, until the queue is full.
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let (r, i) = ex(&client, Op::Write(&ipv4(0, 40)), &mut dst);
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
    for n in 1..256 {
        let (r, i) = ex(&client, Op::Write(&ipv4(n, 40)), &mut dst);
        assert_eq!(r.op, DONE, "packet {}", n);
        assert_eq!(i.events, ev::QUEUE_ADMITTED);
    }
    let (r, i) = ex(&client, Op::Write(&ipv4(256, 40)), &mut dst);
    assert_eq!((r.op, r.size), (ERR, 17));
    assert_eq!(
        facts(&i),
        (0, 0, 0, st::INITIATION_PENDING | st::QUEUE_NONEMPTY)
    );

    let server = plain(&b, &a, 2, 0);
    let client = plain(&a, &b, 3, 0);
    establish(&client, &server);
    let (r, i) = ex(&client, Op::Write(&ipv4(1, 40)), &mut dst[..71]);
    assert_eq!((r.op, r.size), (ERR, 0));
    assert_eq!(facts(&i), (0, 0, 0, st::SESSION_CURRENT));
    let (r, i) = ex(&client, Op::Write(&ipv4(1, 40)), &mut dst);
    assert_eq!(r.op, WTN);
    assert_eq!(
        facts(&i),
        (0, k(PacketKind::TransportData), 0, st::SESSION_CURRENT)
    );
}

// ---------------------------------------------------------------------------
// Input roles
// ---------------------------------------------------------------------------

/// What a received datagram was accepted as, and what that did -- and that
/// nothing which is not ours is reported as anything: a forged initiation
/// with a valid mac1, a replayed initiation or response, a tampered or
/// replayed transport packet, garbage.
#[test]
fn input_roles_are_authenticated_facts() {
    let (a, b, mallory) = (party(), party(), party());
    let client = plain(&a, &b, 1, 0);
    let server = plain(&b, &a, 2, 0);
    let forger = plain(&mallory, &b, 3, 0);
    let (mut cb, mut sb) = (vec![0u8; 2048], vec![0u8; 2048]);

    // A forged initiation: the right shape and a valid mac1 (keyed on the
    // server's public key, which the forger has), the wrong static key.
    let (r, _) = call(Api::Legacy, &forger, Op::Force, &mut cb);
    let forged = cb[..r.size].to_vec();
    let (r, i) = ex(&server, Op::Read(&forged), &mut sb);
    assert_eq!((r.op, r.size), (ERR, 5));
    assert_eq!(facts(&i), (0, 0, 0, 0));

    // The initiation: authenticated, a responder session stored -- not
    // selected for sending until transport arrives on it.
    let (r, i) = ex(&client, Op::Force, &mut cb);
    assert_eq!(
        (r.op, i.output_kind, i.events),
        (
            WTN,
            k(PacketKind::HandshakeInitiation),
            ev::INITIATION_PRODUCED
        )
    );
    let init = cb[..r.size].to_vec();
    let (r, i) = ex(&server, Op::Read(&init), &mut sb);
    assert_eq!(r.op, WTN);
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
    let (r, i) = ex(&server, Op::Read(&init), &mut sb);
    assert_eq!((r.op, r.size), (ERR, 7), "a replayed initiation");
    assert_eq!(facts(&i), (0, 0, 0, 0));

    // The response, distinguished from the initiation it answers.
    let (r, i) = ex(&client, Op::Read(&resp), &mut cb);
    assert_eq!(r.op, WTN);
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
    let keepalive = cb[..r.size].to_vec();
    let (r, i) = ex(&client, Op::Read(&resp), &mut cb);
    assert_eq!((r.op, r.size), (ERR, 2), "a replayed response");
    assert_eq!(facts(&i), (0, 0, 0, st::SESSION_CURRENT));

    // The keepalive: authenticated transport, the responder's first, which
    // selects its session.
    let (r, i) = ex(&server, Op::Read(&keepalive), &mut sb);
    assert_eq!(r.op, DONE);
    assert_eq!(
        facts(&i),
        (
            k(PacketKind::TransportKeepalive),
            0,
            ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED | ev::CURRENT_SESSION_CHANGED,
            st::SESSION_CURRENT
        )
    );

    // Data; the same data tampered, then replayed.
    let (r, _) = call(Api::Legacy, &client, Op::Write(&ipv4(9, 40)), &mut cb);
    let data = cb[..r.size].to_vec();
    let mut tampered = data.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let (r, i) = ex(&server, Op::Read(&tampered), &mut sb);
    assert_eq!((r.op, r.size), (ERR, 9));
    assert_eq!(facts(&i), (0, 0, 0, st::SESSION_CURRENT));
    let (r, i) = ex(&server, Op::Read(&data), &mut sb);
    assert_eq!(r.op, WTT4);
    assert_eq!(
        facts(&i),
        (
            k(PacketKind::TransportData),
            0,
            ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED,
            st::SESSION_CURRENT
        )
    );
    let (r, i) = ex(&server, Op::Read(&data), &mut sb);
    assert_eq!((r.op, r.size), (ERR, 11), "a replayed transport packet");
    assert_eq!(facts(&i), (0, 0, 0, st::SESSION_CURRENT));

    let garbage = [0xffu8; 100];
    let (r, i) = ex(&server, Op::Read(&garbage), &mut sb);
    assert_eq!((r.op, r.size), (ERR, 12));
    assert_eq!(facts(&i), (0, 0, 0, st::SESSION_CURRENT));
}

/// A cookie reply is accepted -- and held -- but it authenticates no peer.
/// The FFI cannot provoke one (it passes no source address), so the peer
/// here is a Rust tunnel whose limiter is permanently under load.
#[test]
fn a_cookie_reply_is_accepted_but_not_peer_authentication() {
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let mut server = Tunn::new_with_obfuscation(
        b.secret.clone(),
        a.public,
        None,
        None,
        2,
        Some(Arc::new(RateLimiter::new(&b.public, 0))),
        Default::default(),
        AmneziaConfig::default(),
    )
    .unwrap();
    let (mut cb, mut sb) = (vec![0u8; 2048], vec![0u8; 2048]);
    let (r, _) = ex(&client, Op::Force, &mut cb);
    let init = cb[..r.size].to_vec();
    let cookie = match server.decapsulate(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), &init, &mut sb) {
        TunnResult::WriteToNetwork(c) => c.to_vec(),
        other => panic!("no cookie reply: {:?}", other),
    };
    let (r, i) = ex(&client, Op::Read(&cookie), &mut cb);
    assert_eq!(r.op, DONE);
    assert_eq!(
        facts(&i),
        (
            k(PacketKind::CookieReply),
            0,
            ev::INPUT_ACCEPTED,
            st::INITIATION_PENDING | st::COOKIE_HELD
        )
    );
}

/// An input accepted and committed, then an error: the error is reported, and
/// so is exactly what happened before it -- never more, never less.
///
/// * An initiation into a `dst` below the 92-byte response: the timestamp is
///   committed (re-offering it is a replay), but no session was stored.
/// * An initiation into a `dst` that fits the response but not its S2
///   prefix: the session WAS stored before framing failed.
/// * An authenticated transport packet whose plaintext is not IP.
#[test]
fn an_error_after_acceptance_keeps_what_really_happened() {
    let (a, b) = (party(), party());
    let s2 = wireguard_awg_params {
        s2_response_junk: 28,
        ..params()
    };
    let client = awg(&a, &b, 1, &s2);
    let server = awg(&b, &a, 2, &s2);
    let (mut cb, mut sb) = (vec![0u8; 2048], vec![0u8; 2048]);

    let (r, _) = ex(&client, Op::Force, &mut cb);
    let init = cb[..r.size].to_vec();
    let (r, i) = ex(&server, Op::Read(&init), &mut sb[..91]);
    assert_eq!((r.op, r.size), (ERR, 0));
    assert_eq!(
        facts(&i),
        (
            k(PacketKind::HandshakeInitiation),
            0,
            ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED,
            0
        )
    );
    let (r, i) = ex(&server, Op::Read(&init), &mut sb);
    assert_eq!((r.op, r.size), (ERR, 7), "it was accepted: now a replay");
    assert_eq!(facts(&i), (0, 0, 0, 0));

    advance(Duration::from_millis(2));
    let (r, _) = ex(&client, Op::Force, &mut cb);
    let init = cb[..r.size].to_vec();
    let (r, i) = ex(&server, Op::Read(&init), &mut sb[..100]);
    assert_eq!((r.op, r.size), (ERR, 0));
    assert_eq!(
        facts(&i),
        (
            k(PacketKind::HandshakeInitiation),
            0,
            ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED | ev::SESSION_STORED,
            0
        )
    );

    // Malformed inner packets on an established pair.
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let server = plain(&b, &a, 2, 0);
    establish(&client, &server);
    let mut short_ip = ipv4(5, 40);
    short_ip[2..4].copy_from_slice(&10u16.to_be_bytes());
    for plaintext in [vec![0x99u8; 40], short_ip] {
        let (r, i) = ex(&client, Op::Write(&plaintext), &mut cb);
        assert_eq!((r.op, i.output_kind), (WTN, k(PacketKind::TransportData)));
        let data = cb[..r.size].to_vec();
        let (r, i) = ex(&server, Op::Read(&data), &mut sb);
        assert_eq!((r.op, r.size), (ERR, 12));
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
}

/// A tick's keepalive demand whose producer is refused for capacity reports
/// the refusal along with the error. Needs a second of tunnel time.
#[cfg(feature = "mock-instant")]
#[test]
fn a_refused_tick_demand_is_reported() {
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 1);
    let server = plain(&b, &a, 2, 0);
    establish(&client, &server);
    advance(Duration::from_millis(1100));
    let mut dst = vec![0u8; 2048];
    let (r, i) = ex(&client, Op::Tick, &mut dst[..16]);
    assert_eq!((r.op, r.size), (ERR, 0));
    assert_eq!(
        facts(&i),
        (0, 0, ev::TICK_DEMAND_REFUSED, st::SESSION_CURRENT)
    );
    let (r, i) = ex(&client, Op::Tick, &mut dst);
    assert_eq!((r.op, i.events), (DONE, 0));
}

/// The tick that ends a handshake cycle -- here the untuned 90-second bound,
/// with a packet queued behind the initiation -- reports the expiry, and the
/// queue it cleared. The next tick finds it already expired: the same error,
/// no event.
#[cfg(feature = "mock-instant")]
#[test]
fn an_expiry_is_reported_by_the_tick_that_expires() {
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let mut dst = vec![0u8; 2048];
    let (r, i) = ex(&client, Op::Write(&ipv4(1, 40)), &mut dst);
    assert_eq!(r.op, WTN);
    assert_eq!(i.state, st::INITIATION_PENDING | st::QUEUE_NONEMPTY);
    advance(Duration::from_secs(91));
    let (r, i) = ex(&client, Op::Tick, &mut dst);
    assert_eq!((r.op, r.size), (ERR, 15));
    assert_eq!(
        facts(&i),
        (0, 0, ev::HANDSHAKE_EXPIRED, st::HANDSHAKE_EXPIRED)
    );
    let (r, i) = ex(&client, Op::Tick, &mut dst);
    assert_eq!((r.op, r.size), (ERR, 15));
    assert_eq!(facts(&i), (0, 0, 0, st::HANDSHAKE_EXPIRED));
}

/// A session older than reject-after-time is dropped by the tick that ages
/// it, and that tick reports both the ageing and that the selected session is
/// gone.
#[cfg(feature = "mock-instant")]
#[test]
fn ageing_out_the_current_session_is_reported() {
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let server = plain(&b, &a, 2, 0);
    establish(&client, &server);
    advance(Duration::from_secs(181));
    let mut dst = vec![0u8; 2048];
    let (r, i) = ex(&client, Op::Tick, &mut dst);
    assert_eq!(r.op, DONE);
    assert_eq!(
        facts(&i),
        (0, 0, ev::SESSIONS_AGED_OUT | ev::CURRENT_SESSION_CHANGED, 0)
    );
}

// ---------------------------------------------------------------------------
// Memory protocol
// ---------------------------------------------------------------------------

const CANARY: u8 = 0xA5;

fn put(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_ne_bytes());
}

fn get(buf: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap())
}

fn tick_raw(t: &Owned, info: *mut u8) -> Res {
    let mut dst = [0u8; 256];
    res(unsafe {
        wireguard_tick_ex(
            t.0,
            dst.as_mut_ptr(),
            256,
            info as *mut wireguard_packet_info,
        )
    })
}

fn valid_seq(t: &Owned) -> u64 {
    let mut dst = [0u8; 256];
    op_seq(&ex(t, Op::Tick, &mut dst).1)
}

/// Input head: size, in_flags, the two budgets.
fn head(m: &mut [u8], size: u32, in_flags: u32, transport: u32, control: u32) {
    put(m, 0, size);
    put(m, 4, in_flags);
    put(m, 8, transport);
    put(m, 12, control);
}

/// Every refused shape returns 19 before anything runs: no byte of the
/// caller's memory changes and no sequence number is taken. Accepted shapes
/// write exactly `[16, 48)`, at any alignment, and leave `[0, 16)`, the
/// declared tail and everything past it alone. A refusal on storage that
/// holds a previous success leaves that success's values in place.
#[test]
fn invalid_packet_info_is_refused_before_anything_runs() {
    let (a, b) = (party(), party());
    let t = plain(&a, &b, 1, 0);
    type Shape = fn(&mut [u8]);
    let refused: [(&str, Shape); 17] = [
        ("size 0", |m| put(m, 0, 0)),
        ("size 3", |m| put(m, 0, 3)),
        ("size 4", |m| put(m, 0, 4)),
        ("size 7", |m| put(m, 0, 7)),
        ("size 8", |m| put(m, 0, 8)),
        ("size 16", |m| put(m, 0, 16)),
        ("size 43", |m| put(m, 0, 43)),
        ("size 44", |m| put(m, 0, 44)),
        ("size 47", |m| put(m, 0, 47)),
        ("size 1025", |m| put(m, 0, 1025)),
        ("size max", |m| put(m, 0, u32::MAX)),
        ("in_flags 1", |m| head(m, 48, 1, 0, 0)),
        ("in_flags top", |m| head(m, 48, 0x8000_0000, 0, 0)),
        ("transport budget", |m| head(m, 48, 0, 1400, 0)),
        ("control budget", |m| head(m, 48, 0, 0, 200)),
        ("first tail byte", |m| {
            head(m, 64, 0, 0, 0);
            m[48..64].fill(0);
            m[48] = 1;
        }),
        ("last tail byte", |m| {
            head(m, 64, 0, 0, 0);
            m[48..64].fill(0);
            m[63] = 0x80;
        }),
    ];

    for at in 0..4 {
        let mut buf = vec![CANARY; 1024 + 64];
        for (name, shape) in refused {
            buf.fill(CANARY);
            shape(&mut buf[at..]);
            let before = buf.clone();
            let seq = valid_seq(&t);
            let r = tick_raw(&t, buf[at..].as_mut_ptr());
            assert_eq!((r.op, r.size), (ERR, 19), "offset {} {}", at, name);
            assert_eq!(buf, before, "offset {} {}: nothing written", at, name);
            assert_eq!(
                valid_seq(&t),
                seq + 1,
                "offset {} {}: no sequence",
                at,
                name
            );
        }

        for size in [48u32, 49, 52, 64, 1024] {
            buf.fill(CANARY);
            head(&mut buf[at..], size, 0, 0, 0);
            buf[at + 48..at + size as usize].fill(0);
            let before = buf.clone();
            let seq = valid_seq(&t);
            let r = tick_raw(&t, buf[at..].as_mut_ptr());
            assert_eq!((r.op, r.size), (DONE, 0), "offset {} size {}", at, size);
            assert_eq!(&buf[..at + 16], &before[..at + 16], "prefix untouched");
            assert_eq!(&buf[at + 48..], &before[at + 48..], "tail untouched");
            let m = &buf[at..];
            assert_eq!(get(m, 16), 48, "written_size");
            assert_eq!(get(m, 20), 0, "input_kind");
            assert_eq!(get(m, 24), 0, "output_kind");
            assert_eq!(get(m, 28), 0, "events");
            assert_eq!(get(m, 32), 0, "state");
            assert_eq!(
                (u64::from(get(m, 40)) << 32) | u64::from(get(m, 36)),
                seq + 1
            );
            assert_eq!(get(m, 44), BURST_DUE_NONE);

            let written = buf.clone();
            put(&mut buf[at..], 4, 1);
            let r = tick_raw(&t, buf[at..].as_mut_ptr());
            assert_eq!((r.op, r.size), (ERR, 19));
            assert_eq!(&buf[at + 16..at + 48], &written[at + 16..at + 48]);
        }
    }
}

/// Error 19 is a no-op on the tunnel too: a write refused for its metadata is
/// not admitted, so the queue holds exactly what the legacy write before it
/// put there.
#[test]
fn a_refused_write_admits_nothing() {
    let (a, b) = (party(), party());
    let client = plain(&a, &b, 1, 0);
    let server = plain(&b, &a, 2, 0);
    let (mut cb, mut sb) = (vec![0u8; 2048], vec![0u8; 2048]);
    let (r, _) = call(Api::Legacy, &client, Op::Write(&ipv4(1, 40)), &mut cb);
    assert_eq!(r.op, WTN);
    let init = cb[..r.size].to_vec();

    let mut bad = new_info();
    bad.size = 44;
    let p = ipv4(2, 40);
    let r = res(unsafe {
        wireguard_write_ex(
            client.0,
            p.as_ptr(),
            p.len() as u32,
            cb.as_mut_ptr(),
            cb.len() as u32,
            &mut bad,
        )
    });
    assert_eq!((r.op, r.size), (ERR, 19));

    let (r, _) = call(Api::Legacy, &server, Op::Read(&init), &mut sb);
    let resp = sb[..r.size].to_vec();
    let (r, _) = call(Api::Legacy, &client, Op::Read(&resp), &mut cb);
    assert_eq!(r.op, WTN);
    let mut tags = Vec::new();
    loop {
        let (r, _) = call(Api::Legacy, &client, Op::Read(EMPTY), &mut cb);
        if r.op == DONE {
            break;
        }
        let data = cb[..r.size].to_vec();
        let (r, _) = call(Api::Legacy, &server, Op::Read(&data), &mut sb);
        tags.push(tag_of(&sb[..r.size]));
    }
    assert_eq!(tags, [1]);
}

/// A no-access page right after `info`: a refused size reads only its 4
/// bytes, and an accepted 48-byte struct is read and written up to its last
/// byte and not one past it, aligned or not.
#[test]
fn only_the_declared_extent_is_touched() {
    let (a, b) = (party(), party());
    let t = plain(&a, &b, 1, 0);
    let g = guard::Guarded::new();
    unsafe {
        for size in [0u32, 4, 47, 1025, u32::MAX] {
            let info = g.end().sub(4);
            ptr::write_unaligned(info as *mut u32, size);
            let r = tick_raw(&t, info);
            assert_eq!((r.op, r.size), (ERR, 19), "size {}", size);
            assert_eq!(ptr::read_unaligned(info as *const u32), size);
        }
        for extra in [0, 1] {
            let info = g.end().sub(48 + extra);
            ptr::write_bytes(info, 0, 48 + extra);
            ptr::write_unaligned(info as *mut u32, 48);
            let r = tick_raw(&t, info);
            assert_eq!((r.op, r.size), (DONE, 0));
            assert_eq!(ptr::read_unaligned(info.add(16) as *const u32), 48);
            assert_eq!(
                ptr::read_unaligned(info.add(44) as *const u32),
                BURST_DUE_NONE
            );
        }
    }
}

#[cfg(windows)]
mod guard {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualAlloc(addr: *mut c_void, size: usize, ty: u32, protect: u32) -> *mut c_void;
        fn VirtualProtect(addr: *mut c_void, size: usize, protect: u32, old: *mut u32) -> i32;
        fn VirtualFree(addr: *mut c_void, size: usize, ty: u32) -> i32;
    }
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE: usize = 4096;

    /// A read/write page followed by a no-access page.
    pub(super) struct Guarded(*mut u8);

    impl Guarded {
        pub(super) fn new() -> Self {
            unsafe {
                let base = VirtualAlloc(
                    std::ptr::null_mut(),
                    2 * PAGE,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                ) as *mut u8;
                assert!(!base.is_null());
                let mut old = 0;
                let guard = base.add(PAGE) as *mut c_void;
                assert_ne!(VirtualProtect(guard, PAGE, PAGE_NOACCESS, &mut old), 0);
                Guarded(base)
            }
        }

        /// The first byte of the no-access page.
        pub(super) fn end(&self) -> *mut u8 {
            unsafe { self.0.add(PAGE) }
        }
    }

    impl Drop for Guarded {
        fn drop(&mut self) {
            unsafe { VirtualFree(self.0 as *mut c_void, 0, MEM_RELEASE) };
        }
    }
}

#[cfg(unix)]
mod guard {
    /// A read/write page followed by a no-access page.
    pub(super) struct Guarded(*mut u8, usize);

    impl Guarded {
        pub(super) fn new() -> Self {
            unsafe {
                let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
                let base = libc::mmap(
                    std::ptr::null_mut(),
                    2 * page,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                );
                assert_ne!(base, libc::MAP_FAILED);
                let base = base as *mut u8;
                assert_eq!(
                    libc::mprotect(base.add(page) as *mut libc::c_void, page, libc::PROT_NONE),
                    0
                );
                Guarded(base, page)
            }
        }

        /// The first byte of the no-access page.
        pub(super) fn end(&self) -> *mut u8 {
            unsafe { self.0.add(self.1) }
        }
    }

    impl Drop for Guarded {
        fn drop(&mut self) {
            unsafe { libc::munmap(self.0 as *mut libc::c_void, 2 * self.1) };
        }
    }
}

// ---------------------------------------------------------------------------
// Sequence
// ---------------------------------------------------------------------------

/// One sequence number per participating call, legacy or `_ex`, starting at 1
/// per tunnel object; `wireguard_stats` and the MTU setter take none. The low
/// word carries into the high word.
#[test]
fn the_sequence_counts_every_operation_and_carries() {
    let (a, b) = (party(), party());
    let t = plain(&a, &b, 1, 0);
    let other = plain(&a, &b, 2, 0);
    let mut dst = vec![0u8; 2048];
    assert_eq!(op_seq(&ex(&t, Op::Tick, &mut dst).1), 1);
    call(Api::Legacy, &t, Op::Tick, &mut dst);
    call(Api::Legacy, &t, Op::Force, &mut dst);
    call(Api::Null, &t, Op::Read(EMPTY), &mut dst);
    call(Api::Legacy, &t, Op::Write(&ipv4(1, 40)), &mut dst);
    unsafe {
        wireguard_stats(t.0);
        assert!(wireguard_set_content_padding_mtu(t.0, 1420));
    }
    assert_eq!(op_seq(&ex(&t, Op::Tick, &mut dst).1), 6);
    assert_eq!(op_seq(&ex(&other, Op::Tick, &mut dst).1), 1);

    unsafe { (*t.0).lock().op_state_mut().set_op_seq(0xFFFF_FFFE) };
    let (_, i) = ex(&t, Op::Tick, &mut dst);
    assert_eq!((i.op_seq_hi, i.op_seq_lo), (0, 0xFFFF_FFFF));
    let (_, i) = ex(&t, Op::Tick, &mut dst);
    assert_eq!((i.op_seq_hi, i.op_seq_lo), (1, 0));
    assert_eq!(op_seq(&i), 1 << 32);
}
