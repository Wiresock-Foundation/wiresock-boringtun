//! The write-ownership contract of [`Tunn::encapsulate`] and the owned drain.
//!
//! A refused write (`Err`) never accepts `src`; `WriteToNetwork` / `Done`
//! accept it exactly once; a full queue refuses before any protocol work; a
//! drain never re-admits an owned packet and restores a head that does not fit.
//! Every assertion carries a stable `[R3:<test>:<invariant>]` tag, first in its
//! panic message, so a failure names the invariant it broke.

use super::amnezia::{AmneziaConfig, AmneziaImitationProtocol};
use super::timers::TimerName;
use super::*;
use rand_core::{OsRng, RngCore};
#[cfg(feature = "mock-instant")]
use std::convert::TryInto;
use std::time::Duration;

fn pair(client: AmneziaConfig, server: AmneziaConfig) -> (Tunn, Tunn) {
    let c_sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let c_pk = x25519_dalek::PublicKey::from(&c_sk);
    let s_sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let s_pk = x25519_dalek::PublicKey::from(&s_sk);
    let mk = |sk, pk, cfg| {
        Tunn::new_with_amnezia(
            sk,
            pk,
            None,
            None,
            OsRng.next_u32() >> 8,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            cfg,
        )
        .unwrap()
    };
    (mk(c_sk, s_pk, client), mk(s_sk, c_pk, server))
}

fn plain() -> AmneziaConfig {
    AmneziaConfig::new(0, 0, 0, 0)
}

fn ipv4(seq: u8) -> Vec<u8> {
    let header = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 3], 64)
        .udp(4000 + seq as u16, 53);
    let payload = [seq; 40];
    let mut p = Vec::new();
    header.write(&mut p, &payload).unwrap();
    p
}

fn net(r: TunnResult<'_>) -> Vec<u8> {
    match r {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!(
            "[R3:C-NET:EXPECTED-WRITETONETWORK-GOT] expected WriteToNetwork, got {:?}",
            other
        ),
    }
}

/// `net` with the caller's assertion tag, for checks whose point IS that this
/// output is sent: the panic names the invariant, not the helper. Its callers
/// here are the mock-clock tests.
#[cfg(feature = "mock-instant")]
fn sent(r: TunnResult<'_>, tag: &str) -> Vec<u8> {
    match r {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("{} expected WriteToNetwork, got {:?}", tag, other),
    }
}

fn is_dbts(r: &TunnResult<'_>) -> bool {
    matches!(
        r,
        TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
    )
}

fn queue(t: &Tunn) -> Vec<Vec<u8>> {
    t.packet_queue.iter().cloned().collect()
}

/// Complete the handshake from `first` (the client's initiation, possibly
/// after burst datagrams the server ignores), then drain the client queue into
/// the server. Returns every plaintext the server delivered.
fn complete_and_drain(c: &mut Tunn, s: &mut Tunn, mut first: Vec<u8>) -> Vec<Vec<u8>> {
    let mut big = vec![0u8; 65535];
    let mut sbuf = vec![0u8; 65535];
    let mut delivered = Vec::new();
    for _ in 0..300 {
        match s.decapsulate(None, &first, &mut sbuf) {
            TunnResult::WriteToNetwork(resp) => {
                let resp = resp.to_vec();
                let ka = net(c.decapsulate(None, &resp, &mut big));
                let _ = s.decapsulate(None, &ka, &mut sbuf);
                loop {
                    match c.decapsulate(None, &[], &mut big) {
                        TunnResult::WriteToNetwork(p) => {
                            let p = p.to_vec();
                            if let TunnResult::WriteToTunnelV4(pl, _) =
                                s.decapsulate(None, &p, &mut sbuf)
                            {
                                delivered.push(pl.to_vec());
                            }
                        }
                        TunnResult::Done => return delivered,
                        other => panic!("[R3:C-COMPLETE-AND-DRAIN:DRAIN] drain: {:?}", other),
                    }
                }
            }
            _ => {
                // A burst datagram the server refuses: fetch the next output.
                #[cfg(feature = "mock-instant")]
                mock_instant::thread_local::MockClock::advance(Duration::from_millis(250));
                #[cfg(not(feature = "mock-instant"))]
                std::thread::sleep(Duration::from_millis(1));
                loop {
                    match c.update_timers(&mut big) {
                        TunnResult::WriteToNetwork(p) => {
                            first = p.to_vec();
                            break;
                        }
                        TunnResult::Done => {
                            #[cfg(feature = "mock-instant")]
                            mock_instant::thread_local::MockClock::advance(Duration::from_millis(
                                250,
                            ));
                            #[cfg(not(feature = "mock-instant"))]
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        other => panic!("[R3:C-COMPLETE-AND-DRAIN:TIMERS] timers: {:?}", other),
                    }
                }
            }
        }
    }
    panic!("[R3:C-COMPLETE-AND-DRAIN:HANDSHAKE-DID-NOT-COMPLETE] handshake did not complete")
}

/// Everything a refusal must leave alone (the clock excepted): queue order and
/// content, handshake state, the cycle's timers, attempts, the handshake latch,
/// the pending burst (with its owed reset), the session and the RNG position.
#[derive(Debug, PartialEq, Clone)]
struct Snap {
    queue: Vec<Vec<u8>>,
    expired: bool,
    in_progress: bool,
    /// `Debug` form: the default build's `Instant` has no `PartialEq`.
    sent_at: Option<String>,
    established: Duration,
    started: Duration,
    last_sent: Duration,
    attempts: u32,
    want_handshake: bool,
    pending: Option<(usize, u16, Option<String>, bool)>,
    has_session: bool,
    rng: u128,
}

fn snap(t: &Tunn) -> Snap {
    Snap {
        queue: queue(t),
        expired: t.handshake.is_expired(),
        in_progress: t.handshake.is_in_progress(),
        sent_at: t.handshake.timer().map(|i| format!("{:?}", i)),
        established: t.timers[TimerName::TimeSessionEstablished],
        started: t.timers[TimerName::TimeLastHandshakeStarted],
        last_sent: t.timers[TimerName::TimeLastPacketSent],
        attempts: t.timers.handshake_attempts,
        want_handshake: t.timers.want_handshake,
        pending: t.pending_amnezia_junk.as_ref().map(|p| {
            (
                p.imitation_datagrams.len(),
                p.remaining,
                p.last_packet_at.map(|i| format!("{:?}", i)),
                p.reset_expired_timers,
            )
        }),
        has_session: t.has_current_session(),
        rng: t.handshake.rng.get_word_pos(),
    }
}

fn copies(d: &[Vec<u8>], p: &[u8]) -> usize {
    d.iter().filter(|x| x.as_slice() == p).count()
}

// T1
#[test]
fn a_no_session_write_into_a_short_dst_is_not_accepted_and_its_retry_delivers_once() {
    let (mut c, mut s) = pair(plain(), plain());
    let p = ipv4(1);
    let before = snap(&c);
    let mut tmp = [0u8; HANDSHAKE_INIT_SZ - 1];
    let r = c.encapsulate(&p, &mut tmp);
    assert!(is_dbts(&r), "[R3:T1:IS-DBTS]");
    assert_eq!(
        snap(&c),
        before,
        "[R3:T1:A-REFUSAL-CHANGES-NOTHING] a refusal changes nothing"
    );
    assert!(queue(&c).is_empty(), "[R3:T1:QUEUE-IS-EMPTY]");
    let init = net(c.encapsulate(&p, &mut [0u8; 2048]));
    assert_eq!(
        init.len(),
        HANDSHAKE_INIT_SZ,
        "[R3:T1:INIT-LEN-HANDSHAKE-INIT-SZ]"
    );
    assert_eq!(queue(&c), vec![p.clone()], "[R3:T1:QUEUE]");
    let d = complete_and_drain(&mut c, &mut s, init);
    assert_eq!(copies(&d, &p), 1, "[R3:T1:COPIES]");
}

// T2
#[test]
fn an_s1_framed_initiation_that_does_not_fit_consumes_no_handshake_state() {
    let cfg = AmneziaConfig::new(64, 0, 0, 0);
    let (mut c, mut s) = pair(cfg.clone(), cfg);
    let p = ipv4(2);
    let rng_before = c.handshake.rng.get_word_pos();
    let started = c.timers[TimerName::TimeLastHandshakeStarted];
    let sent = c.timers[TimerName::TimeLastPacketSent];
    let mut tmp = [0u8; HANDSHAKE_INIT_SZ + 63];
    let r = c.encapsulate(&p, &mut tmp);
    assert!(is_dbts(&r), "[R3:T2:IS-DBTS]");
    assert!(queue(&c).is_empty(), "[R3:T2:QUEUE-IS-EMPTY]");
    assert!(
        !c.handshake.is_in_progress(),
        "[R3:T2:HANDSHAKE-IS-IN-PROGRESS]"
    );
    assert!(
        c.handshake.timer().is_none(),
        "[R3:T2:HANDSHAKE-TIMER-IS-NONE]"
    );
    assert_eq!(
        c.timers.handshake_attempts, 0,
        "[R3:T2:TIMERS-HANDSHAKE-ATTEMPTS]"
    );
    assert_eq!(
        c.timers[TimerName::TimeLastHandshakeStarted],
        started,
        "[R3:T2:TIMERS-TIMERNAME-TIMELASTHANDSHAKESTARTED-STARTED]"
    );
    assert_eq!(
        c.timers[TimerName::TimeLastPacketSent],
        sent,
        "[R3:T2:TIMERS-TIMERNAME-TIMELASTPACKETSENT-SENT]"
    );
    assert_eq!(
        c.handshake.rng.get_word_pos(),
        rng_before,
        "[R3:T2:HANDSHAKE-RNG-GET-WORD-POS-RNG-BEFORE]"
    );
    let init = net(c.encapsulate(&p, &mut [0u8; HANDSHAKE_INIT_SZ + 64]));
    assert_eq!(
        init.len(),
        HANDSHAKE_INIT_SZ + 64,
        "[R3:T2:INIT-LEN-HANDSHAKE-INIT-SZ]"
    );
    assert_eq!(
        c.timers.handshake_attempts, 0,
        "[R3:T2:TIMERS-HANDSHAKE-ATTEMPTS-2]"
    );
    let d = complete_and_drain(&mut c, &mut s, init);
    assert_eq!(copies(&d, &p), 1, "[R3:T2:COPIES]");
}

// T3
#[test]
fn repeated_short_retries_never_grow_the_queue() {
    let (mut c, mut s) = pair(plain(), plain());
    let p = ipv4(3);
    let before = snap(&c);
    for _ in 0..5 {
        assert!(
            is_dbts(&c.encapsulate(&p, &mut [0u8; 100])),
            "[R3:T3:IS-DBTS-ENCAPSULATE]"
        );
        assert_eq!(snap(&c), before, "[R3:T3:REPEATED-REFUSALS-LEAVE-STATE]");
    }
    let init = net(c.encapsulate(&p, &mut [0u8; 2048]));
    let d = complete_and_drain(&mut c, &mut s, init);
    assert_eq!(copies(&d, &p), 1, "[R3:T3:COPIES]");
}

// T5
#[test]
fn done_while_the_handshake_is_in_flight_means_accepted() {
    let (mut c, _s) = pair(plain(), plain());
    let a = ipv4(4);
    let b = ipv4(5);
    let _ = net(c.encapsulate(&a, &mut [0u8; 2048]));
    let mut tmp = [0u8; 0];
    let r = c.encapsulate(&b, &mut tmp);
    assert!(
        matches!(r, TunnResult::Done),
        "[R3:T5:MATCHES-TUNNRESULT-DONE]"
    );
    assert_eq!(queue(&c), vec![a, b], "[R3:T5:QUEUE-A-B]");
}

// T6
#[test]
fn a_pending_imitation_datagram_that_does_not_fit_is_kept_and_src_is_not_accepted() {
    let cfg =
        plain().with_protocol_imitation(AmneziaImitationProtocol::Dns, Some("example.com".into()));
    let (mut c, _s) = pair(cfg, plain());
    let p = ipv4(6);
    assert!(
        is_dbts(&c.encapsulate(&p, &mut [0u8; 10])),
        "[R3:T6:IS-DBTS-ENCAPSULATE]"
    );
    assert!(queue(&c).is_empty(), "[R3:T6:QUEUE-IS-EMPTY]");
    let pending = c
        .pending_amnezia_junk
        .as_ref()
        .expect("[R3:T6:BURST-KEPT] burst kept");
    let front = pending.imitation_datagrams.front().unwrap().1.clone();
    assert_eq!(
        pending.imitation_datagrams.len(),
        3,
        "[R3:T6:PENDING-IMITATION-DATAGRAMS-LEN]"
    );
    // One byte short of the actual front datagram: still refused, still kept.
    let before = snap(&c);
    assert!(
        is_dbts(&c.encapsulate(&p, &mut vec![0u8; front.len() - 1])),
        "[R3:T6:IS-DBTS-ENCAPSULATE-FRONT-LEN]"
    );
    assert_eq!(snap(&c), before, "[R3:T6:SNAP-BEFORE]");
    assert!(
        !before.in_progress && before.attempts == 0,
        "[R3:T6:BEFORE-IN-PROGRESS-BEFORE-ATTEMPTS]"
    );
    assert_eq!(
        c.pending_amnezia_junk
            .as_ref()
            .unwrap()
            .imitation_datagrams
            .len(),
        3,
        "[R3:T6:PENDING-AMNEZIA-JUNK-IMITATION-DATAGRAMS-LEN]"
    );
    // Exact: the same datagram goes out, src accepted once.
    let out = net(c.encapsulate(&p, &mut vec![0u8; front.len()]));
    assert_eq!(out, front, "[R3:T6:OUT-FRONT]");
    assert_eq!(queue(&c), vec![p], "[R3:T6:QUEUE]");
}

// T7
#[test]
fn a_jc_refusal_against_the_configured_maximum_draws_nothing() {
    let cfg = plain().with_pre_handshake_junk(2, 500, 600, 0);
    let (mut c, _s) = pair(cfg, plain());
    let p = ipv4(7);
    // The burst is created by this call, but Jc has no imitation sequence, so
    // nothing was drawn to build it.
    let before = c.handshake.rng.get_word_pos();
    assert!(
        is_dbts(&c.encapsulate(&p, &mut [0u8; 599])),
        "[R3:T7:IS-DBTS-ENCAPSULATE]"
    );
    assert_eq!(
        c.handshake.rng.get_word_pos(),
        before,
        "[R3:T7:NO-SIZE-DRAW-ON-A-REFUSAL] no size draw on a refusal"
    );
    let pending = c.pending_amnezia_junk.as_ref().unwrap();
    assert_eq!(
        (pending.remaining, pending.last_packet_at.is_none()),
        (2, true),
        "[R3:T7:PENDING-REMAINING-PENDING-LAST-PACKET-AT-IS-NONE]"
    );
    assert!(queue(&c).is_empty(), "[R3:T7:QUEUE-IS-EMPTY]");
    let before = snap(&c);
    assert!(
        is_dbts(&c.encapsulate(&p, &mut [0u8; 599])),
        "[R3:T7:IS-DBTS-ENCAPSULATE-2]"
    );
    assert!(
        is_dbts(&c.update_timers(&mut [0u8; 599])),
        "[R3:T7:IS-DBTS-UPDATE-TIMERS]"
    );
    assert_eq!(
        snap(&c),
        before,
        "[R3:T7:REPEATED-REFUSALS-NOTHING-MOVES] repeated refusals: nothing moves"
    );
    let junk = net(c.encapsulate(&p, &mut [0u8; 600]));
    assert!(
        (500..=600).contains(&junk.len()),
        "[R3:T7:CONTAINS-JUNK-LEN]"
    );
    assert_eq!(
        c.pending_amnezia_junk.as_ref().unwrap().remaining,
        1,
        "[R3:T7:PENDING-AMNEZIA-JUNK-REMAINING]"
    );
    assert_eq!(queue(&c), vec![p], "[R3:T7:QUEUE]");
}

// T9
#[test]
fn a_full_queue_refuses_a_new_write_without_preparing_output() {
    let cfg = plain().with_pre_handshake_junk(1, 100, 100, 200);
    let (mut c, _s) = pair(cfg, plain());
    let _ = net(c.encapsulate(&ipv4(0), &mut [0u8; 2048])); // junk; burst now paced
    for i in 1..MAX_QUEUE_DEPTH {
        assert!(
            matches!(
                c.encapsulate(&ipv4(i as u8), &mut [0u8; 2048]),
                TunnResult::Done
            ),
            "[R3:T9:MATCHES-ENCAPSULATE-IPV4-I-TUNNRESULT]"
        );
    }
    assert_eq!(
        c.packet_queue.len(),
        MAX_QUEUE_DEPTH,
        "[R3:T9:PACKET-QUEUE-LEN-MAX-QUEUE-DEPTH]"
    );
    let snapshot = queue(&c);
    let rng = c.handshake.rng.get_word_pos();
    let remaining = c.pending_amnezia_junk.as_ref().unwrap().remaining;
    #[cfg(feature = "mock-instant")]
    mock_instant::thread_local::MockClock::advance(Duration::from_millis(250));
    #[cfg(not(feature = "mock-instant"))]
    std::thread::sleep(Duration::from_millis(250));
    // The paced burst is now due; a full queue must still not advance it.
    let mut tmp = [0u8; 2048];
    let r = c.encapsulate(&ipv4(0xff), &mut tmp);
    assert!(
        matches!(r, TunnResult::Err(WireGuardError::PacketQueueFull)),
        "[R3:T9:MATCHES-TUNNRESULT-ERR-WIREGUARDERROR-PACKETQUEUEFULL]"
    );
    assert_eq!(queue(&c), snapshot, "[R3:T9:QUEUE-SNAPSHOT]");
    assert_eq!(
        c.handshake.rng.get_word_pos(),
        rng,
        "[R3:T9:HANDSHAKE-RNG-GET-WORD-POS-RNG]"
    );
    assert_eq!(
        c.pending_amnezia_junk.as_ref().map(|p| p.remaining),
        Some(remaining),
        "[R3:T9:QUEUE-FULL-DOES-NOT-ADVANCE-BURST]"
    );
    // A zero-length dst reports the queue, not the buffer.
    assert!(
        matches!(
            c.encapsulate(&ipv4(0xfe), &mut [0u8; 0]),
            TunnResult::Err(WireGuardError::PacketQueueFull)
        ),
        "[R3:T9:MATCHES-ENCAPSULATE-IPV4-XFE-TUNNRESULT]"
    );
}

// T10 / T11
#[test]
fn the_256th_write_is_admitted_once_and_an_empty_write_occupies_a_slot() {
    let (mut c, _s) = pair(plain(), plain());
    let _ = net(c.encapsulate(&[], &mut [0u8; 2048]));
    assert_eq!(c.packet_queue.len(), 1, "[R3:T10:PACKET-QUEUE-LEN]");
    assert!(
        c.packet_queue[0].is_empty(),
        "[R3:T10:PACKET-QUEUE-IS-EMPTY]"
    );
    for i in 2..MAX_QUEUE_DEPTH {
        assert!(
            matches!(
                c.encapsulate(&ipv4(i as u8), &mut [0u8; 2048]),
                TunnResult::Done
            ),
            "[R3:T10:MATCHES-ENCAPSULATE-IPV4-I-TUNNRESULT]"
        );
    }
    assert_eq!(
        c.packet_queue.len(),
        MAX_QUEUE_DEPTH - 1,
        "[R3:T10:PACKET-QUEUE-LEN-MAX-QUEUE-DEPTH]"
    );
    assert!(
        matches!(
            c.encapsulate(&ipv4(0xaa), &mut [0u8; 2048]),
            TunnResult::Done
        ),
        "[R3:T10:MATCHES-ENCAPSULATE-IPV4-XAA-TUNNRESULT]"
    );
    assert_eq!(
        c.packet_queue.len(),
        MAX_QUEUE_DEPTH,
        "[R3:T10:PACKET-QUEUE-LEN-MAX-QUEUE-DEPTH-2]"
    );
    assert_eq!(
        c.packet_queue.back().unwrap(),
        &ipv4(0xaa),
        "[R3:T10:PACKET-QUEUE-BACK-IPV4-XAA]"
    );
}

// T12 / T13
#[test]
fn a_short_empty_drain_without_a_session_never_readmits_the_queue() {
    let cfg = AmneziaConfig::new(64, 0, 0, 0);
    let (mut c, _s) = pair(cfg, plain());
    // Accept two packets with an adequate buffer; the initiation is in flight.
    let _ = net(c.encapsulate(&ipv4(1), &mut [0u8; 2048]));
    assert!(
        matches!(c.encapsulate(&ipv4(2), &mut [0u8; 2048]), TunnResult::Done),
        "[R3:T12:MATCHES-ENCAPSULATE-IPV4-TUNNRESULT-DONE]"
    );
    let snapshot = snap(&c);
    assert_eq!(
        snapshot.queue,
        vec![ipv4(1), ipv4(2)],
        "[R3:T12:SNAPSHOT-QUEUE-IPV4-IPV4]"
    );
    for dst in [0usize, 100, 2048] {
        let mut tmp = vec![0u8; dst];
        let r = c.decapsulate(None, &[], &mut tmp);
        assert!(
            matches!(r, TunnResult::Done),
            "[R3:T12:SHORT-EMPTY-DRAIN-IS-DONE] dst {}: {:?}",
            dst,
            r
        );
        assert_eq!(
            snap(&c),
            snapshot,
            "[R3:T12:NO-SESSION-DRAIN-LEAVES-QUEUE-AND-STATE] dst {}",
            dst
        );
    }
}

#[test]
fn a_no_session_drain_drives_the_handshake_and_leaves_the_queue() {
    let cfg = plain().with_pre_handshake_junk(2, 100, 100, 0);
    let (mut c, _s) = pair(cfg, plain());
    let _ = net(c.encapsulate(&ipv4(1), &mut [0u8; 2048])); // first junk
    let snapshot = queue(&c);
    // Short drain: capacity error from the protocol output, nothing moves.
    let before = snap(&c);
    assert!(
        is_dbts(&c.decapsulate(None, &[], &mut [0u8; 50])),
        "[R3:T13:IS-DBTS-DECAPSULATE-NONE]"
    );
    assert_eq!(snap(&c), before, "[R3:T13:SNAP-BEFORE]");
    // Adequate drain: the second junk, then the initiation; queue untouched.
    assert_eq!(
        net(c.decapsulate(None, &[], &mut [0u8; 2048])).len(),
        100,
        "[R3:T13:NET-DECAPSULATE-NONE-LEN]"
    );
    assert_eq!(
        net(c.decapsulate(None, &[], &mut [0u8; 2048])).len(),
        HANDSHAKE_INIT_SZ,
        "[R3:T13:NET-DECAPSULATE-NONE-LEN-HANDSHAKE-INIT-SZ]"
    );
    assert_eq!(queue(&c), snapshot, "[R3:T13:QUEUE-SNAPSHOT]");
}

// T14 / T15 / T16
#[test]
fn an_owned_head_that_does_not_fit_is_reported_kept_and_later_sent_in_order() {
    let (mut c, mut s) = pair(plain(), plain());
    let large = {
        let h = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 3], 64).udp(1, 2);
        let mut v = Vec::new();
        h.write(&mut v, &[0x5a; 1400]).unwrap();
        v
    };
    let small = ipv4(9);
    let init = net(c.encapsulate(&large, &mut [0u8; 2048]));
    assert!(
        matches!(c.encapsulate(&small, &mut [0u8; 2048]), TunnResult::Done),
        "[R3:T14:MATCHES-ENCAPSULATE-SMALL-TUNNRESULT-DONE]"
    );
    let mut sbuf = vec![0u8; 65535];
    let resp = net(s.decapsulate(None, &init, &mut sbuf));
    let ka = net(c.decapsulate(None, &resp, &mut [0u8; 2048]));
    let _ = s.decapsulate(None, &ka, &mut sbuf);
    let before = snap(&c);
    assert_eq!(
        before.queue,
        vec![large.clone(), small.clone()],
        "[R3:T14:BEFORE-QUEUE-LARGE-SMALL]"
    );
    assert!(before.has_session, "[R3:T14:BEFORE-HAS-SESSION]");
    for _ in 0..3 {
        let mut tmp = [0u8; 1000];
        let r = c.decapsulate(None, &[], &mut tmp);
        assert!(
            is_dbts(&r),
            "[R3:T14:OWNED-HEAD-REFUSAL-REPORTS-DBTS] {:?}",
            r
        );
        assert_eq!(snap(&c), before, "[R3:T14:OWNED-HEAD-RESTORED-NOTHING-ELSE-MOVED] owned head restored, nothing else moved");
    }
    let mut delivered = Vec::new();
    loop {
        match c.decapsulate(None, &[], &mut [0u8; 2048]) {
            TunnResult::WriteToNetwork(p) => {
                let p = p.to_vec();
                if let TunnResult::WriteToTunnelV4(pl, _) = s.decapsulate(None, &p, &mut sbuf) {
                    delivered.push(pl.to_vec());
                }
            }
            TunnResult::Done => break,
            other => panic!("[R3:T14:CHECK-2] {:?}", other),
        }
    }
    assert_eq!(
        delivered,
        vec![large, small],
        "[R3:T14:DELIVERED-LARGE-SMALL]"
    );
}

// T18 (needs the mock clock to reach the retransmission deadline)
#[cfg(feature = "mock-instant")]
#[test]
fn a_timer_retransmission_into_a_short_dst_consumes_nothing_and_stays_due() {
    let cfg = AmneziaConfig::new(64, 0, 0, 0);
    let (mut c, _s) = pair(cfg, plain());
    let first = net(c.encapsulate(&ipv4(1), &mut [0u8; 2048]));
    let idx = u32::from_le_bytes(first[64 + 4..64 + 8].try_into().unwrap());
    mock_instant::thread_local::MockClock::advance(Duration::from_secs(6));
    let sent_at = c.handshake.timer();
    let attempts = c.timers.handshake_attempts;
    let mut tmp = [0u8; HANDSHAKE_INIT_SZ + 63];
    let r = c.update_timers(&mut tmp);
    assert!(is_dbts(&r), "[R3:T18:CHECK] {:?}", r);
    assert_eq!(
        c.handshake.timer(),
        sent_at,
        "[R3:T18:HANDSHAKE-TIMER-SENT-AT]"
    );
    assert_eq!(
        c.timers.handshake_attempts, attempts,
        "[R3:T18:TIMERS-HANDSHAKE-ATTEMPTS-ATTEMPTS]"
    );
    let again = net(c.update_timers(&mut [0u8; 2048]));
    let idx2 = u32::from_le_bytes(again[64 + 4..64 + 8].try_into().unwrap());
    assert_eq!(
        idx2,
        idx.wrapping_add(1),
        "[R3:T18:EXACTLY-ONE-NEW-INDEX-FOR-THE] exactly one new index, for the one that left"
    );
    assert_eq!(
        c.timers.handshake_attempts,
        attempts + 1,
        "[R3:T18:TIMERS-HANDSHAKE-ATTEMPTS-ATTEMPTS-2]"
    );
}

// Timer latch: KEEPALIVE + REKEY_TIMEOUT demand survives a capacity refusal.
#[cfg(feature = "mock-instant")]
#[test]
fn a_refused_keepalive_rekey_initiation_rearms_its_latch() {
    let cfg = AmneziaConfig::new(64, 0, 0, 0);
    let (mut c, mut s) = pair(cfg.clone(), cfg);
    let mut big = vec![0u8; 2048];
    let init = net(c.format_handshake_initiation(&mut big, false));
    let resp = net(s.decapsulate(None, &init, &mut vec![0u8; 2048]));
    let _ka = net(c.decapsulate(None, &resp, &mut big));
    mock_instant::thread_local::MockClock::advance(Duration::from_secs(1));
    let _ = c.update_timers(&mut big);
    let _data = net(c.encapsulate(&ipv4(1), &mut big)); // arms want_handshake
    mock_instant::thread_local::MockClock::advance(Duration::from_secs(16));
    let mut tmp = [0u8; HANDSHAKE_INIT_SZ + 63];
    let r = c.update_timers(&mut tmp);
    assert!(is_dbts(&r), "[R3:T18C:CHECK] {:?}", r);
    assert!(
        !c.handshake.is_in_progress(),
        "[R3:T18C:HANDSHAKE-IS-IN-PROGRESS]"
    );
    // Re-armed latch: the next adequate tick sends the initiation (without
    // the re-arm this tick is Done and `net` panics).
    let init2 = sent(
        c.update_timers(&mut big),
        "[R3:T18C:REARMED-LATCH-SENDS-INITIATION]",
    );
    assert_eq!(
        init2.len(),
        HANDSHAKE_INIT_SZ + 64,
        "[R3:T18C:INIT2-LEN-HANDSHAKE-INIT-SZ]"
    );
}

// Expired cycle with a burst: refusal leaves timers alone; the first committed
// datagram resets them exactly once.
#[cfg(feature = "mock-instant")]
#[test]
fn an_expired_cycle_resets_its_timers_at_the_first_committed_output_only() {
    let cfg = plain().with_pre_handshake_junk(2, 100, 100, 0);
    let (mut c, _s) = pair(cfg, plain());
    mock_instant::thread_local::MockClock::advance(Duration::from_secs(1));
    let _ = c.update_timers(&mut [0u8; 2048]);
    c.handshake.set_expired();
    mock_instant::thread_local::MockClock::advance(Duration::from_secs(7));
    let before = c.timers[TimerName::TimeSessionEstablished];
    assert!(
        is_dbts(&c.encapsulate(&ipv4(1), &mut [0u8; 50])),
        "[R3:T20B:IS-DBTS-ENCAPSULATE-IPV4]"
    );
    assert_eq!(
        c.timers[TimerName::TimeSessionEstablished],
        before,
        "[R3:T20B:NO-RESET-ON-A-REFUSAL] no reset on a refusal"
    );
    assert!(
        c.pending_amnezia_junk
            .as_ref()
            .unwrap()
            .reset_expired_timers,
        "[R3:T20B:PENDING-AMNEZIA-JUNK-RESET-EXPIRED-TIMERS]"
    );
    let _ = net(c.encapsulate(&ipv4(1), &mut [0u8; 2048]));
    let reset_to = c.timers[TimerName::TimeSessionEstablished];
    assert!(
        reset_to > before,
        "[R3:T20B:RESET-AT-THE-FIRST-COMMITTED-DATAGRAM] reset at the first committed datagram"
    );
    assert!(
        !c.pending_amnezia_junk
            .as_ref()
            .unwrap()
            .reset_expired_timers,
        "[R3:T20B:PENDING-AMNEZIA-JUNK-RESET-EXPIRED-TIMERS-2]"
    );
    mock_instant::thread_local::MockClock::advance(Duration::from_secs(3));
    let _ = net(c.update_timers(&mut [0u8; 2048])); // second junk
    assert_eq!(
        c.timers[TimerName::TimeSessionEstablished],
        reset_to,
        "[R3:T20B:ONLY-ONCE] only once"
    );
}

// Old forced burst-completion mutant: an initiation already in flight when a
// retransmission burst completes.
#[cfg(feature = "mock-instant")]
#[test]
fn a_retransmission_burst_completes_over_an_initiation_already_in_flight() {
    let cfg = plain().with_pre_handshake_junk(1, 100, 100, 0);
    let (mut c, _s) = pair(cfg, plain());
    let mut big = vec![0u8; 2048];
    assert_eq!(
        net(c.encapsulate(&ipv4(1), &mut big)).len(),
        100,
        "[R3:T19B:NET-ENCAPSULATE-IPV4-BIG-LEN]"
    );
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        HANDSHAKE_INIT_SZ,
        "[R3:T19B:NET-UPDATE-TIMERS-BIG-LEN-HANDSHAKE-INIT-SZ]"
    );
    assert!(
        c.handshake.is_in_progress(),
        "[R3:T19B:HANDSHAKE-IS-IN-PROGRESS]"
    );
    mock_instant::thread_local::MockClock::advance(Duration::from_secs(6));
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        100,
        "[R3:T19B:RETRANSMISSION-BURST-JUNK] retransmission burst junk"
    );
    assert!(
        c.handshake.is_in_progress(),
        "[R3:T19B:HANDSHAKE-IS-IN-PROGRESS-2]"
    );
    assert_eq!(
        sent(
            c.update_timers(&mut big),
            "[R3:T19B:FORCED-COMPLETION-SENDS-INITIATION]"
        )
        .len(),
        HANDSHAKE_INIT_SZ,
        "[R3:T19B:FORCED-COMPLETION] forced completion"
    );
    assert!(
        c.pending_amnezia_junk.is_none(),
        "[R3:T19B:PENDING-AMNEZIA-JUNK-IS-NONE]"
    );
}

// T28
#[test]
fn every_pre_existing_error_code_is_unchanged() {
    use WireGuardError::*;
    let codes = [
        (DestinationBufferTooSmall as usize, 0),
        (IncorrectPacketLength as usize, 1),
        (UnexpectedPacket as usize, 2),
        (WrongPacketType as usize, 3),
        (WrongIndex as usize, 4),
        (WrongKey as usize, 5),
        (InvalidTai64nTimestamp as usize, 6),
        (WrongTai64nTimestamp as usize, 7),
        (InvalidMac as usize, 8),
        (InvalidAeadTag as usize, 9),
        (InvalidCounter as usize, 10),
        (DuplicateCounter as usize, 11),
        (InvalidPacket as usize, 12),
        (NoCurrentSession as usize, 13),
        (LockFailed as usize, 14),
        (ConnectionExpired as usize, 15),
        (UnderLoad as usize, 16),
        (PacketQueueFull as usize, 17),
    ];
    for (got, want) in codes {
        assert_eq!(got, want, "[R3:T28:ERROR-CODE-VALUE-PINNED]");
    }
}

// T23 feasibility: a seeded SIP burst gives a deterministic front length.
#[test]
fn a_seeded_sip_burst_is_refused_one_byte_short_and_sent_exact() {
    use rand_core::SeedableRng;
    let host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(host.len(), 253, "[R3:T23:HOST-LEN]");
    let cfg = plain().with_protocol_imitation(AmneziaImitationProtocol::Sip, Some(host));
    assert!(
        cfg.imitation.domain().is_some(),
        "[R3:T23:253-BYTE-HOST-ACCEPTED] 253-byte host accepted"
    );
    let (mut c, _s) = pair(cfg, plain());
    c.handshake.rng = rand_chacha::ChaCha8Rng::seed_from_u64(5_202_668);
    let p = ipv4(23);
    assert!(
        is_dbts(&c.encapsulate(&p, &mut [0u8; 1])),
        "[R3:T23:IS-DBTS-ENCAPSULATE]"
    );
    let len = c
        .pending_amnezia_junk
        .as_ref()
        .unwrap()
        .imitation_datagrams
        .front()
        .unwrap()
        .1
        .len();
    assert!(
        is_dbts(&c.encapsulate(&p, &mut vec![0u8; len - 1])),
        "[R3:T23:IS-DBTS-ENCAPSULATE-LEN]"
    );
    assert_eq!(
        net(c.encapsulate(&p, &mut vec![0u8; len])).len(),
        len,
        "[R3:T23:NET-ENCAPSULATE-LEN-LEN-LEN]"
    );
    assert_eq!(queue(&c), vec![p], "[R3:T23:QUEUE]");
    assert_eq!(
        len, 1298,
        "[R3:T23:THE-MAXIMAL-INVITE-FOR-A-253] the maximal INVITE for a 253-byte host (rand_chacha 0.3.1)"
    );
}

#[cfg(feature = "ffi-bindings")]
#[test]
fn the_c_write_reports_queue_full_as_its_appended_code() {
    use crate::ffi::{result_type, tunnel_free, wireguard_write};
    let (c, _s) = pair(plain(), plain());
    let t = Box::into_raw(Box::new(parking_lot::Mutex::new(c)));
    let mut dst = vec![0u8; 2048];
    unsafe {
        for i in 0..MAX_QUEUE_DEPTH {
            let p = ipv4(i as u8);
            let r = wireguard_write(t, p.as_ptr(), p.len() as u32, dst.as_mut_ptr(), 2048);
            assert!(
                matches!(
                    r.op,
                    result_type::WRITE_TO_NETWORK | result_type::WIREGUARD_DONE
                ),
                "[R3:T27:MATCHES-OP-RESULT-TYPE-WRITE-TO-NETWORK-RESULT-TYPE]"
            );
        }
        let p = ipv4(0xff);
        let r = wireguard_write(t, p.as_ptr(), p.len() as u32, dst.as_mut_ptr(), 2048);
        assert!(
            matches!(r.op, result_type::WIREGUARD_ERROR),
            "[R3:T27:MATCHES-OP-RESULT-TYPE-WIREGUARD-ERROR]"
        );
        assert_eq!(r.size, 17, "[R3:T27:SIZE]");
        let r = wireguard_write(t, p.as_ptr(), p.len() as u32, dst.as_mut_ptr(), 100);
        assert!(
            matches!(r.op, result_type::WIREGUARD_ERROR),
            "[R3:T27:MATCHES-OP-RESULT-TYPE-WIREGUARD-ERROR-2]"
        );
        assert_eq!(r.size, 17, "[R3:T27:QUEUE-FULL-TAKES-PRECEDENCE-OVER-CAPACITY] queue-full takes precedence over capacity");
        tunnel_free(t);
    }
}

#[cfg(feature = "ffi-bindings")]
#[test]
fn the_c_write_capacity_error_does_not_accept_src() {
    use crate::ffi::{result_type, tunnel_free, wireguard_write};
    let (c, _s) = pair(plain(), plain());
    let t = Box::into_raw(Box::new(parking_lot::Mutex::new(c)));
    let mut dst = vec![0u8; 2048];
    let p = ipv4(1);
    unsafe {
        let r = wireguard_write(t, p.as_ptr(), p.len() as u32, dst.as_mut_ptr(), 100);
        assert!(
            matches!(r.op, result_type::WIREGUARD_ERROR),
            "[R3:T25:MATCHES-OP-RESULT-TYPE-WIREGUARD-ERROR]"
        );
        assert_eq!(r.size, 0, "[R3:T25:SIZE]");
        assert!(
            (*t).lock().packet_queue.is_empty(),
            "[R3:T25:LOCK-PACKET-QUEUE-IS-EMPTY]"
        );
        let r = wireguard_write(t, p.as_ptr(), p.len() as u32, dst.as_mut_ptr(), 2048);
        assert!(
            matches!(r.op, result_type::WRITE_TO_NETWORK),
            "[R3:T25:MATCHES-OP-RESULT-TYPE-WRITE-TO-NETWORK]"
        );
        assert_eq!(r.size, HANDSHAKE_INIT_SZ, "[R3:T25:SIZE-HANDSHAKE-INIT-SZ]");
        assert_eq!(
            (*t).lock().packet_queue.len(),
            1,
            "[R3:T25:LOCK-PACKET-QUEUE-LEN]"
        );
        tunnel_free(t);
    }
}

// M14: a refused write leaves an existing queue exactly as it was.
#[test]
fn a_capacity_refusal_leaves_the_existing_queue_order_alone() {
    let cfg =
        plain().with_protocol_imitation(AmneziaImitationProtocol::Dns, Some("example.com".into()));
    let (mut c, _s) = pair(cfg, plain());
    let (a, b, x) = (ipv4(1), ipv4(2), ipv4(3));
    let _ = net(c.encapsulate(&a, &mut [0u8; 2048])); // DNS A
    let _ = net(c.encapsulate(&b, &mut [0u8; 2048])); // DNS AAAA
    assert_eq!(queue(&c), vec![a.clone(), b.clone()], "[R3:TM14:QUEUE-A-B]");
    #[cfg(feature = "mock-instant")]
    mock_instant::thread_local::MockClock::advance(Duration::from_millis(20));
    #[cfg(not(feature = "mock-instant"))]
    std::thread::sleep(Duration::from_millis(20));
    let mut tiny = [0u8; 10];
    let r = c.encapsulate(&x, &mut tiny); // DNS HTTPS query due, does not fit
    assert!(is_dbts(&r), "[R3:TM14:CHECK] {:?}", r);
    assert_eq!(queue(&c), vec![a, b], "[R3:TM14:REFUSAL-KEEPS-QUEUE-ORDER]");
}

// M17: the head of a FULL queue survives a short drain (requeue is infallible).
#[test]
fn a_full_queue_keeps_its_head_through_a_short_drain() {
    let (mut c, mut s) = pair(plain(), plain());
    let init = net(c.encapsulate(&ipv4(0), &mut [0u8; 2048]));
    for i in 1..MAX_QUEUE_DEPTH {
        assert!(
            matches!(
                c.encapsulate(&ipv4(i as u8), &mut [0u8; 2048]),
                TunnResult::Done
            ),
            "[R3:T16:MATCHES-ENCAPSULATE-IPV4-I-TUNNRESULT]"
        );
    }
    assert_eq!(
        c.packet_queue.len(),
        MAX_QUEUE_DEPTH,
        "[R3:T16:PACKET-QUEUE-LEN-MAX-QUEUE-DEPTH]"
    );
    let snapshot = queue(&c);
    let mut sbuf = vec![0u8; 65535];
    let resp = net(s.decapsulate(None, &init, &mut sbuf));
    let _ka = net(c.decapsulate(None, &resp, &mut [0u8; 2048]));
    let before = snap(&c);
    let mut short = [0u8; 50];
    let r = c.decapsulate(None, &[], &mut short);
    assert!(
        is_dbts(&r),
        "[R3:T16:FULL-QUEUE-SHORT-DRAIN-REPORTS-DBTS] {:?}",
        r
    );
    assert_eq!(
        snap(&c),
        before,
        "[R3:T16:FULL-QUEUE-HEAD-RESTORED-STATE-UNCHANGED]"
    );
    assert_eq!(queue(&c), snapshot, "[R3:T16:QUEUE-SNAPSHOT]");
    // Later, every owned entry leaves once, in order: no loss, no duplicate.
    let mut delivered = Vec::new();
    loop {
        match c.decapsulate(None, &[], &mut [0u8; 2048]) {
            TunnResult::WriteToNetwork(p) => {
                let p = p.to_vec();
                match s.decapsulate(None, &p, &mut sbuf) {
                    TunnResult::WriteToTunnelV4(pl, _) => delivered.push(pl.to_vec()),
                    other => panic!("[R3:T16:CHECK-2] {:?}", other),
                }
            }
            TunnResult::Done => break,
            other => panic!("[R3:T16:CHECK-3] {:?}", other),
        }
    }
    assert_eq!(
        delivered.len(),
        MAX_QUEUE_DEPTH,
        "[R3:T16:DELIVERED-LEN-MAX-QUEUE-DEPTH]"
    );
    assert_eq!(
        delivered, snapshot,
        "[R3:T16:FIFO-ONCE-EACH] FIFO, once each"
    );
    assert!(c.packet_queue.is_empty(), "[R3:T16:PACKET-QUEUE-IS-EMPTY]");
}

// T11b: an admitted empty write is eventually sent, as an empty transport
// (keepalive), in its queue position.
#[test]
fn an_admitted_empty_write_is_eventually_sent_as_a_keepalive() {
    let (mut c, mut s) = pair(plain(), plain());
    let init = net(c.encapsulate(&[], &mut [0u8; 2048]));
    assert!(
        matches!(c.encapsulate(&ipv4(2), &mut [0u8; 2048]), TunnResult::Done),
        "[R3:T11B:MATCHES-ENCAPSULATE-IPV4-TUNNRESULT-DONE]"
    );
    assert_eq!(queue(&c), vec![vec![], ipv4(2)], "[R3:T11B:QUEUE-IPV4]");
    let mut sbuf = vec![0u8; 65535];
    let resp = net(s.decapsulate(None, &init, &mut sbuf));
    let ka = net(c.decapsulate(None, &resp, &mut [0u8; 2048]));
    let _ = s.decapsulate(None, &ka, &mut sbuf);
    let first = net(c.decapsulate(None, &[], &mut [0u8; 2048]));
    assert_eq!(
        first.len(),
        32,
        "[R3:T11B:HEADER-EMPTY-PAYLOAD-TAG] header + empty payload + tag"
    );
    assert!(
        matches!(s.decapsulate(None, &first, &mut sbuf), TunnResult::Done),
        "[R3:T11B:MATCHES-DECAPSULATE-NONE-FIRST-SBUF]"
    );
    let second = net(c.decapsulate(None, &[], &mut [0u8; 2048]));
    match s.decapsulate(None, &second, &mut sbuf) {
        TunnResult::WriteToTunnelV4(pl, _) => assert_eq!(pl, &ipv4(2)[..], "[R3:T11B:PL-IPV4]"),
        other => panic!("[R3:T11B:CHECK] {:?}", other),
    }
    assert!(
        matches!(c.decapsulate(None, &[], &mut [0u8; 2048]), TunnResult::Done),
        "[R3:T11B:MATCHES-DECAPSULATE-NONE-TUNNRESULT-DONE]"
    );
}

// T18b: a refused fresh plain write creates no
// handshake request, so later ticks have nothing due -- not capacity errors.
#[test]
fn a_refused_fresh_write_creates_no_handshake_request() {
    let (mut c, _s) = pair(plain(), plain());
    assert!(
        is_dbts(&c.encapsulate(&ipv4(1), &mut [0u8; 100])),
        "[R3:T18B:IS-DBTS-ENCAPSULATE-IPV4]"
    );
    assert!(
        !c.handshake.is_in_progress(),
        "[R3:T18B:HANDSHAKE-IS-IN-PROGRESS]"
    );
    for _ in 0..3 {
        let mut short = [0u8; 100];
        let r = c.update_timers(&mut short);
        assert!(matches!(r, TunnResult::Done), "[R3:T18B:CHECK] {:?}", r);
    }
    assert!(
        !c.handshake.is_in_progress(),
        "[R3:T18B:HANDSHAKE-IS-IN-PROGRESS-2]"
    );
    assert!(queue(&c).is_empty(), "[R3:T18B:QUEUE-IS-EMPTY]");
}

// T19, public half: the public setter refuses an HP prefix
// shorter than the nonce and keeps the previous configuration.
#[test]
fn the_public_setter_refuses_a_header_protection_prefix_shorter_than_the_nonce() {
    let (mut c, _s) = pair(plain(), plain());
    let broken = AmneziaConfig::new(4, 16, 16, 16).with_header_protection([7u8; 32]);
    assert!(
        c.try_set_obfuscation(Default::default(), broken).is_err(),
        "[R3:T19P:TRY-SET-OBFUSCATION-DEFAULT-DEFAULT-BROKEN-IS-ERR]"
    );
    let init = net(c.encapsulate(&ipv4(1), &mut [0u8; 2048]));
    assert_eq!(
        init.len(),
        HANDSHAKE_INIT_SZ,
        "[R3:T19P:PREVIOUS-PLAIN-CONFIGURATION-KEPT] previous (plain) configuration kept"
    );
}

// T19, private half: the send-time masking backstop (reachable only through
// the unchecked setter) refuses the write; the new src is still not accepted.
#[test]
fn the_unchecked_header_protection_backstop_refuses_without_accepting_src() {
    let (mut c, _s) = pair(plain(), plain());
    let broken = AmneziaConfig::new(4, 16, 16, 16).with_header_protection([7u8; 32]);
    c.apply_obfuscation(Default::default(), broken);
    let mut big = [0u8; 2048];
    let r = c.encapsulate(&ipv4(1), &mut big);
    assert!(is_dbts(&r), "[R3:T19U:CHECK] {:?}", r);
    assert!(queue(&c).is_empty(), "[R3:T19U:QUEUE-IS-EMPTY]");
    // Documented, not promised away: this backstop fires after the handshake
    // was formatted, as before R3.
    assert!(
        c.handshake.is_in_progress(),
        "[R3:T19U:HANDSHAKE-IS-IN-PROGRESS]"
    );
}

// T8: an adequate Jc emission draws exactly what the generator draws.
#[test]
fn an_adequate_jc_emission_is_the_generators_own_draw() {
    use rand_core::SeedableRng;
    let cfg = plain().with_pre_handshake_junk(2, 300, 900, 0);
    let (mut c, _s) = pair(cfg.clone(), plain());
    c.handshake.rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
    let mut twin = rand_chacha::ChaCha8Rng::seed_from_u64(42);
    let mut expected = vec![0u8; 2048];
    let expected = cfg
        .fill_pre_handshake_junk(&mut expected, &mut twin)
        .unwrap()
        .to_vec();
    let got = net(c.encapsulate(&ipv4(1), &mut [0u8; 2048]));
    assert_eq!(got, expected, "[R3:T8:GOT-EXPECTED]");
    assert_eq!(
        c.handshake.rng.get_word_pos(),
        twin.get_word_pos(),
        "[R3:T8:HANDSHAKE-RNG-GET-WORD-POS-TWIN-GET-WORD-POS]"
    );
}

// T4: an established session refuses a short dst without admitting the
// packet or touching the session; the exact size is then sent once.
#[test]
fn an_established_short_dst_is_refused_without_admission() {
    let cfg = AmneziaConfig::new(0, 0, 0, 16);
    let (mut c, mut s) = pair(cfg.clone(), cfg);
    let mut big = vec![0u8; 2048];
    let mut sbuf = vec![0u8; 2048];
    let init = net(c.format_handshake_initiation(&mut big, false));
    let resp = net(s.decapsulate(None, &init, &mut sbuf));
    let ka = net(c.decapsulate(None, &resp, &mut big));
    let _ = s.decapsulate(None, &ka, &mut sbuf);
    let p = ipv4(4);
    let need = p.len() + 32 + 16;
    let before = snap(&c);
    assert!(before.has_session, "[R3:T4:SESSION-UP]");
    let mut buf = vec![0u8; need - 1];
    let r = c.encapsulate(&p, &mut buf);
    assert!(is_dbts(&r), "[R3:T4:SHORT-DST-REFUSED] {:?}", r);
    assert_eq!(snap(&c), before, "[R3:T4:REFUSAL-LEAVES-STATE]");
    let frame = net(c.encapsulate(&p, &mut vec![0u8; need]));
    assert_eq!(frame.len(), need, "[R3:T4:EXACT-DST-SENDS]");
    assert!(queue(&c).is_empty(), "[R3:T4:NEVER-QUEUED]");
    match s.decapsulate(None, &frame, &mut sbuf) {
        TunnResult::WriteToTunnelV4(pl, _) => assert_eq!(pl, &p[..], "[R3:T4:DELIVERED-ONCE]"),
        other => panic!("[R3:T4:DELIVERED] {:?}", other),
    }
}

// T17: a session that appears between a refused write and its retry carries
// the retry on the established path; nothing was queued by the refusal.
#[test]
fn a_session_appearing_between_refusal_and_retry_takes_the_established_path() {
    let (mut c, mut s) = pair(plain(), plain());
    let mut big = vec![0u8; 2048];
    let mut sbuf = vec![0u8; 2048];
    let p = ipv4(17);
    assert!(
        is_dbts(&c.encapsulate(&p, &mut [0u8; 100])),
        "[R3:T17:NO-SESSION-REFUSED]"
    );
    assert!(queue(&c).is_empty(), "[R3:T17:REFUSED-SRC-NOT-QUEUED]");
    // The peer initiates; the client answers and the peer confirms.
    let init = net(s.format_handshake_initiation(&mut sbuf, false));
    let resp = net(c.decapsulate(None, &init, &mut big));
    let ka = net(s.decapsulate(None, &resp, &mut sbuf));
    let _ = c.decapsulate(None, &ka, &mut big);
    assert!(c.has_current_session(), "[R3:T17:CLIENT-HAS-SESSION]");
    let frame = net(c.encapsulate(&p, &mut vec![0u8; p.len() + 32]));
    assert_eq!(
        frame.len(),
        p.len() + 32,
        "[R3:T17:RETRY-SENT-AS-TRANSPORT]"
    );
    assert!(queue(&c).is_empty(), "[R3:T17:QUEUE-STILL-EMPTY]");
    match s.decapsulate(None, &frame, &mut sbuf) {
        TunnResult::WriteToTunnelV4(pl, _) => assert_eq!(pl, &p[..], "[R3:T17:DELIVERED-ONCE]"),
        other => panic!("[R3:T17:DELIVERED] {:?}", other),
    }
}

// T19: a burst's deferred initiation that does not fit consumes nothing; the
// next adequate call sends it once and clears the burst.
#[test]
fn a_burst_completion_initiation_that_does_not_fit_consumes_nothing() {
    let cfg = AmneziaConfig::new(64, 0, 0, 0).with_pre_handshake_junk(1, 10, 20, 0);
    let (mut c, _s) = pair(cfg.clone(), cfg);
    let p = ipv4(19);
    let junk = net(c.encapsulate(&p, &mut [0u8; 2048]));
    assert!((10..=20).contains(&junk.len()), "[R3:T19:JC-SENT]");
    let before = snap(&c);
    assert!(
        matches!(before.pending, Some((0, 0, Some(_), false))),
        "[R3:T19:INITIATION-DUE]"
    );
    let mut buf = [0u8; HANDSHAKE_INIT_SZ + 63];
    let r = c.update_timers(&mut buf);
    assert!(is_dbts(&r), "[R3:T19:SHORT-COMPLETION-REFUSED] {:?}", r);
    assert_eq!(snap(&c), before, "[R3:T19:REFUSAL-LEAVES-STATE]");
    let init = net(c.update_timers(&mut [0u8; HANDSHAKE_INIT_SZ + 64]));
    assert_eq!(
        init.len(),
        HANDSHAKE_INIT_SZ + 64,
        "[R3:T19:EXACT-COMPLETION-SENT]"
    );
    assert!(c.pending_amnezia_junk.is_none(), "[R3:T19:BURST-CLEARED]");
    assert!(c.handshake.is_in_progress(), "[R3:T19:INIT-SENT]");
    assert_eq!(
        c.timers.handshake_attempts, 0,
        "[R3:T19:FIRST-INITIATION-NOT-A-RETRY]"
    );
    assert_eq!(queue(&c), vec![p], "[R3:T19:QUEUE-OWNED-ONCE]");
}

// T20: without a burst, a destination that never fits still ends the cycle at
// the absolute 90 s bound; refused retransmissions are not counted.
#[cfg(feature = "mock-instant")]
#[test]
fn absolute_expiry_still_ends_a_cycle_whose_dst_stays_short() {
    let (mut c, _s) = pair(plain(), plain());
    let p = ipv4(20);
    let _init = net(c.encapsulate(&p, &mut [0u8; 2048]));
    let started = c.timers[TimerName::TimeLastHandshakeStarted];
    let mut expired = false;
    for _ in 0..40 {
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(5));
        let mut buf = [0u8; 100];
        let r = c.update_timers(&mut buf);
        let now = c.timers[TimerName::TimeCurrent];
        if now - started < super::timers::REKEY_ATTEMPT_TIME {
            assert!(is_dbts(&r), "[R3:T20:RETRANSMISSION-REFUSED] {:?}", r);
            assert_eq!(
                c.timers.handshake_attempts, 0,
                "[R3:T20:REFUSAL-NOT-COUNTED]"
            );
            assert_eq!(
                queue(&c),
                vec![p.clone()],
                "[R3:T20:QUEUE-OWNED-UNTIL-EXPIRY]"
            );
        } else {
            assert!(
                matches!(r, TunnResult::Err(WireGuardError::ConnectionExpired)),
                "[R3:T20:EXPIRES-AT-BOUND] {:?}",
                r
            );
            expired = true;
            break;
        }
    }
    assert!(expired, "[R3:T20:CYCLE-EXPIRED]");
    assert!(queue(&c).is_empty(), "[R3:T20:EXPIRY-DISPOSES-QUEUE]");
    assert!(c.handshake.is_expired(), "[R3:T20:HANDSHAKE-EXPIRED]");
}

// T21: RandomTrailers adds no mandatory capacity: the exact base + S1 frame is
// enough, the trailer shrinks to the room left.
#[test]
fn random_trailers_add_no_mandatory_capacity() {
    let cfg = AmneziaConfig::new(64, 0, 0, 0).with_random_trailers(true);
    let (mut c, _s) = pair(cfg.clone(), cfg);
    let p = ipv4(21);
    assert!(
        is_dbts(&c.encapsulate(&p, &mut [0u8; HANDSHAKE_INIT_SZ + 63])),
        "[R3:T21:BELOW-FLOOR-REFUSED]"
    );
    assert!(queue(&c).is_empty(), "[R3:T21:REFUSED-SRC-NOT-QUEUED]");
    let init = net(c.encapsulate(&p, &mut [0u8; HANDSHAKE_INIT_SZ + 64]));
    assert_eq!(
        init.len(),
        HANDSHAKE_INIT_SZ + 64,
        "[R3:T21:EXACT-FLOOR-SENDS]"
    );
    assert_eq!(queue(&c), vec![p], "[R3:T21:ACCEPTED-ONCE]");
}

// T22: content padding still shrinks to the room left on the established path.
#[test]
fn content_padding_still_shrinks_to_the_room_left() {
    let cfg = AmneziaConfig::new(0, 0, 0, 0).with_content_padding_addition(8, 200, 1420);
    let (mut c, mut s) = pair(cfg.clone(), cfg);
    let mut big = vec![0u8; 2048];
    let mut sbuf = vec![0u8; 2048];
    let init = net(c.format_handshake_initiation(&mut big, false));
    let resp = net(s.decapsulate(None, &init, &mut sbuf));
    let ka = net(c.decapsulate(None, &resp, &mut big));
    let _ = s.decapsulate(None, &ka, &mut sbuf);
    let p = ipv4(22);
    let need = p.len() + 32;
    let tight = net(c.encapsulate(&p, &mut vec![0u8; need]));
    assert_eq!(tight.len(), need, "[R3:T22:EXACT-ROOM-NO-PADDING]");
    let roomy = net(c.encapsulate(&p, &mut vec![0u8; need + 300]));
    assert!(
        roomy.len() >= need && roomy.len() <= need + 200,
        "[R3:T22:PADDING-WITHIN-BOUNDS] {}",
        roomy.len()
    );
    for frame in [tight, roomy] {
        match s.decapsulate(None, &frame, &mut sbuf) {
            TunnResult::WriteToTunnelV4(pl, _) => assert_eq!(pl, &p[..], "[R3:T22:DELIVERED]"),
            other => panic!("[R3:T22:DELIVERED-RESULT] {:?}", other),
        }
    }
}

// T24: the write-ownership contract, result by result: `Err` never changes
// the queue; `Done` / `WriteToNetwork` without a session add exactly one entry;
// an established-session send queues nothing.
#[test]
fn the_write_ownership_contract_holds_for_every_result() {
    let (mut c, _s) = pair(plain(), plain());
    let mut buf = [0u8; 100];
    let r = c.encapsulate(&ipv4(1), &mut buf);
    assert!(is_dbts(&r), "[R3:T24:NO-SESSION-ERR]");
    assert_eq!(
        c.packet_queue.len(),
        0,
        "[R3:T24:NO-SESSION-ERR-NOT-ADMITTED]"
    );
    let mut buf = [0u8; 2048];
    let r = c.encapsulate(&ipv4(2), &mut buf);
    assert!(
        matches!(r, TunnResult::WriteToNetwork(_)),
        "[R3:T24:WRITE-TO-NETWORK]"
    );
    assert_eq!(
        c.packet_queue.len(),
        1,
        "[R3:T24:WRITE-TO-NETWORK-ADMITTED-ONCE]"
    );
    let mut buf = [0u8; 2048];
    let r = c.encapsulate(&ipv4(3), &mut buf);
    assert!(matches!(r, TunnResult::Done), "[R3:T24:DONE]");
    assert_eq!(c.packet_queue.len(), 2, "[R3:T24:DONE-ADMITTED-ONCE]");
    for i in 2..MAX_QUEUE_DEPTH {
        let _ = c.encapsulate(&ipv4(i as u8), &mut [0u8; 2048]);
    }
    assert_eq!(
        c.packet_queue.len(),
        MAX_QUEUE_DEPTH,
        "[R3:T24:QUEUE-FILLED]"
    );
    let mut buf = [0u8; 2048];
    let r = c.encapsulate(&ipv4(0xfd), &mut buf);
    assert!(
        matches!(r, TunnResult::Err(WireGuardError::PacketQueueFull)),
        "[R3:T24:QUEUE-FULL]"
    );
    assert_eq!(
        c.packet_queue.len(),
        MAX_QUEUE_DEPTH,
        "[R3:T24:QUEUE-FULL-NOT-ADMITTED]"
    );
    let (mut e, mut s) = pair(plain(), plain());
    let mut big = vec![0u8; 2048];
    let mut sbuf = vec![0u8; 2048];
    let init = net(e.format_handshake_initiation(&mut big, false));
    let resp = net(s.decapsulate(None, &init, &mut sbuf));
    let _ka = net(e.decapsulate(None, &resp, &mut big));
    let mut buf = [0u8; 50];
    let r = e.encapsulate(&ipv4(4), &mut buf);
    assert!(is_dbts(&r), "[R3:T24:ESTABLISHED-ERR]");
    assert_eq!(
        e.packet_queue.len(),
        0,
        "[R3:T24:ESTABLISHED-ERR-NOT-ADMITTED]"
    );
    let r = e.encapsulate(&ipv4(4), &mut big);
    assert!(
        matches!(r, TunnResult::WriteToNetwork(_)),
        "[R3:T24:ESTABLISHED-SENT]"
    );
    assert_eq!(
        e.packet_queue.len(),
        0,
        "[R3:T24:ESTABLISHED-SENT-DIRECTLY]"
    );
}

// T25 (read half): the C read drain reports a stranded head as an error and
// keeps it; an adequate drain then sends it, once.
#[cfg(feature = "ffi-bindings")]
#[test]
fn the_c_read_drain_reports_a_stranded_head() {
    use crate::ffi::{result_type, tunnel_free, wireguard_read, wireguard_write};
    let (c, mut s) = pair(plain(), plain());
    let t = Box::into_raw(Box::new(parking_lot::Mutex::new(c)));
    let large = {
        let h = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 3], 64).udp(1, 2);
        let mut v = Vec::new();
        h.write(&mut v, &[0x5a; 1400]).unwrap();
        v
    };
    let mut dst = vec![0u8; 2048];
    let mut sbuf = vec![0u8; 2048];
    let empty: [u8; 0] = [];
    unsafe {
        let r = wireguard_write(
            t,
            large.as_ptr(),
            large.len() as u32,
            dst.as_mut_ptr(),
            2048,
        );
        assert!(
            matches!(r.op, result_type::WRITE_TO_NETWORK),
            "[R3:T25R:INITIATION]"
        );
        let init = dst[..r.size].to_vec();
        let resp = net(s.decapsulate(None, &init, &mut sbuf));
        let r = wireguard_read(t, resp.as_ptr(), resp.len() as u32, dst.as_mut_ptr(), 2048);
        assert!(
            matches!(r.op, result_type::WRITE_TO_NETWORK),
            "[R3:T25R:KEEPALIVE]"
        );
        let ka = dst[..r.size].to_vec();
        let _ = s.decapsulate(None, &ka, &mut sbuf);
        let r = wireguard_read(t, empty.as_ptr(), 0, dst.as_mut_ptr(), 1000);
        assert!(
            matches!(r.op, result_type::WIREGUARD_ERROR),
            "[R3:T25R:SHORT-DRAIN-IS-ERROR]"
        );
        assert_eq!(r.size, 0, "[R3:T25R:SHORT-DRAIN-CODE-0]");
        assert_eq!((*t).lock().packet_queue.len(), 1, "[R3:T25R:HEAD-KEPT]");
        let r = wireguard_read(t, empty.as_ptr(), 0, dst.as_mut_ptr(), 2048);
        assert!(
            matches!(r.op, result_type::WRITE_TO_NETWORK),
            "[R3:T25R:ADEQUATE-DRAIN-SENDS]"
        );
        // The plaintext is padded to a multiple of 16 before the 32-byte overhead.
        assert_eq!(
            r.size,
            large.len().div_ceil(16) * 16 + 32,
            "[R3:T25R:TRANSPORT-SIZE]"
        );
        let frame = dst[..r.size].to_vec();
        match s.decapsulate(None, &frame, &mut sbuf) {
            TunnResult::WriteToTunnelV4(pl, _) => {
                assert_eq!(pl, &large[..], "[R3:T25R:DELIVERED]")
            }
            other => panic!("[R3:T25R:DELIVERED-RESULT] {:?}", other),
        }
        let r = wireguard_read(t, empty.as_ptr(), 0, dst.as_mut_ptr(), 2048);
        assert!(
            matches!(r.op, result_type::WIREGUARD_DONE),
            "[R3:T25R:DRAINED]"
        );
        tunnel_free(t);
    }
}
