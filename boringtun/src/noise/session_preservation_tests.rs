// Copyright (c) 2026 Vadim Smirnov (doing business as WireSock). All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! A peer's initiation must neither give send authority to the responder
//! session it creates nor destroy the session selected for sending by being
//! stored into that session's ring slot (WRS-225 LC-REV-01).
//!
//! Sessions live at `local_index % N_SESSIONS`, and the session `encapsulate`
//! and the drain use is the occupant of `current % N_SESSIONS`. A responder
//! session becomes usable only when authenticated transport arrives on it.
//!
//! Every history is driven by real tunnels with synthetic keys. Indices and
//! slots are read back from the datagrams actually exchanged, never assumed:
//! the high bits are random. Success means the peer really decrypts the tagged
//! plaintext -- a session merely recorded as current proves nothing.
//!
//! The six/seven histories are the ones the native lifecycle review
//! reproduced: retained A, one unanswered local index, selected B, then six or
//! seven unanswered local initiations before the peer's initiation, which
//! cancels a partly sent Jc burst. The sweeps run the count over two whole
//! turns of the ring, so every slot the responder can be offered is covered,
//! not one magic index.

use super::amnezia::AmneziaConfig;
use super::{Tunn, TunnResult, HANDSHAKE_INIT_SZ, HANDSHAKE_RESP_SZ, N_SESSIONS};
use crate::x25519;
use rand_core::{OsRng, RngCore};
use std::convert::TryInto;
use std::time::Duration;

/// `me`'s pre-handshake burst: this many Jc datagrams, then the initiation.
const JC: usize = 5;
const JUNK: usize = 100;

/// Mock time when the clock is mocked, else a real sleep: either way later
/// TAI64N stamps and distinct session establishment times.
fn pause() {
    #[cfg(feature = "mock-instant")]
    mock_instant::thread_local::MockClock::advance(Duration::from_millis(5));
    #[cfg(not(feature = "mock-instant"))]
    std::thread::sleep(Duration::from_millis(5));
}

fn tunnel(me: x25519::StaticSecret, peer: x25519::PublicKey, cfg: AmneziaConfig) -> Tunn {
    Tunn::new_with_amnezia(
        me,
        peer,
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
}

/// A UDP/IPv4 packet of `len` bytes carrying `tag`.
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

/// The little-endian index at `offset`: 4 is the sender of an initiation or
/// response, and the receiver of a transport packet.
fn index_at(datagram: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(datagram[offset..offset + 4].try_into().unwrap())
}

fn slot(index: u32) -> usize {
    index as usize % N_SESSIONS
}

fn net(r: TunnResult<'_>, what: &str) -> Vec<u8> {
    match r {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("{}: expected WriteToNetwork, got {:?}", what, other),
    }
}

/// What a receive did: `Ok(None)` for Done, `Ok(Some(tag))` for a decrypted
/// IPv4 packet, `Err(code)` for an error. Anything else is a test failure.
fn received(r: TunnResult<'_>) -> Result<Option<u32>, u32> {
    match r {
        TunnResult::Done => Ok(None),
        TunnResult::WriteToTunnelV4(p, _) => Ok(Some(tag_of(p))),
        TunnResult::Err(e) => Err(e as u32),
        other => panic!("unexpected receive result {:?}", other),
    }
}

/// `me` -- whose ring the histories fill -- with a Jc burst of 100-byte
/// datagrams and no pacing delay; `peer` plain WireGuard. Neither has an S
/// prefix, so they understand each other's handshake and transport.
struct Pair {
    me: Tunn,
    peer: Tunn,
}

impl Pair {
    fn new() -> Pair {
        let me_sk = x25519::StaticSecret::random_from_rng(OsRng);
        let me_pk = x25519::PublicKey::from(&me_sk);
        let peer_sk = x25519::StaticSecret::random_from_rng(OsRng);
        let peer_pk = x25519::PublicKey::from(&peer_sk);
        let burst = AmneziaConfig::new(0, 0, 0, 0).with_pre_handshake_junk(
            JC as u16,
            JUNK as u16,
            JUNK as u16,
            0,
        );
        Pair {
            me: tunnel(me_sk, peer_pk, burst),
            peer: tunnel(peer_sk, me_pk, AmneziaConfig::default()),
        }
    }

    /// The peer initiates and `me` answers: (initiation, response). The
    /// response is not delivered.
    fn peer_initiates(&mut self) -> (Vec<u8>, Vec<u8>) {
        pause();
        let mut d = vec![0u8; 2048];
        let init = net(
            self.peer.format_handshake_initiation(&mut d, true),
            "peer initiation",
        );
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ);
        let resp = net(self.me.decapsulate(None, &init, &mut d), "response");
        assert_eq!(resp.len(), HANDSHAKE_RESP_SZ);
        (init, resp)
    }

    /// Deliver `me`'s response; the peer's confirming keepalive.
    fn peer_accepts(&mut self, resp: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; 2048];
        net(self.peer.decapsulate(None, resp, &mut d), "peer keepalive")
    }

    fn me_reads(&mut self, datagram: &[u8]) -> Result<Option<u32>, u32> {
        let mut d = vec![0u8; 2048];
        received(self.me.decapsulate(None, datagram, &mut d))
    }

    fn peer_reads(&mut self, datagram: &[u8]) -> Result<Option<u32>, u32> {
        let mut d = vec![0u8; 2048];
        received(self.peer.decapsulate(None, datagram, &mut d))
    }

    fn me_sends(&mut self, tag: u32) -> Vec<u8> {
        let mut d = vec![0u8; 2048];
        net(self.me.encapsulate(&ipv4(tag, 60), &mut d), "me transport")
    }

    fn peer_sends(&mut self, tag: u32) -> Vec<u8> {
        let mut d = vec![0u8; 2048];
        net(
            self.peer.encapsulate(&ipv4(tag, 60), &mut d),
            "peer transport",
        )
    }

    /// The rest of a burst through ticks: the remaining Jc datagrams, then
    /// the initiation, which is returned and never delivered.
    fn finish_attempt(&mut self, emitted: usize) -> Vec<u8> {
        let mut d = vec![0u8; 2048];
        for _ in emitted..JC {
            let out = net(self.me.update_timers(&mut d), "burst item");
            assert_eq!(out.len(), JUNK);
        }
        let init = net(self.me.update_timers(&mut d), "local initiation");
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ);
        init
    }

    /// One complete local attempt nobody answers: a forced burst, its Jc
    /// datagrams, its initiation. One local index allocated.
    fn unanswered_attempt(&mut self) -> Vec<u8> {
        let mut d = vec![0u8; 2048];
        let first = net(
            self.me.format_handshake_initiation(&mut d, true),
            "first burst item",
        );
        assert_eq!(first.len(), JUNK);
        self.finish_attempt(1)
    }

    /// A new burst with only its first item sent: the remainder is pending.
    fn partial_burst(&mut self) {
        let mut d = vec![0u8; 2048];
        let first = net(
            self.me.format_handshake_initiation(&mut d, true),
            "first burst item",
        );
        assert_eq!(first.len(), JUNK);
        assert!(self.me.pending_amnezia_junk.is_some());
    }

    /// Who holds `slot` in `me`'s ring, by local index.
    fn occupant(&self, slot: usize) -> Option<u32> {
        self.me.sessions[slot].as_ref().map(|s| s.receiving_index)
    }

    /// The peer's initiation, confirmed by its keepalive: `(my index, the
    /// peer's index)` of the session it selects in `me`.
    fn establish_by_peer(&mut self) -> (u32, u32) {
        let (init, resp) = self.peer_initiates();
        let k = self.peer_accepts(&resp);
        assert_eq!(self.me_reads(&k), Ok(None), "confirming keepalive");
        let mine = index_at(&resp, 4);
        assert_eq!(self.me.current, mine as usize, "confirmation selects");
        (mine, index_at(&init, 4))
    }
}

/// What a retained-session history leaves: `me`'s indices of A, B and the
/// unconfirmed responder R; the peer's indices of B and R; the saved fresh A
/// packet; the withheld response.
struct Retained {
    a: u32,
    b: u32,
    r: u32,
    peer_b: u32,
    peer_r: u32,
    saved_a: Vec<u8>,
    withheld: Vec<u8>,
}

const TAG_A: u32 = 0xA000_0001;

/// Retained A, a hole, selected B, `extra` unanswered local attempts, a
/// partly sent burst, then the peer's initiation -- answered, the answer
/// withheld.
fn retained_history(p: &mut Pair, extra: usize) -> Retained {
    let (a, _) = p.establish_by_peer();
    let saved_a = p.peer_sends(TAG_A);
    p.unanswered_attempt(); // the hole between A and B

    // Distinct establishment times, or an older A would tie with B.
    pause();
    let _ = p.me.update_timers(&mut [0u8; 2048]);

    let (b, peer_b) = p.establish_by_peer();
    assert_ne!(slot(a), slot(b));
    let out = p.me_sends(0xB000_0000);
    assert_eq!(p.peer_reads(&out), Ok(Some(0xB000_0000)));

    for _ in 0..extra {
        p.unanswered_attempt();
    }
    p.partial_burst();
    let (peer_init, withheld) = p.peer_initiates();
    assert!(
        p.me.pending_amnezia_junk.is_none(),
        "the peer's initiation cancels the pending burst whole"
    );
    Retained {
        a,
        b,
        r: index_at(&withheld, 4),
        peer_b,
        peer_r: index_at(&peer_init, 4),
        saved_a,
        withheld,
    }
}

/// The corrected oracle for one retained history: B sends and receives until
/// the replacement is confirmed, also after authenticated A; then the
/// replacement does.
fn retained_b_survives_until_confirmation(extra: usize) {
    let mut p = Pair::new();
    let h = retained_history(&mut p, extra);
    let ctx = format!(
        "{} unanswered allocations: A {:#x}, B {:#x}, responder {:#x}",
        extra, h.a, h.b, h.r
    );

    let out = p.me_sends(1);
    assert_eq!(index_at(&out, 4), h.peer_b, "{}: sent on B", ctx);
    assert_eq!(p.peer_reads(&out), Ok(Some(1)), "{}: B still sends", ctx);
    let back = p.peer_sends(2);
    assert_eq!(p.me_reads(&back), Ok(Some(2)), "{}: B still receives", ctx);

    // A is gone only if the responder took A's slot: ordinary retirement of
    // a session that is not selected.
    let got = p.me_reads(&h.saved_a);
    if slot(h.r) == slot(h.a) {
        assert!(got.is_err(), "{}: A retired by the ring", ctx);
    } else {
        assert_eq!(got, Ok(Some(TAG_A)), "{}: saved A authenticates", ctx);
    }
    assert_eq!(p.me.current, h.b as usize, "{}: A does not displace B", ctx);
    let out = p.me_sends(3);
    assert_eq!(index_at(&out, 4), h.peer_b, "{}: still sent on B", ctx);
    assert_eq!(p.peer_reads(&out), Ok(Some(3)), "{}: B after A", ctx);

    assert_ne!(slot(h.r), slot(h.b), "{}", ctx);
    assert_eq!(p.occupant(slot(h.b)), Some(h.b), "{}: B kept", ctx);
    assert_eq!(
        p.occupant(slot(h.r)),
        Some(h.r),
        "{}: responder stored",
        ctx
    );

    let k = p.peer_accepts(&h.withheld);
    assert_eq!(p.me_reads(&k), Ok(None), "{}: confirmation", ctx);
    assert_eq!(p.me.current, h.r as usize, "{}: confirmation selects", ctx);
    let out = p.me_sends(4);
    assert_eq!(
        index_at(&out, 4),
        h.peer_r,
        "{}: sent on the replacement",
        ctx
    );
    assert_eq!(p.peer_reads(&out), Ok(Some(4)), "{}", ctx);
}

#[test]
fn six_unanswered_allocations_keep_b_selected() {
    retained_b_survives_until_confirmation(6);
}

#[test]
fn seven_unanswered_allocations_keep_b_selected() {
    retained_b_survives_until_confirmation(7);
}

#[test]
fn no_allocation_count_lets_a_responder_replace_b() {
    for extra in 0..=2 * N_SESSIONS {
        retained_b_survives_until_confirmation(extra);
    }
}

const QA: u32 = 0x5100_0001;
const QB: u32 = 0x5100_0002;

/// Two tags queued with no session, `initiations` unanswered local
/// initiations in all, a partly sent burst, then the peer's initiation with
/// its answer withheld. Returns the peer's index and the withheld response.
fn queued_history(p: &mut Pair, initiations: usize, tags: &[(u32, usize)]) -> (u32, Vec<u8>) {
    let mut d = vec![0u8; 2048];
    for &(tag, len) in tags {
        let out = net(p.me.encapsulate(&ipv4(tag, len), &mut d), "queued write");
        assert_eq!(out.len(), JUNK, "the write sends a burst item");
    }
    assert_eq!(p.me.packet_queue.len(), tags.len());
    p.finish_attempt(tags.len());
    for _ in 1..initiations {
        p.unanswered_attempt();
    }
    p.partial_burst();
    let (peer_init, withheld) = p.peer_initiates();
    assert!(p.me.pending_amnezia_junk.is_none());
    (index_at(&peer_init, 4), withheld)
}

/// Drain until Done; every packet must be transport the peer decrypts on the
/// session `peer_index` names. The tags, in emission order.
fn drain_to_peer(p: &mut Pair, peer_index: u32) -> Vec<u32> {
    let mut tags = Vec::new();
    let mut d = vec![0u8; 2048];
    for _ in 0..8 {
        match p.me.decapsulate(None, &[], &mut d) {
            TunnResult::WriteToNetwork(pkt) => {
                let pkt = pkt.to_vec();
                assert_eq!(
                    index_at(&pkt, 4),
                    peer_index,
                    "drained on the confirmed session"
                );
                tags.push(p.peer_reads(&pkt).unwrap().expect("a tagged packet"));
            }
            TunnResult::Done => return tags,
            other => panic!("drain: {:?}", other),
        }
    }
    panic!("the drain did not finish");
}

fn queue_waits_for_confirmation(initiations: usize) {
    let mut p = Pair::new();
    let (peer_r, withheld) = queued_history(&mut p, initiations, &[(QA, 60), (QB, 60)]);
    let r = index_at(&withheld, 4);
    let ctx = format!(
        "{} initiations, responder {:#x} at slot {}",
        initiations,
        r,
        slot(r)
    );
    assert!(!p.me.has_current_session(), "{}: not selected", ctx);

    // An ordinary tick and an explicit drain while the answer is withheld:
    // whatever control they produce, no tag leaves the queue.
    let mut d = vec![0u8; 2048];
    let _ = p.me.update_timers(&mut d);
    let _ = p.me.decapsulate(None, &[], &mut d);
    assert!(!p.me.has_current_session(), "{}", ctx);
    assert_eq!(
        p.me.packet_queue.len(),
        2,
        "{}: both tags still queued",
        ctx
    );

    let k = p.peer_accepts(&withheld);
    assert_eq!(p.me_reads(&k), Ok(None), "{}", ctx);
    assert_eq!(p.me.current, r as usize, "{}", ctx);
    assert_eq!(
        drain_to_peer(&mut p, peer_r),
        vec![QA, QB],
        "{}: once, in order",
        ctx
    );
    assert!(p.me.packet_queue.is_empty(), "{}", ctx);
}

#[test]
fn seven_initiations_keep_the_queue_until_confirmation() {
    queue_waits_for_confirmation(7);
}

#[test]
fn no_initiation_count_lets_the_queue_leave_before_confirmation() {
    for initiations in 1..=2 * N_SESSIONS + 1 {
        queue_waits_for_confirmation(initiations);
    }
}

/// An incoming initiation alone selects nothing on a fresh tunnel; the
/// peer's confirming transport does.
#[test]
fn an_incoming_initiation_alone_selects_nothing() {
    let mut p = Pair::new();
    let (init, resp) = p.peer_initiates();
    assert!(!p.me.has_current_session());
    let mut d = vec![0u8; 2048];
    let out = net(p.me.encapsulate(&ipv4(7, 60), &mut d), "write");
    assert_eq!(
        out.len(),
        JUNK,
        "a write drives the handshake, it is not transport"
    );
    assert_eq!(p.me.packet_queue.len(), 1);
    let k = p.peer_accepts(&resp);
    assert_eq!(p.me_reads(&k), Ok(None));
    assert_eq!(p.me.current, index_at(&resp, 4) as usize);
    assert_eq!(drain_to_peer(&mut p, index_at(&init, 4)), vec![7]);
}

/// The other role: an initiator that accepts the genuine response sends its
/// confirming keepalive on the session it just derived, and uses it.
#[test]
fn an_initiator_confirms_on_the_session_it_derived() {
    let mut p = Pair::new();
    let init = p.unanswered_attempt();
    let mut d = vec![0u8; 2048];
    let resp = net(p.peer.decapsulate(None, &init, &mut d), "peer response");
    let keepalive = net(p.me.decapsulate(None, &resp, &mut d), "keepalive");
    assert!(p.me.has_current_session());
    assert_eq!(p.me.current, index_at(&init, 4) as usize);
    assert_eq!(index_at(&keepalive, 4), index_at(&resp, 4));
    assert_eq!(p.peer_reads(&keepalive), Ok(None));
    let out = p.me_sends(8);
    assert_eq!(p.peer_reads(&out), Ok(Some(8)));
    let back = p.peer_sends(9);
    assert_eq!(p.me_reads(&back), Ok(Some(9)));
}

/// Responder after responder around a selected session: the ring wraps, the
/// selected session is never the one reused, each responder survives until a
/// later one takes its slot, and only genuine transport confirms one -- here
/// the second newest, after forged, re-addressed and replayed attempts.
#[test]
fn unconfirmed_responders_wrap_the_ring_around_the_selected_session() {
    let mut p = Pair::new();
    let (b, peer_b) = p.establish_by_peer();
    let b_packet = p.peer_sends(0x0B);
    assert_eq!(p.me_reads(&b_packet), Ok(Some(0x0B)));

    let mut responders = Vec::new();
    for i in 0..N_SESSIONS as u32 {
        let (init, resp) = p.peer_initiates();
        let r = index_at(&resp, 4);
        assert_ne!(slot(r), slot(b), "responder {} took the selected slot", i);
        assert_eq!(p.me.current, b as usize);
        let out = p.me_sends(0x100 + i);
        assert_eq!(index_at(&out, 4), peer_b);
        assert_eq!(p.peer_reads(&out), Ok(Some(0x100 + i)));
        let back = p.peer_sends(0x200 + i);
        assert_eq!(p.me_reads(&back), Ok(Some(0x200 + i)));
        responders.push((index_at(&init, 4), r, resp));

        // The ring holds B once, and every responder no later one displaced.
        assert_eq!(p.occupant(slot(b)), Some(b));
        for (j, (_, rj, _)) in responders.iter().enumerate() {
            let displaced = responders[j + 1..]
                .iter()
                .any(|(_, rk, _)| slot(*rk) == slot(*rj));
            assert_eq!(p.occupant(slot(*rj)) == Some(*rj), !displaced);
        }
        let held = p.me.sessions.iter().flatten().count();
        assert!(held <= N_SESSIONS);
        assert_eq!(
            p.me.sessions
                .iter()
                .flatten()
                .filter(|s| s.receiving_index == b)
                .count(),
            1
        );
    }
    // Eight responders around one selected slot: some slot was reused.
    let distinct: std::collections::HashSet<_> =
        responders.iter().map(|(_, r, _)| slot(*r)).collect();
    assert!(distinct.len() < responders.len());

    // The peer keeps its last two initiations; answer the older of them.
    let (peer_r7, r7, resp7) = responders[N_SESSIONS - 2].clone();
    let (_, r8, _) = responders[N_SESSIONS - 1].clone();
    assert_ne!(slot(r7), slot(r8));
    let k7 = p.peer_accepts(&resp7);

    let mut tampered = k7.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(p.me_reads(&tampered).is_err(), "forged confirmation");
    for wrong in [r8, b] {
        let mut readdressed = k7.clone();
        readdressed[4..8].copy_from_slice(&wrong.to_le_bytes());
        assert!(
            p.me_reads(&readdressed).is_err(),
            "re-addressed to {:#x}",
            wrong
        );
    }
    assert!(p.me_reads(&b_packet).is_err(), "replayed B transport");
    assert_eq!(p.me.current, b as usize, "nothing above confirms");

    assert_eq!(
        p.me_reads(&k7),
        Ok(None),
        "the delayed genuine confirmation"
    );
    assert_eq!(p.me.current, r7 as usize);
    assert!(p.me_reads(&k7).is_err(), "its replay");
    assert_eq!(p.me.current, r7 as usize);
    let out = p.me_sends(0x300);
    assert_eq!(index_at(&out, 4), peer_r7);
    assert_eq!(p.peer_reads(&out), Ok(Some(0x300)));
}

/// A key change or `clear_all` with B selected and a responder unconfirmed
/// leaves neither behind: no transport on either is accepted afterwards and
/// nothing is selected.
#[test]
fn key_changes_and_clear_all_keep_no_session() {
    for change in 0..3 {
        let mut p = Pair::new();
        p.establish_by_peer();
        let (_, withheld) = p.peer_initiates();
        let b_packet = p.peer_sends(0x0C);
        match change {
            0 => p.me.set_preshared_key(Some([7u8; 32])),
            1 => {
                let sk = x25519::StaticSecret::random_from_rng(OsRng);
                let pk = x25519::PublicKey::from(&sk);
                p.me.set_static_private(sk, pk, None);
            }
            _ => p.me.clear_all(),
        }
        assert!(
            p.me.sessions.iter().all(Option::is_none),
            "change {}",
            change
        );
        assert!(!p.me.has_current_session(), "change {}", change);
        assert!(p.me_reads(&b_packet).is_err(), "change {}: B", change);
        let k = p.peer_accepts(&withheld);
        assert!(p.me_reads(&k).is_err(), "change {}: responder", change);
        assert!(!p.me.has_current_session(), "change {}", change);
        let mut d = vec![0u8; 2048];
        let out = net(p.me.encapsulate(&ipv4(0x0D, 60), &mut d), "write");
        assert_eq!(out.len(), JUNK, "change {}: queued, not transport", change);
    }
}

/// Ageing out the selected session leaves an unconfirmed responder
/// unselected: writes queue, and its own confirmation then delivers them. A
/// responder that is never confirmed ages out on its own.
#[cfg(feature = "mock-instant")]
#[test]
fn ageing_never_promotes_an_unconfirmed_responder() {
    use mock_instant::thread_local::MockClock;
    for confirm in [true, false] {
        let mut p = Pair::new();
        let mut d = vec![0u8; 2048];
        let _ = p.me.update_timers(&mut d);
        let (b, _) = p.establish_by_peer();
        MockClock::advance(Duration::from_secs(100));
        let _ = p.me.update_timers(&mut d);
        let (peer_init, withheld) = p.peer_initiates();
        let r = index_at(&withheld, 4);
        assert_eq!(p.me.current, b as usize);

        MockClock::advance(Duration::from_secs(81));
        let _ = p.me.update_timers(&mut d);
        assert_eq!(p.occupant(slot(b)), None, "B aged out");
        assert_eq!(p.occupant(slot(r)), Some(r), "the responder did not");
        assert!(!p.me.has_current_session());
        let out = net(p.me.encapsulate(&ipv4(0x0E, 60), &mut d), "write");
        assert_eq!(out.len(), JUNK, "queued, not transport");
        assert_eq!(p.me.packet_queue.len(), 1);

        if confirm {
            let k = p.peer_accepts(&withheld);
            assert_eq!(p.me_reads(&k), Ok(None));
            assert_eq!(p.me.current, r as usize);
            assert_eq!(drain_to_peer(&mut p, index_at(&peer_init, 4)), vec![0x0E]);
        } else {
            MockClock::advance(Duration::from_secs(100));
            let _ = p.me.update_timers(&mut d);
            assert_eq!(p.occupant(slot(r)), None, "the responder aged out");
            let k = p.peer_accepts(&withheld);
            assert!(
                p.me_reads(&k).is_err(),
                "an aged-out key is not resurrected"
            );
            assert!(!p.me.has_current_session());
        }
    }
}

/// The same histories through the C entry points: the selected session's
/// serial and the `_ex` facts describe the corrected state, in every calling
/// convention.
#[cfg(feature = "ffi-bindings")]
mod ex {
    use super::*;
    use crate::ffi::{
        wireguard_force_handshake, wireguard_force_handshake_ex, wireguard_packet_info,
        wireguard_read, wireguard_read_ex, wireguard_result, wireguard_tick, wireguard_tick_ex,
        wireguard_write, wireguard_write_ex, WIREGUARD_PACKET_INFO_SIZE_V1,
    };
    use crate::noise::op_report::{event as ev, state as st, PacketKind};
    use parking_lot::Mutex;
    use std::ptr;

    const DONE: u32 = 0;
    const WTN: u32 = 1;
    const ERR: u32 = 2;
    const WTT4: u32 = 4;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Api {
        Legacy,
        Null,
        Info,
    }

    const APIS: [Api; 3] = [Api::Legacy, Api::Null, Api::Info];

    #[derive(Clone, Copy)]
    enum Op<'a> {
        Write(&'a [u8]),
        Read(&'a [u8]),
        Tick,
        Force,
    }

    /// `me` behind the lock the C API takes; the peer stays a plain `Tunn`.
    struct Ffi {
        me: Mutex<Tunn>,
        peer: Tunn,
    }

    /// One call: `(op, size)`, the bytes it wrote, and the metadata when
    /// `api` asked for it. `bt` is the finite transport budget, 0 none.
    fn call(
        api: Api,
        f: &Ffi,
        op: Op,
        dst_len: usize,
        bt: u32,
    ) -> (u32, usize, Vec<u8>, Option<wireguard_packet_info>) {
        let mut dst = vec![0u8; dst_len];
        let mut info = wireguard_packet_info {
            size: WIREGUARD_PACKET_INFO_SIZE_V1,
            max_transport_output: bt,
            ..Default::default()
        };
        assert!(bt == 0 || api == Api::Info, "a budget needs metadata");
        let p: *mut wireguard_packet_info = match api {
            Api::Info => &mut info,
            _ => ptr::null_mut(),
        };
        let (t, d, dl) = (
            &f.me as *const Mutex<Tunn>,
            dst.as_mut_ptr(),
            dst.len() as u32,
        );
        let r: wireguard_result = unsafe {
            match (api, op) {
                (Api::Legacy, Op::Write(s)) => {
                    wireguard_write(t, s.as_ptr(), s.len() as u32, d, dl)
                }
                (Api::Legacy, Op::Read(s)) => wireguard_read(t, s.as_ptr(), s.len() as u32, d, dl),
                (Api::Legacy, Op::Tick) => wireguard_tick(t, d, dl),
                (Api::Legacy, Op::Force) => wireguard_force_handshake(t, d, dl),
                (_, Op::Write(s)) => wireguard_write_ex(t, s.as_ptr(), s.len() as u32, d, dl, p),
                (_, Op::Read(s)) => wireguard_read_ex(t, s.as_ptr(), s.len() as u32, d, dl, p),
                (_, Op::Tick) => wireguard_tick_ex(t, d, dl, p),
                (_, Op::Force) => wireguard_force_handshake_ex(t, d, dl, p),
            }
        };
        let (op, size) = (r.op as u32, r.size);
        let out = if op == WTN || op == WTT4 {
            dst[..size].to_vec()
        } else {
            Vec::new()
        };
        if api == Api::Info {
            assert_eq!(info.written_size, 48);
        }
        (op, size, out, (api == Api::Info).then_some(info))
    }

    fn k(kind: PacketKind) -> u32 {
        kind as u32
    }

    impl Ffi {
        fn new() -> Ffi {
            let p = Pair::new();
            Ffi {
                me: Mutex::new(p.me),
                peer: p.peer,
            }
        }

        fn selected_serial(&self) -> u64 {
            self.me.lock().selected_serial()
        }

        fn serial_of(&self, index: u32) -> u64 {
            self.me.lock().serial_of_slot(slot(index))
        }

        fn current(&self) -> usize {
            self.me.lock().current
        }

        fn peer_initiates(&mut self) -> Vec<u8> {
            pause();
            let mut d = vec![0u8; 2048];
            net(
                self.peer.format_handshake_initiation(&mut d, true),
                "peer initiation",
            )
        }

        fn peer_reads(&mut self, datagram: &[u8]) -> Result<Option<u32>, u32> {
            let mut d = vec![0u8; 2048];
            received(self.peer.decapsulate(None, datagram, &mut d))
        }

        fn peer_accepts(&mut self, resp: &[u8]) -> Vec<u8> {
            let mut d = vec![0u8; 2048];
            net(self.peer.decapsulate(None, resp, &mut d), "peer keepalive")
        }

        fn peer_sends(&mut self, tag: u32) -> Vec<u8> {
            let mut d = vec![0u8; 2048];
            net(
                self.peer.encapsulate(&ipv4(tag, 60), &mut d),
                "peer transport",
            )
        }

        /// A complete unanswered attempt through `api`: Force, then Ticks.
        fn unanswered_attempt(&self, api: Api) {
            let (op, size, _, _) = call(api, self, Op::Force, 2048, 0);
            assert_eq!((op, size), (WTN, JUNK));
            for item in 2..=JC + 1 {
                let (op, size, _, _) = call(api, self, Op::Tick, 2048, 0);
                let want = if item == JC + 1 {
                    HANDSHAKE_INIT_SZ
                } else {
                    JUNK
                };
                assert_eq!((op, size), (WTN, want));
            }
        }

        /// The peer's initiation confirmed: `(my index, peer's index)`.
        fn establish_by_peer(&mut self, api: Api) -> (u32, u32) {
            let init = self.peer_initiates();
            let (op, _, resp, _) = call(api, self, Op::Read(&init), 2048, 0);
            assert_eq!(op, WTN);
            let k = self.peer_accepts(&resp);
            let (op, _, _, _) = call(api, self, Op::Read(&k), 2048, 0);
            assert_eq!(op, DONE);
            (index_at(&resp, 4), index_at(&init, 4))
        }
    }

    /// The retained history through `api`, with its facts: the responder
    /// store keeps B's serial selected and reports no change of it, B keeps
    /// sending after authenticated A, and the confirmation selects exactly the
    /// serial the store issued.
    fn retained_through(api: Api, extra: usize) {
        let ctx = format!("{:?}, {} unanswered allocations", api, extra);
        let mut f = Ffi::new();
        let (a, _) = f.establish_by_peer(api);
        let saved_a = f.peer_sends(TAG_A);
        f.unanswered_attempt(api);
        pause();
        call(api, &f, Op::Tick, 2048, 0);
        let (b, peer_b) = f.establish_by_peer(api);
        let serial_b = f.selected_serial();
        assert_eq!(serial_b, f.serial_of(b), "{}", ctx);
        for _ in 0..extra {
            f.unanswered_attempt(api);
        }
        let (op, size, _, i) = call(api, &f, Op::Force, 2048, 0);
        assert_eq!((op, size), (WTN, JUNK), "{}", ctx);
        if let Some(i) = i {
            assert_ne!(i.state & st::BURST_PENDING, 0, "{}", ctx);
        }

        let peer_init = f.peer_initiates();
        let (op, _, withheld, i) = call(api, &f, Op::Read(&peer_init), 2048, 0);
        assert_eq!(op, WTN, "{}", ctx);
        let r = index_at(&withheld, 4);
        if let Some(i) = i {
            assert_eq!(
                (i.input_kind, i.output_kind, i.events),
                (
                    k(PacketKind::HandshakeInitiation),
                    k(PacketKind::HandshakeResponse),
                    ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED | ev::SESSION_STORED
                ),
                "{}: stored, and the selection did not change",
                ctx
            );
            assert_ne!(i.state & st::SESSION_CURRENT, 0, "{}: B is current", ctx);
            assert_eq!(i.state & st::BURST_PENDING, 0, "{}: burst canceled", ctx);
        }
        assert_eq!(f.selected_serial(), serial_b, "{}", ctx);
        let serial_r = f.serial_of(r);
        assert!(
            serial_r > serial_b,
            "{}: the store issued a new serial",
            ctx
        );

        let (op, _, out, i) = call(api, &f, Op::Write(&ipv4(21, 60)), 2048, 0);
        assert_eq!(op, WTN, "{}", ctx);
        assert_eq!(index_at(&out, 4), peer_b, "{}", ctx);
        assert_eq!(f.peer_reads(&out), Ok(Some(21)), "{}: B sends", ctx);
        if let Some(i) = i {
            assert_eq!(
                (i.output_kind, i.events),
                (k(PacketKind::TransportData), 0),
                "{}",
                ctx
            );
        }

        // Authenticated on A -- unless the responder took A's slot, the
        // ordinary retirement of an unselected session.
        let (op, _, plain, i) = call(api, &f, Op::Read(&saved_a), 2048, 0);
        if slot(r) == slot(a) {
            assert_eq!(op, ERR, "{}: A retired by the ring", ctx);
        } else {
            assert_eq!(op, WTT4, "{}", ctx);
            assert_eq!(tag_of(&plain), TAG_A, "{}", ctx);
            if let Some(i) = i {
                assert_eq!(
                    i.events,
                    ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED,
                    "{}: authenticated A selects nothing",
                    ctx
                );
            }
        }
        assert_eq!(f.selected_serial(), serial_b, "{}", ctx);
        let (op, _, out, _) = call(api, &f, Op::Write(&ipv4(22, 60)), 2048, 0);
        assert_eq!(op, WTN, "{}", ctx);
        assert_eq!(f.peer_reads(&out), Ok(Some(22)), "{}: B after A", ctx);

        let k_r = f.peer_accepts(&withheld);
        let (op, _, _, i) = call(api, &f, Op::Read(&k_r), 2048, 0);
        assert_eq!(op, DONE, "{}", ctx);
        if let Some(i) = i {
            assert_eq!(
                i.events,
                ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED | ev::CURRENT_SESSION_CHANGED,
                "{}: the confirmation is the change",
                ctx
            );
            assert_ne!(i.state & st::SESSION_CURRENT, 0, "{}", ctx);
        }
        assert_eq!(
            f.selected_serial(),
            serial_r,
            "{}: the stored serial is selected",
            ctx
        );
        assert_eq!(f.current(), r as usize, "{}", ctx);
        let (op, _, out, _) = call(api, &f, Op::Write(&ipv4(23, 60)), 2048, 0);
        assert_eq!(op, WTN, "{}", ctx);
        assert_eq!(index_at(&out, 4), index_at(&peer_init, 4), "{}", ctx);
        assert_eq!(f.peer_reads(&out), Ok(Some(23)), "{}", ctx);
    }

    #[test]
    fn the_retained_histories_in_every_calling_convention() {
        for api in APIS {
            for extra in [6, 7] {
                retained_through(api, extra);
            }
        }
    }

    #[test]
    fn the_retained_facts_hold_at_every_allocation_count() {
        for extra in 0..=2 * N_SESSIONS {
            retained_through(Api::Info, extra);
        }
    }

    /// The no-session queue through `api`: while the answer is withheld the
    /// state has no current session and keeps the queue, ticks and drains emit
    /// no transport; the confirmation reports the change, and the drain then
    /// sends both tags, once, in order.
    fn queue_through(api: Api, initiations: usize) {
        let ctx = format!("{:?}, {} initiations", api, initiations);
        let mut f = Ffi::new();
        for tag in [QA, QB] {
            let (op, size, _, i) = call(api, &f, Op::Write(&ipv4(tag, 60)), 2048, 0);
            assert_eq!((op, size), (WTN, JUNK), "{}", ctx);
            if let Some(i) = i {
                assert_ne!(i.events & ev::QUEUE_ADMITTED, 0, "{}", ctx);
            }
        }
        for item in 3..=JC + 1 {
            let (op, size, _, _) = call(api, &f, Op::Tick, 2048, 0);
            let want = if item == JC + 1 {
                HANDSHAKE_INIT_SZ
            } else {
                JUNK
            };
            assert_eq!((op, size), (WTN, want), "{}", ctx);
        }
        for _ in 1..initiations {
            f.unanswered_attempt(api);
        }
        call(api, &f, Op::Force, 2048, 0);

        let peer_init = f.peer_initiates();
        let (op, _, withheld, i) = call(api, &f, Op::Read(&peer_init), 2048, 0);
        assert_eq!(op, WTN, "{}", ctx);
        if let Some(i) = i {
            assert_eq!(
                i.events,
                ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED | ev::SESSION_STORED,
                "{}",
                ctx
            );
            assert_eq!(
                i.state & (st::SESSION_CURRENT | st::QUEUE_NONEMPTY),
                st::QUEUE_NONEMPTY,
                "{}",
                ctx
            );
        }
        assert_eq!(f.selected_serial(), 0, "{}: nothing selected", ctx);

        for op in [Op::Tick, Op::Read(&[])] {
            let (_, _, _, i) = call(api, &f, op, 2048, 0);
            if let Some(i) = i {
                assert_ne!(i.output_kind, k(PacketKind::TransportData), "{}", ctx);
                assert_ne!(i.output_kind, k(PacketKind::TransportKeepalive), "{}", ctx);
                assert_eq!(
                    i.state & (st::SESSION_CURRENT | st::QUEUE_NONEMPTY),
                    st::QUEUE_NONEMPTY,
                    "{}",
                    ctx
                );
            }
        }
        assert_eq!(f.me.lock().packet_queue.len(), 2, "{}", ctx);

        let k_r = f.peer_accepts(&withheld);
        let (op, _, _, i) = call(api, &f, Op::Read(&k_r), 2048, 0);
        assert_eq!(op, DONE, "{}", ctx);
        if let Some(i) = i {
            assert_eq!(
                i.events,
                ev::INPUT_ACCEPTED | ev::PEER_AUTHENTICATED | ev::CURRENT_SESSION_CHANGED,
                "{}",
                ctx
            );
            assert_eq!(
                i.state & (st::SESSION_CURRENT | st::QUEUE_NONEMPTY),
                st::SESSION_CURRENT | st::QUEUE_NONEMPTY,
                "{}",
                ctx
            );
        }
        let mut tags = Vec::new();
        for _ in 0..2 {
            let (op, _, out, i) = call(api, &f, Op::Read(&[]), 2048, 0);
            assert_eq!(op, WTN, "{}", ctx);
            if let Some(i) = i {
                assert_eq!(i.output_kind, k(PacketKind::TransportData), "{}", ctx);
            }
            assert_eq!(index_at(&out, 4), index_at(&peer_init, 4), "{}", ctx);
            tags.push(f.peer_reads(&out).unwrap().unwrap());
        }
        assert_eq!(tags, vec![QA, QB], "{}", ctx);
        let (op, _, _, i) = call(api, &f, Op::Read(&[]), 2048, 0);
        assert_eq!(op, DONE, "{}: nothing is sent twice", ctx);
        if let Some(i) = i {
            assert_eq!(i.state & st::QUEUE_NONEMPTY, 0, "{}", ctx);
        }
    }

    #[test]
    fn the_queued_history_in_every_calling_convention() {
        for api in APIS {
            for initiations in [6, 7] {
                queue_through(api, initiations);
            }
        }
    }

    #[test]
    fn the_queued_facts_hold_at_every_initiation_count() {
        for initiations in 1..=2 * N_SESSIONS + 1 {
            queue_through(Api::Info, initiations);
        }
    }

    /// Budgets keep their meaning on the preserved and the confirmed session:
    /// a refused write on B admits nothing and the retry is sent on B; after
    /// confirmation a storage-short drain keeps the head, a finite transport
    /// budget deletes only the head that cannot fit, and the rest leave once.
    #[test]
    fn budgets_on_the_preserved_and_the_confirmed_session() {
        // Retained B: refusal, then retry, both on B.
        let mut f = Ffi::new();
        f.establish_by_peer(Api::Info);
        f.unanswered_attempt(Api::Info);
        pause();
        call(Api::Info, &f, Op::Tick, 2048, 0);
        let (_, peer_b) = f.establish_by_peer(Api::Info);
        for _ in 0..7 {
            f.unanswered_attempt(Api::Info);
        }
        call(Api::Info, &f, Op::Force, 2048, 0);
        let peer_init = f.peer_initiates();
        let (op, _, _, _) = call(Api::Info, &f, Op::Read(&peer_init), 2048, 0);
        assert_eq!(op, WTN);
        let packet = ipv4(31, 60);
        let (op, size, _, i) = call(Api::Info, &f, Op::Write(&packet), 2048, 64);
        assert_eq!((op, size), (ERR, 18), "over the transport budget");
        assert_eq!(i.unwrap().events & ev::QUEUE_ADMITTED, 0);
        assert_eq!(f.me.lock().packet_queue.len(), 0);
        let (op, _, out, i) = call(Api::Info, &f, Op::Write(&packet), 2048, 2048);
        assert_eq!(op, WTN);
        assert_eq!(i.unwrap().output_kind, k(PacketKind::TransportData));
        assert_eq!(index_at(&out, 4), peer_b);
        assert_eq!(f.peer_reads(&out), Ok(Some(31)), "the retry, once, on B");

        // No session: three tags queued, the seven-initiation history.
        let mut f = Ffi::new();
        for (tag, len) in [(41, 1000), (42, 60), (43, 60)] {
            let (op, _, _, _) = call(Api::Info, &f, Op::Write(&ipv4(tag, len)), 2048, 0);
            assert_eq!(op, WTN);
        }
        for _ in 4..=JC + 1 {
            call(Api::Info, &f, Op::Tick, 2048, 0);
        }
        for _ in 1..7 {
            f.unanswered_attempt(Api::Info);
        }
        call(Api::Info, &f, Op::Force, 2048, 0);
        let peer_init = f.peer_initiates();
        let (op, _, withheld, _) = call(Api::Info, &f, Op::Read(&peer_init), 2048, 0);
        assert_eq!(op, WTN);
        assert_eq!(
            f.me.lock().packet_queue.len(),
            3,
            "nothing left before confirmation"
        );
        let k_r = f.peer_accepts(&withheld);
        let (op, _, _, _) = call(Api::Info, &f, Op::Read(&k_r), 2048, 0);
        assert_eq!(op, DONE);

        let (op, size, _, i) = call(Api::Info, &f, Op::Read(&[]), 200, 0);
        assert_eq!((op, size), (ERR, 0), "storage-short: retained");
        assert_eq!(i.unwrap().events & ev::QUEUE_HEAD_DROPPED, 0);
        assert_eq!(f.me.lock().packet_queue.len(), 3);
        let (op, _, out, i) = call(Api::Info, &f, Op::Read(&[]), 2048, 500);
        assert_eq!(op, WTN);
        assert_ne!(
            i.unwrap().events & ev::QUEUE_HEAD_DROPPED,
            0,
            "only the oversized head"
        );
        let mut tags = vec![f.peer_reads(&out).unwrap().unwrap()];
        let (op, _, out, _) = call(Api::Info, &f, Op::Read(&[]), 2048, 500);
        assert_eq!(op, WTN);
        tags.push(f.peer_reads(&out).unwrap().unwrap());
        let (op, _, _, _) = call(Api::Info, &f, Op::Read(&[]), 2048, 500);
        assert_eq!(op, DONE);
        assert_eq!(tags, vec![42, 43]);
    }
}
