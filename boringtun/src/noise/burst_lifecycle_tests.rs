//! Lifecycle of a pending pre-handshake burst against the timers: the
//! absolute bounds come before every burst except one that restarts an Expired
//! cycle and has committed nothing; the deferred Expired-cycle reset is spent
//! once, at the first datagram that leaves; refusals never move a cycle timer.
//! Every test drives the mock clock. Assertions carry `[R3:...]` tags (see
//! `write_admission_tests`).
#![cfg(feature = "mock-instant")]

use super::amnezia::{AmneziaConfig, AmneziaImitationProtocol, AwgTimers};
use super::timers::TimerName::*;
use super::timers::REKEY_ATTEMPT_TIME;
use super::*;
use mock_instant::thread_local::{Instant, MockClock};
use rand_core::{OsRng, RngCore};
use std::time::Duration;

const S1: u16 = 64;
const FLOOR: usize = HANDSHAKE_INIT_SZ + S1 as usize;
const JC: usize = 100;
/// `keychain_expire() * 3` for an untuned tunnel.
const ZERO_KEY: Duration = Duration::from_secs(540);

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn adv(d: Duration) {
    MockClock::advance(d);
}

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

/// S1 = 64 and `jc` Jc datagrams of exactly 100 bytes, no pacing delay.
fn jc_cfg(jc: u16) -> AmneziaConfig {
    AmneziaConfig::new(S1 as _, 0, 0, 0).with_pre_handshake_junk(jc, JC as u16, JC as u16, 0)
}

/// Tuned: the untuned 90-second bound is off, retransmissions are budgeted
/// generously, and `keychain_expire() * 3` is 120 s.
fn tuned(cfg: AmneziaConfig) -> AmneziaConfig {
    cfg.with_tunable_timers(AwgTimers {
        rekey_after_time: (0, 0),
        rekey_timeout: (5, 5),
        reject_after_time: (40, 40),
        keepalive_timeout: (0, 0),
        max_handshake_attempts: (50, 50),
    })
}

fn ipv4(seq: u8) -> Vec<u8> {
    let header = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 3], 64)
        .udp(4000 + seq as u16, 53);
    let mut p = Vec::new();
    header.write(&mut p, &[seq; 40]).unwrap();
    p
}

fn net(r: TunnResult<'_>) -> Vec<u8> {
    match r {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!(
            "[R3:L-NET:EXPECTED-WRITETONETWORK-GOT] expected WriteToNetwork, got {:?}",
            other
        ),
    }
}

/// `net` with the caller's assertion tag, for checks whose point IS that this
/// output is sent: the panic names the invariant, not the helper.
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

fn is_expired_result(r: &TunnResult<'_>) -> bool {
    matches!(r, TunnResult::Err(WireGuardError::ConnectionExpired))
}

/// Everything a refusal must leave alone (the clock excepted).
#[derive(Debug, PartialEq, Clone)]
struct Snap {
    queue: Vec<Vec<u8>>,
    expired: bool,
    in_progress: bool,
    sent_at: Option<Instant>,
    established: Duration,
    started: Duration,
    last_sent: Duration,
    attempts: u32,
    want_handshake: bool,
    /// (imitation datagrams left, Jc left, last emission, owes the reset)
    pending: Option<(usize, u16, Option<Instant>, bool)>,
    rng: u128,
}

fn snap(t: &Tunn) -> Snap {
    Snap {
        queue: t.packet_queue.iter().cloned().collect(),
        expired: t.handshake.is_expired(),
        in_progress: t.handshake.is_in_progress(),
        sent_at: t.handshake.timer(),
        established: t.timers[TimeSessionEstablished],
        started: t.timers[TimeLastHandshakeStarted],
        last_sent: t.timers[TimeLastPacketSent],
        attempts: t.timers.handshake_attempts,
        want_handshake: t.timers.want_handshake,
        pending: t.pending_amnezia_junk.as_ref().map(|p| {
            (
                p.imitation_datagrams.len(),
                p.remaining,
                p.last_packet_at,
                p.reset_expired_timers,
            )
        }),
        rng: t.handshake.rng.get_word_pos(),
    }
}

fn now(t: &Tunn) -> Duration {
    t.timers[TimeCurrent]
}

/// Expire a fresh tunnel the way the device does: by ticking past
/// `keychain_expire() * 3` with no session. Returns the expiry instant.
fn expire_fresh(t: &mut Tunn) -> Duration {
    adv(ZERO_KEY + secs(1));
    assert!(
        is_expired_result(&t.update_timers(&mut [0u8; 2048])),
        "[R3:L-EXPIRE-FRESH:IS-EXPIRED-RESULT-UPDATE-TIMERS]"
    );
    assert!(
        t.handshake.is_expired(),
        "[R3:L-EXPIRE-FRESH:HANDSHAKE-IS-EXPIRED]"
    );
    assert!(
        t.pending_amnezia_junk.is_none() && t.packet_queue.is_empty(),
        "[R3:L-EXPIRE-FRESH:PENDING-AMNEZIA-JUNK-IS-NONE-PACKET-QUEUE-IS-EMPTY]"
    );
    t.timers[TimeSessionEstablished]
}

/// An Expired tunnel, long enough after its expiry that the stale timers
/// would trip `keychain_expire() * 3`, with a burst a refused write built:
/// nothing committed, the reset still owed. Returns the expiry instant.
fn expired_with_owed_burst(t: &mut Tunn) -> Duration {
    let t_exp = expire_fresh(t);
    adv(ZERO_KEY + secs(1));
    assert!(
        is_dbts(&t.encapsulate(&ipv4(0xee), &mut [0u8; 50])),
        "[R3:L-EXPIRED-WITH-OWED-BURST:IS-DBTS-ENCAPSULATE-IPV4-XEE]"
    );
    let s = snap(t);
    assert_eq!(
        s.pending.map(|p| (p.0, p.2, p.3)),
        Some((0, None, true)),
        "[R3:L-OWED-BURST:REFUSAL-LEAVES-RESET-OWED]"
    );
    assert!(
        s.queue.is_empty(),
        "[R3:L-OWED-BURST:REFUSED-SRC-NOT-ADMITTED]"
    );
    assert!(s.expired, "[R3:L-OWED-BURST:STILL-EXPIRED]");
    assert_eq!(
        s.established, t_exp,
        "[R3:L-OWED-BURST:NO-RESET-ON-REFUSAL]"
    );
    t_exp
}

/// Run ticks one second apart with `dst_len`, expecting capacity refusals
/// that leave `before` intact until `bound` past `reference`, then exactly
/// one `ConnectionExpired` that empties queue and burst. Returns its time.
fn refuse_until_expired(
    t: &mut Tunn,
    dst_len: usize,
    before: &Snap,
    reference: Duration,
    bound: Duration,
) -> Duration {
    let mut dst = vec![0u8; dst_len];
    for _ in 0..2000 {
        adv(secs(1));
        let r = t.update_timers(&mut dst);
        if now(t) - reference < bound {
            assert!(
                is_dbts(&r),
                "[R3:L-REFUSE-UNTIL-EXPIRED:REFUSED-BEFORE-BOUND] at {:?}: {:?}",
                now(t),
                r
            );
            assert_eq!(
                &snap(t),
                before,
                "[R3:L-REFUSE-UNTIL-EXPIRED:REFUSAL-LEAVES-STATE] at {:?}",
                now(t)
            );
        } else {
            assert!(
                is_expired_result(&r),
                "[R3:L-REFUSE-UNTIL-EXPIRED:EXPIRES-AT-BOUND] at {:?}: {:?}",
                now(t),
                r
            );
            let at = now(t);
            assert!(at - reference < bound + secs(1), "[R3:L-REFUSE-UNTIL-EXPIRED:THE-FIRST-TICK-PAST-THE-BOUND] the first tick past the bound");
            assert!(t.packet_queue.is_empty(), "[R3:L-REFUSE-UNTIL-EXPIRED:QUEUED-INPUT-DISPOSED-AS-BEFORE] queued input disposed as before");
            assert!(
                t.pending_amnezia_junk.is_none(),
                "[R3:L-REFUSE-UNTIL-EXPIRED:BURST-REMOVED] burst removed"
            );
            assert!(
                t.handshake.is_expired(),
                "[R3:L-REFUSE-UNTIL-EXPIRED:HANDSHAKE-IS-EXPIRED]"
            );
            // Idle Expired afterwards: no burst comes back.
            adv(secs(1));
            assert!(
                is_expired_result(&t.update_timers(&mut [0u8; 2048])),
                "[R3:L-REFUSE-UNTIL-EXPIRED:IS-EXPIRED-RESULT-UPDATE-TIMERS]"
            );
            assert!(
                t.pending_amnezia_junk.is_none(),
                "[R3:L-REFUSE-UNTIL-EXPIRED:PENDING-AMNEZIA-JUNK-IS-NONE]"
            );
            return at;
        }
    }
    panic!("[R3:L-REFUSE-UNTIL-EXPIRED:NEVER-EXPIRED-A-PENDING-BURST-INTERCEPTED] never expired: a pending burst intercepted every tick")
}

/// Emit outputs (advancing the clock) until the burst owes only its
/// initiation: no imitation datagram and no Jc left.
fn pump_to_initiation_due(t: &mut Tunn) {
    let mut big = vec![0u8; 2048];
    for _ in 0..100 {
        if let Some(p) = &t.pending_amnezia_junk {
            if p.imitation_datagrams.is_empty() && p.remaining == 0 {
                return;
            }
        }
        adv(secs(1));
        let _ = net(t.update_timers(&mut big));
    }
    panic!("[R3:L-PUMP-TO-INITIATION-DUE:BURST-NEVER-REACHED-ITS-INITIATION] burst never reached its initiation")
}

/// Emit outputs until the initiation itself leaves.
fn pump_to_initiation(t: &mut Tunn) -> Vec<u8> {
    let mut big = vec![0u8; 2048];
    for _ in 0..100 {
        adv(secs(1));
        if let TunnResult::WriteToNetwork(p) = t.update_timers(&mut big) {
            let p = p.to_vec();
            if t.pending_amnezia_junk.is_none() {
                return p;
            }
        }
    }
    panic!("[R3:L-PUMP-TO-INITIATION:NO-INITIATION] no initiation")
}

// T-B1 -- pending Jc final-initiation refusal past the untuned 90 s bound.
#[test]
fn t_b1_jc_burst_final_initiation_refused_past_the_90s_bound_expires() {
    let (mut c, _s) = pair(jc_cfg(1), jc_cfg(1));
    let mut big = vec![0u8; 2048];
    let p = ipv4(1);
    assert_eq!(
        net(c.encapsulate(&p, &mut big)).len(),
        JC,
        "[R3:TB1:NET-ENCAPSULATE-BIG-LEN-JC]"
    );
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        FLOOR,
        "[R3:TB1:FIRST-INITIATION] first initiation"
    );
    let started = c.timers[TimeLastHandshakeStarted];
    adv(secs(6));
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        JC,
        "[R3:TB1:RETRANSMISSION-JC] retransmission Jc"
    );
    let before = snap(&c);
    assert_eq!(before.queue, vec![p], "[R3:TB1:BEFORE-QUEUE]");
    assert!(
        before.in_progress && !before.expired,
        "[R3:TB1:BEFORE-IN-PROGRESS-BEFORE-EXPIRED]"
    );
    assert_eq!(before.attempts, 0, "[R3:TB1:BEFORE-ATTEMPTS]");
    assert!(
        matches!(before.pending, Some((0, 0, Some(_), false))),
        "[R3:TB1:MATCHES-BEFORE-PENDING-SOME-SOME]"
    );
    let at = refuse_until_expired(&mut c, FLOOR - 1, &before, started, REKEY_ATTEMPT_TIME);
    assert!(
        at - started >= REKEY_ATTEMPT_TIME,
        "[R3:TB1:AT-STARTED-REKEY-ATTEMPT-TIME]"
    );
}

// T-B1 (tuned) -- the same with the 90 s bound off: keychain_expire() * 3.
#[test]
fn t_b1_tuned_jc_burst_final_initiation_refused_past_keychain_expiry_expires() {
    let cfg = tuned(jc_cfg(1));
    let (mut c, _s) = pair(cfg.clone(), cfg);
    let mut big = vec![0u8; 2048];
    let p = ipv4(1);
    assert_eq!(
        net(c.encapsulate(&p, &mut big)).len(),
        JC,
        "[R3:TB1T:NET-ENCAPSULATE-BIG-LEN-JC]"
    );
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        FLOOR,
        "[R3:TB1T:NET-UPDATE-TIMERS-BIG-LEN-FLOOR]"
    );
    adv(secs(6));
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        JC,
        "[R3:TB1T:NET-UPDATE-TIMERS-BIG-LEN-JC]"
    );
    let before = snap(&c);
    assert_eq!(before.queue, vec![p], "[R3:TB1T:BEFORE-QUEUE]");
    let reference = before.established;
    refuse_until_expired(&mut c, FLOOR - 1, &before, reference, secs(120));
}

// T-B2 -- pending imitation: the final initiation refused past the bound.
#[test]
fn t_b2_imitation_burst_final_initiation_refused_past_the_90s_bound_expires() {
    let cfg = AmneziaConfig::new(S1 as _, 0, 0, 0)
        .with_protocol_imitation(AmneziaImitationProtocol::Dns, Some("example.com".into()));
    let (mut c, _s) = pair(cfg.clone(), cfg);
    let p = ipv4(2);
    let _dns = net(c.encapsulate(&p, &mut [0u8; 2048]));
    assert_eq!(
        pump_to_initiation(&mut c).len(),
        FLOOR,
        "[R3:TB2:PUMP-TO-INITIATION-LEN-FLOOR]"
    );
    let started = c.timers[TimeLastHandshakeStarted];
    adv(secs(6));
    let _ = net(c.update_timers(&mut [0u8; 2048])); // retransmission burst, first DNS
    pump_to_initiation_due(&mut c);
    let before = snap(&c);
    assert_eq!(before.queue, vec![p], "[R3:TB2:BEFORE-QUEUE]");
    assert!(
        matches!(before.pending, Some((0, 0, _, false))),
        "[R3:TB2:MATCHES-BEFORE-PENDING-SOME-FALSE]"
    );
    refuse_until_expired(&mut c, FLOOR - 1, &before, started, REKEY_ATTEMPT_TIME);
}

// T-B2 -- pending imitation datagram itself refused past the bound.
#[test]
fn t_b2_pending_imitation_datagram_refused_past_the_90s_bound_expires() {
    let cfg = AmneziaConfig::new(S1 as _, 0, 0, 0)
        .with_protocol_imitation(AmneziaImitationProtocol::Dns, Some("example.com".into()));
    let (mut c, _s) = pair(cfg.clone(), cfg);
    let p = ipv4(3);
    let _dns = net(c.encapsulate(&p, &mut [0u8; 2048]));
    assert_eq!(
        pump_to_initiation(&mut c).len(),
        FLOOR,
        "[R3:TB2B:PUMP-TO-INITIATION-LEN-FLOOR]"
    );
    let started = c.timers[TimeLastHandshakeStarted];
    adv(secs(6));
    let _ = net(c.update_timers(&mut [0u8; 2048])); // first DNS of the retransmission
    let before = snap(&c);
    assert!(
        matches!(before.pending, Some((n, 0, _, false)) if n > 0),
        "[R3:TB2B:MATCHES-BEFORE-PENDING-SOME-N]"
    );
    refuse_until_expired(&mut c, 10, &before, started, REKEY_ATTEMPT_TIME);
}

// T-B3 -- a newly restarted Expired cycle is not destroyed by its own stale
// timers or by the handshake still reporting Expired.
#[test]
fn t_b3_a_restarted_expired_cycle_burst_progresses() {
    let (mut c, _s) = pair(jc_cfg(2), jc_cfg(2));
    let mut big = vec![0u8; 2048];
    let t_exp = expired_with_owed_burst(&mut c);
    let owed = snap(&c);
    // Short tick while the reset is owed: refused, not expired, nothing moved.
    assert!(
        is_dbts(&c.update_timers(&mut [0u8; 50])),
        "[R3:TB3:IS-DBTS-UPDATE-TIMERS]"
    );
    assert_eq!(snap(&c), owed, "[R3:TB3:SNAP-OWED]");
    // First committed datagram: the reset is spent here, once.
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        JC,
        "[R3:TB3:NET-UPDATE-TIMERS-BIG-LEN-JC]"
    );
    let reset_at = now(&c);
    let s = snap(&c);
    assert_eq!(s.established, reset_at, "[R3:TB3:ESTABLISHED-RESET-AT]");
    assert!(reset_at > t_exp, "[R3:TB3:RESET-AT-T-EXP]");
    assert!(s.expired, "[R3:TB3:STILL-EXPIRED-UNTIL-THE-INITIATION-LEAVES] still Expired until the initiation leaves");
    assert!(
        matches!(s.pending, Some((0, 1, Some(_), false))),
        "[R3:TB3:MATCHES-PENDING-SOME-SOME-FALSE]"
    );
    assert!(
        s.queue.is_empty(),
        "[R3:TB3:A-TICK-ADMITS-NOTHING] a tick admits nothing"
    );
    // The next write is accepted with the second Jc; no second reset.
    adv(secs(1));
    let p = ipv4(4);
    assert_eq!(
        net(c.encapsulate(&p, &mut big)).len(),
        JC,
        "[R3:TB3:NET-ENCAPSULATE-BIG-LEN-JC]"
    );
    assert_eq!(
        c.timers[TimeSessionEstablished], reset_at,
        "[R3:TB3:RESET-ONLY-ONCE] reset only once"
    );
    assert_eq!(
        c.packet_queue.iter().cloned().collect::<Vec<_>>(),
        vec![p.clone()],
        "[R3:TB3:PACKET-QUEUE]"
    );
    // Then the initiation: the restarted cycle begins.
    adv(secs(1));
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        FLOOR,
        "[R3:TB3:NET-UPDATE-TIMERS-BIG-LEN-FLOOR]"
    );
    let s = snap(&c);
    assert!(
        s.in_progress && !s.expired && s.pending.is_none(),
        "[R3:TB3:IN-PROGRESS-EXPIRED-PENDING-IS-NONE]"
    );
    assert_eq!(s.started, now(&c), "[R3:TB3:STARTED-NOW]");
    assert_eq!(s.established, reset_at, "[R3:TB3:ESTABLISHED-RESET-AT-2]");
    assert_eq!(s.attempts, 0, "[R3:TB3:ATTEMPTS]");
    assert_eq!(s.queue, vec![p], "[R3:TB3:QUEUE]");
}

// T-B3b -- once the restarted cycle has begun (reset spent, a packet
// accepted), a burst stuck at its initiation is bounded like any other.
#[test]
fn t_b3b_a_begun_restarted_cycle_stuck_at_its_initiation_expires() {
    let (mut c, _s) = pair(jc_cfg(2), jc_cfg(2));
    let mut big = vec![0u8; 2048];
    let _t_exp = expire_fresh(&mut c);
    adv(ZERO_KEY + secs(1));
    let p = ipv4(5);
    assert_eq!(
        net(c.encapsulate(&p, &mut big)).len(),
        JC,
        "[R3:TB3B:NET-ENCAPSULATE-BIG-LEN-JC]"
    );
    let reset_at = now(&c);
    assert_eq!(
        c.timers[TimeSessionEstablished], reset_at,
        "[R3:TB3B:TIMERS-TIMESESSIONESTABLISHED-RESET-AT]"
    );
    adv(secs(1));
    assert_eq!(
        sent(
            c.update_timers(&mut big),
            "[R3:TB3B:RESTARTED-BURST-PROGRESSES-ON-TICK]"
        )
        .len(),
        JC,
        "[R3:TB3B:NET-UPDATE-TIMERS-BIG-LEN-JC]"
    );
    assert_eq!(
        c.timers[TimeSessionEstablished], reset_at,
        "[R3:TB3B:RESET-ONLY-ONCE] reset only once"
    );
    let before = snap(&c);
    assert_eq!(before.queue, vec![p], "[R3:TB3B:BEFORE-QUEUE]");
    assert!(
        before.expired && matches!(before.pending, Some((0, 0, Some(_), false))),
        "[R3:TB3B:BEGUN-CYCLE-FLAG-SPENT]"
    );
    refuse_until_expired(&mut c, FLOOR - 1, &before, reset_at, ZERO_KEY);
}

// T-B4 -- a restarted empty burst: refusal keeps the demand and the owed
// reset; the successful initiation resets once.
#[test]
fn t_b4_a_restarted_empty_burst_resets_once_at_its_initiation() {
    let (mut c, _s) = pair(jc_cfg(2), jc_cfg(2));
    let mut big = vec![0u8; 2048];
    let t_exp = expired_with_owed_burst(&mut c);
    // Live reframe to no burst at all: Restart leaves an empty burst.
    c.try_set_obfuscation(Default::default(), AmneziaConfig::new(S1 as _, 0, 0, 0))
        .unwrap();
    let before = snap(&c);
    assert_eq!(
        before.pending,
        Some((0, 0, None, true)),
        "[R3:TB4:BEFORE-PENDING-SOME-NONE-TRUE]"
    );
    assert_eq!(
        before.established, t_exp,
        "[R3:TB4:BEFORE-ESTABLISHED-T-EXP]"
    );
    assert!(
        is_dbts(&c.update_timers(&mut vec![0u8; FLOOR - 1])),
        "[R3:TB4:IS-DBTS-UPDATE-TIMERS-FLOOR]"
    );
    assert_eq!(
        snap(&c),
        before,
        "[R3:TB4:REFUSAL-NO-RESET-DEMAND-KEPT] refusal: no reset, demand kept"
    );
    let init = net(c.update_timers(&mut vec![0u8; FLOOR]));
    assert_eq!(init.len(), FLOOR, "[R3:TB4:INIT-LEN-FLOOR]");
    let s = snap(&c);
    assert_eq!(
        s.established,
        now(&c),
        "[R3:TB4:RESET-AT-THE-INITIATION] reset at the initiation"
    );
    assert_eq!(s.started, now(&c), "[R3:TB4:STARTED-NOW]");
    assert!(
        s.in_progress && !s.expired && s.pending.is_none(),
        "[R3:TB4:IN-PROGRESS-EXPIRED-PENDING-IS-NONE]"
    );
    assert_eq!(s.attempts, 0, "[R3:TB4:ATTEMPTS]");
    assert!(s.queue.is_empty(), "[R3:TB4:QUEUE-IS-EMPTY]");
    // Armed by the send itself (every sent packet arms it), not by the refusal.
    assert!(s.want_handshake, "[R3:TB4:WANT-HANDSHAKE]");
    // One demand, one initiation: nothing else is due before the retransmit.
    adv(secs(1));
    assert!(
        matches!(c.update_timers(&mut big), TunnResult::Done),
        "[R3:TB4:MATCHES-UPDATE-TIMERS-BIG-TUNNRESULT-DONE]"
    );
}

// T-B5 -- live reframe Keep preserves the burst and the owed reset.
#[test]
fn t_b5_keep_reframe_preserves_the_owed_reset() {
    let (mut c, _s) = pair(jc_cfg(2), jc_cfg(2));
    let mut big = vec![0u8; 2048];
    let t_exp = expired_with_owed_burst(&mut c);
    let before = snap(&c);
    // Jc sizes and S1 only: Keep.
    c.try_set_obfuscation(
        Default::default(),
        AmneziaConfig::new(32, 0, 0, 0).with_pre_handshake_junk(2, 80, 80, 0),
    )
    .unwrap();
    assert_eq!(
        snap(&c),
        before,
        "[R3:TB5:KEEP-TOUCHES-NEITHER-BURST-NOR-FLAG] Keep touches neither burst nor flag"
    );
    assert_eq!(
        c.timers[TimeSessionEstablished], t_exp,
        "[R3:TB5:TIMERS-TIMESESSIONESTABLISHED-T-EXP]"
    );
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        80,
        "[R3:TB5:NEW-SIZE-READ-AT-EMISSION] new size, read at emission"
    );
    let reset_at = now(&c);
    assert_eq!(
        c.timers[TimeSessionEstablished], reset_at,
        "[R3:TB5:TIMERS-TIMESESSIONESTABLISHED-RESET-AT]"
    );
    // Keep on a burst whose reset is spent: stays spent.
    c.try_set_obfuscation(
        Default::default(),
        AmneziaConfig::new(48, 0, 0, 0).with_pre_handshake_junk(2, 90, 90, 0),
    )
    .unwrap();
    assert!(
        matches!(snap(&c).pending, Some((0, 1, Some(_), false))),
        "[R3:TB5:MATCHES-SNAP-PENDING-SOME-SOME]"
    );
    adv(secs(1));
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        90,
        "[R3:TB5:NET-UPDATE-TIMERS-BIG-LEN]"
    );
    assert_eq!(
        c.timers[TimeSessionEstablished], reset_at,
        "[R3:TB5:NO-SECOND-RESET] no second reset"
    );
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        HANDSHAKE_INIT_SZ + 48,
        "[R3:TB5:NET-UPDATE-TIMERS-BIG-LEN-HANDSHAKE-INIT-SZ]"
    );
    assert!(
        c.pending_amnezia_junk.is_none(),
        "[R3:TB5:PENDING-AMNEZIA-JUNK-IS-NONE]"
    );
}

// T-B6 -- live reframe Restart carries the owed reset, and only the owed one.
#[test]
fn t_b6_restart_reframe_carries_the_owed_reset() {
    let (mut c, _s) = pair(jc_cfg(2), jc_cfg(2));
    let mut big = vec![0u8; 2048];
    let t_exp = expired_with_owed_burst(&mut c);
    let rng = c.handshake.rng.get_word_pos();
    c.try_set_obfuscation(Default::default(), jc_cfg(3))
        .unwrap();
    let s = snap(&c);
    assert_eq!(
        s.pending,
        Some((0, 3, None, true)),
        "[R3:TB6:REBUILT-RESET-STILL-OWED] rebuilt, reset still owed"
    );
    assert_eq!(s.established, t_exp, "[R3:TB6:ESTABLISHED-T-EXP]");
    assert_eq!(
        s.rng, rng,
        "[R3:TB6:A-JC-ONLY-REBUILD-DRAWS-NOTHING] a Jc-only rebuild draws nothing"
    );
    assert!(s.queue.is_empty(), "[R3:TB6:QUEUE-IS-EMPTY]");
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        JC,
        "[R3:TB6:NET-UPDATE-TIMERS-BIG-LEN-JC]"
    );
    let reset_at = now(&c);
    assert_eq!(
        c.timers[TimeSessionEstablished], reset_at,
        "[R3:TB6:TIMERS-TIMESESSIONESTABLISHED-RESET-AT]"
    );
    adv(secs(1));
    // Restart of a burst whose reset is spent: the rebuilt burst owes none.
    c.try_set_obfuscation(Default::default(), jc_cfg(1))
        .unwrap();
    assert!(
        matches!(snap(&c).pending, Some((0, 1, Some(_), false))),
        "[R3:TB6:MATCHES-SNAP-PENDING-SOME-SOME]"
    );
    adv(secs(1));
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        JC,
        "[R3:TB6:NET-UPDATE-TIMERS-BIG-LEN-JC-2]"
    );
    assert_eq!(
        c.timers[TimeSessionEstablished], reset_at,
        "[R3:TB6:NO-SECOND-RESET] no second reset"
    );
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        FLOOR,
        "[R3:TB6:NET-UPDATE-TIMERS-BIG-LEN-FLOOR]"
    );
    assert!(
        c.pending_amnezia_junk.is_none() && c.handshake.is_in_progress(),
        "[R3:TB6:PENDING-AMNEZIA-JUNK-IS-NONE-HANDSHAKE-IS-IN-PROGRESS]"
    );
}

// T-B7 -- a static-key change keeps the burst and its owed reset.
#[test]
fn t_b7_static_key_change_keeps_burst_and_owed_reset() {
    let (mut c, _s) = pair(jc_cfg(2), jc_cfg(2));
    let mut big = vec![0u8; 2048];
    expired_with_owed_burst(&mut c);
    let before = snap(&c);
    let sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let pk = x25519_dalek::PublicKey::from(&sk);
    c.set_static_private(sk, pk, None);
    assert_eq!(snap(&c), before, "[R3:TB7:KEY-CHANGE-KEEPS-BURST-AND-FLAG]");
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        JC,
        "[R3:TB7:NET-UPDATE-TIMERS-BIG-LEN-JC]"
    );
    assert_eq!(
        c.timers[TimeSessionEstablished],
        now(&c),
        "[R3:TB7:RESET-STILL-SPENT-ONCE] reset still spent once"
    );
    // A begun burst with an accepted packet is kept too.
    let (mut d, _t) = pair(jc_cfg(2), jc_cfg(2));
    let p = ipv4(7);
    assert_eq!(
        net(d.encapsulate(&p, &mut big)).len(),
        JC,
        "[R3:TB7:NET-ENCAPSULATE-BIG-LEN-JC]"
    );
    let before = snap(&d);
    let sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let pk = x25519_dalek::PublicKey::from(&sk);
    d.set_static_private(sk, pk, None);
    assert_eq!(snap(&d), before, "[R3:TB7:SNAP-BEFORE-2]");
}

// T-B8 -- a PSK change keeps the burst and its owed reset.
#[test]
fn t_b8_psk_change_keeps_burst_and_owed_reset() {
    let (mut c, _s) = pair(jc_cfg(2), jc_cfg(2));
    let mut big = vec![0u8; 2048];
    expired_with_owed_burst(&mut c);
    let before = snap(&c);
    c.set_preshared_key(Some([7u8; 32]));
    assert_eq!(snap(&c), before, "[R3:TB8:PSK-CHANGE-KEEPS-BURST-AND-FLAG]");
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        JC,
        "[R3:TB8:NET-UPDATE-TIMERS-BIG-LEN-JC]"
    );
    assert_eq!(
        c.timers[TimeSessionEstablished],
        now(&c),
        "[R3:TB8:TIMERS-TIMESESSIONESTABLISHED-NOW]"
    );
    let (mut d, _t) = pair(jc_cfg(2), jc_cfg(2));
    let p = ipv4(8);
    assert_eq!(
        net(d.encapsulate(&p, &mut big)).len(),
        JC,
        "[R3:TB8:NET-ENCAPSULATE-BIG-LEN-JC]"
    );
    let before = snap(&d);
    d.set_preshared_key(Some([9u8; 32]));
    assert_eq!(snap(&d), before, "[R3:TB8:SNAP-BEFORE-2]");
}

// T-B9 -- session establishment discards the burst and its flag.
#[test]
fn t_b9_session_establishment_discards_burst_and_flag() {
    let (mut c, mut s) = pair(jc_cfg(2), jc_cfg(2));
    let mut big = vec![0u8; 2048];
    expired_with_owed_burst(&mut c);
    let init = net(s.format_handshake_initiation_now(&mut big, false, false));
    let mut cbuf = vec![0u8; 2048];
    let _resp = net(c.decapsulate(None, &init, &mut cbuf));
    let st = snap(&c);
    assert!(
        st.pending.is_none(),
        "[R3:TB9:BURST-AND-FLAG-GONE-WITH-IT] burst and flag gone with it"
    );
    assert!(!st.expired, "[R3:TB9:ST-EXPIRED]");
    assert_eq!(st.established, now(&c), "[R3:TB9:ST-ESTABLISHED-NOW]");
    assert!(st.queue.is_empty(), "[R3:TB9:ST-QUEUE-IS-EMPTY]");
    // Begun burst with an accepted packet: the burst goes, the packet stays owned.
    let (mut d, mut t) = pair(jc_cfg(2), jc_cfg(2));
    let p = ipv4(9);
    assert_eq!(
        net(d.encapsulate(&p, &mut big)).len(),
        JC,
        "[R3:TB9:NET-ENCAPSULATE-BIG-LEN-JC]"
    );
    let init = net(t.format_handshake_initiation_now(&mut big, false, false));
    let _resp = net(d.decapsulate(None, &init, &mut cbuf));
    assert!(
        d.pending_amnezia_junk.is_none(),
        "[R3:TB9:PENDING-AMNEZIA-JUNK-IS-NONE]"
    );
    assert_eq!(
        d.packet_queue.iter().cloned().collect::<Vec<_>>(),
        vec![p],
        "[R3:TB9:PACKET-QUEUE]"
    );
}

// T-B10 -- clear_all discards burst and flag (and the queue).
#[test]
fn t_b10_clear_all_discards_burst_and_flag() {
    let (mut c, _s) = pair(jc_cfg(2), jc_cfg(2));
    expired_with_owed_burst(&mut c);
    c.clear_all();
    assert!(
        c.pending_amnezia_junk.is_none() && c.packet_queue.is_empty(),
        "[R3:TB10:PENDING-AMNEZIA-JUNK-IS-NONE-PACKET-QUEUE-IS-EMPTY]"
    );
    let (mut d, _t) = pair(jc_cfg(2), jc_cfg(2));
    let _ = net(d.encapsulate(&ipv4(10), &mut [0u8; 2048]));
    assert!(
        d.pending_amnezia_junk.is_some() && !d.packet_queue.is_empty(),
        "[R3:TB10:PENDING-AMNEZIA-JUNK-IS-SOME-PACKET-QUEUE-IS-EMPTY]"
    );
    d.clear_all();
    assert!(
        d.pending_amnezia_junk.is_none() && d.packet_queue.is_empty(),
        "[R3:TB10:PENDING-AMNEZIA-JUNK-IS-NONE-PACKET-QUEUE-IS-EMPTY-2]"
    );
}

// T-B11 -- refused writes, drains and ticks never extend the lifetime.
#[test]
fn t_b11_repeated_refusals_cannot_extend_the_lifetime() {
    let cfg = tuned(jc_cfg(1));
    let (mut c, _s) = pair(cfg.clone(), cfg);
    let p = ipv4(11);
    assert_eq!(
        net(c.encapsulate(&p, &mut [0u8; 2048])).len(),
        JC,
        "[R3:TB11:NET-ENCAPSULATE-LEN-JC]"
    );
    let before = snap(&c);
    assert!(
        !before.in_progress && !before.expired,
        "[R3:TB11:BEFORE-IN-PROGRESS-BEFORE-EXPIRED]"
    );
    assert!(
        matches!(before.pending, Some((0, 0, Some(_), false))),
        "[R3:TB11:MATCHES-BEFORE-PENDING-SOME-SOME]"
    );
    let reference = before.established;
    let mut short = vec![0u8; FLOOR - 1];
    for i in 0..2000u32 {
        adv(secs(1));
        // A refused write: not admitted.
        let r = c.encapsulate(&ipv4((i % 200) as u8 + 20), &mut short);
        assert!(is_dbts(&r), "[R3:TB11:REFUSED-WRITE] {:?}", r);
        // A refused drain: nothing re-admitted.
        let r = c.decapsulate(None, &[], &mut short);
        assert!(is_dbts(&r), "[R3:TB11:REFUSED-DRAIN] {:?}", r);
        assert_eq!(
            snap(&c),
            before,
            "[R3:TB11:REFUSED-WRITE-AND-DRAIN-LEAVE-STATE]"
        );
        let r = c.update_timers(&mut short);
        if now(&c) - reference < secs(120) {
            assert!(is_dbts(&r), "[R3:TB11:REFUSED-TICK] {:?}", r);
            assert_eq!(snap(&c), before, "[R3:TB11:REFUSED-TICK-LEAVES-STATE]");
        } else {
            assert!(is_expired_result(&r), "[R3:TB11:EXPIRES-AT-BOUND] {:?}", r);
            assert!(
                now(&c) - reference < secs(121),
                "[R3:TB11:NOW-REFERENCE-SECS]"
            );
            assert!(
                c.packet_queue.is_empty() && c.pending_amnezia_junk.is_none(),
                "[R3:TB11:PACKET-QUEUE-IS-EMPTY-PENDING-AMNEZIA-JUNK-IS-NONE]"
            );
            return;
        }
    }
    panic!("[R3:TB11:REFUSALS-KEPT-THE-BURST-ALIVE-PAST] refusals kept the burst alive past keychain_expire() * 3");
}

// T-B12 -- a burst-bearing latch refusal keeps exactly one demand: the burst.
#[test]
fn t_b12_a_burst_bearing_latch_refusal_keeps_exactly_one_demand() {
    let (mut c, mut s) = pair(jc_cfg(1), jc_cfg(1));
    let mut big = vec![0u8; 2048];
    let mut sbuf = vec![0u8; 2048];
    assert_eq!(
        net(c.encapsulate(&ipv4(1), &mut big)).len(),
        JC,
        "[R3:TB12:NET-ENCAPSULATE-IPV4-BIG-LEN]"
    );
    let init = net(c.update_timers(&mut big));
    let resp = net(s.decapsulate(None, &init, &mut sbuf));
    let _ka = net(c.decapsulate(None, &resp, &mut big));
    let _data = net(c.decapsulate(None, &[], &mut big)); // drain the queued packet
    adv(secs(1));
    let _ = c.update_timers(&mut big);
    let _data = net(c.encapsulate(&ipv4(2), &mut big));
    assert!(
        c.timers.want_handshake,
        "[R3:TB12:LATCH-ARMED-BY-THE-SEND] latch armed by the send"
    );
    adv(secs(16));
    let rng = c.handshake.rng.get_word_pos();
    let mut short = [0u8; 50];
    let r = c.update_timers(&mut short);
    assert!(is_dbts(&r), "[R3:TB12:CHECK] {:?}", r);
    let st = snap(&c);
    assert!(
        !st.want_handshake,
        "[R3:TB12:THE-BURST-OWNS-THE-DEMAND-NO] the burst owns the demand: no re-arm"
    );
    assert_eq!(
        st.pending,
        Some((0, 1, None, false)),
        "[R3:TB12:ST-PENDING-SOME-NONE-FALSE]"
    );
    assert!(!st.in_progress, "[R3:TB12:ST-IN-PROGRESS]");
    assert_eq!(
        st.rng, rng,
        "[R3:TB12:NO-JC-SIZE-DRAWN-ON-THE] no Jc size drawn on the refusal"
    );
    let mut initiations = 0;
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        JC,
        "[R3:TB12:NET-UPDATE-TIMERS-BIG-LEN-JC]"
    );
    let i2 = net(c.update_timers(&mut big));
    assert_eq!(i2.len(), FLOOR, "[R3:TB12:I2-LEN-FLOOR]");
    initiations += 1;
    assert!(
        c.handshake.is_in_progress() && c.pending_amnezia_junk.is_none(),
        "[R3:TB12:HANDSHAKE-IS-IN-PROGRESS-PENDING-AMNEZIA-JUNK-IS-NONE]"
    );
    for _ in 0..4 {
        adv(secs(1));
        match c.update_timers(&mut big) {
            TunnResult::Done => {}
            TunnResult::WriteToNetwork(_) => initiations += 1,
            other => panic!("[R3:TB12:CHECK-2] {:?}", other),
        }
    }
    assert_eq!(
        initiations, 1,
        "[R3:TB12:EXACTLY-ONE-INITIATION-FOR-ONE-DEMAND] exactly one initiation for one demand"
    );
}

// T-B13 -- the exemption never shields handshake state: once a peer's
// initiation moved the handshake out of Expired, the bounds apply again.
#[test]
fn t_b13_the_exemption_ends_when_the_handshake_leaves_expired() {
    let (mut c, mut s) = pair(jc_cfg(2), jc_cfg(2));
    let mut big = vec![0u8; 2048];
    expired_with_owed_burst(&mut c);
    let init = net(s.format_handshake_initiation_now(&mut big, false, false));
    // The response does not fit: the handshake holds InitReceived state.
    assert!(
        is_dbts(&c.decapsulate(None, &init, &mut [0u8; 50])),
        "[R3:TB13:IS-DBTS-DECAPSULATE-NONE-INIT]"
    );
    assert!(
        !c.handshake.is_expired() && c.handshake.is_in_progress(),
        "[R3:TB13:HANDSHAKE-IS-EXPIRED-HANDSHAKE-IS-IN-PROGRESS]"
    );
    assert!(
        c.pending_amnezia_junk
            .as_ref()
            .unwrap()
            .reset_expired_timers,
        "[R3:TB13:PENDING-AMNEZIA-JUNK-RESET-EXPIRED-TIMERS]"
    );
    // Stale timers past keychain_expire() * 3: the bound ends it.
    assert!(
        is_expired_result(&c.update_timers(&mut [0u8; 50])),
        "[R3:TB13:IS-EXPIRED-RESULT-UPDATE-TIMERS]"
    );
    assert!(
        c.pending_amnezia_junk.is_none() && c.packet_queue.is_empty(),
        "[R3:TB13:PENDING-AMNEZIA-JUNK-IS-NONE-PACKET-QUEUE-IS-EMPTY]"
    );
    assert!(c.handshake.is_expired(), "[R3:TB13:HANDSHAKE-IS-EXPIRED]");
}

// ---------------------------------------------------------------------------
// Reachable restart from a NONEMPTY old application queue (OQ-A, OQ-B).

/// Admit `old` through a normal first cycle, then tick (adequate buffers,
/// no peer) until the untuned 90 s bound ends the cycle the normal way.
/// Returns the expiry instant; the old queue must be gone.
fn expire_with_old_queue(t: &mut Tunn, old: &[Vec<u8>]) -> Duration {
    let mut big = vec![0u8; 2048];
    for p in old {
        let _ = t.encapsulate(p, &mut big);
    }
    assert_eq!(
        t.packet_queue.iter().cloned().collect::<Vec<_>>(),
        old.to_vec(),
        "[R3:L-EXPIRE-WITH-OLD-QUEUE:PACKET-QUEUE-OLD]"
    );
    for _ in 0..400 {
        adv(secs(1));
        match t.update_timers(&mut big) {
            TunnResult::WriteToNetwork(_) | TunnResult::Done => {
                assert_eq!(t.packet_queue.len(), old.len(), "[R3:L-EXPIRE-WITH-OLD-QUEUE:OLD-QUEUE-OWNED-UNTIL-EXPIRY] old queue owned until expiry");
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                assert!(
                    t.handshake.is_expired(),
                    "[R3:L-EXPIRE-WITH-OLD-QUEUE:HANDSHAKE-IS-EXPIRED]"
                );
                assert!(t.packet_queue.is_empty(), "[R3:L-EXPIRE-WITH-OLD-QUEUE:CLEAR-ALL-DISPOSED-OF-THE-OLD] clear_all disposed of the old queue");
                assert!(
                    t.pending_amnezia_junk.is_none(),
                    "[R3:L-EXPIRE-WITH-OLD-QUEUE:PENDING-AMNEZIA-JUNK-IS-NONE]"
                );
                return t.timers[TimeSessionEstablished];
            }
            other => panic!("[R3:L-EXPIRE-WITH-OLD-QUEUE:CHECK] {:?}", other),
        }
    }
    panic!("[R3:L-EXPIRE-WITH-OLD-QUEUE:THE-OLD-CYCLE-NEVER-EXPIRED] the old cycle never expired")
}

/// Refuse the first output of an owed restart burst with `short`, through a
/// write, a tick and a drain, every 30 s for three zero-key lifetimes.
/// Everything in `before` must hold throughout; `same` checks storage identity.
fn refuse_owed_restart(
    t: &mut Tunn,
    src: &[u8],
    short: usize,
    before: &Snap,
    mut same: impl FnMut(&Tunn),
) {
    let mut dst = vec![0u8; short];
    let mut elapsed = Duration::ZERO;
    while elapsed < ZERO_KEY * 3 {
        adv(secs(30));
        elapsed += secs(30);
        assert!(
            is_dbts(&t.encapsulate(src, &mut dst)),
            "[R3:L-REFUSE-OWED-RESTART:NEW-SRC-NEVER-ADMITTED] new src never admitted"
        );
        assert!(
            is_dbts(&t.update_timers(&mut dst)),
            "[R3:L-REFUSE-OWED-RESTART:EXEMPT-REFUSED-NOT-EXPIRED] exempt: refused, not expired"
        );
        assert!(
            matches!(t.decapsulate(None, &[], &mut dst), TunnResult::Done),
            "[R3:L-REFUSE-OWED-RESTART:MATCHES-DECAPSULATE-NONE-DST-TUNNRESULT]"
        );
        assert_eq!(
            &snap(t),
            before,
            "[R3:L-REFUSE-OWED-RESTART:REFUSAL-LEAVES-STATE] after {:?}",
            elapsed
        );
        same(t);
    }
}

// OQ-A: old queue -> normal expiry -> restart whose FIRST Jc never fits.
#[test]
fn oq_a_old_queue_expiry_then_restart_with_first_jc_refused() {
    let (mut c, _s) = pair(jc_cfg(2), jc_cfg(2));
    let mut big = vec![0u8; 2048];
    let (p1, p2, p3) = (ipv4(31), ipv4(32), ipv4(33));
    let t_exp = expire_with_old_queue(&mut c, &[p1.clone(), p2.clone()]);
    let attempts_after_expiry = c.timers.handshake_attempts;
    adv(ZERO_KEY + secs(1));
    // Restart: the first Jc (100 bytes) cannot fit 50.
    assert!(
        is_dbts(&c.encapsulate(&p3, &mut [0u8; 50])),
        "[R3:OQA:IS-DBTS-ENCAPSULATE-P3]"
    );
    let before = snap(&c);
    assert!(
        before.expired && before.queue.is_empty(),
        "[R3:OQA:BEFORE-EXPIRED-BEFORE-QUEUE-IS-EMPTY]"
    );
    assert_eq!(
        before.pending,
        Some((0, 2, None, true)),
        "[R3:OQA:ONE-SHELL-RESET-OWED] one shell, reset owed"
    );
    assert_eq!(
        before.established, t_exp,
        "[R3:OQA:NO-RESET-ON-A-REFUSAL] no reset on a refusal"
    );
    assert_eq!(
        before.attempts, attempts_after_expiry,
        "[R3:OQA:BEFORE-ATTEMPTS-ATTEMPTS-AFTER-EXPIRY]"
    );
    // Jc is generated only when it fits: the shell holds no payload storage.
    assert_eq!(
        c.pending_amnezia_junk
            .as_ref()
            .unwrap()
            .imitation_datagrams
            .capacity(),
        0,
        "[R3:OQA:PENDING-AMNEZIA-JUNK-IMITATION-DATAGRAMS-CAPACITY]"
    );
    refuse_owed_restart(&mut c, &p3, 50, &before, |t| {
        assert_eq!(
            t.pending_amnezia_junk
                .as_ref()
                .unwrap()
                .imitation_datagrams
                .capacity(),
            0,
            "[R3:OQA:NO-JC-PAYLOAD-ALLOCATED-BY-A] no Jc payload allocated by a refusal"
        );
    });
    // Capacity: progress, and exactly one reset at the first committed Jc.
    assert_eq!(
        net(c.encapsulate(&p3, &mut big)).len(),
        JC,
        "[R3:OQA:NET-ENCAPSULATE-P3-BIG-LEN]"
    );
    let reset_at = now(&c);
    let s = snap(&c);
    assert_eq!(s.established, reset_at, "[R3:OQA:ESTABLISHED-RESET-AT]");
    assert_eq!(
        s.pending,
        Some((0, 1, s.pending.unwrap().2, false)),
        "[R3:OQA:PENDING-SOME-PENDING-FALSE]"
    );
    assert_eq!(
        s.queue,
        vec![p3.clone()],
        "[R3:OQA:ONLY-THE-NEW-SRC-NO-OLD] only the new src; no old packet"
    );
    adv(secs(1));
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        JC,
        "[R3:OQA:NET-UPDATE-TIMERS-BIG-LEN-JC]"
    );
    assert_eq!(
        c.timers[TimeSessionEstablished], reset_at,
        "[R3:OQA:RESET-CONSUMED-ONCE] reset consumed once"
    );
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        FLOOR,
        "[R3:OQA:NET-UPDATE-TIMERS-BIG-LEN-FLOOR]"
    );
    let s = snap(&c);
    assert!(
        s.in_progress && !s.expired && s.pending.is_none(),
        "[R3:OQA:IN-PROGRESS-EXPIRED-PENDING-IS-NONE]"
    );
    assert_eq!(
        (s.established, s.started, s.attempts),
        (reset_at, now(&c), 0),
        "[R3:OQA:ESTABLISHED-STARTED-ATTEMPTS-RESET-AT-NOW]"
    );
    assert_eq!(s.queue, vec![p3], "[R3:OQA:QUEUE-P3]");
}

// OQ-B: old queue -> normal expiry -> restart whose FIRST pre-generated
// imitation datagram never fits.
#[test]
fn oq_b_old_queue_expiry_then_restart_with_first_imitation_refused() {
    let cfg = AmneziaConfig::new(S1 as _, 0, 0, 0)
        .with_protocol_imitation(AmneziaImitationProtocol::Dns, Some("example.com".into()));
    let (mut c, _s) = pair(cfg.clone(), cfg);
    let mut big = vec![0u8; 2048];
    let (p1, p2, p3) = (ipv4(41), ipv4(42), ipv4(43));
    let t_exp = expire_with_old_queue(&mut c, &[p1.clone(), p2.clone()]);
    adv(ZERO_KEY + secs(1));
    assert!(
        is_dbts(&c.encapsulate(&p3, &mut [0u8; 10])),
        "[R3:OQB:IS-DBTS-ENCAPSULATE-P3]"
    );
    let before = snap(&c);
    assert!(
        before.expired && before.queue.is_empty(),
        "[R3:OQB:BEFORE-EXPIRED-BEFORE-QUEUE-IS-EMPTY]"
    );
    assert_eq!(
        before.pending,
        Some((3, 0, None, true)),
        "[R3:OQB:BEFORE-PENDING-SOME-NONE-TRUE]"
    );
    assert_eq!(
        before.established, t_exp,
        "[R3:OQB:BEFORE-ESTABLISHED-T-EXP]"
    );
    // The one prepared burst: datagram bytes and their heap buffers.
    let prepared: Vec<(Duration, Vec<u8>, *const u8)> = c
        .pending_amnezia_junk
        .as_ref()
        .unwrap()
        .imitation_datagrams
        .iter()
        .map(|(d, b)| (*d, b.clone(), b.as_ptr()))
        .collect();
    let identity = |t: &Tunn| {
        let now: Vec<(Duration, Vec<u8>, *const u8)> = t
            .pending_amnezia_junk
            .as_ref()
            .unwrap()
            .imitation_datagrams
            .iter()
            .map(|(d, b)| (*d, b.clone(), b.as_ptr()))
            .collect();
        assert_eq!(now, prepared, "[R3:OQB:SAME-BURST-SAME-BUFFERS-NOTHING-REGENERATED] same burst, same buffers, nothing regenerated");
    };
    refuse_owed_restart(&mut c, &p3, 10, &before, identity);
    // Capacity for exactly the front: the SAME prepared datagram leaves.
    let front = prepared[0].1.clone();
    assert_eq!(
        net(c.encapsulate(&p3, &mut vec![0u8; front.len()])),
        front,
        "[R3:OQB:NET-ENCAPSULATE-P3-FRONT-LEN]"
    );
    let reset_at = now(&c);
    assert_eq!(
        c.timers[TimeSessionEstablished], reset_at,
        "[R3:OQB:TIMERS-TIMESESSIONESTABLISHED-RESET-AT]"
    );
    assert!(
        !c.pending_amnezia_junk
            .as_ref()
            .unwrap()
            .reset_expired_timers,
        "[R3:OQB:PENDING-AMNEZIA-JUNK-RESET-EXPIRED-TIMERS]"
    );
    assert_eq!(
        c.packet_queue.iter().cloned().collect::<Vec<_>>(),
        vec![p3.clone()],
        "[R3:OQB:PACKET-QUEUE-P3]"
    );
    for (_, want, _) in &prepared[1..] {
        adv(secs(1));
        assert_eq!(
            &net(c.update_timers(&mut big)),
            want,
            "[R3:OQB:NET-UPDATE-TIMERS-BIG-WANT]"
        );
        assert_eq!(
            c.timers[TimeSessionEstablished], reset_at,
            "[R3:OQB:RESET-CONSUMED-ONCE] reset consumed once"
        );
    }
    adv(secs(1));
    assert_eq!(
        net(c.update_timers(&mut big)).len(),
        FLOOR,
        "[R3:OQB:NET-UPDATE-TIMERS-BIG-LEN-FLOOR]"
    );
    let s = snap(&c);
    assert!(
        s.in_progress && !s.expired && s.pending.is_none(),
        "[R3:OQB:IN-PROGRESS-EXPIRED-PENDING-IS-NONE]"
    );
    assert_eq!(
        (s.established, s.attempts),
        (reset_at, 0),
        "[R3:OQB:ESTABLISHED-ATTEMPTS-RESET-AT]"
    );
    assert_eq!(s.queue, vec![p3], "[R3:OQB:QUEUE-P3]");
}
