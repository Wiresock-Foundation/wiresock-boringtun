// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::errors::WireGuardError;
use crate::noise::{Tunn, TunnResult};
use std::mem;
use std::ops::{Index, IndexMut};

use std::time::Duration;

#[cfg(feature = "mock-instant")]
use mock_instant::thread_local::Instant;

#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;

// Some constants, represent time in seconds
// https://www.wireguard.com/papers/wireguard.pdf#page=14
pub(crate) const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub(crate) const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub(crate) const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub(crate) const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub enum TimerName {
    /// Current time, updated each call to `update_timers`
    TimeCurrent,
    /// Time when last handshake was completed
    TimeSessionEstablished,
    /// Time the last attempt for a new handshake began
    TimeLastHandshakeStarted,
    /// Time we last received and authenticated a packet
    TimeLastPacketReceived,
    /// Time we last send a packet
    TimeLastPacketSent,
    /// Time we last received and authenticated a DATA packet
    TimeLastDataPacketReceived,
    /// Time we last send a DATA packet
    TimeLastDataPacketSent,
    /// Time we last received a cookie
    TimeCookieReceived,
    /// Time we last sent persistent keepalive
    TimePersistentKeepalive,
    Top,
}

use self::TimerName::*;

#[derive(Debug)]
pub struct Timers {
    /// Is the owner of the timer the initiator or the responder for the last handshake?
    is_initiator: bool,
    /// Start time of the tunnel
    time_started: Instant,
    timers: [Duration; TimerName::Top as usize],
    pub(super) session_timers: [Duration; super::N_SESSIONS],
    /// Did we receive data without sending anything back?
    want_keepalive: bool,
    /// Did we send data without hearing back?
    want_handshake: bool,
    persistent_keepalive: usize,
    /// Should this timer call reset rr function (if not a shared rr instance)
    pub(super) should_reset_rr: bool,
    /// Per-arming draws from the AmneziaWG tunable timer ranges; the classic
    /// constants when unset, and at construction. Each is re-drawn when its
    /// deadline is armed, so an armed deadline is one uniform draw from its
    /// range -- a fresh draw per 250ms poll would instead fire near the low
    /// end with high probability (first passage), which is not the
    /// distribution a range configures.
    ///
    /// Four of the six arm where amneziawg-go re-arms the matching timer. The
    /// last two are a deliberate divergence, noted at their own field: upstream
    /// re-draws those per *check*, which it can afford because it checks them
    /// on the send and receive paths rather than on a poll.
    ///
    /// Re-drawn per initiation send (upstream `timersHandshakeInitiated`):
    pub(super) retransmit_current: Duration,
    /// Initiations sent in the current handshake cycle, and the count this
    /// cycle may reach before giving up -- upstream's `handshakeAttempts` and
    /// its per-cycle `maxHandshakeAttempts` snapshot. A count, not a window:
    /// see [`AwgTimers::max_attempts`].
    pub(super) handshake_attempts: u32,
    pub(super) max_attempts_current: u32,
    /// Re-drawn when the keepalive latch arms (upstream `timersDataReceived`):
    pub(super) keepalive_current: Duration,
    /// Re-drawn when the unanswered-data latch arms (upstream
    /// `timersDataSent`):
    pub(super) new_handshake_current: Duration,
    /// Re-drawn per established session (upstream draws per check; one draw
    /// per session lands in the same configured band without the first-passage
    /// bias of drawing against a 250ms poll):
    pub(super) rekey_after_current: Duration,
    pub(super) refresh_receive_current: Duration,
}

impl Timers {
    pub(super) fn new(persistent_keepalive: Option<u16>, reset_rr: bool) -> Timers {
        Timers {
            is_initiator: false,
            time_started: Instant::now(),
            timers: Default::default(),
            session_timers: Default::default(),
            want_keepalive: Default::default(),
            want_handshake: Default::default(),
            persistent_keepalive: usize::from(persistent_keepalive.unwrap_or(0)),
            should_reset_rr: reset_rr,
            retransmit_current: REKEY_TIMEOUT,
            handshake_attempts: 0,
            max_attempts_current: (REKEY_ATTEMPT_TIME.as_secs() / REKEY_TIMEOUT.as_secs()) as u32,
            keepalive_current: KEEPALIVE_TIMEOUT,
            new_handshake_current: KEEPALIVE_TIMEOUT.saturating_add(REKEY_TIMEOUT),
            rekey_after_current: REKEY_AFTER_TIME,
            refresh_receive_current: REJECT_AFTER_TIME
                .saturating_sub(KEEPALIVE_TIMEOUT)
                .saturating_sub(REKEY_TIMEOUT),
        }
    }

    fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    pub(super) fn clear(&mut self) {
        let now = Instant::now().duration_since(self.time_started);
        for t in &mut self.timers[..] {
            *t = now;
        }
        self.want_handshake = false;
        self.want_keepalive = false;
    }
}

impl Index<TimerName> for Timers {
    type Output = Duration;
    fn index(&self, index: TimerName) -> &Duration {
        &self.timers[index as usize]
    }
}

impl IndexMut<TimerName> for Timers {
    fn index_mut(&mut self, index: TimerName) -> &mut Duration {
        &mut self.timers[index as usize]
    }
}

impl Tunn {
    pub(super) fn timer_tick(&mut self, timer_name: TimerName) {
        match timer_name {
            TimeLastPacketReceived => {
                // Draw only when the latch arms, not per packet: upstream mods
                // its sendKeepalive timer only when it is not already pending,
                // so each armed deadline is a single uniform draw from the
                // configured range. Unset ranges return the constant without
                // touching the RNG.
                if !self.timers.want_keepalive {
                    self.timers.keepalive_current =
                        self.amnezia.timers.keepalive(&mut self.handshake.rng);
                }
                self.timers.want_keepalive = true;
                self.timers.want_handshake = false;
            }
            TimeLastPacketSent => {
                // Same arming rule as above, for the unanswered-data deadline
                // (upstream `timersDataSent` / `newHandshakeTimeout`).
                if !self.timers.want_handshake {
                    self.timers.new_handshake_current = self
                        .amnezia
                        .timers
                        .new_handshake_timeout(&mut self.handshake.rng);
                }
                self.timers.want_handshake = true;
                self.timers.want_keepalive = false;
            }
            _ => {}
        }

        let time = self.timers[TimeCurrent];
        self.timers[timer_name] = time;
    }

    pub(super) fn timer_tick_session_established(
        &mut self,
        is_initiator: bool,
        session_idx: usize,
    ) {
        self.timer_tick(TimeSessionEstablished);
        self.timers.session_timers[session_idx % crate::noise::N_SESSIONS] =
            self.timers[TimeCurrent];
        self.timers.is_initiator = is_initiator;
        self.pending_amnezia_junk = None;
        // One rekey deadline per session: the age at which this key is
        // actively refreshed on send, and the last-minute refresh age on
        // receive. Unset ranges are the classic constants, RNG untouched.
        self.timers.rekey_after_current = self
            .amnezia
            .timers
            .key_refresh_sending(&mut self.handshake.rng);
        self.timers.refresh_receive_current = self
            .amnezia
            .timers
            .key_refresh_receiving(&mut self.handshake.rng);
    }

    /// Re-draw every cached tunable-timer deadline from the current config.
    ///
    /// Each `*_current` field is otherwise drawn only where amneziawg-go
    /// re-arms the corresponding timer, so a live `set=1` that changes a range
    /// would not reach an established session: [`Tunn::update_session_timers`]
    /// reads `keychain_expire()` fresh on every poll, but the other five would
    /// keep the draw made under the *previous* configuration until the next
    /// handshake. That mix is worse than either half -- a session that expires
    /// on the new `reject_after_time` while still rekeying on the old
    /// `rekey_after_time` never rekeys before it is dropped, and the tunnel
    /// stalls until traffic forces a fresh handshake.
    ///
    /// Drawn here rather than lazily at each check because the draw *is* the
    /// arming: see the [`Timers`] field docs for why a fresh draw per 250ms
    /// poll would not be the distribution a range configures.
    pub(super) fn redraw_tunable_timers(&mut self) {
        let t = self.amnezia.timers;
        let retransmit = t.retransmit_timeout(&mut self.handshake.rng);
        let keepalive = t.keepalive(&mut self.handshake.rng);
        let new_handshake = t.new_handshake_timeout(&mut self.handshake.rng);
        let rekey_after = t.key_refresh_sending(&mut self.handshake.rng);
        let refresh_receive = t.key_refresh_receiving(&mut self.handshake.rng);

        // The attempt *limit* is re-drawn; the attempts already spent in the
        // current cycle are not reset, or a peer could be kept retrying
        // forever by a periodic `awg syncconf`.
        let max_attempts = t.max_attempts(&mut self.handshake.rng);

        self.timers.retransmit_current = retransmit;
        self.timers.max_attempts_current = max_attempts;
        self.timers.keepalive_current = keepalive;
        self.timers.new_handshake_current = new_handshake;
        self.timers.rekey_after_current = rekey_after;
        self.timers.refresh_receive_current = refresh_receive;
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    fn clear_all(&mut self) {
        for session in &mut self.sessions {
            *session = None;
        }

        self.packet_queue.clear();
        self.pending_amnezia_junk = None;

        self.timers.clear();
    }

    fn update_session_timers(&mut self, time_now: Duration) {
        // The tunable reject_after_time's high end, matching upstream's
        // `keychainExpireTime`: expiry honours the most permissive draw a
        // peer re-picking inside the same range could be running, so a key
        // the peer still uses is not dropped early. The classic constant when
        // unset.
        let reject_after_time = self.amnezia.timers.keychain_expire();
        let timers = &mut self.timers;

        for (i, t) in timers.session_timers.iter_mut().enumerate() {
            if time_now - *t > reject_after_time {
                if let Some(session) = self.sessions[i].take() {
                    tracing::debug!(
                        message = "SESSION_EXPIRED(REJECT_AFTER_TIME)",
                        session = session.receiving_index
                    );
                }
                *t = time_now;
            }
        }
    }

    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        let mut handshake_initiation_required = false;
        let mut keepalive_required = false;

        let time = Instant::now();

        if self.timers.should_reset_rr {
            self.rate_limiter.reset_count();
        }

        // All the times are counted from tunnel initiation, for efficiency our timers are rounded
        // to a second, as there is no real benefit to having highly accurate timers.
        let now = time.duration_since(self.timers.time_started);
        self.timers[TimeCurrent] = now;

        self.update_session_timers(now);

        if self.pending_amnezia_junk.is_some() {
            return self.advance_amnezia_junk(dst);
        }

        if self.handshake.is_expired() {
            return TunnResult::Err(WireGuardError::ConnectionExpired);
        }

        // Load timers only once:
        let session_established = self.timers[TimeSessionEstablished];
        let aut_packet_received = self.timers[TimeLastPacketReceived];
        let aut_packet_sent = self.timers[TimeLastPacketSent];
        let data_packet_received = self.timers[TimeLastDataPacketReceived];
        let data_packet_sent = self.timers[TimeLastDataPacketSent];
        let persistent_keepalive = self.timers.persistent_keepalive;

        {
            // Clear cookie after COOKIE_EXPIRATION_TIME
            if self.handshake.has_cookie()
                && now - self.timers[TimeCookieReceived] >= COOKIE_EXPIRATION_TIME
            {
                self.handshake.clear_cookie();
            }

            // All ephemeral private keys and symmetric session keys are zeroed out after
            // (REJECT_AFTER_TIME * 3) ms if no new keys have been exchanged.
            // The tunable's high end stands in when configured, exactly as
            // upstream arms zeroKeyMaterial at keychainExpireTime() * 3.
            if now - session_established >= self.amnezia.timers.keychain_expire() * 3 {
                tracing::error!("CONNECTION_EXPIRED(REJECT_AFTER_TIME * 3)");
                self.handshake.set_expired();
                self.clear_all();
                return TunnResult::Err(WireGuardError::ConnectionExpired);
            }

            if let Some(time_init_sent) = self.handshake.timer() {
                // Handshake Initiation Retransmission.
                //
                // We avoid using `time` here, because it can be earlier than
                // `time_init_sent`. Once `checked_duration_since` is stable we
                // can use that. A handshake initiation is retried after
                // REKEY_TIMEOUT (or a draw from the configured rekey_timeout
                // range, made at the previous send) if a response has not been
                // received.
                if time_init_sent.elapsed() >= self.timers.retransmit_current {
                    // Giving up is counted, not timed, and the count is checked
                    // here rather than beside the wall clock: a separate
                    // give-up deadline races the retransmission one, and with a
                    // `rekey_timeout` range wide enough that a draw exceeds it,
                    // the race is lost before the first retry is ever sent.
                    // Upstream reaches its own limit the same way -- inside the
                    // retransmit handler, never in parallel with it.
                    //
                    // After the cycle's attempt count is used up the retries
                    // cease and every packet queued up to be sent is cleared.
                    // If a packet is explicitly queued up to be sent, then this
                    // timer is reset.
                    if self.timers.handshake_attempts >= self.timers.max_attempts_current {
                        tracing::error!("CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME)");
                        self.handshake.set_expired();
                        self.clear_all();
                        return TunnResult::Err(WireGuardError::ConnectionExpired);
                    }

                    tracing::warn!("HANDSHAKE(REKEY_TIMEOUT)");
                    handshake_initiation_required = true;
                }
            } else {
                if self.timers.is_initiator() {
                    // After sending a packet, if the sender was the original initiator
                    // of the handshake and if the current session key is REKEY_AFTER_TIME
                    // ms old (one draw per session when the range is configured), we
                    // initiate a new handshake. If the sender was the original
                    // responder of the handshake, it does not re-initiate a new handshake
                    // after REKEY_AFTER_TIME ms like the original initiator does.
                    if session_established < data_packet_sent
                        && now - session_established >= self.timers.rekey_after_current
                    {
                        tracing::debug!("HANDSHAKE(REKEY_AFTER_TIME (on send))");
                        handshake_initiation_required = true;
                    }

                    // After receiving a packet, if the receiver was the original initiator
                    // of the handshake and if the current session key is REJECT_AFTER_TIME
                    // - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT ms old (drawn per session,
                    // saturating, when configured), we initiate a new handshake.
                    if session_established < data_packet_received
                        && now - session_established >= self.timers.refresh_receive_current
                    {
                        tracing::warn!(
                            "HANDSHAKE(REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - \
                        REKEY_TIMEOUT \
                        (on receive))"
                        );
                        handshake_initiation_required = true;
                    }
                }

                // If we have sent a packet to a given peer but have not received a
                // packet after from that peer for (KEEPALIVE + REKEY_TIMEOUT) ms
                // (keepalive high end plus a rekey_timeout draw, made when the
                // latch armed), we initiate a new handshake.
                if data_packet_sent > aut_packet_received
                    && now - aut_packet_received >= self.timers.new_handshake_current
                    && mem::replace(&mut self.timers.want_handshake, false)
                {
                    tracing::warn!("HANDSHAKE(KEEPALIVE + REKEY_TIMEOUT)");
                    handshake_initiation_required = true;
                }

                if !handshake_initiation_required {
                    // If a packet has been received from a given peer, but we have not sent one back
                    // to the given peer in KEEPALIVE ms (drawn when the latch armed,
                    // when configured), we send an empty packet.
                    if data_packet_received > aut_packet_sent
                        && now - aut_packet_sent >= self.timers.keepalive_current
                        && mem::replace(&mut self.timers.want_keepalive, false)
                    {
                        tracing::debug!("KEEPALIVE(KEEPALIVE_TIMEOUT)");
                        keepalive_required = true;
                    }

                    // Persistent KEEPALIVE
                    if persistent_keepalive > 0
                        && (now - self.timers[TimePersistentKeepalive]
                            >= Duration::from_secs(persistent_keepalive as _))
                    {
                        tracing::debug!("KEEPALIVE(PERSISTENT_KEEPALIVE)");
                        self.timer_tick(TimePersistentKeepalive);
                        keepalive_required = true;
                    }
                }
            }
        }

        if handshake_initiation_required {
            return self.format_handshake_initiation(dst, true);
        }

        if keepalive_required {
            return self.encapsulate(&[], dst);
        }

        TunnResult::Done
    }

    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        let current_session = self.current;
        if self.sessions[current_session % super::N_SESSIONS].is_some() {
            let duration_since_tun_start = Instant::now().duration_since(self.timers.time_started);
            let duration_since_session_established = self.timers[TimeSessionEstablished];

            Some(duration_since_tun_start - duration_since_session_established)
        } else {
            None
        }
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        let keepalive = self.timers.persistent_keepalive;

        if keepalive > 0 {
            Some(keepalive as u16)
        } else {
            None
        }
    }
}

impl Timers {
    /// Replace the persistent-keepalive interval. `None` (or zero) disables it,
    /// matching how [`Timers::new`] interprets the same argument.
    pub(super) fn set_persistent_keepalive(&mut self, keepalive: Option<u16>) {
        self.persistent_keepalive = usize::from(keepalive.unwrap_or(0));
    }
}
