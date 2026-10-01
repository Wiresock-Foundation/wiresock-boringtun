// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! What the OS said about the Device's UDP sends, and about errors on a
//! peer's connected socket -- reported, bounded, and nothing else.
//!
//! Before this module every Device send discarded its `io::Result`, and the
//! connected-socket receive loop ended silently on any error, so a refused
//! route, a pending ICMP error or an EMSGSIZE left no trace. A failed send is
//! still exactly what it was: a datagram lost, as if on the network. Nothing
//! here retries, re-queues, rolls back a counter or a timer, or touches the
//! tunnel. The observers see diagnostics metadata and lengths, never `Tunn`,
//! `Endpoint`, queues or counters; the step functions do take `&mut Peer`,
//! because they pick the socket inside the existing handler flow, and for them
//! the same rule is a prohibition rather than a type: no `tunnel.` call, no
//! retry.
//!
//! # Shape
//!
//! Each Device send site calls one of six *steps*. A step builds the attempt's
//! metadata from values the handler already holds, makes exactly one call into
//! a *single-attempt boundary* -- the only place a socket is sent on or read
//! from -- and hands the result to an *observer*. Under `cfg(test)` the
//! boundary journals the attempt, lets a fault plan replace its result, and
//! journals the result; in production its body is the syscall alone. Unit
//! tests call the same steps the handlers call, so the wiring is tested
//! without root or a TUN device.
//!
//! # Policy
//!
//! Per peer there are two failure *episodes* -- one for the connected socket,
//! one for the shared listener path -- each keyed by a socket generation (and,
//! for the listener, the destination), plus one WARN and one ERROR cooldown of
//! 60 s. An actionable error on a configured peer's path WARNs at most once
//! per peer per cooldown; a persistent failure gets one summary per cooldown;
//! a lifecycle error -- a socket used outside its valid state -- ERRORs once
//! per generation. The first send success on the *same* identity closes the
//! episode with a DEBUG line that says only that local send acceptance
//! resumed. Cookie replies, probe replies, and replies on a connected socket
//! that may be a Tunn-formatted cookie reply can be paced by an attacker, so
//! they never WARN. A receive that ends because nothing is queued is how
//! every batch ends, and is silent.

use std::io;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::time::Duration;

use parking_lot::Mutex;
// `portable_atomic` for the 64-bit width, as everywhere else in this crate:
// see `probe_budget`.
use portable_atomic::{AtomicU64, Ordering};
use socket2::{SockAddr, Socket};

#[cfg(feature = "mock-instant")]
use mock_instant::thread_local::Instant;

#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;

use super::peer::Peer;

/// At most one WARN per peer per this long, across both of its episodes.
const WARN_COOLDOWN: Duration = Duration::from_secs(60);
/// At most one connected-socket lifecycle ERROR per peer per this long, and
/// one per Untracked listener family per device.
const ERROR_COOLDOWN: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------- generations

/// A socket's diagnostic identity.
///
/// Descriptor numbers cannot be one: the Device `dup`s every socket it
/// registers, and the kernel reuses a closed descriptor's number for the next
/// socket. A generation is handed out once per socket, never reused, and
/// shared by the clones of that one socket. `Untracked` is what the allocator
/// returns once its 2^64 values are spent: such a socket works exactly as any
/// other, its errors keep their severity, but it has no episode and never
/// claims a recovery.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum DiagGen {
    Tracked(NonZeroU64),
    Untracked,
}

impl DiagGen {
    fn tracked(self) -> Option<NonZeroU64> {
        match self {
            DiagGen::Tracked(g) => Some(g),
            DiagGen::Untracked => None,
        }
    }

    /// The `socket_gen` log field: the number, or 0, which no tracked
    /// generation ever is.
    fn field(self) -> u64 {
        self.tracked().map_or(0, NonZeroU64::get)
    }
}

/// Hands out `1..=u64::MAX` once each, then `Untracked` for ever: no wrap, no
/// reuse, no panic, and nothing that could fail the socket it names.
pub(super) struct GenAllocator {
    /// The next value to hand out; 0 once exhausted.
    next: AtomicU64,
}

impl GenAllocator {
    const fn new() -> Self {
        GenAllocator {
            next: AtomicU64::new(1),
        }
    }

    /// An isolated allocator for boundary tests; the process one is never
    /// driven near exhaustion.
    #[cfg(test)]
    pub(super) const fn starting_at(next: u64) -> Self {
        GenAllocator {
            next: AtomicU64::new(next),
        }
    }

    pub(super) fn allocate(&self) -> DiagGen {
        let previous = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                if next == 0 {
                    // Exhausted: leave it so.
                    None
                } else {
                    // Handing out u64::MAX moves to the exhausted state.
                    Some(next.checked_add(1).unwrap_or(0))
                }
            });
        match previous.ok().and_then(NonZeroU64::new) {
            Some(g) => DiagGen::Tracked(g),
            None => DiagGen::Untracked,
        }
    }
}

/// The only production allocator: an allocator, not a destination map.
static GENERATIONS: GenAllocator = GenAllocator::new();

/// A generation for a socket that now exists.
pub(super) fn allocate_generation() -> DiagGen {
    GENERATIONS.allocate()
}

pub(super) fn generations() -> &'static GenAllocator {
    &GENERATIONS
}

// ---------------------------------------------------------------- sites

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Family {
    V4,
    V6,
}

impl Family {
    fn slot(self) -> usize {
        match self {
            Family::V4 => 0,
            Family::V6 => 1,
        }
    }
}

/// One of the device's two listeners, by family and generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct ListenerId {
    pub(super) family: Family,
    pub(super) gen: DiagGen,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Op {
    Send,
    Recv,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Op::Send => "send",
            Op::Recv => "recv",
        }
    }
}

/// One variant per concrete socket operation in the Device: the eleven sends
/// and the connected receive. A test proves a branch is wired by the `Site`
/// its attempt carries, never by a shared path name.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub(super) enum Site {
    /// Timer output (handshake, keepalive, Jc junk, imitation) to an IPv4
    /// endpoint, on the IPv4 listener.
    TimerV4,
    /// The same to an IPv6 endpoint, on the IPv6 listener.
    TimerV6,
    /// A reply to an unauthenticated probe.
    ProbeReply,
    /// A cookie reply to an unauthenticated handshake under load.
    CookieReply,
    /// The output of an authenticated commit on the listener.
    HandshakeReply,
    /// A peer's queued packets, flushed on the listener.
    ListenerFlush,
    /// Output of `decapsulate` on a connected socket: a response, a
    /// keepalive, or a cookie reply to a datagram that spoofed the 4-tuple.
    ConnectedReply,
    /// A peer's queued packets, flushed on its connected socket.
    ConnectedFlush,
    /// Encapsulated TUN output on the peer's connected socket.
    TunConnected,
    /// Encapsulated TUN output to an IPv4 endpoint, on the IPv4 listener.
    TunV4,
    /// Encapsulated TUN output to an IPv6 endpoint, on the IPv6 listener.
    TunV6,
    /// The connected-socket receive loop.
    ConnectedRecv,
}

/// Who could have caused this operation, which is what bounds its severity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Provenance {
    /// A path that carries a configured peer's traffic. Only the *path* is
    /// claimed, never the message kind.
    ConfiguredPeer,
    /// A connected-socket reply that may be a cookie reply provoked by a
    /// spoofed 4-tuple. Owning a connected socket authenticates nothing.
    Mixed,
    /// A reply to a source nobody has authenticated.
    Unauthenticated,
    ConnectedRecv,
}

impl Site {
    fn provenance(self) -> Provenance {
        match self {
            Site::TimerV4
            | Site::TimerV6
            | Site::HandshakeReply
            | Site::ListenerFlush
            | Site::ConnectedFlush
            | Site::TunConnected
            | Site::TunV4
            | Site::TunV6 => Provenance::ConfiguredPeer,
            Site::ConnectedReply => Provenance::Mixed,
            Site::ProbeReply | Site::CookieReply => Provenance::Unauthenticated,
            Site::ConnectedRecv => Provenance::ConnectedRecv,
        }
    }

    /// The `path` log field.
    fn path(self) -> &'static str {
        match self {
            Site::TimerV4 | Site::TimerV6 => "timer",
            Site::ProbeReply => "probe-reply",
            Site::CookieReply => "cookie-reply",
            Site::HandshakeReply => "handshake-reply",
            Site::ListenerFlush => "listener-flush",
            Site::ConnectedReply => "connected-reply",
            Site::ConnectedFlush => "connected-flush",
            Site::TunConnected | Site::TunV4 | Site::TunV6 => "tun",
            Site::ConnectedRecv => "connected-recv",
        }
    }
}

/// Which socket an attempt used, by diagnostic identity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) enum SocketRef {
    Connected(DiagGen),
    Listener(ListenerId),
}

/// What an attempt was: copied scalars the step already holds -- no borrow,
/// no allocation, no OS query. Read only by the `cfg(test)` seam; production
/// builds it and lets it go.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct AttemptMeta {
    pub(super) site: Site,
    pub(super) socket: SocketRef,
    pub(super) dest: Option<SocketAddr>,
}

#[cfg(test)]
impl AttemptMeta {
    fn gen(&self) -> DiagGen {
        match self.socket {
            SocketRef::Connected(g) => g,
            SocketRef::Listener(id) => id.gen,
        }
    }
}

/// The socket and destination an observation is about.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Target {
    Connected {
        gen: DiagGen,
        to: Option<SocketAddr>,
    },
    Listener {
        id: ListenerId,
        to: SocketAddr,
    },
}

impl Target {
    fn identity(self) -> Option<Identity> {
        match self {
            Target::Connected { gen, .. } => gen.tracked().map(Identity::Connected),
            Target::Listener { id, to } => id.gen.tracked().map(|g| Identity::Listener(g, to)),
        }
    }

    fn gen(self) -> DiagGen {
        match self {
            Target::Connected { gen, .. } => gen,
            Target::Listener { id, .. } => id.gen,
        }
    }

    fn endpoint(self) -> Option<SocketAddr> {
        match self {
            Target::Connected { to, .. } => to,
            Target::Listener { to, .. } => Some(to),
        }
    }

    /// The `socket` log field.
    fn mode(self) -> &'static str {
        match self {
            Target::Connected { .. } => "connected",
            Target::Listener { .. } => "listener",
        }
    }
}

// ---------------------------------------------------------------- classifier

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Class {
    /// Momentary local resource/interrupt condition (WouldBlock, EINTR,
    /// ENOBUFS). The datagram is lost; that is the whole information.
    Transient,
    /// EMSGSIZE: a size / PMTU / configuration signal. Not a defect, not proof
    /// about the current path's MTU, and not retryable with the same bytes.
    Size,
    /// No usable route or source address for the destination.
    Route,
    /// The socket reported ECONNREFUSED.
    Refused,
    /// A local policy or argument refusal: prohibit or blackhole route,
    /// netfilter, a scopeless link-local destination.
    Policy,
    /// A LIVE socket used outside its valid state: a defect, never expected.
    Lifecycle,
    /// ANY non-WouldBlock error from a connected handler already known to be
    /// retired: retirement overrides classification, not only for
    /// ENOTCONN/EPIPE.
    Teardown,
    /// Anything else, including an `io::Error` without an errno.
    Unknown,
}

impl Class {
    fn as_str(self) -> &'static str {
        match self {
            Class::Transient => "transient",
            Class::Size => "size",
            Class::Route => "route",
            Class::Refused => "refused",
            Class::Policy => "policy",
            Class::Lifecycle => "lifecycle",
            Class::Teardown => "teardown",
            Class::Unknown => "unknown",
        }
    }
}

/// Classify a socket error, in this order: (1) a receive that ended because
/// nothing is queued is `None` -- how every batch ends, not a failure,
/// retired or not; (2) any other error from a handler already known retired
/// is `Teardown`; (3) the ordinary table.
///
/// Errnos are matched by `libc` name, never by number: Linux and Darwin
/// disagree on most of them (EHOSTUNREACH 113 vs 65, ENOBUFS 105 vs 55,
/// EMSGSIZE 90 vs 40). `ErrorKind::{HostUnreachable, ..}` would be neater but
/// is newer than the crate's 1.75 floor.
pub(super) fn classify(op: Op, e: &io::Error, retired: bool) -> Option<Class> {
    if op == Op::Recv && e.kind() == io::ErrorKind::WouldBlock {
        return None;
    }
    if retired {
        return Some(Class::Teardown);
    }
    if matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) {
        return Some(Class::Transient);
    }
    let Some(errno) = e.raw_os_error() else {
        return Some(Class::Unknown);
    };
    Some(match errno {
        libc::ENOBUFS => Class::Transient,
        libc::EMSGSIZE => Class::Size,
        libc::ENETUNREACH | libc::EHOSTUNREACH | libc::EHOSTDOWN | libc::EADDRNOTAVAIL => {
            Class::Route
        }
        // ICMP host isolated, as Linux converts it.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::ENONET => Class::Route,
        libc::ECONNREFUSED => Class::Refused,
        // EINVAL is ambiguous -- a blackhole route, a scopeless link-local
        // destination, or a bad argument -- and a route is the realistic
        // cause, so it is the operator's configuration, not a defect.
        libc::EACCES | libc::EPERM | libc::EINVAL => Class::Policy,
        // ENOTCONN/EPIPE only reach here from a live socket: a handler whose
        // socket the peer no longer commits was classified `Teardown` above.
        libc::EBADF
        | libc::ENOTSOCK
        | libc::EAFNOSUPPORT
        | libc::EDESTADDRREQ
        | libc::EISCONN
        | libc::ENOTCONN
        | libc::EPIPE => Class::Lifecycle,
        _ => Class::Unknown,
    })
}

// ---------------------------------------------------------------- attempts

/// Which attempt a decision belongs to. In test builds a fixture id and an
/// attempt id, carried explicitly from the boundary to the observer -- never
/// a thread's "last attempt". In production it is zero-sized.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct AttemptToken {
    pub(super) fixture: u64,
    pub(super) id: u64,
}

#[cfg(not(test))]
#[derive(Clone, Copy)]
pub(super) struct AttemptToken;

/// What a single-attempt boundary returns: the OS result, untouched, and the
/// token the step passes on to the observer.
pub(super) struct Attempt {
    pub(super) result: io::Result<usize>,
    pub(super) token: AttemptToken,
}

/// Every line an observation can produce.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Line {
    /// The first WARN of an episode (or any Untracked WARN).
    WarnOpening,
    /// A later WARN of the same, still-failing episode.
    WarnSummary,
    ErrorConnected,
    ErrorListener,
    DebugFailure,
    DebugRecovery,
    DebugClosed,
    DebugRetired,
}

// ---------------------------------------------------------------- device-wide state

/// The diagnostics state one `Device` owns: the clock epoch and the listener
/// lifecycle latches, which belong to the listener sockets every peer shares
/// rather than to any peer -- one broken listener must not ERROR once per
/// peer. In test builds also the manual clock, the fault plan and the journal,
/// per device, so parallel tests never share them.
pub(super) struct DeviceUdpDiagnostics {
    epoch: Instant,
    /// Per family: the last tracked listener generation that ERRORed.
    listener_error_latch: [AtomicU64; 2],
    /// Per family, for an Untracked listener: when it last ERRORed, as
    /// nanoseconds on this device's clock plus one (0: never).
    untracked_listener_error: [AtomicU64; 2],
    #[cfg(test)]
    seam: Seam,
}

impl DeviceUdpDiagnostics {
    pub(super) fn new() -> Self {
        DeviceUdpDiagnostics {
            epoch: Instant::now(),
            listener_error_latch: [AtomicU64::new(0), AtomicU64::new(0)],
            untracked_listener_error: [AtomicU64::new(0), AtomicU64::new(0)],
            #[cfg(test)]
            seam: Seam::new(),
        }
    }

    /// Time since this device's epoch. Read only on failure paths and on a
    /// same-identity recovery, never on a healthy send.
    fn now(&self) -> Duration {
        #[cfg(test)]
        {
            self.seam.clock_reads.fetch_add(1, Ordering::Relaxed);
            if let Some(t) = *self.seam.manual_clock.lock() {
                // Manual mode: the stored value and nothing else.
                return t;
            }
            self.seam.wall_reads.fetch_add(1, Ordering::Relaxed);
        }
        Instant::now().duration_since(self.epoch)
    }

    /// Whether a listener lifecycle failure gets its ERROR: once per tracked
    /// listener generation per family, or once per cooldown per family for an
    /// Untracked listener. Device-wide, whichever peer or reply hit it.
    fn listener_error_first(&self, id: ListenerId, now: impl FnOnce() -> Duration) -> bool {
        let slot = id.family.slot();
        match id.gen.tracked() {
            Some(g) => self.listener_error_latch[slot].swap(g.get(), Ordering::Relaxed) != g.get(),
            None => {
                let at = (now().as_nanos().min(u128::from(u64::MAX - 1)) as u64) + 1;
                let cooldown = ERROR_COOLDOWN.as_nanos() as u64;
                self.untracked_listener_error[slot]
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                        (last == 0 || at.saturating_sub(last) >= cooldown).then_some(at)
                    })
                    .is_ok()
            }
        }
    }

    /// Journal a decision (test builds); nothing in production.
    #[inline(always)]
    fn note_decision(
        &self,
        attempt: Option<AttemptToken>,
        line: Line,
        class: Option<Class>,
        peer: Option<u32>,
        gen: DiagGen,
    ) {
        #[cfg(test)]
        self.seam.push(JournalEvent::Decision {
            attempt,
            line,
            class,
            peer,
            gen,
        });
        #[cfg(not(test))]
        let _ = (attempt, line, class, peer, gen);
    }
}

// ---------------------------------------------------------------- single-attempt boundaries

// Exactly one syscall expression each, and nothing that loops. Under
// `cfg(test)`: (A) the attempt is journaled, (B) the fault plan decides, the
// syscall or the injected error, (C) the result is journaled. An injected
// failure is therefore always an attempt, and a retry anywhere above a
// boundary meets the plan's next step. The observer cannot tell an injected
// error from a real one.

#[cfg_attr(not(test), allow(unused_variables))]
#[inline]
pub(super) fn single_send_attempt(
    env: &DeviceUdpDiagnostics,
    sock: &Socket,
    meta: AttemptMeta,
    buf: &[u8],
) -> Attempt {
    #[cfg(not(test))]
    let token = AttemptToken;
    #[cfg(test)]
    let (token, injected) = env.seam_begin(Op::Send, meta);
    #[cfg(test)]
    if let Some(e) = injected {
        let result = Err(e);
        env.seam_finish(token, true, &result);
        return Attempt { result, token };
    }
    let result = sock.send(buf);
    #[cfg(test)]
    env.seam_finish(token, false, &result);
    Attempt { result, token }
}

#[cfg_attr(not(test), allow(unused_variables))]
#[inline]
pub(super) fn single_send_to_attempt(
    env: &DeviceUdpDiagnostics,
    sock: &Socket,
    meta: AttemptMeta,
    buf: &[u8],
    to: &SockAddr,
) -> Attempt {
    #[cfg(not(test))]
    let token = AttemptToken;
    #[cfg(test)]
    let (token, injected) = env.seam_begin(Op::Send, meta);
    #[cfg(test)]
    if let Some(e) = injected {
        let result = Err(e);
        env.seam_finish(token, true, &result);
        return Attempt { result, token };
    }
    let result = sock.send_to(buf, to);
    #[cfg(test)]
    env.seam_finish(token, false, &result);
    Attempt { result, token }
}

#[cfg_attr(not(test), allow(unused_variables))]
#[inline]
pub(super) fn single_recv_attempt(
    env: &DeviceUdpDiagnostics,
    sock: &Socket,
    meta: AttemptMeta,
    buf: &mut [MaybeUninit<u8>],
) -> Attempt {
    #[cfg(not(test))]
    let token = AttemptToken;
    #[cfg(test)]
    let (token, injected) = env.seam_begin(Op::Recv, meta);
    #[cfg(test)]
    if let Some(e) = injected {
        let result = Err(e);
        env.seam_finish(token, true, &result);
        return Attempt { result, token };
    }
    let result = sock.recv(buf);
    #[cfg(test)]
    env.seam_finish(token, false, &result);
    Attempt { result, token }
}

/// A receive that ended because nothing is queued: the normal end of a batch.
fn recv_end_is_quiet(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::WouldBlock
}

// ---------------------------------------------------------------- steps

// The only diagnostics code the Device handlers call: one step per family of
// send sites, plus the connected receive. A step selects the socket exactly
// as the handler did before, makes one boundary call and one observation.
// It never calls into the tunnel and never retries.

/// Timer output (sites #1/#2): to the peer's endpoint, on the listener of the
/// endpoint's family.
#[allow(clippy::too_many_arguments)]
pub(super) fn timer_send_step(
    env: &DeviceUdpDiagnostics,
    p: &mut Peer,
    udp4: &Socket,
    id4: ListenerId,
    udp6: &Socket,
    id6: ListenerId,
    endpoint: SocketAddr,
    packet: &[u8],
) {
    let (sock, id, site) = match endpoint {
        SocketAddr::V4(_) => (udp4, id4, Site::TimerV4),
        SocketAddr::V6(_) => (udp6, id6, Site::TimerV6),
    };
    let meta = AttemptMeta {
        site,
        socket: SocketRef::Listener(id),
        dest: Some(endpoint),
    };
    let attempt = single_send_to_attempt(env, sock, meta, packet, &endpoint.into());
    let peer = p.index();
    let target = Target::Listener { id, to: endpoint };
    observe_peer_send(
        env,
        p.udp_diagnostics_mut(),
        peer,
        target,
        site,
        packet.len(),
        &attempt,
        false,
    );
}

/// A probe reply (#3) or cookie reply (#4): to an unauthenticated source, on
/// the listener that received from it.
pub(super) fn unauthenticated_send_step(
    env: &DeviceUdpDiagnostics,
    udp: &Socket,
    id: ListenerId,
    site: Site,
    buf: &[u8],
    from: SocketAddr,
    to: &SockAddr,
) {
    let meta = AttemptMeta {
        site,
        socket: SocketRef::Listener(id),
        dest: Some(from),
    };
    let attempt = single_send_to_attempt(env, udp, meta, buf, to);
    observe_unauthenticated_send(env, id, site, from, buf.len(), &attempt);
}

/// An authenticated commit's output (#5) or a queued flush (#6), on the
/// listener that received the peer's datagram.
#[allow(clippy::too_many_arguments)]
pub(super) fn listener_peer_send_step(
    env: &DeviceUdpDiagnostics,
    p: &mut Peer,
    udp: &Socket,
    id: ListenerId,
    site: Site,
    packet: &[u8],
    from: SocketAddr,
    to: &SockAddr,
) {
    let meta = AttemptMeta {
        site,
        socket: SocketRef::Listener(id),
        dest: Some(from),
    };
    let attempt = single_send_to_attempt(env, udp, meta, packet, to);
    let peer = p.index();
    let target = Target::Listener { id, to: from };
    observe_peer_send(
        env,
        p.udp_diagnostics_mut(),
        peer,
        target,
        site,
        packet.len(),
        &attempt,
        false,
    );
}

/// A reply (#7) or flush (#8) on the connected socket whose handler this is.
/// The handler may outlive the peer's commitment to its socket -- a roam or
/// an expiry takes `endpoint.conn` first -- so an error is checked against
/// the generation the peer commits now. Only on `Err`: a success never takes
/// the endpoint lock.
#[allow(clippy::too_many_arguments)]
pub(super) fn connected_send_step(
    env: &DeviceUdpDiagnostics,
    p: &mut Peer,
    udp: &Socket,
    gen: DiagGen,
    endpoint: SocketAddr,
    site: Site,
    packet: &[u8],
) {
    let meta = AttemptMeta {
        site,
        socket: SocketRef::Connected(gen),
        dest: Some(endpoint),
    };
    let attempt = single_send_attempt(env, udp, meta, packet);
    let retired = attempt.result.is_err() && p.connected_generation() != Some(gen);
    let peer = p.index();
    let target = Target::Connected {
        gen,
        to: Some(endpoint),
    };
    observe_peer_send(
        env,
        p.udp_diagnostics_mut(),
        peer,
        target,
        site,
        packet.len(),
        &attempt,
        retired,
    );
}

/// What the connected receive loop does next.
pub(super) enum RecvStep {
    Datagram(usize),
    End,
}

/// One receive on a peer's connected socket. A datagram is never an
/// observation: receiving says nothing about whether sends are accepted. An
/// error ends the batch exactly as it always did; only a non-quiet one takes
/// the peer lock, once, to be observed. Pending socket errors -- an ICMP
/// refusal, an EMSGSIZE -- are delivered to whichever of send or receive runs
/// next, and on a connected socket this loop is usually where they surface.
pub(super) fn conn_recv_step(
    env: &DeviceUdpDiagnostics,
    peer: &Mutex<Peer>,
    udp: &Socket,
    gen: DiagGen,
    endpoint: SocketAddr,
    buf: &mut [MaybeUninit<u8>],
) -> RecvStep {
    let meta = AttemptMeta {
        site: Site::ConnectedRecv,
        socket: SocketRef::Connected(gen),
        dest: Some(endpoint),
    };
    let attempt = single_recv_attempt(env, udp, meta, buf);
    match attempt.result {
        Ok(n) => RecvStep::Datagram(n),
        Err(e) => {
            if !recv_end_is_quiet(&e) {
                let mut p = peer.lock();
                let retired = p.connected_generation() != Some(gen);
                let index = p.index();
                observe_peer_recv_error(
                    env,
                    p.udp_diagnostics_mut(),
                    index,
                    gen,
                    Some(endpoint),
                    &e,
                    attempt.token,
                    retired,
                );
            }
            RecvStep::End
        }
    }
}

/// Encapsulated TUN output (#9-#11), in the order the handler always used:
/// the peer's connected socket, else the listener of its endpoint's family.
/// Sent under the endpoint's *read* guard -- a connected socket sends through
/// `&self` -- and observed once the guard is gone. Returns `false` when there
/// is neither a connected socket nor an address; nothing is sent then.
pub(super) fn tun_send_step(
    env: &DeviceUdpDiagnostics,
    peer: &mut Peer,
    udp4: &Socket,
    id4: ListenerId,
    udp6: &Socket,
    id6: ListenerId,
    packet: &[u8],
) -> bool {
    let (attempt, target, site) = {
        let endpoint = peer.endpoint();
        if let Some(conn) = endpoint.conn.as_ref() {
            // Not `connected_generation()`: that takes this same lock again.
            let gen = peer.assigned_connected_generation();
            let to = endpoint.addr;
            let meta = AttemptMeta {
                site: Site::TunConnected,
                socket: SocketRef::Connected(gen),
                dest: to,
            };
            (
                single_send_attempt(env, conn, meta, packet),
                Target::Connected { gen, to },
                Site::TunConnected,
            )
        } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
            let meta = AttemptMeta {
                site: Site::TunV4,
                socket: SocketRef::Listener(id4),
                dest: Some(addr),
            };
            (
                single_send_to_attempt(env, udp4, meta, packet, &addr.into()),
                Target::Listener { id: id4, to: addr },
                Site::TunV4,
            )
        } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
            let meta = AttemptMeta {
                site: Site::TunV6,
                socket: SocketRef::Listener(id6),
                dest: Some(addr),
            };
            (
                single_send_to_attempt(env, udp6, meta, packet, &addr.into()),
                Target::Listener { id: id6, to: addr },
                Site::TunV6,
            )
        } else {
            return false;
        }
    };
    let index = peer.index();
    observe_peer_send(
        env,
        peer.udp_diagnostics_mut(),
        index,
        target,
        site,
        packet.len(),
        &attempt,
        false,
    );
    true
}

/// Device plumbing at the connected-socket upgrade: give the peer's freshly
/// committed socket a generation, and record what that did to its episode.
/// Called under the same peer lock as the commit, so nothing can observe the
/// new socket under the old generation.
pub(super) fn commit_connected_socket(env: &DeviceUdpDiagnostics, p: &mut Peer) -> DiagGen {
    let (gen, decision) = p.assign_connected_generation();
    record_replacement(env, p.index(), gen, decision);
    gen
}

// ---------------------------------------------------------------- episodes

/// What a failure episode is about: a tracked connected socket, or a tracked
/// listener and the destination it was sending to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Identity {
    Connected(NonZeroU64),
    Listener(NonZeroU64, SocketAddr),
}

/// The class and raw errno of an episode's latest failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Failure {
    class: Class,
    os_error: Option<i32>,
}

#[derive(Default, Debug)]
struct Episode {
    identity: Option<Identity>,
    /// A failure since the last same-identity send success.
    active: bool,
    /// This episode has produced a WARN or ERROR line.
    announced: bool,
    /// A lifecycle ERROR has been emitted for this identity.
    error_latched: bool,
    /// Saturating.
    failures: u32,
    last: Option<Failure>,
}

/// One peer's failure state: a plain field of `Peer`, mutated under the peer
/// lock its sites already hold. No interior mutability, no heap.
#[derive(Default, Debug)]
pub(super) struct PeerUdpDiagnostics {
    connected: Episode,
    listener: Episode,
    /// When this peer last WARNed, on either record.
    last_warn: Option<Duration>,
    /// When this peer last ERRORed for a connected socket.
    last_error: Option<Duration>,
}

/// What committing a new connected socket did to the CONNECTED record. A
/// plain value, so the episode state never touches tracing: the Device
/// records it with [`record_replacement`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum ReplacementDecision {
    /// Nothing was active; the record now names the new socket (or nothing,
    /// for an Untracked one).
    Rekeyed,
    /// An active episode of the previous socket was closed.
    ClosedEpisode {
        last: Option<Failure>,
        failures: u32,
    },
}

/// Inclusive: at exactly `cooldown` after `anchor` the window is open.
fn open(anchor: Option<Duration>, now: Duration, cooldown: Duration) -> bool {
    anchor.map_or(true, |t| now.saturating_sub(t) >= cooldown)
}

impl PeerUdpDiagnostics {
    fn record(&self, t: Target) -> &Episode {
        match t {
            Target::Connected { .. } => &self.connected,
            Target::Listener { .. } => &self.listener,
        }
    }

    fn record_mut(&mut self, t: Target) -> &mut Episode {
        match t {
            Target::Connected { .. } => &mut self.connected,
            Target::Listener { .. } => &mut self.listener,
        }
    }

    /// Re-key CONNECTED to a newly committed socket. Once it names the new
    /// generation, nothing the old socket's handler reports can touch it.
    /// The cooldown anchors are kept: a new socket is no reason to WARN again.
    pub(super) fn replace_connected(&mut self, gen: DiagGen) -> ReplacementDecision {
        let new = gen.tracked().map(Identity::Connected);
        let decision = if self.connected.active && self.connected.identity != new {
            ReplacementDecision::ClosedEpisode {
                last: self.connected.last,
                failures: self.connected.failures,
            }
        } else {
            ReplacementDecision::Rekeyed
        };
        if self.connected.identity != new || new.is_none() {
            self.connected = Episode {
                identity: new,
                ..Episode::default()
            };
        }
        decision
    }
}

// ---------------------------------------------------------------- observers

/// A send on a configured peer's path, or on its connected socket. The
/// healthy case -- a success with no active episode for that record -- reads
/// no clock, takes no lock and formats nothing.
#[allow(clippy::too_many_arguments)]
pub(super) fn observe_peer_send(
    env: &DeviceUdpDiagnostics,
    diag: &mut PeerUdpDiagnostics,
    peer: u32,
    target: Target,
    site: Site,
    len: usize,
    attempt: &Attempt,
    retired: bool,
) {
    match &attempt.result {
        Ok(_) if !diag.record(target).active => {}
        Ok(_) => success_slow(env, diag, peer, target, site, attempt.token),
        Err(e) => failure(
            env,
            diag,
            peer,
            target,
            site,
            Op::Send,
            Some(len),
            e,
            attempt.token,
            retired,
        ),
    }
}

/// A non-quiet error from a connected socket's receive. No length: the
/// datagram an EMSGSIZE refers to was an earlier one, of unknown size.
#[allow(clippy::too_many_arguments)]
pub(super) fn observe_peer_recv_error(
    env: &DeviceUdpDiagnostics,
    diag: &mut PeerUdpDiagnostics,
    peer: u32,
    gen: DiagGen,
    to: Option<SocketAddr>,
    e: &io::Error,
    token: AttemptToken,
    retired: bool,
) {
    let target = Target::Connected { gen, to };
    failure(
        env,
        diag,
        peer,
        target,
        Site::ConnectedRecv,
        Op::Recv,
        None,
        e,
        token,
        retired,
    );
}

/// A probe or cookie reply. Attacker-paced and to an unverified source, so
/// never a WARN, never an episode; only a broken listener socket ERRORs, once
/// per listener generation.
pub(super) fn observe_unauthenticated_send(
    env: &DeviceUdpDiagnostics,
    id: ListenerId,
    site: Site,
    to: SocketAddr,
    len: usize,
    attempt: &Attempt,
) {
    let Err(e) = &attempt.result else {
        return;
    };
    unauthenticated_failure(env, id, site, to, len, e, attempt.token);
}

/// Record a connected-socket replacement's decision. Not caused by any socket
/// attempt, so it carries none.
pub(super) fn record_replacement(
    env: &DeviceUdpDiagnostics,
    peer: u32,
    gen: DiagGen,
    decision: ReplacementDecision,
) {
    if let ReplacementDecision::ClosedEpisode { last, failures } = decision {
        emit_closed(env, peer, "connected", last, failures, gen);
    }
}

#[cold]
#[inline(never)]
fn unauthenticated_failure(
    env: &DeviceUdpDiagnostics,
    id: ListenerId,
    site: Site,
    to: SocketAddr,
    len: usize,
    e: &io::Error,
    token: AttemptToken,
) {
    let class = classify(Op::Send, e, false).unwrap_or(Class::Unknown);
    let ctx = Ctx {
        who: Who::Unauthenticated,
        endpoint: Some(to),
        op: Op::Send,
        site,
        mode: "listener",
        gen: id.gen,
        len: Some(len),
        attempt: Some(token),
    };
    let line = if class == Class::Lifecycle && env.listener_error_first(id, || env.now()) {
        Line::ErrorListener
    } else {
        Line::DebugFailure
    };
    emit_failure(env, line, class, e, &ctx);
}

/// A send success while the target's record is active.
#[cold]
#[inline(never)]
fn success_slow(
    env: &DeviceUdpDiagnostics,
    diag: &mut PeerUdpDiagnostics,
    peer: u32,
    target: Target,
    site: Site,
    token: AttemptToken,
) {
    // Untracked: no identity, so no recovery to claim.
    let Some(id) = target.identity() else {
        return;
    };
    let rec = diag.record_mut(target);
    if rec.identity == Some(id) {
        emit_recovery(env, peer, target, site, rec.last, rec.failures, token);
        rec.active = false;
        rec.announced = false;
        rec.failures = 0;
        rec.last = None;
    } else {
        match target {
            // A listener target is always the current listener and
            // destination, so the record moves to it.
            Target::Listener { .. } => {
                if rec.active {
                    emit_closed(
                        env,
                        peer,
                        target.mode(),
                        rec.last,
                        rec.failures,
                        target.gen(),
                    );
                }
                *rec = Episode {
                    identity: Some(id),
                    ..Episode::default()
                };
            }
            // A late success of a replaced connected socket: its episode was
            // closed at the replacement, and the new one is not its to touch.
            Target::Connected { .. } => {}
        }
    }
    // A success never moves a cooldown anchor.
}

#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn failure(
    env: &DeviceUdpDiagnostics,
    diag: &mut PeerUdpDiagnostics,
    peer: u32,
    target: Target,
    site: Site,
    op: Op,
    len: Option<usize>,
    e: &io::Error,
    token: AttemptToken,
    retired: bool,
) {
    let Some(class) = classify(op, e, retired) else {
        return;
    };
    let mut ctx = Ctx {
        who: Who::PeerNoEpisode(peer),
        endpoint: target.endpoint(),
        op,
        site,
        mode: target.mode(),
        gen: target.gen(),
        len,
        attempt: Some(token),
    };
    if class == Class::Teardown {
        emit_failure(env, Line::DebugRetired, class, e, &ctx);
        return;
    }
    // An interrupted or starved receive says nothing about send acceptance.
    if op == Op::Recv && class == Class::Transient {
        emit_failure(env, Line::DebugFailure, class, e, &ctx);
        return;
    }
    let eligible = matches!(
        site.provenance(),
        Provenance::ConfiguredPeer | Provenance::ConnectedRecv
    );
    let now = env.now();
    let Some(id) = target.identity() else {
        let line = untracked_line(env, diag, target, class, eligible, now);
        emit_failure(env, line, class, e, &ctx);
        return;
    };
    let (last_warn, last_error) = (diag.last_warn, diag.last_error);
    let mut set_warn = false;
    let mut set_error = false;
    let line = {
        let rec = diag.record_mut(target);
        if rec.identity != Some(id) {
            if rec.active {
                emit_closed(
                    env,
                    peer,
                    target.mode(),
                    rec.last,
                    rec.failures,
                    target.gen(),
                );
            }
            *rec = Episode {
                identity: Some(id),
                ..Episode::default()
            };
        }
        if !rec.active {
            rec.active = true;
            rec.failures = 0;
            rec.announced = false;
        }
        rec.failures = rec.failures.saturating_add(1);
        rec.last = Some(Failure {
            class,
            os_error: e.raw_os_error(),
        });
        ctx.who = Who::PeerEpisode(peer, rec.failures);
        match class {
            Class::Lifecycle => match target {
                Target::Connected { .. } => {
                    if !rec.error_latched && open(last_error, now, ERROR_COOLDOWN) {
                        rec.error_latched = true;
                        rec.announced = true;
                        set_error = true;
                        Line::ErrorConnected
                    } else {
                        Line::DebugFailure
                    }
                }
                Target::Listener { id, .. } => {
                    if env.listener_error_first(id, || now) {
                        rec.announced = true;
                        Line::ErrorListener
                    } else {
                        Line::DebugFailure
                    }
                }
            },
            Class::Size | Class::Route | Class::Refused | Class::Policy | Class::Unknown
                if eligible =>
            {
                if open(last_warn, now, WARN_COOLDOWN) {
                    let summary = rec.announced;
                    rec.announced = true;
                    set_warn = true;
                    if summary {
                        Line::WarnSummary
                    } else {
                        Line::WarnOpening
                    }
                } else {
                    Line::DebugFailure
                }
            }
            // Transient sends, and anything on the mixed reply path: counted
            // in the episode, never above DEBUG.
            _ => Line::DebugFailure,
        }
    };
    if set_warn {
        diag.last_warn = Some(now);
    }
    if set_error {
        diag.last_error = Some(now);
    }
    emit_failure(env, line, class, e, &ctx);
}

/// An Untracked socket keeps the severity a tracked one would get, bounded by
/// the same cooldowns, with no episode -- and so no summary and no recovery.
fn untracked_line(
    env: &DeviceUdpDiagnostics,
    diag: &mut PeerUdpDiagnostics,
    target: Target,
    class: Class,
    eligible: bool,
    now: Duration,
) -> Line {
    match class {
        Class::Lifecycle => match target {
            Target::Connected { .. } => {
                if open(diag.last_error, now, ERROR_COOLDOWN) {
                    diag.last_error = Some(now);
                    Line::ErrorConnected
                } else {
                    Line::DebugFailure
                }
            }
            Target::Listener { id, .. } => {
                if env.listener_error_first(id, || now) {
                    Line::ErrorListener
                } else {
                    Line::DebugFailure
                }
            }
        },
        Class::Size | Class::Route | Class::Refused | Class::Policy | Class::Unknown
            if eligible =>
        {
            if open(diag.last_warn, now, WARN_COOLDOWN) {
                diag.last_warn = Some(now);
                Line::WarnOpening
            } else {
                Line::DebugFailure
            }
        }
        _ => Line::DebugFailure,
    }
}

// ---------------------------------------------------------------- emission

/// Which of the failure field sets a line carries.
#[derive(Clone, Copy)]
enum Who {
    /// A line of a tracked episode: `peer` and `failures`.
    PeerEpisode(u32, u32),
    /// A peer line with no episode (Untracked, teardown, receive transient):
    /// `peer` only.
    PeerNoEpisode(u32),
    /// Probe or cookie reply: neither.
    Unauthenticated,
}

struct Ctx {
    who: Who,
    endpoint: Option<SocketAddr>,
    op: Op,
    site: Site,
    mode: &'static str,
    gen: DiagGen,
    /// Sends only: the attempted datagram's length.
    len: Option<usize>,
    attempt: Option<AttemptToken>,
}

/// An address for a log field, or `none`; formatted only when the line is.
struct ShownAddr(Option<SocketAddr>);

impl std::fmt::Display for ShownAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(addr) => addr.fmt(f),
            None => f.write_str("none"),
        }
    }
}

/// The opening line of an episode, or an Untracked WARN: what the socket
/// reported, never a cause it did not report.
fn observation(class: Class, op: Op) -> &'static str {
    match (class, op) {
        (Class::Size, Op::Send) => {
            "UDP send to peer not accepted: socket reported message too long"
        }
        (Class::Size, Op::Recv) => {
            "connected UDP socket for peer reported a pending message-too-long error"
        }
        (Class::Route, Op::Send) => {
            "UDP send to peer not accepted: socket reported no route or no usable address"
        }
        (Class::Route, Op::Recv) => {
            "connected UDP socket for peer reported no route or no usable address"
        }
        (Class::Refused, Op::Send) => {
            "UDP send to peer not accepted: socket reported connection refusal"
        }
        (Class::Refused, Op::Recv) => "connected UDP socket for peer reported connection refusal",
        (Class::Policy, Op::Send) => {
            "UDP send to peer not accepted: socket reported a permission or argument refusal"
        }
        (Class::Policy, Op::Recv) => {
            "connected UDP socket for peer reported a permission or argument refusal"
        }
        (_, Op::Send) => "UDP send to peer not accepted: socket reported an unclassified error",
        (_, Op::Recv) => "connected UDP socket for peer reported an unclassified error",
    }
}

fn emit_failure(env: &DeviceUdpDiagnostics, line: Line, class: Class, e: &io::Error, c: &Ctx) {
    let peer = match c.who {
        Who::PeerEpisode(p, _) | Who::PeerNoEpisode(p) => Some(p),
        Who::Unauthenticated => None,
    };
    env.note_decision(c.attempt, line, Some(class), peer, c.gen);

    let message = match line {
        Line::WarnOpening => observation(class, c.op),
        Line::WarnSummary => "UDP socket for peer still failing",
        Line::ErrorConnected => "UDP socket for peer reported an invalid-socket-state error",
        Line::ErrorListener => "listener UDP socket reported an invalid-socket-state error",
        Line::DebugRetired => "UDP operation on a retired connected socket failed",
        Line::DebugFailure | Line::DebugRecovery | Line::DebugClosed => {
            "UDP socket operation failed"
        }
    };
    let endpoint = ShownAddr(c.endpoint);
    let op = c.op.as_str();
    let path = c.site.path();
    let socket = c.mode;
    let os_error = e.raw_os_error();
    let error_kind = e.kind();
    let class = class.as_str();
    let socket_gen = c.gen.field();
    let len = c.len.unwrap_or(0);

    // One callsite per level and field set. `len` only on sends, `failures`
    // only in a tracked episode, `peer` never on an unauthenticated line.
    macro_rules! failure_event {
        ($level:ident) => {
            match (c.op, c.who) {
                (Op::Send, Who::PeerEpisode(peer, failures)) => tracing::$level!(
                    message,
                    peer,
                    endpoint = %endpoint,
                    op,
                    path,
                    socket,
                    os_error = ?os_error,
                    error_kind = ?error_kind,
                    class,
                    len,
                    failures,
                    socket_gen
                ),
                (Op::Send, Who::PeerNoEpisode(peer)) => tracing::$level!(
                    message,
                    peer,
                    endpoint = %endpoint,
                    op,
                    path,
                    socket,
                    os_error = ?os_error,
                    error_kind = ?error_kind,
                    class,
                    len,
                    socket_gen
                ),
                (Op::Send, Who::Unauthenticated) => tracing::$level!(
                    message,
                    endpoint = %endpoint,
                    op,
                    path,
                    socket,
                    os_error = ?os_error,
                    error_kind = ?error_kind,
                    class,
                    len,
                    socket_gen
                ),
                (Op::Recv, Who::PeerEpisode(peer, failures)) => tracing::$level!(
                    message,
                    peer,
                    endpoint = %endpoint,
                    op,
                    path,
                    socket,
                    os_error = ?os_error,
                    error_kind = ?error_kind,
                    class,
                    failures,
                    socket_gen
                ),
                (Op::Recv, Who::PeerNoEpisode(peer)) => tracing::$level!(
                    message,
                    peer,
                    endpoint = %endpoint,
                    op,
                    path,
                    socket,
                    os_error = ?os_error,
                    error_kind = ?error_kind,
                    class,
                    socket_gen
                ),
                // Receives are only ever observed for a peer's own socket.
                (Op::Recv, Who::Unauthenticated) => tracing::$level!(
                    message,
                    endpoint = %endpoint,
                    op,
                    path,
                    socket,
                    os_error = ?os_error,
                    error_kind = ?error_kind,
                    class,
                    socket_gen
                ),
            }
        };
    }
    match line {
        Line::WarnOpening | Line::WarnSummary => failure_event!(warn),
        Line::ErrorConnected | Line::ErrorListener => failure_event!(error),
        Line::DebugFailure | Line::DebugRetired | Line::DebugRecovery | Line::DebugClosed => {
            failure_event!(debug)
        }
    }
}

/// C: the same socket accepts sends again. That is all it claims -- not that
/// a route recovered, the peer is reachable, or anything arrived.
fn emit_recovery(
    env: &DeviceUdpDiagnostics,
    peer: u32,
    target: Target,
    site: Site,
    last: Option<Failure>,
    failures: u32,
    token: AttemptToken,
) {
    env.note_decision(
        Some(token),
        Line::DebugRecovery,
        last.map(|f| f.class),
        Some(peer),
        target.gen(),
    );
    let (previous_class, previous_os_error) =
        last.map_or(("", None), |f| (f.class.as_str(), f.os_error));
    tracing::debug!(
        message = "local socket send acceptance resumed",
        peer,
        endpoint = %ShownAddr(target.endpoint()),
        path = site.path(),
        socket = target.mode(),
        previous_class,
        previous_os_error = ?previous_os_error,
        failures,
        socket_gen = target.gen().field()
    );
}

/// C-closed: an active episode ended because its socket or destination
/// changed, not because anything succeeded. `socket_gen` names the identity
/// that replaces the closed one. Not caused by an attempt, so it carries
/// none.
fn emit_closed(
    env: &DeviceUdpDiagnostics,
    peer: u32,
    socket: &'static str,
    last: Option<Failure>,
    failures: u32,
    replacing: DiagGen,
) {
    env.note_decision(
        None,
        Line::DebugClosed,
        last.map(|f| f.class),
        Some(peer),
        replacing,
    );
    let (previous_class, previous_os_error) =
        last.map_or(("", None), |f| (f.class.as_str(), f.os_error));
    tracing::debug!(
        message = "UDP failure episode closed by a socket or endpoint change",
        peer,
        socket,
        previous_class,
        previous_os_error = ?previous_os_error,
        failures,
        socket_gen = replacing.field()
    );
}

// ---------------------------------------------------------------- test seam

/// One scripted outcome of a fault rule.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Step {
    Pass,
    Fail(i32),
}

/// Replace the results of the attempts it matches, in order: the k-th
/// matching attempt takes `script[k]`, and every attempt past the end passes.
/// A `None` field matches anything.
#[cfg(test)]
#[derive(Clone, Debug)]
pub(super) struct FaultRule {
    pub(super) op: Op,
    pub(super) site: Option<Site>,
    pub(super) socket: Option<DiagGen>,
    pub(super) dest: Option<SocketAddr>,
    pub(super) script: Vec<Step>,
}

#[cfg(test)]
impl FaultRule {
    /// Whether one attempt could match both rules. Rejected at install time:
    /// there is no precedence, so an overlap would be a guess.
    fn overlaps(&self, other: &FaultRule) -> bool {
        fn compatible<T: PartialEq>(a: &Option<T>, b: &Option<T>) -> bool {
            match (a, b) {
                (Some(x), Some(y)) => x == y,
                _ => true,
            }
        }
        self.op == other.op
            && compatible(&self.site, &other.site)
            && compatible(&self.socket, &other.socket)
            && compatible(&self.dest, &other.dest)
    }

    fn matches(&self, op: Op, meta: &AttemptMeta) -> bool {
        self.op == op
            && self.site.map_or(true, |s| s == meta.site)
            && self.socket.map_or(true, |g| g == meta.gen())
            && self.dest.map_or(true, |d| Some(d) == meta.dest)
    }
}

/// What the seam records, in order.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq)]
pub(super) enum JournalEvent {
    /// Appended before the fault decision; `result` filled in after it.
    Attempt {
        token: AttemptToken,
        op: Op,
        meta: AttemptMeta,
        injected: bool,
        result: Option<Result<usize, Option<i32>>>,
    },
    Decision {
        attempt: Option<AttemptToken>,
        line: Line,
        class: Option<Class>,
        peer: Option<u32>,
        gen: DiagGen,
    },
}

/// Long privileged tests cannot grow the journal without bound.
#[cfg(test)]
const JOURNAL_CAPACITY: usize = 8192;

/// Gives every diagnostics instance its own token space.
#[cfg(test)]
static FIXTURES: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
struct Seam {
    fixture: u64,
    rules: Mutex<Vec<(FaultRule, usize)>>,
    journal: Mutex<std::collections::VecDeque<JournalEvent>>,
    next_attempt: AtomicU64,
    /// `Some(t)`: manual mode, `now()` is `t` and nothing else.
    manual_clock: Mutex<Option<Duration>>,
    wall_reads: AtomicU64,
    clock_reads: AtomicU64,
}

#[cfg(test)]
impl Seam {
    fn new() -> Self {
        Seam {
            fixture: FIXTURES.fetch_add(1, Ordering::Relaxed),
            rules: Mutex::new(Vec::new()),
            journal: Mutex::new(std::collections::VecDeque::new()),
            next_attempt: AtomicU64::new(0),
            manual_clock: Mutex::new(None),
            wall_reads: AtomicU64::new(0),
            clock_reads: AtomicU64::new(0),
        }
    }

    fn push(&self, event: JournalEvent) {
        let mut journal = self.journal.lock();
        if journal.len() == JOURNAL_CAPACITY {
            journal.pop_front();
        }
        journal.push_back(event);
    }
}

/// Held by every test that can execute a diagnostics tracing callsite, so no
/// other test first-registers one of those callsites -- caching its interest
/// -- while a capture test runs. Poison-tolerant: an earlier test's panic says
/// nothing about this one.
#[cfg(test)]
static DIAG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(super) struct DiagGuard {
    _held: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
pub(super) fn diag_lock() -> DiagGuard {
    DiagGuard {
        _held: DIAG_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    }
}

#[cfg(test)]
impl DeviceUdpDiagnostics {
    /// A unit-test instance: manual clock at zero. Takes the test lock's
    /// guard, so no test can build one without holding it.
    pub(super) fn for_tests(_held: &DiagGuard) -> Self {
        let d = DeviceUdpDiagnostics::new();
        d.set_manual_clock(Duration::ZERO);
        d
    }

    pub(super) fn fixture(&self) -> u64 {
        self.seam.fixture
    }

    /// Enter manual clock mode at `t`, or move to `t`.
    pub(super) fn set_manual_clock(&self, t: Duration) {
        *self.seam.manual_clock.lock() = Some(t);
    }

    /// Saturating. A test bug, and a panic, outside manual mode.
    pub(super) fn advance_clock(&self, by: Duration) {
        let mut clock = self.seam.manual_clock.lock();
        let t = clock.expect("advance_clock needs the manual clock");
        *clock = Some(t.saturating_add(by));
    }

    pub(super) fn clock_value(&self) -> Option<Duration> {
        *self.seam.manual_clock.lock()
    }

    pub(super) fn wall_reads(&self) -> u64 {
        self.seam.wall_reads.load(Ordering::Relaxed)
    }

    pub(super) fn clock_reads(&self) -> u64 {
        self.seam.clock_reads.load(Ordering::Relaxed)
    }

    /// Replace the fault plan. Panics, naming both, on overlapping rules.
    pub(super) fn plan(&self, rules: Vec<FaultRule>) {
        Self::validate(&[], &rules);
        *self.seam.rules.lock() = rules.into_iter().map(|r| (r, 0)).collect();
    }

    /// Add to the fault plan, validated against the rules already installed.
    pub(super) fn extend_plan(&self, rules: Vec<FaultRule>) {
        let mut installed = self.seam.rules.lock();
        let existing: Vec<FaultRule> = installed.iter().map(|(r, _)| r.clone()).collect();
        Self::validate(&existing, &rules);
        installed.extend(rules.into_iter().map(|r| (r, 0)));
    }

    fn validate(existing: &[FaultRule], new: &[FaultRule]) {
        let all: Vec<&FaultRule> = existing.iter().chain(new).collect();
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate().skip(i + 1) {
                if j >= existing.len() && a.overlaps(b) {
                    panic!(
                        "overlapping fault rules can match the same attempt: {:?} and {:?}",
                        a, b
                    );
                }
            }
        }
    }

    /// Scripted `Fail` steps not yet consumed: 0 once every scripted fault
    /// has fired.
    pub(super) fn pending_fail_steps(&self) -> usize {
        self.seam
            .rules
            .lock()
            .iter()
            .map(|(rule, seen)| {
                rule.script
                    .iter()
                    .skip(*seen)
                    .filter(|step| matches!(step, Step::Fail(_)))
                    .count()
            })
            .sum()
    }

    /// (A) journal the attempt, minting its token; (B) decide its fault.
    fn seam_begin(&self, op: Op, meta: AttemptMeta) -> (AttemptToken, Option<io::Error>) {
        let token = AttemptToken {
            fixture: self.seam.fixture,
            id: self.seam.next_attempt.fetch_add(1, Ordering::Relaxed),
        };
        self.seam.push(JournalEvent::Attempt {
            token,
            op,
            meta,
            injected: false,
            result: None,
        });
        let mut injected = None;
        for (rule, seen) in self.seam.rules.lock().iter_mut() {
            if rule.matches(op, &meta) {
                let step = rule.script.get(*seen).copied().unwrap_or(Step::Pass);
                *seen += 1;
                if let Step::Fail(errno) = step {
                    injected = Some(io::Error::from_raw_os_error(errno));
                }
            }
        }
        (token, injected)
    }

    /// (C) journal the result exactly as the observer will receive it.
    fn seam_finish(&self, token: AttemptToken, injected: bool, result: &io::Result<usize>) {
        let mut journal = self.seam.journal.lock();
        for event in journal.iter_mut().rev() {
            if let JournalEvent::Attempt {
                token: t,
                injected: i,
                result: r,
                ..
            } = event
            {
                if *t == token {
                    *i = injected;
                    *r = Some(match result {
                        Ok(n) => Ok(*n),
                        Err(e) => Err(e.raw_os_error()),
                    });
                    break;
                }
            }
        }
    }

    pub(super) fn journal(&self) -> Vec<JournalEvent> {
        self.seam.journal.lock().iter().cloned().collect()
    }

    /// The most recent attempt journaled -- for inspection only; nothing
    /// attributes a decision with it.
    pub(super) fn last_attempt(&self) -> Option<AttemptToken> {
        self.seam.journal.lock().iter().rev().find_map(|e| match e {
            JournalEvent::Attempt { token, .. } => Some(*token),
            JournalEvent::Decision { .. } => None,
        })
    }

    pub(super) fn attempts(&self, site: Site) -> usize {
        self.journal()
            .iter()
            .filter(|e| matches!(e, JournalEvent::Attempt { meta, .. } if meta.site == site))
            .count()
    }

    pub(super) fn decisions(&self) -> Vec<(Line, Option<Class>)> {
        self.journal()
            .iter()
            .filter_map(|e| match e {
                JournalEvent::Decision { line, class, .. } => Some((*line, *class)),
                JournalEvent::Attempt { .. } => None,
            })
            .collect()
    }

    pub(super) fn decision_attempts(&self) -> Vec<(Line, Option<AttemptToken>)> {
        self.journal()
            .iter()
            .filter_map(|e| match e {
                JournalEvent::Decision { line, attempt, .. } => Some((*line, *attempt)),
                JournalEvent::Attempt { .. } => None,
            })
            .collect()
    }

    pub(super) fn count(&self, line: Line) -> usize {
        self.decisions().iter().filter(|(l, _)| *l == line).count()
    }
}

/// A journaled attempt with this result and no socket behind it.
#[cfg(test)]
pub(super) fn synthetic_attempt(env: &DeviceUdpDiagnostics, result: io::Result<usize>) -> Attempt {
    let meta = AttemptMeta {
        site: Site::TunConnected,
        socket: SocketRef::Connected(DiagGen::Untracked),
        dest: None,
    };
    let (token, _) = env.seam_begin(Op::Send, meta);
    env.seam_finish(token, false, &result);
    Attempt { result, token }
}

/// As [`commit_connected_socket`], from an isolated allocator.
#[cfg(test)]
pub(super) fn commit_connected_socket_from(
    env: &DeviceUdpDiagnostics,
    p: &mut Peer,
    alloc: &GenAllocator,
) -> DiagGen {
    let (gen, decision) = p.assign_connected_generation_from(alloc);
    record_replacement(env, p.index(), gen, decision);
    gen
}

#[cfg(test)]
impl PeerUdpDiagnostics {
    pub(super) fn connected_active(&self) -> bool {
        self.connected.active
    }

    pub(super) fn listener_active(&self) -> bool {
        self.listener.active
    }

    pub(super) fn connected_failures(&self) -> u32 {
        self.connected.failures
    }

    pub(super) fn listener_failures(&self) -> u32 {
        self.listener.failures
    }

    pub(super) fn last_warn(&self) -> Option<Duration> {
        self.last_warn
    }

    pub(super) fn last_error(&self) -> Option<Duration> {
        self.last_error
    }
}

/// The calibration callsite of the capture harness: never a production
/// diagnostic, on the diagnostics target, at DEBUG -- the lowest level any
/// diagnostic line uses.
#[cfg(test)]
pub(super) fn emit_capture_readiness(nonce: u64) {
    tracing::debug!(
        message = capture::READINESS_MESSAGE,
        readiness_nonce = nonce
    );
}

/// The tracing target of every line this module emits.
#[cfg(test)]
pub(super) const TARGET: &str = module_path!();

/// Direct capture of the events a scenario emits, for the field-contract
/// tests here and in the Device's converted-stderr tests.
///
/// Only subscriber *readiness* is ever retried. A capture installs a fresh
/// subscriber, rebuilds tracing's interest cache and proves the subscriber
/// sees a dedicated calibration event on the production target, at DEBUG --
/// at most `SETUP_ATTEMPTS` times. Then the scenario runs exactly once: it is
/// an `FnOnce`, taken out of an `Option`, and nothing looks at its outcome to
/// decide anything. A missing, duplicate or wrong event fails the test.
///
/// What makes a missing production event a real defect rather than a setup
/// artefact: the interest rebuild runs with the capture dispatcher installed,
/// so every already-registered callsite is recomputed against it, and one not
/// yet registered registers on its first hit, on this thread, inside the
/// scope. The only other way to cache "never" is a concurrent first
/// registration on another thread, and every test that can execute a
/// diagnostics callsite holds `DIAG_LOCK` (a capture holds it and then
/// `crate::tracing_test_lock()`, in that order).
#[cfg(test)]
pub(super) mod capture {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use portable_atomic::{AtomicU64, Ordering};
    use tracing::field::{Field, Visit};
    use tracing::{Level, Subscriber};
    use tracing_subscriber::layer::{Context, SubscriberExt};
    use tracing_subscriber::Layer;

    pub(in crate::device) const SETUP_ATTEMPTS: usize = 5;
    pub(in crate::device) const READINESS_MESSAGE: &str = "udp-diagnostics capture readiness";

    static NONCE: AtomicU64 = AtomicU64::new(1);

    #[derive(Debug, Clone)]
    pub(in crate::device) struct Captured {
        pub(in crate::device) level: Level,
        pub(in crate::device) target: String,
        pub(in crate::device) fields: BTreeMap<String, String>,
    }

    struct Buffer(Arc<std::sync::Mutex<Vec<Captured>>>);

    struct Fields(BTreeMap<String, String>);

    impl Visit for Fields {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_owned(), format!("{:?}", value));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }
    }

    impl<S: Subscriber> Layer<S> for Buffer {
        fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
            let mut fields = Fields(BTreeMap::new());
            event.record(&mut fields);
            let captured = Captured {
                level: *event.metadata().level(),
                target: event.metadata().target().to_owned(),
                fields: fields.0,
            };
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(captured);
        }
    }

    /// What the probe did for one readiness attempt, as the probe declares it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::device) enum ProbeEmission {
        /// The calibration event was emitted; the production probe always is.
        Emitted,
        /// A harness self-test deliberately withheld it.
        Withheld,
    }

    /// Why a readiness attempt was retried, labelled when it happens.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::device) enum RetryCause {
        /// The probe withheld the event on purpose (harness self-tests only).
        Deliberate,
        /// The probe emitted the event and the subscriber did not see it.
        Organic,
    }

    impl RetryCause {
        fn as_str(self) -> &'static str {
            match self {
                RetryCause::Deliberate => "deliberate",
                RetryCause::Organic => "organic",
            }
        }
    }

    pub(in crate::device) fn retry_cause(emission: ProbeEmission) -> RetryCause {
        match emission {
            ProbeEmission::Withheld => RetryCause::Deliberate,
            ProbeEmission::Emitted => RetryCause::Organic,
        }
    }

    /// One capture's readiness retries, by cause.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(in crate::device) struct SetupReport {
        pub(in crate::device) deliberate_readiness_retries: usize,
        pub(in crate::device) organic_readiness_retries: usize,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(in crate::device) enum HarnessError {
        NotReady {
            attempts: usize,
            report: SetupReport,
        },
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(in crate::device) enum Mismatch {
        Count {
            expected: usize,
            got: usize,
        },
        Level {
            index: usize,
            expected: Level,
            got: Level,
        },
        Target {
            index: usize,
            got: String,
        },
        Message {
            index: usize,
            expected: &'static str,
            got: Option<String>,
        },
        Fields {
            index: usize,
            missing: Vec<String>,
            extra: Vec<String>,
        },
        Value {
            index: usize,
            field: &'static str,
            expected: String,
            got: Option<String>,
        },
        Forbidden {
            index: usize,
            field: String,
        },
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(in crate::device) enum CaptureFailure {
        Harness(HarnessError),
        Mismatch(Mismatch),
    }

    /// One expected event: level, message, the exact set of field names
    /// (message included) and the values to check.
    pub(in crate::device) struct Spec {
        pub(in crate::device) level: Level,
        pub(in crate::device) message: &'static str,
        pub(in crate::device) fields: &'static [&'static str],
        pub(in crate::device) values: Vec<(&'static str, String)>,
    }

    /// Names no diagnostic line may ever carry.
    pub(in crate::device) const FORBIDDEN: &[&str] = &[
        "packet",
        "bytes",
        "payload",
        "plaintext",
        "ciphertext",
        "key",
        "private_key",
        "preshared_key",
        "cookie",
        "mac",
        "hp_key",
        "secret",
        "config",
    ];

    fn is_readiness(c: &Captured, target: &str, nonce: u64) -> bool {
        c.level == Level::DEBUG
            && c.target == target
            && c.fields.get("message").map(String::as_str) == Some(READINESS_MESSAGE)
            && c.fields.get("readiness_nonce") == Some(&nonce.to_string())
    }

    /// Phase A, retried at most `SETUP_ATTEMPTS` times: a fresh subscriber,
    /// an interest rebuild, and exactly the calibration event the probe
    /// emitted for this attempt's nonce on `target`. Phase B, once: the
    /// scenario, whose events are returned as captured. The caller holds
    /// `DIAG_LOCK`; this takes `crate::tracing_test_lock()`.
    pub(in crate::device) fn capture_with<R>(
        target: &'static str,
        probe: &mut dyn FnMut(u64) -> ProbeEmission,
        scenario: impl FnOnce() -> R,
    ) -> Result<(R, Vec<Captured>, SetupReport), HarnessError> {
        let _serialized = crate::tracing_test_lock();
        let mut scenario = Some(scenario);
        let mut report = SetupReport::default();
        for _ in 0..SETUP_ATTEMPTS {
            let buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
            let subscriber = tracing_subscriber::registry().with(Buffer(Arc::clone(&buffer)));
            let outcome = tracing::subscriber::with_default(subscriber, || {
                tracing::callsite::rebuild_interest_cache();
                let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
                let emission = probe(nonce);
                let ready = {
                    let events = buffer
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    events.len() == 1 && is_readiness(&events[0], target, nonce)
                };
                if !ready {
                    let cause = retry_cause(emission);
                    match cause {
                        RetryCause::Deliberate => report.deliberate_readiness_retries += 1,
                        RetryCause::Organic => report.organic_readiness_retries += 1,
                    }
                    // One pre-formatted record in one write: libtest's own
                    // output on the same descriptor cannot land inside it.
                    let record = format!(
                        "[udpdiag-readiness-retry cause={} nonce={}]\n",
                        cause.as_str(),
                        nonce
                    );
                    let _ =
                        std::io::Write::write_all(&mut std::io::stderr().lock(), record.as_bytes());
                    // The scenario has not run; tear this subscriber down.
                    return None;
                }
                buffer
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clear();
                let run = scenario.take().expect("the scenario runs at most once");
                Some(run())
            });
            if let Some(result) = outcome {
                let events = std::mem::take(
                    &mut *buffer
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                );
                return Ok((result, events, report));
            }
        }
        Err(HarnessError::NotReady {
            attempts: SETUP_ATTEMPTS,
            report,
        })
    }

    /// Exactly `specs`, in order: count, level, target, message, the field-name
    /// set, the listed values, and no forbidden name.
    pub(in crate::device) fn check(
        target: &str,
        events: &[Captured],
        specs: &[Spec],
    ) -> Result<(), Mismatch> {
        if events.len() != specs.len() {
            return Err(Mismatch::Count {
                expected: specs.len(),
                got: events.len(),
            });
        }
        for (index, (c, s)) in events.iter().zip(specs).enumerate() {
            if c.level != s.level {
                return Err(Mismatch::Level {
                    index,
                    expected: s.level,
                    got: c.level,
                });
            }
            if c.target != target {
                return Err(Mismatch::Target {
                    index,
                    got: c.target.clone(),
                });
            }
            if c.fields.get("message").map(String::as_str) != Some(s.message) {
                return Err(Mismatch::Message {
                    index,
                    expected: s.message,
                    got: c.fields.get("message").cloned(),
                });
            }
            if let Some(field) = c.fields.keys().find(|f| FORBIDDEN.contains(&f.as_str())) {
                return Err(Mismatch::Forbidden {
                    index,
                    field: field.clone(),
                });
            }
            let have: BTreeSet<&str> = c.fields.keys().map(String::as_str).collect();
            let want: BTreeSet<&str> = s.fields.iter().copied().collect();
            if have != want {
                return Err(Mismatch::Fields {
                    index,
                    missing: want.difference(&have).map(|f| f.to_string()).collect(),
                    extra: have.difference(&want).map(|f| f.to_string()).collect(),
                });
            }
            for (field, expected) in &s.values {
                if c.fields.get(*field) != Some(expected) {
                    return Err(Mismatch::Value {
                        index,
                        field,
                        expected: expected.clone(),
                        got: c.fields.get(*field).cloned(),
                    });
                }
            }
        }
        Ok(())
    }

    /// The production capture: the calibration event through `probe` on
    /// `target`, then the scenario once, then an exact check.
    pub(in crate::device) fn capture_exactly<R>(
        target: &'static str,
        probe: fn(u64),
        specs: &[Spec],
        scenario: impl FnOnce() -> R,
    ) -> Result<R, CaptureFailure> {
        let mut emit = |nonce: u64| {
            probe(nonce);
            ProbeEmission::Emitted
        };
        let (result, events, _) =
            capture_with(target, &mut emit, scenario).map_err(CaptureFailure::Harness)?;
        check(target, &events, specs).map_err(CaptureFailure::Mismatch)?;
        Ok(result)
    }

    pub(in crate::device) fn value(field: &'static str, value: &str) -> (&'static str, String) {
        (field, value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::capture::{
        capture_exactly, capture_with, check, retry_cause, value as v, CaptureFailure,
        HarnessError, Mismatch, ProbeEmission, RetryCause, SetupReport, Spec,
    };
    use super::*;
    use crate::noise::amnezia::AmneziaConfig;
    use crate::noise::Tunn;
    use crate::x25519;
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use tracing::Level;

    // ======================================================== fixtures

    const NS: Duration = Duration::from_nanos(1);

    fn bound(addr: SocketAddr) -> Socket {
        let s = Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        s.bind(&addr.into()).unwrap();
        s.set_nonblocking(true).unwrap();
        s
    }

    fn v4() -> Socket {
        bound(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    }

    fn v6() -> Socket {
        bound(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)))
    }

    fn local(s: &Socket) -> SocketAddr {
        s.local_addr().unwrap().as_socket().unwrap()
    }

    fn connected_to(sink: &Socket) -> Socket {
        let s = match local(sink) {
            SocketAddr::V4(_) => v4(),
            SocketAddr::V6(_) => v6(),
        };
        s.connect(&local(sink).into()).unwrap();
        s
    }

    fn recv_now(s: &Socket) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buf = [MaybeUninit::<u8>::uninit(); 2048];
        match s.recv_from(&mut buf) {
            Ok((n, from)) => Some((
                buf[..n]
                    .iter()
                    .map(|b| unsafe { b.assume_init() })
                    .collect(),
                from.as_socket().unwrap(),
            )),
            Err(_) => None,
        }
    }

    /// The next datagram at `s` within a second.
    fn wait_recv(s: &Socket) -> Option<Vec<u8>> {
        wait_recv_from(s).map(|(bytes, _)| bytes)
    }

    fn wait_recv_from(s: &Socket) -> Option<(Vec<u8>, SocketAddr)> {
        for _ in 0..200 {
            if let Some(got) = recv_now(s) {
                return Some(got);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        None
    }

    /// Nothing arrives at `s` for a while: a datagram that was never sent.
    fn stays_empty(s: &Socket) -> bool {
        std::thread::sleep(Duration::from_millis(50));
        recv_now(s).is_none()
    }

    fn gen(n: u64) -> DiagGen {
        DiagGen::Tracked(NonZeroU64::new(n).unwrap())
    }

    fn lid(family: Family, n: u64) -> ListenerId {
        ListenerId {
            family,
            gen: gen(n),
        }
    }

    fn ulid(family: Family) -> ListenerId {
        ListenerId {
            family,
            gen: DiagGen::Untracked,
        }
    }

    fn rule(
        op: Op,
        site: Option<Site>,
        socket: Option<DiagGen>,
        dest: Option<SocketAddr>,
        script: Vec<Step>,
    ) -> FaultRule {
        FaultRule {
            op,
            site,
            socket,
            dest,
            script,
        }
    }

    fn ep() -> SocketAddr {
        "192.0.2.1:51820".parse().unwrap()
    }

    fn conn_target(g: DiagGen) -> Target {
        Target::Connected {
            gen: g,
            to: Some(ep()),
        }
    }

    fn io_err(errno: i32) -> io::Error {
        io::Error::from_raw_os_error(errno)
    }

    fn att(env: &DeviceUdpDiagnostics, result: io::Result<usize>) -> Attempt {
        synthetic_attempt(env, result)
    }

    fn err_att(env: &DeviceUdpDiagnostics, errno: i32) -> Attempt {
        att(env, Err(io_err(errno)))
    }

    fn ok_att(env: &DeviceUdpDiagnostics) -> Attempt {
        att(env, Ok(100))
    }

    fn send_fail(
        env: &DeviceUdpDiagnostics,
        d: &mut PeerUdpDiagnostics,
        t: Target,
        site: Site,
        errno: i32,
    ) {
        let a = err_att(env, errno);
        observe_peer_send(env, d, 1, t, site, 10, &a, false);
    }

    fn send_ok(env: &DeviceUdpDiagnostics, d: &mut PeerUdpDiagnostics, t: Target, site: Site) {
        let a = ok_att(env);
        observe_peer_send(env, d, 1, t, site, 10, &a, false);
    }

    /// A real `Peer` around a real `Tunn`, from fixed keys.
    fn test_peer(index: u32) -> Peer {
        test_peer_with(index, AmneziaConfig::default(), None)
    }

    fn test_peer_with(index: u32, amnezia: AmneziaConfig, endpoint: Option<SocketAddr>) -> Peer {
        let secret = x25519::StaticSecret::from([0x11; 32]);
        let peer_public = x25519::PublicKey::from(&x25519::StaticSecret::from([0x22; 32]));
        let tunnel = Tunn::new_with_obfuscation(
            secret,
            peer_public,
            None,
            None,
            index,
            None,
            Default::default(),
            amnezia,
        )
        .unwrap();
        Peer::new(tunnel, index, endpoint, None)
    }

    /// A peer whose committed connected socket is a dup of the returned one
    /// -- the handler's own, as `connect_endpoint` arranges -- connected to
    /// `sink`, with a generation from `alloc`.
    fn connected_peer(
        env: &DeviceUdpDiagnostics,
        index: u32,
        sink: &Socket,
        alloc: &GenAllocator,
    ) -> (Peer, Socket, DiagGen) {
        let mut p = test_peer(index);
        let conn = connected_to(sink);
        p.endpoint_mut().addr = Some(local(sink));
        p.endpoint_mut().conn = Some(conn.try_clone().unwrap());
        let g = commit_connected_socket_from(env, &mut p, alloc);
        (p, conn, g)
    }

    /// The two listeners a device has, as unconnected loopback sockets.
    struct Listeners {
        u4: Socket,
        u6: Socket,
        id4: ListenerId,
        id6: ListenerId,
    }

    fn listeners() -> Listeners {
        Listeners {
            u4: v4(),
            u6: v6(),
            id4: lid(Family::V4, 4),
            id6: lid(Family::V6, 6),
        }
    }

    impl Listeners {
        fn tun(&self, env: &DeviceUdpDiagnostics, p: &mut Peer, packet: &[u8]) -> bool {
            tun_send_step(env, p, &self.u4, self.id4, &self.u6, self.id6, packet)
        }

        fn timer(&self, env: &DeviceUdpDiagnostics, p: &mut Peer, to: SocketAddr, packet: &[u8]) {
            timer_send_step(env, p, &self.u4, self.id4, &self.u6, self.id6, to, packet)
        }
    }

    /// The `(site, socket, dest)` of every journaled attempt.
    fn attempted(env: &DeviceUdpDiagnostics) -> Vec<(Site, SocketRef, Option<SocketAddr>)> {
        env.journal()
            .iter()
            .filter_map(|e| match e {
                JournalEvent::Attempt { meta, .. } => Some((meta.site, meta.socket, meta.dest)),
                JournalEvent::Decision { .. } => None,
            })
            .collect()
    }

    // Field-name sets of the logging contract.
    const A_EPISODE: &[&str] = &[
        "message",
        "peer",
        "endpoint",
        "op",
        "path",
        "socket",
        "os_error",
        "error_kind",
        "class",
        "len",
        "failures",
        "socket_gen",
    ];
    const A_NO_EPISODE: &[&str] = &[
        "message",
        "peer",
        "endpoint",
        "op",
        "path",
        "socket",
        "os_error",
        "error_kind",
        "class",
        "len",
        "socket_gen",
    ];
    const A_UNAUTH: &[&str] = &[
        "message",
        "endpoint",
        "op",
        "path",
        "socket",
        "os_error",
        "error_kind",
        "class",
        "len",
        "socket_gen",
    ];
    const B_EPISODE: &[&str] = &[
        "message",
        "peer",
        "endpoint",
        "op",
        "path",
        "socket",
        "os_error",
        "error_kind",
        "class",
        "failures",
        "socket_gen",
    ];
    const B_NO_EPISODE: &[&str] = &[
        "message",
        "peer",
        "endpoint",
        "op",
        "path",
        "socket",
        "os_error",
        "error_kind",
        "class",
        "socket_gen",
    ];
    const C_RECOVERY: &[&str] = &[
        "message",
        "peer",
        "endpoint",
        "path",
        "socket",
        "previous_class",
        "previous_os_error",
        "failures",
        "socket_gen",
    ];
    const C_CLOSED: &[&str] = &[
        "message",
        "peer",
        "socket",
        "previous_class",
        "previous_os_error",
        "failures",
        "socket_gen",
    ];

    fn capture<R>(specs: &[Spec], scenario: impl FnOnce() -> R) -> Result<R, CaptureFailure> {
        capture_exactly(TARGET, emit_capture_readiness, specs, scenario)
    }

    /// Run `f` with nothing listening, so a precondition's events stay out of
    /// the capture that follows.
    fn quietly<R>(f: impl FnOnce() -> R) -> R {
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), f)
    }

    // ======================================================== capture harness (C1-C8)

    fn fake_spec() -> Vec<Spec> {
        vec![Spec {
            level: Level::WARN,
            message: "fake diagnostic",
            fields: &["message", "peer"],
            values: vec![v("peer", "1")],
        }]
    }

    fn emit_fake() {
        tracing::warn!(target: TARGET, message = "fake diagnostic", peer = 1u32);
    }

    #[test]
    fn c1_setup_retry_still_runs_the_scenario_exactly_once() {
        let _g = diag_lock();
        let probes = AtomicUsize::new(0);
        let runs = AtomicUsize::new(0);
        let mut probe = |n: u64| {
            if probes.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 2 {
                emit_capture_readiness(n);
                ProbeEmission::Emitted
            } else {
                ProbeEmission::Withheld
            }
        };
        let (_, events, report) = capture_with(TARGET, &mut probe, || {
            runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            emit_fake();
        })
        .expect("[C1] setup becomes ready on the third attempt");
        assert_eq!(probes.into_inner(), 3, "[C1] three setup attempts");
        assert_eq!(runs.into_inner(), 1, "[C1] scenario executed exactly once");
        assert_eq!(
            report,
            SetupReport {
                deliberate_readiness_retries: 2,
                organic_readiness_retries: 0
            },
            "[C1] two deliberate retries, labelled by the harness"
        );
        assert_eq!(check(TARGET, &events, &fake_spec()), Ok(()));
    }

    #[test]
    fn c2_zero_expected_events_fails_without_retry() {
        let _g = diag_lock();
        let runs = AtomicUsize::new(0);
        let r = capture(&fake_spec(), || {
            runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        assert_eq!(
            r,
            Err(CaptureFailure::Mismatch(Mismatch::Count {
                expected: 1,
                got: 0
            })),
            "[C2] a missing event fails"
        );
        assert_eq!(runs.into_inner(), 1, "[C2] scenario executed exactly once");
    }

    #[test]
    fn c3_duplicate_events_fail_without_retry() {
        let _g = diag_lock();
        let runs = AtomicUsize::new(0);
        let r = capture(&fake_spec(), || {
            runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            emit_fake();
            emit_fake();
        });
        assert_eq!(
            r,
            Err(CaptureFailure::Mismatch(Mismatch::Count {
                expected: 1,
                got: 2
            })),
            "[C3] a duplicate fails"
        );
        assert_eq!(runs.into_inner(), 1, "[C3] scenario executed exactly once");
    }

    #[test]
    fn c4_wrong_level_fails() {
        let _g = diag_lock();
        let r = capture(
            &fake_spec(),
            || tracing::debug!(target: TARGET, message = "fake diagnostic", peer = 1u32),
        );
        assert_eq!(
            r,
            Err(CaptureFailure::Mismatch(Mismatch::Level {
                index: 0,
                expected: Level::WARN,
                got: Level::DEBUG
            })),
            "[C4] a wrong level fails"
        );
    }

    #[test]
    fn c5_missing_required_field_fails() {
        let _g = diag_lock();
        let r = capture(
            &fake_spec(),
            || tracing::warn!(target: TARGET, message = "fake diagnostic"),
        );
        assert_eq!(
            r,
            Err(CaptureFailure::Mismatch(Mismatch::Fields {
                index: 0,
                missing: vec!["peer".into()],
                extra: vec![]
            })),
            "[C5] a missing field fails"
        );
    }

    #[test]
    fn c6_extra_field_fails_under_an_exact_allowlist() {
        let _g = diag_lock();
        let r = capture(
            &fake_spec(),
            || tracing::warn!(target: TARGET, message = "fake diagnostic", peer = 1u32, failures = 3u32),
        );
        assert_eq!(
            r,
            Err(CaptureFailure::Mismatch(Mismatch::Fields {
                index: 0,
                missing: vec![],
                extra: vec!["failures".into()]
            })),
            "[C6] an extra field fails"
        );
        let r = capture(
            &fake_spec(),
            || tracing::warn!(target: TARGET, message = "fake diagnostic", peer = 1u32, cookie = 7u8),
        );
        assert_eq!(
            r,
            Err(CaptureFailure::Mismatch(Mismatch::Forbidden {
                index: 0,
                field: "cookie".into()
            })),
            "[C6] a sensitive field fails"
        );
    }

    #[test]
    fn c7_calibration_failing_every_attempt_never_runs_the_scenario() {
        let _g = diag_lock();
        let probes = AtomicUsize::new(0);
        let runs = AtomicUsize::new(0);
        let mut probe = |_n: u64| {
            probes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ProbeEmission::Withheld
        };
        let r = capture_with(TARGET, &mut probe, || {
            runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        let five_deliberate = SetupReport {
            deliberate_readiness_retries: 5,
            organic_readiness_retries: 0,
        };
        assert_eq!(
            r.err(),
            Some(HarnessError::NotReady {
                attempts: 5,
                report: five_deliberate
            }),
            "[C7] a harness error after five deliberate setups"
        );
        assert_eq!(probes.into_inner(), 5, "[C7] exactly five setup attempts");
        assert_eq!(runs.into_inner(), 0, "[C7] the scenario never executed");
    }

    #[test]
    fn c8_a_poisoned_capture_lock_does_not_hide_the_current_result() {
        // Poison both locks, in the harness's order, from a panicking thread.
        let _ = std::thread::spawn(|| {
            let _d = DIAG_LOCK.lock();
            let _t = crate::tracing_test_lock();
            panic!("poisoning on purpose");
        })
        .join();
        assert!(
            DIAG_LOCK.is_poisoned(),
            "precondition: DIAG_LOCK is poisoned"
        );
        let _g = diag_lock();
        let runs = AtomicUsize::new(0);
        let ok = capture(&fake_spec(), || {
            runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            emit_fake();
        });
        assert_eq!(
            ok,
            Ok(()),
            "[C8] the recovered harness checks its own scenario"
        );
        assert_eq!(runs.into_inner(), 1, "[C8] scenario executed exactly once");
        let bad = capture(&fake_spec(), || {});
        assert_eq!(
            bad,
            Err(CaptureFailure::Mismatch(Mismatch::Count {
                expected: 1,
                got: 0
            })),
            "[C8] the current failure is still reported"
        );
    }

    #[test]
    fn retry_cause_labels_withheld_as_deliberate_and_unobserved_emission_as_organic() {
        assert_eq!(
            retry_cause(ProbeEmission::Withheld),
            RetryCause::Deliberate,
            "[RC] withheld is deliberate"
        );
        assert_eq!(
            retry_cause(ProbeEmission::Emitted),
            RetryCause::Organic,
            "[RC] an emitted but unobserved event is organic"
        );
    }

    // ======================================================== direct capture: field contracts

    #[test]
    fn direct_a_configured_peer_warn_fields() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let spec = [Spec {
            level: Level::WARN,
            message: "UDP send to peer not accepted: socket reported message too long",
            fields: A_EPISODE,
            values: vec![
                v("len", "1384"),
                v("class", "size"),
                v("op", "send"),
                v("path", "tun"),
                v("socket", "connected"),
                v("failures", "1"),
                v("peer", "11"),
                v("socket_gen", "4"),
                v("endpoint", "192.0.2.1:51820"),
                v("os_error", &format!("{:?}", Some(libc::EMSGSIZE))),
            ],
        }];
        capture(&spec, || {
            let a = err_att(&env, libc::EMSGSIZE);
            observe_peer_send(
                &env,
                &mut d,
                11,
                conn_target(gen(4)),
                Site::TunConnected,
                1384,
                &a,
                false,
            );
        })
        .expect("[A] configured-peer WARN fields");
    }

    #[test]
    fn direct_a_untracked_warn_has_no_episode_fields() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let spec = [Spec {
            level: Level::WARN,
            message: "UDP send to peer not accepted: socket reported connection refusal",
            fields: A_NO_EPISODE,
            values: vec![v("socket_gen", "0"), v("class", "refused")],
        }];
        capture(&spec, || {
            send_fail(
                &env,
                &mut d,
                conn_target(DiagGen::Untracked),
                Site::TunConnected,
                libc::ECONNREFUSED,
            )
        })
        .expect("[A0] Untracked WARN fields");
    }

    #[test]
    fn direct_a_unauthenticated_debug_fields() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let spec = [Spec {
            level: Level::DEBUG,
            message: "UDP socket operation failed",
            fields: A_UNAUTH,
            values: vec![
                v("path", "cookie-reply"),
                v("len", "64"),
                v("socket", "listener"),
                v("endpoint", "198.51.100.7:53"),
            ],
        }];
        capture(&spec, || {
            let a = err_att(&env, libc::ENETUNREACH);
            observe_unauthenticated_send(
                &env,
                lid(Family::V4, 1),
                Site::CookieReply,
                "198.51.100.7:53".parse().unwrap(),
                64,
                &a,
            );
        })
        .expect("[A-UNAUTH] unauthenticated DEBUG fields: no peer, no failures");
    }

    #[test]
    fn direct_b_recv_failure_has_no_len() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let spec = [Spec {
            level: Level::WARN,
            message: "connected UDP socket for peer reported a pending message-too-long error",
            fields: B_EPISODE,
            values: vec![
                v("op", "recv"),
                v("path", "connected-recv"),
                v("class", "size"),
            ],
        }];
        capture(&spec, || {
            let a = err_att(&env, libc::EMSGSIZE);
            observe_peer_recv_error(
                &env,
                &mut d,
                11,
                gen(4),
                Some(ep()),
                &io_err(libc::EMSGSIZE),
                a.token,
                false,
            );
        })
        .expect("[B] receive failure fields: no len");
    }

    #[test]
    fn direct_b_recv_transient_has_no_len_and_no_episode() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let spec = [Spec {
            level: Level::DEBUG,
            message: "UDP socket operation failed",
            fields: B_NO_EPISODE,
            values: vec![v("class", "transient"), v("op", "recv")],
        }];
        capture(&spec, || {
            let a = err_att(&env, libc::ENOBUFS);
            observe_peer_recv_error(
                &env,
                &mut d,
                11,
                gen(4),
                Some(ep()),
                &io_err(libc::ENOBUFS),
                a.token,
                false,
            );
        })
        .expect("[B0] receive transient fields");
    }

    #[test]
    fn direct_c_debug_recovery_fields() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        // Outside the capture: one failure opens the episode.
        quietly(|| {
            send_fail(
                &env,
                &mut d,
                conn_target(gen(4)),
                Site::TunConnected,
                libc::ENETUNREACH,
            )
        });
        let spec = [Spec {
            level: Level::DEBUG,
            message: "local socket send acceptance resumed",
            fields: C_RECOVERY,
            values: vec![
                v("previous_class", "route"),
                v(
                    "previous_os_error",
                    &format!("{:?}", Some(libc::ENETUNREACH)),
                ),
                v("failures", "1"),
                v("socket_gen", "4"),
                v("path", "tun"),
                v("socket", "connected"),
                v("endpoint", "192.0.2.1:51820"),
            ],
        }];
        capture(&spec, || {
            send_ok(&env, &mut d, conn_target(gen(4)), Site::TunConnected)
        })
        .expect("[C-REC] recovery DEBUG fields");
    }

    #[test]
    fn direct_c_closed_replacement_fields() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let alloc = GenAllocator::starting_at(140);
        let mut p = test_peer(8);
        // Outside the capture: G1 = 140 has an active two-failure episode.
        quietly(|| {
            let g1 = commit_connected_socket_from(&env, &mut p, &alloc);
            assert_eq!(g1, gen(140));
            send_fail(
                &env,
                p.udp_diagnostics_mut(),
                conn_target(g1),
                Site::TunConnected,
                libc::ENETUNREACH,
            );
            send_fail(
                &env,
                p.udp_diagnostics_mut(),
                conn_target(g1),
                Site::TunConnected,
                libc::ENETUNREACH,
            );
        });
        let spec = [Spec {
            level: Level::DEBUG,
            message: "UDP failure episode closed by a socket or endpoint change",
            fields: C_CLOSED,
            values: vec![
                v("peer", "8"),
                v("socket", "connected"),
                v("previous_class", "route"),
                v(
                    "previous_os_error",
                    &format!("{:?}", Some(libc::ENETUNREACH)),
                ),
                v("failures", "2"),
                v("socket_gen", "141"),
            ],
        }];
        // The scenario: committing the replacement G2 = 141, exactly once.
        let g2 = capture(&spec, || commit_connected_socket_from(&env, &mut p, &alloc))
            .expect("[C-CLOSED] closure DEBUG fields");
        assert_eq!(g2, gen(141));
        assert_eq!(
            env.decision_attempts().last(),
            Some(&(Line::DebugClosed, None)),
            "[C-CLOSED] journaled with attempt = None"
        );
        assert!(
            !p.udp_diagnostics().connected_active(),
            "[C-CLOSED] the new identity starts inactive"
        );
    }

    #[test]
    fn direct_error_lifecycle_fields() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let spec = [Spec {
            level: Level::ERROR,
            message: "UDP socket for peer reported an invalid-socket-state error",
            fields: A_EPISODE,
            values: vec![v("class", "lifecycle"), v("socket", "connected")],
        }];
        capture(&spec, || {
            send_fail(
                &env,
                &mut d,
                conn_target(gen(4)),
                Site::TunConnected,
                libc::EBADF,
            )
        })
        .expect("[ERR] connected lifecycle ERROR fields");
        let spec = [Spec {
            level: Level::ERROR,
            message: "listener UDP socket reported an invalid-socket-state error",
            fields: A_EPISODE,
            values: vec![
                v("class", "lifecycle"),
                v("socket", "listener"),
                v("path", "timer"),
            ],
        }];
        capture(&spec, || {
            send_fail(
                &env,
                &mut d,
                Target::Listener {
                    id: lid(Family::V4, 9),
                    to: ep(),
                },
                Site::TimerV4,
                libc::ENOTSOCK,
            )
        })
        .expect("[ERR] listener lifecycle ERROR fields");
    }

    #[test]
    fn direct_recv_would_block_is_silent() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let sink = v4();
        let (p, conn, gn) = connected_peer(&env, 1, &sink, &GenAllocator::starting_at(5));
        let p = Mutex::new(p);
        let mut buf = [MaybeUninit::<u8>::uninit(); 64];
        capture(&[], || {
            assert!(matches!(
                conn_recv_step(&env, &p, &conn, gn, local(&sink), &mut buf),
                RecvStep::End
            ));
        })
        .expect("[WB] silent WouldBlock");
        assert!(
            env.decisions().is_empty(),
            "[WB] no journal decision either"
        );
    }

    /// Every line kind, in one scenario: the exact field set of each, and no
    /// datagram bytes anywhere -- the packet below is a marker no field may
    /// carry.
    #[test]
    fn log_fields_are_the_allowed_set_and_carry_no_payload() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let to: SocketAddr = "198.51.100.7:53".parse().unwrap();
        let listener = Target::Listener {
            id: lid(Family::V4, 3),
            to,
        };
        let spec = vec![
            // WARN opening (A), DEBUG within the cooldown (A), WARN summary (A).
            Spec {
                level: Level::WARN,
                message:
                    "UDP send to peer not accepted: socket reported no route or no usable address",
                fields: A_EPISODE,
                values: vec![v("failures", "1")],
            },
            Spec {
                level: Level::DEBUG,
                message: "UDP socket operation failed",
                fields: A_EPISODE,
                values: vec![v("failures", "2")],
            },
            Spec {
                level: Level::WARN,
                message: "UDP socket for peer still failing",
                fields: A_EPISODE,
                values: vec![v("failures", "3")],
            },
            // Recovery (C).
            Spec {
                level: Level::DEBUG,
                message: "local socket send acceptance resumed",
                fields: C_RECOVERY,
                values: vec![v("failures", "3")],
            },
            // A listener episode, then its re-key by a new destination (C-closed).
            Spec {
                level: Level::DEBUG,
                message: "UDP socket operation failed",
                fields: A_EPISODE,
                values: vec![v("socket", "listener")],
            },
            Spec {
                level: Level::DEBUG,
                message: "UDP failure episode closed by a socket or endpoint change",
                fields: C_CLOSED,
                values: vec![v("socket", "listener"), v("socket_gen", "3")],
            },
            Spec {
                level: Level::DEBUG,
                message: "UDP socket operation failed",
                fields: A_EPISODE,
                values: vec![v("failures", "1")],
            },
            // Retired handler (A0 send, B0 receive).
            Spec {
                level: Level::DEBUG,
                message: "UDP operation on a retired connected socket failed",
                fields: A_NO_EPISODE,
                values: vec![v("class", "teardown")],
            },
            Spec {
                level: Level::DEBUG,
                message: "UDP operation on a retired connected socket failed",
                fields: B_NO_EPISODE,
                values: vec![v("class", "teardown")],
            },
            // Unauthenticated (A-U).
            Spec {
                level: Level::DEBUG,
                message: "UDP socket operation failed",
                fields: A_UNAUTH,
                values: vec![v("path", "probe-reply")],
            },
        ];
        let packet = b"PAYLOAD-MARKER-plaintext-ciphertext";
        let events = {
            let mut probe = |n: u64| {
                emit_capture_readiness(n);
                ProbeEmission::Emitted
            };
            let (_, events, _) = capture_with(TARGET, &mut probe, || {
                let t = conn_target(gen(4));
                let fail = |env: &DeviceUdpDiagnostics,
                            d: &mut PeerUdpDiagnostics,
                            t: Target,
                            site: Site,
                            errno: i32| {
                    let a = err_att(env, errno);
                    observe_peer_send(env, d, 1, t, site, packet.len(), &a, false);
                };
                fail(&env, &mut d, t, Site::TunConnected, libc::ENETUNREACH);
                fail(&env, &mut d, t, Site::TunConnected, libc::ENETUNREACH);
                env.advance_clock(WARN_COOLDOWN);
                fail(&env, &mut d, t, Site::TunConnected, libc::ENETUNREACH);
                send_ok(&env, &mut d, t, Site::TunConnected);
                fail(&env, &mut d, listener, Site::TimerV4, libc::ENETUNREACH);
                let moved = Target::Listener {
                    id: lid(Family::V4, 3),
                    to: ep(),
                };
                fail(&env, &mut d, moved, Site::TimerV4, libc::ENETUNREACH);
                let a = err_att(&env, libc::EPIPE);
                observe_peer_send(
                    &env,
                    &mut d,
                    1,
                    t,
                    Site::ConnectedFlush,
                    packet.len(),
                    &a,
                    true,
                );
                observe_peer_recv_error(
                    &env,
                    &mut d,
                    1,
                    gen(4),
                    Some(ep()),
                    &io_err(libc::EBADF),
                    a.token,
                    true,
                );
                let a = err_att(&env, libc::EPERM);
                observe_unauthenticated_send(
                    &env,
                    lid(Family::V4, 3),
                    Site::ProbeReply,
                    to,
                    packet.len(),
                    &a,
                );
            })
            .expect("[FIELDS] capture ready");
            events
        };
        assert_eq!(
            check(TARGET, &events, &spec),
            Ok(()),
            "[FIELDS] exact field sets"
        );
        let marker = String::from_utf8_lossy(packet);
        for e in &events {
            for value in e.fields.values() {
                assert!(
                    !value.contains(&*marker),
                    "[FIELDS] no payload in {:?}",
                    e.fields
                );
            }
        }
    }

    // ======================================================== classifier

    #[test]
    fn classifier_table() {
        let send = |errno| classify(Op::Send, &io_err(errno), false);
        assert_eq!(send(libc::EAGAIN), Some(Class::Transient));
        assert_eq!(send(libc::EINTR), Some(Class::Transient));
        assert_eq!(send(libc::ENOBUFS), Some(Class::Transient));
        assert_eq!(send(libc::EMSGSIZE), Some(Class::Size));
        for errno in [
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::EHOSTDOWN,
            libc::EADDRNOTAVAIL,
        ] {
            assert_eq!(send(errno), Some(Class::Route), "errno {}", errno);
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_eq!(send(libc::ENONET), Some(Class::Route));
        assert_eq!(send(libc::ECONNREFUSED), Some(Class::Refused));
        for errno in [libc::EACCES, libc::EPERM, libc::EINVAL] {
            assert_eq!(send(errno), Some(Class::Policy), "errno {}", errno);
        }
        for errno in [
            libc::EBADF,
            libc::ENOTSOCK,
            libc::EAFNOSUPPORT,
            libc::EDESTADDRREQ,
            libc::EISCONN,
            libc::ENOTCONN,
            libc::EPIPE,
        ] {
            assert_eq!(send(errno), Some(Class::Lifecycle), "errno {}", errno);
        }
        for errno in [
            libc::ENOMEM,
            libc::EPROTO,
            libc::ENOPROTOOPT,
            libc::EOPNOTSUPP,
        ] {
            assert_eq!(send(errno), Some(Class::Unknown), "errno {}", errno);
        }
        assert_eq!(
            classify(Op::Send, &io::Error::other("no errno"), false),
            Some(Class::Unknown)
        );
        let recv = |errno| classify(Op::Recv, &io_err(errno), false);
        assert_eq!(recv(libc::EAGAIN), None);
        assert_eq!(recv(libc::EINTR), Some(Class::Transient));
        assert_eq!(recv(libc::ENOBUFS), Some(Class::Transient));
        assert_eq!(recv(libc::ECONNREFUSED), Some(Class::Refused));
        assert_eq!(recv(libc::EMSGSIZE), Some(Class::Size));
    }

    /// The classifier matches this target's errno values: the names, not
    /// Linux's numbers.
    #[test]
    fn classify_uses_this_targets_errno_values() {
        #[cfg(target_os = "linux")]
        let (hostunreach, nobufs, msgsize) = (113, 105, 90);
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        let (hostunreach, nobufs, msgsize) = (65, 55, 40);
        assert_eq!(
            classify(Op::Send, &io_err(hostunreach), false),
            Some(Class::Route)
        );
        assert_eq!(
            classify(Op::Send, &io_err(nobufs), false),
            Some(Class::Transient)
        );
        assert_eq!(
            classify(Op::Send, &io_err(msgsize), false),
            Some(Class::Size)
        );
    }

    #[test]
    fn recv_would_block_is_silent_even_when_retired() {
        let e = io_err(libc::EAGAIN);
        assert_eq!(classify(Op::Recv, &e, false), None);
        assert_eq!(classify(Op::Recv, &e, true), None);
        assert_eq!(classify(Op::Send, &e, false), Some(Class::Transient));
        assert_eq!(classify(Op::Send, &e, true), Some(Class::Teardown));
    }

    #[test]
    fn retired_override_precedes_every_classification() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        for errno in [
            libc::EBADF,
            libc::ENOTSOCK,
            libc::ENOTCONN,
            libc::EPIPE,
            libc::ECONNREFUSED,
            libc::EMSGSIZE,
            libc::EINTR,
            libc::ENOBUFS,
            libc::EAGAIN,
        ] {
            let a = err_att(&env, errno);
            observe_peer_send(
                &env,
                &mut d,
                1,
                conn_target(gen(1)),
                Site::ConnectedFlush,
                10,
                &a,
                true,
            );
            if errno != libc::EAGAIN {
                observe_peer_recv_error(
                    &env,
                    &mut d,
                    1,
                    gen(1),
                    None,
                    &io_err(errno),
                    a.token,
                    true,
                );
            }
        }
        assert_eq!(env.decisions().len(), 17);
        assert!(
            env.decisions()
                .iter()
                .all(|(l, c)| *l == Line::DebugRetired && *c == Some(Class::Teardown)),
            "[N2] teardown for every retired error"
        );
        assert!(!d.connected_active(), "[N2] record untouched");
        send_fail(
            &env,
            &mut d,
            conn_target(gen(1)),
            Site::ConnectedFlush,
            libc::ENOTCONN,
        );
        assert_eq!(
            env.count(Line::ErrorConnected),
            1,
            "control: a live socket's ENOTCONN is lifecycle"
        );
    }

    fn open_episode_then_recv(
        g: &DiagGuard,
        errno: i32,
    ) -> (DeviceUdpDiagnostics, PeerUdpDiagnostics, AttemptToken) {
        let env = DeviceUdpDiagnostics::for_tests(g);
        let mut d = PeerUdpDiagnostics::default();
        send_fail(
            &env,
            &mut d,
            conn_target(gen(1)),
            Site::TunConnected,
            libc::ENETUNREACH,
        );
        let a = err_att(&env, errno);
        observe_peer_recv_error(
            &env,
            &mut d,
            1,
            gen(1),
            None,
            &io_err(errno),
            a.token,
            false,
        );
        (env, d, a.token)
    }

    #[test]
    fn recv_eintr_is_debug_untouched_and_not_recovery() {
        let g = diag_lock();
        let (env, d, t) = open_episode_then_recv(&g, libc::EINTR);
        assert_eq!(
            env.decision_attempts().last(),
            Some(&(Line::DebugFailure, Some(t)))
        );
        assert_eq!(
            env.decisions().last(),
            Some(&(Line::DebugFailure, Some(Class::Transient))),
            "[RX-EINTR] DEBUG transient"
        );
        assert!(d.connected_active(), "[RX-EINTR] episode still active");
        assert_eq!(d.connected_failures(), 1, "[RX-EINTR] episode untouched");
        assert_eq!(env.count(Line::DebugRecovery), 0, "[RX-EINTR] not recovery");
    }

    #[test]
    fn recv_enobufs_is_debug_untouched_and_not_recovery() {
        let g = diag_lock();
        let (env, d, _) = open_episode_then_recv(&g, libc::ENOBUFS);
        assert_eq!(
            env.decisions().last(),
            Some(&(Line::DebugFailure, Some(Class::Transient))),
            "[RX-ENOBUFS] DEBUG transient"
        );
        assert!(d.connected_active(), "[RX-ENOBUFS] episode still active");
        assert_eq!(d.connected_failures(), 1, "[RX-ENOBUFS] episode untouched");
        assert_eq!(
            env.count(Line::DebugRecovery),
            0,
            "[RX-ENOBUFS] not recovery"
        );
    }

    // ======================================================== generations

    #[test]
    fn generation_allocator_last_normal_final_and_first_exhausted() {
        let a = GenAllocator::starting_at(u64::MAX - 1);
        assert_eq!(
            a.allocate(),
            gen(u64::MAX - 1),
            "[N1] last normal allocation"
        );
        assert_eq!(a.allocate(), gen(u64::MAX), "[N1] final valid generation");
        assert_eq!(
            a.allocate(),
            DiagGen::Untracked,
            "[N1] first exhausted allocation"
        );
    }

    #[test]
    fn exhausted_allocations_never_reuse_an_identity() {
        let a = GenAllocator::starting_at(u64::MAX);
        assert_eq!(a.allocate(), gen(u64::MAX));
        for _ in 0..1000 {
            assert_eq!(
                a.allocate(),
                DiagGen::Untracked,
                "[N1] no identity after exhaustion"
            );
        }
        assert_eq!(GenAllocator::new().allocate(), gen(1));
    }

    #[test]
    fn generation_allocation_near_exhaustion_is_unique_under_concurrency() {
        let a = Arc::new(GenAllocator::starting_at(u64::MAX - 63));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let a = Arc::clone(&a);
                std::thread::spawn(move || (0..32).map(|_| a.allocate()).collect::<Vec<_>>())
            })
            .collect();
        let all: Vec<DiagGen> = handles
            .into_iter()
            .flat_map(|h| h.join().expect("no panic"))
            .collect();
        let tracked: Vec<u64> = all
            .iter()
            .filter_map(|g| g.tracked().map(NonZeroU64::get))
            .collect();
        let unique: BTreeSet<u64> = tracked.iter().copied().collect();
        assert_eq!(all.len(), 256);
        assert_eq!(
            tracked.len(),
            64,
            "[GC] exactly the 64 remaining identities"
        );
        assert_eq!(unique.len(), 64, "[GC] every tracked identity unique");
        assert_eq!(
            tracked.iter().filter(|&&g| g == u64::MAX).count(),
            1,
            "[GC] the final value once"
        );
        assert_eq!(
            all.iter().filter(|g| **g == DiagGen::Untracked).count(),
            192,
            "[GC] the rest Untracked"
        );
    }

    #[test]
    fn m10b_replacement_does_not_carry_the_stale_episode() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let alloc = GenAllocator::starting_at(300);
        let mut p = test_peer(5);
        let g1 = commit_connected_socket_from(&env, &mut p, &alloc);
        for _ in 0..3 {
            send_fail(
                &env,
                p.udp_diagnostics_mut(),
                conn_target(g1),
                Site::TunConnected,
                libc::EBADF,
            );
        }
        let g2 = commit_connected_socket_from(&env, &mut p, &alloc);
        env.advance_clock(ERROR_COOLDOWN);
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g2),
            Site::TunConnected,
            libc::EBADF,
        );
        assert_eq!(
            p.udp_diagnostics().connected_failures(),
            1,
            "[M10b-c] fresh episode for the new generation"
        );
        assert_eq!(
            env.count(Line::ErrorConnected),
            2,
            "[M10b-c] the new generation may ERROR"
        );
    }

    #[test]
    fn m10b_listener_rebind_does_not_carry_the_stale_episode() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let to: SocketAddr = "192.0.2.5:51820".parse().unwrap();
        for _ in 0..3 {
            send_fail(
                &env,
                &mut d,
                Target::Listener {
                    id: lid(Family::V4, 1),
                    to,
                },
                Site::TimerV4,
                libc::EBADF,
            );
        }
        send_fail(
            &env,
            &mut d,
            Target::Listener {
                id: lid(Family::V4, 2),
                to,
            },
            Site::TimerV4,
            libc::EBADF,
        );
        assert_eq!(
            env.count(Line::ErrorListener),
            2,
            "[M10b-l] one per listener generation"
        );
        assert_eq!(d.listener_failures(), 1, "[M10b-l] fresh episode");
        env.advance_clock(WARN_COOLDOWN);
        send_fail(
            &env,
            &mut d,
            Target::Listener {
                id: lid(Family::V4, 3),
                to,
            },
            Site::TimerV4,
            libc::ENETUNREACH,
        );
        assert_eq!(
            (env.count(Line::WarnOpening), env.count(Line::WarnSummary)),
            (1, 0),
            "[M10b-l] an opening, not a summary"
        );
    }

    // ======================================================== Untracked (U1-U8)

    #[test]
    fn u1_u2_u3_untracked_actionable_errors_warn_under_the_peer_cooldown() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let t = conn_target(DiagGen::Untracked);
        send_fail(&env, &mut d, t, Site::TunConnected, libc::ECONNREFUSED);
        assert_eq!(
            env.count(Line::WarnOpening),
            1,
            "[U1] WARN, under the peer cooldown"
        );
        env.advance_clock(WARN_COOLDOWN - NS);
        send_fail(&env, &mut d, t, Site::TunConnected, libc::ENETUNREACH);
        assert_eq!(
            env.count(Line::WarnOpening),
            1,
            "[U2] no WARN before the cooldown"
        );
        env.advance_clock(NS);
        send_fail(&env, &mut d, t, Site::TunConnected, libc::ENETUNREACH);
        assert_eq!(
            (env.count(Line::WarnOpening), env.count(Line::WarnSummary)),
            (2, 0),
            "[U3] another opening WARN after it, never a summary"
        );
        assert!(!d.connected_active(), "[U1] no identity episode");
    }

    #[test]
    fn u4_untracked_connected_lifecycle_is_bounded_error() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let t = conn_target(DiagGen::Untracked);
        send_fail(&env, &mut d, t, Site::TunConnected, libc::EBADF);
        send_fail(&env, &mut d, t, Site::TunConnected, libc::EBADF);
        assert_eq!(
            env.count(Line::ErrorConnected),
            1,
            "[U4] one ERROR inside the cooldown"
        );
        env.advance_clock(ERROR_COOLDOWN);
        send_fail(&env, &mut d, t, Site::TunConnected, libc::EBADF);
        assert_eq!(env.count(Line::ErrorConnected), 2, "[U4] another after it");
    }

    #[test]
    fn u5_untracked_listener_lifecycle_is_bounded_per_device_family() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let (mut a, mut b) = (PeerUdpDiagnostics::default(), PeerUdpDiagnostics::default());
        let to: SocketAddr = "192.0.2.5:51820".parse().unwrap();
        send_fail(
            &env,
            &mut a,
            Target::Listener {
                id: ulid(Family::V4),
                to,
            },
            Site::TimerV4,
            libc::EBADF,
        );
        send_fail(
            &env,
            &mut b,
            Target::Listener {
                id: ulid(Family::V4),
                to,
            },
            Site::TimerV4,
            libc::EBADF,
        );
        let x = err_att(&env, libc::EBADF);
        observe_unauthenticated_send(&env, ulid(Family::V4), Site::CookieReply, to, 64, &x);
        assert_eq!(
            env.count(Line::ErrorListener),
            1,
            "[U5] one device/family ERROR, not one per peer"
        );
        let to6: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        send_fail(
            &env,
            &mut b,
            Target::Listener {
                id: ulid(Family::V6),
                to: to6,
            },
            Site::TimerV6,
            libc::EBADF,
        );
        assert_eq!(
            env.count(Line::ErrorListener),
            2,
            "[U5] the other family is independent"
        );
        env.advance_clock(ERROR_COOLDOWN);
        send_fail(
            &env,
            &mut a,
            Target::Listener {
                id: ulid(Family::V4),
                to,
            },
            Site::TimerV4,
            libc::EBADF,
        );
        assert_eq!(
            env.count(Line::ErrorListener),
            3,
            "[U5] bounded by the cooldown, not silenced for ever"
        );
    }

    #[test]
    fn u6_untracked_cookie_probe_and_mixed_stay_debug() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let to: SocketAddr = "198.51.100.7:53".parse().unwrap();
        for errno in [
            libc::ENETUNREACH,
            libc::ECONNREFUSED,
            libc::EMSGSIZE,
            libc::EPERM,
        ] {
            for site in [Site::CookieReply, Site::ProbeReply] {
                let a = err_att(&env, errno);
                observe_unauthenticated_send(&env, ulid(Family::V4), site, to, 64, &a);
            }
            send_fail(
                &env,
                &mut d,
                conn_target(DiagGen::Untracked),
                Site::ConnectedReply,
                errno,
            );
        }
        assert_eq!(env.decisions().len(), 12);
        assert!(
            env.decisions()
                .iter()
                .all(|(l, _)| *l == Line::DebugFailure),
            "[U6] DEBUG only"
        );
    }

    #[test]
    fn u7_untracked_recv_would_block_is_silent() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let sink = v4();
        let (p, conn, gn) = connected_peer(&env, 1, &sink, &GenAllocator::starting_at(0));
        assert_eq!(gn, DiagGen::Untracked);
        let p = Mutex::new(p);
        let mut buf = [MaybeUninit::<u8>::uninit(); 64];
        assert!(matches!(
            conn_recv_step(&env, &p, &conn, gn, local(&sink), &mut buf),
            RecvStep::End
        ));
        assert!(env.decisions().is_empty(), "[U7] silent");
    }

    #[test]
    fn u8_untracked_success_claims_no_recovery() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let sink = v4();
        let (mut p, conn, gn) = connected_peer(&env, 1, &sink, &GenAllocator::starting_at(0));
        env.plan(vec![rule(
            Op::Send,
            Some(Site::ConnectedFlush),
            Some(gn),
            None,
            vec![Step::Fail(libc::ENETUNREACH)],
        )]);
        connected_send_step(
            &env,
            &mut p,
            &conn,
            gn,
            local(&sink),
            Site::ConnectedFlush,
            b"x",
        );
        connected_send_step(
            &env,
            &mut p,
            &conn,
            gn,
            local(&sink),
            Site::ConnectedFlush,
            b"y",
        );
        assert_eq!(
            wait_recv(&sink).as_deref(),
            Some(&b"y"[..]),
            "[U8] I/O unchanged"
        );
        assert_eq!(
            env.decisions(),
            vec![(Line::WarnOpening, Some(Class::Route))],
            "[U8] no recovery after an Untracked failure"
        );
    }

    // ======================================================== seam and fault rules

    #[test]
    fn an_injected_failure_is_journaled_as_an_attempt_before_the_decision() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let sink = v4();
        let mut p = test_peer(1);
        let to = local(&sink);
        env.plan(vec![rule(
            Op::Send,
            Some(Site::TimerV4),
            None,
            Some(to),
            vec![Step::Fail(libc::EHOSTUNREACH)],
        )]);
        l.timer(&env, &mut p, to, b"a");
        let j = env.journal();
        assert_eq!(j.len(), 2, "[N5] {:?}", j);
        match (&j[0], &j[1]) {
            (
                JournalEvent::Attempt {
                    token,
                    injected: true,
                    result: Some(Err(Some(e))),
                    meta,
                    ..
                },
                JournalEvent::Decision {
                    attempt: Some(a),
                    line: Line::WarnOpening,
                    ..
                },
            ) => {
                assert_eq!(*e, libc::EHOSTUNREACH);
                assert_eq!(a, token, "[N5] the decision is linked to its attempt");
                assert_eq!(meta.dest, Some(to));
            }
            other => panic!("[N5] unexpected journal {:?}", other),
        }
        assert_eq!(env.pending_fail_steps(), 0, "every scripted fault consumed");
        assert!(stays_empty(&sink), "an injected attempt sends nothing");
    }

    #[test]
    fn fail_fail_succeed_sequence_counts_three_attempts() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let sink = v4();
        let (mut p, _conn, gn) = connected_peer(&env, 1, &sink, &GenAllocator::starting_at(10));
        env.plan(vec![rule(
            Op::Send,
            Some(Site::TunConnected),
            Some(gn),
            None,
            vec![Step::Fail(libc::EAGAIN), Step::Fail(libc::EAGAIN)],
        )]);
        for _ in 0..3 {
            assert!(l.tun(&env, &mut p, b"seq"));
        }
        assert_eq!(
            env.attempts(Site::TunConnected),
            3,
            "[N5] three attempts journaled"
        );
        let injected = env
            .journal()
            .iter()
            .filter(|e| matches!(e, JournalEvent::Attempt { injected: true, .. }))
            .count();
        assert_eq!(injected, 2, "[N5] two injected attempts");
        assert_eq!(wait_recv(&sink).as_deref(), Some(&b"seq"[..]));
        assert!(stays_empty(&sink), "exactly one datagram left the host");
        assert_eq!(env.count(Line::DebugRecovery), 1);
    }

    #[test]
    fn class_a_then_class_b_sequence() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let sink = v4();
        let (mut p, _conn, gn) = connected_peer(&env, 1, &sink, &GenAllocator::starting_at(3));
        env.plan(vec![rule(
            Op::Send,
            None,
            Some(gn),
            None,
            vec![Step::Fail(libc::ENETUNREACH), Step::Fail(libc::EMSGSIZE)],
        )]);
        l.tun(&env, &mut p, b"1");
        l.tun(&env, &mut p, b"2");
        assert_eq!(
            env.decisions(),
            vec![
                (Line::WarnOpening, Some(Class::Route)),
                (Line::DebugFailure, Some(Class::Size))
            ]
        );
    }

    #[test]
    #[should_panic(expected = "overlapping fault rules")]
    fn overlapping_wildcard_and_exact_generation_is_rejected() {
        let g = diag_lock();
        DeviceUdpDiagnostics::for_tests(&g).plan(vec![
            rule(Op::Send, Some(Site::TunV4), None, None, vec![Step::Fail(1)]),
            rule(
                Op::Send,
                Some(Site::TunV4),
                Some(gen(4)),
                None,
                vec![Step::Fail(1)],
            ),
        ]);
    }

    #[test]
    #[should_panic(expected = "overlapping fault rules")]
    fn overlapping_wildcard_and_exact_destination_is_rejected() {
        let g = diag_lock();
        let d: SocketAddr = "192.0.2.9:1".parse().unwrap();
        DeviceUdpDiagnostics::for_tests(&g).plan(vec![
            rule(
                Op::Send,
                Some(Site::TimerV4),
                None,
                None,
                vec![Step::Fail(1)],
            ),
            rule(
                Op::Send,
                Some(Site::TimerV4),
                None,
                Some(d),
                vec![Step::Fail(1)],
            ),
        ]);
    }

    #[test]
    #[should_panic(expected = "overlapping fault rules")]
    fn overlapping_generic_and_exact_site_is_rejected() {
        let g = diag_lock();
        DeviceUdpDiagnostics::for_tests(&g).plan(vec![
            rule(Op::Send, None, Some(gen(4)), None, vec![Step::Fail(1)]),
            rule(
                Op::Send,
                Some(Site::ConnectedFlush),
                Some(gen(4)),
                None,
                vec![Step::Fail(1)],
            ),
        ]);
    }

    #[test]
    #[should_panic(expected = "overlapping fault rules")]
    fn extend_plan_rejects_overlap_with_an_installed_rule() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        env.plan(vec![rule(Op::Recv, None, None, None, vec![Step::Fail(1)])]);
        env.extend_plan(vec![rule(
            Op::Recv,
            None,
            Some(gen(2)),
            None,
            vec![Step::Fail(1)],
        )]);
    }

    #[test]
    fn disjoint_rules_are_accepted() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        env.plan(vec![
            rule(Op::Send, Some(Site::TunV4), None, None, vec![Step::Fail(1)]),
            rule(Op::Send, Some(Site::TunV6), None, None, vec![Step::Fail(1)]),
            rule(Op::Recv, None, None, None, vec![Step::Fail(1)]),
            rule(
                Op::Send,
                Some(Site::TimerV4),
                Some(gen(1)),
                None,
                vec![Step::Fail(1)],
            ),
            rule(
                Op::Send,
                Some(Site::TimerV4),
                Some(gen(2)),
                None,
                vec![Step::Fail(1)],
            ),
        ]);
        env.extend_plan(vec![rule(
            Op::Send,
            Some(Site::TimerV6),
            None,
            None,
            vec![Step::Fail(1)],
        )]);
        assert_eq!(env.pending_fail_steps(), 6);
    }

    /// One logical operation is one attempt, in every step: a retry around
    /// any boundary call would meet the plan's next scripted failure and be
    /// journaled as a second attempt.
    #[test]
    fn a_failed_send_is_attempted_exactly_once_by_the_step() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let sink = v4();
        let to = local(&sink);
        let transient = || {
            vec![
                Step::Fail(libc::EAGAIN),
                Step::Fail(libc::EINTR),
                Step::Fail(libc::ENOBUFS),
            ]
        };
        let (mut p, conn, gn) = connected_peer(&env, 1, &sink, &GenAllocator::starting_at(20));
        env.plan(vec![
            rule(Op::Send, Some(Site::TimerV4), None, None, transient()),
            rule(Op::Send, Some(Site::ProbeReply), None, None, transient()),
            rule(
                Op::Send,
                Some(Site::HandshakeReply),
                None,
                None,
                transient(),
            ),
            rule(
                Op::Send,
                Some(Site::ConnectedFlush),
                None,
                None,
                transient(),
            ),
            rule(
                Op::Recv,
                None,
                None,
                None,
                vec![Step::Fail(libc::EINTR), Step::Fail(libc::EINTR)],
            ),
            rule(Op::Send, Some(Site::TunConnected), None, None, transient()),
        ]);
        l.timer(&env, &mut p, to, b"timer");
        assert_eq!(
            env.attempts(Site::TimerV4),
            1,
            "[M11] timer: one send, one attempt"
        );
        unauthenticated_send_step(
            &env,
            &l.u4,
            l.id4,
            Site::ProbeReply,
            b"probe",
            to,
            &to.into(),
        );
        assert_eq!(
            env.attempts(Site::ProbeReply),
            1,
            "[M11] unauthenticated: one attempt"
        );
        listener_peer_send_step(
            &env,
            &mut p,
            &l.u4,
            l.id4,
            Site::HandshakeReply,
            b"reply",
            to,
            &to.into(),
        );
        assert_eq!(
            env.attempts(Site::HandshakeReply),
            1,
            "[M11] listener peer: one attempt"
        );
        connected_send_step(&env, &mut p, &conn, gn, to, Site::ConnectedFlush, b"flush");
        assert_eq!(
            env.attempts(Site::ConnectedFlush),
            1,
            "[M11] connected: one attempt"
        );
        let p = Mutex::new(p);
        let mut buf = [MaybeUninit::<u8>::uninit(); 64];
        assert!(matches!(
            conn_recv_step(&env, &p, &conn, gn, to, &mut buf),
            RecvStep::End
        ));
        assert_eq!(
            env.attempts(Site::ConnectedRecv),
            1,
            "[M11] receive: one attempt"
        );
        assert!(l.tun(&env, &mut p.lock(), b"tun"));
        assert_eq!(
            env.attempts(Site::TunConnected),
            1,
            "[M11] tun: one attempt"
        );
        assert!(
            stays_empty(&sink),
            "[M11] no failed datagram is ever re-sent"
        );
    }

    // ======================================================== site and family wiring

    #[test]
    fn timer_step_sends_each_family_on_its_own_listener() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let (s4, s6) = (v4(), v6());
        let mut p = test_peer(1);
        l.timer(&env, &mut p, local(&s4), b"four");
        l.timer(&env, &mut p, local(&s6), b"six");
        assert_eq!(wait_recv(&s4).as_deref(), Some(&b"four"[..]));
        assert_eq!(wait_recv(&s6).as_deref(), Some(&b"six"[..]));
        let sites: Vec<(Site, SocketRef)> =
            attempted(&env).iter().map(|(s, r, _)| (*s, *r)).collect();
        assert_eq!(
            sites,
            vec![
                (Site::TimerV4, SocketRef::Listener(l.id4)),
                (Site::TimerV6, SocketRef::Listener(l.id6))
            ],
            "[FAM] one Site per family branch"
        );
    }

    #[test]
    fn timer_step_sends_v4_endpoints_on_the_v4_listener() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let sink = v4();
        let mut p = test_peer(1);
        l.timer(&env, &mut p, local(&sink), b"timer4");
        let (bytes, from) = wait_recv_from(&sink).expect("[FAM-T4] delivered");
        assert_eq!(bytes, b"timer4");
        assert_eq!(from, local(&l.u4), "[FAM-T4] sent from the IPv4 listener");
        assert_eq!(
            attempted(&env),
            vec![(
                Site::TimerV4,
                SocketRef::Listener(l.id4),
                Some(local(&sink))
            )],
            "[FAM-T4] journal site, socket and destination"
        );
    }

    #[test]
    fn timer_step_sends_v6_endpoints_on_the_v6_listener() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let sink = v6();
        let mut p = test_peer(1);
        l.timer(&env, &mut p, local(&sink), b"timer6");
        let (bytes, from) = wait_recv_from(&sink).expect("[FAM-T6] delivered");
        assert_eq!(bytes, b"timer6");
        assert_eq!(from, local(&l.u6), "[FAM-T6] sent from the IPv6 listener");
        assert_eq!(
            attempted(&env),
            vec![(
                Site::TimerV6,
                SocketRef::Listener(l.id6),
                Some(local(&sink))
            )],
            "[FAM-T6] journal site, socket and destination"
        );
    }

    #[test]
    fn tun_step_prefers_the_connected_socket() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let sink = v4();
        let (mut p, conn, gn) = connected_peer(&env, 1, &sink, &GenAllocator::starting_at(30));
        assert!(l.tun(&env, &mut p, b"via-conn"));
        let (bytes, from) = wait_recv_from(&sink).expect("[TUNC] delivered");
        assert_eq!(bytes, b"via-conn");
        assert_eq!(
            from,
            local(&conn),
            "[TUNC] sent from the connected socket, not a listener"
        );
        assert_eq!(
            attempted(&env),
            vec![(
                Site::TunConnected,
                SocketRef::Connected(gn),
                Some(local(&sink))
            )],
            "[TUNC] journal site, socket and destination"
        );
    }

    #[test]
    fn tun_step_sends_v4_endpoints_on_the_v4_listener() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let sink = v4();
        let mut p = test_peer_with(1, AmneziaConfig::default(), Some(local(&sink)));
        assert!(l.tun(&env, &mut p, b"tun4"));
        let (bytes, from) = wait_recv_from(&sink).expect("[FAM-U4] delivered");
        assert_eq!(bytes, b"tun4");
        assert_eq!(from, local(&l.u4), "[FAM-U4] sent from the IPv4 listener");
        assert_eq!(
            attempted(&env),
            vec![(Site::TunV4, SocketRef::Listener(l.id4), Some(local(&sink)))],
            "[FAM-U4] journal site, socket and destination"
        );
    }

    #[test]
    fn tun_step_sends_v6_endpoints_on_the_v6_listener() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let sink = v6();
        let mut p = test_peer_with(1, AmneziaConfig::default(), Some(local(&sink)));
        assert!(l.tun(&env, &mut p, b"tun6"));
        let (bytes, from) = wait_recv_from(&sink).expect("[FAM-U6] delivered");
        assert_eq!(bytes, b"tun6");
        assert_eq!(from, local(&l.u6), "[FAM-U6] sent from the IPv6 listener");
        assert_eq!(
            attempted(&env),
            vec![(Site::TunV6, SocketRef::Listener(l.id6), Some(local(&sink)))],
            "[FAM-U6] journal site, socket and destination"
        );
    }

    #[test]
    fn tun_step_without_endpoint_returns_false_and_sends_nothing() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let mut p = test_peer(1);
        assert!(
            !l.tun(&env, &mut p, b"nowhere"),
            "neither a socket nor an address"
        );
        assert!(env.journal().is_empty(), "no attempt, no decision");
    }

    #[test]
    fn listener_peer_step_records_handshake_replies() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let (s4, s6) = (v4(), v6());
        let mut p = test_peer(1);
        for (sock, id, sink) in [(&l.u4, l.id4, &s4), (&l.u6, l.id6, &s6)] {
            let to = local(sink);
            listener_peer_send_step(
                &env,
                &mut p,
                sock,
                id,
                Site::HandshakeReply,
                b"response",
                to,
                &to.into(),
            );
            assert_eq!(wait_recv(sink).as_deref(), Some(&b"response"[..]));
        }
        assert_eq!(
            attempted(&env),
            vec![
                (
                    Site::HandshakeReply,
                    SocketRef::Listener(l.id4),
                    Some(local(&s4))
                ),
                (
                    Site::HandshakeReply,
                    SocketRef::Listener(l.id6),
                    Some(local(&s6))
                )
            ]
        );
        // Eligible: a refusal WARNs.
        env.plan(vec![rule(
            Op::Send,
            Some(Site::HandshakeReply),
            None,
            None,
            vec![Step::Fail(libc::ECONNREFUSED)],
        )]);
        let to = local(&s4);
        listener_peer_send_step(
            &env,
            &mut p,
            &l.u4,
            l.id4,
            Site::HandshakeReply,
            b"response",
            to,
            &to.into(),
        );
        assert_eq!(
            env.decisions(),
            vec![(Line::WarnOpening, Some(Class::Refused))]
        );
        assert!(p.udp_diagnostics().listener_active());
    }

    #[test]
    fn listener_peer_step_records_flushes() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let sink = v4();
        let to = local(&sink);
        let mut p = test_peer(1);
        listener_peer_send_step(
            &env,
            &mut p,
            &l.u4,
            l.id4,
            Site::ListenerFlush,
            b"queued",
            to,
            &to.into(),
        );
        assert_eq!(wait_recv(&sink).as_deref(), Some(&b"queued"[..]));
        assert_eq!(
            attempted(&env),
            vec![(Site::ListenerFlush, SocketRef::Listener(l.id4), Some(to))]
        );
        env.plan(vec![rule(
            Op::Send,
            Some(Site::ListenerFlush),
            None,
            None,
            vec![Step::Fail(libc::EHOSTUNREACH)],
        )]);
        listener_peer_send_step(
            &env,
            &mut p,
            &l.u4,
            l.id4,
            Site::ListenerFlush,
            b"queued",
            to,
            &to.into(),
        );
        assert_eq!(
            env.decisions(),
            vec![(Line::WarnOpening, Some(Class::Route))]
        );
    }

    #[test]
    fn unauthenticated_step_records_probe_replies_at_debug() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let prober = v4();
        let to = local(&prober);
        unauthenticated_send_step(
            &env,
            &l.u4,
            l.id4,
            Site::ProbeReply,
            b"servfail",
            to,
            &to.into(),
        );
        assert_eq!(
            wait_recv(&prober).as_deref(),
            Some(&b"servfail"[..]),
            "I/O unchanged"
        );
        assert_eq!(
            attempted(&env),
            vec![(Site::ProbeReply, SocketRef::Listener(l.id4), Some(to))]
        );
        env.plan(vec![rule(
            Op::Send,
            Some(Site::ProbeReply),
            None,
            None,
            vec![Step::Fail(libc::ECONNREFUSED)],
        )]);
        unauthenticated_send_step(
            &env,
            &l.u4,
            l.id4,
            Site::ProbeReply,
            b"servfail",
            to,
            &to.into(),
        );
        assert_eq!(
            env.decisions(),
            vec![(Line::DebugFailure, Some(Class::Refused))]
        );
    }

    #[test]
    fn unauthenticated_step_records_cookie_replies_at_debug() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let prober = v4();
        let to = local(&prober);
        unauthenticated_send_step(
            &env,
            &l.u4,
            l.id4,
            Site::CookieReply,
            b"cookie-reply",
            to,
            &to.into(),
        );
        assert_eq!(
            wait_recv(&prober).as_deref(),
            Some(&b"cookie-reply"[..]),
            "I/O unchanged"
        );
        assert_eq!(
            attempted(&env),
            vec![(Site::CookieReply, SocketRef::Listener(l.id4), Some(to))]
        );
        env.plan(vec![rule(
            Op::Send,
            Some(Site::CookieReply),
            None,
            None,
            vec![Step::Fail(libc::EMSGSIZE)],
        )]);
        unauthenticated_send_step(
            &env,
            &l.u4,
            l.id4,
            Site::CookieReply,
            b"cookie-reply",
            to,
            &to.into(),
        );
        assert_eq!(
            env.decisions(),
            vec![(Line::DebugFailure, Some(Class::Size))]
        );
    }

    #[test]
    fn connected_step_mixed_reply_stays_debug() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let sink = v4();
        let (mut p, conn, gn) = connected_peer(&env, 1, &sink, &GenAllocator::starting_at(40));
        connected_send_step(
            &env,
            &mut p,
            &conn,
            gn,
            local(&sink),
            Site::ConnectedReply,
            b"reply",
        );
        assert_eq!(wait_recv(&sink).as_deref(), Some(&b"reply"[..]));
        assert_eq!(
            attempted(&env),
            vec![(
                Site::ConnectedReply,
                SocketRef::Connected(gn),
                Some(local(&sink))
            )]
        );
        env.plan(vec![rule(
            Op::Send,
            Some(Site::ConnectedReply),
            Some(gn),
            None,
            vec![Step::Fail(libc::ECONNREFUSED)],
        )]);
        connected_send_step(
            &env,
            &mut p,
            &conn,
            gn,
            local(&sink),
            Site::ConnectedReply,
            b"reply",
        );
        assert_eq!(
            env.decisions(),
            vec![(Line::DebugFailure, Some(Class::Refused))],
            "[M7] mixed is DEBUG"
        );
    }

    #[test]
    fn connected_step_flush_is_eligible() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let sink = v4();
        let (mut p, conn, gn) = connected_peer(&env, 1, &sink, &GenAllocator::starting_at(41));
        connected_send_step(
            &env,
            &mut p,
            &conn,
            gn,
            local(&sink),
            Site::ConnectedFlush,
            b"flush",
        );
        assert_eq!(wait_recv(&sink).as_deref(), Some(&b"flush"[..]));
        assert_eq!(
            attempted(&env),
            vec![(
                Site::ConnectedFlush,
                SocketRef::Connected(gn),
                Some(local(&sink))
            )]
        );
        env.plan(vec![rule(
            Op::Send,
            Some(Site::ConnectedFlush),
            Some(gn),
            None,
            vec![Step::Fail(libc::ECONNREFUSED)],
        )]);
        connected_send_step(
            &env,
            &mut p,
            &conn,
            gn,
            local(&sink),
            Site::ConnectedFlush,
            b"flush",
        );
        assert_eq!(
            env.decisions(),
            vec![(Line::WarnOpening, Some(Class::Refused))]
        );
    }

    // ======================================================== attempt correlation (J1-J4)

    #[test]
    fn j1_a_replacement_after_an_attempt_records_no_attempt() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let alloc = GenAllocator::starting_at(40);
        let mut p = test_peer(2);
        let g1 = commit_connected_socket_from(&env, &mut p, &alloc);
        let a = err_att(&env, libc::ENETUNREACH);
        observe_peer_send(
            &env,
            p.udp_diagnostics_mut(),
            2,
            conn_target(g1),
            Site::TunConnected,
            10,
            &a,
            false,
        );
        commit_connected_socket_from(&env, &mut p, &alloc);
        assert_eq!(
            env.decision_attempts().last(),
            Some(&(Line::DebugClosed, None)),
            "[R4] [J1] the lifecycle record has attempt = None"
        );
    }

    #[test]
    fn j2_a_new_fixture_on_the_same_thread_inherits_nothing() {
        let g = diag_lock();
        {
            let env_a = DeviceUdpDiagnostics::for_tests(&g);
            let _ = err_att(&env_a, libc::ENETUNREACH);
        }
        let env_b = DeviceUdpDiagnostics::for_tests(&g);
        let alloc = GenAllocator::starting_at(50);
        let mut p = test_peer(3);
        let g1 = commit_connected_socket_from(&env_b, &mut p, &alloc);
        let a = err_att(&env_b, libc::ENETUNREACH);
        assert_eq!(
            a.token.fixture,
            env_b.fixture(),
            "[J2] the token belongs to fixture B"
        );
        observe_peer_send(
            &env_b,
            p.udp_diagnostics_mut(),
            3,
            conn_target(g1),
            Site::TunConnected,
            10,
            &a,
            false,
        );
        commit_connected_socket_from(&env_b, &mut p, &alloc);
        assert_eq!(
            env_b.decision_attempts(),
            vec![
                (Line::WarnOpening, Some(a.token)),
                (Line::DebugClosed, None)
            ],
            "[J2] nothing inherited"
        );
    }

    #[test]
    fn j3_interleaved_fixtures_keep_their_own_tokens() {
        let g = diag_lock();
        let env_a = DeviceUdpDiagnostics::for_tests(&g);
        let env_b = DeviceUdpDiagnostics::for_tests(&g);
        let (mut da, mut db) = (PeerUdpDiagnostics::default(), PeerUdpDiagnostics::default());
        let a1 = err_att(&env_a, libc::ENETUNREACH);
        let b1 = err_att(&env_b, libc::ENETUNREACH);
        let a2 = ok_att(&env_a);
        observe_peer_send(
            &env_a,
            &mut da,
            1,
            conn_target(gen(1)),
            Site::TunConnected,
            10,
            &a1,
            false,
        );
        observe_peer_send(
            &env_b,
            &mut db,
            1,
            conn_target(gen(1)),
            Site::TunConnected,
            10,
            &b1,
            false,
        );
        assert_ne!(a1.token, a2.token);
        assert_eq!(
            env_a.decision_attempts(),
            vec![(Line::WarnOpening, Some(a1.token))],
            "[J3] A's decision names A1, not A's latest"
        );
        assert_eq!(
            env_b.decision_attempts(),
            vec![(Line::WarnOpening, Some(b1.token))],
            "[J3] B's decision names B1"
        );
        assert_eq!(b1.token.fixture, env_b.fixture());
    }

    #[test]
    fn j4_the_token_follows_the_call_flow_not_the_thread() {
        let g = diag_lock();
        let env = Arc::new(DeviceUdpDiagnostics::for_tests(&g));
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = {
            let env = Arc::clone(&env);
            std::thread::spawn(move || tx.send(err_att(&env, libc::ENETUNREACH)).unwrap())
        };
        worker.join().unwrap();
        let from_worker = rx.recv().unwrap();
        let here = ok_att(&env);
        let mut d = PeerUdpDiagnostics::default();
        observe_peer_send(
            &env,
            &mut d,
            1,
            conn_target(gen(1)),
            Site::TunConnected,
            10,
            &from_worker,
            false,
        );
        assert_ne!(from_worker.token, here.token);
        assert_eq!(
            env.decision_attempts(),
            vec![(Line::WarnOpening, Some(from_worker.token))],
            "[J3] [J4] the worker's token, passed explicitly"
        );
    }

    // ======================================================== replacement (R1-R4)

    #[test]
    fn replacement_keeps_both_cooldown_anchors() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let alloc = GenAllocator::starting_at(65);
        let mut p = test_peer(4);
        let g1 = commit_connected_socket_from(&env, &mut p, &alloc);
        let t1 = conn_target(g1);
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            t1,
            Site::TunConnected,
            libc::ENETUNREACH,
        );
        env.advance_clock(Duration::from_secs(1));
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            t1,
            Site::TunConnected,
            libc::EBADF,
        );
        let before = anchors(p.udp_diagnostics());
        assert_eq!(before, (Some(Duration::ZERO), Some(Duration::from_secs(1))));
        let g2 = commit_connected_socket_from(&env, &mut p, &alloc);
        assert_eq!(
            anchors(p.udp_diagnostics()),
            before,
            "[R-ANCH] a new socket is no reason to WARN or ERROR again"
        );
        let t2 = conn_target(g2);
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            t2,
            Site::TunConnected,
            libc::ENETUNREACH,
        );
        assert_eq!(
            env.count(Line::WarnOpening),
            1,
            "[R-ANCH] still inside the cooldown"
        );
    }

    #[test]
    fn r1_connected_replacement_closes_the_old_identity() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let alloc = GenAllocator::starting_at(60);
        let mut p = test_peer(4);
        let g1 = commit_connected_socket_from(&env, &mut p, &alloc);
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g1),
            Site::TunConnected,
            libc::ENETUNREACH,
        );
        let (g2, decision) = p.assign_connected_generation_from(&alloc);
        assert_eq!(
            decision,
            ReplacementDecision::ClosedEpisode {
                last: Some(Failure {
                    class: Class::Route,
                    os_error: Some(libc::ENETUNREACH)
                }),
                failures: 1
            },
            "[R1] a pure decision"
        );
        record_replacement(&env, 4, g2, decision);
        assert_eq!(
            env.count(Line::DebugClosed),
            1,
            "[R1] the closure is recorded once"
        );
        assert!(
            !p.udp_diagnostics().connected_active(),
            "[R1] the new identity starts inactive"
        );
        let (_, again) = p.assign_connected_generation_from(&alloc);
        assert_eq!(
            again,
            ReplacementDecision::Rekeyed,
            "[R1] nothing to close the second time"
        );
    }

    /// The Device's own upgrade plumbing, with the process allocator: the
    /// commit records the closure.
    #[test]
    fn r1_device_plumbing_records_the_replacement() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut p = test_peer(4);
        let g1 = commit_connected_socket(&env, &mut p);
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g1),
            Site::TunConnected,
            libc::ENETUNREACH,
        );
        let g2 = commit_connected_socket(&env, &mut p);
        assert_ne!(g1, g2, "[REPL] a fresh generation");
        assert_eq!(p.assigned_connected_generation(), g2);
        assert_eq!(
            env.decision_attempts().last(),
            Some(&(Line::DebugClosed, None)),
            "[REPL] the upgrade records the closure"
        );
    }

    #[test]
    fn r2_listener_replacement_uses_the_new_generation_and_family_latch() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let to: SocketAddr = "192.0.2.5:51820".parse().unwrap();
        send_fail(
            &env,
            &mut d,
            Target::Listener {
                id: lid(Family::V4, 70),
                to,
            },
            Site::TimerV4,
            libc::EBADF,
        );
        send_fail(
            &env,
            &mut d,
            Target::Listener {
                id: lid(Family::V4, 70),
                to,
            },
            Site::TimerV4,
            libc::EBADF,
        );
        send_fail(
            &env,
            &mut d,
            Target::Listener {
                id: lid(Family::V4, 71),
                to,
            },
            Site::TimerV4,
            libc::EBADF,
        );
        assert_eq!(
            env.count(Line::ErrorListener),
            2,
            "[R2] once per listener generation"
        );
        let closed: Vec<_> = env
            .decision_attempts()
            .into_iter()
            .filter(|(l, _)| *l == Line::DebugClosed)
            .collect();
        assert_eq!(
            closed,
            vec![(Line::DebugClosed, None)],
            "[R2] re-key closure without an attempt"
        );
    }

    #[test]
    fn r3_replacement_journal_has_no_attempt() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let alloc = GenAllocator::starting_at(80);
        let mut p = test_peer(6);
        let g1 = commit_connected_socket_from(&env, &mut p, &alloc);
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g1),
            Site::TunConnected,
            libc::ENETUNREACH,
        );
        commit_connected_socket_from(&env, &mut p, &alloc);
        let closed: Vec<_> = env
            .decision_attempts()
            .into_iter()
            .filter(|(l, _)| *l == Line::DebugClosed)
            .collect();
        assert_eq!(
            closed,
            vec![(Line::DebugClosed, None)],
            "[R3] attempt = None"
        );
    }

    #[test]
    fn r4_replacement_cannot_inherit_a_socket_attempt_token() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let alloc = GenAllocator::starting_at(90);
        let mut p = test_peer(7);
        let g1 = commit_connected_socket_from(&env, &mut p, &alloc);
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g1),
            Site::TunConnected,
            libc::ENETUNREACH,
        );
        let unrelated = ok_att(&env);
        assert_eq!(env.last_attempt(), Some(unrelated.token));
        commit_connected_socket_from(&env, &mut p, &alloc);
        assert_eq!(
            env.decision_attempts().last(),
            Some(&(Line::DebugClosed, None)),
            "[R4] the closure does not take the latest attempt"
        );
    }

    // ======================================================== stale success (S1-S3)

    fn anchors(d: &PeerUdpDiagnostics) -> (Option<Duration>, Option<Duration>) {
        (d.last_warn(), d.last_error())
    }

    #[test]
    fn s1_historical_g1_success_may_close_g1_and_keeps_both_anchors() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let alloc = GenAllocator::starting_at(110);
        let mut p = test_peer(8);
        let g1 = commit_connected_socket_from(&env, &mut p, &alloc);
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g1),
            Site::TunConnected,
            libc::ENETUNREACH,
        );
        env.advance_clock(Duration::from_secs(1));
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g1),
            Site::TunConnected,
            libc::EBADF,
        );
        let before = anchors(p.udp_diagnostics());
        assert_eq!(before, (Some(Duration::ZERO), Some(Duration::from_secs(1))));
        let s = ok_att(&env);
        observe_peer_send(
            &env,
            p.udp_diagnostics_mut(),
            8,
            conn_target(g1),
            Site::ConnectedFlush,
            10,
            &s,
            false,
        );
        assert_eq!(
            env.decision_attempts().last(),
            Some(&(Line::DebugRecovery, Some(s.token))),
            "[S1] recovery for G1, tied to its attempt"
        );
        assert_eq!(
            anchors(p.udp_diagnostics()),
            before,
            "[S1] WARN and ERROR anchors unchanged"
        );
        assert!(!p.udp_diagnostics().connected_active());
    }

    #[test]
    fn s2_late_g1_success_after_g2_with_no_failure_changes_nothing() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let alloc = GenAllocator::starting_at(120);
        let mut p = test_peer(8);
        let g1 = commit_connected_socket_from(&env, &mut p, &alloc);
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g1),
            Site::TunConnected,
            libc::ENETUNREACH,
        );
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g1),
            Site::TunConnected,
            libc::EBADF,
        );
        commit_connected_socket_from(&env, &mut p, &alloc);
        let (before_anchors, before_decisions) =
            (anchors(p.udp_diagnostics()), env.decisions().len());
        send_ok(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g1),
            Site::ConnectedFlush,
        );
        assert_eq!(env.count(Line::DebugRecovery), 0, "[S2] no recovery");
        assert_eq!(
            env.decisions().len(),
            before_decisions,
            "[S2] no decision at all"
        );
        assert_eq!(
            anchors(p.udp_diagnostics()),
            before_anchors,
            "[S2] anchors unchanged"
        );
        assert!(!p.udp_diagnostics().connected_active());
    }

    #[test]
    fn s3_late_g1_success_with_an_active_g2_episode_changes_nothing() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let alloc = GenAllocator::starting_at(130);
        let mut p = test_peer(8);
        let g1 = commit_connected_socket_from(&env, &mut p, &alloc);
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g1),
            Site::TunConnected,
            libc::ENETUNREACH,
        );
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g1),
            Site::TunConnected,
            libc::EBADF,
        );
        env.advance_clock(Duration::from_secs(1));
        let g2 = commit_connected_socket_from(&env, &mut p, &alloc);
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g2),
            Site::TunConnected,
            libc::ENETUNREACH,
        );
        let before = anchors(p.udp_diagnostics());
        let decisions = env.decisions().len();
        send_ok(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g1),
            Site::ConnectedFlush,
        );
        assert_eq!(
            env.decisions().len(),
            decisions,
            "[S3] no recovery, no closure"
        );
        assert!(
            p.udp_diagnostics().connected_active(),
            "[S3] G2's episode still active"
        );
        assert_eq!(
            p.udp_diagnostics().connected_failures(),
            1,
            "[S3] G2's count unchanged"
        );
        assert_eq!(
            anchors(p.udp_diagnostics()),
            before,
            "[S3] both anchors unchanged"
        );
        send_ok(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g2),
            Site::TunConnected,
        );
        assert_eq!(
            env.count(Line::DebugRecovery),
            1,
            "[S3] the same identity closes it"
        );
    }

    // ======================================================== handler steps (M6, M12, M15)

    fn open_connected_episode(
        env: &DeviceUdpDiagnostics,
        p: &Mutex<Peer>,
        conn: &Socket,
        g: DiagGen,
        ep: SocketAddr,
    ) {
        env.plan(vec![rule(
            Op::Send,
            Some(Site::ConnectedFlush),
            Some(g),
            None,
            vec![Step::Fail(libc::ENETUNREACH)],
        )]);
        connected_send_step(env, &mut p.lock(), conn, g, ep, Site::ConnectedFlush, b"f");
        assert!(p.lock().udp_diagnostics().connected_active());
    }

    #[test]
    fn m6_conn_recv_step_would_block_is_not_recovery() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let sink = v4();
        let (p, conn, gn) = connected_peer(&env, 2, &sink, &GenAllocator::starting_at(50));
        let p = Mutex::new(p);
        let ep = local(&sink);
        open_connected_episode(&env, &p, &conn, gn, ep);
        env.extend_plan(vec![rule(
            Op::Recv,
            None,
            Some(gn),
            None,
            vec![Step::Fail(libc::EAGAIN)],
        )]);
        let mut buf = [MaybeUninit::<u8>::uninit(); 64];
        assert!(
            matches!(
                conn_recv_step(&env, &p, &conn, gn, ep, &mut buf),
                RecvStep::End
            ),
            "injected WouldBlock"
        );
        assert!(
            matches!(
                conn_recv_step(&env, &p, &conn, gn, ep, &mut buf),
                RecvStep::End
            ),
            "real WouldBlock"
        );
        assert_eq!(env.attempts(Site::ConnectedRecv), 2);
        assert_eq!(
            env.decisions().len(),
            1,
            "[M6] nothing after the opening failure"
        );
        assert_eq!(
            env.count(Line::DebugRecovery),
            0,
            "[M6] no recovery on WouldBlock"
        );
        assert!(
            p.lock().udp_diagnostics().connected_active(),
            "[M6] the episode is still active"
        );
    }

    #[test]
    fn m12_conn_recv_step_success_is_not_recovery() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let remote = v4();
        let (p, conn, gn) = connected_peer(&env, 2, &remote, &GenAllocator::starting_at(60));
        remote.connect(&local(&conn).into()).unwrap();
        let p = Mutex::new(p);
        let ep = local(&remote);
        open_connected_episode(&env, &p, &conn, gn, ep);
        remote.send(b"inbound").unwrap();
        let mut buf = [MaybeUninit::<u8>::uninit(); 64];
        let mut got = false;
        for _ in 0..200 {
            if let RecvStep::Datagram(n) = conn_recv_step(&env, &p, &conn, gn, ep, &mut buf) {
                assert_eq!(n, 7);
                got = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(got, "the datagram arrived");
        assert_eq!(
            env.count(Line::DebugRecovery),
            0,
            "[M12] no recovery on a receive success"
        );
        assert!(
            p.lock().udp_diagnostics().connected_active(),
            "[M12] the episode is still active"
        );
    }

    #[test]
    fn m15_conn_steps_apply_retirement_before_classification() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let sink = v4();
        let (p, conn, gn) = connected_peer(&env, 3, &sink, &GenAllocator::starting_at(70));
        // The peer no longer commits this socket: the handler is retired.
        p.endpoint_mut().conn = None;
        let p = Mutex::new(p);
        let ep = local(&sink);
        env.plan(vec![
            rule(
                Op::Recv,
                None,
                Some(gn),
                None,
                vec![Step::Fail(libc::EBADF)],
            ),
            rule(
                Op::Send,
                Some(Site::ConnectedReply),
                Some(gn),
                None,
                vec![Step::Fail(libc::EPIPE)],
            ),
        ]);
        let mut buf = [MaybeUninit::<u8>::uninit(); 64];
        conn_recv_step(&env, &p, &conn, gn, ep, &mut buf);
        connected_send_step(
            &env,
            &mut p.lock(),
            &conn,
            gn,
            ep,
            Site::ConnectedReply,
            b"r",
        );
        assert_eq!(
            env.decisions(),
            vec![(Line::DebugRetired, Some(Class::Teardown)); 2],
            "[M15] teardown, decided at the caller"
        );
        assert!(!p.lock().udp_diagnostics().connected_active());
    }

    // ======================================================== cooldowns (manual clock)

    fn warn_after(gap: Duration) -> usize {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let t = conn_target(gen(1));
        send_fail(&env, &mut d, t, Site::TunConnected, libc::ENETUNREACH);
        env.advance_clock(gap);
        send_fail(&env, &mut d, t, Site::TunConnected, libc::ENETUNREACH);
        assert_eq!(env.wall_reads(), 0, "[CLK-W] no wall time");
        env.count(Line::WarnOpening) + env.count(Line::WarnSummary)
    }

    #[test]
    fn warn_cooldown_minus_one_tick_is_closed() {
        assert_eq!(warn_after(WARN_COOLDOWN - NS), 1, "[CLK-W] closed at -1 ns");
    }

    #[test]
    fn warn_cooldown_exact_is_open() {
        assert_eq!(warn_after(WARN_COOLDOWN), 2, "[CLK-W] open at exactly 60 s");
    }

    #[test]
    fn warn_cooldown_plus_one_tick_is_open() {
        assert_eq!(warn_after(WARN_COOLDOWN + NS), 2, "[CLK-W] open at +1 ns");
    }

    fn errors_after(gap: Duration) -> usize {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        send_fail(
            &env,
            &mut d,
            conn_target(gen(1)),
            Site::TunConnected,
            libc::EBADF,
        );
        env.advance_clock(gap);
        send_fail(
            &env,
            &mut d,
            conn_target(gen(2)),
            Site::TunConnected,
            libc::EBADF,
        );
        assert_eq!(env.wall_reads(), 0, "[CLK-E] no wall time");
        env.count(Line::ErrorConnected)
    }

    #[test]
    fn error_cooldown_minus_one_tick_is_closed() {
        assert_eq!(
            errors_after(ERROR_COOLDOWN - NS),
            1,
            "[CLK-E] closed at -1 ns"
        );
    }

    #[test]
    fn error_cooldown_exact_is_open() {
        assert_eq!(
            errors_after(ERROR_COOLDOWN),
            2,
            "[CLK-E] open at exactly 60 s"
        );
    }

    #[test]
    fn error_cooldown_plus_one_tick_is_open() {
        assert_eq!(
            errors_after(ERROR_COOLDOWN + NS),
            2,
            "[CLK-E] open at +1 ns"
        );
    }

    #[test]
    fn manual_clock_never_reads_wall_time_and_saturates() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        env.set_manual_clock(Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            env.now(),
            Duration::from_secs(5),
            "[CLK-W] the manual value only"
        );
        env.advance_clock(Duration::MAX);
        assert_eq!(env.now(), Duration::MAX);
        env.advance_clock(Duration::from_secs(1));
        assert_eq!(env.clock_value(), Some(Duration::MAX), "saturates");
        assert_eq!(env.wall_reads(), 0, "[CLK-W] no wall time");
    }

    #[test]
    fn alternating_failure_and_success_warns_once_per_cooldown() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let t = conn_target(gen(1));
        for _ in 0..1000 {
            send_fail(&env, &mut d, t, Site::TunConnected, libc::ENETUNREACH);
            send_ok(&env, &mut d, t, Site::TunConnected);
            env.advance_clock(Duration::from_millis(59));
        }
        assert_eq!(
            env.count(Line::WarnOpening),
            1,
            "[M1] one WARN per cooldown under alternation"
        );
        assert_eq!(env.count(Line::DebugRecovery), 1000);
    }

    #[test]
    fn errno_change_and_endpoint_change_do_not_grant_a_warning() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let a: SocketAddr = "192.0.2.5:1".parse().unwrap();
        let b: SocketAddr = "192.0.2.6:1".parse().unwrap();
        for (errno, to) in [
            (libc::ENETUNREACH, a),
            (libc::EMSGSIZE, a),
            (libc::EPERM, b),
            (libc::ECONNREFUSED, b),
        ] {
            send_fail(
                &env,
                &mut d,
                Target::Listener {
                    id: lid(Family::V4, 1),
                    to,
                },
                Site::TimerV4,
                errno,
            );
        }
        assert_eq!(
            env.count(Line::WarnOpening) + env.count(Line::WarnSummary),
            1,
            "[M2M3] no WARN from an errno or endpoint change"
        );
    }

    #[test]
    fn a_persistent_failure_gets_one_summary_per_cooldown() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let t = conn_target(gen(1));
        for _ in 0..1250 {
            send_fail(&env, &mut d, t, Site::TunConnected, libc::ENETUNREACH);
            env.advance_clock(Duration::from_millis(100));
        }
        assert_eq!(
            (env.count(Line::WarnOpening), env.count(Line::WarnSummary)),
            (1, 2),
            "[M9] one opening, then one summary per cooldown"
        );
    }

    // ======================================================== isolation and provenance

    #[test]
    fn listener_success_does_not_close_the_connected_episode() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let to: SocketAddr = "192.0.2.5:51820".parse().unwrap();
        send_fail(
            &env,
            &mut d,
            conn_target(gen(1)),
            Site::TunConnected,
            libc::ENETUNREACH,
        );
        for _ in 0..50 {
            send_ok(
                &env,
                &mut d,
                Target::Listener {
                    id: lid(Family::V4, 9),
                    to,
                },
                Site::TimerV4,
            );
        }
        assert!(
            d.connected_active(),
            "[M4] the connected episode is unaffected"
        );
        assert_eq!(env.count(Line::DebugRecovery), 0, "[M4] no recovery");
    }

    #[test]
    fn connected_mixed_reply_failure_stays_debug() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        for errno in [
            libc::EMSGSIZE,
            libc::ENETUNREACH,
            libc::ECONNREFUSED,
            libc::EPERM,
            libc::ENOMEM,
            libc::EAGAIN,
        ] {
            send_fail(
                &env,
                &mut d,
                conn_target(gen(1)),
                Site::ConnectedReply,
                errno,
            );
        }
        assert!(
            env.decisions()
                .iter()
                .all(|(l, _)| *l == Line::DebugFailure),
            "[M7] the mixed path is DEBUG"
        );
        assert!(d.connected_active());
        send_fail(
            &env,
            &mut d,
            conn_target(gen(1)),
            Site::ConnectedFlush,
            libc::ENETUNREACH,
        );
        assert_eq!(
            env.count(Line::WarnOpening),
            1,
            "eligibility is per site, the record per socket"
        );
    }

    #[test]
    fn cookie_and_probe_failures_stay_debug() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let to: SocketAddr = "198.51.100.7:53".parse().unwrap();
        for site in [Site::CookieReply, Site::ProbeReply] {
            for errno in [
                libc::EMSGSIZE,
                libc::ENETUNREACH,
                libc::ECONNREFUSED,
                libc::EPERM,
                libc::ENOMEM,
                libc::EAGAIN,
                libc::ENOBUFS,
            ] {
                for _ in 0..20 {
                    let a = err_att(&env, errno);
                    observe_unauthenticated_send(&env, lid(Family::V4, 1), site, to, 64, &a);
                }
            }
        }
        assert_eq!(env.decisions().len(), 280);
        assert!(
            env.decisions()
                .iter()
                .all(|(l, _)| *l == Line::DebugFailure),
            "[M8] DEBUG only"
        );
    }

    #[test]
    fn unauthenticated_lifecycle_is_latched_per_listener_generation() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let to: SocketAddr = "198.51.100.7:53".parse().unwrap();
        for _ in 0..3 {
            let a = err_att(&env, libc::EBADF);
            observe_unauthenticated_send(&env, lid(Family::V4, 1), Site::CookieReply, to, 64, &a);
        }
        assert_eq!(
            env.count(Line::ErrorListener),
            1,
            "once per listener generation"
        );
        let a = err_att(&env, libc::EBADF);
        observe_unauthenticated_send(&env, lid(Family::V4, 2), Site::ProbeReply, to, 64, &a);
        assert_eq!(
            env.count(Line::ErrorListener),
            2,
            "a new listener generation may ERROR"
        );
    }

    // ======================================================== hot path

    #[test]
    fn healthy_success_reads_no_clock() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let sink = v4();
        let (mut p, conn, gn) = connected_peer(&env, 1, &sink, &GenAllocator::starting_at(1));
        for _ in 0..1000 {
            connected_send_step(
                &env,
                &mut p,
                &conn,
                gn,
                local(&sink),
                Site::ConnectedFlush,
                b"h",
            );
            assert!(l.tun(&env, &mut p, b"h"));
            while recv_now(&sink).is_some() {}
        }
        assert_eq!(
            env.clock_reads(),
            0,
            "[N8] no clock read on a healthy success"
        );
        assert!(env.decisions().is_empty());
    }

    /// The diagnostics state is plain data and atomics: no public type's auto
    /// traits move.
    #[test]
    fn peer_device_and_handle_keep_their_auto_traits() {
        fn assert_auto<T: Send + Sync + Unpin>() {}
        assert_auto::<Peer>();
        assert_auto::<crate::device::Device>();
        assert_auto::<crate::device::DeviceHandle>();
        assert_auto::<DeviceUdpDiagnostics>();
        assert_auto::<PeerUdpDiagnostics>();
    }

    // ======================================================== the mandatory behaviours, through the steps

    /// A connected peer, its handler socket and generation, a sink standing
    /// in for its endpoint, and the device's listeners.
    struct Connected {
        env: DeviceUdpDiagnostics,
        l: Listeners,
        sink: Socket,
        p: Peer,
        conn: Socket,
        gen: DiagGen,
    }

    fn connected(g: &DiagGuard, first_gen: u64) -> Connected {
        let env = DeviceUdpDiagnostics::for_tests(g);
        let sink = v4();
        let (p, conn, gen) = connected_peer(&env, 1, &sink, &GenAllocator::starting_at(first_gen));
        Connected {
            env,
            l: listeners(),
            sink,
            p,
            conn,
            gen,
        }
    }

    impl Connected {
        fn fail_tun(&self, script: Vec<Step>) {
            self.env.plan(vec![rule(
                Op::Send,
                Some(Site::TunConnected),
                Some(self.gen),
                None,
                script,
            )]);
        }

        fn tun(&mut self, packet: &[u8]) {
            assert!(self.l.tun(&self.env, &mut self.p, packet));
        }
    }

    #[test]
    fn connected_configured_peer_first_failure_emits_one_warning() {
        let g = diag_lock();
        let mut c = connected(&g, 100);
        c.fail_tun(vec![Step::Fail(libc::ENETUNREACH)]);
        c.tun(b"x");
        assert_eq!(
            c.env.decisions(),
            vec![(Line::WarnOpening, Some(Class::Route))]
        );
        assert_eq!(c.env.attempts(Site::TunConnected), 1);
        assert!(stays_empty(&c.sink), "an injected failure sends nothing");
    }

    #[test]
    fn repeated_identical_connected_failure_does_not_spam_warning() {
        let g = diag_lock();
        let mut c = connected(&g, 100);
        c.fail_tun(vec![Step::Fail(libc::ENETUNREACH); 1000]);
        for _ in 0..1000 {
            c.tun(b"x");
            c.env.advance_clock(Duration::from_millis(59));
        }
        assert_eq!(
            c.env.count(Line::WarnOpening),
            1,
            "one WARN in 58.941 s of failures"
        );
        assert_eq!(c.env.count(Line::WarnSummary), 0);
        assert_eq!(c.env.count(Line::DebugFailure), 999);
        assert_eq!(c.p.udp_diagnostics().connected_failures(), 1000);
    }

    #[test]
    fn success_closes_episode_and_emits_debug_recovery() {
        let g = diag_lock();
        let mut c = connected(&g, 100);
        c.fail_tun(vec![Step::Fail(libc::ENETUNREACH)]);
        c.tun(b"lost");
        c.tun(b"accepted");
        assert_eq!(wait_recv(&c.sink).as_deref(), Some(&b"accepted"[..]));
        assert_eq!(
            c.env.decisions(),
            vec![
                (Line::WarnOpening, Some(Class::Route)),
                (Line::DebugRecovery, Some(Class::Route))
            ]
        );
        assert!(!c.p.udp_diagnostics().connected_active());
    }

    #[test]
    fn immediate_failure_after_recovery_stays_warn_suppressed_until_cooldown() {
        let g = diag_lock();
        let mut c = connected(&g, 100);
        c.fail_tun(vec![
            Step::Fail(libc::ENETUNREACH),
            Step::Pass,
            Step::Fail(libc::ENETUNREACH),
            Step::Fail(libc::ENETUNREACH),
        ]);
        c.tun(b"1");
        c.tun(b"2");
        c.env.advance_clock(Duration::from_secs(1));
        c.tun(b"3");
        assert_eq!(
            c.env.count(Line::WarnOpening),
            1,
            "a fresh episode inside the cooldown does not WARN"
        );
        c.env.advance_clock(WARN_COOLDOWN);
        c.tun(b"4");
        assert_eq!(
            (
                c.env.count(Line::WarnOpening),
                c.env.count(Line::WarnSummary)
            ),
            (2, 0),
            "after the cooldown the episode, never announced, opens with a WARN"
        );
    }

    #[test]
    fn failure_after_cooldown_emits_one_new_warning_or_summary() {
        let g = diag_lock();
        let mut c = connected(&g, 100);
        c.fail_tun(vec![
            Step::Fail(libc::ENETUNREACH),
            Step::Fail(libc::ENETUNREACH),
            Step::Pass,
            Step::Fail(libc::ENETUNREACH),
        ]);
        c.tun(b"1");
        c.env.advance_clock(WARN_COOLDOWN);
        c.tun(b"2");
        assert_eq!(
            c.env.count(Line::WarnSummary),
            1,
            "still failing after the cooldown: one summary"
        );
        c.tun(b"3");
        c.env.advance_clock(WARN_COOLDOWN);
        c.tun(b"4");
        assert_eq!(
            (
                c.env.count(Line::WarnOpening),
                c.env.count(Line::WarnSummary)
            ),
            (2, 1),
            "a new episode after the cooldown opens with a new WARN"
        );
    }

    #[test]
    fn errno_class_change_updates_details_without_bypassing_cooldown() {
        let g = diag_lock();
        let mut c = connected(&g, 100);
        c.fail_tun(vec![
            Step::Fail(libc::ENETUNREACH),
            Step::Fail(libc::EMSGSIZE),
            Step::Fail(libc::ECONNREFUSED),
        ]);
        c.tun(b"1");
        c.tun(b"2");
        c.tun(b"3");
        assert_eq!(
            c.env.count(Line::WarnOpening) + c.env.count(Line::WarnSummary),
            1
        );
        assert_eq!(
            c.p.udp_diagnostics().connected.last,
            Some(Failure {
                class: Class::Refused,
                os_error: Some(libc::ECONNREFUSED)
            }),
            "the details follow the latest failure"
        );
    }

    #[test]
    fn listener_configured_peer_failure_isolated_from_connected_record() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let sink = v4();
        let mut p = test_peer_with(1, AmneziaConfig::default(), Some(local(&sink)));
        env.plan(vec![rule(
            Op::Send,
            Some(Site::TunV4),
            None,
            None,
            vec![Step::Fail(libc::EHOSTUNREACH)],
        )]);
        assert!(l.tun(&env, &mut p, b"x"));
        assert!(p.udp_diagnostics().listener_active());
        assert!(
            !p.udp_diagnostics().connected_active(),
            "the connected record is untouched"
        );
        // A connected failure on the same peer is its own record, but shares
        // the peer's WARN cooldown.
        let g1 = commit_connected_socket_from(&env, &mut p, &GenAllocator::starting_at(5));
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g1),
            Site::TunConnected,
            libc::ENETUNREACH,
        );
        assert!(p.udp_diagnostics().connected_active() && p.udp_diagnostics().listener_active());
        assert_eq!(
            env.count(Line::WarnOpening),
            1,
            "one WARN per peer per cooldown, across records"
        );
    }

    #[test]
    fn two_peers_on_one_listener_do_not_reset_each_other() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let (sa, sb) = (v4(), v4());
        let mut a = test_peer_with(1, AmneziaConfig::default(), Some(local(&sa)));
        let mut b = test_peer_with(2, AmneziaConfig::default(), Some(local(&sb)));
        env.plan(vec![rule(
            Op::Send,
            Some(Site::TunV4),
            None,
            Some(local(&sa)),
            vec![Step::Fail(libc::EHOSTUNREACH)],
        )]);
        assert!(l.tun(&env, &mut a, b"a"));
        for _ in 0..3 {
            assert!(l.tun(&env, &mut b, b"b"));
        }
        assert!(
            a.udp_diagnostics().listener_active(),
            "[M5] B's successes do not close A's episode"
        );
        assert!(!b.udp_diagnostics().listener_active());
        assert_eq!(
            env.count(Line::DebugRecovery),
            0,
            "[M5] no recovery attributed to B"
        );
        assert!(l.tun(&env, &mut a, b"a"));
        assert_eq!(
            env.count(Line::DebugRecovery),
            1,
            "[M5] A's own success closes it"
        );
    }

    #[test]
    fn listener_cookie_failure_stays_debug() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let prober = v4();
        let to = local(&prober);
        let errnos = [
            libc::ENETUNREACH,
            libc::EMSGSIZE,
            libc::ECONNREFUSED,
            libc::EPERM,
            libc::ENOBUFS,
        ];
        env.plan(vec![rule(
            Op::Send,
            Some(Site::CookieReply),
            None,
            None,
            errnos.iter().map(|&e| Step::Fail(e)).collect(),
        )]);
        for _ in errnos {
            unauthenticated_send_step(
                &env,
                &l.u4,
                l.id4,
                Site::CookieReply,
                b"cookie",
                to,
                &to.into(),
            );
        }
        assert_eq!(env.decisions().len(), 5);
        assert!(
            env.decisions()
                .iter()
                .all(|(l, _)| *l == Line::DebugFailure),
            "[M8] cookie replies never WARN"
        );
    }

    #[test]
    fn probe_reply_failure_stays_debug() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let prober = v4();
        let to = local(&prober);
        let errnos = [
            libc::ENETUNREACH,
            libc::EMSGSIZE,
            libc::ECONNREFUSED,
            libc::EPERM,
            libc::ENOBUFS,
        ];
        env.plan(vec![rule(
            Op::Send,
            Some(Site::ProbeReply),
            None,
            None,
            errnos.iter().map(|&e| Step::Fail(e)).collect(),
        )]);
        for _ in errnos {
            unauthenticated_send_step(
                &env,
                &l.u4,
                l.id4,
                Site::ProbeReply,
                b"probe",
                to,
                &to.into(),
            );
        }
        assert_eq!(env.decisions().len(), 5);
        assert!(
            env.decisions()
                .iter()
                .all(|(l, _)| *l == Line::DebugFailure),
            "[M8] probe replies never WARN"
        );
    }

    #[test]
    fn connected_mixed_reply_cookie_failure_stays_debug() {
        let g = diag_lock();
        let mut c = connected(&g, 100);
        let ep = local(&c.sink);
        c.env.plan(vec![
            rule(
                Op::Send,
                Some(Site::ConnectedReply),
                Some(c.gen),
                None,
                vec![Step::Fail(libc::ECONNREFUSED); 3],
            ),
            rule(
                Op::Send,
                Some(Site::ConnectedFlush),
                Some(c.gen),
                None,
                vec![Step::Fail(libc::ECONNREFUSED)],
            ),
        ]);
        for _ in 0..3 {
            connected_send_step(
                &c.env,
                &mut c.p,
                &c.conn,
                c.gen,
                ep,
                Site::ConnectedReply,
                b"maybe-a-cookie",
            );
        }
        assert!(
            c.env
                .decisions()
                .iter()
                .all(|(l, _)| *l == Line::DebugFailure),
            "[M7] mixed replies DEBUG"
        );
        assert_eq!(
            c.p.udp_diagnostics().connected_failures(),
            3,
            "counted in the episode"
        );
        connected_send_step(
            &c.env,
            &mut c.p,
            &c.conn,
            c.gen,
            ep,
            Site::ConnectedFlush,
            b"queued",
        );
        assert_eq!(
            c.env.count(Line::WarnSummary) + c.env.count(Line::WarnOpening),
            1,
            "the flush is eligible"
        );
    }

    #[test]
    fn send_would_block_stays_debug() {
        let g = diag_lock();
        let mut c = connected(&g, 100);
        c.fail_tun(vec![Step::Fail(libc::EAGAIN); 5]);
        for _ in 0..5 {
            c.tun(b"x");
        }
        assert_eq!(
            c.env.decisions(),
            vec![(Line::DebugFailure, Some(Class::Transient)); 5]
        );
        assert_eq!(c.p.udp_diagnostics().connected_failures(), 5, "counted");
    }

    #[test]
    fn send_enobufs_stays_debug() {
        let g = diag_lock();
        let mut c = connected(&g, 100);
        c.fail_tun(vec![Step::Fail(libc::ENOBUFS); 5]);
        for _ in 0..5 {
            c.tun(b"x");
        }
        assert_eq!(
            c.env.decisions(),
            vec![(Line::DebugFailure, Some(Class::Transient)); 5]
        );
        assert!(c.p.udp_diagnostics().connected_active());
    }

    #[test]
    fn recv_would_block_logs_nothing_and_is_not_recovery() {
        let g = diag_lock();
        let c = connected(&g, 100);
        let ep = local(&c.sink);
        let p = Mutex::new(c.p);
        open_connected_episode(&c.env, &p, &c.conn, c.gen, ep);
        let mut buf = [MaybeUninit::<u8>::uninit(); 64];
        for _ in 0..3 {
            assert!(matches!(
                conn_recv_step(&c.env, &p, &c.conn, c.gen, ep, &mut buf),
                RecvStep::End
            ));
        }
        assert_eq!(
            c.env.decisions().len(),
            1,
            "nothing after the opening failure"
        );
        assert!(
            p.lock().udp_diagnostics().connected_active(),
            "not recovery"
        );
    }

    #[test]
    fn send_emsgsize_is_bounded_warn_with_attempted_length() {
        let g = diag_lock();
        let mut c = connected(&g, 100);
        c.fail_tun(vec![Step::Fail(libc::EMSGSIZE); 3]);
        let packet = vec![0u8; 1384];
        let spec = [Spec {
            level: Level::WARN,
            message: "UDP send to peer not accepted: socket reported message too long",
            fields: A_EPISODE,
            values: vec![v("len", "1384"), v("class", "size"), v("path", "tun")],
        }];
        capture(&spec, || c.tun(&packet)).expect("[EMSGSIZE-S] WARN with the attempted length");
        c.tun(&packet);
        c.tun(&packet);
        assert_eq!(c.env.count(Line::WarnOpening), 1, "bounded");
        assert_eq!(c.env.count(Line::DebugFailure), 2);
    }

    #[test]
    fn recv_emsgsize_is_bounded_warn_without_fabricated_length() {
        let g = diag_lock();
        let c = connected(&g, 100);
        let ep = local(&c.sink);
        let p = Mutex::new(c.p);
        c.env.plan(vec![rule(
            Op::Recv,
            None,
            Some(c.gen),
            None,
            vec![Step::Fail(libc::EMSGSIZE); 2],
        )]);
        let spec = [Spec {
            level: Level::WARN,
            message: "connected UDP socket for peer reported a pending message-too-long error",
            fields: B_EPISODE,
            values: vec![v("class", "size"), v("op", "recv")],
        }];
        let mut buf = [MaybeUninit::<u8>::uninit(); 64];
        let (env, conn, gn) = (&c.env, &c.conn, c.gen);
        capture(&spec, || conn_recv_step(env, &p, conn, gn, ep, &mut buf))
            .expect("[EMSGSIZE-R] WARN without a length");
        conn_recv_step(&c.env, &p, &c.conn, c.gen, ep, &mut buf);
        assert_eq!(c.env.count(Line::WarnOpening), 1, "bounded");
    }

    #[test]
    fn route_unreachable_and_refused_errors_get_bounded_warning() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let errnos = [
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::EADDRNOTAVAIL,
            libc::ECONNREFUSED,
            libc::EACCES,
            libc::EINVAL,
        ];
        for (i, &errno) in errnos.iter().enumerate() {
            let mut d = PeerUdpDiagnostics::default();
            for _ in 0..3 {
                send_fail(
                    &env,
                    &mut d,
                    conn_target(gen(i as u64 + 1)),
                    Site::TunConnected,
                    errno,
                );
            }
        }
        assert_eq!(
            env.count(Line::WarnOpening),
            errnos.len(),
            "one WARN per peer"
        );
        assert_eq!(
            env.count(Line::DebugFailure),
            errnos.len() * 2,
            "the repeats are DEBUG"
        );
    }

    #[test]
    fn lifecycle_ebadf_enotsock_error_once_per_socket_generation() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let alloc = GenAllocator::starting_at(500);
        let mut p = test_peer(1);
        let g1 = commit_connected_socket_from(&env, &mut p, &alloc);
        for errno in [libc::EBADF, libc::EBADF, libc::ENOTSOCK] {
            send_fail(
                &env,
                p.udp_diagnostics_mut(),
                conn_target(g1),
                Site::TunConnected,
                errno,
            );
        }
        assert_eq!(env.count(Line::ErrorConnected), 1, "once per generation");
        env.advance_clock(ERROR_COOLDOWN * 2);
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g1),
            Site::TunConnected,
            libc::EBADF,
        );
        assert_eq!(
            env.count(Line::ErrorConnected),
            1,
            "the latch outlives the cooldown"
        );
        let g2 = commit_connected_socket_from(&env, &mut p, &alloc);
        send_fail(
            &env,
            p.udp_diagnostics_mut(),
            conn_target(g2),
            Site::TunConnected,
            libc::ENOTSOCK,
        );
        assert_eq!(
            env.count(Line::ErrorConnected),
            2,
            "a new generation may ERROR"
        );
    }

    #[test]
    fn expected_teardown_error_remains_debug() {
        let g = diag_lock();
        let c = connected(&g, 100);
        let ep = local(&c.sink);
        // Roam, expiry and removal take `endpoint.conn` before the handler goes.
        c.p.endpoint_mut().conn = None;
        let p = Mutex::new(c.p);
        c.env.plan(vec![
            rule(
                Op::Recv,
                None,
                Some(c.gen),
                None,
                vec![Step::Fail(libc::ENOTCONN), Step::Fail(libc::EBADF)],
            ),
            rule(
                Op::Send,
                Some(Site::ConnectedFlush),
                Some(c.gen),
                None,
                vec![Step::Fail(libc::EPIPE), Step::Fail(libc::ECONNREFUSED)],
            ),
        ]);
        let mut buf = [MaybeUninit::<u8>::uninit(); 64];
        for _ in 0..2 {
            conn_recv_step(&c.env, &p, &c.conn, c.gen, ep, &mut buf);
            connected_send_step(
                &c.env,
                &mut p.lock(),
                &c.conn,
                c.gen,
                ep,
                Site::ConnectedFlush,
                b"late",
            );
        }
        assert_eq!(
            c.env.decisions(),
            vec![(Line::DebugRetired, Some(Class::Teardown)); 4]
        );
        assert!(
            !p.lock().udp_diagnostics().connected_active(),
            "the record is untouched"
        );
    }

    #[test]
    fn socket_or_endpoint_change_resets_episode_identity_but_keeps_cooldown() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let mut d = PeerUdpDiagnostics::default();
        let (a, b): (SocketAddr, SocketAddr) = (
            "192.0.2.5:1".parse().unwrap(),
            "192.0.2.6:1".parse().unwrap(),
        );
        send_fail(
            &env,
            &mut d,
            Target::Listener {
                id: lid(Family::V4, 1),
                to: a,
            },
            Site::TimerV4,
            libc::ENETUNREACH,
        );
        send_fail(
            &env,
            &mut d,
            Target::Listener {
                id: lid(Family::V4, 1),
                to: b,
            },
            Site::TimerV4,
            libc::ENETUNREACH,
        );
        assert_eq!(
            env.decisions(),
            vec![
                (Line::WarnOpening, Some(Class::Route)),
                (Line::DebugClosed, Some(Class::Route)),
                (Line::DebugFailure, Some(Class::Route))
            ],
            "the endpoint change closes the episode; the cooldown still holds"
        );
        assert_eq!(d.listener_failures(), 1, "a fresh episode");
        send_fail(
            &env,
            &mut d,
            Target::Listener {
                id: lid(Family::V4, 2),
                to: b,
            },
            Site::TimerV4,
            libc::ENETUNREACH,
        );
        assert_eq!(
            env.count(Line::DebugClosed),
            2,
            "a listener generation change too"
        );
        assert_eq!(
            env.count(Line::WarnOpening),
            1,
            "and still no WARN inside the cooldown"
        );
    }

    /// Every step, every family: a healthy send delivers exactly its bytes to
    /// exactly its destination, logs nothing and reads no clock.
    #[test]
    fn ordinary_successful_sends_preserve_bytes_and_destination_and_emit_no_failure_log() {
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        let l = listeners();
        let (s4, s6) = (v4(), v6());
        let mut p = test_peer(1);
        let check = |sink: &Socket, from: &Socket, bytes: &[u8]| {
            let (got, src) = wait_recv_from(sink).expect("delivered");
            assert_eq!(got, bytes);
            assert_eq!(src, local(from));
        };
        l.timer(&env, &mut p, local(&s4), b"timer-v4");
        check(&s4, &l.u4, b"timer-v4");
        l.timer(&env, &mut p, local(&s6), b"timer-v6");
        check(&s6, &l.u6, b"timer-v6");
        for (site, bytes) in [
            (Site::ProbeReply, &b"probe"[..]),
            (Site::CookieReply, &b"cookie"[..]),
        ] {
            let to = local(&s4);
            unauthenticated_send_step(&env, &l.u4, l.id4, site, bytes, to, &to.into());
            check(&s4, &l.u4, bytes);
        }
        for (sock, id, sink) in [(&l.u4, l.id4, &s4), (&l.u6, l.id6, &s6)] {
            let to = local(sink);
            for site in [Site::HandshakeReply, Site::ListenerFlush] {
                listener_peer_send_step(&env, &mut p, sock, id, site, b"listener", to, &to.into());
                check(sink, sock, b"listener");
            }
        }
        p.endpoint_mut().addr = Some(local(&s4));
        assert!(l.tun(&env, &mut p, b"tun-v4"));
        check(&s4, &l.u4, b"tun-v4");
        p.endpoint_mut().addr = Some(local(&s6));
        assert!(l.tun(&env, &mut p, b"tun-v6"));
        check(&s6, &l.u6, b"tun-v6");
        let (mut cp, conn, gn) = connected_peer(&env, 2, &s4, &GenAllocator::starting_at(9));
        for site in [Site::ConnectedReply, Site::ConnectedFlush] {
            connected_send_step(&env, &mut cp, &conn, gn, local(&s4), site, b"connected");
            check(&s4, &conn, b"connected");
        }
        assert!(l.tun(&env, &mut cp, b"tun-connected"));
        check(&s4, &conn, b"tun-connected");
        assert!(env.decisions().is_empty(), "no line");
        assert_eq!(env.clock_reads(), 0, "no clock");
        let sites: BTreeSet<String> = attempted(&env)
            .iter()
            .map(|(s, _, _)| format!("{:?}", s))
            .collect();
        assert_eq!(sites.len(), 11, "all eleven send sites: {:?}", sites);
    }

    // ======================================================== kernel evidence (opt-in)

    fn evidence_enabled() -> bool {
        std::env::var_os("WSBT_KERNEL_EVIDENCE").is_some_and(|v| v == "1")
    }

    /// One ICMP port-unreachable, consumed once -- by a receive or by a send
    /// -- and observed through the production steps; then a real success.
    fn single_icmp_through_the_observer(consumer: Op, tracked: bool) {
        // Gate first: nothing is created unless evidence was asked for.
        if !evidence_enabled() {
            eprintln!("kernel evidence skipped: WSBT_KERNEL_EVIDENCE unset");
            return;
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let left = || deadline.saturating_duration_since(std::time::Instant::now());
        let g = diag_lock();
        let env = DeviceUdpDiagnostics::for_tests(&g);
        // 1. The receiver is absent: a port reserved and released.
        let port = local(&v4()).port();
        let dest = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
        let conn = v4();
        conn.connect(&dest.into()).unwrap();
        let mut p = test_peer(1);
        p.endpoint_mut().addr = Some(dest);
        p.endpoint_mut().conn = Some(conn.try_clone().unwrap());
        let alloc = GenAllocator::starting_at(if tracked { 1000 } else { 0 });
        let gn = commit_connected_socket_from(&env, &mut p, &alloc);
        let p = Mutex::new(p);
        // 2. Exactly one eliciting datagram.
        connected_send_step(
            &env,
            &mut p.lock(),
            &conn,
            gn,
            dest,
            Site::ConnectedFlush,
            b"elicit",
        );
        assert!(
            env.decisions().is_empty(),
            "the eliciting send was accepted"
        );
        // 3. Wait for the pending error without consuming it.
        let mut pfd = libc::pollfd {
            fd: conn.as_raw_fd(),
            events: 0,
            revents: 0,
        };
        loop {
            assert!(
                !left().is_zero(),
                "no pending socket error within the deadline"
            );
            let wait = left().min(Duration::from_millis(10)).as_millis() as i32;
            if unsafe { libc::poll(&mut pfd, 1, wait) } > 0 && pfd.revents & libc::POLLERR != 0 {
                break;
            }
        }
        // 4. Consume it with the chosen operation, through the production step.
        let mut buf = [MaybeUninit::<u8>::uninit(); 64];
        match consumer {
            Op::Recv => {
                assert!(matches!(
                    conn_recv_step(&env, &p, &conn, gn, dest, &mut buf),
                    RecvStep::End
                ));
            }
            Op::Send => connected_send_step(
                &env,
                &mut p.lock(),
                &conn,
                gn,
                dest,
                Site::ConnectedFlush,
                b"consume",
            ),
        }
        assert_eq!(
            env.decisions(),
            vec![(Line::WarnOpening, Some(Class::Refused))],
            "one refused WARN"
        );
        // 5. Consumed once: a receive now ends quietly, and SO_ERROR is clear.
        assert!(matches!(
            conn_recv_step(&env, &p, &conn, gn, dest, &mut buf),
            RecvStep::End
        ));
        assert_eq!(env.decisions().len(), 1, "consumed once");
        assert!(conn.take_error().unwrap().is_none());
        // 6. A receiver appears; 7. the socket sends again.
        let rx = bound(dest);
        connected_send_step(
            &env,
            &mut p.lock(),
            &conn,
            gn,
            dest,
            Site::ConnectedFlush,
            b"again",
        );
        let expected = if tracked {
            vec![
                (Line::WarnOpening, Some(Class::Refused)),
                (Line::DebugRecovery, Some(Class::Refused)),
            ]
        } else {
            vec![(Line::WarnOpening, Some(Class::Refused))]
        };
        assert_eq!(
            env.decisions(),
            expected,
            "a recovery only for a tracked identity"
        );
        loop {
            assert!(
                !left().is_zero(),
                "the datagram was not delivered within the deadline"
            );
            if let Some((bytes, _)) = recv_now(&rx) {
                assert_eq!(bytes, b"again");
                break;
            }
            std::thread::sleep(Duration::from_millis(5).min(left()));
        }
        eprintln!(
            "evidence: consumer={:?} tracked={}: one ECONNREFUSED consumed once -> WARN decision; send accepted again -> {}",
            consumer,
            tracked,
            if tracked { "DEBUG recovery" } else { "no recovery (Untracked)" }
        );
    }

    #[test]
    #[ignore]
    fn kernel_single_icmp_is_consumed_once_by_recv() {
        single_icmp_through_the_observer(Op::Recv, true);
    }

    #[test]
    #[ignore]
    fn kernel_single_icmp_is_consumed_once_by_send() {
        single_icmp_through_the_observer(Op::Send, true);
    }

    #[test]
    #[ignore]
    fn kernel_single_icmp_untracked_warns_without_recovery() {
        single_icmp_through_the_observer(Op::Recv, false);
    }

    // ======================================================== protocol preservation (mock clock)

    /// A failed OS send stays a lost datagram: the tunnel's handshake budget,
    /// its pre-handshake imitation sequence and its Jc junk go on exactly as
    /// if the datagram had been lost on the network. Each proof runs a real
    /// `Tunn` twice through the production steps -- once with no fault, once
    /// with an exact fault script -- on the Device's 250 ms timer cadence, and
    /// compares what the tunnel produced, when, and in what state.
    #[cfg(feature = "mock-instant")]
    mod preservation {
        use super::*;
        use crate::noise::amnezia::AmneziaImitationProtocol;
        use crate::noise::errors::WireGuardError;
        use crate::noise::TunnResult;
        use mock_instant::thread_local::MockClock;

        const TICK: Duration = Duration::from_millis(250);
        const MAX_TICKS: usize = 2000;
        const HANDSHAKE_INIT_LEN: usize = 148;

        /// What one run produced: each datagram by tick, step and length, the
        /// burst state after every tick, and how the run ended.
        #[derive(Debug, PartialEq)]
        struct Trace {
            outputs: Vec<(usize, Site, usize)>,
            pending_burst: Vec<bool>,
            expired_at: Option<usize>,
            session: bool,
            pending_at_end: bool,
        }

        /// One journaled attempt: its site, whether it was injected, its result.
        type Attempted = (Site, bool, Option<Result<usize, Option<i32>>>);

        struct Run {
            trace: Trace,
            /// Every journaled attempt: site, injected, result.
            attempts: Vec<Attempted>,
            pending_fail_steps: usize,
        }

        /// Drive a fresh tunnel from a fixed configuration: one TUN packet at
        /// tick 0 through `tun_send_step`, then `update_timers` every tick
        /// through `timer_send_step`, until expiry or `ticks`.
        fn run(
            g: &DiagGuard,
            amnezia: AmneziaConfig,
            faults: impl FnOnce(ListenerId, SocketAddr) -> Vec<FaultRule>,
            ticks: usize,
        ) -> Run {
            MockClock::set_time(Duration::ZERO);
            let env = DeviceUdpDiagnostics::for_tests(g);
            env.set_manual_clock(Duration::ZERO);
            let l = listeners();
            // The peer's endpoint: bound, never read, so nothing is refused.
            let endpoint_sock = v4();
            let endpoint = local(&endpoint_sock);
            let mut p = test_peer_with(7, amnezia, Some(endpoint));
            env.plan(faults(l.id4, endpoint));
            let mut dst = vec![0u8; 4096];
            let mut outputs = Vec::new();
            let mut pending_burst = Vec::new();
            let mut expired_at = None;
            let payload = [0x45u8; 60];
            match p.tunnel.encapsulate(&payload, &mut dst) {
                TunnResult::WriteToNetwork(packet) => {
                    outputs.push((0, Site::TunV4, packet.len()));
                    assert!(l.tun(&env, &mut p, packet));
                }
                other => panic!(
                    "the first TUN packet must start a handshake, got {:?}",
                    other
                ),
            }
            pending_burst.push(p.tunnel.has_pending_burst());
            for tick in 1..=ticks {
                MockClock::advance(TICK);
                match p.update_timers(&mut dst) {
                    TunnResult::Done => {}
                    TunnResult::WriteToNetwork(packet) => {
                        outputs.push((tick, Site::TimerV4, packet.len()));
                        l.timer(&env, &mut p, endpoint, packet);
                    }
                    TunnResult::Err(WireGuardError::ConnectionExpired) => {
                        // What the Device's timer does with it.
                        p.shutdown_endpoint();
                        expired_at = Some(tick);
                        pending_burst.push(p.tunnel.has_pending_burst());
                        break;
                    }
                    other => panic!("unexpected timer result {:?}", other),
                }
                pending_burst.push(p.tunnel.has_pending_burst());
            }
            let attempts = env
                .journal()
                .into_iter()
                .filter_map(|e| match e {
                    JournalEvent::Attempt {
                        meta,
                        injected,
                        result,
                        ..
                    } => Some((meta.site, injected, result)),
                    JournalEvent::Decision { .. } => None,
                })
                .collect();
            Run {
                trace: Trace {
                    outputs,
                    pending_burst,
                    expired_at,
                    session: p.time_since_last_handshake().is_some(),
                    pending_at_end: p.tunnel.has_pending_burst(),
                },
                attempts,
                pending_fail_steps: env.pending_fail_steps(),
            }
        }

        fn no_faults(_: ListenerId, _: SocketAddr) -> Vec<FaultRule> {
            Vec::new()
        }

        /// The baseline and faulted runs produced the same thing, and every
        /// output was attempted exactly once -- no retry, no extra datagram.
        fn assert_preserved(tag: &str, baseline: &Run, faulted: &Run, injected: usize) {
            assert_eq!(
                faulted.trace, baseline.trace,
                "{} the tunnel's output and state",
                tag
            );
            assert_eq!(
                faulted.pending_fail_steps, 0,
                "{} the exact scripted faults were consumed",
                tag
            );
            assert_eq!(
                faulted.attempts.len(),
                faulted.trace.outputs.len(),
                "{} one attempt per produced datagram",
                tag
            );
            let sites: Vec<Site> = faulted.attempts.iter().map(|(s, _, _)| *s).collect();
            let produced: Vec<Site> = faulted.trace.outputs.iter().map(|(_, s, _)| *s).collect();
            assert_eq!(sites, produced, "{} attempts in output order", tag);
            assert_eq!(
                faulted
                    .attempts
                    .iter()
                    .filter(|(_, injected, _)| *injected)
                    .count(),
                injected,
                "{} each scripted fault is an injected attempt",
                tag
            );
            assert!(baseline.attempts.iter().all(|(_, injected, _)| !injected));
        }

        #[test]
        fn handshake_budget_is_unchanged_by_failed_initiation_sends() {
            let g = diag_lock();
            let baseline = run(&g, AmneziaConfig::default(), no_faults, MAX_TICKS);
            let expired = baseline
                .trace
                .expired_at
                .expect("the untuned tunnel gives up within the cap");
            assert!(baseline
                .trace
                .outputs
                .iter()
                .all(|(_, _, len)| *len == HANDSHAKE_INIT_LEN));
            let initiations = baseline.trace.outputs.len();
            assert!(initiations > 1, "at least one retransmission");
            let on_tun = baseline
                .attempts
                .iter()
                .filter(|(s, _, _)| *s == Site::TunV4)
                .count();
            let on_timer = baseline
                .attempts
                .iter()
                .filter(|(s, _, _)| *s == Site::TimerV4)
                .count();
            assert_eq!((on_tun, on_timer), (1, initiations - 1));
            // Every initiation send fails, script exactly as long as the
            // baseline's attempts.
            let faulted = run(
                &g,
                AmneziaConfig::default(),
                |id4, _| {
                    vec![
                        rule(
                            Op::Send,
                            Some(Site::TunV4),
                            Some(id4.gen),
                            None,
                            vec![Step::Fail(libc::EHOSTUNREACH); on_tun],
                        ),
                        rule(
                            Op::Send,
                            Some(Site::TimerV4),
                            Some(id4.gen),
                            None,
                            vec![Step::Fail(libc::EHOSTUNREACH); on_timer],
                        ),
                    ]
                },
                MAX_TICKS,
            );
            assert_preserved("[PRES-HS]", &baseline, &faulted, initiations);
            assert_eq!(
                faulted.trace.expired_at,
                Some(expired),
                "[PRES-HS] expiry at the same time"
            );
            assert!(
                !faulted.trace.session && !faulted.trace.pending_at_end,
                "[PRES-HS] no session, nothing pending"
            );
            assert!(
                faulted
                    .attempts
                    .iter()
                    .all(|(_, _, r)| *r == Some(Err(Some(libc::EHOSTUNREACH)))),
                "[PRES-HS] every initiation send failed"
            );
        }

        /// The second datagram of an imitation burst fails.
        #[test]
        fn imitation_burst_loss_matches_baseline() {
            let g = diag_lock();
            let config = || {
                AmneziaConfig::default().with_protocol_imitation(
                    AmneziaImitationProtocol::Dns,
                    Some("example.com".to_owned()),
                )
            };
            let ticks = 12;
            let baseline = run(&g, config(), no_faults, ticks);
            let outputs = &baseline.trace.outputs;
            assert!(
                outputs.len() >= 3,
                "[PRES-IMIT] a burst ahead of the initiation: {:?}",
                outputs
            );
            assert_eq!(
                outputs.last().map(|o| o.2),
                Some(HANDSHAKE_INIT_LEN),
                "the initiation follows the burst"
            );
            assert!(
                baseline.trace.pending_burst[0],
                "the burst is pending after the first datagram"
            );
            let faulted = run(
                &g,
                config(),
                |id4, endpoint| {
                    vec![rule(
                        Op::Send,
                        None,
                        Some(id4.gen),
                        Some(endpoint),
                        vec![Step::Pass, Step::Fail(libc::ENOBUFS)],
                    )]
                },
                ticks,
            );
            assert_preserved("[PRES-IMIT]", &baseline, &faulted, 1);
            assert_eq!(
                faulted.attempts[1].2,
                Some(Err(Some(libc::ENOBUFS))),
                "[PRES-IMIT] the second datagram failed"
            );
        }

        /// The second Jc junk datagram fails, with no imitation configured.
        #[test]
        fn jc_burst_loss_matches_baseline() {
            let g = diag_lock();
            let config = || AmneziaConfig::default().with_pre_handshake_junk(3, 100, 100, 0);
            let ticks = 12;
            let baseline = run(&g, config(), no_faults, ticks);
            let lens: Vec<usize> = baseline.trace.outputs.iter().map(|o| o.2).collect();
            assert_eq!(
                lens,
                vec![100, 100, 100, HANDSHAKE_INIT_LEN],
                "[PRES-JC] three junk, then the initiation"
            );
            let faulted = run(
                &g,
                config(),
                |id4, endpoint| {
                    vec![rule(
                        Op::Send,
                        None,
                        Some(id4.gen),
                        Some(endpoint),
                        vec![Step::Pass, Step::Fail(libc::ENOBUFS)],
                    )]
                },
                ticks,
            );
            assert_preserved("[PRES-JC]", &baseline, &faulted, 1);
            assert_eq!(
                faulted.attempts[1].2,
                Some(Err(Some(libc::ENOBUFS))),
                "[PRES-JC] the second junk failed"
            );
        }
    }
}
