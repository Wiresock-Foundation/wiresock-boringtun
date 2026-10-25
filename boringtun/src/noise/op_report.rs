// Copyright (c) 2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! What one tunnel operation did, for the C `wireguard_*_ex` entry points.
//!
//! The facts are recorded where they happen -- the commit, store, queue and
//! emit sites in `noise` -- not reconstructed afterwards from bytes or from a
//! before/after diff of the state. A fact recorded before a later error stays
//! recorded: `events` is the union of everything the operation did, which is
//! what lets a caller tell "authenticated, then the inner packet was
//! malformed" from "never authenticated". The only derived fact is
//! [`event::CURRENT_SESSION_CHANGED`], an entry/exit comparison of the
//! selected session's serial.
//!
//! Everything here lives in the `Tunn` and is written and read under the one
//! lock hold of a single operation ([`Tunn::begin_op`] .. [`Tunn::finish_op`]).
//! There is no "last result" to query later: the report is returned with the
//! result it describes, or not at all.
//!
//! The vocabulary is the accepted P1-prime metadata contract (WRS-225 V1-V6).
//! Nothing here changes what the operation does; the output budgets the same
//! entry points carry are applied by the producers (`budget`), and their
//! effects are recorded here like any other fact.
//!
//! Only the C entry points read a report. The one exception is the accepted
//! input kind, which `Tunn::decapsulate_from_with_metadata` reads back for the
//! receive it scopes (`begin_receive` .. `take_receive_input`), so the Rust
//! and C reports share one recording site. A build without the C entry points
//! still records the facts -- a few bit operations at the sites -- and never
//! reads the rest back, which is all the allowance below covers.
#![cfg_attr(not(feature = "ffi-bindings"), allow(dead_code))]

use super::{AuthenticatedPacketKind, PendingAmneziaJunk, Tunn, TunnResult, N_SESSIONS};
use std::convert::TryFrom;
use std::time::Duration;

/// Kind of a datagram: the one an operation accepted, or the one it returned
/// with `WriteToNetwork`. ABI values; never renumbered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum PacketKind {
    None = 0,
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    /// Output only through `decapsulate(Some(addr), ..)`; the C `wireguard_read`
    /// passes no address and never reaches it.
    CookieReply = 3,
    TransportData = 4,
    TransportKeepalive = 5,
    /// A Jc pre-handshake junk datagram.
    Junk = 6,
    /// A DNS/QUIC/SIP/STUN imitation datagram of the pre-handshake burst.
    Imitation = 7,
}

/// Facts of THIS operation; a set bit means "at least once". ABI values.
pub(crate) mod event {
    pub(crate) const INPUT_ACCEPTED: u32 = 0x0000_0001;
    pub(crate) const PEER_AUTHENTICATED: u32 = 0x0000_0002;
    pub(crate) const SESSION_STORED: u32 = 0x0000_0004;
    pub(crate) const CURRENT_SESSION_CHANGED: u32 = 0x0000_0008;
    pub(crate) const INITIATION_PRODUCED: u32 = 0x0000_0010;
    pub(crate) const QUEUE_ADMITTED: u32 = 0x0000_0020;
    pub(crate) const HANDSHAKE_EXPIRED: u32 = 0x0000_0040;
    pub(crate) const SESSIONS_AGED_OUT: u32 = 0x0000_0080;
    pub(crate) const BURST_PREPARED: u32 = 0x0000_0100;
    pub(crate) const TICK_DEMAND_REFUSED: u32 = 0x0000_0200;
    /// A drain deleted one or more queued plaintext packets whose mandatory
    /// frame exceeded the call's finite transport budget.
    pub(crate) const QUEUE_HEAD_DROPPED: u32 = 0x0001_0000;
}

/// Snapshot after the operation, under the same lock hold. ABI values.
pub(crate) mod state {
    pub(crate) const SESSION_CURRENT: u32 = 0x0000_0001;
    pub(crate) const INITIATION_PENDING: u32 = 0x0000_0002;
    pub(crate) const HANDSHAKE_EXPIRED: u32 = 0x0000_0004;
    pub(crate) const QUEUE_NONEMPTY: u32 = 0x0000_0008;
    pub(crate) const BURST_PENDING: u32 = 0x0000_0010;
    pub(crate) const COOKIE_HELD: u32 = 0x0000_0020;
}

/// `burst_due_ms` when no burst is pending.
pub(crate) const BURST_DUE_NONE: u32 = u32::MAX;
/// The largest finite `burst_due_ms`.
const BURST_DUE_MAX: u32 = u32::MAX - 1;

/// Per-tunnel bookkeeping behind the report.
#[derive(Debug)]
pub(crate) struct OpState {
    /// Operation sequence: 0 before the first FFI operation, then +1 per
    /// operation, assigned right after the lock is taken. Wrapping only so a
    /// counter nobody can exhaust (2^64) cannot panic under `extern "C"`.
    op_seq: u64,
    /// Never-reused identity of each stored session, by ring slot; 0 = none.
    /// The local index is not an identity: the allocator advances only the
    /// low byte, so a later session can land in the same slot with the same
    /// index.
    slot_serial: [u64; N_SESSIONS],
    next_session_serial: u64,
    /// Facts of the operation in progress; cleared by `begin_op`.
    events: u32,
    input_kind: PacketKind,
    output_kind: PacketKind,
    /// The last input any commit accepted, from any entry point -- the same
    /// fact as `INPUT_ACCEPTED` and `input_kind`, written by the same
    /// `note_input`, so the Rust and C reports cannot disagree. Every commit
    /// writes it, and only [`Tunn::decapsulate_from_with_metadata`] reads or
    /// clears it: it clears it first (`begin_receive`) and takes it last, so
    /// a value left by a legacy, device or C call is never reported. Scoped by `begin_receive` rather than `begin_op`, so a
    /// Rust receive never advances the C operation sequence.
    receive_input: Option<AuthenticatedPacketKind>,
}

impl Default for OpState {
    fn default() -> Self {
        OpState {
            op_seq: 0,
            slot_serial: [0; N_SESSIONS],
            next_session_serial: 1,
            events: 0,
            input_kind: PacketKind::None,
            output_kind: PacketKind::None,
            receive_input: None,
        }
    }
}

impl OpState {
    pub(super) fn note(&mut self, events: u32) {
        self.events |= events;
    }

    /// The input was accepted as `accepted`, reported to C as `kind`. The
    /// peer is authenticated unless it is a cookie reply, which proves nothing
    /// about the peer: [`AuthenticatedPacketKind::moves_endpoint`] is that
    /// rule, for the C report, the Rust report and the device's roaming alike.
    pub(super) fn note_input(&mut self, kind: PacketKind, accepted: AuthenticatedPacketKind) {
        self.input_kind = kind;
        self.events |= event::INPUT_ACCEPTED;
        if accepted.moves_endpoint() {
            self.events |= event::PEER_AUTHENTICATED;
        }
        self.receive_input = Some(accepted);
    }

    /// Start a [`Tunn::decapsulate_from_with_metadata`] call: forget what an
    /// earlier operation accepted.
    pub(super) fn begin_receive(&mut self) {
        self.receive_input = None;
    }

    /// What the receive `begin_receive` started accepted, if anything.
    pub(super) fn take_receive_input(&mut self) -> Option<AuthenticatedPacketKind> {
        self.receive_input.take()
    }

    /// `result` was produced as `kind`. Recorded only when it really is
    /// network output: a frame that failed in framing produced nothing.
    pub(super) fn note_output(&mut self, kind: PacketKind, result: &TunnResult) {
        if matches!(result, TunnResult::WriteToNetwork(_)) {
            self.output_kind = kind;
        }
    }

    /// A session was written into ring slot `slot`: give it a new serial.
    /// Saturating at the end of a domain no tunnel can reach.
    pub(super) fn session_stored(&mut self, slot: usize) {
        self.slot_serial[slot] = self.next_session_serial;
        self.next_session_serial = self.next_session_serial.saturating_add(1);
        self.events |= event::SESSION_STORED;
    }

    pub(super) fn session_removed(&mut self, slot: usize) {
        self.slot_serial[slot] = 0;
    }

    pub(super) fn all_sessions_removed(&mut self) {
        self.slot_serial = [0; N_SESSIONS];
    }

    /// Test seams: the sequence of the last operation, and a way to put it
    /// near the low word's carry without running four billion operations.
    #[cfg(all(test, feature = "ffi-bindings"))]
    pub(crate) fn op_seq(&self) -> u64 {
        self.op_seq
    }

    #[cfg(all(test, feature = "ffi-bindings"))]
    pub(crate) fn set_op_seq(&mut self, op_seq: u64) {
        self.op_seq = op_seq;
    }
}

/// What `begin_op` saw at entry.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpEntry {
    op_seq: u64,
    selected_serial: u64,
}

/// The facts and snapshot of one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpReport {
    pub(crate) input_kind: PacketKind,
    /// Kind of the returned bytes iff the result is `WriteToNetwork`.
    pub(crate) output_kind: PacketKind,
    pub(crate) events: u32,
    pub(crate) state: u32,
    pub(crate) op_seq: u64,
    pub(crate) burst_due_ms: u32,
}

impl Tunn {
    /// Start one participating operation: take the next sequence number,
    /// clear the facts, remember the selected session. Every FFI operation
    /// calls this, with or without metadata, so the sequence and the serials
    /// mean the same thing whichever entry point a caller mixes in.
    pub(crate) fn begin_op(&mut self) -> OpEntry {
        let meta = &mut self.meta;
        meta.op_seq = meta.op_seq.wrapping_add(1);
        meta.events = 0;
        meta.input_kind = PacketKind::None;
        meta.output_kind = PacketKind::None;
        OpEntry {
            op_seq: meta.op_seq,
            selected_serial: self.selected_session_serial(),
        }
    }

    /// The report of the operation `entry` began, still under its lock hold.
    pub(crate) fn finish_op(&self, entry: OpEntry, result: &TunnResult) -> OpReport {
        let mut events = self.meta.events;
        if self.selected_session_serial() != entry.selected_serial {
            events |= event::CURRENT_SESSION_CHANGED;
        }
        // Every network output is tagged at the site that produced it; the
        // FFI tests pin the kind of each one reachable through the C API. Not
        // asserted here: a panic under `extern "C"` aborts the caller.
        let output_kind = match result {
            TunnResult::WriteToNetwork(_) => self.meta.output_kind,
            _ => PacketKind::None,
        };
        OpReport {
            input_kind: self.meta.input_kind,
            output_kind,
            events,
            state: self.state_snapshot(),
            op_seq: entry.op_seq,
            burst_due_ms: self.burst_due_ms(),
        }
    }

    /// The serial of the session in slot `current`, 0 when that slot is empty.
    fn selected_session_serial(&self) -> u64 {
        let slot = self.current % N_SESSIONS;
        if self.sessions[slot].is_some() {
            self.meta.slot_serial[slot]
        } else {
            0
        }
    }

    fn state_snapshot(&self) -> u32 {
        let mut s = 0;
        if self.has_current_session() {
            s |= state::SESSION_CURRENT;
        }
        if self.handshake.has_initiation_pending() {
            s |= state::INITIATION_PENDING;
        }
        if self.handshake.is_expired() {
            s |= state::HANDSHAKE_EXPIRED;
        }
        if !self.packet_queue.is_empty() {
            s |= state::QUEUE_NONEMPTY;
        }
        if self.pending_amnezia_junk.is_some() {
            s |= state::BURST_PENDING;
        }
        if self.handshake.has_cookie() {
            s |= state::COOKIE_HELD;
        }
        s
    }

    /// Milliseconds, rounded up, until the pending burst's next item passes
    /// the pacing gate in `advance_amnezia_junk`; 0 when it already would.
    /// A hint for when to call again, not a schedule: the gate still decides.
    fn burst_due_ms(&self) -> u32 {
        let Some(pending) = self.pending_amnezia_junk.as_ref() else {
            return BURST_DUE_NONE;
        };
        let Some(last) = pending.last_packet_at else {
            return 0;
        };
        let remaining = self.burst_delay(pending).saturating_sub(last.elapsed());
        if remaining.is_zero() {
            return 0;
        }
        let ms = remaining.as_nanos().div_ceil(1_000_000);
        u32::try_from(ms)
            .unwrap_or(BURST_DUE_MAX)
            .min(BURST_DUE_MAX)
    }

    /// The delay the gate applies to the next item: the front imitation
    /// datagram's own, otherwise Jd.
    fn burst_delay(&self, pending: &PendingAmneziaJunk) -> Duration {
        pending
            .imitation_datagrams
            .front()
            .map(|(d, _)| *d)
            .unwrap_or_else(|| self.amnezia.pre_handshake_junk.delay())
    }

    /// The pending burst as (imitation datagrams left, Jc items left), for the
    /// FFI tests to check the emitted sequence against what was prepared.
    #[cfg(all(test, feature = "ffi-bindings"))]
    pub(crate) fn pending_burst_shape(&self) -> Option<(usize, u16)> {
        self.pending_amnezia_junk
            .as_ref()
            .map(|p| (p.imitation_datagrams.len(), p.remaining))
    }

    #[cfg(all(test, feature = "ffi-bindings"))]
    pub(crate) fn op_state_mut(&mut self) -> &mut OpState {
        &mut self.meta
    }

    /// The selected session's serial (0 for none), and the serial of the
    /// session in `slot`: which stored session a selection follows.
    #[cfg(all(test, feature = "ffi-bindings"))]
    pub(crate) fn selected_serial(&self) -> u64 {
        self.selected_session_serial()
    }

    #[cfg(all(test, feature = "ffi-bindings"))]
    pub(crate) fn serial_of_slot(&self, slot: usize) -> u64 {
        self.meta.slot_serial[slot]
    }

    /// Plaintext packets the tunnel owns, waiting for a session or a drain.
    #[cfg(all(test, feature = "ffi-bindings"))]
    pub(crate) fn queued_len(&self) -> usize {
        self.packet_queue.len()
    }

    /// The bytes of the pending burst's next imitation datagram, so a test
    /// can check that a refused item is the one emitted later, unchanged.
    #[cfg(all(test, feature = "ffi-bindings"))]
    pub(crate) fn pending_front_imitation(&self) -> Option<Vec<u8>> {
        self.pending_amnezia_junk
            .as_ref()?
            .imitation_datagrams
            .front()
            .map(|(_, d)| d.clone())
    }

    /// How far the handshake generator -- tags, S prefixes, junk sizes and
    /// fills, imitation -- has advanced, so a test can tell a refusal that
    /// drew nothing from one that did.
    #[cfg(all(test, feature = "ffi-bindings"))]
    pub(crate) fn rng_word_pos(&self) -> u128 {
        self.handshake.rng.get_word_pos()
    }
}
