// Copyright (c) 2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! `struct wireguard_packet_info`: what a `wireguard_*_ex` call did, returned
//! with the result it describes.
//!
//! The layout and meaning are the accepted WRS-225 P1-prime metadata contract
//! (V1 declarations with the V2 `written_size` reading). The two input budgets,
//! `max_transport_output` and `max_control_output`, bound the network datagram
//! this one operation may produce; 0 is unbounded, each on its own. A mandatory
//! datagram over a finite budget is error 18 (`OutputBudgetExceeded`): the
//! operation ran, and its report says what it did. With metadata or without --
//! or with both budgets 0 -- the operation is the legacy one; the legacy entry
//! points are this same body with `info` NULL.
//!
//! The memory protocol, in the order the code below follows it:
//!
//! 1. `info` NULL: no metadata, no budget; the call is the legacy call.
//! 2. Read the 4-byte `size` -- the only read before it is checked. Outside
//!    48..=1024: error 19.
//! 3. Read the 16-byte input head. `in_flags` != 0: error 19. The budgets are
//!    taken as they are; any value is valid.
//! 4. Every byte of `[48, size)` must be zero (a field from a newer header
//!    that this library cannot honour): otherwise error 19.
//! 5. Only now lock the tunnel, take the operation's sequence number, run it
//!    under the budgets just read -- a copy, held for this call only -- and
//!    compute the report under the same lock hold.
//! 6. After unlocking, write `[16, 48)` once. Nothing else is ever written:
//!    `[0, 16)` and `[48, size)` are the caller's.
//!
//! Error 19 means nothing ran: no lock, no sequence number, no read of `src`,
//! and no byte of `info` written -- its output fields may still hold an older
//! call's values and must not be read. Every access is unaligned, and no
//! reference is ever formed over caller memory.

use super::wireguard_result;
use crate::noise::budget::OutputBudget;
use crate::noise::errors::WireGuardError;
use crate::noise::op_report::OpReport;
use crate::noise::{Tunn, TunnResult};
use parking_lot::Mutex;
use std::mem::{align_of, size_of};
use std::ptr;

/// The smallest `size` accepted, and the end of the output region this
/// library writes.
pub const WIREGUARD_PACKET_INFO_SIZE_V1: u32 = 48;
/// The largest `size` accepted: bounds the zero-tail scan.
pub const WIREGUARD_PACKET_INFO_SIZE_MAX: u32 = 1024;
/// Fixed start of the output region.
pub const WIREGUARD_PACKET_INFO_OUTPUT_START: u32 = 16;

/// Metadata of one `wireguard_*_ex` operation. All `uint32_t`: size 48 and
/// alignment 4 on every target, 32- and 64-bit alike.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct wireguard_packet_info {
    /// In: the bytes the caller declares readable at `info`. Never written.
    pub size: u32,
    /// In: reserved, must be 0.
    pub in_flags: u32,
    /// In: largest transport data or keepalive datagram this call may
    /// produce, in bytes of UDP payload; 0 is unbounded.
    pub max_transport_output: u32,
    /// In: largest initiation, response, junk or imitation datagram this call
    /// may produce, in bytes of UDP payload; 0 is unbounded.
    pub max_control_output: u32,
    /// Out: exclusive end offset of the output region this call wrote (48).
    pub written_size: u32,
    /// Out: kind of the input the operation accepted, else NONE.
    pub input_kind: u32,
    /// Out: kind of `dst[..result.size]` iff the result is WRITE_TO_NETWORK.
    pub output_kind: u32,
    /// Out: `WIREGUARD_EV_*` facts of this operation.
    pub events: u32,
    /// Out: `WIREGUARD_ST_*` snapshot after this operation.
    pub state: u32,
    /// Out: operation sequence, low 32 bits.
    pub op_seq_lo: u32,
    /// Out: operation sequence, high 32 bits.
    pub op_seq_hi: u32,
    /// Out: ms until the pending burst's next item is due, 0 if due now,
    /// `WIREGUARD_BURST_DUE_NONE` iff no burst is pending.
    pub burst_due_ms: u32,
}

/// The output region, `[16, 48)` of the public struct. Never public.
#[repr(C)]
struct PacketInfoOut {
    written_size: u32,
    input_kind: u32,
    output_kind: u32,
    events: u32,
    state: u32,
    op_seq_lo: u32,
    op_seq_hi: u32,
    burst_due_ms: u32,
}

const _: () = assert!(size_of::<wireguard_packet_info>() == 48);
const _: () = assert!(align_of::<wireguard_packet_info>() == 4);
const _: () = assert!(size_of::<PacketInfoOut>() == 32);
const _: () = assert!(align_of::<PacketInfoOut>() == 4);
const _: () = assert!(
    WIREGUARD_PACKET_INFO_OUTPUT_START as usize + size_of::<PacketInfoOut>()
        == WIREGUARD_PACKET_INFO_SIZE_V1 as usize
);

/// Steps 2-4 of the protocol: the call's budgets, or `None` for error 19.
/// Reads 4 bytes, then -- only for a `size` this library accepts, which the
/// caller has declared readable -- the input head and the tail.
unsafe fn accepts(info: *const u8) -> Option<OutputBudget> {
    let size = ptr::read_unaligned(info as *const u32);
    if !(WIREGUARD_PACKET_INFO_SIZE_V1..=WIREGUARD_PACKET_INFO_SIZE_MAX).contains(&size) {
        return None;
    }
    let [_, in_flags, max_transport_output, max_control_output] =
        ptr::read_unaligned(info as *const [u32; 4]);
    if in_flags != 0 {
        return None;
    }
    (WIREGUARD_PACKET_INFO_SIZE_V1 as usize..size as usize)
        .all(|i| ptr::read(info.add(i)) == 0)
        .then_some(OutputBudget {
            transport: max_transport_output,
            control: max_control_output,
        })
}

/// Step 6: the one write.
unsafe fn publish(info: *mut wireguard_packet_info, report: &OpReport) {
    let out = PacketInfoOut {
        written_size: WIREGUARD_PACKET_INFO_SIZE_V1,
        input_kind: report.input_kind as u32,
        output_kind: report.output_kind as u32,
        events: report.events,
        state: report.state,
        op_seq_lo: report.op_seq as u32,
        op_seq_hi: (report.op_seq >> 32) as u32,
        burst_due_ms: report.burst_due_ms,
    };
    let at = (info as *mut u8).add(WIREGUARD_PACKET_INFO_OUTPUT_START as usize);
    ptr::write_unaligned(at as *mut PacketInfoOut, out);
}

/// One FFI operation, with or without metadata: the shared body of the
/// legacy and `_ex` entry points. `op` runs under the tunnel lock, with the
/// budgets `info` carries (none without it); it is where `src` and `dst` are
/// turned into slices, so a refused `info` never reaches them.
pub(super) unsafe fn run<'a>(
    tunnel: *const Mutex<Tunn>,
    info: *mut wireguard_packet_info,
    op: impl FnOnce(&mut Tunn, OutputBudget) -> TunnResult<'a>,
) -> wireguard_result {
    let budget = if info.is_null() {
        OutputBudget::UNBOUNDED
    } else {
        match accepts(info as *const u8) {
            Some(budget) => budget,
            None => {
                return wireguard_result::from(TunnResult::Err(WireGuardError::InvalidPacketInfo))
            }
        }
    };
    let mut tunnel = tunnel.as_ref().unwrap().lock();
    let entry = tunnel.begin_op();
    let result = op(&mut tunnel, budget);
    let report = (!info.is_null()).then(|| tunnel.finish_op(entry, &result));
    drop(tunnel);
    let result = wireguard_result::from(result);
    if let Some(report) = report {
        publish(info, &report);
    }
    result
}
