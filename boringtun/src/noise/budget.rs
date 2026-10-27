// Copyright (c) 2026 Vadim Smirnov (doing business as WireSock). All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Per-call output budgets of the C `wireguard_*_ex` entry points
//! (`max_transport_output` / `max_control_output` in `wireguard_packet_info`).
//!
//! A budget bounds the UDP payload one operation returns with
//! `WriteToNetwork` -- S prefix, trailer and padding included, outer IP, UDP
//! and SOCKS headers not. `transport` bounds data and keepalive frames;
//! `control` bounds initiations, responses, Jc junk and imitation datagrams.
//! 0 is unbounded, independently for each. Decrypted plaintext is never
//! budgeted. With `ordinary_junk_only` (`WIREGUARD_INFO_F_CONTROL_ORDINARY_JUNK_ONLY`)
//! `control` bounds ordinary Jc junk alone; every other control datagram is
//! then produced as under a `control` of 0 ([`OutputBudget::control_for`]).
//!
//! An [`OutputBudget`] is an argument of the one operation that carries it,
//! never state of the tunnel, so no call's limit -- or mode -- can reach a
//! later call.
//!
//! Every producer applies [`admit`] to its mandatory datagram before it
//! consumes anything -- a nonce, a draw, handshake state, a queued packet --
//! and hands the ceiling it returns to the optional bytes, which shrink to
//! fit it rather than fail.

use super::errors::WireGuardError;
use super::DATA_OVERHEAD_SZ;

// A `u32` budget converts to `usize` without loss.
const _: () = assert!(usize::BITS >= 32);

/// The two budgets of one operation; 0 is unbounded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OutputBudget {
    /// Transport data and keepalive frames.
    pub(crate) transport: u32,
    /// Initiation, response, junk and imitation datagrams -- read through
    /// [`Self::control_for`].
    pub(crate) control: u32,
    /// `control` bounds ordinary Jc junk only.
    pub(crate) ordinary_junk_only: bool,
}

/// A control datagram, as the control budget tells them apart. The producer
/// knows which it is making; nothing is inferred from bytes or lengths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlOutput {
    /// Jc junk with no imitation protocol: random bytes from the configured
    /// size range.
    OrdinaryJunk,
    /// An initiation, a response, a whole imitation datagram, or Jc junk
    /// shaped by an imitation protocol.
    Other,
}

impl OutputBudget {
    /// The legacy calls, `_ex(NULL)`, an all-zero record and every Rust caller.
    pub(crate) const UNBOUNDED: Self = Self {
        transport: 0,
        control: 0,
        ordinary_junk_only: false,
    };

    /// The control budget a datagram of `kind` is produced under: `control`,
    /// except that with `ordinary_junk_only` only ordinary junk has one --
    /// anything else gets 0, exactly what a call whose `control` is 0 gives
    /// it, mandatory admission and optional ceiling alike.
    pub(crate) fn control_for(self, kind: ControlOutput) -> u32 {
        match kind {
            ControlOutput::Other if self.ordinary_junk_only => 0,
            _ => self.control,
        }
    }
}

/// Whether a mandatory datagram of `mandatory` bytes -- `None` when its size
/// overflowed -- is larger than a finite `budget`.
pub(crate) fn exceeds(mandatory: Option<usize>, budget: u32) -> bool {
    budget != 0 && mandatory.map_or(true, |m| m > budget as usize)
}

/// The largest datagram a producer may return into `dst_len` bytes under
/// `budget`: the smaller of the two, or `dst_len` when unbounded.
pub(crate) fn ceiling(dst_len: usize, budget: u32) -> usize {
    match budget {
        0 => dst_len,
        b => dst_len.min(b as usize),
    }
}

/// Admit a mandatory datagram of `mandatory` bytes (`None`: its size
/// overflowed) into `dst_len` bytes under `budget`, returning the
/// [`ceiling`] its optional bytes must stay within.
///
/// The budget is checked first, so a datagram over both is
/// `OutputBudgetExceeded`, and over the destination alone
/// `DestinationBufferTooSmall`. Equality fits.
pub(crate) fn admit(
    mandatory: Option<usize>,
    dst_len: usize,
    budget: u32,
) -> Result<usize, WireGuardError> {
    if exceeds(mandatory, budget) {
        return Err(WireGuardError::OutputBudgetExceeded);
    }
    match mandatory {
        Some(m) if m <= dst_len => Ok(ceiling(dst_len, budget)),
        _ => Err(WireGuardError::DestinationBufferTooSmall),
    }
}

/// The mandatory size of a transport frame for `plaintext_len` bytes with an
/// `s4`-byte prefix, before padding; `None` if that does not fit a `usize`
/// (on a 32-bit target, from `2^32 - 32 - s4` bytes up).
pub(crate) fn transport_frame(plaintext_len: usize, s4: usize) -> Option<usize> {
    plaintext_len.checked_add(DATA_OVERHEAD_SZ)?.checked_add(s4)
}

/// The range a Jc junk datagram is drawn from under a `control` budget,
/// given its configured inclusive `range`.
///
/// Ordinary junk lowers both ends to the budget (owner decision 1A), so it
/// never refuses: `[min(lo, c), min(hi, c)]`. Protocol-shaped junk keeps
/// its protocol's lower bound and lowers only the upper one; when that
/// leaves no size, it is `OutputBudgetExceeded`. 0 keeps `range`. The
/// destination never narrows the range: a short `dst` is the caller's
/// storage refusal, before the draw.
pub(crate) fn junk_range(
    range: (usize, usize),
    protocol_shaped: bool,
    control: u32,
) -> Result<(usize, usize), WireGuardError> {
    if control == 0 {
        return Ok(range);
    }
    let c = control as usize;
    let (lo, hi) = range;
    if !protocol_shaped {
        return Ok((lo.min(c), hi.min(c)));
    }
    let hi = hi.min(c);
    if lo > hi {
        return Err(WireGuardError::OutputBudgetExceeded);
    }
    Ok((lo, hi))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(r: Result<usize, WireGuardError>) -> Result<usize, usize> {
        r.map_err(|e| e as usize)
    }

    /// The admission rule, row by row: budget before storage, equality fits,
    /// an overflowed size refused by whichever bound applies, and the
    /// ceiling the optional bytes get.
    #[test]
    fn admission_checks_the_budget_first_and_equality_fits() {
        // (mandatory, dst, budget) -> ceiling | code
        type Row = (Option<usize>, usize, u32, Result<usize, usize>);
        let rows: [Row; 12] = [
            (Some(132), 2048, 0, Ok(2048)),
            (Some(132), 2048, 140, Ok(140)),
            (Some(132), 2048, 132, Ok(132)),
            (Some(132), 2048, 131, Err(18)),
            (Some(132), 131, 0, Err(0)),
            (Some(132), 131, 131, Err(18)),
            (Some(132), 131, 140, Err(0)),
            (Some(132), 132, 140, Ok(132)),
            (Some(0), 0, 0, Ok(0)),
            (None, 2048, 0, Err(0)),
            (None, 2048, u32::MAX, Err(18)),
            (Some(usize::MAX), usize::MAX, 0, Ok(usize::MAX)),
        ];
        for (m, d, b, want) in rows {
            assert_eq!(code(admit(m, d, b)), want, "m {:?} d {} b {}", m, d, b);
            assert_eq!(exceeds(m, b), want == Err(18), "m {:?} b {}", m, b);
        }
    }

    /// The flag gives ordinary junk the call's `control` and everything
    /// else 0; without it, or with `control` 0, every kind gets `control`.
    /// `transport` is never read.
    #[test]
    fn control_for_bounds_only_ordinary_junk_under_the_flag() {
        for transport in [0, 1200] {
            for control in [0u32, 1, 572, u32::MAX] {
                for ordinary_junk_only in [false, true] {
                    let b = OutputBudget {
                        transport,
                        control,
                        ordinary_junk_only,
                    };
                    let other = if ordinary_junk_only { 0 } else { control };
                    assert_eq!(b.control_for(ControlOutput::OrdinaryJunk), control);
                    assert_eq!(b.control_for(ControlOutput::Other), other, "{:?}", b);
                }
            }
        }
        assert_eq!(OutputBudget::default(), OutputBudget::UNBOUNDED);
    }

    /// The transport frame's size is checked arithmetic: the largest
    /// plaintext that still has a size, and the first that does not, on this
    /// target's `usize` -- on a 32-bit target that is `2^32 - 32 - S4`. No
    /// buffer of that size is ever allocated.
    #[test]
    fn transport_frame_size_is_checked_on_every_word_size() {
        for s4 in [0usize, 16, 100, 65535] {
            let last = usize::MAX - DATA_OVERHEAD_SZ - s4;
            assert_eq!(transport_frame(last, s4), Some(usize::MAX), "s4 {}", s4);
            assert_eq!(transport_frame(last + 1, s4), None, "s4 {}", s4);
            assert_eq!(transport_frame(100, s4), Some(132 + s4));
        }
        // 2^32 - 32 - 4 = 4_294_967_260.
        #[cfg(target_pointer_width = "32")]
        {
            assert_eq!(transport_frame(4_294_967_259, 4), Some(usize::MAX));
            assert_eq!(transport_frame(4_294_967_260, 4), None);
        }
        // A refused overflow is the budget's 18 when one is set, else 0.
        assert_eq!(
            code(admit(transport_frame(usize::MAX, 0), usize::MAX, 1200)),
            Err(18)
        );
        assert_eq!(
            code(admit(transport_frame(usize::MAX, 0), usize::MAX, 0)),
            Err(0)
        );
    }

    /// BUD-JUNK-02. Ordinary ranges clamp at both ends and never refuse;
    /// protocol ranges keep their lower bound and refuse when the budget is
    /// below it; 0 keeps the configured range. The (x, 1400) rows are the
    /// owner's arithmetic examples, outside what a constructor accepts
    /// (Jmax <= 1280); (1000, 1280) is their constructible counterpart.
    #[test]
    fn junk_ranges_follow_decision_1a_and_the_protocol_rule() {
        let ordinary = [
            ((50, 1000), 40, (40, 40)),
            ((1000, 1400), 572, (572, 572)),
            ((100, 1400), 572, (100, 572)),
            ((1000, 1280), 572, (572, 572)),
            ((100, 1280), 572, (100, 572)),
            ((50, 1000), 1000, (50, 1000)),
            ((50, 1000), 0, (50, 1000)),
        ];
        for (range, c, want) in ordinary {
            assert_eq!(
                junk_range(range, false, c).ok(),
                Some(want),
                "{:?} / {}",
                range,
                c
            );
        }
        type Row = ((usize, usize), u32, Option<(usize, usize)>);
        let protocol: [Row; 7] = [
            ((1200, 1252), 1210, Some((1200, 1210))),
            ((1200, 1252), 1200, Some((1200, 1200))),
            ((1200, 1252), 1199, None),
            ((28, 100), 2000, Some((28, 100))),
            ((28, 100), 27, None),
            ((50, 200), 100, Some((50, 100))),
            ((200, 1200), 0, Some((200, 1200))),
        ];
        for (range, c, want) in protocol {
            let got = junk_range(range, true, c);
            assert_eq!(got.as_ref().ok().copied(), want, "{:?} / {}", range, c);
            if want.is_none() {
                assert!(matches!(got, Err(WireGuardError::OutputBudgetExceeded)));
            }
        }
    }
}
