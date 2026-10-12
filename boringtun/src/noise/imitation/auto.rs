// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Temporary camouflage evidence, kept separate from authenticated peer state.
//!
//! Evidence comes from datagrams that fit no AmneziaWG packet shape, and from
//! ones that fit a shape by chance but whose every reading was refused for a
//! reason [`allows_imitation_hint`] allows. Either way it is only recorded.

use std::net::IpAddr;
use std::time::Duration;

use super::super::{amnezia::AmneziaImitationProtocol, errors::WireGuardError, Instant};
use super::detect::detect;

pub(crate) const HINT_LIFETIME: Duration = Duration::from_secs(30);

/// Whether a candidate reading refused with `error` still lets Auto mode
/// inspect the datagram as a camouflage hint.
///
/// A prelude datagram can fit an AmneziaWG packet shape by chance -- a STUN
/// USERNAME whose bytes at S4 fall in H4 -- and its reading then fails like
/// any stranger's datagram. These errors say only that the reading
/// established nothing: its mac1 did not hold (`InvalidMac`), no peer, index,
/// session or in-flight handshake matched (`WrongKey`, `WrongIndex`,
/// `NoCurrentSession`, `UnexpectedPacket`), or its AEAD did not open
/// (`InvalidAeadTag`). Timestamp validation follows decryption. Counter
/// refusals, which can occur before or after AEAD, are conservatively
/// excluded. Local buffer failures and every other non-allowlisted error
/// also veto fallback.
///
/// This is policy, not an authentication statement: an allowed refusal
/// proves nothing about who sent the datagram, and a hint it yields stays
/// unauthenticated evidence, used only under the rules of
/// [`AutoImitation::observe`]. It never selects a mode by itself.
pub(crate) fn allows_imitation_hint(error: &WireGuardError) -> bool {
    matches!(
        error,
        WireGuardError::InvalidMac
            | WireGuardError::WrongKey
            | WireGuardError::WrongIndex
            | WireGuardError::NoCurrentSession
            | WireGuardError::UnexpectedPacket
            | WireGuardError::InvalidAeadTag
    )
}

#[derive(Clone, Copy)]
pub(crate) struct Hint {
    pub(crate) protocol: AmneziaImitationProtocol,
    pub(crate) received: Instant,
}

impl Hint {
    pub(crate) fn detect(datagram: &[u8]) -> Option<Self> {
        Some(Self::new(detect(datagram)?.protocol()))
    }

    pub(crate) fn new(protocol: AmneziaImitationProtocol) -> Self {
        Self {
            protocol,
            received: Instant::now(),
        }
    }

    pub(crate) fn is_live(self) -> bool {
        self.received.elapsed() < HINT_LIFETIME
    }
}

#[derive(Default)]
pub(crate) struct AutoImitation {
    pub(crate) learned: Option<AmneziaImitationProtocol>,
    pending: Option<(Option<IpAddr>, Hint)>,
    pub(crate) warned: bool,
}

impl AutoImitation {
    pub(crate) fn observe(&mut self, source: Option<IpAddr>, datagram: &[u8]) -> bool {
        let Some(hint) = Hint::detect(datagram) else {
            return false;
        };
        if self.learned.is_none()
            && !self
                .pending
                .is_some_and(|(from, hint)| from == source && hint.is_live())
        {
            self.pending = Some((source, hint));
        }
        true
    }

    pub(crate) fn hint(&self, source: Option<IpAddr>) -> Option<AmneziaImitationProtocol> {
        self.pending
            .filter(|(from, hint)| *from == source && hint.is_live())
            .map(|(_, hint)| hint.protocol)
    }

    pub(crate) fn clear_pending(&mut self) {
        self.pending = None;
    }

    #[cfg(test)]
    pub(crate) fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
}
