// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Temporary camouflage evidence, kept separate from authenticated peer state.

use std::net::IpAddr;
use std::time::Duration;

use super::super::{amnezia::AmneziaImitationProtocol, Instant};
use super::detect::detect;

pub(crate) const HINT_LIFETIME: Duration = Duration::from_secs(30);

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

    #[cfg(all(test, feature = "device"))]
    pub(crate) fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
}
