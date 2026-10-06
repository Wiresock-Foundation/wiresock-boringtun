// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::probe_reply::{self, Ingress, ProbeResponder};
use crate::noise::amnezia::{AmneziaConfig, AmneziaImitationProtocol};
use crate::noise::handshake::ObfuscationRanges;
use crate::noise::imitation::auto::Hint;
use parking_lot::Mutex;
use rand_core::RngCore;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

const MAX_HINTS: usize = 1024;

#[derive(Default)]
struct Pending {
    by_source: HashMap<SocketAddr, Hint>,
    order: VecDeque<SocketAddr>,
}

impl Pending {
    fn pop_oldest(&mut self) {
        if let Some(source) = self.order.pop_front() {
            self.by_source.remove(&source);
        }
    }

    fn expire(&mut self) {
        while self
            .order
            .front()
            .is_some_and(|source| !self.by_source[source].is_live())
        {
            self.pop_oldest();
        }
    }
}

#[derive(Default)]
pub(super) struct ImitationHints(Mutex<Pending>);

impl ImitationHints {
    /// The listener's classification door: only non-WireGuard traffic supplies
    /// hints, including when probe replies are disabled or the budget is empty.
    pub(super) fn classify(
        &self,
        datagram: &[u8],
        amnezia: &AmneziaConfig,
        obf: ObfuscationRanges,
        source: SocketAddr,
        responder: Option<&ProbeResponder>,
        rng: &mut impl RngCore,
    ) -> Ingress {
        let ingress = probe_reply::classify(datagram, amnezia, obf, source, responder, rng);
        if amnezia.imitation.protocol == AmneziaImitationProtocol::Auto
            && !matches!(&ingress, Ingress::Wireguard(_))
        {
            self.observe(source, datagram);
        }
        ingress
    }

    fn observe(&self, source: SocketAddr, datagram: &[u8]) {
        let Some(hint) = Hint::detect(datagram) else {
            return;
        };
        let mut pending = self.0.lock();
        pending.expire();
        if pending.by_source.contains_key(&source) {
            return;
        }
        if pending.order.len() == MAX_HINTS {
            pending.pop_oldest();
        }
        // Timestamp under the lock so expiry order matches insertion order even
        // when a worker is descheduled after detecting a packet.
        pending.by_source.insert(source, Hint::new(hint.protocol));
        pending.order.push_back(source);
    }

    pub(super) fn get(&self, source: SocketAddr) -> Option<AmneziaImitationProtocol> {
        let mut pending = self.0.lock();
        pending.expire();
        pending.by_source.get(&source).map(|hint| hint.protocol)
    }

    pub(super) fn discard(&self, source: SocketAddr) {
        let mut pending = self.0.lock();
        if pending.by_source.remove(&source).is_some() {
            pending.order.retain(|entry| *entry != source);
        }
    }

    pub(super) fn clear(&self) {
        *self.0.lock() = Pending::default();
    }

    /// Cookie camouflage uses evidence without adopting any peer state.
    pub(super) fn cookie_config<'a>(
        &self,
        amnezia: &'a AmneziaConfig,
        source: SocketAddr,
        datagram: &[u8],
    ) -> std::borrow::Cow<'a, AmneziaConfig> {
        if amnezia.imitation.protocol != AmneziaImitationProtocol::Auto {
            return std::borrow::Cow::Borrowed(amnezia);
        }
        let protocol = self
            .get(source)
            .or_else(|| Hint::detect(datagram).map(|hint| hint.protocol))
            .unwrap_or(AmneziaImitationProtocol::None);
        amnezia.resolve_imitation(protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::amnezia::{AmneziaConfig, AmneziaImitationProtocol as P};
    use rand_core::OsRng;

    fn source(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], port))
    }
    fn prelude(protocol: P) -> Vec<u8> {
        AmneziaConfig::default()
            .with_protocol_imitation(protocol, None)
            .pre_handshake_imitation_datagrams(&mut OsRng)
            .pop_front()
            .unwrap()
            .1
    }

    #[test]
    fn auto_imitation_cache_separates_ports_and_keeps_first_hint() {
        let hints = ImitationHints::default();
        hints.observe(source(1), &prelude(P::Dns));
        hints.observe(source(2), &prelude(P::Stun));
        hints.observe(source(1), &prelude(P::Quic));
        assert_eq!(hints.get(source(1)), Some(P::Dns));
        assert_eq!(hints.get(source(2)), Some(P::Stun));
        assert_eq!(hints.get(source(3)), None);
    }

    #[test]
    fn auto_imitation_cache_evicts_oldest_at_capacity() {
        let hints = ImitationHints::default();
        let packet = prelude(P::Stun);
        for port in 1..=1025 {
            hints.observe(source(port), &packet);
        }
        assert_eq!(hints.get(source(1)), None);
        assert_eq!(hints.get(source(2)), Some(P::Stun));
        assert_eq!(hints.get(source(1025)), Some(P::Stun));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn auto_imitation_cache_expires_at_thirty_seconds_without_refresh() {
        use mock_instant::thread_local::MockClock;
        use std::time::Duration;
        let hints = ImitationHints::default();
        hints.observe(source(1), &prelude(P::Dns));
        MockClock::advance(Duration::from_secs(29));
        hints.observe(source(1), &prelude(P::Dns));
        assert_eq!(hints.get(source(1)), Some(P::Dns));
        MockClock::advance(Duration::from_secs(1));
        assert_eq!(hints.get(source(1)), None);
        hints.observe(source(1), &prelude(P::Stun));
        assert_eq!(hints.get(source(1)), Some(P::Stun));
    }

    #[test]
    fn auto_imitation_classifies_wireguard_before_recording_hints() {
        use crate::noise::inbound::fixtures::pair;
        use crate::noise::TunnResult;
        let hints = ImitationHints::default();
        let dns = AmneziaConfig::new(128, 128, 128, 128)
            .with_protocol_imitation(P::Dns, None)
            .as_responder();
        let config = dns.clone().with_protocol_imitation(P::Auto, None);
        let (mut client, _) = pair(&dns, None);
        let mut buffer = [0u8; 2048];
        let TunnResult::WriteToNetwork(init) =
            client.format_handshake_initiation(&mut buffer, false)
        else {
            panic!("initiation");
        };
        assert!(matches!(
            hints.classify(
                init,
                &config,
                Default::default(),
                source(1),
                None,
                &mut OsRng
            ),
            Ingress::Wireguard(_)
        ));
        assert_eq!(
            hints.get(source(1)),
            None,
            "unauthenticated WireGuard candidates cannot seed hints"
        );
        assert!(matches!(
            hints.classify(
                &prelude(P::Stun),
                &config,
                Default::default(),
                source(1),
                None,
                &mut OsRng
            ),
            Ingress::Drop
        ));
        assert_eq!(
            hints.get(source(1)),
            Some(P::Stun),
            "probe replies need not be enabled to learn"
        );
        hints.clear();
        assert_eq!(hints.get(source(1)), None);
        let _ = hints.classify(
            &prelude(P::Stun),
            &dns,
            Default::default(),
            source(1),
            None,
            &mut OsRng,
        );
        assert_eq!(
            hints.get(source(1)),
            None,
            "fixed modes never allocate hints"
        );
    }

    #[test]
    fn auto_imitation_anonymous_clients_pin_independently_and_keep_mode_when_roaming() {
        use crate::device::{authenticate_anonymous, commit_anonymous, peer::Peer};
        use crate::noise::{inbound, rate_limiter::RateLimiter, Tunn, TunnResult};
        use crate::x25519::{PublicKey, StaticSecret};
        use std::sync::Arc;
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let config = AmneziaConfig::new(128, 128, 128, 128).with_protocol_imitation(P::Auto, None);
        let mut peers = HashMap::new();
        let mut indices = HashMap::new();
        let mut clients = Vec::new();
        let hints = ImitationHints::default();
        let limiter = RateLimiter::new(&public, 100);
        for (i, protocol) in [P::Dns, P::Quic, P::Sip, P::Stun]
            .iter()
            .copied()
            .enumerate()
        {
            let key = StaticSecret::random_from_rng(OsRng);
            let pubkey = PublicKey::from(&key);
            let index = i as u32 + 1;
            let client = Tunn::new_with_obfuscation(
                key,
                public,
                None,
                None,
                index,
                None,
                Default::default(),
                config
                    .clone()
                    .with_protocol_imitation(protocol, None)
                    .as_responder(),
            )
            .unwrap();
            let server = Tunn::new_with_obfuscation(
                secret.clone(),
                pubkey,
                None,
                None,
                index,
                None,
                Default::default(),
                config.clone(),
            )
            .unwrap();
            let peer = Arc::new(Mutex::new(Peer::new(server, index, None, None)));
            peers.insert(pubkey, peer.clone());
            indices.insert(index, peer);
            clients.push((client, protocol, pubkey));
            let _ = hints.classify(
                &prelude(protocol),
                &config,
                Default::default(),
                source(index as u16),
                None,
                &mut OsRng,
            );
        }
        for (i, (client, protocol, pubkey)) in clients.iter_mut().enumerate() {
            let from = source(i as u16 + 1);
            let mut buffer = [0u8; 2048];
            let mut output = [0u8; 2048];
            let TunnResult::WriteToNetwork(init) =
                client.format_handshake_initiation(&mut buffer, false)
            else {
                panic!("initiation");
            };
            let Ingress::Wireguard(candidates) =
                hints.classify(init, &config, Default::default(), from, None, &mut OsRng)
            else {
                panic!("WireGuard framing first");
            };
            let inbound::Inbound::Accepted((_, mut peer, packet)) = inbound::receive(
                &config,
                Default::default(),
                &limiter,
                Some(from.ip()),
                &candidates,
                init,
                |p| authenticate_anonymous(&peers, &indices, &secret, &public, p, &mut output),
            ) else {
                panic!("authenticated peer");
            };
            let TunnResult::WriteToNetwork(response) =
                commit_anonymous(&mut peer, packet, from, init, hints.get(from), &mut output)
            else {
                panic!("response");
            };
            assert_eq!(peer.tunnel.imitation_protocol(), *protocol);
            peer.adopt_endpoint(from);
            let TunnResult::WriteToNetwork(keepalive) =
                client.decapsulate(None, response, &mut buffer)
            else {
                panic!("keepalive");
            };
            let keepalive = keepalive.to_vec();
            drop(peer);
            let roam = source(i as u16 + 100);
            let _ = hints.classify(
                &prelude(P::Stun),
                &config,
                Default::default(),
                roam,
                None,
                &mut OsRng,
            );
            let Ingress::Wireguard(candidates) = hints.classify(
                &keepalive,
                &config,
                Default::default(),
                roam,
                None,
                &mut OsRng,
            ) else {
                panic!("roaming keepalive");
            };
            let inbound::Inbound::Accepted((_, mut peer, packet)) = inbound::receive(
                &config,
                Default::default(),
                &limiter,
                Some(roam.ip()),
                &candidates,
                &keepalive,
                |p| authenticate_anonymous(&peers, &indices, &secret, &public, p, &mut output),
            ) else {
                panic!("authenticated roam");
            };
            assert!(matches!(
                commit_anonymous(
                    &mut peer,
                    packet,
                    roam,
                    &keepalive,
                    hints.get(roam),
                    &mut output
                ),
                TunnResult::Done
            ));
            peer.adopt_endpoint(roam);
            assert_eq!(peer.tunnel.imitation_protocol(), *protocol);
            drop(peer);
            assert_eq!(peers[pubkey].lock().tunnel.imitation_protocol(), *protocol);
        }
    }
}
