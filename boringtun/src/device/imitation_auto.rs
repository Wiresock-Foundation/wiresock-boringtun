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
    /// hints here, including when probe replies are disabled or the budget is
    /// empty. WireGuard-shaped traffic is classified first and never answered
    /// as a probe; if no reading of it is accepted, [`Self::observe_refused`]
    /// may still record it.
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

    /// The listener's second door, after `classify` called the datagram
    /// WireGuard and every reading of it was refused for a reason
    /// [`crate::noise::inbound::Refusal`] allows: a recognizable prelude whose
    /// bytes merely fit a packet shape. Records evidence only, under the same
    /// rules as the first door; it never replies, selects or logs.
    pub(super) fn observe_refused(
        &self,
        datagram: &[u8],
        amnezia: &AmneziaConfig,
        source: SocketAddr,
    ) {
        if amnezia.imitation.protocol == AmneziaImitationProtocol::Auto {
            self.observe(source, datagram);
        }
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

        // A prelude whose bytes fit a packet shape is WireGuard to this door,
        // which records nothing for it; only a refusal later may.
        use crate::noise::auto_imitation_fixtures::*;
        let request = recorded_stun_prelude()[0].clone();
        assert!(matches!(
            hints.classify(
                &request,
                &recorded_layout(P::Auto),
                recorded_obf(COLLIDING_H4),
                source(1),
                None,
                &mut OsRng
            ),
            Ingress::Wireguard(_)
        ));
        assert_eq!(hints.get(source(1)), None);
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

    type SharedPeer = std::sync::Arc<Mutex<crate::device::peer::Peer>>;

    /// One authenticated server peer behind the shared listener and its
    /// connected socket, for following a single client across endpoints.
    struct Roaming {
        secret: crate::x25519::StaticSecret,
        public: crate::x25519::PublicKey,
        config: AmneziaConfig,
        obf: ObfuscationRanges,
        peer: SharedPeer,
        peers: HashMap<crate::x25519::PublicKey, SharedPeer>,
        indices: HashMap<u32, SharedPeer>,
        hints: ImitationHints,
        limiter: crate::noise::rate_limiter::RateLimiter,
        /// Plaintext either door wrote to the tunnel, oldest first.
        delivered: Mutex<Vec<Vec<u8>>>,
    }

    /// What the server sent back, if anything; `Err` for a refused packet or
    /// a failed commit, neither of which may move the endpoint.
    type Reply = Result<Option<Vec<u8>>, ()>;

    impl Roaming {
        /// The default layout: S1..S4 = 128, default H ranges, Auto.
        fn new() -> (Self, crate::noise::Tunn) {
            Self::with_layout(
                AmneziaConfig::new(128, 128, 128, 128).with_protocol_imitation(P::Auto, None),
                ObfuscationRanges::default(),
            )
        }

        /// A server under `config` and `obf` -- Auto unless a test means a
        /// fixed mode -- and a client under the same layout imitating
        /// nothing: plain random S padding, no prelude of its own.
        fn with_layout(
            config: AmneziaConfig,
            obf: ObfuscationRanges,
        ) -> (Self, crate::noise::Tunn) {
            use crate::device::peer::Peer;
            use crate::noise::{rate_limiter::RateLimiter, Tunn};
            use crate::x25519::{PublicKey, StaticSecret};
            use std::sync::Arc;
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            let key = StaticSecret::random_from_rng(OsRng);
            let pubkey = PublicKey::from(&key);
            let client = Tunn::new_with_obfuscation(
                key,
                public,
                None,
                None,
                1,
                None,
                obf,
                config
                    .clone()
                    .with_protocol_imitation(P::None, None)
                    .as_responder(),
            )
            .unwrap();
            let server = Tunn::new_with_obfuscation(
                secret.clone(),
                pubkey,
                None,
                None,
                1,
                None,
                obf,
                config.clone(),
            )
            .unwrap();
            let peer = Arc::new(Mutex::new(Peer::new(server, 1, None, None)));
            let roaming = Self {
                limiter: RateLimiter::new(&public, 100),
                secret,
                public,
                config,
                obf,
                peers: HashMap::from([(pubkey, peer.clone())]),
                indices: HashMap::from([(1, peer.clone())]),
                peer,
                hints: ImitationHints::default(),
                delivered: Mutex::default(),
            };
            (roaming, client)
        }

        /// What the listener's receive step decides for `datagram`, with
        /// nothing committed; `None` when classification never got there.
        fn receive(
            &self,
            from: SocketAddr,
            datagram: &[u8],
        ) -> Option<crate::noise::inbound::Inbound<()>> {
            use crate::device::authenticate_anonymous;
            use crate::noise::inbound::{self, Inbound};
            let Ingress::Wireguard(candidates) =
                self.hints
                    .classify(datagram, &self.config, self.obf, from, None, &mut OsRng)
            else {
                return None;
            };
            let mut scratch = [0u8; 2048];
            Some(
                match inbound::receive(
                    &self.config,
                    self.obf,
                    &self.limiter,
                    Some(from.ip()),
                    &candidates,
                    datagram,
                    |p| {
                        authenticate_anonymous(
                            &self.peers,
                            &self.indices,
                            &self.secret,
                            &self.public,
                            p,
                            &mut scratch,
                        )
                    },
                ) {
                    Inbound::Accepted(_) => Inbound::Accepted(()),
                    Inbound::NotOurs => Inbound::NotOurs,
                    Inbound::Cookie(demand) => Inbound::Cookie(demand),
                    Inbound::Refused(refusal) => Inbound::Refused(refusal),
                },
            )
        }

        /// The shared listener's door, as the device handler drives it.
        fn listener(&self, from: SocketAddr, datagram: &[u8], dst_len: usize) -> Reply {
            self.listener_with(None, from, datagram, dst_len)
        }

        /// [`Self::listener`] with probe replies on: `Ok(Some(reply))` for an
        /// answered probe.
        fn listener_with(
            &self,
            responder: Option<&ProbeResponder>,
            from: SocketAddr,
            datagram: &[u8],
            dst_len: usize,
        ) -> Reply {
            use crate::device::{authenticate_anonymous, commit_anonymous};
            use crate::noise::{inbound, Authenticated, TunnResult};
            let candidates = match self.hints.classify(
                datagram,
                &self.config,
                self.obf,
                from,
                responder,
                &mut OsRng,
            ) {
                Ingress::Wireguard(candidates) => candidates,
                Ingress::Reply(reply) => return Ok(Some(reply)),
                Ingress::Drop => return Ok(None),
            };
            // One buffer for authentication and commit, as the handler's
            // `dst_buf`: a transport's plaintext is opened into it and
            // delivered from it.
            let mut dst = vec![0u8; dst_len];
            let (mut peer, packet) = match inbound::receive(
                &self.config,
                self.obf,
                &self.limiter,
                Some(from.ip()),
                &candidates,
                datagram,
                |p| {
                    authenticate_anonymous(
                        &self.peers,
                        &self.indices,
                        &self.secret,
                        &self.public,
                        p,
                        &mut dst,
                    )
                },
            ) {
                inbound::Inbound::Accepted((_, peer, packet)) => (peer, packet),
                // As the handler: evidence only, and only when every reading
                // was refused for a reason that established nothing.
                inbound::Inbound::Refused(refusal) => {
                    if refusal.allows_imitation_hint {
                        self.hints.observe_refused(datagram, &self.config, from);
                    }
                    return Err(());
                }
                inbound::Inbound::Cookie(_) | inbound::Inbound::NotOurs => return Err(()),
            };
            // As the handler: only an Auto initiation consults the cache, and
            // a selected one discards the source's evidence.
            let auto_initiation = self.config.imitation.protocol == P::Auto
                && matches!(&packet, Authenticated::HandshakeInit(_));
            let hint = if auto_initiation {
                self.hints.get(from)
            } else {
                None
            };
            let reply = match commit_anonymous(&mut peer, packet, from, datagram, hint, &mut dst) {
                TunnResult::Err(_) => return Err(()),
                TunnResult::WriteToNetwork(reply) => Some(reply.to_vec()),
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    self.delivered.lock().push(packet.to_vec());
                    None
                }
                TunnResult::Done => None,
            };
            if auto_initiation && peer.tunnel.imitation_protocol() != P::None {
                self.hints.discard(from);
            }
            peer.adopt_endpoint(from);
            Ok(reply)
        }

        /// The peer's connected socket: the tunnel sees only the source IP.
        fn connected(&self, from: SocketAddr, datagram: &[u8]) -> Reply {
            use crate::noise::TunnResult;
            let mut dst = [0u8; 2048];
            match self
                .peer
                .lock()
                .tunnel
                .decapsulate(Some(from.ip()), datagram, &mut dst)
            {
                TunnResult::Err(_) => Err(()),
                TunnResult::WriteToNetwork(reply) => Ok(Some(reply.to_vec())),
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    self.delivered.lock().push(packet.to_vec());
                    Ok(None)
                }
                TunnResult::Done => Ok(None),
            }
        }

        fn take_delivered(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.delivered.lock())
        }

        /// The server's transport for `packet`, as it leaves the peer.
        fn send(&self, packet: &[u8]) -> Vec<u8> {
            use crate::noise::TunnResult;
            let mut dst = [0u8; 2048];
            match self.peer.lock().tunnel.encapsulate(packet, &mut dst) {
                TunnResult::WriteToNetwork(data) => data.to_vec(),
                other => panic!("server transport: {:?}", other),
            }
        }

        fn has_tunnel_hint(&self) -> bool {
            self.peer.lock().tunnel.has_imitation_hint()
        }

        fn endpoint(&self) -> Option<SocketAddr> {
            self.peer.lock().endpoint().addr
        }

        fn protocol(&self) -> P {
            self.peer.lock().tunnel.imitation_protocol()
        }
    }

    fn is_stun(packet: &[u8]) -> bool {
        packet[4..8] == [0x21, 0x12, 0xa4, 0x42]
    }

    /// Complete a handshake the server answered and return the client's
    /// confirming keepalive.
    fn confirm(client: &mut crate::noise::Tunn, response: &[u8]) -> Vec<u8> {
        use crate::noise::TunnResult;
        let mut buf = [0u8; 2048];
        match client.decapsulate(None, response, &mut buf) {
            TunnResult::WriteToNetwork(keepalive) => keepalive.to_vec(),
            other => panic!("client keepalive: {:?}", other),
        }
    }

    fn initiation(client: &mut crate::noise::Tunn) -> Vec<u8> {
        use crate::noise::TunnResult;
        // A mocked clock stands still, and a responder refuses an initiation
        // whose timestamp does not advance as a replay.
        #[cfg(feature = "mock-instant")]
        mock_instant::thread_local::MockClock::advance(std::time::Duration::from_millis(1));
        let mut buf = [0u8; 2048];
        match client.format_handshake_initiation(&mut buf, true) {
            TunnResult::WriteToNetwork(init) => init.to_vec(),
            other => panic!("initiation: {:?}", other),
        }
    }

    fn keepalive(client: &mut crate::noise::Tunn) -> Vec<u8> {
        use crate::noise::TunnResult;
        let mut buf = [0u8; 2048];
        match client.encapsulate(&[], &mut buf) {
            TunnResult::WriteToNetwork(keepalive) => keepalive.to_vec(),
            other => panic!("keepalive: {:?}", other),
        }
    }

    /// The tunnel's own pending hint is bound only to a source IP. A prelude
    /// on endpoint A must not select the imitation for a rekey on endpoint B
    /// of the same host after the peer roamed there without a prelude.
    #[test]
    fn auto_imitation_pending_tunnel_hint_does_not_follow_a_roam() {
        let (server, mut client) = Roaming::new();
        let a = source(1000);
        let b = source(2000);

        // Unresolved handshake on A: random.
        let first = server
            .listener(a, &initiation(&mut client), 2048)
            .unwrap()
            .expect("first response");
        assert!(!is_stun(&first));
        let ack = confirm(&mut client, &first);
        server.listener(a, &ack, 2048).unwrap();
        assert_eq!(server.endpoint(), Some(a));

        // STUN prelude on A's connected socket, with no initiation behind it.
        assert_eq!(server.connected(a, &prelude(P::Stun)), Ok(None));

        // Roam to B without a prelude: an authenticated keepalive.
        server.listener(b, &keepalive(&mut client), 2048).unwrap();
        assert_eq!(server.endpoint(), Some(b));

        // Rekey on B's connected socket, then on the listener: still random.
        let second = server
            .connected(b, &initiation(&mut client))
            .unwrap()
            .expect("rekey on B's connected socket");
        assert!(
            !is_stun(&second),
            "A's prelude must not select the imitation on B"
        );
        assert_eq!(server.protocol(), P::None);
        confirm(&mut client, &second);
        let third = server
            .listener(b, &initiation(&mut client), 2048)
            .unwrap()
            .expect("rekey on the listener");
        assert!(!is_stun(&third));
        assert_eq!(server.protocol(), P::None);
        confirm(&mut client, &third);

        // Fresh evidence from B itself is still honoured...
        assert_eq!(server.connected(b, &prelude(P::Stun)), Ok(None));
        let learned = server
            .connected(b, &initiation(&mut client))
            .unwrap()
            .expect("rekey with B's own prelude");
        assert!(is_stun(&learned));
        assert_eq!(server.protocol(), P::Stun);
        confirm(&mut client, &learned);

        // ...and a learned mode survives roaming back to A, whatever A says.
        server.listener(a, &keepalive(&mut client), 2048).unwrap();
        assert_eq!(server.endpoint(), Some(a));
        assert_eq!(server.listener(a, &prelude(P::Dns), 2048), Ok(None));
        let after = server
            .listener(a, &initiation(&mut client), 2048)
            .unwrap()
            .expect("rekey after roaming back");
        assert!(is_stun(&after));
        assert_eq!(server.protocol(), P::Stun);
    }

    /// Neither a refused packet nor a failed commit from another endpoint
    /// moves the peer, so neither may discard the evidence on its endpoint.
    #[test]
    fn auto_imitation_rejected_roams_keep_pending_tunnel_hint() {
        let (server, mut client) = Roaming::new();
        let a = source(1000);
        let b = source(2000);
        let first = server
            .listener(a, &initiation(&mut client), 2048)
            .unwrap()
            .expect("first response");
        let ack = confirm(&mut client, &first);
        server.listener(a, &ack, 2048).unwrap();
        assert_eq!(server.connected(a, &prelude(P::Stun)), Ok(None));

        // A forged initiation from B is refused before any commit.
        let mut forged = initiation(&mut client);
        forged[128 + 20] ^= 1;
        assert_eq!(server.listener(b, &forged, 2048), Err(()));
        assert_eq!(server.endpoint(), Some(a));

        // An authenticated initiation from B whose response does not fit the
        // caller's buffer fails its commit.
        assert_eq!(server.listener(b, &initiation(&mut client), 219), Err(()));
        assert_eq!(server.endpoint(), Some(a));
        assert_eq!(server.protocol(), P::None);

        // A's evidence is intact.
        let learned = server
            .connected(a, &initiation(&mut client))
            .unwrap()
            .expect("rekey on A");
        assert!(is_stun(&learned));
        assert_eq!(server.protocol(), P::Stun);
    }

    /// Send [`bare_ipv4`] both ways through `door` and the peer's tunnel,
    /// checking the server's transport against `shape`.
    fn exchange(
        server: &Roaming,
        client: &mut crate::noise::Tunn,
        door: impl Fn(&[u8]) -> Reply,
        shape: impl Fn(&[u8]) -> bool,
    ) {
        use crate::noise::inbound::fixtures::bare_ipv4;
        use crate::noise::TunnResult;
        let mut buf = [0u8; 2048];
        let data = match client.encapsulate(&bare_ipv4(), &mut buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("client transport: {:?}", other),
        };
        assert_eq!(door(&data), Ok(None));
        assert_eq!(server.take_delivered(), vec![bare_ipv4()]);
        let data = server.send(&bare_ipv4());
        assert!(shape(&data), "server transport shape");
        match client.decapsulate(None, &data, &mut buf) {
            TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, bare_ipv4()),
            other => panic!("server to client: {:?}", other),
        }
    }

    /// The recorded STUN burst's first Binding Request under the recorded
    /// layout and its colliding H4, on an unresolved Auto server.
    fn recorded_colliding() -> (Roaming, crate::noise::Tunn, Vec<u8>) {
        use crate::noise::auto_imitation_fixtures::*;
        use crate::noise::imitation::detect::{detect, Probe};
        let (server, client) =
            Roaming::with_layout(recorded_layout(P::Auto), recorded_obf(COLLIDING_H4));
        let request = recorded_stun_prelude()[0].clone();
        assert_eq!(detect(&request), Some(Probe::Stun));
        assert_eq!(
            server
                .config
                .inbound_candidates(server.obf, &request)
                .offsets(),
            vec![36]
        );
        assert_eq!(server.protocol(), P::None);
        assert!(!server.has_tunnel_hint());
        (server, client, request)
    }

    /// A 72-byte DNS query whose QNAME puts `hIew` -- the recorded STUN
    /// requests' bytes at S4 = 36 -- at offset 36 too.
    fn colliding_dns_query() -> Vec<u8> {
        use crate::noise::auto_imitation_fixtures::*;
        use crate::noise::imitation::detect::{detect, Probe};
        let domain = format!("{}hIew{}.com", "x".repeat(23), "x".repeat(23));
        let query = AmneziaConfig::default()
            .with_protocol_imitation(P::Dns, Some(domain))
            .pre_handshake_imitation_datagrams(&mut OsRng)
            .pop_front()
            .unwrap()
            .1;
        assert_eq!(query.len(), 72);
        assert_eq!(&query[36..40], b"hIew");
        assert_eq!(detect(&query), Some(Probe::Dns));
        assert_eq!(
            recorded_layout(P::Auto)
                .inbound_candidates(recorded_obf(COLLIDING_H4), &query)
                .offsets(),
            vec![36]
        );
        query
    }

    /// The shared listener records a refused prelude for its full source
    /// address, and the next initiation from there selects it.
    #[test]
    fn auto_imitation_listener_learns_from_eligible_refusal() {
        use crate::noise::auto_imitation_fixtures::*;
        use crate::noise::errors::WireGuardError;
        use crate::noise::imitation::detect::{detect, Probe};
        use crate::noise::inbound::fixtures::{bare_ipv4, stun_header};
        use crate::noise::inbound::{Inbound, Refusal};
        let (server, mut client, request) = recorded_colliding();
        let a = source(1000);

        // Classification and receive alone record nothing: the listener's
        // refusal arm does.
        assert!(matches!(
            server
                .hints
                .classify(&request, &server.config, server.obf, a, None, &mut OsRng),
            Ingress::Wireguard(_)
        ));
        assert!(matches!(
            server.receive(a, &request),
            Some(Inbound::Refused(Refusal {
                error: WireGuardError::WrongIndex,
                allows_imitation_hint: true,
            }))
        ));
        assert_eq!(server.hints.get(a), None);
        assert_eq!(server.listener(a, &request, 2048), Err(()));
        assert_eq!(server.hints.get(a), Some(P::Stun));
        assert_eq!(server.hints.get(source(1001)), None, "same IP, other port");

        let init = initiation(&mut client);
        assert_eq!(detect(&init), None, "the initiation cannot detect itself");
        let response = server.listener(a, &init, 2048).unwrap().expect("response");
        assert!(is_stun(&response));
        assert_eq!(server.protocol(), P::Stun);
        assert_eq!(server.hints.get(a), None, "selection discards the evidence");
        let ack = confirm(&mut client, &response);
        assert_eq!(server.listener(a, &ack, 2048), Ok(None));
        exchange(
            &server,
            &mut client,
            |d| server.listener(a, d, 2048),
            is_stun,
        );

        // A replayed transport on the real session is refused for its
        // counter: vetoed, so nothing is recorded, though it is a request.
        let mut buf = [0u8; 2048];
        let mut data = match client.encapsulate(&bare_ipv4(), &mut buf) {
            crate::noise::TunnResult::WriteToNetwork(d) => d.to_vec(),
            other => panic!("{:?}", other),
        };
        stun_header(&mut data);
        assert_eq!(detect(&data), Some(Probe::Stun));
        assert_eq!(
            server
                .config
                .inbound_candidates(server.obf, &data)
                .offsets(),
            vec![36]
        );
        assert_eq!(server.listener(a, &data, 2048), Ok(None));
        assert_eq!(server.take_delivered(), vec![bare_ipv4()]);
        let c = source(1002);
        assert!(matches!(
            server.receive(c, &data),
            Some(Inbound::Refused(Refusal {
                error: WireGuardError::DuplicateCounter,
                allows_imitation_hint: false,
            }))
        ));
        assert_eq!(server.listener(c, &data, 2048), Err(()));
        assert_eq!(server.hints.get(c), None);

        // A real peer's index with no session behind it: still evidence.
        let (server, _, request) = recorded_colliding();
        let mut planted = request.clone();
        planted[40..44].copy_from_slice(&(1u32 << 8).to_le_bytes());
        assert_eq!(detect(&planted), Some(Probe::Stun));
        assert_eq!(
            server
                .config
                .inbound_candidates(server.obf, &planted)
                .offsets(),
            vec![36]
        );
        assert!(matches!(
            server.receive(a, &planted),
            Some(Inbound::Refused(Refusal {
                error: WireGuardError::NoCurrentSession,
                allows_imitation_hint: true,
            }))
        ));
        assert_eq!(server.listener(a, &planted, 2048), Err(()));
        assert_eq!(server.hints.get(a), Some(P::Stun));

        // A fixed mode records nothing.
        let (fixed, _) = Roaming::with_layout(
            recorded_layout(P::Dns).as_responder(),
            recorded_obf(COLLIDING_H4),
        );
        assert!(matches!(
            fixed.receive(a, &request),
            Some(Inbound::Refused(Refusal {
                allows_imitation_hint: true,
                ..
            }))
        ));
        assert_eq!(fixed.listener(a, &request, 2048), Err(()));
        assert_eq!(fixed.hints.get(a), None);
    }

    /// Probe replies on: a colliding request is WireGuard traffic, so it is
    /// never answered and charges nothing; a request with no reading is
    /// answered as before. The budget is exactly one reply, on a frozen
    /// clock, so a charge the colliding request made would show.
    #[test]
    #[cfg(feature = "mock-instant")]
    fn auto_imitation_listener_wiring_with_probe_replies_enabled() {
        use crate::noise::imitation::stun;
        use rand_chacha::ChaCha8Rng;
        use rand_core::SeedableRng;
        let (server, _, colliding) = recorded_colliding();
        let control = (0..)
            .map(|seed| stun::generate(&mut ChaCha8Rng::seed_from_u64(seed)).remove(0))
            .find(|r| {
                server
                    .config
                    .inbound_candidates(server.obf, r)
                    .offsets()
                    .is_empty()
            })
            .unwrap();
        let (a, b, c) = (source(1000), source(2000), source(3000));
        let software = stun::host_software();
        assert!(
            stun::binding_success(&colliding, a, software).is_some(),
            "a responder would answer the colliding request"
        );
        let reply = stun::binding_success(&control, b, software).expect("an answerable control");
        assert_eq!(
            stun::binding_success(&control, c, software).map(|r| r.len()),
            Some(reply.len())
        );
        let responder = ProbeResponder::new(reply.len() as u32);

        assert_eq!(
            server.listener_with(Some(&responder), a, &colliding, 2048),
            Err(())
        );
        assert_eq!(server.hints.get(a), Some(P::Stun));
        assert_eq!(
            server.listener_with(Some(&responder), b, &control, 2048),
            Ok(Some(reply))
        );
        assert_eq!(
            server.listener_with(Some(&responder), c, &control, 2048),
            Ok(None),
            "the budget held exactly one reply"
        );

        // Under load, a datagram whose initiation reading has a valid mac1
        // gets the cookie disposition: one load decision, no evidence.
        use crate::noise::inbound::fixtures::{
            assert_initiation_gate_passes, colliding as colliding_layout, stun_gated_initiation,
        };
        use crate::noise::inbound::Inbound;
        use crate::noise::rate_limiter::RateLimiter;
        let (mut server, _) = Roaming::with_layout(
            colliding_layout(None).with_protocol_imitation(P::Auto, None),
            ObfuscationRanges::default(),
        );
        let wire = stun_gated_initiation(&server.public);
        assert_initiation_gate_passes(&RateLimiter::new(&server.public, 100), &wire);
        server.limiter = RateLimiter::new(&server.public, 0);
        assert!(matches!(server.receive(a, &wire), Some(Inbound::Cookie(_))));
        assert_eq!(server.limiter.load_events(), 1);
        server.limiter = RateLimiter::new(&server.public, 0);
        assert_eq!(server.listener(a, &wire, 2048), Err(()));
        assert_eq!(server.limiter.load_events(), 1);
        assert_eq!(server.hints.get(a), None);
    }

    /// Refused evidence lives under the cache's existing rules.
    #[test]
    fn auto_imitation_cache_retention_expiry_and_isolation() {
        let (server, mut client, request) = recorded_colliding();
        let dns = colliding_dns_query();
        let a = source(1000);

        // The same source keeps its first live hint; another port is its own.
        assert_eq!(server.listener(a, &request, 2048), Err(()));
        assert_eq!(server.listener(a, &dns, 2048), Err(()));
        assert_eq!(server.hints.get(a), Some(P::Stun));
        assert_eq!(server.listener(source(1001), &dns, 2048), Err(()));
        assert_eq!(server.hints.get(source(1001)), Some(P::Dns));
        assert_eq!(server.hints.get(source(1002)), None);
        // Peer removal clears the cache.
        server.hints.clear();
        assert_eq!(server.hints.get(a), None);
        assert_eq!(server.hints.get(source(1001)), None);

        // Evidence at a learned peer's endpoint is stored, ignored by
        // selection, and discarded after it.
        assert_eq!(server.listener(a, &request, 2048), Err(()));
        let response = server
            .listener(a, &initiation(&mut client), 2048)
            .unwrap()
            .expect("response");
        assert!(is_stun(&response));
        confirm(&mut client, &response);
        assert_eq!(server.listener(a, &dns, 2048), Err(()));
        assert_eq!(server.hints.get(a), Some(P::Dns));
        let rekey = server
            .listener(a, &initiation(&mut client), 2048)
            .unwrap()
            .expect("rekey");
        assert!(is_stun(&rekey), "a learned mode is not repinned");
        assert_eq!(server.protocol(), P::Stun);
        assert_eq!(server.hints.get(a), None);

        #[cfg(feature = "mock-instant")]
        {
            use mock_instant::thread_local::MockClock;
            use std::time::Duration;
            let (server, _, request) = recorded_colliding();
            assert_eq!(server.listener(a, &request, 2048), Err(()));
            MockClock::advance(Duration::from_secs(29));
            assert_eq!(server.listener(a, &dns, 2048), Err(()));
            assert_eq!(server.hints.get(a), Some(P::Stun));
            MockClock::advance(Duration::from_secs(1));
            assert_eq!(server.hints.get(a), None, "expired at 30 s");
            assert_eq!(server.listener(a, &dns, 2048), Err(()));
            assert_eq!(server.hints.get(a), Some(P::Dns));
        }
    }

    /// A colliding prelude on the peer's connected socket is the tunnel's
    /// evidence, and a rekey there learns from it.
    #[test]
    fn auto_imitation_connected_learns_from_colliding_prelude() {
        let (server, mut client, request) = recorded_colliding();
        let a = source(1000);
        let first = server
            .listener(a, &initiation(&mut client), 2048)
            .unwrap()
            .expect("first response");
        assert!(!is_stun(&first));
        let ack = confirm(&mut client, &first);
        server.listener(a, &ack, 2048).unwrap();
        assert_eq!(server.endpoint(), Some(a));
        assert_eq!(server.protocol(), P::None);
        assert!(!server.has_tunnel_hint());

        assert_eq!(server.connected(a, &request), Err(()));
        assert!(server.has_tunnel_hint());
        assert_eq!(
            server.hints.get(a),
            None,
            "the listener's cache is not involved"
        );
        let learned = server
            .connected(a, &initiation(&mut client))
            .unwrap()
            .expect("rekey on A");
        assert!(is_stun(&learned));
        assert_eq!(server.protocol(), P::Stun);
        assert!(!server.has_tunnel_hint());
        let ack = confirm(&mut client, &learned);
        assert_eq!(server.connected(a, &ack), Ok(None));
        exchange(&server, &mut client, |d| server.connected(a, d), is_stun);
    }

    /// A colliding prelude's tunnel evidence is dropped by a roam like any
    /// other: it does not shape a rekey on the new endpoint, and that
    /// endpoint's own prelude still does.
    #[test]
    fn auto_imitation_colliding_pending_hint_does_not_follow_a_roam() {
        use crate::noise::auto_imitation_fixtures::recorded_stun_prelude;
        let (server, mut client, request) = recorded_colliding();
        let (a, b) = (source(1000), source(2000));
        let first = server
            .listener(a, &initiation(&mut client), 2048)
            .unwrap()
            .expect("first response");
        let ack = confirm(&mut client, &first);
        server.listener(a, &ack, 2048).unwrap();
        assert_eq!(server.protocol(), P::None);
        assert!(!server.has_tunnel_hint());

        assert_eq!(server.connected(a, &request), Err(()));
        assert!(server.has_tunnel_hint());
        server.listener(b, &keepalive(&mut client), 2048).unwrap();
        assert_eq!(server.endpoint(), Some(b));
        assert!(!server.has_tunnel_hint(), "the roam discarded A's evidence");

        let second = server
            .connected(b, &initiation(&mut client))
            .unwrap()
            .expect("rekey on B");
        assert!(!is_stun(&second));
        assert_eq!(server.protocol(), P::None);
        confirm(&mut client, &second);

        let own = recorded_stun_prelude()[1].clone();
        assert_eq!(
            server.config.inbound_candidates(server.obf, &own).offsets(),
            vec![36]
        );
        assert_eq!(server.connected(b, &own), Err(()));
        assert!(server.has_tunnel_hint());
        let learned = server
            .connected(b, &initiation(&mut client))
            .unwrap()
            .expect("rekey with B's own prelude");
        assert!(is_stun(&learned));
        assert_eq!(server.protocol(), P::Stun);
    }
}
