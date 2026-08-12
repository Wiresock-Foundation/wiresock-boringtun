// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::RwLock;
use socket2::{Domain, Protocol, Type};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use crate::device::Error;
use crate::noise::{Tunn, TunnResult};

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
    pub conn: Option<socket2::Socket>,
}

/// Report a failed endpoint shutdown without taking the process with it.
///
/// `endpoint.conn` is a `dup(2)`, so closing it does NOT close the descriptor
/// the registered connected-socket handler owns. The `shutdown` is what raises
/// EPOLLHUP on that descriptor, which is how the event loop reaches
/// `handler.cancel()` and frees the handler, its socket and its `Arc<Peer>` --
/// see the `p.shutdown_endpoint(); // close open udp socket and free the
/// closure` call in `device::mod`. So a failure here is not free; it retains a
/// handler.
///
/// There is still no cheaper recovery available at this point, and no errno has
/// been identified that makes `shutdown` fail on a genuinely connected UDP
/// socket, so the result is discarded rather than propagated. What must not
/// happen is a panic: unwrapping a discarded result turns any unexpected errno
/// into a panicked worker thread, and `DeviceHandle::wait`'s `join().unwrap()`
/// turns that into a dead daemon. Callers: connection expiry, peer removal,
/// listen-port changes, and each source-address change of an authenticated
/// peer -- that last one is the only caller a remote input paces.
///
/// Deliberately not claiming a specific trigger. An earlier version of this
/// comment blamed ICMP, which was wrong: an ICMP error sets `sk_err` on a
/// connected UDP socket and is reported to the next send or receive, it does
/// not tear the association down, so it cannot make a later `shutdown` return
/// ENOTCONN. Logged at debug because a failure here is not actionable.
fn log_shutdown_error(result: std::io::Result<()>) {
    if let Err(e) = result {
        tracing::debug!(message = "Endpoint shutdown failed", error = ?e);
    }
}

pub struct Peer {
    /// The associated tunnel struct
    pub(crate) tunnel: Tunn,
    /// The index the tunnel uses
    index: u32,
    endpoint: RwLock<Endpoint>,
    preshared_key: Option<[u8; 32]>,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct AllowedIP {
    pub addr: IpAddr,
    pub cidr: u8,
}

impl FromStr for AllowedIP {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: Vec<&str> = s.split('/').collect();
        if ip.len() != 2 {
            return Err("Invalid IP format".to_owned());
        }

        let (addr, cidr) = (ip[0].parse::<IpAddr>(), ip[1].parse::<u8>());
        match (addr, cidr) {
            (Ok(addr @ IpAddr::V4(_)), Ok(cidr)) if cidr <= 32 => Ok(AllowedIP { addr, cidr }),
            (Ok(addr @ IpAddr::V6(_)), Ok(cidr)) if cidr <= 128 => Ok(AllowedIP { addr, cidr }),
            _ => Err("Invalid IP format".to_owned()),
        }
    }
}

impl Peer {
    /// Allowed IPs are deliberately absent: `Device::peers_by_ip` owns them.
    pub fn new(
        tunnel: Tunn,
        index: u32,
        endpoint: Option<SocketAddr>,
        preshared_key: Option<[u8; 32]>,
    ) -> Peer {
        Peer {
            tunnel,
            index,
            endpoint: RwLock::new(Endpoint {
                addr: endpoint,
                conn: None,
            }),
            preshared_key,
        }
    }

    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.update_timers(dst)
    }

    pub fn endpoint(&self) -> parking_lot::RwLockReadGuard<'_, Endpoint> {
        self.endpoint.read()
    }

    pub(crate) fn endpoint_mut(&self) -> parking_lot::RwLockWriteGuard<'_, Endpoint> {
        self.endpoint.write()
    }

    pub fn shutdown_endpoint(&self) {
        if let Some(conn) = self.endpoint.write().conn.take() {
            tracing::info!("Disconnecting from endpoint");
            // Best-effort: the socket is being dropped either way, so the
            // result is discarded. Reached on connection expiry, peer removal
            // and listen-port changes -- at most once per connected socket, and
            // even so, unwrapping it panics a worker. See `log_shutdown_error`.
            log_shutdown_error(conn.shutdown(Shutdown::Both));
        }
    }

    pub fn set_endpoint(&self, addr: SocketAddr) {
        let mut endpoint = self.endpoint.write();
        if endpoint.addr != Some(addr) {
            // We only need to update the endpoint if it differs from the current one
            if let Some(conn) = endpoint.conn.take() {
                // Same as `shutdown_endpoint`, and more exposed: fires once
                // per source-address change of an authenticated peer that has a
                // connected socket open, so a peer alternating addresses drives
                // one per datagram -- a remote input on the ingress path.
                log_shutdown_error(conn.shutdown(Shutdown::Both));
            }

            endpoint.addr = Some(addr);
        }
    }

    pub fn connect_endpoint(
        &self,
        port: u16,
        fwmark: Option<u32>,
    ) -> Result<socket2::Socket, Error> {
        let mut endpoint = self.endpoint.write();

        if endpoint.conn.is_some() {
            return Err(Error::Connect("Connected".to_owned()));
        }

        let addr = endpoint
            .addr
            .ok_or_else(|| Error::Connect("No endpoint address set".to_owned()))?;

        let udp_conn =
            socket2::Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        udp_conn.set_reuse_address(true)?;
        let bind_addr = if addr.is_ipv4() {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into()
        } else {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into()
        };
        udp_conn.bind(&bind_addr)?;
        udp_conn.connect(&addr.into())?;
        udp_conn.set_nonblocking(true)?;

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(fwmark) = fwmark {
            udp_conn.set_mark(fwmark)?;
        }

        // `try_clone` is a `dup(2)`, which fails on fd exhaustion -- reachable
        // on a server with many peers, and not a reason to abort.
        endpoint.conn = Some(udp_conn.try_clone()?);

        // Deliberately silent. An earlier revision of this function logged
        // "Connected endpoint" here, and an earlier revision of this comment
        // argued that moving the line to the caller would put it "further from
        // the thing it describes". That was wrong: committing a `conn` is not
        // the event worth reporting, because `register_conn_handler` can still
        // fail and roll it straight back. The caller logs it on the arm where
        // the socket actually enters service.
        //
        // `addr` is still bound above rather than re-read: it is what the
        // caller reports, and it is one less `unwrap` on a path this branch is
        // removing them from.
        let _ = addr;

        Ok(udp_conn)
    }

    /// Replace this peer's pre-shared key, discarding sessions if it changed.
    pub(crate) fn set_preshared_key(&mut self, preshared_key: Option<[u8; 32]>) {
        self.preshared_key = preshared_key;
        self.tunnel.set_preshared_key(preshared_key);
    }

    /// Replace this peer's persistent-keepalive interval, keeping sessions.
    pub(crate) fn set_persistent_keepalive(&mut self, keepalive: Option<u16>) {
        self.tunnel.set_persistent_keepalive(keepalive);
    }

    // Deliberately no `is_allowed_ip` / `allowed_ips` here. Which prefixes
    // route to a peer is a property of `Device::peers_by_ip`, and keeping a
    // second copy on the peer is what let the two disagree: a prefix moved
    // between peers updated the trie and left the old owner's copy behind,
    // so it could still source-spoof an address it no longer held. Use
    // `Device::peer_owns` and `Device::peer_allowed_ips`.

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.time_since_last_handshake()
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    pub fn preshared_key(&self) -> Option<&[u8; 32]> {
        self.preshared_key.as_ref()
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::amnezia::AmneziaConfig;
    use crate::noise::Tunn;
    use crate::x25519;
    use rand_core::OsRng;
    use socket2::{Domain, Protocol, Socket, Type};

    fn test_peer() -> Peer {
        let secret = x25519::StaticSecret::random_from_rng(OsRng);
        let peer_public = x25519::PublicKey::from(&x25519::StaticSecret::random_from_rng(OsRng));
        let tunnel = Tunn::new_with_obfuscation(
            secret,
            peer_public,
            None,
            None,
            1,
            None,
            Default::default(),
            AmneziaConfig::default(),
        )
        .unwrap();
        Peer::new(tunnel, 1, None, None)
    }

    /// An *unconnected* UDP socket, which is what makes this deterministic:
    /// `shutdown(2)` on one returns ENOTCONN on every unix.
    ///
    /// This is a stand-in for "shutdown failed", not a claim that production
    /// reaches ENOTCONN by this route -- the production socket is connected. The
    /// property under test is that a failed shutdown does not abort the process,
    /// and any errno demonstrates it.
    fn unconnected_socket() -> Socket {
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap()
    }

    #[test]
    fn a_roam_survives_a_failing_endpoint_shutdown() {
        // `set_endpoint` fires whenever an authenticated peer changes source
        // address, so the trigger is a remote datagram on the ingress path.
        // This used to `unwrap` the shutdown and abort the whole daemon.
        let peer = test_peer();
        peer.endpoint_mut().conn = Some(unconnected_socket());
        peer.endpoint_mut().addr = Some("192.0.2.1:51820".parse().unwrap());

        assert!(
            unconnected_socket().shutdown(Shutdown::Both).is_err(),
            "precondition: shutdown on an unconnected UDP socket must fail, \
             otherwise this test proves nothing"
        );

        peer.set_endpoint("192.0.2.2:51820".parse().unwrap());

        assert_eq!(
            peer.endpoint().addr,
            Some("192.0.2.2:51820".parse().unwrap()),
            "the roam must still be applied"
        );
        assert!(
            peer.endpoint().conn.is_none(),
            "the stale connected socket must be dropped either way"
        );
    }

    #[test]
    fn shutdown_endpoint_survives_a_failing_shutdown() {
        // Same call, reached from connection expiry, removal and port changes.
        let peer = test_peer();
        peer.endpoint_mut().conn = Some(unconnected_socket());

        peer.shutdown_endpoint();

        assert!(peer.endpoint().conn.is_none());
    }

    #[test]
    fn connecting_without_an_endpoint_address_is_an_error_not_a_panic() {
        let peer = test_peer();
        assert!(peer.endpoint().addr.is_none());
        assert!(peer.connect_endpoint(51820, None).is_err());
    }
}
