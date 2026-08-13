// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::RwLock;
use socket2::{Domain, Protocol, Type};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

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
    /// `connect_endpoint` failed for the endpoint address currently in
    /// `endpoint.addr`, with an errno that says nothing about the listener's
    /// capacity. Retrying it per datagram is the storm the listener-wide gate
    /// in `device::mod` exists to stop, but latching the *listener* for a
    /// per-destination failure takes the connected socket away from every
    /// other peer, so the suppression is scoped here.
    ///
    /// Per endpoint *address*, not per peer: `set_endpoint` clears it when the
    /// address actually changes, since the address is the whole reason the
    /// connect failed and a roam to a routable one must be allowed to try
    /// again. A peer alternating between two bad addresses therefore drives
    /// one attempt per alternation -- the same bound the upgrade path already
    /// had for a healthy alternating peer.
    ///
    /// Atomic rather than a plain `bool` only so `connect_endpoint`'s and
    /// `set_endpoint`'s `&self` signatures stay put; every `Peer` is already
    /// behind a `Mutex`, so there is no contention to speak of.
    upgrade_suppressed: AtomicBool,
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
            upgrade_suppressed: AtomicBool::new(false),
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

    /// Whether a connected-socket upgrade for the current endpoint address has
    /// already failed for a reason that will not change until the address does.
    pub(crate) fn upgrade_suppressed(&self) -> bool {
        self.upgrade_suppressed.load(Ordering::Relaxed)
    }

    /// Suppress further upgrade attempts for the current endpoint address.
    /// Returns `true` if this is the first one, so the caller can log once.
    pub(crate) fn suppress_upgrade(&self) -> bool {
        !self.upgrade_suppressed.swap(true, Ordering::Relaxed)
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
            // The suppression describes the address we just left, not this
            // peer. Held across a roam it would strand the peer on the shared
            // listener for the life of the process after one bad endpoint --
            // and cleared *outside* this guard it would rearm on every datagram
            // from the same unroutable endpoint, which is the per-datagram
            // storm again.
            self.upgrade_suppressed.store(false, Ordering::Relaxed);
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

        // `dup(2)` here rather than after the connect. It is the one call
        // *after* `Socket::new` that fails on fd exhaustion -- under blanket
        // exhaustion `Socket::new` above fails first, so this line is reached
        // only when a single descriptor remains, or when another thread takes
        // the last one in between. Once `connect` has run, this socket
        // outranks the wildcard listener for the peer's 4-tuple, and although
        // a failing `?` closes it on the way out, every datagram arriving
        // inside that window is delivered to it and dies with it. Doing the
        // dup first means fd exhaustion can no longer open the window.
        //
        // A `dup` shares the underlying `struct socket`, so the `bind` and
        // `connect` below apply to both descriptors. `set_mark` is hoisted for
        // the same reason -- SO_MARK is order-independent.
        let conn_dup = udp_conn.try_clone()?;

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(fwmark) = fwmark {
            udp_conn.set_mark(fwmark)?;
        }

        udp_conn.bind(&bind_addr)?;
        udp_conn.connect(&addr.into())?;
        udp_conn.set_nonblocking(true)?;

        endpoint.conn = Some(conn_dup);

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

    /// The upgrade suppression is per endpoint address, in both directions.
    ///
    /// A roam to a different address must rearm the upgrade -- the address is
    /// the whole reason the connect failed. A datagram from the SAME address
    /// must not, because rearming there is the per-datagram retry storm the
    /// suppression exists to stop.
    #[test]
    fn suppression_is_cleared_when_the_endpoint_address_changes() {
        let peer = test_peer();
        peer.set_endpoint("192.0.2.7:51820".parse().unwrap());
        assert!(!peer.upgrade_suppressed());

        assert!(
            peer.suppress_upgrade(),
            "the first suppression reports itself"
        );
        assert!(!peer.suppress_upgrade(), "the second must not log again");

        // Same address: `set_endpoint` runs on every datagram, and rearming
        // here would retry the doomed connect once per datagram.
        peer.set_endpoint("192.0.2.7:51820".parse().unwrap());
        assert!(
            peer.upgrade_suppressed(),
            "a datagram from the same unroutable endpoint must not rearm the \
             upgrade; that is the per-datagram retry storm"
        );

        // A roam: the failure described the old address, not the peer.
        peer.set_endpoint("198.51.100.9:51820".parse().unwrap());
        assert!(
            !peer.upgrade_suppressed(),
            "a roam to a different endpoint must rearm the upgrade"
        );
    }

    /// Environment marker naming the child half of the descriptor-exhaustion
    /// test below. Set by the parent, read by the same test function.
    const DUP_EMFILE_CHILD: &str = "BORINGTUN_TEST_DUP_EMFILE_CHILD";

    /// Test name for the re-exec, hoisted so the filter and the function cannot
    /// drift apart silently -- a filter matching nothing exits 0.
    const DUP_EMFILE_TEST: &str =
        "device::peer::tests::a_failed_endpoint_dup_is_an_error_not_a_panic";

    /// A failing `dup(2)` in `connect_endpoint` must return an error, not abort
    /// the daemon.
    ///
    /// Runs the real failure in a *child process*. `RLIMIT_NOFILE` is
    /// process-global and shared by every thread, so lowering it in this binary
    /// would starve every other test's sockets. Unlike epoll's
    /// `max_user_watches` -- machine-wide per-UID, which is why `EventPoll`
    /// injects a fault instead -- this limit *is* forceable in a process of our
    /// own, so nothing here is faked: a real `dup(2)` returns a real EMFILE.
    ///
    /// The child leaves *exactly one* descriptor free, which is the only state
    /// in which the dup is reached at all: under blanket exhaustion the
    /// `Socket::new` above it fails first and `try_clone` never runs. Both
    /// halves of that arithmetic are asserted in the child, so drift fails the
    /// test loudly instead of quietly retargeting it at `Socket::new`.
    #[test]
    fn a_failed_endpoint_dup_is_an_error_not_a_panic() {
        if std::env::var_os(DUP_EMFILE_CHILD).is_some() {
            dup_emfile_child();
            return;
        }

        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                DUP_EMFILE_TEST,
            ])
            .env(DUP_EMFILE_CHILD, "1")
            .output()
            .expect("failed to re-run the test binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);

        assert!(
            out.status.success(),
            "the child aborted instead of returning an error: {:?}
             --- child stdout ---
{}--- child stderr ---
{}",
            out.status,
            stdout,
            stderr
        );
        // A filter matching nothing exits 0, so a successful child is not yet
        // evidence that anything ran. Without this, the test turns into a no-op
        // the moment the name in `DUP_EMFILE_TEST` drifts from the function.
        assert!(
            stdout.contains("1 passed"),
            "the child ran no test -- the filter matched nothing:
{}",
            stdout
        );
    }

    fn dup_emfile_child() {
        use std::os::unix::io::AsRawFd;

        fn nofile(limit: libc::rlim_t) -> libc::rlim_t {
            let mut rlim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) },
                0,
                "getrlimit"
            );
            let saved = rlim.rlim_cur;
            rlim.rlim_cur = limit;
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) },
                0,
                "setrlimit"
            );
            saved
        }
        fn udp() -> std::io::Result<Socket> {
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        }

        // Built before the limit drops: key generation is allowed a descriptor.
        let peer = test_peer();
        peer.endpoint_mut().addr = Some("192.0.2.1:51820".parse().unwrap());

        // A little headroom above the lowest free descriptor, so the fill below
        // has something to do whatever this binary already has open.
        let ceiling = udp().unwrap().as_raw_fd() as libc::rlim_t + 8;
        let saved = nofile(ceiling);

        let mut hogs = Vec::new();
        while let Ok(s) = udp() {
            hogs.push(s);
        }
        // Release exactly one. The `socket(2)` inside `connect_endpoint` takes
        // it, and the `dup(2)` that follows has nothing left.
        hogs.pop();

        let first = udp();
        let second = udp();
        let one_free = first.is_ok();
        let only_one = second.is_err();
        drop((first, second));

        let outcome = peer.connect_endpoint(0, None);
        let committed = peer.endpoint().conn.is_some();

        // Restore before asserting, or a failure cannot print itself.
        drop(hogs);
        nofile(saved);

        assert!(
            one_free,
            "precondition: one descriptor must be free, or `Socket::new` fails              first and this test proves nothing about `try_clone`"
        );
        assert!(
            only_one,
            "precondition: only one descriptor may be free, or `try_clone`              succeeds and this test proves nothing"
        );
        match outcome {
            Err(Error::IoError(e)) => assert_eq!(
                e.raw_os_error(),
                Some(libc::EMFILE),
                "expected the dup to fail with EMFILE, got {:?}",
                e
            ),
            other => panic!("expected an EMFILE i/o error, got {:?}", other),
        }
        assert!(
            !committed,
            "a failed upgrade must not leave a connected socket on the endpoint"
        );
    }
}
