// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This module contains some integration tests for boringtun
// Those tests require docker and sudo privileges to run
#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use crate::device::{DeviceConfig, DeviceHandle};
    #[cfg(target_os = "linux")]
    use crate::noise::{Packet, Tunn, TunnResult};
    use crate::x25519::{PublicKey, StaticSecret};
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    use hex::encode;
    use rand_core::OsRng;
    use ring::rand::{SecureRandom, SystemRandom};
    use std::fmt::Write as _;
    use std::io::{BufRead, BufReader, Read, Write};
    #[cfg(target_os = "linux")]
    use std::net::UdpSocket;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::unix::net::UnixStream;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    #[cfg(target_os = "linux")]
    use std::time::{Duration, Instant};

    static NEXT_IFACE_IDX: AtomicUsize = AtomicUsize::new(100); // utun 100+ should be vacant during testing on CI
    static NEXT_PORT: AtomicUsize = AtomicUsize::new(61111); // Use ports starting with 61111, hoping we don't run into a taken port 🤷
    static NEXT_IP: AtomicUsize = AtomicUsize::new(0xc0000200); // Use 192.0.2.0/24 for those tests, we might use more than 256 addresses though, usize must be >=32 bits on all supported platforms
    static NEXT_IP_V6: AtomicUsize = AtomicUsize::new(0); // Use the 2001:db8:: address space, append this atomic counter for bottom 32 bits

    fn next_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(
            NEXT_IP.fetch_add(1, Ordering::Relaxed) as u32
        ))
    }

    fn next_ip_v6() -> IpAddr {
        let addr = 0x2001_0db8_0000_0000_0000_0000_0000_0000_u128
            + u128::from(NEXT_IP_V6.fetch_add(1, Ordering::Relaxed) as u32);

        IpAddr::V6(Ipv6Addr::from(addr))
    }

    fn next_port() -> u16 {
        NEXT_PORT.fetch_add(1, Ordering::Relaxed) as u16
    }

    /// Represents an allowed IP and cidr for a peer
    struct AllowedIp {
        ip: IpAddr,
        cidr: u8,
    }

    /// Represents a single peer running in a container
    struct Peer {
        key: StaticSecret,
        endpoint: SocketAddr,
        allowed_ips: Vec<AllowedIp>,
        container_name: Option<String>,
    }

    /// Represents a single WireGuard interface on local machine
    struct WGHandle {
        _device: DeviceHandle,
        name: String,
        addr_v4: IpAddr,
        addr_v6: IpAddr,
        started: bool,
        peers: Vec<Arc<Peer>>,
    }

    impl Drop for Peer {
        fn drop(&mut self) {
            if let Some(name) = &self.container_name {
                Command::new("docker")
                    .args([
                        "stop", // Run docker
                        &name[5..],
                    ])
                    .status()
                    .ok();

                std::fs::remove_file(name).ok();
                std::fs::remove_file(format!("{}.ngx", name)).ok();
            }
        }
    }

    impl Peer {
        /// Create a new peer with a given endpoint and a list of allowed IPs
        fn new(endpoint: SocketAddr, allowed_ips: Vec<AllowedIp>) -> Peer {
            Peer {
                key: StaticSecret::random_from_rng(OsRng),
                endpoint,
                allowed_ips,
                container_name: None,
            }
        }

        /// Creates a new configuration file that can be used by wg-quick
        fn gen_wg_conf(
            &self,
            local_key: &PublicKey,
            local_addr: &IpAddr,
            local_port: u16,
        ) -> String {
            let mut conf = String::from("[Interface]\n");
            // Each allowed ip, becomes a possible address in the config
            for ip in &self.allowed_ips {
                let _ = writeln!(conf, "Address = {}/{}", ip.ip, ip.cidr);
            }

            // The local endpoint port is the remote listen port
            let _ = writeln!(conf, "ListenPort = {}", self.endpoint.port());
            // HACK: this should consume the key so it can't be reused instead of cloning and serializing
            let _ = writeln!(conf, "PrivateKey = {}", BASE64.encode(self.key.to_bytes()));

            // We are the peer
            let _ = writeln!(conf, "[Peer]");
            let _ = writeln!(conf, "PublicKey = {}", BASE64.encode(local_key.as_bytes()));
            let _ = writeln!(conf, "AllowedIPs = {}", local_addr);
            let _ = write!(conf, "Endpoint = 127.0.0.1:{}", local_port);

            conf
        }

        /// Create a simple nginx config, that will respond with the peer public key
        fn gen_nginx_conf(&self) -> String {
            format!(
                "server {{\n\
                 listen 80;\n\
                 listen [::]:80;\n\
                 location / {{\n\
                 return 200 '{}';\n\
                 }}\n\
                 }}",
                encode(PublicKey::from(&self.key).as_bytes())
            )
        }

        fn start_in_container(
            &mut self,
            local_key: &PublicKey,
            local_addr: &IpAddr,
            local_port: u16,
        ) {
            let peer_config = self.gen_wg_conf(local_key, local_addr, local_port);
            let peer_config_file = temp_path();
            std::fs::write(&peer_config_file, peer_config).unwrap();
            let nginx_config = self.gen_nginx_conf();
            let nginx_config_file = format!("{}.ngx", peer_config_file);
            std::fs::write(&nginx_config_file, nginx_config).unwrap();

            Command::new("docker")
                .args([
                    "run",                 // Run docker
                    "-d",                  // In detached mode
                    "--cap-add=NET_ADMIN", // Grant permissions to open a tunnel
                    "--device=/dev/net/tun",
                    "--sysctl", // Enable ipv6
                    "net.ipv6.conf.all.disable_ipv6=0",
                    "--sysctl",
                    "net.ipv6.conf.default.disable_ipv6=0",
                    "-p", // Open port for the endpoint
                    &format!("{0}:{0}/udp", self.endpoint.port()),
                    "-v", // Map the generated WireGuard config file
                    &format!("{}:/wireguard/wg.conf", peer_config_file),
                    "-v", // Map the nginx config file
                    &format!("{}:/etc/nginx/conf.d/default.conf", nginx_config_file),
                    "--rm", // Cleanup
                    "--name",
                    &peer_config_file[5..],
                    "vkrasnov/wireguard-test",
                ])
                .status()
                .expect("Failed to run docker");

            self.container_name = Some(peer_config_file);
        }

        fn connect(&self) -> std::net::TcpStream {
            let http_addr = SocketAddr::new(self.allowed_ips[0].ip, 80);
            for _i in 0..5 {
                let res = std::net::TcpStream::connect(http_addr);
                if let Err(err) = res {
                    println!("failed to connect: {:?}", err);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }

                return res.unwrap();
            }

            panic!("failed to connect");
        }

        fn get_request(&self) -> String {
            let mut tcp_conn = self.connect();

            write!(
                tcp_conn,
                "GET / HTTP/1.1\nHost: localhost\nAccept: */*\nConnection: close\n\n"
            )
            .unwrap();

            tcp_conn
                .set_read_timeout(Some(std::time::Duration::from_secs(60)))
                .ok();

            let mut reader = BufReader::new(tcp_conn);
            let mut line = String::new();
            let mut response = String::new();
            let mut len = 0usize;

            // Read response code
            if reader.read_line(&mut line).is_ok() && !line.starts_with("HTTP/1.1 200") {
                return response;
            }
            line.clear();

            // Read headers
            while reader.read_line(&mut line).is_ok() {
                if line.trim() == "" {
                    break;
                }

                {
                    let parsed_line: Vec<&str> = line.split(':').collect();
                    if parsed_line.len() < 2 {
                        return response;
                    }

                    let (key, val) = (parsed_line[0], parsed_line[1]);
                    if key.to_lowercase() == "content-length" {
                        len = match val.trim().parse() {
                            Err(_) => return response,
                            Ok(len) => len,
                        };
                    }
                }
                line.clear();
            }

            // Read body
            let mut buf = [0u8; 256];
            while len > 0 {
                let to_read = len.min(buf.len());
                if reader.read_exact(&mut buf[..to_read]).is_err() {
                    return response;
                }
                response.push_str(&String::from_utf8_lossy(&buf[..to_read]));
                len -= to_read;
            }

            response
        }
    }

    impl WGHandle {
        /// Create a new interface for the tunnel with the given address
        fn init(addr_v4: IpAddr, addr_v6: IpAddr) -> WGHandle {
            WGHandle::init_with_config(
                addr_v4,
                addr_v6,
                DeviceConfig {
                    n_threads: 2,
                    use_connected_socket: true,
                    #[cfg(target_os = "linux")]
                    use_multi_queue: true,
                    #[cfg(target_os = "linux")]
                    uapi_fd: -1,
                    // Vanilla WireGuard: the AmneziaWG and probe-reply fields
                    // stay at their defaults. `..default()` rather than naming
                    // them, so a future field does not break this build.
                    ..Default::default()
                },
            )
        }

        /// Create a new interface for the tunnel with the given address
        fn init_with_config(addr_v4: IpAddr, addr_v6: IpAddr, config: DeviceConfig) -> WGHandle {
            // Generate a new name, utun100+ should work on macOS and Linux
            let name = format!("utun{}", NEXT_IFACE_IDX.fetch_add(1, Ordering::Relaxed));
            let _device = DeviceHandle::new(&name, config).unwrap();
            WGHandle {
                _device,
                name,
                addr_v4,
                addr_v6,
                started: false,
                peers: vec![],
            }
        }

        #[cfg(target_os = "macos")]
        /// Starts the tunnel
        fn start(&mut self) {
            // Assign the ipv4 address to the interface
            Command::new("ifconfig")
                .args(&[
                    &self.name,
                    &self.addr_v4.to_string(),
                    &self.addr_v4.to_string(),
                    "alias",
                ])
                .status()
                .expect("failed to assign ip to tunnel");

            // Assign the ipv6 address to the interface
            Command::new("ifconfig")
                .args(&[
                    &self.name,
                    "inet6",
                    &self.addr_v6.to_string(),
                    "prefixlen",
                    "128",
                    "alias",
                ])
                .status()
                .expect("failed to assign ipv6 to tunnel");

            // Start the tunnel
            Command::new("ifconfig")
                .args(&[&self.name, "up"])
                .status()
                .expect("failed to start the tunnel");

            self.started = true;

            // Add each peer to the routing table
            for p in &self.peers {
                for r in &p.allowed_ips {
                    let inet_flag = match r.ip {
                        IpAddr::V4(_) => "-inet",
                        IpAddr::V6(_) => "-inet6",
                    };

                    Command::new("route")
                        .args(&[
                            "-q",
                            "-n",
                            "add",
                            inet_flag,
                            &format!("{}/{}", r.ip, r.cidr),
                            "-interface",
                            &self.name,
                        ])
                        .status()
                        .expect("failed to add route");
                }
            }
        }

        #[cfg(target_os = "linux")]
        /// Starts the tunnel
        fn start(&mut self) {
            Command::new("ip")
                .args([
                    "address",
                    "add",
                    &self.addr_v4.to_string(),
                    "dev",
                    &self.name,
                ])
                .status()
                .expect("failed to assign ip to tunnel");

            Command::new("ip")
                .args([
                    "address",
                    "add",
                    &self.addr_v6.to_string(),
                    "dev",
                    &self.name,
                ])
                .status()
                .expect("failed to assign ipv6 to tunnel");

            // Start the tunnel
            Command::new("ip")
                .args(["link", "set", "mtu", "1400", "up", "dev", &self.name])
                .status()
                .expect("failed to start the tunnel");

            self.started = true;

            // Add each peer to the routing table
            for p in &self.peers {
                for r in &p.allowed_ips {
                    Command::new("ip")
                        .args([
                            "route",
                            "add",
                            &format!("{}/{}", r.ip, r.cidr),
                            "dev",
                            &self.name,
                        ])
                        .status()
                        .expect("failed to add route");
                }
            }
        }

        /// Issue a get command on the interface
        fn wg_get(&self) -> String {
            let path = format!("/var/run/wireguard/{}.sock", self.name);

            let mut socket = UnixStream::connect(path).unwrap();
            write!(socket, "get=1\n\n").unwrap();

            let mut ret = String::new();
            socket.read_to_string(&mut ret).unwrap();
            ret
        }

        /// Issue a set command on the interface
        fn wg_set(&self, setting: &str) -> String {
            let path = format!("/var/run/wireguard/{}.sock", self.name);
            let mut socket = UnixStream::connect(path).unwrap();
            write!(socket, "set=1\n{}\n\n", setting).unwrap();

            let mut ret = String::new();
            socket.read_to_string(&mut ret).unwrap();
            ret
        }

        /// Assign a listen_port to the interface
        fn wg_set_port(&self, port: u16) -> String {
            self.wg_set(&format!("listen_port={}", port))
        }

        /// Assign a private_key to the interface
        fn wg_set_key(&self, key: StaticSecret) -> String {
            self.wg_set(&format!("private_key={}", encode(key.to_bytes())))
        }

        /// Arm this device's event queue so the next `EPOLL_CTL_ADD` fails.
        ///
        /// Linux-only: the hook lives on `epoll.rs`'s `EventPoll`, and the
        /// module gate above excludes only macOS -- iOS and tvOS also reach
        /// here and select `kqueue.rs`, which has no such hook.
        #[cfg(target_os = "linux")]
        fn fail_next_event_registration(&self) {
            self._device.device.read().queue.fail_next_registration();
        }

        /// As above but sticky: a process out of watches stays out.
        #[cfg(target_os = "linux")]
        fn fail_all_event_registrations(&self) {
            self._device.device.read().queue.fail_all_registrations();
        }

        /// How many `EPOLL_CTL_ADD` calls this device has attempted.
        #[cfg(target_os = "linux")]
        fn event_registration_attempts(&self) -> usize {
            self._device.device.read().queue.registration_attempts()
        }

        /// Block until this device has attempted at least `n` more
        /// `EPOLL_CTL_ADD`s than `before`, or `timeout` elapses. Returns what
        /// was actually observed, so the caller still asserts on it -- waiting
        /// must never be able to stand in for the assertion.
        ///
        /// This is the synchronisation the connected-socket tests need. The
        /// handshake response is written to the socket in the UDP handler
        /// *before* the connected-socket block runs, so the client can be
        /// holding the response while the worker has not yet reached the
        /// registration. A fixed delay is a bet on the scheduler, and it is a
        /// bet that loses: measured at 24 of 40 runs when the worker is starved.
        #[cfg(target_os = "linux")]
        fn wait_for_event_registrations(
            &self,
            before: usize,
            n: usize,
            timeout: Duration,
        ) -> usize {
            let deadline = Instant::now() + timeout;
            loop {
                let seen = self.event_registration_attempts() - before;
                if seen >= n || Instant::now() >= deadline {
                    return seen;
                }
                // Sleeps rather than spins: the worker this waits on may be
                // waiting for a core, and burning one here is exactly wrong
                // under the load that makes the race visible.
                thread::sleep(Duration::from_millis(1));
            }
        }

        /// Assign a peer to the interface (with public_key, endpoint and a series of nallowed_ip)
        fn wg_set_peer(
            &self,
            key: &PublicKey,
            ep: &SocketAddr,
            allowed_ips: &[AllowedIp],
        ) -> String {
            let mut req = format!("public_key={}\nendpoint={}", encode(key.as_bytes()), ep);
            for AllowedIp { ip, cidr } in allowed_ips {
                let _ = write!(req, "\nallowed_ip={}/{}", ip, cidr);
            }

            self.wg_set(&req)
        }

        /// Add a new known peer
        fn add_peer(&mut self, peer: Arc<Peer>) {
            self.wg_set_peer(
                &PublicKey::from(&peer.key),
                &peer.endpoint,
                &peer.allowed_ips,
            );
            self.peers.push(peer);
        }
    }

    /// Create a new filename in the /tmp dir
    fn temp_path() -> String {
        let mut path = String::from("/tmp/");
        let mut buf = [0u8; 32];
        SystemRandom::new().fill(&mut buf[..]).unwrap();
        path.push_str(&encode(buf));
        path
    }

    #[test]
    #[ignore]
    /// Test if wireguard starts and creates a unix socket that we can read from
    fn test_wireguard_get() {
        let wg = WGHandle::init("192.0.2.0".parse().unwrap(), "::2".parse().unwrap());
        let response = wg.wg_get();
        assert!(response.ends_with("errno=0\n\n"));
    }

    #[test]
    #[ignore]
    /// Test if wireguard starts and creates a unix socket that we can use to set settings
    fn test_wireguard_set() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let own_public_key = PublicKey::from(&private_key);

        let wg = WGHandle::init("192.0.2.0".parse().unwrap(), "::2".parse().unwrap());
        assert!(wg.wg_get().ends_with("errno=0\n\n"));
        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        // Check that the response matches what we expect
        assert_eq!(
            wg.wg_get(),
            format!(
                "own_public_key={}\nlisten_port={}\nerrno=0\n\n",
                encode(own_public_key.as_bytes()),
                port
            )
        );

        let peer_key = StaticSecret::random_from_rng(OsRng);
        let peer_pub_key = PublicKey::from(&peer_key);
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 0, 0, 1)), 50001);
        let allowed_ips = [
            AllowedIp {
                ip: IpAddr::V4(Ipv4Addr::new(172, 0, 0, 2)),
                cidr: 32,
            },
            AllowedIp {
                ip: IpAddr::V6(Ipv6Addr::new(0xf120, 0, 0, 2, 2, 2, 0, 0)),
                cidr: 100,
            },
        ];

        assert_eq!(
            wg.wg_set_peer(&peer_pub_key, &endpoint, &allowed_ips),
            "errno=0\n\n"
        );

        // Check that the response matches what we expect
        assert_eq!(
            wg.wg_get(),
            format!(
                "own_public_key={}\n\
                 listen_port={}\n\
                 public_key={}\n\
                 endpoint={}\n\
                 allowed_ip={}/{}\n\
                 allowed_ip={}/{}\n\
                 rx_bytes=0\n\
                 tx_bytes=0\n\
                 errno=0\n\n",
                encode(own_public_key.as_bytes()),
                port,
                encode(peer_pub_key.as_bytes()),
                endpoint,
                allowed_ips[0].ip,
                allowed_ips[0].cidr,
                allowed_ips[1].ip,
                allowed_ips[1].cidr
            )
        );
    }

    #[test]
    #[ignore]
    /// `update_only` must not create a peer that does not already exist.
    ///
    /// `Device::update_peer` has no existence check of its own, so a section
    /// carrying `update_only=true` for an unknown key would otherwise create the
    /// peer and install its allowed-IPs -- letting a stale block from a
    /// management plane resurrect a peer that was deliberately revoked, and
    /// reporting success while doing it. amneziawg-go/wireguard-go discard the
    /// whole section instead, which is what this pins.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`; CI runs it via
    /// `cargo test -- --ignored`.
    fn test_update_only_does_not_create_a_missing_peer() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);

        let wg = WGHandle::init("192.0.2.0".parse().unwrap(), "::2".parse().unwrap());
        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        let peer_key = StaticSecret::random_from_rng(OsRng);
        let peer_pub_key = PublicKey::from(&peer_key);
        let peer_hex = encode(peer_pub_key.as_bytes());

        // The peer does not exist, so the whole section is discarded -- and the
        // transaction still succeeds, which is the point of tolerating the key
        // rather than returning EINVAL.
        assert_eq!(
            wg.wg_set(&format!(
                "public_key={}\nupdate_only=true\nendpoint=172.0.0.1:50001\nallowed_ip=172.0.0.2/32",
                peer_hex
            )),
            "errno=0\n\n"
        );
        assert!(
            !wg.wg_get().contains(&peer_hex),
            "update_only must not create a peer that does not exist"
        );

        // Once the peer does exist, the same section applies normally.
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 0, 0, 1)), 50001);
        assert_eq!(wg.wg_set_peer(&peer_pub_key, &endpoint, &[]), "errno=0\n\n");
        assert_eq!(
            wg.wg_set(&format!(
                "public_key={}\nupdate_only=true\nendpoint=172.0.0.1:50002",
                peer_hex
            )),
            "errno=0\n\n"
        );
        let response = wg.wg_get();
        assert!(response.contains(&peer_hex), "the peer must still be there");
        assert!(
            response.contains("endpoint=172.0.0.1:50002"),
            "update_only must still update an existing peer, got {}",
            response
        );
    }

    /// Test if wireguard can handle simple ipv4 connections, don't use a connected socket
    #[test]
    #[ignore]
    fn test_wg_start_ipv4_non_connected() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init_with_config(
            addr_v4,
            addr_v6,
            DeviceConfig {
                n_threads: 2,
                use_connected_socket: false,
                #[cfg(target_os = "linux")]
                use_multi_queue: true,
                #[cfg(target_os = "linux")]
                uapi_fd: -1,
                // As above: defaults for everything AmneziaWG and probe-reply.
                ..Default::default()
            },
        );

        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        // Create a new peer whose endpoint is on this machine
        let mut peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), next_port()),
            vec![AllowedIp {
                ip: next_ip(),
                cidr: 32,
            }],
        );

        peer.start_in_container(&public_key, &addr_v4, port);

        let peer = Arc::new(peer);

        wg.add_peer(Arc::clone(&peer));
        wg.start();

        let response = peer.get_request();

        assert_eq!(response, encode(PublicKey::from(&peer.key).as_bytes()));
    }

    /// Test if wireguard can handle simple ipv4 connections
    #[test]
    #[ignore]
    fn test_wg_start_ipv4() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6);

        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        // Create a new peer whose endpoint is on this machine
        let mut peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), next_port()),
            vec![AllowedIp {
                ip: next_ip(),
                cidr: 32,
            }],
        );

        peer.start_in_container(&public_key, &addr_v4, port);

        let peer = Arc::new(peer);

        wg.add_peer(Arc::clone(&peer));
        wg.start();

        let response = peer.get_request();

        assert_eq!(response, encode(PublicKey::from(&peer.key).as_bytes()));
    }

    #[test]
    #[ignore]
    /// Test if wireguard can handle simple ipv6 connections
    fn test_wg_start_ipv6() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6);

        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        let mut peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), next_port()),
            vec![AllowedIp {
                ip: next_ip_v6(),
                cidr: 128,
            }],
        );

        peer.start_in_container(&public_key, &addr_v6, port);

        let peer = Arc::new(peer);

        wg.add_peer(Arc::clone(&peer));
        wg.start();

        let response = peer.get_request();

        assert_eq!(response, encode(PublicKey::from(&peer.key).as_bytes()));
    }

    /// Test if wireguard can handle connection with an ipv6 endpoint
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")] // Can't make docker work with ipv6 on macOS ATM
    fn test_wg_start_ipv6_endpoint() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6);

        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        let mut peer = Peer::new(
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                next_port(),
            ),
            vec![AllowedIp {
                ip: next_ip_v6(),
                cidr: 128,
            }],
        );

        peer.start_in_container(&public_key, &addr_v6, port);

        let peer = Arc::new(peer);

        wg.add_peer(Arc::clone(&peer));
        wg.start();

        let response = peer.get_request();

        assert_eq!(response, encode(PublicKey::from(&peer.key).as_bytes()));
    }

    /// Test if wireguard can handle connection with an ipv6 endpoint
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")] // Can't make docker work with ipv6 on macOS ATM
    fn test_wg_start_ipv6_endpoint_not_connected() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init_with_config(
            addr_v4,
            addr_v6,
            DeviceConfig {
                n_threads: 2,
                use_connected_socket: false,
                #[cfg(target_os = "linux")]
                use_multi_queue: true,
                #[cfg(target_os = "linux")]
                uapi_fd: -1,
                // As above: defaults for everything AmneziaWG and probe-reply.
                ..Default::default()
            },
        );

        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        let mut peer = Peer::new(
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                next_port(),
            ),
            vec![AllowedIp {
                ip: next_ip_v6(),
                cidr: 128,
            }],
        );

        peer.start_in_container(&public_key, &addr_v6, port);

        let peer = Arc::new(peer);

        wg.add_peer(Arc::clone(&peer));
        wg.start();

        let response = peer.get_request();

        assert_eq!(response, encode(PublicKey::from(&peer.key).as_bytes()));
    }

    /// Test many concurrent connections
    #[test]
    #[ignore]
    fn test_wg_concurrent() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6);

        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        for _ in 0..5 {
            // Create a new peer whose endpoint is on this machine
            let mut peer = Peer::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), next_port()),
                vec![AllowedIp {
                    ip: next_ip(),
                    cidr: 32,
                }],
            );

            peer.start_in_container(&public_key, &addr_v4, port);

            let peer = Arc::new(peer);

            wg.add_peer(Arc::clone(&peer));
        }

        wg.start();

        let mut threads = vec![];

        for p in wg.peers {
            let pub_key = PublicKey::from(&p.key);
            threads.push(thread::spawn(move || {
                for _ in 0..100 {
                    let response = p.get_request();
                    assert_eq!(response, encode(pub_key.as_bytes()));
                }
            }));
        }

        for t in threads {
            t.join().unwrap();
        }
    }

    /// Test many concurrent connections
    #[test]
    #[ignore]
    fn test_wg_concurrent_v6() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6);

        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        for _ in 0..5 {
            // Create a new peer whose endpoint is on this machine
            let mut peer = Peer::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), next_port()),
                vec![AllowedIp {
                    ip: next_ip_v6(),
                    cidr: 128,
                }],
            );

            peer.start_in_container(&public_key, &addr_v6, port);

            let peer = Arc::new(peer);

            wg.add_peer(Arc::clone(&peer));
        }

        wg.start();

        let mut threads = vec![];

        for p in wg.peers {
            let pub_key = PublicKey::from(&p.key);
            threads.push(thread::spawn(move || {
                for _ in 0..100 {
                    let response = p.get_request();
                    assert_eq!(response, encode(pub_key.as_bytes()));
                }
            }));
        }

        for t in threads {
            t.join().unwrap();
        }
    }

    /// A refused connected-socket registration must return the peer to the
    /// shared listening socket, in *both* directions.
    ///
    /// `connect_endpoint` has already stored a `dup(2)` of the connected socket
    /// in `endpoint.conn` by the time `register_conn_handler` runs, and the
    /// kernel gives a connected UDP socket priority over the wildcard listener
    /// for datagrams from that 4-tuple. So if registration fails and `conn` is
    /// left in place, the peer's next datagram is taken off the listener by a
    /// socket no handler reads: a blackhole, not a fallback. The direction that
    /// dies is inbound, not outbound -- the surviving dup still sends.
    ///
    /// Asserts the observable consequence rather than `endpoint.conn.is_none()`,
    /// so it cannot be satisfied by a rollback that clears the field while
    /// leaving the socket in service.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`; CI runs it with
    /// `cargo test -- --ignored`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_refused_connected_socket_registration_returns_the_peer_to_the_shared_socket() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);

        // Single-queue, unlike `WGHandle::init`: with `use_multi_queue`, worker
        // thread 1 registers a second TUN handler *asynchronously* from
        // `event_loop`, and that is the one EPOLL_CTL_ADD that could land inside
        // the window this test subtracts over.
        let wg = WGHandle::init_with_config(
            next_ip(),
            next_ip_v6(),
            DeviceConfig {
                n_threads: 2,
                use_connected_socket: true,
                use_multi_queue: false,
                uapi_fd: -1,
                ..Default::default()
            },
        );
        assert_eq!(
            wg.wg_set_port(port),
            "errno=0

"
        );
        assert_eq!(
            wg.wg_set_key(private_key),
            "errno=0

"
        );

        // No endpoint configured: it is learned from the datagram, which is what
        // takes the device down the `connect_endpoint` path.
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let peer_public = PublicKey::from(&peer_secret);
        assert_eq!(
            wg.wg_set(&format!(
                "public_key={}
allowed_ip=10.66.66.2/32",
                encode(peer_public.as_bytes())
            )),
            "errno=0

"
        );

        let mut client = Tunn::new_with_obfuscation(
            peer_secret,
            public_key,
            None,
            None,
            100,
            None,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let server: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

        let mut buf = vec![0u8; 2048];
        let mut rx = vec![0u8; 2048];

        // Armed after every other registration has happened -- the API socket,
        // the timers, the notifiers and both listeners are already in -- so the
        // next EPOLL_CTL_ADD is the connected socket for this peer.
        let before = wg.event_registration_attempts();
        wg.fail_next_event_registration();

        let init = match client.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(d) => d.to_vec(),
            other => panic!("expected an initiation, got {:?}", other),
        };
        sock.send_to(&init, server).unwrap();
        // The response is written before the connected-socket block, so it
        // arrives whether or not the rollback runs. This only establishes that
        // the device authenticated the peer and therefore reached that block.
        let (n, _) = sock
            .recv_from(&mut rx)
            .expect("the device must answer the first initiation");
        assert!(
            matches!(
                Tunn::parse_incoming_packet(Default::default(), &rx[..n]),
                Ok(Packet::HandshakeResponse(_))
            ),
            "expected a handshake response to the first initiation"
        );

        // Waits for the upgrade attempt, not for an interval. The response is
        // written strictly before the connected-socket block, so an elapsed-time
        // bound only decides how often the worker loses the race, never whether
        // it can. The assertion below is unchanged and still reads the counter
        // itself: at 0 this times out and fails, and a second attempt that has
        // already landed is still seen.
        wg.wait_for_event_registrations(before, 1, Duration::from_secs(5));

        // This pins that the armed one-shot was actually consumed -- without
        // it, a device that never attempts the upgrade satisfies this whole
        // test, because the second initiation is then answered by the shared
        // listener for the trivial reason that no connected socket ever existed.
        assert_eq!(
            wg.event_registration_attempts() - before,
            1,
            "the device attempted no connected-socket upgrade, so the refused \
             registration this test exercises never happened"
        );

        // Retried until a deadline, not sent once. The counter above ticks at
        // the top of `register_event`, but the rollback runs after it returns,
        // so a single shot can still land on the rejected socket in the window
        // between the two -- and such a datagram is silently swallowed, which is
        // indistinguishable from the bug this test exists for.
        //
        // Retrying does not weaken the assertion. `conn` is cleared only by the
        // rollback, by a roam, or by connection expiry (~3 min), none of which
        // this loop reaches: delete the rollback and `conn` stays in place for
        // the life of the endpoint, so every retry is swallowed, the deadline is
        // hit, and the test fails exactly as before.
        //
        // `force_resend`, because `format_handshake_initiation` returns `Done`
        // while a handshake is already in progress. Each call restamps, and
        // `Tai64N` is nanosecond-resolution, so successive initiations are
        // strictly increasing without help from a sleep -- which is what the
        // fixed delay this replaced was also claimed to be for.
        sock.set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let n2 = loop {
            let init2 = match client.format_handshake_initiation(&mut buf, true) {
                TunnResult::WriteToNetwork(d) => d.to_vec(),
                other => panic!("expected a second initiation, got {:?}", other),
            };
            sock.send_to(&init2, server).unwrap();
            match sock.recv_from(&mut rx) {
                Ok((n2, _)) => break n2,
                Err(e) => assert!(
                    Instant::now() < deadline,
                    "the device never saw the second initiation: the rejected \
                     connected socket is still taking the peer's datagrams off \
                     the shared listener ({:?})",
                    e
                ),
            }
        };
        assert!(
            matches!(
                Tunn::parse_incoming_packet(Default::default(), &rx[..n2]),
                Ok(Packet::HandshakeResponse(_))
            ),
            "expected a handshake response to the second initiation"
        );
    }

    /// A peer whose connected-socket upgrade cannot succeed must not retry it
    /// on every datagram.
    ///
    /// `register_conn_handler` failing rolls `endpoint.conn` back to `None`, so
    /// `connect_endpoint` stops short-circuiting and the next authenticated
    /// datagram redoes the whole socket/bind/connect/dup/epoll_ctl sequence.
    /// While this UID is out of `max_user_watches` that cannot succeed, so
    /// the retry is pure cost -- and worse than cost: each attempt binds a
    /// socket to the listen port and connects it to the peer's 4-tuple, which
    /// the kernel prefers over the wildcard listener, so datagrams arriving
    /// inside the window are delivered to a socket with no reader.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_peer_whose_upgrade_cannot_succeed_does_not_retry_it_per_datagram() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);

        // Single-queue, unlike `WGHandle::init`: with `use_multi_queue`, worker
        // thread 1 registers a second TUN handler *asynchronously* from
        // `event_loop`, and that is the one EPOLL_CTL_ADD that could land inside
        // the window this test subtracts over.
        let wg = WGHandle::init_with_config(
            next_ip(),
            next_ip_v6(),
            DeviceConfig {
                n_threads: 2,
                use_connected_socket: true,
                use_multi_queue: false,
                uapi_fd: -1,
                ..Default::default()
            },
        );
        assert_eq!(
            wg.wg_set_port(port),
            "errno=0

"
        );
        assert_eq!(
            wg.wg_set_key(private_key),
            "errno=0

"
        );

        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let peer_public = PublicKey::from(&peer_secret);
        assert_eq!(
            wg.wg_set(&format!(
                "public_key={}
allowed_ip=10.66.66.2/32",
                encode(peer_public.as_bytes())
            )),
            "errno=0

"
        );

        let mut client = Tunn::new_with_obfuscation(
            peer_secret,
            public_key,
            None,
            None,
            100,
            None,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let server: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

        let mut buf = vec![0u8; 2048];
        let mut rx = vec![0u8; 2048];

        // Out of watches from here on, which is the state the gate exists for.
        wg.fail_all_event_registrations();
        let before = wg.event_registration_attempts();

        // Every one of these is authenticated, so every one reaches the
        // connected-socket block.
        let datagrams = 52;
        for i in 0..datagrams {
            let init = match client.format_handshake_initiation(&mut buf, true) {
                TunnResult::WriteToNetwork(d) => d.to_vec(),
                other => panic!("expected an initiation, got {:?}", other),
            };
            sock.send_to(&init, server).unwrap();
            let (n, _) = sock
                .recv_from(&mut rx)
                .unwrap_or_else(|e| panic!("no response to initiation {}: {:?}", i, e));
            assert!(
                matches!(
                    Tunn::parse_incoming_packet(Default::default(), &rx[..n]),
                    Ok(Packet::HandshakeResponse(_))
                ),
                "expected a handshake response to initiation {}",
                i
            );
            thread::sleep(Duration::from_millis(20));
        }

        let attempts = wg.event_registration_attempts() - before;
        // Exactly one, not "at most one": zero would mean the upgrade was never
        // attempted at all, which every one of these mutations produces --
        // `use_connected_socket` forced off, the gate initialised true, the
        // whole block deleted -- and each of those would have satisfied a
        // `<= 1` bound while proving nothing.
        assert_eq!(
            attempts, 1,
            "{} authenticated datagrams drove {} EPOLL_CTL_ADD attempts; a \
             failed upgrade must be attempted exactly once -- 0 means it was \
             never attempted, more than 1 means it was retried per datagram",
            datagrams, attempts
        );
    }

    /// DisableCookies through the real control path, both ways.
    ///
    /// Every change here is a `set=1` on the live UAPI socket: `api_set` ->
    /// `AwgParams::apply` -> `Device::set_obfuscation`, which writes the
    /// interface's copy -- the one the anonymous ingress reads -- and pushes to
    /// every peer's tunnel; peers added later are built from the interface's
    /// copy by `update_peer`. Nothing is patched by hand. The only fixture
    /// reach-in is the overload: the device's rate limiter is replaced with a
    /// zero-budget one, so it is under load from the first counted message
    /// without any flooding. The policy is read off the wire, not off that
    /// limiter's counter: the device resets the counter every second, so a
    /// sample of it races the reset. Exact load accounting is pinned by the
    /// deterministic tests in `noise::disable_cookies_tests`.
    ///
    /// Off -> on, with peer A's first payload queued behind its pre-handshake
    /// burst: the interface and A carry the new policy at once, A's burst
    /// survives, A's remaining junk and initiation reach A over UDP, the
    /// starved ingress takes A's response without sending a cookie, and the
    /// queued payload arrives exactly once. A peer B added afterwards inherits
    /// the policy: under load its initiation is answered with a response,
    /// which B takes, not a cookie.
    ///
    /// On -> off, with peer C's burst pending: every copy carries the old
    /// policy again, C's burst survives and still reaches C with its
    /// initiation, A's endpoint, window, session and RandomTrailers setting are
    /// untouched, and B's next initiation is met with a cookie reply, which B
    /// stores, not a response.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn disable_cookies_propagates_through_the_uapi_to_the_ingress_and_every_peer() {
        use crate::device::peer::Peer;
        use crate::noise::amnezia::AmneziaConfig;
        use crate::noise::handshake::ObfuscationRanges;
        use crate::noise::rate_limiter::RateLimiter;
        use parking_lot::Mutex;

        const OK: &str = "errno=0\n\n";
        // Every kind at its own size, and no RandomTrailers, so a reply's
        // length names it: a response is S2 + 92, a cookie reply S3 + 64.
        const S: [u16; 4] = [40, 24, 32, 160];
        const RESPONSE: usize = 24 + 92;
        const COOKIE: usize = 32 + 64;
        // A burst long enough to toggle inside: six junk datagrams, one per
        // 250 ms timer tick.
        let framing = AmneziaConfig::new(S[0], S[1], S[2], S[3]);
        let amnezia = framing.clone().with_pre_handshake_junk(6, 64, 64, 200);

        let port = next_port();
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);
        let wg = WGHandle::init_with_config(
            next_ip(),
            next_ip_v6(),
            DeviceConfig {
                n_threads: 2,
                use_connected_socket: false,
                use_multi_queue: false,
                uapi_fd: -1,
                amnezia: amnezia.clone(),
                ..Default::default()
            },
        );
        assert_eq!(wg.wg_set_port(port), OK);
        assert_eq!(wg.wg_set_key(server_secret), OK);
        assert_eq!(wg.wg_set("disable_cookies=0"), OK);
        let server: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

        // The deterministic overload: a zero budget is under load from the
        // first message it counts, whatever the once-a-second reset does.
        {
            let mut guard = wg._device.device.read();
            guard.try_writeable(
                |d| d.trigger_yield(),
                |d| {
                    d.cancel_yield();
                    d.rate_limiter = Some(Arc::new(RateLimiter::new(&server_public, 0)));
                },
            );
        }
        struct Client {
            sock: UdpSocket,
            tunn: Tunn,
            public: PublicKey,
        }
        let add_client = |index: u32, allowed_ip: &str| -> Client {
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(1500)))
                .unwrap();
            assert_eq!(
                wg.wg_set(&format!(
                    "public_key={}\nendpoint={}\nallowed_ip={}",
                    encode(public.as_bytes()),
                    sock.local_addr().unwrap(),
                    allowed_ip
                )),
                OK
            );
            let tunn = Tunn::new_with_obfuscation(
                secret,
                server_public,
                None,
                None,
                index,
                None,
                ObfuscationRanges::default(),
                // The same framing; the burst is the device's alone, so a
                // client's initiation is an initiation.
                framing.clone(),
            )
            .unwrap();
            Client { sock, tunn, public }
        };
        let peer = |c: &Client| -> Arc<Mutex<Peer>> {
            wg._device
                .device
                .read()
                .peers
                .get(&c.public)
                .cloned()
                .unwrap()
        };
        let payload = |tag: u8| {
            let mut p = vec![0u8; 60];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&60u16.to_be_bytes());
            p[8] = 64;
            p[9] = 17;
            p[12..16].copy_from_slice(&[10, 66, 66, 1]);
            p[16..20].copy_from_slice(&[10, 66, 66, 2]);
            p[20] = tag;
            p
        };
        // Queue a first payload on a device peer with no session: it starts the
        // peer's pre-handshake burst, whose first junk comes back here (the
        // device's timer sends the rest to the peer's endpoint).
        let queue_first_payload = |c: &Client, p: &[u8]| {
            let mut buf = vec![0u8; 2048];
            match peer(c).lock().tunnel.encapsulate(p, &mut buf) {
                TunnResult::WriteToNetwork(d) => assert_eq!(d.len(), 64, "the burst's first junk"),
                other => panic!("expected the burst to start, got {:?}", other),
            }
            assert!(peer(c).lock().tunnel.has_pending_burst());
        };
        let everywhere = |clients: &[&Client], want: bool| {
            assert_eq!(
                wg._device.device.read().config.amnezia.disable_cookies,
                want,
                "the interface's copy"
            );
            for c in clients {
                assert_eq!(
                    peer(c).lock().tunnel.amnezia_config().disable_cookies,
                    want,
                    "a peer's copy"
                );
            }
        };
        // What arrives at `c` until its client reads a handshake initiation:
        // the junk count, and the client's answer to the initiation.
        let until_initiation = |c: &mut Client| -> (usize, Vec<u8>) {
            let mut junk = 0;
            let mut rx = vec![0u8; 2048];
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, _) = c
                    .sock
                    .recv_from(&mut rx)
                    .unwrap_or_else(|e| panic!("the burst stalled after {} junk: {:?}", junk, e));
                match c.tunn.decapsulate(Some(server.ip()), &rx[..n], &mut buf) {
                    TunnResult::WriteToNetwork(response) => return (junk, response.to_vec()),
                    _ => junk += 1,
                }
            }
        };

        // --- off -> on, with a burst pending ------------------------------------
        let mut a = add_client(0x10, "10.66.66.2/32");
        everywhere(&[&a], false);
        let first = payload(1);
        queue_first_payload(&a, &first);

        assert_eq!(wg.wg_set("disable_cookies=1"), OK);
        everywhere(&[&a], true);
        assert!(
            peer(&a).lock().tunnel.has_pending_burst(),
            "the DisableCookies change cancelled the pending burst"
        );

        let (junk, response) = until_initiation(&mut a);
        assert!(junk >= 1, "the rest of the burst went out");
        // The starved ingress lets the response in -- cookies off -- and the
        // device then sends the payload it had queued.
        a.sock.send_to(&response, server).unwrap();
        let mut rx = vec![0u8; 2048];
        let mut buf = vec![0u8; 2048];
        let mut delivered = 0;
        while let Ok((n, _)) = a.sock.recv_from(&mut rx) {
            assert_ne!(n, COOKIE, "A's response drew a cookie reply");
            if let TunnResult::WriteToTunnelV4(p, _) =
                a.tunn.decapsulate(Some(server.ip()), &rx[..n], &mut buf)
            {
                assert_eq!(p, &first[..]);
                delivered += 1;
            }
        }
        assert_eq!(delivered, 1, "the first payload, exactly once");

        // A peer added now is built from the interface's copy.
        let mut b = add_client(0x20, "10.66.66.3/32");
        everywhere(&[&a, &b], true);
        let init = match b.tunn.format_handshake_initiation(&mut buf, true) {
            TunnResult::WriteToNetwork(d) => d.to_vec(),
            other => panic!("{:?}", other),
        };
        b.sock.send_to(&init, server).unwrap();
        let (n, _) = b.sock.recv_from(&mut rx).expect("no reply to B");
        assert_eq!(n, RESPONSE, "B is answered under load with cookies off");
        // ...and it is a response: B takes it and the handshake completes.
        assert!(
            matches!(
                b.tunn.decapsulate(Some(server.ip()), &rx[..n], &mut buf),
                TunnResult::WriteToNetwork(_)
            ),
            "B did not take the reply as a response"
        );
        assert!(b.tunn.time_since_last_handshake().is_some());

        // --- on -> off, with another burst pending ------------------------------
        let mut c = add_client(0x30, "10.66.66.4/32");
        everywhere(&[&a, &b, &c], true);
        queue_first_payload(&c, &payload(3));
        let before = {
            let p = peer(&a);
            let p = p.lock();
            let addr = p.endpoint().addr;
            let snapshot = (
                addr,
                p.tunnel.udp_window(),
                p.tunnel.time_since_last_handshake().is_some(),
                p.tunnel.amnezia_config().random_trailers,
            );
            snapshot
        };

        assert_eq!(wg.wg_set("disable_cookies=0"), OK);
        everywhere(&[&a, &b, &c], false);
        assert!(
            peer(&c).lock().tunnel.has_pending_burst(),
            "the DisableCookies change cancelled the pending burst"
        );
        let after = {
            let p = peer(&a);
            let p = p.lock();
            let addr = p.endpoint().addr;
            let snapshot = (
                addr,
                p.tunnel.udp_window(),
                p.tunnel.time_since_last_handshake().is_some(),
                p.tunnel.amnezia_config().random_trailers,
            );
            snapshot
        };
        assert_eq!(before, after, "A's endpoint, window, session and RT");
        assert!(after.2, "A's session survived");
        // ...and still carries traffic.
        let wire = match peer(&a).lock().tunnel.encapsulate(&payload(2), &mut buf) {
            TunnResult::WriteToNetwork(d) => d.to_vec(),
            other => panic!("{:?}", other),
        };
        assert!(matches!(
            a.tunn.decapsulate(Some(server.ip()), &wire, &mut rx),
            TunnResult::WriteToTunnelV4(..)
        ));

        // Cookies armed again under the same load: B's next initiation earns a
        // cookie reply.
        thread::sleep(Duration::from_millis(20));
        let init = match b.tunn.format_handshake_initiation(&mut buf, true) {
            TunnResult::WriteToNetwork(d) => d.to_vec(),
            other => panic!("{:?}", other),
        };
        b.sock.send_to(&init, server).unwrap();
        let (n, _) = b.sock.recv_from(&mut rx).expect("no reply to B");
        assert_eq!(n, COOKIE, "B is sent a cookie now cookies are armed");
        // ...and it is a cookie reply: B stores it and answers nothing.
        assert!(
            matches!(
                b.tunn.decapsulate(Some(server.ip()), &rx[..n], &mut buf),
                TunnResult::Done
            ),
            "B did not take the reply as a cookie"
        );

        // C's burst went on to its initiation.
        let (junk, _) = until_initiation(&mut c);
        assert!(junk >= 1, "the rest of C's burst went out");
    }

    /// An amplification-prone AmneziaWG profile loads through the real UAPI
    /// with cookies on, and the device's ingress still never sends a cookie
    /// reply larger than the datagram that provoked it.
    ///
    /// The profile is the stock amneziawg-install one the live Raspberry Pi
    /// run was handed -- S1 = 136, S2 = 59, S3 = 149, S4 = 16, the installer's
    /// H1-H4 ranges, header protection, RandomTrailers on, DisableCookies off.
    /// Its cookie reply is 213 bytes before any trailer, against a 284-byte
    /// minimum initiation and a 151-byte minimum response. `set=1` used to
    /// refuse it with EINVAL; now it loads with a warning, which makes the
    /// runtime guard (`reply_policy::cookie_verdict` plus the post-framing
    /// check) the only thing between it and a reflector. So, through the real
    /// control path and the real anonymous ingress:
    ///
    /// * the profile loads (`errno=0`) and `get=1` reports it; a universally
    ///   invalid S3 still fails with `errno=22` and changes nothing;
    /// * DisableCookies on -> off over it succeeds, changes only that field on
    ///   the interface and on an existing peer, and keeps that peer's pending
    ///   first-handshake burst (the Keep rule for a DisableCookies-only change);
    /// * under a zero-budget limiter, a **forged minimum response** -- built
    ///   from nothing but the device's *public* key, exactly as an attacker
    ///   would -- draws **no reply**, because 213 > 151;
    /// * the same forgery against S3 = 87 draws a reply of exactly 151 bytes:
    ///   the control that proves the forgery reaches the cookie gate, and that
    ///   parity is sent (the bound is strict) with zero trailer room;
    /// * a **minimum initiation** (284 bytes) draws a cookie reply that the
    ///   client authenticates, never larger than 284 whatever trailer the draw
    ///   takes from the 71 bytes of room: the flood defence works for the
    ///   stock profile.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn an_amplification_prone_profile_loads_and_its_cookie_replies_never_amplify() {
        use crate::noise::amnezia::AmneziaConfig;
        use crate::noise::handshake::{b2s_hash, b2s_keyed_mac_16, ObfuscationRanges, LABEL_MAC1};
        use crate::noise::rate_limiter::RateLimiter;

        const OK: &str = "errno=0\n\n";
        const EINVAL: &str = "errno=22\n\n";
        const S: [u16; 4] = [136, 59, 149, 16];
        const H: [(u32, u32); 4] = [
            (21806348, 121806347),
            (880390969, 980390968),
            (1131164401, 1231164400),
            (1662290386, 1762290385),
        ];
        const HP: [u8; 32] = [0x42; 32];
        const INIT: usize = 148 + 136;
        const RESP: usize = 92 + 59;
        const COOKIE: usize = 64 + 149;
        let stock_block = format!(
            "jc=4\njmin=50\njmax=1000\ns1={}\ns2={}\ns3={}\ns4={}\n\
             h1={}-{}\nh2={}-{}\nh3={}-{}\nh4={}-{}\n\
             header_protection_key={}\ncontent_padding_addition=10-100\n\
             random_trailers=true\ndisable_cookies=false",
            S[0],
            S[1],
            S[2],
            S[3],
            H[0].0,
            H[0].1,
            H[1].0,
            H[1].1,
            H[2].0,
            H[2].1,
            H[3].0,
            H[3].1,
            encode(HP)
        );
        let obf = ObfuscationRanges::new(
            H[0].0, H[0].1, H[1].0, H[1].1, H[2].0, H[2].1, H[3].0, H[3].1,
        )
        .unwrap();
        // What a client of this server is framed with; RandomTrailers off so
        // each provoking message is exactly its minimum size.
        let framing = AmneziaConfig::new(S[0], S[1], S[2], S[3]).with_header_protection(HP);

        let port = next_port();
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);
        let wg = WGHandle::init_with_config(
            next_ip(),
            next_ip_v6(),
            DeviceConfig {
                n_threads: 2,
                use_connected_socket: false,
                use_multi_queue: false,
                uapi_fd: -1,
                ..Default::default()
            },
        );
        assert_eq!(wg.wg_set_port(port), OK);
        assert_eq!(wg.wg_set_key(server_secret), OK);
        let server: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let interface = || wg._device.device.read().config.amnezia.clone();

        // --- the stock profile loads through the real UAPI, cookies on --------
        assert_eq!(
            wg.wg_set(&stock_block),
            OK,
            "the stock installer profile must load with DisableCookies off"
        );
        let get = wg.wg_get();
        for line in [
            "s1=136",
            "s2=59",
            "s3=149",
            "s4=16",
            "h2=880390969-980390968",
            "h3=1131164401-1231164400",
            "random_trailers=1",
        ] {
            assert!(
                get.lines().any(|l| l == line),
                "get=1 must report {}: {}",
                line,
                get
            );
        }
        assert!(
            !get.lines().any(|l| l == "disable_cookies=1"),
            "cookies stay on: {}",
            get
        );
        let installed = interface();
        assert!(!installed.disable_cookies && installed.random_trailers);
        assert!(installed.header_protection_enabled());
        assert!(
            installed.cookie_amplification_complaint().is_some(),
            "loaded, and still diagnosed on the response bound"
        );

        // --- universal invalidity is still refused, and applies nothing -------
        assert_eq!(
            wg.wg_set("s3=65535"),
            EINVAL,
            "an S3 that cannot frame a cookie reply must still fail the transaction"
        );
        assert_eq!(
            interface().cookie_packet_junk_size,
            149,
            "and change nothing"
        );

        // --- DisableCookies on -> off over the profile, with a peer bursting --
        // A longer Jc burst than the stock 4 (one junk per 250 ms tick), so the
        // burst is still pending when the toggle lands and is checked.
        assert_eq!(wg.wg_set("jc=8"), OK);
        assert_eq!(wg.wg_set("disable_cookies=1"), OK);
        let peer_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let peer_public = PublicKey::from(&peer_secret);
        assert_eq!(
            wg.wg_set(&format!(
                "public_key={}\nendpoint={}\nallowed_ip=10.66.66.2/32",
                encode(peer_public.as_bytes()),
                peer_sock.local_addr().unwrap()
            )),
            OK
        );
        let peer = wg
            ._device
            .device
            .read()
            .peers
            .get(&peer_public)
            .cloned()
            .unwrap();
        {
            // A first payload with no session starts the peer's Jc burst.
            let mut p = vec![0u8; 60];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&60u16.to_be_bytes());
            p[8] = 64;
            p[9] = 17;
            p[12..16].copy_from_slice(&[10, 66, 66, 1]);
            p[16..20].copy_from_slice(&[10, 66, 66, 2]);
            let mut buf = vec![0u8; 2048];
            let mut locked = peer.lock();
            assert!(matches!(
                locked.tunnel.encapsulate(&p, &mut buf),
                TunnResult::WriteToNetwork(_)
            ));
            assert!(locked.tunnel.has_pending_burst());
            assert!(locked.tunnel.amnezia_config().disable_cookies);
        }
        let before = interface();
        assert!(before.disable_cookies);

        assert_eq!(
            wg.wg_set("disable_cookies=0"),
            OK,
            "re-enabling cookies over an amplification-prone S3 must succeed"
        );
        let after = interface();
        assert!(!after.disable_cookies, "the interface's copy is back on");
        assert_eq!(
            after,
            before.clone().with_disable_cookies(false),
            "and nothing else on the interface changed"
        );
        {
            let locked = peer.lock();
            assert!(
                !locked.tunnel.amnezia_config().disable_cookies,
                "the existing peer's copy is back on"
            );
            assert_eq!(locked.tunnel.amnezia_config().cookie_packet_junk_size, 149);
            assert!(
                locked.tunnel.has_pending_burst(),
                "a DisableCookies-only change keeps the pending burst"
            );
        }

        // --- the runtime guard, under a deterministic overload ----------------
        {
            let mut guard = wg._device.device.read();
            guard.try_writeable(
                |d| d.trigger_yield(),
                |d| {
                    d.cancel_yield();
                    d.rate_limiter = Some(Arc::new(RateLimiter::new(&server_public, 0)));
                },
            );
        }
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        probe
            .set_read_timeout(Some(Duration::from_millis(1500)))
            .unwrap();
        let mut rx = vec![0u8; 2048];

        // A handshake response forged from the device's public key alone: a
        // tag in H2, random indices and ephemeral, a valid mac1, no mac2. It
        // names no handshake this device has in flight -- it does not need to:
        // the under-load gate sits before any index lookup.
        let forge_response = |amnezia: &AmneziaConfig| -> Vec<u8> {
            let mut buf = vec![0u8; 2048];
            SystemRandom::new().fill(&mut buf[4..60]).unwrap();
            buf[..4].copy_from_slice(&(H[1].0 + 4242).to_le_bytes());
            let mac1_key = b2s_hash(LABEL_MAC1, server_public.as_bytes());
            let mac1 = b2s_keyed_mac_16(&mac1_key, &buf[..60]);
            buf[60..76].copy_from_slice(&mac1);
            amnezia
                .prepend_outbound(obf, &mut buf, 92, &mut OsRng)
                .unwrap()
                .to_vec()
        };

        let forged = forge_response(&framing);
        assert_eq!(forged.len(), RESP, "a minimum-size forged response");
        probe.send_to(&forged, server).unwrap();
        if let Ok((n, _)) = probe.recv_from(&mut rx) {
            panic!(
                "a {}-byte forged response drew a {}-byte reply: the device reflected \
                 an amplified cookie ({} > {})",
                RESP, n, COOKIE, RESP
            );
        }

        // The control: at S3 = 87 the reply is exactly as large as the forged
        // response, so it is sent -- with no trailer, because parity leaves no
        // room. Proves the forgery reaches the cookie gate, and that the bound
        // is strict.
        assert_eq!(wg.wg_set("s3=87"), OK);
        assert!(interface().cookie_amplification_complaint().is_none());
        let parity_framing = AmneziaConfig::new(S[0], S[1], 87, S[3]).with_header_protection(HP);
        let forged = forge_response(&parity_framing);
        assert_eq!(forged.len(), RESP);
        probe.send_to(&forged, server).unwrap();
        let (n, _) = probe
            .recv_from(&mut rx)
            .expect("at parity the forged response must draw its cookie reply");
        assert_eq!(n, RESP, "64 + 87 == 92 + 59, and no trailer room");
        assert!(
            parity_framing
                .clone()
                .with_random_trailers(true)
                .inbound_candidates(obf, &rx[..n])
                .offsets()
                .contains(&87),
            "and it is a cookie reply, framed at S3"
        );
        assert_eq!(wg.wg_set("s3=149"), OK);

        // Minimum initiations: 213 <= 284, so each draws a cookie reply, which
        // may take up to the 71 bytes of room parity leaves and no more.
        for i in 0..8u32 {
            let secret = StaticSecret::random_from_rng(OsRng);
            let mut client = Tunn::new_with_obfuscation(
                secret,
                server_public,
                None,
                None,
                0x100 + i,
                None,
                obf,
                framing.clone(),
            )
            .unwrap();
            let mut buf = vec![0u8; 2048];
            let init = match client.format_handshake_initiation(&mut buf, false) {
                TunnResult::WriteToNetwork(d) => d.to_vec(),
                other => panic!("expected an initiation, got {:?}", other),
            };
            assert_eq!(init.len(), INIT, "a minimum-size initiation");
            probe.send_to(&init, server).unwrap();
            let (n, _) = probe
                .recv_from(&mut rx)
                .unwrap_or_else(|e| panic!("initiation {}: no cookie reply: {:?}", i, e));
            assert!(
                (COOKIE..=INIT).contains(&n),
                "initiation {}: a {}-byte reply to a {}-byte request",
                i,
                n,
                INIT
            );
            // The client runs the full profile to take a reply that may carry
            // a trailer, and authenticates it: Done is the cookie stored, a
            // reply that failed its AEAD would be an error.
            client.set_obfuscation(obf, framing.clone().with_random_trailers(true));
            assert!(
                matches!(
                    client.decapsulate(Some(server.ip()), &rx[..n], &mut buf),
                    TunnResult::Done
                ),
                "initiation {}: the client must accept the cookie reply",
                i
            );
        }
    }
}
