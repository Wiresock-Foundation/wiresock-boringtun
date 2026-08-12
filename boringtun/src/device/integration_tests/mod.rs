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
}
