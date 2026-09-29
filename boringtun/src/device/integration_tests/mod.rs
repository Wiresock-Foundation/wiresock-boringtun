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
    #[cfg(target_os = "linux")]
    use std::os::unix::io::{AsRawFd, RawFd};
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

    /// How `Peer::try_connect` reaches a peer's HTTP server through the tunnel.
    ///
    /// Measured on the suite (10 runs, 10,050 connects): a test's first
    /// connect takes about 5.2 s, as the container's WireGuard misses the
    /// first handshake initiation and the retry comes after REKEY_TIMEOUT
    /// (5 s). Every later one takes milliseconds. The only failures were
    /// single `ConnectionRefused`s, each followed by a success. So an attempt
    /// waits 8 s -- the first connect, with headroom -- and three attempts
    /// cover a refusal twice over, or a container slow enough to miss
    /// several handshakes: a later attempt's SYN is queued until one lands.
    const CONNECT_ATTEMPTS: u32 = 3;
    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
    const CONNECT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);
    /// The most `try_connect` can take, scheduling aside: 24.2 s. A plain
    /// `connect` could take about two minutes per attempt.
    const CONNECT_BUDGET: std::time::Duration = std::time::Duration::from_millis(
        CONNECT_ATTEMPTS as u64 * CONNECT_TIMEOUT.as_millis() as u64
            + (CONNECT_ATTEMPTS as u64 - 1) * CONNECT_RETRY_DELAY.as_millis() as u64,
    );

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
                run(Command::new("docker").args([
                    "stop", // Run docker
                    &name[5..],
                ]))
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

            run(Command::new("docker").args([
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
            ]))
            .expect("Failed to run docker");

            self.container_name = Some(peer_config_file);
        }

        /// Connect to the peer's HTTP server through the tunnel, or return
        /// the last attempt's error once `CONNECT_ATTEMPTS` have failed.
        ///
        /// Every attempt is bounded. A plain `TcpStream::connect` waits out
        /// the kernel's SYN retries when the tunnel is down -- about two
        /// minutes on Linux, per attempt -- so retrying it bounded nothing,
        /// and a dead tunnel looked like a hung suite.
        fn try_connect(&self) -> std::io::Result<std::net::TcpStream> {
            let http_addr = SocketAddr::new(self.allowed_ips[0].ip, 80);
            let mut attempt = 1;
            loop {
                match std::net::TcpStream::connect_timeout(&http_addr, CONNECT_TIMEOUT) {
                    Ok(stream) => return Ok(stream),
                    Err(err) if attempt == CONNECT_ATTEMPTS => return Err(err),
                    Err(err) => println!(
                        "connect to {} failed, attempt {}/{}: {}",
                        http_addr, attempt, CONNECT_ATTEMPTS, err
                    ),
                }
                attempt += 1;
                std::thread::sleep(CONNECT_RETRY_DELAY);
            }
        }

        fn connect(&self) -> std::net::TcpStream {
            self.try_connect().unwrap_or_else(|err| {
                panic!(
                    "failed to connect to {} through the tunnel: {} attempts, {:?} budget; last error: {}",
                    SocketAddr::new(self.allowed_ips[0].ip, 80),
                    CONNECT_ATTEMPTS,
                    CONNECT_BUDGET,
                    err
                )
            })
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
            run(Command::new("ip").args([
                "address",
                "add",
                &self.addr_v4.to_string(),
                "dev",
                &self.name,
            ]))
            .expect("failed to assign ip to tunnel");

            run(Command::new("ip").args([
                "address",
                "add",
                &self.addr_v6.to_string(),
                "dev",
                &self.name,
            ]))
            .expect("failed to assign ipv6 to tunnel");

            // Start the tunnel
            run(Command::new("ip").args(["link", "set", "mtu", "1400", "up", "dev", &self.name]))
                .expect("failed to start the tunnel");

            self.started = true;

            // Add each peer to the routing table
            for p in &self.peers {
                for r in &p.allowed_ips {
                    run(Command::new("ip").args([
                        "route",
                        "add",
                        &format!("{}/{}", r.ip, r.cidr),
                        "dev",
                        &self.name,
                    ]))
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

        /// As `fail_next_event_registration`, but `allowed` registrations
        /// later: those go through and the one after them fails, once.
        #[cfg(target_os = "linux")]
        fn fail_event_registration_after(&self, allowed: usize) {
            self._device
                .device
                .read()
                .queue
                .fail_registration_after(allowed);
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

    /// Held shared for the life of every child process the tests run, and
    /// exclusively by any check of whether a port is free.
    ///
    /// A child starts with a copy of every descriptor this process has open,
    /// CLOEXEC or not, so a socket the device has just closed can stay bound
    /// while a parallel test is spawning `ip` or `docker` -- and a
    /// port-release check that lands then fails spuriously. Measured: 31 of
    /// 600 released ports looked held with a concurrent spawner, none
    /// without. Not the spawn alone: `Command::spawn` can return before the
    /// child has closed its CLOEXEC copies (1 of 300 still looked held), so
    /// the gate is held until the child has exited.
    static SPAWN_GATE: std::sync::RwLock<()> = std::sync::RwLock::new(());

    /// `cmd.status()`, under `SPAWN_GATE`.
    fn run(cmd: &mut Command) -> std::io::Result<std::process::ExitStatus> {
        let _gate = SPAWN_GATE
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cmd.status()
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

    /// A connect through a tunnel nobody answers gives up within
    /// `CONNECT_BUDGET`, instead of waiting out the kernel's SYN retries
    /// once per attempt.
    ///
    /// The peer has no container: its endpoint is a local port nothing
    /// listens on, so the handshake is never answered and the SYN, routed
    /// into this test's own TUN, is never delivered -- a dead tunnel, with no
    /// change to the host's network. Every attempt waits its full timeout.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_connect_through_a_silent_tunnel_gives_up_within_its_budget() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let mut wg = WGHandle::init(next_ip(), next_ip_v6());
        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        let peer = Arc::new(Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), next_port()),
            vec![AllowedIp {
                ip: next_ip(),
                cidr: 32,
            }],
        ));
        wg.add_peer(Arc::clone(&peer));
        wg.start();

        let started = Instant::now();
        let err = peer
            .try_connect()
            .expect_err("nothing answers through this tunnel");
        let took = started.elapsed();
        println!(
            "gave up after {:?} ({} attempts, {:?} budget): {}",
            took, CONNECT_ATTEMPTS, CONNECT_BUDGET, err
        );

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{}", err);
        assert!(
            took >= CONNECT_TIMEOUT * CONNECT_ATTEMPTS,
            "every attempt waits its timeout: {:?}",
            took
        );
        assert!(
            took <= CONNECT_BUDGET + Duration::from_secs(2),
            "{:?} is over the {:?} budget",
            took,
            CONNECT_BUDGET
        );
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

    /// Header protection over protocol imitation through the live UAPI socket,
    /// in boringtun-cli's order: imitation and the stock S sizes fixed at
    /// startup (`--imitate-protocol` has no UAPI key), the key sent later in a
    /// `set=1`. Under SIP the stock sizes put a request line in every prefix
    /// but S4's, so the key is refused with EINVAL and not installed -- `get`
    /// reports none -- while the same transaction loads under DNS, STUN and
    /// QUIC.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    fn header_protection_over_shaped_sip_imitation_is_refused_over_the_uapi() {
        use crate::noise::amnezia::{AmneziaConfig, AmneziaImitationProtocol as P};

        const OK: &str = "errno=0\n\n";
        const EINVAL: &str = "errno=22\n\n";
        let key = format!("header_protection_key={}", encode([0x6b; 32]));
        for (protocol, accepted) in [
            (P::Sip, false),
            (P::Dns, true),
            (P::Stun, true),
            (P::Quic, true),
        ] {
            let wg = WGHandle::init_with_config(
                next_ip(),
                next_ip_v6(),
                DeviceConfig {
                    n_threads: 2,
                    use_connected_socket: false,
                    use_multi_queue: false,
                    uapi_fd: -1,
                    amnezia: AmneziaConfig::new(136, 59, 149, 16)
                        .with_protocol_imitation(protocol, None),
                    ..Default::default()
                },
            );
            assert_eq!(wg.wg_set_port(next_port()), OK);
            assert_eq!(
                wg.wg_set(&key),
                if accepted { OK } else { EINVAL },
                "{:?}",
                protocol
            );
            assert_eq!(
                wg.wg_get().contains("header_protection_key="),
                accepted,
                "{:?}: the key is installed exactly when accepted",
                protocol
            );
        }
    }

    /// A listen-port change over `set=1` replaces the listening sockets:
    /// their events leave the poll and the old port is released, so the
    /// event count holds steady and a plain socket can bind the old port.
    ///
    /// `open_listen_socket` registers a `try_clone` of each socket and used to
    /// clear by the original's descriptor, which was never registered. The
    /// previous listeners then stayed registered and bound -- two more events
    /// and a held port per change, which this pins deterministically -- and,
    /// when `dup` had handed the clone a lower number than the original, the
    /// clear indexed past the events table and panicked inside the `set=1`
    /// write lock, killing the worker with the lock's write intent set and
    /// leaving every other thread of the device waiting for it forever.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_listen_port_change_releases_the_previous_listeners() {
        const OK: &str = "errno=0\n\n";
        // Single-queue, so no worker registers a TUN queue of its own while
        // starting up: the only registrations that come and go below are the
        // ones `set=1` makes, and the count is exact.
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
        let registered = || wg._device.device.read().queue.registered_count();

        let (a, b, c) = (next_port(), next_port(), next_port());
        assert_eq!(wg.wg_set_port(a), OK);
        let steady = registered();
        for port in [b, c] {
            assert_eq!(wg.wg_set_port(port), OK, "listen_port={}", port);
            assert_eq!(
                registered(),
                steady,
                "listen_port={}: the previous listeners' events are removed, not kept beside the new ones",
                port
            );
        }
        assert!(wg.wg_get().contains(&format!("listen_port={}", c)));

        // `a` and `b` are no longer this device's: a socket without
        // SO_REUSEADDR binds each, in both families. Under `SPAWN_GATE`, so no
        // child of a parallel test holds a copy of a released socket.
        let _gate = SPAWN_GATE
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for port in [a, b] {
            UdpSocket::bind(("0.0.0.0", port))
                .unwrap_or_else(|e| panic!("IPv4 port {} is still held: {}", port, e));
            UdpSocket::bind(("::", port))
                .unwrap_or_else(|e| panic!("IPv6 port {} is still held: {}", port, e));
        }
    }

    // Listen-port rebinding is a transaction: a refused `listen_port=` leaves
    // the device exactly as it was, and only a successful one replaces the
    // listeners, the port and the peers' connected sockets. The helpers below
    // are shared by the tests that pin that.

    #[cfg(target_os = "linux")]
    const UAPI_OK: &str = "errno=0\n\n";

    /// `bindable` of a port nothing holds, and of one held in both families.
    #[cfg(target_os = "linux")]
    const FREE: (bool, bool) = (true, true);
    #[cfg(target_os = "linux")]
    const HELD: (bool, bool) = (false, false);

    /// Single-queue, so no worker registers a TUN queue of its own while
    /// starting up: the registrations that come and go are exactly the ones
    /// `set=1` makes, and event counts are exact.
    #[cfg(target_os = "linux")]
    fn single_queue_device() -> WGHandle {
        WGHandle::init_with_config(
            next_ip(),
            next_ip_v6(),
            DeviceConfig {
                n_threads: 2,
                use_connected_socket: true,
                use_multi_queue: false,
                uapi_fd: -1,
                ..Default::default()
            },
        )
    }

    /// `(IPv4, IPv6)`: whether a socket without SO_REUSEADDR binds `port` in
    /// each family. Such a bind fails while any socket holds the port -- the
    /// device's SO_REUSEADDR listeners included. Tried one after the other,
    /// as the IPv6 wildcard is dual-stack and would collide with the IPv4
    /// probe; under `SPAWN_GATE`, so a released socket is not still held by
    /// a parallel test's half-spawned child.
    #[cfg(target_os = "linux")]
    fn bindable(port: u16) -> (bool, bool) {
        let _gate = SPAWN_GATE
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let v4 = UdpSocket::bind(("0.0.0.0", port)).is_ok();
        let v6 = UdpSocket::bind(("::", port)).is_ok();
        (v4, v6)
    }

    /// As `bindable`, for sockets made the way the device makes its
    /// listeners: with SO_REUSEADDR, IPv6 dual-stack.
    #[cfg(target_os = "linux")]
    fn listener_bindable(port: u16) -> (bool, bool) {
        use socket2::{Domain, Socket, Type};
        let _gate = SPAWN_GATE
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bind = |domain, addr: SocketAddr| {
            let s = Socket::new(domain, Type::DGRAM, None).unwrap();
            s.set_reuse_address(true).unwrap();
            s.bind(&addr.into()).is_ok()
        };
        let v4 = bind(
            Domain::IPV4,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
        );
        let v6 = bind(
            Domain::IPV6,
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
        );
        (v4, v6)
    }

    /// A test port nothing holds.
    #[cfg(target_os = "linux")]
    fn free_port() -> u16 {
        loop {
            let port = next_port();
            if bindable(port) == FREE {
                return port;
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn listen_port(wg: &WGHandle) -> u16 {
        let get = wg.wg_get();
        get.lines()
            .find_map(|l| l.strip_prefix("listen_port="))
            .unwrap_or_else(|| panic!("no listen_port in {:?}", get))
            .parse()
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    fn registered_events(wg: &WGHandle) -> usize {
        wg._device.device.read().queue.registered_count()
    }

    #[cfg(target_os = "linux")]
    fn listener_fds(wg: &WGHandle) -> Vec<RawFd> {
        wg._device.device.read().udp_listener_fds.clone()
    }

    /// Every worker is still running: none has panicked or exited.
    #[cfg(target_os = "linux")]
    fn workers_alive(wg: &WGHandle) -> bool {
        let threads = &wg._device.threads;
        !threads.is_empty() && threads.iter().all(|t| !t.is_finished())
    }

    /// Give the peer a connected socket, as a completed handshake would, and
    /// return its descriptor. It is not registered with the poll: the tests
    /// only ask whether a rebind keeps it or shuts it down, which
    /// `Endpoint::conn` shows.
    #[cfg(target_os = "linux")]
    fn plant_conn(wg: &WGHandle, key: &PublicKey) -> RawFd {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.connect("127.0.0.1:9").unwrap();
        let sock = socket2::Socket::from(sock);
        let fd = sock.as_raw_fd();
        let device = wg._device.device.read();
        device.peers[key].lock().endpoint_mut().conn = Some(sock);
        fd
    }

    #[cfg(target_os = "linux")]
    fn conn_fd(wg: &WGHandle, key: &PublicKey) -> Option<RawFd> {
        let device = wg._device.device.read();
        let peer = device.peers[key].lock();
        let fd = peer.endpoint().conn.as_ref().map(|c| c.as_raw_fd());
        fd
    }

    #[cfg(target_os = "linux")]
    fn drop_conn(wg: &WGHandle, key: &PublicKey) {
        let device = wg._device.device.read();
        let conn = device.peers[key].lock().endpoint_mut().conn.take();
        assert!(conn.is_some());
    }

    /// A peer of the device under test, reached through its TUN: a packet
    /// routed to `ip` is encapsulated for it, and the handshake initiation
    /// that starts goes to `endpoint`, a socket the test reads.
    #[cfg(target_os = "linux")]
    struct TunPeer {
        key: PublicKey,
        ip: IpAddr,
        endpoint: UdpSocket,
    }

    #[cfg(target_os = "linux")]
    impl TunPeer {
        /// Adds a peer over `set=1` and routes its address into the device's
        /// TUN, which must be up (`WGHandle::start`).
        fn add(wg: &WGHandle) -> TunPeer {
            let key = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
            let ip = next_ip();
            let endpoint = UdpSocket::bind("127.0.0.1:0").unwrap();
            endpoint
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let allowed = [AllowedIp { ip, cidr: 32 }];
            let reply = wg.wg_set_peer(&key, &endpoint.local_addr().unwrap(), &allowed);
            assert_eq!(reply, UAPI_OK, "adding a peer");
            let status = run(Command::new("ip").args([
                "route",
                "add",
                &format!("{}/32", ip),
                "dev",
                &wg.name,
            ]))
            .expect("failed to run ip");
            assert!(status.success(), "route {} via {}", ip, wg.name);
            TunPeer { key, ip, endpoint }
        }

        /// Send a packet into the TUN towards this peer and return where the
        /// handshake initiation the device sends for it came from.
        ///
        /// This is the iface handler, end to end: it reads the packet, finds
        /// the peer and, the peer having no connected socket, sends through
        /// `udp4` -- which it `expect`s to be present, so a worker without
        /// listeners panics there and nothing arrives. Once per peer: the
        /// handshake is then in progress, and a second packet waits for it.
        fn dispatch(&self) -> SocketAddr {
            UdpSocket::bind("0.0.0.0:0")
                .unwrap()
                .send_to(b"through the tunnel", (self.ip, 9))
                .unwrap();
            let mut buf = [0u8; 256];
            let (n, from) = self
                .endpoint
                .recv_from(&mut buf)
                .expect("no handshake initiation reached the peer's endpoint");
            assert_eq!(n, 148, "a vanilla handshake initiation");
            assert_eq!(&buf[..4], &[1, 0, 0, 0], "message type 1");
            from
        }
    }

    /// The device's IPv4 listener on `port`, as seen from loopback.
    #[cfg(target_os = "linux")]
    fn listener(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    /// A rebind that fails after registering half of the new listener pair
    /// changes nothing. The IPv4 candidate, already live in the poll when the
    /// IPv6 one is refused, is removed again; both candidates close and
    /// release the new port; the device keeps its listeners, its port, its
    /// peers' connected sockets and its event count -- and keeps working, a
    /// later rebind included.
    ///
    /// The refusal is a real failing `epoll_ctl`, injected into this device's
    /// poll alone. `open_listen_socket` used to tear the current listeners
    /// down first, so this left the device with no `udp4`/`udp6`, and the
    /// next packet from the TUN panicked a worker in the iface handler's
    /// `expect("Not connected")`.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_rebind_refused_halfway_through_registration_changes_nothing() {
        let mut wg = single_queue_device();
        let old = free_port();
        assert_eq!(wg.wg_set_key(StaticSecret::random_from_rng(OsRng)), UAPI_OK);
        assert_eq!(wg.wg_set_port(old), UAPI_OK);
        wg.start();
        let first = TunPeer::add(&wg);
        let conn = plant_conn(&wg, &first.key);

        // What the refused attempt must leave exactly as it is.
        let get_before = wg.wg_get();
        assert!(get_before.contains(&format!("listen_port={}\n", old)));
        let events_before = registered_events(&wg);
        let listeners_before = listener_fds(&wg);
        let attempts_before = wg.event_registration_attempts();

        // The IPv4 candidate's registration goes through, the IPv6 one's is
        // refused.
        let new = free_port();
        wg.fail_event_registration_after(1);
        let reply = wg.wg_set_port(new);
        assert!(
            reply.starts_with("errno=") && reply != UAPI_OK,
            "listen_port={} is refused, got {:?}",
            new,
            reply
        );
        assert_eq!(
            wg.event_registration_attempts() - attempts_before,
            2,
            "both candidates reached registration: the IPv4 one was live when the IPv6 one was refused"
        );

        // 1. The UAPI still reports the old state, the old port included.
        assert_eq!(wg.wg_get(), get_before);
        // 2. The live IPv4 candidate's event was removed again.
        assert_eq!(registered_events(&wg), events_before);
        assert_eq!(listener_fds(&wg), listeners_before);
        // 3. The old port is still the device's, in both families.
        assert_eq!(bindable(old), HELD, "old port {}", old);
        // 4. The candidates are gone: the new port is free in both families.
        assert_eq!(bindable(new), FREE, "new port {}", new);
        // Peers keep their connected sockets.
        assert_eq!(conn_fd(&wg, &first.key), Some(conn));
        drop_conn(&wg, &first.key); // so the dispatch below uses the listener

        // 5. Ordinary UAPI operations still work.
        let second = TunPeer::add(&wg);
        assert!(wg.wg_get().ends_with(UAPI_OK));
        // 6. A packet from the TUN is encapsulated and sent from the old port.
        assert_eq!(first.dispatch(), listener(old));
        // 7. No worker panicked or exited.
        assert!(workers_alive(&wg));

        // 8. A later rebind succeeds...
        plant_conn(&wg, &first.key);
        let later = free_port();
        assert_eq!(wg.wg_set_port(later), UAPI_OK);
        assert_eq!(listen_port(&wg), later);
        // 9. ...and replaces the old listeners outright.
        assert_eq!(bindable(old), FREE, "old port {}", old);
        assert_eq!(bindable(later), HELD, "later port {}", later);
        assert_eq!(bindable(new), FREE, "new port {}", new);
        assert_eq!(registered_events(&wg), events_before);
        assert_eq!(
            conn_fd(&wg, &first.key),
            None,
            "a successful rebind shuts the peers' connected sockets down"
        );
        assert_eq!(second.dispatch(), listener(later));
        assert!(workers_alive(&wg));
    }

    /// A rebind to a port someone else holds fails at the bind, before any
    /// registration, and changes nothing either. Both binds are covered: an
    /// IPv4 holder fails the first; an IPv6-only holder lets the IPv4
    /// candidate bind and fails the second, and that candidate must then
    /// release the port too. Once the port is free the same rebind succeeds.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_rebind_to_a_port_in_use_changes_nothing() {
        let mut wg = single_queue_device();
        let old = free_port();
        assert_eq!(wg.wg_set_key(StaticSecret::random_from_rng(OsRng)), UAPI_OK);
        assert_eq!(wg.wg_set_port(old), UAPI_OK);
        wg.start();
        let first = TunPeer::add(&wg);
        let conn = plant_conn(&wg, &first.key);

        let get_before = wg.wg_get();
        let events_before = registered_events(&wg);
        let listeners_before = listener_fds(&wg);
        let attempts_before = wg.event_registration_attempts();

        let new = free_port();
        let hold_v4 = || socket2::Socket::from(UdpSocket::bind(("0.0.0.0", new)).unwrap());
        let hold_v6_only = || {
            use socket2::{Domain, Socket, Type};
            let s = Socket::new(Domain::IPV6, Type::DGRAM, None).unwrap();
            s.set_only_v6(true).unwrap();
            s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, new)).into())
                .unwrap();
            s
        };
        // With each holder, which of the candidates' binds (SO_REUSEADDR, as
        // `bind_listen_pair` makes them) succeed: none, or the IPv4 one only.
        type Hold<'a> = &'a dyn Fn() -> socket2::Socket;
        let holders: [(&str, Hold, (bool, bool)); 2] = [
            ("IPv4", &hold_v4, (false, false)),
            ("IPv6-only", &hold_v6_only, (true, false)),
        ];
        for (family, hold, candidates) in holders {
            let holder = hold();
            assert_eq!(listener_bindable(new), candidates, "{}", family);
            let reply = wg.wg_set_port(new);
            assert!(
                reply.starts_with("errno=") && reply != UAPI_OK,
                "listen_port={} with an {} holder is refused, got {:?}",
                new,
                family,
                reply
            );
            assert_eq!(
                wg.event_registration_attempts(),
                attempts_before,
                "{}: a failed bind comes before any registration",
                family
            );
            assert_eq!(wg.wg_get(), get_before, "{}", family);
            assert_eq!(registered_events(&wg), events_before, "{}", family);
            assert_eq!(listener_fds(&wg), listeners_before, "{}", family);
            assert_eq!(bindable(old), HELD, "{}: old port {}", family, old);
            assert_eq!(conn_fd(&wg, &first.key), Some(conn), "{}", family);
            drop(holder);
            assert_eq!(
                bindable(new),
                FREE,
                "{}: no candidate outlives the attempt",
                family
            );
        }

        // The device is unharmed: the UAPI works, a packet from the TUN goes
        // out from the old port, and no worker died.
        drop_conn(&wg, &first.key);
        let second = TunPeer::add(&wg);
        assert_eq!(first.dispatch(), listener(old));
        assert!(workers_alive(&wg));

        // With the port released, the same rebind succeeds.
        plant_conn(&wg, &first.key);
        assert_eq!(wg.wg_set_port(new), UAPI_OK);
        assert_eq!(listen_port(&wg), new);
        assert_eq!(bindable(old), FREE, "old port {}", old);
        assert_eq!(bindable(new), HELD, "new port {}", new);
        assert_eq!(registered_events(&wg), events_before);
        assert_eq!(conn_fd(&wg, &first.key), None);
        assert_eq!(second.dispatch(), listener(new));
        assert!(workers_alive(&wg));
    }

    /// `listen_port=` naming the port already held is a no-op: `awg
    /// syncconf` resends an unchanged ListenPort on every run, and rebinding
    /// would only disconnect every peer's connected socket for nothing. The
    /// listeners, their events and the peers' sockets all stay. `listen_port=0`
    /// is not "the same port" -- it asks for a fresh one, and gets it.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn setting_the_held_port_again_is_a_no_op_but_port_0_rebinds() {
        let wg = single_queue_device();
        let old = free_port();
        assert_eq!(wg.wg_set_key(StaticSecret::random_from_rng(OsRng)), UAPI_OK);
        assert_eq!(wg.wg_set_port(old), UAPI_OK);
        let key = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let allowed = [AllowedIp {
            ip: next_ip(),
            cidr: 32,
        }];
        assert_eq!(wg.wg_set_peer(&key, &endpoint, &allowed), UAPI_OK);
        let conn = plant_conn(&wg, &key);

        let events_before = registered_events(&wg);
        let listeners_before = listener_fds(&wg);
        let attempts_before = wg.event_registration_attempts();

        assert_eq!(wg.wg_set_port(old), UAPI_OK);
        assert_eq!(listen_port(&wg), old);
        assert_eq!(wg.event_registration_attempts(), attempts_before);
        assert_eq!(listener_fds(&wg), listeners_before);
        assert_eq!(registered_events(&wg), events_before);
        assert_eq!(bindable(old), HELD, "old port {}", old);
        assert_eq!(conn_fd(&wg, &key), Some(conn), "the peer keeps its socket");

        assert_eq!(wg.wg_set_port(0), UAPI_OK);
        let fresh = listen_port(&wg);
        // `next_port` hands out ports above Linux's default ephemeral range,
        // so the OS cannot pick `old` back.
        assert_ne!(fresh, old);
        assert_eq!(wg.event_registration_attempts() - attempts_before, 2);
        let listeners_after = listener_fds(&wg);
        assert_eq!(listeners_after.len(), 2);
        assert!(listeners_after
            .iter()
            .all(|fd| !listeners_before.contains(fd)));
        assert_eq!(registered_events(&wg), events_before);
        assert_eq!(bindable(old), FREE, "old port {}", old);
        assert_eq!(bindable(fresh), HELD, "fresh port {}", fresh);
        assert_eq!(conn_fd(&wg, &key), None, "a real rebind shuts it down");
    }

    /// A UAPI request that fails instead of blocking if no worker serves it
    /// within `timeout`.
    #[cfg(target_os = "linux")]
    fn uapi_within(wg: &WGHandle, request: &str, timeout: Duration) -> std::io::Result<String> {
        let path = format!("/var/run/wireguard/{}.sock", wg.name);
        let mut socket = UnixStream::connect(path)?;
        socket.set_read_timeout(Some(timeout))?;
        write!(socket, "{}\n\n", request)?;
        let mut reply = String::new();
        socket.read_to_string(&mut reply)?;
        Ok(reply)
    }

    /// A panic inside a device write leaves the device working.
    ///
    /// `try_writeable` raises the device's write intent before its closures
    /// run, and each worker's next `Lock::read` waits for the intent to drop.
    /// It used to be dropped only on return, so a panic in a write -- the
    /// listener-rebind panic fixed in #65 was one -- left it raised for good,
    /// and every worker, the UAPI included, waited forever. Driven here
    /// through the device lock the way `set=1` drives it, yield included,
    /// rather than by planting a panic in production code.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_panic_in_a_device_write_leaves_the_device_working() {
        const SERVED: Duration = Duration::from_secs(10);
        let wg = single_queue_device();
        let (old, new) = (free_port(), free_port());
        assert_eq!(wg.wg_set_port(old), UAPI_OK);

        {
            let mut device = wg._device.device.read();
            // `AssertUnwindSafe`: the closure borrows the guard mutably, and
            // looking at the device after a write unwound is the point.
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                device.try_writeable(
                    |d| d.trigger_yield(),
                    |d| {
                        d.cancel_yield();
                        panic!("in a device write")
                    },
                )
            }))
            .unwrap_err();
            assert_eq!(
                panic.downcast_ref::<&str>(),
                Some(&"in a device write"),
                "the panic propagates as is"
            );
        }

        // The workers yielded to that write; they must get the device back.
        let get = uapi_within(&wg, "get=1", SERVED)
            .expect("no worker served get=1: the device is frozen");
        assert!(get.contains(&format!("listen_port={}\n", old)), "{:?}", get);
        assert!(get.ends_with(UAPI_OK));
        // And a later write goes through.
        let set = uapi_within(&wg, &format!("set=1\nlisten_port={}", new), SERVED)
            .expect("no worker served set=1: the device is frozen");
        assert_eq!(set, UAPI_OK);
        assert_eq!(listen_port(&wg), new);
        assert!(workers_alive(&wg));
    }

    /// A mark no test socket would carry by accident.
    #[cfg(target_os = "linux")]
    const MARK: u32 = 0x00c0_ffee;

    /// The SO_MARK the kernel holds on the device's two listeners, read back
    /// from the sockets -- not `Device::fwmark`, which is only what they are
    /// supposed to hold.
    #[cfg(target_os = "linux")]
    fn listener_marks(wg: &WGHandle) -> (u32, u32) {
        let device = wg._device.device.read();
        let mark = |s: &Option<socket2::Socket>| s.as_ref().unwrap().mark().unwrap();
        (mark(&device.udp4), mark(&device.udp6))
    }

    /// The `fwmark=` line of `get=1`, if any.
    #[cfg(target_os = "linux")]
    fn reported_fwmark(wg: &WGHandle) -> Option<u32> {
        wg.wg_get()
            .lines()
            .find_map(|l| l.strip_prefix("fwmark="))
            .map(|v| v.parse().unwrap())
    }

    /// A connected socket for the peer made the way the device makes one on a
    /// handshake -- `connect_endpoint` with the device's listen port and
    /// fwmark -- and the SO_MARK and local port it came out with.
    #[cfg(target_os = "linux")]
    fn connect_peer(wg: &WGHandle, key: &PublicKey) -> (u32, u16) {
        let device = wg._device.device.read();
        let conn = device.peers[key]
            .lock()
            .connect_endpoint(device.listen_port, device.fwmark)
            .unwrap();
        let port = conn.local_addr().unwrap().as_socket().unwrap().port();
        (conn.mark().unwrap(), port)
    }

    /// The device's fwmark stays on its listeners across every kind of
    /// `listen_port=`: an explicit new port, port 0, and the held port.
    ///
    /// `set_fwmark` marks the listeners it finds, but a rebind replaces them,
    /// and the replacements used to come out unmarked: the device went on
    /// reporting `fwmark=` while sending from sockets that ignored it, so its
    /// traffic left the policy routing the mark selects. Peers' connected
    /// sockets never lost it -- `connect_endpoint` takes the mark itself --
    /// which left the two out of step.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn the_fwmark_survives_listener_rebinds() {
        let wg = single_queue_device();
        let first = free_port();
        assert_eq!(wg.wg_set_key(StaticSecret::random_from_rng(OsRng)), UAPI_OK);
        assert_eq!(wg.wg_set_port(first), UAPI_OK);
        let key = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let allowed = [AllowedIp {
            ip: next_ip(),
            cidr: 32,
        }];
        assert_eq!(wg.wg_set_peer(&key, &endpoint, &allowed), UAPI_OK);

        assert_eq!(wg.wg_set(&format!("fwmark={}", MARK)), UAPI_OK);
        assert_eq!(
            listener_marks(&wg),
            (MARK, MARK),
            "fwmark= marks the listeners"
        );
        assert_eq!(reported_fwmark(&wg), Some(MARK));
        assert_eq!(connect_peer(&wg, &key), (MARK, first));
        let events = registered_events(&wg);

        // An explicit new port.
        let fds = listener_fds(&wg);
        let second = free_port();
        assert_eq!(wg.wg_set_port(second), UAPI_OK);
        assert_eq!(listen_port(&wg), second);
        assert_ne!(listener_fds(&wg), fds, "a new listener pair");
        assert_eq!(registered_events(&wg), events);
        assert_eq!(bindable(first), FREE, "first port {}", first);
        assert_eq!(bindable(second), HELD, "second port {}", second);
        assert_eq!(listener_marks(&wg), (MARK, MARK), "listen_port={}", second);
        assert_eq!(reported_fwmark(&wg), Some(MARK));
        assert_eq!(conn_fd(&wg, &key), None, "the rebind shut the old one");
        assert_eq!(connect_peer(&wg, &key), (MARK, second));

        // Port 0: a fresh pair on a port the OS picks.
        let fds = listener_fds(&wg);
        assert_eq!(wg.wg_set_port(0), UAPI_OK);
        let fresh = listen_port(&wg);
        assert_ne!(fresh, second);
        assert_ne!(listener_fds(&wg), fds, "a new listener pair");
        assert_eq!(registered_events(&wg), events);
        assert_eq!(bindable(second), FREE, "second port {}", second);
        assert_eq!(listener_marks(&wg), (MARK, MARK), "listen_port=0");
        assert_eq!(reported_fwmark(&wg), Some(MARK));

        // The held port: a no-op, marks and sockets untouched.
        let fds = listener_fds(&wg);
        let attempts = wg.event_registration_attempts();
        assert_eq!(wg.wg_set_port(fresh), UAPI_OK);
        assert_eq!(listener_fds(&wg), fds);
        assert_eq!(wg.event_registration_attempts(), attempts);
        assert_eq!(
            listener_marks(&wg),
            (MARK, MARK),
            "listen_port={} again",
            fresh
        );
    }

    /// The listeners end up marked whichever way round `fwmark=` and
    /// `listen_port=` come in one request, and an explicit `fwmark=0` --
    /// kept as `Some(0)` and reported as `fwmark=0` -- is carried over as the
    /// value it is.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn every_ordering_of_fwmark_and_listen_port_leaves_the_listeners_marked() {
        let wg = single_queue_device();
        assert_eq!(wg.wg_set_port(free_port()), UAPI_OK);

        // The mark first, then the rebind: the new listeners must inherit it.
        let port = free_port();
        let request = format!("fwmark={}\nlisten_port={}", MARK, port);
        assert_eq!(wg.wg_set(&request), UAPI_OK);
        assert_eq!(listen_port(&wg), port);
        assert_eq!(
            listener_marks(&wg),
            (MARK, MARK),
            "fwmark, then listen_port"
        );

        // The rebind first, then the mark: it marks the listeners it finds.
        let (port, mark) = (free_port(), MARK + 1);
        let request = format!("listen_port={}\nfwmark={}", port, mark);
        assert_eq!(wg.wg_set(&request), UAPI_OK);
        assert_eq!(listen_port(&wg), port);
        assert_eq!(
            listener_marks(&wg),
            (mark, mark),
            "listen_port, then fwmark"
        );

        // Zero is a value: it unmarks the listeners, is reported, and a
        // rebind keeps it.
        assert_eq!(wg.wg_set("fwmark=0"), UAPI_OK);
        assert_eq!(listener_marks(&wg), (0, 0));
        assert_eq!(reported_fwmark(&wg), Some(0));
        assert_eq!(wg.wg_set_port(free_port()), UAPI_OK);
        assert_eq!(listener_marks(&wg), (0, 0));
        assert_eq!(reported_fwmark(&wg), Some(0));
    }

    /// A rebind whose fwmark cannot be put on the replacement listeners is
    /// refused and changes nothing. The mark is applied in PREPARE, before
    /// any registration: with the IPv4 candidate marked and the IPv6 one
    /// refused, both candidates just close -- no event was registered, no
    /// port is left held -- and the device keeps its marked listeners, its
    /// port, its fwmark and its peers' connected sockets.
    ///
    /// The refusal is injected into this device only, at the IPv6
    /// candidate's `mark_listener`, as the EPERM an unprivileged `set_mark`
    /// gets.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_rebind_whose_fwmark_cannot_be_applied_changes_nothing() {
        let wg = single_queue_device();
        let old = free_port();
        assert_eq!(wg.wg_set_key(StaticSecret::random_from_rng(OsRng)), UAPI_OK);
        assert_eq!(wg.wg_set_port(old), UAPI_OK);
        let key = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let allowed = [AllowedIp {
            ip: next_ip(),
            cidr: 32,
        }];
        assert_eq!(wg.wg_set_peer(&key, &endpoint, &allowed), UAPI_OK);
        assert_eq!(wg.wg_set(&format!("fwmark={}", MARK)), UAPI_OK);
        let conn = plant_conn(&wg, &key);

        let get_before = wg.wg_get();
        let events_before = registered_events(&wg);
        let listeners_before = listener_fds(&wg);
        let attempts_before = wg.event_registration_attempts();

        let new = free_port();
        // The IPv4 candidate's mark goes through, the IPv6 one's is refused.
        fail_mark_after(&wg, 1);
        let reply = wg.wg_set_port(new);
        assert!(
            reply.starts_with("errno=") && reply != UAPI_OK,
            "listen_port={} is refused, got {:?}",
            new,
            reply
        );
        assert!(
            !mark_fault_armed(&wg),
            "the refusal came from the IPv6 candidate's mark"
        );
        assert_eq!(
            wg.event_registration_attempts(),
            attempts_before,
            "marking comes before any registration"
        );
        assert_eq!(
            wg.wg_get(),
            get_before,
            "fwmark and port reported as before"
        );
        assert_eq!(registered_events(&wg), events_before);
        assert_eq!(listener_fds(&wg), listeners_before);
        assert_eq!(
            listener_marks(&wg),
            (MARK, MARK),
            "the old listeners keep it"
        );
        assert_eq!(bindable(old), HELD, "old port {}", old);
        assert_eq!(bindable(new), FREE, "no candidate outlives the attempt");
        assert_eq!(conn_fd(&wg, &key), Some(conn), "peers keep their sockets");

        // Nothing is stuck: the same rebind, unhindered, goes through marked.
        assert_eq!(wg.wg_set_port(new), UAPI_OK);
        assert_eq!(listen_port(&wg), new);
        assert_eq!(listener_marks(&wg), (MARK, MARK));
        assert_eq!(registered_events(&wg), events_before);
        assert_eq!(bindable(old), FREE, "old port {}", old);
        assert_eq!(conn_fd(&wg, &key), None);
    }

    /// Arm the device's one-shot mark fault: the next `allowed` SO_MARK
    /// applications go through and the one after fails with EPERM.
    #[cfg(target_os = "linux")]
    fn fail_mark_after(wg: &WGHandle, allowed: usize) {
        wg._device.device.read().fail_mark_after(allowed);
    }

    #[cfg(target_os = "linux")]
    fn mark_fault_armed(wg: &WGHandle) -> bool {
        let device = wg._device.device.read();
        device.mark_fault.load(std::sync::atomic::Ordering::Relaxed) != usize::MAX
    }

    /// The device's stored fwmark, as the device itself holds it.
    #[cfg(target_os = "linux")]
    fn stored_fwmark(wg: &WGHandle) -> Option<u32> {
        wg._device.device.read().fwmark
    }

    /// Add a peer and give it a connected socket, made by `connect_endpoint`
    /// as a handshake would make it.
    #[cfg(target_os = "linux")]
    fn add_connected_peer(wg: &WGHandle) -> PublicKey {
        let key = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let allowed = [AllowedIp {
            ip: next_ip(),
            cidr: 32,
        }];
        assert_eq!(wg.wg_set_peer(&key, &endpoint, &allowed), UAPI_OK);
        connect_peer(wg, &key);
        key
    }

    /// The SO_MARK the kernel holds on the peer's connected socket.
    #[cfg(target_os = "linux")]
    fn peer_conn_mark(wg: &WGHandle, key: &PublicKey) -> Option<u32> {
        let device = wg._device.device.read();
        let peer = device.peers[key].lock();
        let mark = peer.endpoint().conn.as_ref().map(|c| c.mark().unwrap());
        mark
    }

    /// A refused `fwmark=` is not stored: the device keeps -- and reports,
    /// and carries to its next listener pair -- the last fwmark that every
    /// socket accepted. The refusal here is the first listener's, before
    /// any socket changed.
    ///
    /// `set_fwmark` used to store the mark first. Without CAP_NET_ADMIN,
    /// where every `set_mark` fails -- boringtun-cli drops privileges by
    /// default -- one failed `fwmark=` then left a mark the device reported
    /// but no socket carried, and every later rebind, which now carries the
    /// stored mark over, was refused until restart.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_refused_fwmark_update_leaves_the_last_committed_one() {
        let wg = single_queue_device();
        assert_eq!(wg.wg_set_key(StaticSecret::random_from_rng(OsRng)), UAPI_OK);
        assert_eq!(wg.wg_set_port(free_port()), UAPI_OK);
        let peer = add_connected_peer(&wg);
        let refused = |wg: &WGHandle, mark: u32| {
            fail_mark_after(wg, 0);
            let reply = wg.wg_set(&format!("fwmark={}", mark));
            assert!(
                reply.starts_with("errno=") && reply != UAPI_OK,
                "{:?}",
                reply
            );
            assert!(!mark_fault_armed(wg));
        };

        // Nothing committed yet: the device stays unmarked.
        refused(&wg, MARK);
        assert_eq!(stored_fwmark(&wg), None);
        assert_eq!(reported_fwmark(&wg), None);
        assert_eq!(listener_marks(&wg), (0, 0));
        assert_eq!(peer_conn_mark(&wg, &peer), Some(0));
        let port = free_port();
        assert_eq!(wg.wg_set_port(port), UAPI_OK, "no stale mark to carry over");
        assert_eq!(listen_port(&wg), port);
        assert_eq!(listener_marks(&wg), (0, 0));
        assert!(wg.wg_get().ends_with(UAPI_OK));

        // A committed mark stays the committed one.
        let (old, new) = (MARK, MARK + 1);
        assert_eq!(wg.wg_set(&format!("fwmark={}", old)), UAPI_OK);
        connect_peer(&wg, &peer); // the rebind above shut the old one
        assert_eq!(peer_conn_mark(&wg, &peer), Some(old));
        refused(&wg, new);
        assert_eq!(stored_fwmark(&wg), Some(old));
        assert_eq!(reported_fwmark(&wg), Some(old));
        assert_eq!(listener_marks(&wg), (old, old));
        assert_eq!(peer_conn_mark(&wg, &peer), Some(old));
        let port = free_port();
        assert_eq!(wg.wg_set_port(port), UAPI_OK);
        assert_eq!(
            listener_marks(&wg),
            (old, old),
            "the committed mark is carried"
        );
    }

    /// Characterisation, not a guarantee of all-or-nothing: `set_fwmark`
    /// stores the mark only once every socket took it, but does not roll
    /// back the sockets that took it before a later one refused. What each
    /// stage of a refusal leaves behind is pinned here, so neither the code
    /// nor its comments can drift into claiming more.
    ///
    /// The order is fixed: IPv4 listener, IPv6 listener, then peers. Peers
    /// are visited in map order, so with two of them the assertion is on
    /// how many took the new mark, not which.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_fwmark_update_refused_part_way_is_not_rolled_back() {
        let wg = single_queue_device();
        assert_eq!(wg.wg_set_key(StaticSecret::random_from_rng(OsRng)), UAPI_OK);
        assert_eq!(wg.wg_set_port(free_port()), UAPI_OK);
        let (old, new) = (MARK, MARK + 1);
        assert_eq!(wg.wg_set(&format!("fwmark={}", old)), UAPI_OK);
        let peers = [add_connected_peer(&wg), add_connected_peer(&wg)];
        let peer_marks = |wg: &WGHandle| {
            let mut marks: Vec<u32> = peers
                .iter()
                .map(|k| peer_conn_mark(wg, k).unwrap())
                .collect();
            marks.sort();
            marks
        };
        let refused_at = |wg: &WGHandle, allowed: usize| {
            fail_mark_after(wg, allowed);
            let reply = wg.wg_set(&format!("fwmark={}", new));
            assert!(
                reply.starts_with("errno=") && reply != UAPI_OK,
                "{:?}",
                reply
            );
            assert!(!mark_fault_armed(wg));
            assert_eq!(stored_fwmark(wg), Some(old), "the stored mark stays");
            assert_eq!(reported_fwmark(wg), Some(old));
        };
        let restore = |wg: &WGHandle| {
            assert_eq!(wg.wg_set(&format!("fwmark={}", old)), UAPI_OK);
            assert_eq!(listener_marks(wg), (old, old));
        };
        assert_eq!(peer_marks(&wg), [old, old]);

        // The first listener refuses: nothing changed.
        refused_at(&wg, 0);
        assert_eq!(listener_marks(&wg), (old, old));
        assert_eq!(peer_marks(&wg), [old, old]);

        // The second listener refuses: the first keeps the new mark.
        refused_at(&wg, 1);
        assert_eq!(listener_marks(&wg), (new, old));
        assert_eq!(peer_marks(&wg), [old, old], "the peer stage is not reached");
        restore(&wg);

        // The first peer refuses: both listeners keep the new mark.
        refused_at(&wg, 2);
        assert_eq!(listener_marks(&wg), (new, new));
        assert_eq!(peer_marks(&wg), [old, old]);
        restore(&wg);

        // The second peer refuses: the listeners and one peer keep it.
        refused_at(&wg, 3);
        assert_eq!(listener_marks(&wg), (new, new));
        assert_eq!(peer_marks(&wg), [old, new]);
        restore(&wg);

        // Unhindered, the update takes everywhere and is stored.
        assert_eq!(wg.wg_set(&format!("fwmark={}", new)), UAPI_OK);
        assert_eq!(stored_fwmark(&wg), Some(new));
        assert_eq!(listener_marks(&wg), (new, new));
        assert_eq!(peer_marks(&wg), [new, new]);
    }

    /// A successful `fwmark=` marks both listeners and every connected peer
    /// socket, and is stored and reported. `fwmark=0` is a value, not an
    /// absence: stored as `Some(0)`, reported as `fwmark=0`, applied as 0 --
    /// and a peer socket made afterwards takes it through `connect_endpoint`.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn fwmark_marks_the_listeners_and_connected_peers_and_zero_is_a_value() {
        let wg = single_queue_device();
        assert_eq!(wg.wg_set_key(StaticSecret::random_from_rng(OsRng)), UAPI_OK);
        assert_eq!(wg.wg_set_port(free_port()), UAPI_OK);
        let peers = [add_connected_peer(&wg), add_connected_peer(&wg)];
        for peer in &peers {
            assert_eq!(peer_conn_mark(&wg, peer), Some(0));
        }

        assert_eq!(wg.wg_set(&format!("fwmark={}", MARK)), UAPI_OK);
        assert_eq!(stored_fwmark(&wg), Some(MARK));
        assert_eq!(reported_fwmark(&wg), Some(MARK));
        assert_eq!(listener_marks(&wg), (MARK, MARK));
        for peer in &peers {
            assert_eq!(peer_conn_mark(&wg, peer), Some(MARK));
        }

        assert_eq!(wg.wg_set("fwmark=0"), UAPI_OK);
        assert_eq!(stored_fwmark(&wg), Some(0));
        assert_eq!(reported_fwmark(&wg), Some(0));
        assert_eq!(listener_marks(&wg), (0, 0));
        for peer in &peers {
            assert_eq!(peer_conn_mark(&wg, peer), Some(0));
        }

        drop_conn(&wg, &peers[0]);
        assert_eq!(connect_peer(&wg, &peers[0]).0, 0);
        assert_eq!(peer_conn_mark(&wg, &peers[0]), Some(0));
    }

    /// SO_MARK belongs to the socket, not the descriptor: a `try_clone` --
    /// the descriptor the device registers each listener under -- sees a mark
    /// set through the original, and the other way round. So marking the
    /// listener marks what the event loop receives on.
    ///
    /// Needs CAP_NET_ADMIN, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn so_mark_is_shared_by_a_socket_and_its_clone() {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        let clone = socket.try_clone().unwrap();
        assert_ne!(socket.as_raw_fd(), clone.as_raw_fd());
        socket.set_mark(MARK).unwrap();
        assert_eq!(clone.mark().unwrap(), MARK);
        clone.set_mark(MARK + 1).unwrap();
        assert_eq!(socket.mark().unwrap(), MARK + 1);
    }
}
