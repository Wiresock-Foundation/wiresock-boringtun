// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This module contains some integration tests for boringtun
// Those tests require docker and sudo privileges to run
#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    #[cfg(target_os = "linux")]
    use crate::device::udp_diagnostics;
    #[cfg(target_os = "linux")]
    use crate::device::MAX_UDP_SIZE;
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
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
    #[cfg(target_os = "linux")]
    use std::os::unix::net::UnixDatagram;
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

        /// GET the peer's page through the tunnel: connect within
        /// `CONNECT_BUDGET`, then exchange the request and the response
        /// under `HTTP_IO_TIMEOUT` per socket operation. The error names the
        /// stage that failed.
        fn try_get_request(&self) -> std::io::Result<String> {
            http_exchange(self.connect(), HTTP_IO_TIMEOUT)
        }

        fn get_request(&self) -> String {
            self.try_get_request().unwrap_or_else(|err| {
                panic!(
                    "HTTP GET from {} through the tunnel failed ({:?}): {}",
                    SocketAddr::new(self.allowed_ips[0].ip, 80),
                    err.kind(),
                    err
                )
            })
        }
    }

    /// How long each socket operation of an HTTP exchange may wait once the
    /// connection is up -- the request write, and every read of the status
    /// line, the headers and the body. Separate from `CONNECT_BUDGET`, which
    /// ends when `connect` returns.
    ///
    /// Measured on the suite (10 runs, 10,050 exchanges): from the request
    /// write to the last body byte took 1.9 ms at the median, 25 ms at
    /// p99.9 and 48 ms at worst, nearly all of it waiting for the status
    /// line. 10 s is some 200 times the worst.
    ///
    /// Per operation, not a deadline for the whole response: a server that
    /// keeps trickling bytes restarts it with each read. The peer is this
    /// suite's own nginx, which answers in one short burst, so the case
    /// that matters is a peer that stops -- and that fails after one
    /// timeout, naming the stage.
    const HTTP_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    /// The request, byte for byte: HTTP/1.1 with CRLF line ends.
    const HTTP_REQUEST: &[u8] =
        b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nConnection: close\r\n\r\n";

    /// Ceilings for what the helper will read. The page is a 64-character
    /// hex public key and nginx sends a few hundred bytes of headers, so
    /// both are generous; exceeding either is a malformed response, not
    /// something to allocate for.
    const HTTP_MAX_HEAD: usize = 8 * 1024;
    const HTTP_MAX_BODY: usize = 4 * 1024;

    /// Send `HTTP_REQUEST` on a connected `stream` and read the response
    /// body, with `timeout` on every socket operation.
    fn http_exchange(
        mut stream: std::net::TcpStream,
        timeout: std::time::Duration,
    ) -> std::io::Result<String> {
        configure_http_stream(&stream, timeout)?;
        stream
            .write_all(HTTP_REQUEST)
            .map_err(|e| http_stage("writing the request", e))?;
        read_http_response(&mut BufReader::new(stream))
    }

    /// Bound both directions before any I/O. A timeout that cannot be set
    /// is an error, not a socket left blocking forever.
    fn configure_http_stream(
        stream: &std::net::TcpStream,
        timeout: std::time::Duration,
    ) -> std::io::Result<()> {
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| http_stage("setting the write timeout", e))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| http_stage("setting the read timeout", e))
    }

    /// Read the one response this suite's nginx sends: `HTTP/1.1 200`,
    /// headers up to the blank line, and exactly `Content-Length` bytes of
    /// UTF-8 body. Only as much HTTP as that fixture needs; anything else
    /// is an error naming what was wrong.
    ///
    /// * A read error, and EOF, fail the stage they happen in -- they never
    ///   stand in for a blank line or a successful status.
    /// * Headers are split at the first colon, and names compare
    ///   ASCII-case-insensitively. Unknown headers are ignored.
    /// * `Content-Length` is required. A repeat with the same value is
    ///   accepted, as RFC 9110 lets a recipient; a different one is an
    ///   error. Zero is a valid, empty body.
    /// * `Transfer-Encoding` is refused: nginx sends a length for this
    ///   page, and a chunked decoder is more HTTP than the suite needs.
    /// * The body is read with `read_exact`, never to EOF, so a server that
    ///   keeps the connection open does not delay it.
    fn read_http_response(reader: &mut impl BufRead) -> std::io::Result<String> {
        let mut budget = HTTP_MAX_HEAD;
        let mut line = String::new();

        read_head_line(reader, &mut line, &mut budget, "reading the status line")?;
        let status = line.trim_end_matches(['\r', '\n']);
        let mut parts = status.splitn(3, ' ');
        match (parts.next(), parts.next()) {
            (Some("HTTP/1.1"), Some("200")) => {}
            _ => return Err(http_invalid(format!("unexpected status line {:?}", status))),
        }

        let mut content_length: Option<usize> = None;
        loop {
            line.clear();
            read_head_line(reader, &mut line, &mut budget, "reading the headers")?;
            let header = line.trim_end_matches(['\r', '\n']);
            if header.is_empty() {
                break;
            }
            let (name, value) = match header.split_once(':') {
                Some((name, value))
                    if !name.is_empty() && !name.contains(|c: char| c.is_ascii_whitespace()) =>
                {
                    (name, value.trim())
                }
                _ => return Err(http_invalid(format!("malformed header line {:?}", header))),
            };
            if name.eq_ignore_ascii_case("content-length") {
                let len = match value.parse::<usize>() {
                    Ok(len) if value.bytes().all(|b| b.is_ascii_digit()) => len,
                    _ => {
                        return Err(http_invalid(format!(
                            "malformed Content-Length {:?}",
                            value
                        )))
                    }
                };
                match content_length {
                    Some(previous) if previous != len => {
                        return Err(http_invalid(format!(
                            "conflicting Content-Length values {} and {}",
                            previous, len
                        )))
                    }
                    _ => content_length = Some(len),
                }
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err(http_invalid(format!(
                    "Transfer-Encoding {:?} is not supported by this test helper",
                    value
                )));
            }
        }

        let len = content_length.ok_or_else(|| http_invalid("no Content-Length header".into()))?;
        if len > HTTP_MAX_BODY {
            return Err(http_invalid(format!(
                "Content-Length {} exceeds the {}-byte limit",
                len, HTTP_MAX_BODY
            )));
        }
        let mut body = vec![0u8; len];
        reader
            .read_exact(&mut body)
            .map_err(|e| http_stage("reading the body", e))?;
        String::from_utf8(body).map_err(|_| http_invalid("the body is not UTF-8".into()))
    }

    /// One line of the status line and headers, charged against `budget`,
    /// the bytes left for the whole head. EOF before the line ends fails
    /// `stage`, and so does running out of budget.
    fn read_head_line(
        reader: &mut impl BufRead,
        line: &mut String,
        budget: &mut usize,
        stage: &str,
    ) -> std::io::Result<()> {
        let read = reader
            .by_ref()
            .take(*budget as u64)
            .read_line(line)
            .map_err(|e| http_stage(stage, e))?;
        if !line.ends_with('\n') {
            return Err(if read == *budget {
                http_invalid(format!(
                    "{}: the response head exceeds {} bytes",
                    stage, HTTP_MAX_HEAD
                ))
            } else {
                http_stage(
                    stage,
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "the connection closed mid-response",
                    ),
                )
            });
        }
        *budget -= read;
        Ok(())
    }

    /// `err` with the stage it happened in, keeping its kind -- so a
    /// timeout still reads as one.
    fn http_stage(stage: &str, err: std::io::Error) -> std::io::Error {
        std::io::Error::new(err.kind(), format!("{}: {}", stage, err))
    }

    fn http_invalid(detail: String) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, detail)
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

    /// What this suite's nginx sends for its page (captured from the
    /// fixture), with `body` and its length.
    fn nginx_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nServer: nginx/1.15.9\r\nDate: Wed, 30 Sep 2026 11:32:53 GMT\r\n\
             Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            body.len(),
            body
        )
    }

    fn parse(response: &str) -> std::io::Result<String> {
        read_http_response(&mut std::io::Cursor::new(response.as_bytes().to_vec()))
    }

    fn parse_err(response: &str) -> std::io::Error {
        parse(response).expect_err("a malformed response must be an error")
    }

    /// The request is HTTP/1.1 with CRLF line ends -- never bare LFs -- and
    /// the blank line that ends it.
    #[test]
    fn the_http_request_is_crlf_terminated() {
        assert_eq!(
            HTTP_REQUEST,
            b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        assert!(HTTP_REQUEST.ends_with(b"\r\n\r\n"));
        for (i, &b) in HTTP_REQUEST.iter().enumerate() {
            if b == b'\n' {
                assert_eq!(HTTP_REQUEST[i - 1], b'\r', "bare LF at byte {}", i);
            }
        }
    }

    /// The fixture's own response parses to its body, and a body of exactly
    /// `Content-Length` bytes is taken whole, with nothing read past it.
    #[test]
    fn the_nginx_response_parses_to_its_body() {
        let key = "7a".repeat(32);
        assert_eq!(parse(&nginx_response(&key)).unwrap(), key);
        let mut trailing = nginx_response(&key);
        trailing.push_str("unread");
        assert_eq!(parse(&trailing).unwrap(), key);
    }

    #[test]
    fn a_status_other_than_200_is_an_error() {
        for status in [
            "HTTP/1.1 404 Not Found",
            "HTTP/1.1 500 Internal Server Error",
            "HTTP/1.1 2000 OK",
            "HTTP/1.0 200 OK",
            "HTTP/1.1  200 OK",
            "garbage 200",
        ] {
            let response = nginx_response("x").replacen("HTTP/1.1 200 OK", status, 1);
            let err = parse_err(&response);
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidData,
                "{}: {}",
                status,
                err
            );
        }
    }

    /// EOF where a line should be fails the stage it happened in -- it is
    /// not a blank line and not a success.
    #[test]
    fn eof_before_the_status_or_inside_the_headers_is_an_error() {
        for (response, stage) in [
            ("", "reading the status line"),
            ("HTTP/1.1 200", "reading the status line"),
            ("HTTP/1.1 200 OK\r\n", "reading the headers"),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n",
                "reading the headers",
            ),
            ("HTTP/1.1 200 OK\r\nContent-Len", "reading the headers"),
        ] {
            let err = parse_err(response);
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::UnexpectedEof,
                "{:?}",
                response
            );
            assert!(
                err.to_string().starts_with(stage),
                "{:?}: {}",
                response,
                err
            );
        }
    }

    /// A read error is returned as itself, from the stage it happened in.
    #[test]
    fn a_read_error_is_returned_not_parsed_past() {
        struct Failing(Vec<u8>);
        impl Read for Failing {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() {
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "stalled"));
                }
                let n = buf.len().min(self.0.len());
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0.drain(..n);
                Ok(n)
            }
        }
        let full = nginx_response(&"7a".repeat(32));
        let head_end = full.find("\r\n\r\n").unwrap() + 4;
        for (cut, stage) in [
            (0, "reading the status line"),
            (full.find("\r\n").unwrap() + 2, "reading the headers"),
            (head_end, "reading the body"),
            (head_end + 10, "reading the body"),
        ] {
            let mut reader = BufReader::new(Failing(full.as_bytes()[..cut].to_vec()));
            let err = read_http_response(&mut reader).expect_err("stalled");
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::TimedOut,
                "cut at {}: {}",
                cut,
                err
            );
            assert!(
                err.to_string().starts_with(stage),
                "cut at {}: {}",
                cut,
                err
            );
        }
    }

    #[test]
    fn a_malformed_header_line_is_an_error() {
        for header in [
            "no colon here",
            ": empty name",
            "Bad Name: x",
            "Content-Length : 1",
        ] {
            let response = nginx_response("x").replacen("Server: nginx/1.15.9", header, 1);
            let err = parse_err(&response);
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidData,
                "{}: {}",
                header,
                err
            );
        }
    }

    /// Content-Length is required, must be a plain decimal, and must not
    /// contradict itself. The same value twice is accepted; zero is an
    /// empty body.
    #[test]
    fn content_length_is_required_well_formed_and_consistent() {
        let missing = nginx_response("x").replacen("Content-Length: 1\r\n", "", 1);
        assert_eq!(parse_err(&missing).kind(), std::io::ErrorKind::InvalidData);

        for value in [
            "",
            "abc",
            "-1",
            "+1",
            "1 2",
            "1:1",
            "0x10",
            "99999999999999999999999",
        ] {
            let response = nginx_response("x").replacen(
                "Content-Length: 1",
                &format!("Content-Length: {}", value),
                1,
            );
            let err = parse_err(&response);
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidData,
                "{:?}: {}",
                value,
                err
            );
        }

        let conflicting = nginx_response("x").replacen("Connection: close", "Content-Length: 2", 1);
        assert_eq!(
            parse_err(&conflicting).kind(),
            std::io::ErrorKind::InvalidData
        );

        let repeated = nginx_response("x").replacen("Connection: close", "Content-Length: 1", 1);
        assert_eq!(parse(&repeated).unwrap(), "x");

        assert_eq!(parse(&nginx_response("")).unwrap(), "");
    }

    #[test]
    fn content_length_is_case_insensitive() {
        let lower = nginx_response("abc").replacen("Content-Length", "content-length", 1);
        assert_eq!(parse(&lower).unwrap(), "abc");
        let upper = nginx_response("abc").replacen("Content-Length", "CONTENT-LENGTH", 1);
        assert_eq!(parse(&upper).unwrap(), "abc");
    }

    /// Only the first colon splits a header: a value with colons in it is
    /// ignored like any other unknown header, and a header whose *value*
    /// mentions Content-Length is not taken for one.
    #[test]
    fn a_header_value_with_colons_is_not_split_again() {
        let response = nginx_response("abc").replacen(
            "Server: nginx/1.15.9",
            "X-Note: Content-Length: 9999: not this one",
            1,
        );
        assert_eq!(parse(&response).unwrap(), "abc");
    }

    #[test]
    fn a_body_shorter_than_its_content_length_is_an_error() {
        let response = nginx_response("abcdef").replacen("abcdef", "abc", 1);
        let err = parse_err(&response);
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof, "{}", err);
        assert!(err.to_string().starts_with("reading the body"), "{}", err);
    }

    #[test]
    fn a_body_over_the_limit_is_an_error_and_is_not_allocated() {
        let at_limit = "a".repeat(HTTP_MAX_BODY);
        assert_eq!(parse(&nginx_response(&at_limit)).unwrap(), at_limit);

        let over = nginx_response("x").replacen(
            "Content-Length: 1",
            &format!("Content-Length: {}", HTTP_MAX_BODY + 1),
            1,
        );
        assert_eq!(parse_err(&over).kind(), std::io::ErrorKind::InvalidData);

        let huge =
            nginx_response("x").replacen("Content-Length: 1", "Content-Length: 4294967296", 1);
        assert_eq!(parse_err(&huge).kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_response_head_over_the_limit_is_an_error() {
        let long = format!("X-Pad: {}", "p".repeat(HTTP_MAX_HEAD));
        let response = nginx_response("x").replacen("Server: nginx/1.15.9", &long, 1);
        let err = parse_err(&response);
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{}", err);
    }

    #[test]
    fn transfer_encoding_is_refused() {
        let chunked =
            nginx_response("x").replacen("Connection: close", "Transfer-Encoding: chunked", 1);
        assert_eq!(parse_err(&chunked).kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_body_that_is_not_utf8_is_an_error() {
        let mut response = nginx_response("xy").into_bytes();
        let n = response.len();
        response[n - 1] = 0xff;
        let err = read_http_response(&mut std::io::Cursor::new(response)).expect_err("not UTF-8");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// Both directions of the exchange's socket are bounded before any I/O,
    /// at the configured timeout. Loopback only; nothing waits.
    #[test]
    fn the_http_stream_gets_read_and_write_timeouts() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        assert_eq!(stream.read_timeout().unwrap(), None);
        assert_eq!(stream.write_timeout().unwrap(), None);

        configure_http_stream(&stream, HTTP_IO_TIMEOUT).unwrap();
        assert_eq!(stream.read_timeout().unwrap(), Some(HTTP_IO_TIMEOUT));
        assert_eq!(stream.write_timeout().unwrap(), Some(HTTP_IO_TIMEOUT));
    }

    /// A timeout that cannot be set is an error naming what failed, not a
    /// socket quietly left to block. A zero duration is the one the
    /// standard library refuses outright.
    #[test]
    fn a_timeout_that_cannot_be_set_is_an_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let err = configure_http_stream(&stream, std::time::Duration::ZERO)
            .expect_err("a zero timeout is refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{}", err);
        assert!(
            err.to_string().starts_with("setting the write timeout"),
            "{}",
            err
        );
    }

    /// End to end over loopback: the exact request reaches the server, and
    /// the nginx-shaped answer comes back as the body.
    #[test]
    fn an_http_exchange_over_loopback_returns_the_body() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let key = "5c".repeat(32);
        let reply = nginx_response(&key);
        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut request = vec![0u8; HTTP_REQUEST.len()];
            conn.read_exact(&mut request).unwrap();
            conn.write_all(reply.as_bytes()).unwrap();
            request
        });
        let stream = std::net::TcpStream::connect(addr).unwrap();
        assert_eq!(http_exchange(stream, HTTP_IO_TIMEOUT).unwrap(), key);
        assert_eq!(server.join().unwrap(), HTTP_REQUEST);
    }

    /// A server that accepts and never answers fails the exchange after one
    /// timeout, at the status line, as the socket's timeout error -- not an
    /// empty body. A short timeout stands in for `HTTP_IO_TIMEOUT`; nothing
    /// asserts how long it took.
    #[test]
    fn a_silent_http_server_fails_the_status_read_with_a_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_held, _) = listener.accept().unwrap();
        let err = http_exchange(stream, std::time::Duration::from_millis(200))
            .expect_err("nothing is ever sent");
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "{:?}: {}",
            err.kind(),
            err
        );
        assert!(
            err.to_string().starts_with("reading the status line"),
            "{}",
            err
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

    /// The `set=1` reply for a failure with this errno.
    #[cfg(target_os = "linux")]
    fn uapi_errno(errno: i32) -> String {
        format!("errno={}\n\n", errno)
    }

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
    /// `Endpoint::conn` shows. It gets a diagnostic generation, as the
    /// upgrade gives one.
    #[cfg(target_os = "linux")]
    fn plant_conn(wg: &WGHandle, key: &PublicKey) -> RawFd {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.connect("127.0.0.1:9").unwrap();
        let sock = socket2::Socket::from(sock);
        let fd = sock.as_raw_fd();
        let device = wg._device.device.read();
        let mut peer = device.peers[key].lock();
        peer.endpoint_mut().conn = Some(sock);
        udp_diagnostics::commit_connected_socket(&device.udp_diag, &mut peer);
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
        // The injected refusal is a real `epoll_ctl` on an invalid epoll
        // descriptor, and its EBADF is what `set=1` reports -- neither a
        // port collision nor a permission error.
        assert_eq!(
            reply,
            uapi_errno(libc::EBADF),
            "listen_port={} is refused",
            new
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
            assert_eq!(
                reply,
                uapi_errno(libc::EADDRINUSE),
                "listen_port={} with an {} holder is refused as in use",
                new,
                family
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
        assert_eq!(
            reply,
            uapi_errno(libc::EPERM),
            "listen_port={} is refused with the mark's own errno",
            new
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
        wg._device.device.read().mark_calls().2
    }

    /// Plan SO_MARK failures from now on: `(call index, errno)` for writes
    /// and for reads, each counted from zero.
    #[cfg(target_os = "linux")]
    fn fail_marks(wg: &WGHandle, writes: &[(usize, i32)], reads: &[(usize, i32)]) {
        wg._device.device.read().fail_mark_calls(writes, reads);
    }

    /// SO_MARK `(reads, writes)` made since the last plan.
    #[cfg(target_os = "linux")]
    fn mark_calls(wg: &WGHandle) -> (usize, usize) {
        let (reads, writes, _) = wg._device.device.read().mark_calls();
        (reads, writes)
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
            assert_eq!(reply, uapi_errno(libc::EPERM), "fwmark={}", mark);
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

    /// The connected-socket marks of `peers`, sorted: what they carry, not
    /// which carries what, since peers are visited in map order.
    #[cfg(target_os = "linux")]
    fn peer_marks(wg: &WGHandle, peers: &[PublicKey]) -> Vec<u32> {
        let mut marks: Vec<u32> = peers
            .iter()
            .map(|k| peer_conn_mark(wg, k).unwrap())
            .collect();
        marks.sort();
        marks
    }

    /// Send `fwmark=<mark>` with SO_MARK failures planned, and assert it is
    /// refused with `errno`.
    #[cfg(target_os = "linux")]
    fn refused_fwmark(
        wg: &WGHandle,
        mark: u32,
        writes: &[(usize, i32)],
        reads: &[(usize, i32)],
        errno: i32,
    ) {
        fail_marks(wg, writes, reads);
        let reply = wg.wg_set(&format!("fwmark={}", mark));
        assert_eq!(
            reply,
            uapi_errno(errno),
            "fwmark={} with {:?}",
            mark,
            writes
        );
        assert!(!mark_fault_armed(wg), "every planned failure was reached");
    }

    /// Two connected peers on a keyed device with `fwmark=<old>` committed.
    #[cfg(target_os = "linux")]
    fn marked_device_with_two_peers(old: Option<u32>) -> (WGHandle, [PublicKey; 2]) {
        let wg = single_queue_device();
        assert_eq!(wg.wg_set_key(StaticSecret::random_from_rng(OsRng)), UAPI_OK);
        assert_eq!(wg.wg_set_port(free_port()), UAPI_OK);
        if let Some(old) = old {
            assert_eq!(wg.wg_set(&format!("fwmark={}", old)), UAPI_OK);
        }
        let peers = [add_connected_peer(&wg), add_connected_peer(&wg)];
        (wg, peers)
    }

    /// An `fwmark=` refused part-way puts back every socket it had already
    /// changed, and keeps the stored mark: the listeners and every peer
    /// socket end where they started, whichever stage refused.
    ///
    /// SO_MARK writes run IPv4 listener (0), IPv6 listener (1), then the two
    /// peers (2, 3) in map order; a refusal at write `k` is followed by `k`
    /// restores, newest first. Best effort only -- a restore that is itself
    /// refused is pinned by
    /// `a_refused_restore_keeps_the_original_errno_and_tries_every_socket`.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_fwmark_update_refused_part_way_is_rolled_back() {
        let (old, new) = (MARK, MARK + 1);
        let (wg, peers) = marked_device_with_two_peers(Some(old));
        assert_eq!(peer_marks(&wg, &peers), [old, old]);

        for (stage, refused) in [
            ("the IPv4 listener", 0),
            ("the IPv6 listener", 1),
            ("the first peer", 2),
            ("the second peer", 3),
        ] {
            refused_fwmark(&wg, new, &[(refused, libc::EPERM)], &[], libc::EPERM);
            assert_eq!(
                mark_calls(&wg),
                (4, 2 * refused + 1),
                "{}: 4 snapshot reads; {} forward writes, then {} restores",
                stage,
                refused + 1,
                refused
            );
            assert_eq!(stored_fwmark(&wg), Some(old), "{}", stage);
            assert_eq!(reported_fwmark(&wg), Some(old), "{}", stage);
            assert_eq!(listener_marks(&wg), (old, old), "{}", stage);
            assert_eq!(peer_marks(&wg, &peers), [old, old], "{}", stage);
        }

        // Unhindered, the update takes everywhere and is stored.
        assert_eq!(wg.wg_set(&format!("fwmark={}", new)), UAPI_OK);
        assert_eq!(stored_fwmark(&wg), Some(new));
        assert_eq!(listener_marks(&wg), (new, new));
        assert_eq!(peer_marks(&wg, &peers), [new, new]);
    }

    /// The snapshot comes before any change: a mark that cannot be read
    /// fails the update with that read's errno, and no socket is written.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_fwmark_snapshot_that_cannot_be_read_changes_nothing() {
        let (old, new) = (MARK, MARK + 1);
        let (wg, peers) = marked_device_with_two_peers(Some(old));

        // Reads: IPv4 (0), IPv6 (1), then the peers; the first peer's fails.
        refused_fwmark(&wg, new, &[], &[(2, libc::ENOBUFS)], libc::ENOBUFS);
        assert_eq!(mark_calls(&wg), (3, 0), "no socket was written");
        assert_eq!(stored_fwmark(&wg), Some(old));
        assert_eq!(listener_marks(&wg), (old, old));
        assert_eq!(peer_marks(&wg, &peers), [old, old]);
    }

    /// A rollback puts each socket back to the mark it actually carried --
    /// not to the stored mark, which after an earlier failed update need not
    /// be what the sockets carry.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_rolled_back_fwmark_restores_each_socket_to_its_own_mark() {
        let (old, new) = (MARK, MARK + 1);
        let (wg, peers) = marked_device_with_two_peers(Some(old));
        let (a, b, c, d) = (MARK + 10, MARK + 11, MARK + 12, MARK + 13);
        {
            let device = wg._device.device.read();
            device.udp4.as_ref().unwrap().set_mark(a).unwrap();
            device.udp6.as_ref().unwrap().set_mark(b).unwrap();
            for (key, mark) in peers.iter().zip([c, d]) {
                let peer = device.peers[key].lock();
                peer.endpoint()
                    .conn
                    .as_ref()
                    .unwrap()
                    .set_mark(mark)
                    .unwrap();
            }
        }
        assert_eq!(stored_fwmark(&wg), Some(old));

        // The second peer refuses: the first peer, IPv6 and IPv4 go back.
        refused_fwmark(&wg, new, &[(3, libc::EACCES)], &[], libc::EACCES);
        assert_eq!(listener_marks(&wg), (a, b));
        assert_eq!(peer_conn_mark(&wg, &peers[0]), Some(c));
        assert_eq!(peer_conn_mark(&wg, &peers[1]), Some(d));
        assert_eq!(stored_fwmark(&wg), Some(old));
    }

    /// A rollback keeps the stored mark exactly: `None` stays `None` (and
    /// unreported), `Some(0)` stays `Some(0)` (and reported as 0), and a
    /// refused `fwmark=0` puts a nonzero mark back.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_rolled_back_fwmark_keeps_none_and_zero_apart() {
        let new = MARK + 1;

        // Nothing committed: the sockets go back to 0, the device to `None`.
        let (wg, peers) = marked_device_with_two_peers(None);
        refused_fwmark(&wg, new, &[(2, libc::EPERM)], &[], libc::EPERM);
        assert_eq!(stored_fwmark(&wg), None);
        assert_eq!(reported_fwmark(&wg), None);
        assert_eq!(listener_marks(&wg), (0, 0));
        assert_eq!(peer_marks(&wg, &peers), [0, 0]);
        assert_eq!(wg.wg_set_port(free_port()), UAPI_OK);
        assert_eq!(listener_marks(&wg), (0, 0), "a rebind stays unmarked");
        assert_eq!(connect_peer(&wg, &peers[0]).0, 0);
        assert_eq!(stored_fwmark(&wg), None);

        // `Some(0)` committed: the sockets go back to 0, and 0 is reported.
        let (wg, peers) = marked_device_with_two_peers(Some(0));
        refused_fwmark(&wg, new, &[(3, libc::EPERM)], &[], libc::EPERM);
        assert_eq!(stored_fwmark(&wg), Some(0));
        assert_eq!(reported_fwmark(&wg), Some(0));
        assert_eq!(listener_marks(&wg), (0, 0));
        assert_eq!(peer_marks(&wg, &peers), [0, 0]);

        // A refused `fwmark=0` puts the nonzero mark back.
        let old = MARK;
        let (wg, peers) = marked_device_with_two_peers(Some(old));
        refused_fwmark(&wg, 0, &[(3, libc::EPERM)], &[], libc::EPERM);
        assert_eq!(stored_fwmark(&wg), Some(old));
        assert_eq!(listener_marks(&wg), (old, old));
        assert_eq!(peer_marks(&wg, &peers), [old, old]);
    }

    /// A restore can be refused too: that socket keeps the new mark, the
    /// remaining restores are still made, and the update reports the error
    /// that started it -- not the restore's.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_refused_restore_keeps_the_original_errno_and_tries_every_socket() {
        let (old, new) = (MARK, MARK + 1);
        let (wg, peers) = marked_device_with_two_peers(Some(old));

        // Writes: IPv4 (0), IPv6 (1), first peer (2) refuses with EACCES;
        // restores IPv6 (3), refused with EPERM, then IPv4 (4).
        refused_fwmark(
            &wg,
            new,
            &[(2, libc::EACCES), (3, libc::EPERM)],
            &[],
            libc::EACCES,
        );
        assert_eq!(mark_calls(&wg).1, 5, "IPv4 was still restored");
        assert_eq!(listener_marks(&wg), (old, new));
        assert_eq!(peer_marks(&wg, &peers), [old, old]);
        assert_eq!(stored_fwmark(&wg), Some(old));
        assert_eq!(wg.wg_set(&format!("fwmark={}", old)), UAPI_OK);

        // Writes: IPv4 (0), IPv6 (1), a peer (2), the other peer (3) refuses;
        // restores that peer (4, refused), IPv6 (5), IPv4 (6, refused).
        refused_fwmark(
            &wg,
            new,
            &[(3, libc::EACCES), (4, libc::EPERM), (6, libc::EPERM)],
            &[],
            libc::EACCES,
        );
        assert_eq!(mark_calls(&wg).1, 7, "every restore was attempted");
        assert_eq!(listener_marks(&wg), (new, old));
        assert_eq!(peer_marks(&wg, &peers), [old, new]);
        assert_eq!(stored_fwmark(&wg), Some(old));
    }

    /// After a refused restore leaves sockets on the new mark, resending the
    /// stored mark or the new one converges every socket, and a rebind
    /// carries the stored mark over as before.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_device_recovers_from_a_refused_restore() {
        let (old, new) = (MARK, MARK + 1);
        let (wg, peers) = marked_device_with_two_peers(Some(old));
        let mixed = |wg: &WGHandle, from: u32, to: u32| {
            refused_fwmark(
                wg,
                to,
                &[(3, libc::EACCES), (4, libc::EPERM), (6, libc::EPERM)],
                &[],
                libc::EACCES,
            );
            assert_eq!(listener_marks(wg), (to, from));
            let mut one_each = vec![from, to];
            one_each.sort();
            assert_eq!(
                peer_marks(wg, &peers),
                one_each,
                "one peer kept the new mark"
            );
            assert_eq!(stored_fwmark(wg), Some(from));
        };

        mixed(&wg, old, new);
        assert_eq!(wg.wg_set(&format!("fwmark={}", old)), UAPI_OK);
        assert_eq!(listener_marks(&wg), (old, old));
        assert_eq!(peer_marks(&wg, &peers), [old, old]);

        mixed(&wg, old, new);
        assert_eq!(wg.wg_set(&format!("fwmark={}", new)), UAPI_OK);
        assert_eq!(stored_fwmark(&wg), Some(new));
        assert_eq!(listener_marks(&wg), (new, new));
        assert_eq!(peer_marks(&wg, &peers), [new, new]);

        mixed(&wg, new, old);
        assert_eq!(wg.wg_set_port(free_port()), UAPI_OK);
        assert_eq!(listener_marks(&wg), (new, new), "the stored mark");
        for key in &peers {
            assert_eq!(connect_peer(&wg, key).0, new);
        }
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

    // The TUN read. The iface handler reads each packet into its worker's
    // whole source buffer. It used to offer only the cached MTU, which the
    // monitor refreshes once a second -- and a TUN read shorter than the
    // packet returns the start of it and drops the rest, so for up to a
    // second after an MTU increase every packet larger than the old MTU
    // reached the peer truncated, and the peer refused it. The tests below
    // put packets of known bytes into the device's TUN and read them back,
    // decrypted, at a peer running in this process.

    /// How long the MTU monitor, which runs once a second, is given to catch
    /// up with a change. A fail-safe, not a synchronisation: the waits poll
    /// the state the monitor writes and return as soon as it is there.
    #[cfg(target_os = "linux")]
    const MONITOR_WAIT: Duration = Duration::from_secs(5);

    /// Protocol 253, reserved for experimentation (RFC 3692): these packets
    /// are carried through the tunnel, never handed to an IP stack.
    #[cfg(target_os = "linux")]
    const EXPERIMENT: u8 = 253;

    /// An IPv4 packet of exactly `len` bytes, with a valid header checksum
    /// and `tag` in its identification field and its payload, so no two
    /// packets a test sends are alike.
    #[cfg(target_os = "linux")]
    fn packet_v4(src: Ipv4Addr, dst: Ipv4Addr, len: usize, tag: u16) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p[4..6].copy_from_slice(&tag.to_be_bytes());
        p[8] = 64;
        p[9] = EXPERIMENT;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let sum: u32 = p[..20]
            .chunks(2)
            .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
            .sum();
        let sum = (sum & 0xffff) + (sum >> 16);
        let sum = (sum & 0xffff) + (sum >> 16);
        p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        fill_payload(&mut p[20..], tag);
        p
    }

    /// An IPv6 packet of exactly `len` bytes; see `packet_v4`.
    #[cfg(target_os = "linux")]
    fn packet_v6(src: Ipv6Addr, dst: Ipv6Addr, len: usize, tag: u16) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        p[6] = EXPERIMENT;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        fill_payload(&mut p[40..], tag);
        p
    }

    #[cfg(target_os = "linux")]
    fn fill_payload(payload: &mut [u8], tag: u16) {
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i as u16).wrapping_mul(7).wrapping_add(tag) as u8;
        }
    }

    /// `got` is `sent`, byte for byte. Reported by length and first
    /// difference rather than by printing both packets.
    #[cfg(target_os = "linux")]
    fn assert_same(got: &[u8], sent: &[u8]) {
        if got != sent {
            let first_difference = got.iter().zip(sent).position(|(a, b)| a != b);
            panic!(
                "a {}-byte IPv{} packet arrived as {} bytes (first difference at {:?})",
                sent.len(),
                sent[0] >> 4,
                got.len(),
                first_difference
            );
        }
    }

    /// Puts packets into a TUN interface the way routed traffic gets there:
    /// the kernel sends each one out through the interface, and it queues
    /// for the device's reader. An AF_PACKET socket addressing the interface
    /// by index, with protocol 0, so it receives nothing. Like routed
    /// traffic, it is held to the interface MTU -- a larger packet is refused
    /// with EMSGSIZE -- so the device only ever reads what the interface
    /// allowed.
    #[cfg(target_os = "linux")]
    struct TunInjector {
        socket: OwnedFd,
        ifindex: libc::c_int,
    }

    #[cfg(target_os = "linux")]
    impl TunInjector {
        fn new(name: &str) -> TunInjector {
            let c_name = std::ffi::CString::new(name).unwrap();
            let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
            assert_ne!(
                ifindex,
                0,
                "if_nametoindex({}): {}",
                name,
                std::io::Error::last_os_error()
            );
            let fd =
                unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            assert!(
                fd >= 0,
                "AF_PACKET socket: {}",
                std::io::Error::last_os_error()
            );
            TunInjector {
                // SAFETY: a descriptor just returned by socket(2), owned by
                // nothing else.
                socket: unsafe { OwnedFd::from_raw_fd(fd) },
                ifindex: ifindex as libc::c_int,
            }
        }

        fn send(&self, packet: &[u8]) -> std::io::Result<()> {
            let protocol = match packet[0] >> 4 {
                4 => libc::ETH_P_IP,
                6 => libc::ETH_P_IPV6,
                version => panic!("not an IP packet: version {}", version),
            } as u16;
            // SAFETY: all-zero is a valid `sockaddr_ll`.
            let mut to: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            to.sll_family = libc::AF_PACKET as u16;
            to.sll_protocol = protocol.to_be();
            to.sll_ifindex = self.ifindex;
            // SAFETY: both pointers are valid for the lengths passed with
            // them, for the duration of the call.
            let sent = unsafe {
                libc::sendto(
                    self.socket.as_raw_fd(),
                    packet.as_ptr().cast(),
                    packet.len(),
                    0,
                    (&to as *const libc::sockaddr_ll).cast(),
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                return Err(std::io::Error::last_os_error());
            }
            assert_eq!(sent as usize, packet.len(), "a short send");
            Ok(())
        }
    }

    /// The device's peer, in this process: a `Tunn` on a loopback UDP
    /// socket, routed `v4` and `v6` inside the tunnel.
    #[cfg(target_os = "linux")]
    struct LoopbackPeer {
        tunn: Tunn,
        public: PublicKey,
        sock: UdpSocket,
        v4: Ipv4Addr,
        v6: Ipv6Addr,
    }

    #[cfg(target_os = "linux")]
    impl LoopbackPeer {
        fn new(device: PublicKey) -> LoopbackPeer {
            LoopbackPeer::new_on(device, "127.0.0.1:0")
        }

        /// As `new`, with the peer's socket bound to `bind`.
        fn new_on(device: PublicKey, bind: &str) -> LoopbackPeer {
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            let tunn = Tunn::new_with_obfuscation(
                secret,
                device,
                None,
                None,
                0x51,
                None,
                Default::default(),
                Default::default(),
            )
            .unwrap();
            let sock = UdpSocket::bind(bind).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let IpAddr::V4(v4) = next_ip() else {
                unreachable!()
            };
            let IpAddr::V6(v6) = next_ip_v6() else {
                unreachable!()
            };
            LoopbackPeer {
                tunn,
                public,
                sock,
                v4,
                v6,
            }
        }

        /// The `set=1` lines that add this peer to the device.
        fn uapi_entry(&self) -> String {
            format!(
                "public_key={}\nendpoint={}\nallowed_ip={}/32\nallowed_ip={}/128",
                encode(self.public.as_bytes()),
                self.sock.local_addr().unwrap(),
                self.v4,
                self.v6
            )
        }

        /// Answer the handshake the device starts for its first packet, and
        /// return that packet as it arrives once the session is up.
        fn accept_session(&mut self) -> Vec<u8> {
            let mut datagram = vec![0u8; MAX_UDP_SIZE];
            let mut out = vec![0u8; MAX_UDP_SIZE];
            let (n, from) = self
                .sock
                .recv_from(&mut datagram)
                .expect("no handshake initiation reached the peer");
            match self
                .tunn
                .decapsulate(Some(from.ip()), &datagram[..n], &mut out)
            {
                TunnResult::WriteToNetwork(response) => {
                    self.sock.send_to(response, from).unwrap();
                }
                other => panic!("expected a handshake initiation, got {:?}", other),
            }
            self.receive()
                .unwrap_or_else(|e| panic!("the packet that started the handshake: {}", e))
        }

        /// The next packet the device sends through the tunnel, decrypted,
        /// or what arrived instead. Keepalives are skipped. A handshake
        /// message is an error: every caller has a session up, so one would
        /// mean the device had dropped it.
        fn receive(&mut self) -> Result<Vec<u8>, String> {
            let mut datagram = vec![0u8; MAX_UDP_SIZE];
            let mut out = vec![0u8; MAX_UDP_SIZE];
            loop {
                let (n, from) = self
                    .sock
                    .recv_from(&mut datagram)
                    .map_err(|e| format!("nothing arrived: {}", e))?;
                match self
                    .tunn
                    .decapsulate(Some(from.ip()), &datagram[..n], &mut out)
                {
                    TunnResult::WriteToTunnelV4(packet, _)
                    | TunnResult::WriteToTunnelV6(packet, _) => return Ok(packet.to_vec()),
                    TunnResult::Done => {}
                    TunnResult::Err(e) => {
                        return Err(format!("a {}-byte datagram was refused: {:?}", n, e))
                    }
                    other => {
                        return Err(format!(
                            "a {}-byte datagram was not a data packet: {:?}",
                            n, other
                        ))
                    }
                }
            }
        }
    }

    /// A device on a TUN interface, with one `LoopbackPeer` and a session up
    /// between them.
    #[cfg(target_os = "linux")]
    struct TunLink {
        wg: WGHandle,
        device_public: PublicKey,
        tun: TunInjector,
        peer: LoopbackPeer,
        tag: u16,
    }

    #[cfg(target_os = "linux")]
    impl TunLink {
        /// Two workers; the interface up at an MTU of 1420.
        fn new(use_multi_queue: bool, use_connected_socket: bool) -> TunLink {
            let wg = WGHandle::init_with_config(
                next_ip(),
                next_ip_v6(),
                DeviceConfig {
                    n_threads: 2,
                    use_connected_socket,
                    use_multi_queue,
                    uapi_fd: -1,
                    ..Default::default()
                },
            );
            let secret = StaticSecret::random_from_rng(OsRng);
            let device_public = PublicKey::from(&secret);
            let peer = LoopbackPeer::new(device_public);
            assert_eq!(wg.wg_set_key(secret), UAPI_OK);
            assert_eq!(wg.wg_set(&peer.uapi_entry()), UAPI_OK);
            set_link_mtu(&wg, 1420);
            let tun = TunInjector::new(&wg.name);
            let mut link = TunLink {
                wg,
                device_public,
                tun,
                peer,
                tag: 0,
            };
            let first = link.packet_v4(64);
            link.tun.send(&first).unwrap();
            assert_same(&link.peer.accept_session(), &first);
            link
        }

        /// A packet from a source address of its own, so that each is a
        /// flow of its own. A multi-queue TUN picks the queue by flow hash:
        /// with one fixed source, every IPv4 packet went to one queue and
        /// every IPv6 packet to one queue, and the other queue's reader
        /// could go untested.
        fn packet_v4(&mut self, len: usize) -> Vec<u8> {
            self.tag += 1;
            // 198.51.100.0/24 (TEST-NET-2) and on.
            let src = Ipv4Addr::from(0xc633_6400_u32.wrapping_add(u32::from(self.tag)));
            packet_v4(src, self.peer.v4, len, self.tag)
        }

        fn packet_v6(&mut self, len: usize) -> Vec<u8> {
            self.tag += 1;
            let src = Ipv6Addr::new(0x2001, 0xdb8, 0x5, 0, 0, 0, 0, self.tag);
            packet_v6(src, self.peer.v6, len, self.tag)
        }

        /// Put an IPv4 and an IPv6 packet of `len` bytes into the TUN, and
        /// assert each reaches the peer whole.
        fn round_trip(&mut self, len: usize) {
            for packet in [self.packet_v4(len), self.packet_v6(len)] {
                self.tun.send(&packet).unwrap_or_else(|e| {
                    panic!("the kernel refused a {}-byte packet: {}", packet.len(), e)
                });
                let got = self.peer.receive().unwrap_or_else(|e| {
                    panic!(
                        "a {}-byte IPv{} packet did not arrive: {}",
                        packet.len(),
                        packet[0] >> 4,
                        e
                    )
                });
                assert_same(&got, &packet);
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn set_link_mtu(wg: &WGHandle, mtu: usize) {
        let status = run(Command::new("ip").args([
            "link",
            "set",
            "dev",
            &wg.name,
            "mtu",
            &mtu.to_string(),
            "up",
        ]))
        .expect("failed to run ip");
        assert!(status.success(), "ip link set {} mtu {}", wg.name, mtu);
    }

    /// The interface's MTU, as the kernel reports it now.
    #[cfg(target_os = "linux")]
    fn link_mtu(wg: &WGHandle) -> usize {
        wg._device.device.read().iface.mtu().unwrap()
    }

    /// Everywhere the device keeps the MTU: the value the monitor caches,
    /// and the padding clamp it pushes into the interface's AmneziaWG
    /// settings and into every peer's tunnel.
    #[cfg(target_os = "linux")]
    #[derive(Debug)]
    struct MtuSeen {
        cached: usize,
        interface_clamp: u16,
        peer_clamps: Vec<u16>,
    }

    #[cfg(target_os = "linux")]
    impl MtuSeen {
        fn everywhere(&self, mtu: usize) -> bool {
            self.cached == mtu
                && usize::from(self.interface_clamp) == mtu
                && self.peer_clamps.iter().all(|&c| usize::from(c) == mtu)
        }
    }

    #[cfg(target_os = "linux")]
    fn mtu_seen(wg: &WGHandle) -> MtuSeen {
        let device = wg._device.device.read();
        let peer_clamps = device
            .peers
            .values()
            .map(|p| p.lock().tunnel.amnezia_config().content_padding_mtu)
            .collect();
        MtuSeen {
            cached: device.mtu.load(Ordering::Relaxed),
            interface_clamp: device.config.amnezia.content_padding_mtu,
            peer_clamps,
        }
    }

    /// Block until the monitor has put `mtu` everywhere `MtuSeen` looks, or
    /// `MONITOR_WAIT` passes. Returns what was seen last, so the caller
    /// still asserts: waiting must never stand in for the assertion.
    #[cfg(target_os = "linux")]
    fn wait_for_mtu(wg: &WGHandle, mtu: usize) -> MtuSeen {
        let deadline = Instant::now() + MONITOR_WAIT;
        loop {
            let seen = mtu_seen(wg);
            if seen.everywhere(mtu) || Instant::now() >= deadline {
                return seen;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Hold the device's MTU monitor, or release it (`Device::hold_mtu`).
    /// Set under the write lock, which waits out every handler already
    /// running: a refresh in progress when this is called has finished when
    /// it returns, and none begins while the hold is on.
    #[cfg(target_os = "linux")]
    fn hold_mtu_monitor(wg: &WGHandle, hold: bool) {
        wg._device.device.read().try_writeable(
            |d| d.trigger_yield(),
            |d| {
                d.cancel_yield();
                d.hold_mtu.store(hold, Ordering::Relaxed);
            },
        );
    }

    /// After an MTU increase, a packet larger than the old MTU reaches the
    /// peer whole, IPv4 and IPv6, before the monitor has caught up.
    ///
    /// The interface goes 1420 -> 1280, the monitor is allowed to see 1280,
    /// and is then held there while the interface goes back to 1420 -- the
    /// window a real increase leaves until the next refresh, kept open for
    /// as long as the test needs it. The test cannot pass by the monitor
    /// catching up first: the cached MTU is asserted to be 1280 both before
    /// the packets go in and after they have all arrived. With the read
    /// sized by the cached MTU, the 1281-byte packet reached the peer as its
    /// first 1280 bytes, and the peer refused it (`InvalidPacket`, the IP
    /// length being longer than what arrived).
    ///
    /// Also the steady state beforehand: at a settled MTU, packets up to it
    /// arrive as they were sent.
    #[cfg(target_os = "linux")]
    fn a_packet_over_a_stale_cached_mtu_arrives_whole(
        use_multi_queue: bool,
        use_connected_socket: bool,
    ) {
        let mut link = TunLink::new(use_multi_queue, use_connected_socket);
        let seen = wait_for_mtu(&link.wg, 1420);
        assert!(
            seen.everywhere(1420),
            "the monitor never saw 1420: {:?}",
            seen
        );
        for len in [96, 1280, 1400, 1420] {
            link.round_trip(len);
        }

        set_link_mtu(&link.wg, 1280);
        let seen = wait_for_mtu(&link.wg, 1280);
        assert!(
            seen.everywhere(1280),
            "the monitor never saw 1280: {:?}",
            seen
        );
        hold_mtu_monitor(&link.wg, true);
        set_link_mtu(&link.wg, 1420);
        assert_eq!(link_mtu(&link.wg), 1420, "the interface MTU");
        assert_eq!(mtu_seen(&link.wg).cached, 1280, "the cached MTU");

        for len in [1281, 1400, 1420] {
            link.round_trip(len);
        }
        let seen = mtu_seen(&link.wg);
        assert!(
            seen.everywhere(1280),
            "the cached MTU moved while the packets went through, so they may \
             not have been read under it: {:?}",
            seen
        );

        hold_mtu_monitor(&link.wg, false);
        let seen = wait_for_mtu(&link.wg, 1420);
        assert!(
            seen.everywhere(1420),
            "released, the monitor never caught up: {:?}",
            seen
        );
        assert!(workers_alive(&link.wg));
    }

    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_packet_over_a_stale_cached_mtu_arrives_whole_multi_queue_connected() {
        a_packet_over_a_stale_cached_mtu_arrives_whole(true, true);
    }

    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_packet_over_a_stale_cached_mtu_arrives_whole_single_queue_unconnected() {
        a_packet_over_a_stale_cached_mtu_arrives_whole(false, false);
    }

    /// An MTU decrease, both ways round.
    ///
    /// Cached MTU above the interface's: the monitor is held at 1420 while
    /// the interface drops to 1280, and what the interface still lets
    /// through arrives as sent.
    ///
    /// Cached MTU below a queued packet: with the workers stopped (the
    /// write lock), 1400-byte packets go into the TUN's queue at 1420; the
    /// interface then drops to 1280, and the cached MTU follows as the
    /// monitor's next refresh would -- all before any worker runs. The
    /// kernel still hands the queued packets over whole, and the device
    /// must read them whole and send them on: an MTU change is no reason to
    /// refuse a packet the interface already accepted. With the read sized
    /// by the cached MTU, they went out cut to 1280 bytes.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_packet_queued_before_an_mtu_decrease_arrives_whole() {
        let mut link = TunLink::new(true, true);
        let seen = wait_for_mtu(&link.wg, 1420);
        assert!(
            seen.everywhere(1420),
            "the monitor never saw 1420: {:?}",
            seen
        );
        hold_mtu_monitor(&link.wg, true);

        set_link_mtu(&link.wg, 1280);
        assert_eq!(mtu_seen(&link.wg).cached, 1420, "the cached MTU");
        link.round_trip(1280);

        set_link_mtu(&link.wg, 1420);
        let queued = [link.packet_v4(1400), link.packet_v6(1400)];
        link.wg._device.device.read().try_writeable(
            |d| d.trigger_yield(),
            |d| {
                d.cancel_yield();
                for packet in &queued {
                    link.tun.send(packet).unwrap();
                }
                set_link_mtu(&link.wg, 1280);
                d.mtu.store(1280, Ordering::Relaxed);
            },
        );

        // Two queues can hand them over in either order.
        let mut arrived: Vec<Vec<u8>> = (0..queued.len())
            .map(|_| {
                link.peer.receive().unwrap_or_else(|e| {
                    panic!("a packet queued before the decrease did not arrive: {}", e)
                })
            })
            .collect();
        arrived.sort_by_key(|p| p[0] >> 4);
        for (got, sent) in arrived.iter().zip(&queued) {
            assert_same(got, sent);
        }
        assert_eq!(link_mtu(&link.wg), 1280, "the interface MTU");
        assert_eq!(mtu_seen(&link.wg).cached, 1280, "the cached MTU");

        hold_mtu_monitor(&link.wg, false);
        let seen = wait_for_mtu(&link.wg, 1280);
        assert!(
            seen.everywhere(1280),
            "released, the monitor never caught up: {:?}",
            seen
        );
        assert!(workers_alive(&link.wg));
    }

    /// The MTU monitor carries an interface MTU change to the cached MTU,
    /// the interface's padding clamp and every existing peer's; a peer added
    /// afterwards is built with it; and the session survives -- the next
    /// packets go out on it, not after a new handshake. The TUN read no
    /// longer depends on the cached MTU, so this is what keeps the monitor
    /// itself covered.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn the_mtu_monitor_carries_a_change_everywhere_and_keeps_the_session() {
        let mut link = TunLink::new(true, true);
        let seen = wait_for_mtu(&link.wg, 1420);
        assert!(
            seen.everywhere(1420),
            "the monitor never saw 1420: {:?}",
            seen
        );

        set_link_mtu(&link.wg, 1300);
        let seen = wait_for_mtu(&link.wg, 1300);
        assert!(
            seen.everywhere(1300),
            "the monitor did not carry 1300 everywhere: {:?}",
            seen
        );

        let later = LoopbackPeer::new(link.device_public);
        assert_eq!(link.wg.wg_set(&later.uapi_entry()), UAPI_OK);
        let clamp = {
            let device = link.wg._device.device.read();
            let peer = device.peers[&later.public].lock();
            peer.tunnel.amnezia_config().content_padding_mtu
        };
        assert_eq!(clamp, 1300, "the clamp of a peer added after the change");

        link.round_trip(1300);
    }

    /// A `set=1` on the stream an fd-activated device serves its UAPI on
    /// (`DeviceConfig::uapi_fd`), and the reply.
    #[cfg(target_os = "linux")]
    fn uapi_stream_set(stream: &mut UnixStream, setting: &str) -> String {
        write!(stream, "set=1\n{}\n\n", setting).unwrap();
        let mut reader = BufReader::new(&*stream);
        let mut reply = String::new();
        while !reply.ends_with("\n\n") {
            if reader.read_line(&mut reply).unwrap() == 0 {
                break;
            }
        }
        reply
    }

    /// A device on an embedder's descriptor that is not a TUN reads packets
    /// larger than its cached MTU whole.
    ///
    /// Such a descriptor refuses TUNGETIFF with ENOTTY, so `TunSocket::mtu`
    /// answers the 1500 it always has for one, and the monitor re-reads that
    /// same 1500 every second: this cached MTU never catches up with
    /// anything. So this pins the iface handler's read to the whole buffer
    /// with no monitor hold and no timing at all -- and it runs without
    /// root: the descriptor is one end of a datagram socketpair (a read
    /// shorter than a datagram drops the rest of it, as a TUN read does),
    /// and the UAPI is served on a socketpair too. With the read sized by
    /// the cached MTU, anything over 1500 bytes lost its tail for good here,
    /// not for a second.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_provided_descriptor_hands_over_packets_larger_than_its_cached_mtu_whole() {
        let (device_end, tun) = UnixDatagram::pair().unwrap();
        let (uapi_end, mut uapi) = UnixStream::pair().unwrap();
        uapi.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let device = DeviceHandle::new(
            &device_end.into_raw_fd().to_string(),
            DeviceConfig {
                n_threads: 2,
                use_connected_socket: true,
                use_multi_queue: false,
                uapi_fd: uapi_end.into_raw_fd(),
                ..Default::default()
            },
        )
        .unwrap();
        let cached = || device.device.read().mtu.load(Ordering::Relaxed);
        assert_eq!(
            cached(),
            1500,
            "the cached MTU of a descriptor that is not a TUN"
        );

        let secret = StaticSecret::random_from_rng(OsRng);
        let mut peer = LoopbackPeer::new(PublicKey::from(&secret));
        let setting = format!(
            "private_key={}\n{}",
            encode(secret.to_bytes()),
            peer.uapi_entry()
        );
        assert_eq!(uapi_stream_set(&mut uapi, &setting), UAPI_OK);

        let src_v4 = Ipv4Addr::new(192, 0, 2, 1);
        let src_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let first = packet_v4(src_v4, peer.v4, 64, 1);
        tun.send(&first).unwrap();
        assert_same(&peer.accept_session(), &first);

        for (tag, len) in [(2, 1500), (3, 1501), (4, 2000)] {
            let v4 = packet_v4(src_v4, peer.v4, len, tag);
            let v6 = packet_v6(src_v6, peer.v6, len, tag);
            for packet in [v4, v6] {
                tun.send(&packet).unwrap();
                let got = peer.receive().unwrap_or_else(|e| {
                    panic!(
                        "a {}-byte IPv{} packet did not arrive: {}",
                        len,
                        packet[0] >> 4,
                        e
                    )
                });
                assert_same(&got, &packet);
            }
        }
        assert_eq!(cached(), 1500, "the cached MTU");
    }

    // UDP send diagnostics through the real handlers. The unit tests in
    // `udp_diagnostics` run every step without root; these prove the Device's
    // handlers call them -- each concrete send site, each family -- and that
    // a failed send stays a lost datagram end to end. They assert on the
    // device's decision journal, not on captured tracing: the events come from
    // worker threads.

    #[cfg(target_os = "linux")]
    use udp_diagnostics::{
        DeviceUdpDiagnostics, DiagGen, FaultRule, JournalEvent, Line, Op, Site, SocketRef, Step,
    };

    /// Run `f` on the device's diagnostics, under its read lock.
    #[cfg(target_os = "linux")]
    fn udp_diag<R>(wg: &WGHandle, f: impl FnOnce(&DeviceUdpDiagnostics) -> R) -> R {
        let device = wg._device.device.read();
        f(&device.udp_diag)
    }

    #[cfg(target_os = "linux")]
    fn plan_udp_faults(wg: &WGHandle, rules: Vec<FaultRule>) {
        udp_diag(wg, |d| d.plan(rules));
    }

    /// One journaled attempt: site, socket, destination, injected, result.
    #[cfg(target_os = "linux")]
    type Attempted = (
        Site,
        SocketRef,
        Option<SocketAddr>,
        bool,
        Option<Result<usize, Option<i32>>>,
    );

    /// Every journaled attempt, in order.
    #[cfg(target_os = "linux")]
    fn udp_attempts(wg: &WGHandle) -> Vec<Attempted> {
        udp_diag(wg, |d| {
            d.journal()
                .into_iter()
                .filter_map(|e| match e {
                    JournalEvent::Attempt {
                        meta,
                        injected,
                        result,
                        ..
                    } => Some((meta.site, meta.socket, meta.dest, injected, result)),
                    JournalEvent::Decision { .. } => None,
                })
                .collect()
        })
    }

    /// The journal once `settled` holds of it, or as it stands at the deadline.
    ///
    /// A datagram can reach its receiver before the sending worker has
    /// journaled the attempt's result, so a test that has just received one
    /// polls instead of reading once. It never asserts: the assertions on what
    /// it returns stay the test's own, with their own messages.
    #[cfg(target_os = "linux")]
    fn settled_attempts(wg: &WGHandle, settled: impl Fn(&[Attempted]) -> bool) -> Vec<Attempted> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let attempts = udp_attempts(wg);
            if settled(&attempts) || Instant::now() >= deadline {
                return attempts;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(target_os = "linux")]
    fn udp_decisions(wg: &WGHandle) -> Vec<(Line, Option<udp_diagnostics::Class>)> {
        udp_diag(wg, |d| d.decisions())
    }

    #[cfg(target_os = "linux")]
    fn udp_count(wg: &WGHandle, line: Line) -> usize {
        udp_diag(wg, |d| d.count(line))
    }

    /// Wait for `done`, polling; panics naming `what` at the deadline.
    #[cfg(target_os = "linux")]
    fn wait_until(what: &str, timeout: Duration, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {}", what);
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(target_os = "linux")]
    fn fault(op: Op, site: Option<Site>, socket: Option<DiagGen>, script: Vec<Step>) -> FaultRule {
        FaultRule {
            op,
            site,
            socket,
            dest: None,
            script,
        }
    }

    /// The generation of the connected socket the peer commits.
    #[cfg(target_os = "linux")]
    fn conn_generation(wg: &WGHandle, key: &PublicKey) -> DiagGen {
        let device = wg._device.device.read();
        let peer = device.peers[key].lock();
        peer.assigned_connected_generation()
    }

    #[cfg(target_os = "linux")]
    fn listener_generations(wg: &WGHandle) -> (DiagGen, DiagGen) {
        let device = wg._device.device.read();
        (device.udp4_gen, device.udp6_gen)
    }

    #[cfg(target_os = "linux")]
    fn device_listener(wg: &WGHandle, family: IpAddr) -> SocketAddr {
        let port = wg._device.device.read().listen_port;
        SocketAddr::new(family, port)
    }

    /// Real shared-listener demux and connected-socket rekeying, with four
    /// different protocols behind the same source IP. Requires root and TUN.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn auto_imitation_live_listener_and_connected_sockets() {
        use crate::noise::amnezia::{AmneziaConfig, AmneziaImitationProtocol as P};
        fn network(result: TunnResult<'_>) -> Vec<u8> {
            match result {
                TunnResult::WriteToNetwork(p) => p.to_vec(),
                other => panic!("network output: {:?}", other),
            }
        }
        for connected in [false, true] {
            let config =
                AmneziaConfig::new(128, 128, 128, 128).with_protocol_imitation(P::Auto, None);
            let mut wg = WGHandle::init_with_config(
                next_ip(),
                next_ip_v6(),
                DeviceConfig {
                    n_threads: 2,
                    use_connected_socket: connected,
                    use_multi_queue: false,
                    uapi_fd: -1,
                    amnezia: config.clone(),
                    ..Default::default()
                },
            );
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            assert_eq!(wg.wg_set_key(secret), UAPI_OK);
            assert_eq!(wg.wg_set_port(next_port()), UAPI_OK);
            wg.start();
            let endpoint = device_listener(&wg, IpAddr::V4(Ipv4Addr::LOCALHOST));
            let mut clients = Vec::new();
            for (i, protocol) in [P::Dns, P::Quic, P::Sip, P::Stun]
                .iter()
                .copied()
                .enumerate()
            {
                let secret = StaticSecret::random_from_rng(OsRng);
                let key = PublicKey::from(&secret);
                assert_eq!(
                    wg.wg_set(&format!("public_key={}", encode(key.as_bytes()))),
                    UAPI_OK
                );
                let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let client_config = config.clone().with_protocol_imitation(protocol, None);
                let prelude = client_config
                    .pre_handshake_imitation_datagrams(&mut OsRng)
                    .pop_front()
                    .unwrap()
                    .1;
                socket.send_to(&prelude, endpoint).unwrap();
                let client = Tunn::new_with_obfuscation(
                    secret,
                    public,
                    None,
                    None,
                    i as u32 + 1,
                    None,
                    Default::default(),
                    client_config.as_responder(),
                )
                .unwrap();
                clients.push((client, socket, key, protocol));
            }
            for (client, socket, key, protocol) in &mut clients {
                let mut buf = [0u8; 2048];
                for rekey in [false, true] {
                    if rekey {
                        let device = wg._device.device.read();
                        let peer = device.peers[key].lock();
                        assert_eq!(peer.tunnel.imitation_protocol(), *protocol);
                        assert_eq!(peer.endpoint().conn.is_some(), connected);
                    }
                    let init = network(client.format_handshake_initiation(&mut buf, true));
                    socket.send_to(&init, endpoint).unwrap();
                    let (n, _) = socket
                        .recv_from(&mut buf)
                        .expect("an imitated handshake response");
                    let response = buf[..n].to_vec();
                    match protocol {
                        P::Dns => assert_eq!(&response[4..12], &[0, 1, 0, 0, 0, 0, 0, 1]),
                        P::Quic => assert_eq!(response[0] & 0xc0, 0x40),
                        P::Sip => assert!(
                            response.starts_with(b"OPTIONS ")
                                || response.starts_with(b"REGISTER ")
                                || response.starts_with(b"MESSAGE ")
                        ),
                        P::Stun => assert_eq!(&response[4..8], &[0x21, 0x12, 0xa4, 0x42]),
                        _ => unreachable!(),
                    }
                    let keepalive = network(client.decapsulate(None, &response, &mut buf));
                    socket.send_to(&keepalive, endpoint).unwrap();
                }
                if !connected {
                    // A replacement peer on this exact UDP endpoint must learn
                    // its new prelude, not reuse the old peer's cached hint.
                    assert_eq!(
                        wg.wg_set(&format!(
                            "public_key={}\nremove=true",
                            encode(key.as_bytes())
                        )),
                        UAPI_OK
                    );
                    assert_eq!(
                        wg.wg_set(&format!("public_key={}", encode(key.as_bytes()))),
                        UAPI_OK
                    );
                    let replacement = if *protocol == P::Dns { P::Stun } else { P::Dns };
                    let changed = config.clone().with_protocol_imitation(replacement, None);
                    let prelude = changed
                        .pre_handshake_imitation_datagrams(&mut OsRng)
                        .pop_front()
                        .unwrap()
                        .1;
                    client
                        .try_set_obfuscation(Default::default(), changed.as_responder())
                        .unwrap();
                    socket.send_to(&prelude, endpoint).unwrap();
                    let init = network(client.format_handshake_initiation(&mut buf, true));
                    socket.send_to(&init, endpoint).unwrap();
                    socket
                        .recv_from(&mut buf)
                        .expect("replacement peer response");
                    let device = wg._device.device.read();
                    assert_eq!(
                        device.peers[key].lock().tunnel.imitation_protocol(),
                        replacement,
                        "replacement must not inherit the retired peer's hint"
                    );
                    assert_eq!(
                        device.imitation_hints.get(socket.local_addr().unwrap()),
                        None,
                        "successful selection consumes its hint"
                    );
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl LoopbackPeer {
        /// Encrypt `packet` and send it to the device's listener port, from
        /// this peer's socket -- which a connected socket for this peer takes.
        fn send_to_device(&mut self, wg: &WGHandle, packet: &[u8]) {
            let mut out = vec![0u8; MAX_UDP_SIZE];
            let server = device_listener(wg, self.sock.local_addr().unwrap().ip());
            match self.tunn.encapsulate(packet, &mut out) {
                TunnResult::WriteToNetwork(datagram) => {
                    self.sock.send_to(datagram, server).unwrap();
                }
                other => panic!("the peer has a session, got {:?}", other),
            }
        }
    }

    /// A `TunLink` whose peer the device has moved to a connected socket.
    #[cfg(target_os = "linux")]
    fn connected_link() -> TunLink {
        let link = TunLink::new(false, true);
        let key = link.peer.public;
        wait_until(
            "the connected-socket upgrade",
            Duration::from_secs(5),
            || conn_fd(&link.wg, &key).is_some(),
        );
        link
    }

    /// Sites #10/#5/#6 on IPv4 and #11/#5/#6 on IPv6: a peer with no session
    /// is reached through the TUN, its initiation leaves on the listener of
    /// its endpoint's family, and the handshake response it sends back is
    /// answered with a keepalive and the queued packet, on that same listener.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn site_coverage_listener_reply_and_flush_v4_and_v6() {
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
        let secret = StaticSecret::random_from_rng(OsRng);
        let device_public = PublicKey::from(&secret);
        assert_eq!(wg.wg_set_key(secret), UAPI_OK);
        let mut p4 = LoopbackPeer::new(device_public);
        let mut p6 = LoopbackPeer::new_on(device_public, "[::1]:0");
        assert_eq!(wg.wg_set(&p4.uapi_entry()), UAPI_OK);
        assert_eq!(wg.wg_set(&p6.uapi_entry()), UAPI_OK);
        set_link_mtu(&wg, 1420);
        let tun = TunInjector::new(&wg.name);
        let (id4, id6) = listener_generations(&wg);
        let src = Ipv4Addr::new(198, 51, 100, 1);
        let first4 = packet_v4(src, p4.v4, 64, 1);
        tun.send(&first4).unwrap();
        assert_same(&p4.accept_session(), &first4);
        let first6 = packet_v4(src, p6.v4, 64, 2);
        tun.send(&first6).unwrap();
        assert_same(&p6.accept_session(), &first6);
        let ep4 = p4.sock.local_addr().unwrap();
        let ep6 = p6.sock.local_addr().unwrap();
        let saw = |attempts: &[Attempted], site: Site, gen: DiagGen, dest: SocketAddr| {
            attempts.iter().any(|(s, socket, d, injected, result)| {
                *s == site
                    && matches!(socket, SocketRef::Listener(id) if id.gen == gen)
                    && *d == Some(dest)
                    && !injected
                    && matches!(result, Some(Ok(_)))
            })
        };
        let wanted = [
            (Site::TunV4, id4, ep4),
            (Site::TunV6, id6, ep6),
            (Site::HandshakeReply, id4, ep4),
            (Site::HandshakeReply, id6, ep6),
            (Site::ListenerFlush, id4, ep4),
            (Site::ListenerFlush, id6, ep6),
        ];
        let attempts = settled_attempts(&wg, |a| wanted.iter().all(|&(s, g, d)| saw(a, s, g, d)));
        assert!(
            saw(&attempts, Site::TunV4, id4, ep4),
            "[SITE-10] TUN output on the IPv4 listener: {:?}",
            attempts
        );
        assert!(
            saw(&attempts, Site::TunV6, id6, ep6),
            "[SITE-11] TUN output on the IPv6 listener: {:?}",
            attempts
        );
        assert!(
            saw(&attempts, Site::HandshakeReply, id4, ep4),
            "[SITE-5] the keepalive answer, IPv4: {:?}",
            attempts
        );
        assert!(
            saw(&attempts, Site::HandshakeReply, id6, ep6),
            "[SITE-5] the keepalive answer, IPv6: {:?}",
            attempts
        );
        assert!(
            saw(&attempts, Site::ListenerFlush, id4, ep4),
            "[SITE-6] the queued packet, IPv4: {:?}",
            attempts
        );
        assert!(
            saw(&attempts, Site::ListenerFlush, id6, ep6),
            "[SITE-6] the queued packet, IPv6: {:?}",
            attempts
        );
        assert!(
            udp_decisions(&wg).is_empty(),
            "nothing failed, nothing logged"
        );
    }

    /// Sites #1/#2: timer output -- here the initiation a persistent
    /// keepalive starts -- on the listener of each endpoint's family.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn site_coverage_timer_v4_and_v6() {
        let wg = single_queue_device();
        assert_eq!(wg.wg_set_key(StaticSecret::random_from_rng(OsRng)), UAPI_OK);
        let (id4, id6) = listener_generations(&wg);
        let e4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let e6 = UdpSocket::bind("[::1]:0").unwrap();
        for (e, ip) in [(&e4, next_ip()), (&e6, next_ip())] {
            e.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let key = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
            let reply = wg.wg_set(&format!(
                "public_key={}\nendpoint={}\npersistent_keepalive_interval=1\nallowed_ip={}/32",
                encode(key.as_bytes()),
                e.local_addr().unwrap(),
                ip
            ));
            assert_eq!(reply, UAPI_OK);
        }
        let mut buf = [0u8; 256];
        for e in [&e4, &e6] {
            let (n, _) = e.recv_from(&mut buf).expect("a timer initiation");
            assert_eq!(n, 148);
        }
        let saw = |attempts: &[Attempted], site: Site, gen: DiagGen, dest: SocketAddr| {
            attempts.iter().any(|(s, socket, d, _, result)| {
                *s == site
                    && matches!(socket, SocketRef::Listener(id) if id.gen == gen)
                    && *d == Some(dest)
                    && matches!(result, Some(Ok(148)))
            })
        };
        let (d4, d6) = (e4.local_addr().unwrap(), e6.local_addr().unwrap());
        let attempts = settled_attempts(&wg, |a| {
            saw(a, Site::TimerV4, id4, d4) && saw(a, Site::TimerV6, id6, d6)
        });
        assert!(
            saw(&attempts, Site::TimerV4, id4, d4),
            "[SITE-1] {:?}",
            attempts
        );
        assert!(
            saw(&attempts, Site::TimerV6, id6, d6),
            "[SITE-2] {:?}",
            attempts
        );
    }

    /// Sites #3/#4: a probe reply to a DNS query and a cookie reply to an
    /// initiation under load, both on the listener they arrived on.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn site_coverage_probe_and_cookie_replies() {
        use crate::noise::amnezia::{AmneziaConfig, AmneziaImitationProtocol};
        use crate::noise::rate_limiter::RateLimiter;
        let mut wg = WGHandle::init_with_config(
            next_ip(),
            next_ip_v6(),
            DeviceConfig {
                n_threads: 2,
                use_connected_socket: false,
                use_multi_queue: false,
                uapi_fd: -1,
                amnezia: AmneziaConfig::default().with_protocol_imitation(
                    AmneziaImitationProtocol::Dns,
                    Some("example.com".to_owned()),
                ),
                probe_reply_bytes_per_sec: Some(crate::device::DEFAULT_PROBE_REPLY_BYTES_PER_SEC),
                ..Default::default()
            },
        );
        let secret = StaticSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&secret);
        assert_eq!(wg.wg_set_key(secret), UAPI_OK);
        wg.start();
        let (id4, _) = listener_generations(&wg);
        // The probe door refuses loopback sources; the TUN's own address is
        // local and not loopback.
        let IpAddr::V4(own) = wg.addr_v4 else {
            unreachable!()
        };
        let prober = UdpSocket::bind((own, 0)).unwrap();
        prober
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let query = crate::noise::imitation::dns::generate("example.com", &mut OsRng)
            .into_iter()
            .next()
            .unwrap();
        prober
            .send_to(&query, device_listener(&wg, IpAddr::V4(own)))
            .unwrap();
        let mut rx = [0u8; 2048];
        prober.recv_from(&mut rx).expect("a DNS probe reply");
        // Under load: every handshake draws a cookie reply.
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
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        client_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut client = Tunn::new_with_obfuscation(
            StaticSecret::random_from_rng(OsRng),
            server_public,
            None,
            None,
            0x77,
            None,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        let mut buf = vec![0u8; 2048];
        let init = match client.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(d) => d.to_vec(),
            other => panic!("expected an initiation, got {:?}", other),
        };
        client_sock
            .send_to(&init, device_listener(&wg, IpAddr::V4(Ipv4Addr::LOCALHOST)))
            .unwrap();
        let (n, _) = client_sock.recv_from(&mut rx).expect("a cookie reply");
        assert_eq!(n, 64, "a vanilla cookie reply");
        let saw = |attempts: &[Attempted], site: Site, dest: SocketAddr| {
            attempts.iter().any(|(s, socket, d, _, result)| {
                *s == site
                    && matches!(socket, SocketRef::Listener(id) if id.gen == id4)
                    && *d == Some(dest)
                    && matches!(result, Some(Ok(_)))
            })
        };
        let (from_prober, from_client) = (
            prober.local_addr().unwrap(),
            client_sock.local_addr().unwrap(),
        );
        let attempts = settled_attempts(&wg, |a| {
            saw(a, Site::ProbeReply, from_prober) && saw(a, Site::CookieReply, from_client)
        });
        assert!(
            saw(&attempts, Site::ProbeReply, from_prober),
            "[SITE-3] {:?}",
            attempts
        );
        assert!(
            saw(&attempts, Site::CookieReply, from_client),
            "[SITE-4] {:?}",
            attempts
        );
    }

    /// Sites #9/#7/#8 and the connected receive: TUN output on the connected
    /// socket; a datagram from the peer received on it; then, the device's
    /// session dropped by a preshared-key change, a TUN packet queued behind
    /// a new initiation, whose response arrives on the connected socket and
    /// is answered there with a keepalive and the queued packet.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn site_coverage_connected_reply_flush_and_recv() {
        let mut link = connected_link();
        let key = link.peer.public;
        let gen = conn_generation(&link.wg, &key);
        assert!(
            matches!(gen, DiagGen::Tracked(_)),
            "the upgrade assigned a generation"
        );
        let packet = link.packet_v4(80);
        link.tun.send(&packet).unwrap();
        assert_same(&link.peer.receive().unwrap(), &packet);
        let inbound = packet_v4(link.peer.v4, Ipv4Addr::new(198, 51, 100, 9), 60, 77);
        link.peer.send_to_device(&link.wg, &inbound);
        wait_until(
            "a datagram received on the connected socket",
            Duration::from_secs(5),
            || {
                udp_attempts(&link.wg)
                    .iter()
                    .any(|(s, _, _, _, r)| *s == Site::ConnectedRecv && matches!(r, Some(Ok(_))))
            },
        );
        let psk = [0x5au8; 32];
        assert_eq!(
            link.wg.wg_set(&format!(
                "public_key={}\npreshared_key={}",
                encode(key.as_bytes()),
                encode(psk)
            )),
            UAPI_OK
        );
        link.peer.tunn.set_preshared_key(Some(psk));
        assert_eq!(
            conn_generation(&link.wg, &key),
            gen,
            "the same connected socket"
        );
        let queued = link.packet_v4(90);
        link.tun.send(&queued).unwrap();
        assert_same(&link.peer.accept_session(), &queued);
        let peer_addr = link.peer.sock.local_addr().unwrap();
        let saw = |attempts: &[Attempted], site: Site| {
            attempts.iter().any(|(s, socket, d, _, result)| {
                *s == site
                    && *socket == SocketRef::Connected(gen)
                    && *d == Some(peer_addr)
                    && matches!(result, Some(Ok(_)))
            })
        };
        let sites = [
            Site::TunConnected,
            Site::ConnectedRecv,
            Site::ConnectedReply,
            Site::ConnectedFlush,
        ];
        let attempts = settled_attempts(&link.wg, |a| sites.iter().all(|&s| saw(a, s)));
        assert!(
            saw(&attempts, Site::TunConnected),
            "[SITE-9] {:?}",
            attempts
        );
        assert!(
            saw(&attempts, Site::ConnectedRecv),
            "[SITE-R] {:?}",
            attempts
        );
        assert!(
            saw(&attempts, Site::ConnectedReply),
            "[SITE-7] {:?}",
            attempts
        );
        assert!(
            saw(&attempts, Site::ConnectedFlush),
            "[SITE-8] {:?}",
            attempts
        );
        assert!(udp_decisions(&link.wg).is_empty());
    }

    /// M6/M12 end to end: a receive success and the quiet end of the batch
    /// that follows it are not a recovery; only a later send on the same
    /// socket is.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_quiet_receive_end_does_not_close_a_send_failure_episode() {
        let mut link = connected_link();
        let key = link.peer.public;
        let gen = conn_generation(&link.wg, &key);
        plan_udp_faults(
            &link.wg,
            vec![fault(
                Op::Send,
                Some(Site::TunConnected),
                Some(gen),
                vec![Step::Fail(libc::ENETUNREACH)],
            )],
        );
        let lost = link.packet_v4(70);
        link.tun.send(&lost).unwrap();
        wait_until("the failed send", Duration::from_secs(5), || {
            udp_count(&link.wg, Line::WarnOpening) == 1
        });
        let inbound = packet_v4(link.peer.v4, Ipv4Addr::new(198, 51, 100, 9), 60, 78);
        link.peer.send_to_device(&link.wg, &inbound);
        wait_until(
            "the receive and its quiet end",
            Duration::from_secs(5),
            || {
                let a = udp_attempts(&link.wg);
                a.iter()
                    .any(|(s, _, _, _, r)| *s == Site::ConnectedRecv && matches!(r, Some(Ok(_))))
                    && a.iter().any(|(s, _, _, _, r)| {
                        *s == Site::ConnectedRecv && matches!(r, Some(Err(_)))
                    })
            },
        );
        assert_eq!(
            udp_count(&link.wg, Line::DebugRecovery),
            0,
            "[M6] [M12] no recovery from receiving"
        );
        assert!(
            link.wg._device.device.read().peers[&key]
                .lock()
                .udp_diagnostics()
                .connected_active(),
            "[M6] the episode is still open"
        );
        let next = link.packet_v4(70);
        link.tun.send(&next).unwrap();
        assert_same(&link.peer.receive().unwrap(), &next);
        wait_until("the recovery", Duration::from_secs(5), || {
            udp_count(&link.wg, Line::DebugRecovery) == 1
        });
    }

    /// M15 end to end: once the peer no longer commits the socket -- here
    /// taken without a shutdown, the state a refused registration leaves --
    /// the still-registered handler's error is teardown, not a defect.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_retired_connected_handler_reports_teardown_not_a_defect() {
        let mut link = connected_link();
        let key = link.peer.public;
        let gen = conn_generation(&link.wg, &key);
        drop_conn(&link.wg, &key);
        plan_udp_faults(
            &link.wg,
            vec![fault(
                Op::Recv,
                None,
                Some(gen),
                vec![Step::Fail(libc::EBADF)],
            )],
        );
        let inbound = packet_v4(link.peer.v4, Ipv4Addr::new(198, 51, 100, 9), 60, 79);
        link.peer.send_to_device(&link.wg, &inbound);
        wait_until(
            "[M15] the retired handler's error",
            Duration::from_secs(5),
            || udp_count(&link.wg, Line::DebugRetired) == 1,
        );
        assert_eq!(
            udp_count(&link.wg, Line::ErrorConnected),
            0,
            "[M15] no lifecycle ERROR"
        );
        assert!(
            !link.wg._device.device.read().peers[&key]
                .lock()
                .udp_diagnostics()
                .connected_active(),
            "[M15] the record is untouched"
        );
    }

    /// Test 21: an error from the connected receive ends that batch and is
    /// reported, and nothing else: the socket stays committed, its handler
    /// registered, and the datagram behind the error is still read.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_connected_recv_error_keeps_the_socket_and_its_handler() {
        let mut link = connected_link();
        let key = link.peer.public;
        let gen = conn_generation(&link.wg, &key);
        let fd = conn_fd(&link.wg, &key);
        plan_udp_faults(
            &link.wg,
            vec![fault(
                Op::Recv,
                None,
                Some(gen),
                vec![Step::Fail(libc::ECONNREFUSED)],
            )],
        );
        let inbound = packet_v4(link.peer.v4, Ipv4Addr::new(198, 51, 100, 9), 60, 80);
        link.peer.send_to_device(&link.wg, &inbound);
        wait_until(
            "the datagram behind the error",
            Duration::from_secs(5),
            || {
                udp_attempts(&link.wg).iter().any(|(s, _, _, injected, r)| {
                    *s == Site::ConnectedRecv && !injected && matches!(r, Some(Ok(_)))
                })
            },
        );
        assert_eq!(
            udp_decisions(&link.wg),
            vec![(Line::WarnOpening, Some(udp_diagnostics::Class::Refused))],
            "one refused WARN"
        );
        assert_eq!(
            conn_fd(&link.wg, &key),
            fd,
            "the connected socket stays committed"
        );
        assert_eq!(conn_generation(&link.wg, &key), gen);
        let packet = link.packet_v4(80);
        link.tun.send(&packet).unwrap();
        assert_same(&link.peer.receive().unwrap(), &packet);
        assert!(workers_alive(&link.wg));
    }

    /// Test 23: a failed transport send is lost, as on the network: the next
    /// packet goes out, the failed one never does, and nothing is sent twice.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_failed_transport_send_is_not_retried_or_requeued() {
        let mut link = connected_link();
        let key = link.peer.public;
        let gen = conn_generation(&link.wg, &key);
        plan_udp_faults(
            &link.wg,
            vec![fault(
                Op::Send,
                Some(Site::TunConnected),
                Some(gen),
                vec![Step::Fail(libc::ENOBUFS)],
            )],
        );
        let before = udp_attempts(&link.wg).len();
        let lost = link.packet_v4(100);
        link.tun.send(&lost).unwrap();
        wait_until("the failed send", Duration::from_secs(5), || {
            udp_attempts(&link.wg).len() > before
        });
        let next = link.packet_v4(100);
        link.tun.send(&next).unwrap();
        assert_same(&link.peer.receive().unwrap(), &next);
        link.peer
            .sock
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        assert!(
            link.peer.receive().is_err(),
            "[T23] the failed packet never arrives"
        );
        let tun: Vec<_> = udp_attempts(&link.wg)
            .into_iter()
            .skip(before)
            .filter(|(s, ..)| *s == Site::TunConnected)
            .collect();
        assert_eq!(tun.len(), 2, "[T23] two packets, two attempts: {:?}", tun);
        assert!(
            tun[0].3 && !tun[1].3,
            "[T23] the first injected, the second real"
        );
    }

    /// Test 24: a failed initiation send does not move the retransmission:
    /// the timer resends it on schedule, on the listener.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_failed_initiation_send_keeps_the_retransmission_schedule() {
        let mut wg = single_queue_device();
        assert_eq!(wg.wg_set_key(StaticSecret::random_from_rng(OsRng)), UAPI_OK);
        wg.start();
        let peer = TunPeer::add(&wg);
        let (id4, _) = listener_generations(&wg);
        plan_udp_faults(
            &wg,
            vec![fault(
                Op::Send,
                Some(Site::TunV4),
                Some(id4),
                vec![Step::Fail(libc::EHOSTUNREACH)],
            )],
        );
        UdpSocket::bind("0.0.0.0:0")
            .unwrap()
            .send_to(b"through the tunnel", (peer.ip, 9))
            .unwrap();
        let started = Instant::now();
        let mut buf = [0u8; 256];
        let (n, _) = peer
            .endpoint
            .recv_from(&mut buf)
            .expect("[T24] the retransmission reaches the peer");
        assert_eq!(n, 148, "an initiation");
        assert!(
            started.elapsed() >= Duration::from_secs(4),
            "[T24] the resend waited for REKEY_TIMEOUT: {:?}",
            started.elapsed()
        );
        let attempts = udp_attempts(&wg);
        assert_eq!(
            attempts.iter().filter(|(s, ..)| *s == Site::TunV4).count(),
            1,
            "[T24] the failed initiation was attempted once"
        );
        assert!(
            attempts.iter().any(|(s, ..)| *s == Site::TimerV4),
            "[T24] the timer resent it"
        );
    }

    /// Test 25: a failed Jc junk send is not sent again: the burst goes on
    /// with the next junk and the initiation.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_failed_junk_send_is_not_reemitted() {
        let mut wg = single_queue_device();
        assert_eq!(wg.wg_set_key(StaticSecret::random_from_rng(OsRng)), UAPI_OK);
        assert_eq!(wg.wg_set("jc=3\njmin=100\njmax=100"), UAPI_OK);
        wg.start();
        let peer = TunPeer::add(&wg);
        let endpoint = peer.endpoint.local_addr().unwrap();
        let (id4, _) = listener_generations(&wg);
        plan_udp_faults(
            &wg,
            vec![FaultRule {
                op: Op::Send,
                site: None,
                socket: Some(id4),
                dest: Some(endpoint),
                script: vec![Step::Pass, Step::Fail(libc::ENOBUFS)],
            }],
        );
        UdpSocket::bind("0.0.0.0:0")
            .unwrap()
            .send_to(b"through the tunnel", (peer.ip, 9))
            .unwrap();
        let mut buf = [0u8; 2048];
        let mut lens = Vec::new();
        while lens.last() != Some(&148) {
            let (n, _) = peer
                .endpoint
                .recv_from(&mut buf)
                .expect("the burst and its initiation");
            lens.push(n);
        }
        assert_eq!(
            lens,
            vec![100, 100, 148],
            "[T25] junk, junk, initiation: the failed junk is gone"
        );
        let attempts = udp_attempts(&wg);
        let to_peer: Vec<_> = attempts
            .iter()
            .filter(|(_, _, d, ..)| *d == Some(endpoint))
            .collect();
        assert_eq!(
            to_peer.len(),
            4,
            "[T25] four datagrams produced, each attempted once: {:?}",
            to_peer
        );
        assert!(to_peer[1].3, "[T25] the second was the injected failure");
    }

    /// A lifecycle error -- an invalid-socket-state errno on a live listener
    /// -- is reported, once, and every worker carries on.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn an_injected_lifecycle_error_does_not_take_a_worker_down() {
        let mut wg = single_queue_device();
        assert_eq!(wg.wg_set_key(StaticSecret::random_from_rng(OsRng)), UAPI_OK);
        wg.start();
        let (id4, _) = listener_generations(&wg);
        plan_udp_faults(
            &wg,
            vec![fault(
                Op::Send,
                Some(Site::TunV4),
                Some(id4),
                vec![Step::Fail(libc::EBADF)],
            )],
        );
        let first = TunPeer::add(&wg);
        UdpSocket::bind("0.0.0.0:0")
            .unwrap()
            .send_to(b"through the tunnel", (first.ip, 9))
            .unwrap();
        wait_until("the lifecycle ERROR", Duration::from_secs(5), || {
            udp_count(&wg, Line::ErrorListener) == 1
        });
        assert!(workers_alive(&wg), "no worker went down");
        let second = TunPeer::add(&wg);
        second.dispatch();
        assert!(workers_alive(&wg));
        assert_eq!(udp_count(&wg, Line::ErrorListener), 1);
    }

    /// A rebind gives the listener pair fresh generations, and the listener
    /// lifecycle latch is per generation: one ERROR before, one after.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn a_rebind_gives_the_listeners_new_generations_and_a_fresh_listener_latch() {
        let mut wg = single_queue_device();
        assert_eq!(wg.wg_set_key(StaticSecret::random_from_rng(OsRng)), UAPI_OK);
        wg.start();
        let (a4, a6) = listener_generations(&wg);
        assert!(matches!(a4, DiagGen::Tracked(_)) && matches!(a6, DiagGen::Tracked(_)));
        assert_ne!(a4, a6);
        plan_udp_faults(
            &wg,
            vec![fault(
                Op::Send,
                Some(Site::TunV4),
                None,
                vec![Step::Fail(libc::EBADF); 2],
            )],
        );
        for _ in 0..2 {
            let p = TunPeer::add(&wg);
            UdpSocket::bind("0.0.0.0:0")
                .unwrap()
                .send_to(b"through the tunnel", (p.ip, 9))
                .unwrap();
        }
        wait_until("two failed sends", Duration::from_secs(5), || {
            udp_attempts(&wg)
                .iter()
                .filter(|(s, ..)| *s == Site::TunV4)
                .count()
                == 2
        });
        assert_eq!(
            udp_count(&wg, Line::ErrorListener),
            1,
            "once per listener generation"
        );
        assert_eq!(wg.wg_set_port(free_port()), UAPI_OK);
        let (b4, b6) = listener_generations(&wg);
        assert!(
            b4 != a4 && b6 != a6 && b4 != b6,
            "fresh generations, never reused"
        );
        plan_udp_faults(
            &wg,
            vec![fault(
                Op::Send,
                Some(Site::TunV4),
                Some(b4),
                vec![Step::Fail(libc::EBADF)],
            )],
        );
        let p = TunPeer::add(&wg);
        UdpSocket::bind("0.0.0.0:0")
            .unwrap()
            .send_to(b"through the tunnel", (p.ip, 9))
            .unwrap();
        wait_until("the new generation's ERROR", Duration::from_secs(5), || {
            udp_count(&wg, Line::ErrorListener) == 2
        });
    }
}
