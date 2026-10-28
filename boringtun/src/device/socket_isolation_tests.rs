// Copyright (c) 2026 Vadim Smirnov (doing business as WireSock). All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::*;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::os::fd::IntoRawFd;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::time::{Duration, Instant};

fn child_output(command: &mut std::process::Command) -> std::process::Output {
    use std::process::Stdio;
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "child timed out: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn device() -> (Device, UnixDatagram, UnixStream) {
    let (tun, tun_peer) = UnixDatagram::pair().unwrap();
    let (api, api_peer) = UnixStream::pair().unwrap();
    let device = Device::new(
        &tun.into_raw_fd().to_string(),
        DeviceConfig {
            n_threads: 2,
            uapi_fd: api.into_raw_fd(),
            ..Default::default()
        },
    )
    .unwrap();
    (device, tun_peer, api_peer)
}

fn peer(addr: SocketAddr) -> Peer {
    let key = x25519::StaticSecret::random_from_rng(OsRng);
    let remote = x25519::PublicKey::from(&x25519::StaticSecret::random_from_rng(OsRng));
    Peer::new(
        Tunn::new(key, remote, None, None, 1, None, 1, 1, 2, 2, 3, 3, 4, 4).unwrap(),
        1,
        Some(addr),
        None,
    )
}

fn assert_isolated(socket: &socket2::Socket) {
    assert!(
        !socket.reuse_address().unwrap(),
        "SO_REUSEADDR bypasses the UID ownership check"
    );
    assert!(socket.reuse_port().unwrap());
}

#[test]
fn second_spawn_failure_cannot_start_a_worker_on_partial_uapi_input() {
    let (d, _tun, mut api) = device();
    let api_fd = d.uapi_fd;
    api.write_all(b"set=1\nlisten_port=").unwrap();
    let ifaces = vec![Arc::clone(&d.iface), Arc::clone(&d.iface)];
    let queue = Arc::downgrade(&d.queue);
    let (send, receive) = std::sync::mpsc::channel();
    let startup = thread::spawn(move || {
        let mut spawned = false;
        let result = DeviceHandle::start_workers(d, ifaces, |work| {
            if !spawned {
                spawned = true;
                thread::Builder::new().spawn(work)
            } else {
                // On the broken implementation, wait for the first worker to
                // consume the partial frame and block. A gated worker cannot
                // consume it, so the injected failure follows the deadline.
                let deadline = Instant::now() + Duration::from_millis(200);
                loop {
                    let mut unread: libc::c_int = 0;
                    assert_eq!(
                        unsafe { libc::ioctl(api_fd, libc::FIONREAD, &mut unread) },
                        0
                    );
                    if unread == 0 || Instant::now() >= deadline {
                        break;
                    }
                    thread::yield_now();
                }
                Err(io::Error::from_raw_os_error(libc::EAGAIN))
            }
        });
        send.send(result.map(|_| ())).unwrap();
    });
    let result = receive.recv_timeout(Duration::from_secs(2));
    // Unblock the old implementation even on a red test, so no test thread
    // is left holding a device guard or leaking a worker.
    api.shutdown(std::net::Shutdown::Both).ok();
    startup.join().unwrap();
    assert!(matches!(result, Ok(Err(Error::IoError(e))) if e.raw_os_error() == Some(libc::EAGAIN)));
    assert!(queue.upgrade().is_none());
}

#[test]
fn inherited_descriptors_survive_preparation_and_start_after_the_transition() {
    for multi_queue in [false, true] {
        let (mut d, tun, mut api) = device();
        d.config.n_threads = 4;
        d.config.use_multi_queue = multi_queue;
        d.config.use_connected_socket = false;
        api.set_nonblocking(true).unwrap();
        // A complete request is already waiting, but no worker may run yet.
        api.write_all(b"set=1\nlisten_port=0\n\n").unwrap();
        let mut handle = DeviceHandle::start_device(d, |d, ifaces| {
            assert_eq!(ifaces.len(), 4);
            assert!(ifaces.iter().all(|iface| Arc::ptr_eq(iface, &d.iface)));
            assert!(d.udp4.is_none() && d.udp6.is_none());
            assert_eq!(d.listen_port, 0);
            assert_eq!(
                api.read(&mut [0; 32]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            Ok(())
        })
        .unwrap();
        api.set_nonblocking(false).unwrap();
        api.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut reply = [0; 9];
        api.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"errno=0\n\n");
        assert_eq!(handle.threads.len(), 4);
        assert!(handle.threads.iter().all(|t| !t.is_finished()));
        assert_isolated(handle.device.read().udp4.as_ref().unwrap());
        handle.device.read().trigger_exit();
        handle.wait();
        // The device still owns its inherited descriptors after all workers stop.
        assert!(tun.send(b"still owned").is_ok());
    }
}

#[test]
fn failed_transition_releases_descriptors_and_cleans_published_paths() {
    let (mut d, tun, mut api) = device();
    let path = std::env::temp_dir().join(format!("bt-startup-cleanup-{}", std::process::id()));
    std::fs::write(&path, b"published startup file").unwrap();
    d.cleanup_paths.push(path.to_str().unwrap().to_owned());
    let iface = Arc::downgrade(&d.iface);
    let queue = Arc::downgrade(&d.queue);
    let result = DeviceHandle::start_device(d, |d, ifaces| {
        assert_eq!(ifaces.len(), 2);
        assert!(d.udp4.is_none());
        Err(Error::DropPrivileges("injected transition failure".into()))
    });
    assert!(matches!(result, Err(Error::DropPrivileges(_))));
    assert!(iface.upgrade().is_none() && queue.upgrade().is_none());
    assert!(!path.exists());
    api.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    assert_eq!(api.read(&mut [0; 1]).unwrap(), 0);
    assert!(tun.send(b"closed").is_err());
}

// Runs only in the existing privileged Linux integration job. Changes the
// credentials of a child process, never host accounts, capabilities or policy.
#[test]
#[ignore = "requires root to launch a child under a different UID"]
fn different_uid_cannot_join_listener_ports() {
    const PORT: &str = "BT_TEST_ISOLATION_PORT";
    if let Ok(port) = std::env::var(PORT) {
        assert_ne!(unsafe { libc::geteuid() }, 0);
        let port: u16 = port.parse().unwrap();
        for ip in [
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            for (addr, reuseport) in [(true, false), (false, true), (true, true)] {
                let socket = socket2::Socket::new(
                    Domain::for_address(SocketAddr::new(ip, port)),
                    Type::DGRAM,
                    Some(Protocol::UDP),
                )
                .unwrap();
                socket.set_reuse_address(addr).unwrap();
                socket.set_reuse_port(reuseport).unwrap();
                assert_eq!(
                    socket
                        .bind(&SocketAddr::new(ip, port).into())
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EADDRINUSE),
                    "contender {:?}, flags {:?}",
                    ip,
                    (addr, reuseport)
                );
                socket.bind(&SocketAddr::new(ip, 0).into()).unwrap();
            }
        }
        return;
    }
    use std::os::unix::process::CommandExt;
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run only in a privileged test environment"
    );
    let (mut d, _tun, _api) = device();
    d.open_listen_socket(0).unwrap();
    let output = child_output(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "device::socket_isolation_tests::different_uid_cannot_join_listener_ports",
                "--ignored",
                "--nocapture",
            ])
            .env(PORT, d.listen_port.to_string())
            .uid(65534)
            .gid(65534),
    );
    assert!(
        output.status.success(),
        "child: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires root and a disposable TUN interface"]
fn named_queue_failure_cleans_startup_resources() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let name = format!("btqf{}", std::process::id());
    let d = Device::new(
        &name,
        DeviceConfig {
            n_threads: 3,
            ..Default::default()
        },
    )
    .unwrap();
    let paths = d.cleanup_paths.clone();
    assert!(!paths.is_empty());
    let iface = Arc::downgrade(&d.iface);
    let queue = Arc::downgrade(&d.queue);
    d.queue.fail_next_registration();
    let result = DeviceHandle::start_device(d, |_, _| panic!("must fail before the transition"));
    assert!(matches!(result, Err(Error::EventQueue(e)) if e.raw_os_error() == Some(libc::EBADF)));
    assert!(iface.upgrade().is_none() && queue.upgrade().is_none());
    assert!(paths
        .iter()
        .all(|path| !std::path::Path::new(path).exists()));
}

#[test]
#[ignore = "requires root to prepare TUN queues and lower a child's UID"]
fn prepared_queues_and_uapi_work_after_the_child_drops_privileges() {
    const CHILD: &str = "BT_TEST_STARTUP_DROP_CHILD";
    assert_eq!(unsafe { libc::geteuid() }, 0);
    if let Ok(mode) = std::env::var(CHILD) {
        let multi_queue = mode.starts_with("multi-");
        let connected = mode.ends_with("-connected");
        // All address/route setup stays inside this throwaway child netns,
        // which vanishes with its last process/socket. No host policy changes.
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
        ip(&["link", "set", "lo", "up"]);
        let (api, mut client) = UnixStream::pair().unwrap();
        let name = format!("btdr{}", std::process::id());
        let mut handle = DeviceHandle::new_with_startup(
            &name,
            DeviceConfig {
                n_threads: 3,
                use_multi_queue: multi_queue,
                use_connected_socket: connected,
                uapi_fd: api.into_raw_fd(),
                ..Default::default()
            },
            |d, ifaces| {
                assert!(d.udp4.is_none() && d.udp6.is_none());
                assert_eq!(ifaces.len(), 3);
                let fds: std::collections::HashSet<_> =
                    ifaces.iter().map(|iface| iface.as_raw_fd()).collect();
                assert_eq!(fds.len(), if multi_queue { 3 } else { 1 });
                ip(&["address", "add", "198.18.109.1/24", "dev", &name]);
                ip(&["link", "set", "dev", &name, "up"]);
                // Only this throwaway child changes credentials. No retained
                // capabilities, account changes or firewall setup.
                assert_eq!(unsafe { libc::setgroups(0, std::ptr::null()) }, 0);
                assert_eq!(unsafe { libc::setgid(65534) }, 0);
                assert_eq!(unsafe { libc::setuid(65534) }, 0);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(unsafe { libc::geteuid() }, 65534);
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client.write_all(b"set=1\nlisten_port=0\n\n").unwrap();
        let mut reply = [0; 9];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"errno=0\n\n");
        {
            let d = handle.device.read();
            for ip in [
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ] {
                let remote = UdpSocket::bind((ip, 0)).unwrap();
                let p = peer(remote.local_addr().unwrap());
                let conn = p.connect_endpoint(d.listen_port, None).unwrap();
                let listener = if ip.is_ipv4() {
                    d.udp4.as_ref().unwrap()
                } else {
                    d.udp6.as_ref().unwrap()
                };
                for socket in [listener, &conn] {
                    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
                    assert_eq!(unsafe { libc::fstat(socket.as_raw_fd(), &mut stat) }, 0);
                    assert_eq!(stat.st_uid, 65534);
                    assert_isolated(socket);
                }
                remote.send_to(b"after drop", (ip, d.listen_port)).unwrap();
                assert_eq!(receive(&conn).0, b"after drop");
            }
        }
        tun_round_trip(&handle, &mut client, connected);
        handle.device.read().trigger_exit();
        handle.wait();
        return;
    }
    for mode in [
        "multi-connected",
        "single-connected",
        "multi-unconnected",
        "single-unconnected",
    ] {
        let output = child_output(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "device::socket_isolation_tests::prepared_queues_and_uapi_work_after_the_child_drops_privileges", "--ignored", "--nocapture"])
            .env(CHILD, mode));
        assert!(
            output.status.success(),
            "{} child: {}{}",
            mode,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn ip(args: &[&str]) {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ip {:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn tun_round_trip(handle: &DeviceHandle, api: &mut UnixStream, connected: bool) {
    let local_key = x25519::StaticSecret::random_from_rng(OsRng);
    let remote_key = x25519::StaticSecret::random_from_rng(OsRng);
    let remote_public = x25519::PublicKey::from(&remote_key);
    let endpoint = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    endpoint
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        api,
        "set=1\nprivate_key={}\npublic_key={}\nendpoint={}\nallowed_ip=198.18.109.2/32\n\n",
        hex::encode(local_key.to_bytes()),
        hex::encode(remote_public.as_bytes()),
        endpoint.local_addr().unwrap()
    )
    .unwrap();
    let mut reply = [0; 9];
    api.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"errno=0\n\n");
    let mut remote = Tunn::new(
        remote_key,
        x25519::PublicKey::from(&local_key),
        None,
        None,
        7,
        None,
        1,
        1,
        2,
        2,
        3,
        3,
        4,
        4,
    )
    .unwrap();
    let application = UdpSocket::bind((Ipv4Addr::new(198, 18, 109, 1), 0)).unwrap();
    application
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let target = SocketAddr::from((Ipv4Addr::new(198, 18, 109, 2), 8080));
    // The kernel routes this into the real TUN. A worker must read it, start
    // the handshake and flush its encrypted payload after the reply arrives.
    application.send_to(b"postdrop", target).unwrap();
    let mut wire = [0; 2048];
    let mut scratch = [0; 2048];
    let (n, device_endpoint) = endpoint.recv_from(&mut wire).unwrap();
    assert_eq!(&wire[..4], &[1, 0, 0, 0]);
    match remote.decapsulate(None, &wire[..n], &mut scratch) {
        TunnResult::WriteToNetwork(response) => {
            endpoint.send_to(response, device_endpoint).unwrap();
        }
        other => panic!("handshake: {:?}", other),
    }
    let mut packet = loop {
        let (n, from) = endpoint.recv_from(&mut wire).unwrap();
        assert_eq!(from, device_endpoint);
        match remote.decapsulate(None, &wire[..n], &mut scratch) {
            TunnResult::Done => continue, // optional empty confirmation
            TunnResult::WriteToTunnelV4(packet, _) => break packet.to_vec(),
            other => panic!("transport: {:?}", other),
        }
    };
    assert_eq!(&packet[28..], b"postdrop");
    // Echo by swapping addresses and UDP ports. Their one's-complement sums
    // are unchanged, so the kernel-generated IPv4 and UDP checksums remain valid.
    for i in 0..4 {
        packet.swap(12 + i, 16 + i);
    }
    for i in 0..2 {
        packet.swap(20 + i, 22 + i);
    }
    match remote.encapsulate(&packet, &mut scratch) {
        TunnResult::WriteToNetwork(encrypted) => {
            endpoint.send_to(encrypted, device_endpoint).unwrap();
        }
        other => panic!("echo: {:?}", other),
    }
    let mut payload = [0; 64];
    let (n, from) = application.recv_from(&mut payload).unwrap();
    assert_eq!(from, target);
    assert_eq!(&payload[..n], b"postdrop");
    let d = handle.device.read();
    let p = d.peers[&remote_public].lock();
    assert_eq!(p.endpoint().conn.is_some(), connected);
}

fn receive(socket: &socket2::Socket) -> (Vec<u8>, SocketAddr) {
    let udp = UdpSocket::from(socket.try_clone().unwrap());
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut bytes = [0; 64];
    loop {
        match udp.recv_from(&mut bytes) {
            Ok((n, addr)) => return (bytes[..n].to_vec(), addr),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::yield_now()
            }
            Err(e) => panic!("receive: {}", e),
        }
    }
}

#[test]
fn listeners_and_connected_peers_use_uid_checked_port_sharing() {
    let (mut d, _tun, _api) = device();
    d.open_listen_socket(0).unwrap();
    for addr in [
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
    ] {
        let remote = UdpSocket::bind(addr).unwrap();
        let p = peer(remote.local_addr().unwrap());
        let conn = p.connect_endpoint(d.listen_port, None).unwrap();
        assert_isolated(&conn);
        assert_eq!(
            conn.local_addr().unwrap().as_socket().unwrap().port(),
            d.listen_port
        );
    }
    assert_isolated(d.udp4.as_ref().unwrap());
    assert_isolated(d.udp6.as_ref().unwrap());
}

#[test]
fn connected_demultiplexing_roaming_and_rebind_keep_both_families_working() {
    let (mut d, _tun, _api) = device();
    d.open_listen_socket(0).unwrap();
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let listener = if ip.is_ipv4() {
            d.udp4.as_ref().unwrap()
        } else {
            d.udp6.as_ref().unwrap()
        };
        let a = UdpSocket::bind((ip, 0)).unwrap();
        let b = UdpSocket::bind((ip, 0)).unwrap();
        let p = peer(a.local_addr().unwrap());
        let conn = p.connect_endpoint(d.listen_port, None).unwrap();
        let local = SocketAddr::new(ip, d.listen_port);
        a.send_to(b"connected", local).unwrap();
        b.send_to(b"listener", local).unwrap();
        assert_eq!(
            receive(&conn),
            (b"connected".to_vec(), a.local_addr().unwrap())
        );
        assert_eq!(
            receive(listener),
            (b"listener".to_vec(), b.local_addr().unwrap())
        );
        p.set_endpoint(b.local_addr().unwrap());
        drop(conn);
        let moved = p.connect_endpoint(d.listen_port, None).unwrap();
        a.send_to(b"old", local).unwrap();
        b.send_to(b"new", local).unwrap();
        assert_eq!(receive(listener).0, b"old");
        assert_eq!(receive(&moved).0, b"new");
    }
    let old = d.listen_port;
    let fds = d.udp_listener_fds.clone();
    d.open_listen_socket(old).unwrap();
    assert_eq!(d.udp_listener_fds, fds);
    let occupied = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    assert_eq!(
        d.open_listen_socket(occupied.local_addr().unwrap().port())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EADDRINUSE)
    );
    assert_eq!(d.udp_listener_fds, fds);
    d.queue.fail_registration_after(1);
    assert_eq!(
        d.open_listen_socket(0).unwrap_err().raw_os_error(),
        Some(libc::EBADF)
    );
    assert_eq!(d.udp_listener_fds, fds);
    d.open_listen_socket(0).unwrap();
    assert_ne!(d.udp_listener_fds, fds);
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let sender = UdpSocket::bind((ip, 0)).unwrap();
        sender.send_to(b"rebound", (ip, d.listen_port)).unwrap();
        let listener = if ip.is_ipv4() {
            d.udp4.as_ref().unwrap()
        } else {
            d.udp6.as_ref().unwrap()
        };
        assert_eq!(receive(listener).0, b"rebound");
    }
    assert!(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, old)).is_ok());
}
