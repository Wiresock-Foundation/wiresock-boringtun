// Copyright (c) 2026 Vadim Smirnov (doing business as WireSock). All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![cfg(any(target_os = "linux", target_os = "macos"))]

use super::*;
use crate::device::{DeviceConfig, DeviceHandle};
use std::io::{self, Read};
use std::net::Shutdown;
#[cfg(target_os = "linux")]
use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixDatagram;
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct LiveApi {
    handle: DeviceHandle,
    client: UnixStream,
    _tun: Option<UnixDatagram>,
    paths: Vec<std::path::PathBuf>,
}

impl LiveApi {
    fn new() -> Self {
        Self::with_threads(1)
    }

    fn with_threads(n_threads: usize) -> Self {
        #[cfg(target_os = "linux")]
        let (tun_name, tun_peer) = {
            let (tun, peer) = UnixDatagram::pair().unwrap();
            (tun.into_raw_fd().to_string(), Some(peer))
        };
        // macOS has no inherited numeric TUN-fd constructor. Allocate a real,
        // unnamed utun in the existing privileged CI job, without configuring
        // addresses, routes or host networking. Closing the device destroys it.
        #[cfg(target_os = "macos")]
        let (tun_name, tun_peer) = ("utun".to_owned(), None);
        let (api, client) = UnixStream::pair().unwrap();
        socket2::SockRef::from(&api)
            .set_send_buffer_size(4096)
            .unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let handle = DeviceHandle::new(
            &tun_name,
            DeviceConfig {
                n_threads,
                use_connected_socket: false,
                #[cfg(target_os = "linux")]
                use_multi_queue: false,
                #[cfg(target_os = "linux")]
                uapi_fd: api.into_raw_fd(),
                ..Default::default()
            },
        )
        .unwrap();
        // The production inherited-fd constructor is Linux-only. On macOS
        // attach the same transport to the live utun device explicitly, with
        // ownership of the UnixStream, to exercise kqueue and device guards.
        #[cfg(target_os = "macos")]
        transport::register_inherited(&handle.device.read(), api).unwrap();
        Self {
            handle,
            client,
            _tun: tun_peer,
            paths: Vec::new(),
        }
    }

    fn worker_probe(&self) -> (crate::device::poll::EventRef, mpsc::Receiver<()>) {
        let (send, receive) = mpsc::channel();
        let event = self
            .handle
            .device
            .read()
            .queue
            .new_notifier(Box::new(move |_, _| {
                let _ = send.send(());
                Action::Continue
            }))
            .unwrap();
        (event, receive)
    }

    fn listener(&mut self) -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "bt-uapi-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path).unwrap();
        transport::register_listener(&self.handle.device.read(), listener).unwrap();
        self.paths.push(path.clone());
        path
    }

    fn exited(&self) -> bool {
        self.handle.threads.iter().all(|t| t.is_finished())
    }
}

impl Drop for LiveApi {
    fn drop(&mut self) {
        // Also unblocks the old implementation when a regression assertion fails.
        self.client.shutdown(Shutdown::Both).ok();
        self.handle.device.read().trigger_exit();
        self.handle.wait();
        for path in &self.paths {
            std::fs::remove_file(path).ok();
        }
    }
}

fn reply(reader: &mut impl BufRead) -> io::Result<String> {
    let mut response = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        response.push_str(&line);
        if line == "\n" {
            return Ok(response);
        }
    }
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(2);
    while !predicate() {
        assert!(Instant::now() < end, "condition did not become true");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn no_reply(stream: &mut UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_millis(40)))
        .unwrap();
    let result = stream.read(&mut [0; 1]);
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    assert!(
        matches!(result, Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)),
        "responded before frame terminator"
    );
}

fn connect(path: &std::path::Path) -> UnixStream {
    let stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    stream
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn pipelined_commands_each_receive_a_reply() {
    let mut api = LiveApi::new();
    api.client
        .write_all(b"get=1\n\nget=1\n\nset=1\nlisten_port=0\n\nget=1\n\n")
        .unwrap();
    let mut reader = BufReader::new(&api.client);
    for command in 0..4 {
        assert!(reply(&mut reader)
            .unwrap_or_else(|e| panic!("reply {}: {}", command, e))
            .ends_with("errno=0\n\n"));
    }
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn an_incomplete_request_does_not_occupy_the_only_worker() {
    let mut api = LiveApi::new();
    let (event, receive) = api.worker_probe();
    let queue = Arc::clone(&api.handle.device.read().queue);
    api.client.write_all(b"set=1\n").unwrap();
    std::thread::sleep(Duration::from_millis(50));
    queue.trigger_notification(&event);
    let serviced = receive.recv_timeout(Duration::from_millis(500)).is_ok();
    queue.stop_notification(&event);
    assert!(serviced, "an incomplete request blocked the device worker");
}

fn configure_large_reply(api: &mut LiveApi) {
    let key = x25519::PublicKey::from(&x25519::StaticSecret::from([2; 32]));
    let mut request = format!(
        "set=1\nprivate_key={}\npublic_key={}\n",
        encode_hex([1; 32]),
        encode_hex(key.as_bytes())
    );
    for i in 0..2048u16 {
        request.push_str(&format!("allowed_ip=10.{}.{}.1/32\n", i >> 8, i & 255));
    }
    request.push('\n');
    api.client.write_all(request.as_bytes()).unwrap();
    assert_eq!(
        reply(&mut BufReader::new(&api.client)).unwrap(),
        "errno=0\n\n"
    );
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn a_stalled_response_does_not_occupy_the_only_worker() {
    let mut api = LiveApi::new();
    configure_large_reply(&mut api);
    let (event, receive) = api.worker_probe();
    let queue = Arc::clone(&api.handle.device.read().queue);
    api.client.write_all(b"get=1\n\n").unwrap();
    std::thread::sleep(Duration::from_millis(50));
    queue.trigger_notification(&event);
    let serviced = receive.recv_timeout(Duration::from_millis(500)).is_ok();
    queue.stop_notification(&event);
    assert!(
        serviced,
        "a non-reading UAPI client blocked the device worker"
    );
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn split_headers_and_blank_terminators_are_retained() {
    let mut api = LiveApi::new();
    for part in [b"g".as_slice(), b"et=1", b"\n"] {
        api.client.write_all(part).unwrap();
        no_reply(&mut api.client);
    }
    api.client.write_all(b"\n").unwrap();
    assert!(reply(&mut BufReader::new(&api.client))
        .unwrap()
        .ends_with("errno=0\n\n"));
    api.client.write_all(b"set=1\nprivate_key=").unwrap();
    no_reply(&mut api.client);
    api.client
        .write_all(encode_hex([1; 32]).as_bytes())
        .unwrap();
    api.client.write_all(b"\n").unwrap();
    no_reply(&mut api.client);
    assert!(api.handle.device.read().key_pair.is_none());
    api.client.write_all(b"\n").unwrap();
    assert_eq!(
        reply(&mut BufReader::new(&api.client)).unwrap(),
        "errno=0\n\n"
    );
    assert!(api.handle.device.read().key_pair.is_some());
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn buffered_complete_frames_do_not_consume_a_following_partial_frame() {
    let mut api = LiveApi::new();
    api.client.write_all(b"get=1\n\nget=1\n\nset=1\n").unwrap();
    let mut reader = BufReader::new(api.client.try_clone().unwrap());
    for _ in 0..2 {
        assert!(reply(&mut reader).unwrap().ends_with("errno=0\n\n"));
    }
    no_reply(&mut api.client);
    api.client.write_all(b"\nget=1\n\n").unwrap();
    assert_eq!(reply(&mut reader).unwrap(), "errno=0\n\n");
    assert!(reply(&mut reader).unwrap().ends_with("errno=0\n\n"));
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn malformed_complete_transactions_preserve_partial_apply_and_next_frame() {
    let mut api = LiveApi::new();
    let request = format!(
        "get=1\nextra=1\n\nset=1\nprivate_key={}\nunknown=1\n\nget=1\n\n",
        encode_hex([1; 32])
    );
    api.client.write_all(request.as_bytes()).unwrap();
    let mut reader = BufReader::new(&api.client);
    assert_eq!(reply(&mut reader).unwrap(), format!("errno={}\n\n", EIO));
    assert_eq!(reply(&mut reader).unwrap(), format!("errno={}\n\n", EINVAL));
    let response = reply(&mut reader).unwrap();
    let key = x25519::PublicKey::from(&x25519::StaticSecret::from([1; 32]));
    assert!(response.contains(&format!("own_public_key={}\n", encode_hex(key.as_bytes()))));
    assert!(response.ends_with("errno=0\n\n"));
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn a_half_close_drains_complete_frames_then_exits_the_inherited_device() {
    let mut api = LiveApi::new();
    api.client
        .write_all(b"get=1\n\nset=1\n\nget=1\n\n")
        .unwrap();
    api.client.shutdown(Shutdown::Write).unwrap();
    let mut reader = BufReader::new(&api.client);
    for _ in 0..3 {
        assert!(reply(&mut reader).unwrap().ends_with("errno=0\n\n"));
    }
    wait_until(|| api.exited());
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn incomplete_eof_does_not_apply_a_transaction() {
    let mut api = LiveApi::new();
    api.client
        .write_all(format!("set=1\nprivate_key={}\n", encode_hex([1; 32])).as_bytes())
        .unwrap();
    api.client.shutdown(Shutdown::Write).unwrap();
    wait_until(|| api.exited());
    assert!(api.handle.device.read().key_pair.is_none());
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn inherited_eof_reclaims_its_stream_registration() {
    let api = LiveApi::new();
    let before = api.handle.device.read().queue.registered_count();
    api.client.shutdown(Shutdown::Both).unwrap();
    wait_until(|| api.exited());
    assert_eq!(
        api.handle.device.read().queue.registered_count(),
        before - 1
    );
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn a_busy_pipeline_yields_to_other_device_events() {
    let mut api = LiveApi::new();
    let (event, receive) = api.worker_probe();
    let queue = Arc::clone(&api.handle.device.read().queue);
    api.client.write_all(&b"get=1\n\n".repeat(2048)).unwrap();
    // Responses cannot all fit in the 4KiB send buffer. Even while both input
    // and output are ready, the event loop must dispatch another ready event.
    let mut reader = BufReader::new(api.client.try_clone().unwrap());
    assert!(reply(&mut reader).unwrap().ends_with("errno=0\n\n"));
    queue.trigger_notification(&event);
    let serviced = receive.recv_timeout(Duration::from_millis(500)).is_ok();
    queue.stop_notification(&event);
    assert!(serviced);
    for _ in 1..2048 {
        assert!(reply(&mut reader).unwrap().ends_with("errno=0\n\n"));
    }
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn a_stalled_socket_client_does_not_block_other_clients_and_is_reclaimed() {
    let mut api = LiveApi::new();
    let path = api.listener();
    let baseline = api.handle.device.read().queue.registered_count();
    let mut stalled = connect(&path);
    stalled.write_all(b"set=1\n").unwrap();
    wait_until(|| api.handle.device.read().queue.registered_count() == baseline + 1);
    let mut other = connect(&path);
    other.write_all(b"get=1\n\n").unwrap();
    let mut response = String::new();
    other.read_to_string(&mut response).unwrap();
    assert!(response.ends_with("errno=0\n\n"));
    stalled.shutdown(Shutdown::Both).unwrap();
    wait_until(|| api.handle.device.read().queue.registered_count() == baseline);
    assert!(!api.exited());
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn accepted_connection_limit_recovers_after_clients_close() {
    let mut api = LiveApi::new();
    let path = api.listener();
    let baseline = api.handle.device.read().queue.registered_count();
    let mut clients = Vec::new();
    for n in 1..=transport::MAX_CONNECTIONS {
        clients.push(connect(&path));
        wait_until(|| api.handle.device.read().queue.registered_count() == baseline + n);
    }
    let mut excess = connect(&path);
    assert_eq!(excess.read(&mut [0; 1]).unwrap(), 0);
    for c in clients {
        c.shutdown(Shutdown::Both).unwrap();
    }
    wait_until(|| api.handle.device.read().queue.registered_count() == baseline);
    let mut replacement = connect(&path);
    replacement.write_all(b"get=1\n\n").unwrap();
    assert!(reply(&mut BufReader::new(&replacement))
        .unwrap()
        .ends_with("errno=0\n\n"));
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn oversized_requests_are_refused_without_partial_mutation() {
    let mut api = LiveApi::new();
    let mut request = format!("set=1\nprivate_key={}\n", encode_hex([1; 32])).into_bytes();
    request.resize(transport::MAX_REQUEST, b'x');
    api.client.write_all(&request).unwrap();
    assert_eq!(
        reply(&mut BufReader::new(&api.client)).unwrap(),
        format!("errno={}\n\n", E2BIG)
    );
    wait_until(|| api.exited());
    assert!(api.handle.device.read().key_pair.is_none());
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn a_complete_frame_at_the_size_limit_is_parsed() {
    let mut api = LiveApi::new();
    // Unknown key makes the parser reject the complete frame with EINVAL;
    // transport E2BIG would mean the exact permitted boundary was rejected.
    let mut request = b"set=1\nunknown=".to_vec();
    request.resize(transport::MAX_REQUEST - 2, b'x');
    request.extend_from_slice(b"\n\n");
    api.client.write_all(&request).unwrap();
    assert_eq!(
        reply(&mut BufReader::new(&api.client)).unwrap(),
        format!("errno={}\n\n", EINVAL)
    );
    api.client.write_all(b"get=1\n\n").unwrap();
    assert!(reply(&mut BufReader::new(&api.client))
        .unwrap()
        .ends_with("errno=0\n\n"));
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn trickle_input_cannot_extend_the_transaction_deadline() {
    let mut api = LiveApi::new();
    api.client.write_all(b"set=1\n").unwrap();
    let start = Instant::now();
    while start.elapsed() < transport::TRANSACTION_TIMEOUT + Duration::from_secs(1) && !api.exited()
    {
        let _ = api.client.write_all(b"x");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(api.exited(), "trickle input extended the absolute timeout");
    assert!(start.elapsed() >= transport::TRANSACTION_TIMEOUT - Duration::from_millis(200));
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn idle_inherited_control_remains_available_between_transactions() {
    let mut api = LiveApi::new();
    api.client.write_all(b"get=1\n\n").unwrap();
    assert!(reply(&mut BufReader::new(&api.client))
        .unwrap()
        .ends_with("errno=0\n\n"));
    std::thread::sleep(transport::TRANSACTION_TIMEOUT + Duration::from_millis(200));
    api.client.write_all(b"get=1\n\n").unwrap();
    assert!(reply(&mut BufReader::new(&api.client))
        .unwrap()
        .ends_with("errno=0\n\n"));
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn a_slow_reader_receives_the_whole_response_then_the_next_reply() {
    let mut api = LiveApi::new();
    configure_large_reply(&mut api);
    api.client.write_all(b"get=1\n\nset=1\n\n").unwrap();
    let mut response = Vec::new();
    while !response.ends_with(b"errno=0\n\nerrno=0\n\n") {
        let mut buf = [0; 257];
        let n = api.client.read(&mut buf).unwrap();
        assert!(n > 0);
        response.extend_from_slice(&buf[..n]);
        std::thread::sleep(Duration::from_millis(1));
    }
    let text = String::from_utf8(response).unwrap();
    assert_eq!(text.matches("allowed_ip=").count(), 2048);
    assert_eq!(text.matches("errno=0\n\n").count(), 2);
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn an_abandoned_response_expires_and_exits_the_inherited_device() {
    let mut api = LiveApi::new();
    configure_large_reply(&mut api);
    api.client.write_all(b"get=1\n\n").unwrap();
    let start = Instant::now();
    while !api.exited() && start.elapsed() < transport::TRANSACTION_TIMEOUT + Duration::from_secs(1)
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(api.exited(), "stalled output never expired");
    assert!(start.elapsed() >= transport::TRANSACTION_TIMEOUT - Duration::from_millis(200));
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn accepted_idle_clients_expire_without_stopping_the_device() {
    let mut api = LiveApi::new();
    let path = api.listener();
    let baseline = api.handle.device.read().queue.registered_count();
    let mut idle = connect(&path);
    idle.set_read_timeout(Some(
        transport::TRANSACTION_TIMEOUT + Duration::from_secs(1),
    ))
    .unwrap();
    let start = Instant::now();
    assert_eq!(idle.read(&mut [0; 1]).unwrap(), 0);
    assert!(start.elapsed() >= transport::TRANSACTION_TIMEOUT - Duration::from_millis(200));
    wait_until(|| api.handle.device.read().queue.registered_count() == baseline);
    assert!(!api.exited());
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to allocate a temporary utun"
)]
fn concurrent_clients_can_upgrade_device_guards_on_multiple_workers() {
    let mut api = LiveApi::with_threads(4);
    let path = api.listener();
    let baseline = api.handle.device.read().queue.registered_count();
    let mut clients = Vec::new();
    for _ in 0..8 {
        let path = path.clone();
        clients.push(std::thread::spawn(move || {
            for _ in 0..16 {
                let mut client = connect(&path);
                client.write_all(b"set=1\nreplace_peers=false\n\n").unwrap();
                assert_eq!(reply(&mut BufReader::new(&client)).unwrap(), "errno=0\n\n");
            }
        }));
    }
    for client in clients {
        client.join().unwrap();
    }
    wait_until(|| api.handle.device.read().queue.registered_count() == baseline);
}
