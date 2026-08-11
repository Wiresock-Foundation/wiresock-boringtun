// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::dev_lock::LockReadGuard;
use super::drop_privileges::get_saved_ids;
use super::{AllowedIP, Device, Error, SocketAddr};
use crate::device::Action;
use crate::noise::amnezia::AmneziaConfig;
use crate::noise::handshake::ObfuscationRanges;
use crate::noise::timers::{
    KEEPALIVE_TIMEOUT, REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_ATTEMPT_TIME, REKEY_TIMEOUT,
};
use crate::serialization::KeyBytes;
use crate::x25519;
use hex::encode as encode_hex;
use libc::*;
use std::collections::HashMap;
use std::fs::{create_dir, remove_file};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::IpAddr;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const SOCK_DIR: &str = "/var/run/wireguard/";
/// Where `amneziawg-tools` looks for a userspace implementation's UAPI socket.
///
/// `wg` uses `/var/run/wireguard/`, but `awg` is a fork and searches
/// `/var/run/amneziawg/%s.sock` instead, so a socket published only under
/// `SOCK_DIR` is invisible to it -- `awg setconf` fails with "Operation not
/// supported" because it falls back to netlink and finds a TUN device that is
/// not an amneziawg interface. Since AmneziaWG support is the point of this
/// fork, publish in both places rather than choosing.
const AWG_SOCK_DIR: &str = "/var/run/amneziawg/";

/// Parse an AmneziaWG range value: either a bare number (`"1"`) or the
/// inclusive `min-max` form (`"342871004-442871003"`). A bare value is a
/// degenerate range, which is exactly how the kernel module's `mh_genspec`
/// treats it, so existing single-value configs map across unchanged.
///
/// This is the one wire grammar for every AmneziaWG numeric key -- magic
/// headers, the 3.0 tunable timers, `content_padding_addition` and
/// `persistent_keepalive_interval` all arrive in it, because amneziawg-go
/// stores them as `UintRange` and amneziawg-tools renders them with
/// `u16_range_to_string`. One parser, so the accepted grammar cannot differ per
/// key: an earlier revision had two near-identical copies and they had already
/// drifted on inverted ranges.
///
/// An inverted range is rejected, matching both of those implementations
/// (`UintRange::FromString` returns "wrong range specified";
/// `u16_range_from_string` returns false when `hi < lo`).
fn parse_uint_range(val: &str) -> Option<(u32, u32)> {
    let (start, end) = match val.split_once('-') {
        Some((start, end)) => (start.trim().parse().ok()?, end.trim().parse().ok()?),
        None => {
            let v: u32 = val.trim().parse().ok()?;
            (v, v)
        }
    };
    if start > end {
        return None;
    }
    Some((start, end))
}

/// A magic-header tag: [`parse_uint_range`] plus the rejection of 0.
fn parse_tag_range(val: &str) -> Option<(u32, u32)> {
    let (start, end) = parse_uint_range(val)?;
    // Reject 0 rather than accepting it silently. `ObfuscationRanges::new`
    // treats an all-zero range as "unset" and substitutes the vanilla WireGuard
    // message type for that packet kind, so `h1=0` would quietly disable
    // obfuscation instead of using tag 0 -- the opposite of what the operator
    // wrote. Failing the transaction with EINVAL makes that visible.
    if start == 0 {
        return None;
    }
    Some((start, end))
}

/// AmneziaWG values accumulated over one `set=1` transaction.
///
/// They cannot be applied one at a time: `ObfuscationRanges::new` validates all
/// four header ranges together and rejects overlaps, so a partially-applied set
/// could transiently fail validation on a configuration that is valid as a
/// whole. Anything left `None` keeps the device's current value.
#[derive(Default)]
struct AwgParams {
    jc: Option<u16>,
    jmin: Option<u16>,
    jmax: Option<u16>,
    s1: Option<u16>,
    s2: Option<u16>,
    s3: Option<u16>,
    s4: Option<u16>,
    h1: Option<(u32, u32)>,
    h2: Option<(u32, u32)>,
    h3: Option<(u32, u32)>,
    h4: Option<(u32, u32)>,
    seen: bool,
}

impl AwgParams {
    fn set_size(&mut self, key: &str, val: u16) {
        match key {
            "jc" => self.jc = Some(val),
            "jmin" => self.jmin = Some(val),
            "jmax" => self.jmax = Some(val),
            "s1" => self.s1 = Some(val),
            "s2" => self.s2 = Some(val),
            "s3" => self.s3 = Some(val),
            "s4" => self.s4 = Some(val),
            _ => unreachable!("caller matched the key"),
        }
        self.seen = true;
    }

    fn set_header(&mut self, key: &str, range: (u32, u32)) {
        match key {
            "h1" => self.h1 = Some(range),
            "h2" => self.h2 = Some(range),
            "h3" => self.h3 = Some(range),
            "h4" => self.h4 = Some(range),
            _ => unreachable!("caller matched the key"),
        }
        self.seen = true;
    }

    /// Apply the accumulated values, merging with whatever the device already
    /// has. A no-op when the transaction carried no AmneziaWG keys, so plain
    /// WireGuard configurations are untouched.
    fn apply(&self, device: &mut Device) -> Result<(), i32> {
        if !self.seen {
            return Ok(());
        }
        let (obf, amnezia) = self.merged(device.config.obf, &device.config.amnezia)?;
        if device.set_obfuscation(obf, amnezia) {
            tracing::info!(message = "AmneziaWG parameters updated");
        }
        Ok(())
    }

    /// Merge this transaction over the device's current settings.
    ///
    /// Split out of [`Self::apply`] so the merge can be tested without a
    /// `Device`, which needs a TUN interface and root. The property worth
    /// testing is that protocol imitation *survives* — it has no UAPI key, so it
    /// can only arrive via `DeviceConfig` at startup, and rebuilding rather than
    /// merging here would make any `awg setconf` silently switch camouflage off.
    fn merged(
        &self,
        cur_obf: ObfuscationRanges,
        cur_amnezia: &AmneziaConfig,
    ) -> Result<(ObfuscationRanges, AmneziaConfig), i32> {
        let cur_junk = cur_amnezia.pre_handshake_junk;
        let (h1, h2, h3, h4) = (
            self.h1
                .unwrap_or((cur_obf.h1_init.start, cur_obf.h1_init.end)),
            self.h2
                .unwrap_or((cur_obf.h2_resp.start, cur_obf.h2_resp.end)),
            self.h3
                .unwrap_or((cur_obf.h3_cookie.start, cur_obf.h3_cookie.end)),
            self.h4
                .unwrap_or((cur_obf.h4_data.start, cur_obf.h4_data.end)),
        );

        let obf = ObfuscationRanges::new(h1.0, h1.1, h2.0, h2.1, h3.0, h3.1, h4.0, h4.1)
            .map_err(|_| EINVAL)?;

        // Start from the current value and overwrite only what this transaction
        // carried. Rebuilding with `AmneziaConfig::new` would discard the
        // protocol-imitation settings, which have no UAPI key of their own and
        // therefore can only arrive via `DeviceConfig` at startup -- so any
        // `set=1` mentioning an AmneziaWG key would silently turn imitation off.
        let mut amnezia = cur_amnezia.clone();
        amnezia.init_packet_junk_size = self.s1.unwrap_or(amnezia.init_packet_junk_size);
        amnezia.response_packet_junk_size = self.s2.unwrap_or(amnezia.response_packet_junk_size);
        amnezia.cookie_packet_junk_size = self.s3.unwrap_or(amnezia.cookie_packet_junk_size);
        amnezia.transport_packet_junk_size = self.s4.unwrap_or(amnezia.transport_packet_junk_size);
        let amnezia = amnezia.with_pre_handshake_junk(
            self.jc.unwrap_or(cur_junk.packet_count),
            self.jmin.unwrap_or(cur_junk.packet_size_min),
            self.jmax.unwrap_or(cur_junk.packet_size_max),
            cur_junk.packet_delay_ms,
        );

        // Reject sizes that could never emit a valid datagram, before anything
        // is committed. Without this, an oversized S value is accepted here and
        // only shows up later as a tunnel that never completes a handshake.
        if let Err(e) = amnezia.validate() {
            tracing::error!(message = "rejecting AmneziaWG parameters", error = %e);
            return Err(EINVAL);
        }

        Ok((obf, amnezia))
    }
}

/// The attributes of a single `[Peer]` section of a `set=1` transaction.
///
/// Grouped into one struct with a `Default` so that starting a new section is a
/// single assignment. They were previously six separate locals declared outside
/// the parse loop, of which only `allowed_ips` was reset between sections — so
/// every other attribute leaked into the next peer.
#[derive(Default)]
struct PeerSection {
    remove: bool,
    update_only: bool,
    replace_ips: bool,
    endpoint: Option<SocketAddr>,
    keepalive: Option<u16>,
    preshared_key: Option<[u8; 32]>,
    allowed_ips: Vec<AllowedIP>,
}

fn create_sock_dir(dir: &str) {
    let _ = create_dir(dir); // Create the directory if it does not exist

    if let Ok((saved_uid, saved_gid)) = get_saved_ids() {
        unsafe {
            let c_path = std::ffi::CString::new(dir).unwrap();
            // The directory is under the root user, but we want to be able to
            // delete the files there when we exit, so we need to change the owner
            chown(
                c_path.as_bytes_with_nul().as_ptr() as _,
                saved_uid,
                saved_gid,
            );
        }
    }
}

impl Device {
    /// Register the api handler for this Device. The api handler receives stream connections on a Unix socket
    /// with a known path: /var/run/wireguard/{tun_name}.sock.
    ///
    /// The same socket is also published at /var/run/amneziawg/{tun_name}.sock
    /// as a symlink, because `amneziawg-tools` searches that directory rather
    /// than the WireGuard one; without it `awg` cannot see this interface at
    /// all. There is still exactly one socket and one accept loop. If the
    /// symlink cannot be created the handler is registered anyway and a warning
    /// is logged, leaving the device reachable by `wg` but not `awg`.
    pub fn register_api_handler(&mut self) -> Result<(), Error> {
        let name = self.iface.name()?;
        let path = format!("{}/{}.sock", SOCK_DIR, name);

        create_sock_dir(SOCK_DIR);

        let _ = remove_file(&path); // Attempt to remove the socket if already exists

        let api_listener = UnixListener::bind(&path).map_err(Error::ApiSocket)?; // Bind a new socket to the path

        self.cleanup_paths.push(path.clone());

        // Also publish where `awg` looks. A symlink rather than a second
        // listener, so there is exactly one socket and one accept loop; both
        // toolchains then reach the same device. Failure is not fatal -- the
        // daemon still works, just only under `wg`.
        let awg_path = format!("{}/{}.sock", AWG_SOCK_DIR, name);
        create_sock_dir(AWG_SOCK_DIR);
        let _ = remove_file(&awg_path);
        match std::os::unix::fs::symlink(&path, &awg_path) {
            Ok(()) => self.cleanup_paths.push(awg_path),
            Err(e) => tracing::warn!(
                message = "could not publish the UAPI socket for amneziawg-tools; awg will not find this interface",
                path = awg_path.as_str(),
                error = %e
            ),
        }

        self.queue.new_event(
            api_listener.as_raw_fd(),
            Box::new(move |d, _| {
                // This is the closure that listens on the api unix socket
                let (api_conn, _) = match api_listener.accept() {
                    Ok(conn) => conn,
                    _ => return Action::Continue,
                };

                let mut reader = BufReader::new(&api_conn);
                let mut writer = BufWriter::new(&api_conn);
                let mut cmd = String::new();
                if reader.read_line(&mut cmd).is_ok() {
                    cmd.pop(); // pop the new line character
                    let status = match cmd.as_ref() {
                        // Only two commands are legal according to the protocol, get=1 and set=1.
                        "get=1" => api_get(&mut writer, d),
                        "set=1" => api_set(&mut reader, d),
                        _ => EIO,
                    };
                    // The protocol requires to return an error code as the response, or zero on success
                    writeln!(writer, "errno={}\n", status).ok();
                }
                Action::Continue // Indicates the worker thread should continue as normal
            }),
        )?;

        self.register_monitor(path)?;
        self.register_api_signal_handlers()
    }

    pub fn register_api_fd(&mut self, fd: i32) -> Result<(), Error> {
        let io_file = unsafe { UnixStream::from_raw_fd(fd) };

        self.queue.new_event(
            io_file.as_raw_fd(),
            Box::new(move |d, _| {
                // This is the closure that listens on the api file descriptor

                let mut reader = BufReader::new(&io_file);
                let mut writer = BufWriter::new(&io_file);
                let mut cmd = String::new();
                if reader.read_line(&mut cmd).is_ok() {
                    cmd.pop(); // pop the new line character
                    let status = match cmd.as_ref() {
                        // Only two commands are legal according to the protocol, get=1 and set=1.
                        "get=1" => api_get(&mut writer, d),
                        "set=1" => api_set(&mut reader, d),
                        _ => EIO,
                    };
                    // The protocol requires to return an error code as the response, or zero on success
                    writeln!(writer, "errno={}\n", status).ok();
                } else {
                    // The remote side is likely closed; we should trigger an exit.
                    d.trigger_exit();
                    return Action::Exit;
                }

                Action::Continue // Indicates the worker thread should continue as normal
            }),
        )?;

        Ok(())
    }

    fn register_monitor(&self, path: String) -> Result<(), Error> {
        self.queue.new_periodic_event(
            Box::new(move |d, _| {
                // This is not a very nice hack to detect if the control socket was removed
                // and exiting nicely as a result. We check every 3 seconds in a loop if the
                // file was deleted by stating it.
                // The problem is that on linux inotify can be used quite beautifully to detect
                // deletion, and kqueue EVFILT_VNODE can be used for the same purpose, but that
                // will require introducing new events, for no measurable benefit.
                // TODO: Could this be an issue if we restart the service too quickly?
                let path = std::path::Path::new(&path);
                if !path.exists() {
                    d.trigger_exit();
                    return Action::Exit;
                }

                // Periodically read the mtu of the interface in case it changes
                if let Ok(mtu) = d.iface.mtu() {
                    d.mtu.store(mtu, Ordering::Relaxed);
                }

                Action::Continue
            }),
            std::time::Duration::from_millis(1000),
        )?;

        Ok(())
    }

    fn register_api_signal_handlers(&self) -> Result<(), Error> {
        self.queue
            .new_signal_event(SIGINT, Box::new(move |_, _| Action::Exit))?;

        self.queue
            .new_signal_event(SIGTERM, Box::new(move |_, _| Action::Exit))?;

        Ok(())
    }
}

#[allow(unused_must_use)]
fn api_get(writer: &mut BufWriter<&UnixStream>, d: &Device) -> i32 {
    // get command requires an empty line, but there is no reason to be religious about it
    if let Some(ref k) = d.key_pair {
        writeln!(writer, "own_public_key={}", encode_hex(k.1.as_bytes()));
    }

    if d.listen_port != 0 {
        writeln!(writer, "listen_port={}", d.listen_port);
    }

    if let Some(fwmark) = d.fwmark {
        writeln!(writer, "fwmark={}", fwmark);
    }

    // AmneziaWG interface parameters, emitted only when they differ from plain
    // WireGuard so a vanilla device's output is byte-identical to before.
    // Sizes are `%u`; magic headers use the kernel's `mh_genspec` convention --
    // a bare value when the range is degenerate, `start-end` otherwise.
    {
        let a = &d.config.amnezia;
        for (key, val) in [
            ("jc", a.pre_handshake_junk.packet_count),
            ("jmin", a.pre_handshake_junk.packet_size_min),
            ("jmax", a.pre_handshake_junk.packet_size_max),
            ("s1", a.init_packet_junk_size),
            ("s2", a.response_packet_junk_size),
            ("s3", a.cookie_packet_junk_size),
            ("s4", a.transport_packet_junk_size),
        ] {
            if val != 0 {
                writeln!(writer, "{}={}", key, val);
            }
        }

        let obf = d.config.obf;
        let default = ObfuscationRanges::default();
        for (key, range, def) in [
            ("h1", obf.h1_init, default.h1_init),
            ("h2", obf.h2_resp, default.h2_resp),
            ("h3", obf.h3_cookie, default.h3_cookie),
            ("h4", obf.h4_data, default.h4_data),
        ] {
            if range != def {
                if range.start == range.end {
                    writeln!(writer, "{}={}", key, range.start);
                } else {
                    writeln!(writer, "{}={}-{}", key, range.start, range.end);
                }
            }
        }
    }

    // Walk the trie once and group by owner. `peers_by_ip` remains the only
    // place prefixes live, but `AllowedIps::iter` materialises the whole
    // index into a VecDeque, so asking it per peer would be O(peers x
    // prefixes) with a fresh allocation each time -- visible on `awg show`
    // for a server with many peers.
    let mut prefixes_by_peer: HashMap<usize, Vec<(IpAddr, u8)>> = HashMap::new();
    for (owner, addr, cidr) in d.peers_by_ip.iter() {
        prefixes_by_peer
            .entry(Arc::as_ptr(owner) as usize)
            .or_default()
            .push((addr, cidr));
    }

    for (k, peer) in d.peers.iter() {
        let p = peer.lock();
        writeln!(writer, "public_key={}", encode_hex(k.as_bytes()));

        if let Some(ref key) = p.preshared_key() {
            writeln!(writer, "preshared_key={}", encode_hex(key));
        }

        if let Some(keepalive) = p.persistent_keepalive() {
            writeln!(writer, "persistent_keepalive_interval={}", keepalive);
        }

        if let Some(ref addr) = p.endpoint().addr {
            writeln!(writer, "endpoint={}", addr);
        }

        for (ip, cidr) in prefixes_by_peer
            .get(&(Arc::as_ptr(peer) as usize))
            .map_or(&[][..], Vec::as_slice)
        {
            writeln!(writer, "allowed_ip={}/{}", ip, cidr);
        }

        // `last_handshake_time_*` is an absolute wall-clock timestamp in the
        // UAPI, not an age -- `wg`/`awg` subtract it from the current time to
        // render "N seconds ago". Reporting the elapsed duration instead made
        // every peer read as roughly 56 years stale, so any health check or
        // management UI treating a stale handshake as "peer down" saw every
        // peer as permanently dead. Verified against the kernel module, which
        // reports the epoch timestamp here.
        if let Some(elapsed) = p.time_since_last_handshake() {
            if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let handshake_at = now.saturating_sub(elapsed);
                writeln!(writer, "last_handshake_time_sec={}", handshake_at.as_secs());
                writeln!(
                    writer,
                    "last_handshake_time_nsec={}",
                    handshake_at.subsec_nanos()
                );
            }
        }

        let (_, tx_bytes, rx_bytes, ..) = p.tunnel.stats();

        writeln!(writer, "rx_bytes={}", rx_bytes);
        writeln!(writer, "tx_bytes={}", tx_bytes);
    }
    0
}

fn api_set(reader: &mut BufReader<&UnixStream>, d: &mut LockReadGuard<Device>) -> i32 {
    d.try_writeable(
        |device| device.trigger_yield(),
        |device| {
            device.cancel_yield();

            let mut cmd = String::new();
            // AmneziaWG keys are validated as a set (`ObfuscationRanges::new`
            // rejects overlapping H ranges), so they are accumulated across the
            // transaction and applied at whichever exit point comes first --
            // including before delegating to a peer section, since peers
            // snapshot the device's settings when they are created.
            let mut awg = AwgParams::default();

            while reader.read_line(&mut cmd).is_ok() {
                cmd.pop(); // remove newline if any
                if cmd.is_empty() {
                    match awg.apply(device) {
                        Ok(()) => return 0, // Done
                        Err(code) => return code,
                    }
                }
                {
                    // Split on the *first* `=` only. Values may legitimately
                    // contain one: `KeyBytes` accepts base64 as well as hex, and
                    // a base64-encoded 32-byte key is 44 characters ending in
                    // `=` padding, which `split('=')` would turn into three
                    // fields and reject as EPROTO.
                    let parsed_cmd: Vec<&str> = cmd.splitn(2, '=').collect();
                    if parsed_cmd.len() != 2 {
                        return EPROTO;
                    }

                    let (key, val) = (parsed_cmd[0], parsed_cmd[1]);

                    match key {
                        "private_key" => match val.parse::<KeyBytes>() {
                            Ok(key_bytes) => {
                                device.set_key(x25519::StaticSecret::from(key_bytes.0))
                            }
                            Err(_) => return EINVAL,
                        },
                        "listen_port" => match val.parse::<u16>() {
                            Ok(port) => match device.open_listen_socket(port) {
                                Ok(()) => {}
                                Err(_) => return EADDRINUSE,
                            },
                            Err(_) => return EINVAL,
                        },
                        #[cfg(any(
                            target_os = "android",
                            target_os = "fuchsia",
                            target_os = "linux"
                        ))]
                        "fwmark" => match val.parse::<u32>() {
                            Ok(mark) => match device.set_fwmark(mark) {
                                Ok(()) => {}
                                Err(_) => return EADDRINUSE,
                            },
                            Err(_) => return EINVAL,
                        },
                        "replace_peers" => match val.parse::<bool>() {
                            Ok(true) => device.clear_peers(),
                            Ok(false) => {}
                            Err(_) => return EINVAL,
                        },
                        "public_key" => match val.parse::<KeyBytes>() {
                            // Indicates a new peer section
                            Ok(key_bytes) => {
                                // Apply before the first peer is built: peers
                                // snapshot the device's AmneziaWG settings.
                                if let Err(code) = awg.apply(device) {
                                    return code;
                                }
                                return api_set_peer(
                                    reader,
                                    device,
                                    x25519::PublicKey::from(key_bytes.0),
                                );
                            }
                            Err(_) => return EINVAL,
                        },
                        // AmneziaWG device keys. Sizes are `%u`; magic headers
                        // are `%s` and may be a bare value or a `start-end`
                        // range, matching amneziawg-tools' wire format.
                        "jc" | "jmin" | "jmax" | "s1" | "s2" | "s3" | "s4" => {
                            match val.parse::<u16>() {
                                Ok(v) => awg.set_size(key, v),
                                Err(_) => return EINVAL,
                            }
                        }
                        "h1" | "h2" | "h3" | "h4" => match parse_tag_range(val) {
                            Some(range) => awg.set_header(key, range),
                            None => return EINVAL,
                        },
                        // AWG 2.0 signature packets. A responder only has to
                        // tolerate these; accept and ignore rather than failing
                        // the whole transaction on a config that carries them.
                        "i1" | "i2" | "i3" | "i4" | "i5" => {}
                        // AmneziaWG 3.0 device keys: tolerated where ignoring
                        // them is safe, refused where it is not. Everything else
                        // still fails the transaction, because
                        // `handle_awg3_device_key` ends in the same EINVAL this
                        // arm used to be.
                        _ => {
                            if let Err(code) = handle_awg3_device_key(key, val) {
                                return code;
                            }
                        }
                    }
                }
                cmd.clear();
            }

            0
        },
    )
    .unwrap_or(EIO)
}

/// The constant this build actually uses for an AWG-3 tunable timer, in seconds.
///
/// `max_handshake_attempts` has no constant of its own: we bound handshake
/// retries by wall clock instead of by a counter, so the equivalent count is
/// REKEY_ATTEMPT_TIME / REKEY_TIMEOUT, which is what amneziawg-go's
/// `MaxTimerHandshakes` is defined as too (`90 / 5` in device/constants.go).
/// Computed rather than written as `18`, so retuning either constant moves this
/// answer with it instead of leaving the daemon claiming agreement it no longer
/// has.
///
/// `None` for a key with no built-in equivalent.
///
/// Returns an `Option` rather than panicking on the unmatched arm. The caller's
/// key list and this one are two hand-maintained lists that have to agree, and
/// this runs on the UAPI parse path: adding a sixth AWG-3 tunable to the caller
/// and forgetting it here would turn `<newkey>=<anything>` into a panic in the
/// API thread. amneziawg-go has already added five, so a sixth is the expected
/// direction of travel. An unmapped key now degrades to the same "not
/// implemented" warning as a value that merely disagrees, which is the outcome
/// that arm is for. Not a silent `0`, which would make `<newkey>=0` look like
/// agreement.
fn awg3_our_timer(key: &str) -> Option<u64> {
    Some(match key {
        "reject_after_time" => REJECT_AFTER_TIME.as_secs(),
        "rekey_after_time" => REKEY_AFTER_TIME.as_secs(),
        "rekey_timeout" => REKEY_TIMEOUT.as_secs(),
        "keepalive_timeout" => KEEPALIVE_TIMEOUT.as_secs(),
        "max_handshake_attempts" => REKEY_ATTEMPT_TIME.as_secs() / REKEY_TIMEOUT.as_secs(),
        _ => return None,
    })
}

/// AmneziaWG 3.0 device keys this build does not implement.
///
/// Tolerated rather than rejected because one unknown key aborts the rest of
/// the `set=1`: an AWG-3 profile would otherwise lose every jc/s/h line it
/// carries, and every peer section after the offending one. (It does *not*
/// leave the device untouched -- `private_key`, `listen_port`, `fwmark`,
/// `replace_peers` and any peer already committed are applied as they are
/// parsed and there is no rollback, so an abort mid-stream can leave the
/// interface rekeyed with no peers. That is the pre-existing shape of
/// `api_set`, and it is the reason tolerating a key we can safely ignore is
/// worth doing.)
///
/// Ignoring a value the peer actually set is not free, so a value that differs
/// from what we do warns -- see the individual notes. A value that agrees with
/// us, or that means "unset", is silent.
///
/// `Ok(())` tolerates the key; `Err(code)` fails the transaction. Split out of
/// the `api_set` match so the acceptance policy is reachable from a test:
/// `api_set` itself needs a `Device`, which needs root and a TUN interface.
fn handle_awg3_device_key(key: &str, val: &str) -> Result<(), i32> {
    match key {
        "content_padding_addition" => match parse_uint_range(val) {
            // Sender-side only: it pads its own plaintext, and we already
            // tolerate the padded keepalive that results. Nothing breaks; our
            // own transport just keeps a different length distribution to
            // theirs. 0 is amneziawg-go's "unset", which pads to a 16-byte
            // multiple like vanilla WireGuard rather than by a random addition
            // -- not "the peer is not padding", which is what an earlier version
            // of this comment claimed.
            //
            // Silent even so, and the reason is on the other side's get path:
            // amneziawg-go's UAPI only emits this key when the value is
            // non-zero, so `=0` never appears in a config it generated. It can
            // only be hand-typed, which makes a warning here a warning about
            // whether someone spelled "unset" out loud.
            //
            // We do not pad to a 16-byte multiple either (`format_packet_data`
            // seals `src` at its own length), so 0 is a real difference in
            // length distribution. But that difference is a property of this
            // build -- it is there on every tunnel we make, including plain
            // WireGuard with no AWG keys at all -- so it is not caused by this
            // config line and does not belong in a diagnostic keyed to it.
            Some((0, 0)) => {}
            Some((lo, hi)) => tracing::warn!(
                message = "content_padding_addition is not implemented; \
                           our transport packets will not be padded",
                requested_low = lo,
                requested_high = hi
            ),
            None => return Err(EINVAL),
        },
        "reject_after_time"
        | "rekey_after_time"
        | "rekey_timeout"
        | "keepalive_timeout"
        | "max_handshake_attempts" => {
            let ours = awg3_our_timer(key);
            match parse_uint_range(val) {
                // An all-zero range is amneziawg-go's "unset": it falls back to
                // the same built-in default we hardcode (`IsZero()` checks in
                // device/timers.go), so the peer is asking for exactly what we
                // already do. Warning here would fire the one new diagnostic on
                // a configuration that agrees with us.
                Some((0, 0)) => {}
                // Otherwise silence is only safe while the value matches what we
                // hardcode. A peer that shortens reject_after_time discards a
                // keypair we still consider live, which shows up as one-way
                // blackholing minutes later rather than as a handshake failure
                // -- so a mismatch has to say so. A range that merely *contains*
                // our value is not equivalent to it: the peer re-picks, we do
                // not.
                Some((lo, hi)) if ours == Some(u64::from(lo)) && ours == Some(u64::from(hi)) => {}
                Some((lo, hi)) => tracing::warn!(
                    message = "tunable timers are not implemented; \
                               using the built-in WireGuard constant",
                    key = key,
                    requested_low = lo,
                    requested_high = hi,
                    ours = ?ours
                ),
                None => return Err(EINVAL),
            }
        }
        // Deliberately NOT tolerated, unlike everything above it. Header
        // protection masks the message-type field with a ChaCha20 keystream, so
        // a peer that sets it cannot classify our packets and we cannot classify
        // theirs -- the tunnel is mutually unreachable, not degraded. Accepting
        // the key and ignoring it would turn that into an unexplained dead port;
        // failing here at least names the reason.
        //
        // The all-zero key is the exception, and it is not a special case we
        // invented: amneziawg-go accepts it -- `FromHex` is a plain length-checked
        // hex decode with no zero test -- and its `HeaderProtectionCipher` then
        // returns no cipher at all when the key is zero, which also lifts the
        // S1..S4 >= 12 requirement its UAPI otherwise imposes. A zero key means
        // protection is *off*, which is exactly what this build does, so that
        // peer interoperates and aborting the whole transaction over it would
        // refuse a configuration that asks nothing of us. It is also the only
        // way to turn header protection off over UAPI: `set=1` is seeded from
        // the live device, so omitting the key preserves whatever was there.
        "header_protection_key" => match val.parse::<KeyBytes>() {
            Ok(KeyBytes(key)) if key == [0u8; 32] => {}
            Ok(_) => {
                tracing::error!(
                    "header_protection_key is not implemented: a peer using it cannot \
                     interoperate with this build, so the configuration is refused \
                     rather than applied without protection"
                );
                return Err(EINVAL);
            }
            Err(_) => return Err(EINVAL),
        },
        _ => return Err(EINVAL),
    }
    Ok(())
}

/// A peer's `persistent_keepalive_interval`, in seconds.
///
/// amneziawg-go stores this as a `UintRange` and re-picks within it, so a v3
/// config may carry `25-35` rather than a bare `25`. A bare value is by far the
/// common form; the range only has to not abort the transaction.
///
/// The low end, not the middle: sending keepalives more often than asked is
/// safe, sending them less often risks the NAT mapping expiring, which is the
/// failure this setting exists to prevent. Clamped up to 1 when the low end is
/// 0, because 0 does not mean "as often as possible" here -- `Timers` gates the
/// keepalive on `persistent_keepalive > 0`, so `0-30` taken literally would
/// switch keepalives *off* for a peer that asked for them, which is exactly the
/// failure taking the low end is meant to avoid. amneziawg-go treats `0-30` as
/// on (`UintRange::IsZero` tests the whole packed range, not the low end).
///
/// A bare `0` still means off, as in vanilla WireGuard.
///
/// Note this accepts surrounding whitespace where the previous `parse::<u16>()`
/// did not; no tool emits it, and the shared range parser has to trim for the
/// `min - max` form anyway.
fn parse_keepalive_interval(val: &str) -> Option<u16> {
    let (lo, hi) = parse_uint_range(val)?;
    if hi > u32::from(u16::MAX) {
        return None;
    }
    if lo != hi {
        tracing::warn!(
            message = "randomised keepalive intervals are not implemented; \
                       using the low end of the range",
            requested_low = lo,
            requested_high = hi
        );
        return Some(lo.max(1) as u16);
    }
    Some(lo as u16)
}

/// Apply one accumulated `[Peer]` section.
///
/// `update_only` means "do not create this peer if it does not exist", and the
/// whole section is discarded when it does not -- which is what amneziawg-go
/// does too (it swaps in a dummy peer and drops every remaining line of the
/// block). `Device::update_peer` has no existence check of its own, so without
/// this a stale section from a management plane would re-create a peer that was
/// deliberately revoked, reinstalling its allowed-IPs into `peers_by_ip` and
/// returning success.
fn commit_peer(
    d: &mut Device,
    public_key: x25519::PublicKey,
    sec: &PeerSection,
) -> Result<(), i32> {
    if sec.update_only && !d.peers.contains_key(&public_key) {
        tracing::debug!(
            message = "update_only: no such peer, section ignored",
            peer = encode_hex(public_key.as_bytes()).as_str()
        );
        return Ok(());
    }
    if let Err(e) = d.update_peer(
        public_key,
        sec.remove,
        sec.replace_ips,
        sec.endpoint,
        sec.allowed_ips.as_slice(),
        sec.keepalive,
        sec.preshared_key,
    ) {
        tracing::error!(
            message = "failed to apply peer",
            peer = encode_hex(public_key.as_bytes()).as_str(),
            error = ?e
        );
        return Err(EIO);
    }
    Ok(())
}

fn api_set_peer(
    reader: &mut BufReader<&UnixStream>,
    d: &mut Device,
    pub_key: x25519::PublicKey,
) -> i32 {
    let mut cmd = String::new();

    let mut public_key = pub_key;
    let mut sec = PeerSection::default();
    while reader.read_line(&mut cmd).is_ok() {
        cmd.pop(); // remove newline if any
        if cmd.is_empty() {
            if let Err(code) = commit_peer(d, public_key, &sec) {
                return code;
            }
            return 0; // Done
        }
        {
            let parsed_cmd: Vec<&str> = cmd.splitn(2, '=').collect();
            if parsed_cmd.len() != 2 {
                return EPROTO;
            }
            let (key, val) = (parsed_cmd[0], parsed_cmd[1]);
            match key {
                "remove" => match val.parse::<bool>() {
                    Ok(true) => sec.remove = true,
                    Ok(false) => sec.remove = false,
                    Err(_) => return EINVAL,
                },
                "preshared_key" => match val.parse::<KeyBytes>() {
                    Ok(key_bytes) => sec.preshared_key = Some(key_bytes.0),
                    Err(_) => return EINVAL,
                },
                "endpoint" => match val.parse::<SocketAddr>() {
                    Ok(addr) => sec.endpoint = Some(addr),
                    Err(_) => return EINVAL,
                },
                "persistent_keepalive_interval" => match parse_keepalive_interval(val) {
                    Some(interval) => sec.keepalive = Some(interval),
                    None => return EINVAL,
                },
                "replace_allowed_ips" => match val.parse::<bool>() {
                    Ok(true) => sec.replace_ips = true,
                    Ok(false) => sec.replace_ips = false,
                    Err(_) => return EINVAL,
                },
                // A leading `-` is wireguard-go's remove-one-prefix form, which
                // this build does not implement. `AllowedIP::from_str` already
                // rejects it -- an IP address cannot start with `-` -- so the
                // arm below returns EINVAL either way and this one changes no
                // behaviour; it exists only to name the reason in the log,
                // because the errno alone cannot distinguish an unimplemented
                // verb from a malformed prefix.
                //
                // Note what the refusal does and does not buy: it does *not*
                // keep the prefix from staying routable. EINVAL returns before
                // `update_peer`, so the peer keeps every allowed-IP it already
                // had, including the one being revoked -- exactly as if the line
                // had been ignored. What it buys is that the operator's
                // revocation is reported as failed instead of as applied.
                // `replace_allowed_ips=true`, which is what `awg setconf` emits,
                // is supported and does express a revocation.
                "allowed_ip" if val.starts_with('-') => {
                    tracing::error!(
                        message = "removing a single allowed_ip is not implemented; \
                                   the prefix is unchanged and the transaction is refused",
                        prefix = &val[1..]
                    );
                    return EINVAL;
                }
                "allowed_ip" => match val.parse::<AllowedIP>() {
                    Ok(ip) => sec.allowed_ips.push(ip),
                    Err(_) => return EINVAL,
                },
                "public_key" => {
                    // Indicates a new peer section. Commit changes for current peer, and continue to next peer
                    if let Err(code) = commit_peer(d, public_key, &sec) {
                        return code;
                    }
                    // Each `[Peer]` block is independent, matching the kernel's
                    // nested-attribute model. Reset every attribute, not just
                    // allowed_ips: carrying `remove` would delete the next peer,
                    // and carrying `preshared_key` would overwrite its key.
                    sec = PeerSection::default();
                    match val.parse::<KeyBytes>() {
                        Ok(key_bytes) => public_key = key_bytes.0.into(),
                        Err(_) => return EINVAL,
                    }
                }
                "protocol_version" => match val.parse::<u32>() {
                    Ok(1) => {} // Only version 1 is legal
                    _ => return EINVAL,
                },
                // "apply this section only if the peer already exists". Neither
                // `wg` nor `awg` has a CLI flag for it; it comes from clients
                // driving the UAPI directly (wgctrl's `PeerConfig.UpdateOnly`,
                // the wireguard-apple/android tunnel libraries) -- that is,
                // from the automated add/revoke control planes where creating a
                // peer that was deliberately revoked matters most. Honoured in
                // `commit_peer` rather than ignored, for that reason.
                //
                // amneziawg-go also rejects any value but "true".
                "update_only" => {
                    if val != "true" {
                        return EINVAL;
                    }
                    sec.update_only = true;
                }
                _ => return EINVAL,
            }
        }
        cmd.clear();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Protocol imitation survives a `set=1` that carries AmneziaWG keys.
    ///
    /// It has no UAPI key of its own — `awg showconf` drops keys it does not
    /// know, so a value set that way would not round-trip — which makes startup
    /// configuration the only way in. If `merged` rebuilt the config instead of
    /// merging over it, every `awg setconf` would silently switch camouflage off
    /// and nothing would say so.
    ///
    /// The comment at the merge site asserted this; nothing tested it. A
    /// cross-module claim in prose is exactly the thing that drifts.
    #[test]
    fn a_set_transaction_preserves_protocol_imitation() {
        use crate::noise::amnezia::{
            AmneziaImitation, AmneziaImitationBrowser, AmneziaImitationProtocol,
        };

        let current = AmneziaConfig::new(1, 1, 1, 1).with_protocol_imitation_browser(
            AmneziaImitationProtocol::Quic,
            Some("example.com".to_owned()),
            AmneziaImitationBrowser::Firefox,
        );
        let expected_imitation = AmneziaImitation::new(
            AmneziaImitationProtocol::Quic,
            Some("example.com".to_owned()),
            AmneziaImitationBrowser::Firefox,
        );

        // A transaction that touches only the S sizes, as `awg setconf` does.
        let mut params = AwgParams::default();
        params.set_size("s1", 120);
        params.set_size("s2", 130);

        let (_, merged) = params
            .merged(ObfuscationRanges::default(), &current)
            .expect("valid parameters");

        assert_eq!(
            merged.imitation, expected_imitation,
            "the S sizes were updated but imitation must be carried over intact"
        );
        assert_eq!(merged.init_packet_junk_size, 120, "s1 applied");
        assert_eq!(merged.response_packet_junk_size, 130, "s2 applied");
        // And the keys the transaction did not mention keep their old values.
        assert_eq!(merged.cookie_packet_junk_size, 1, "s3 untouched");
        assert_eq!(merged.transport_packet_junk_size, 1, "s4 untouched");
    }

    #[test]
    fn parse_uint_range_accepts_both_forms_and_rejects_an_inverted_one() {
        // amneziawg-go's UintRange accepts a bare value or `min-max`.
        assert_eq!(parse_uint_range("120"), Some((120, 120)));
        assert_eq!(parse_uint_range(" 120 "), Some((120, 120)));
        assert_eq!(parse_uint_range("100-140"), Some((100, 140)));
        assert_eq!(parse_uint_range(" 100 - 140 "), Some((100, 140)));
        assert_eq!(parse_uint_range("notanumber"), None);
        assert_eq!(parse_uint_range(""), None);
        // Inverted is a hard error in both amneziawg-go (`UintRange::FromString`
        // -> "wrong range specified") and amneziawg-tools
        // (`u16_range_from_string` returns false when hi < lo). Rejecting it in
        // the one shared parser is what keeps the answer from depending on which
        // key it arrived under: it used to abort the transaction on
        // persistent_keepalive_interval and merely warn on reject_after_time.
        assert_eq!(parse_uint_range("140-100"), None, "inverted range");
        // Unlike parse_tag_range, zero is a legal value here -- it is how a
        // peer says "unset" for the 3.0 tunables.
        assert_eq!(parse_uint_range("0"), Some((0, 0)));
        assert_eq!(parse_uint_range("0-5"), Some((0, 5)));
    }

    #[test]
    fn an_awg3_timer_reports_the_constant_that_actually_governs_behaviour() {
        // The point of the warning is the mismatch case: a peer that shortens
        // reject_after_time discards a keypair we still consider live, which
        // surfaces as one-way blackholing minutes later rather than as a
        // handshake failure. Silence there would be the wrong default -- so what
        // we report as "ours" has to be what the timer wheel really uses.
        assert_eq!(awg3_our_timer("reject_after_time"), Some(180));
        assert_eq!(awg3_our_timer("rekey_after_time"), Some(120));
        assert_eq!(awg3_our_timer("rekey_timeout"), Some(5));
        assert_eq!(awg3_our_timer("keepalive_timeout"), Some(10));
        // We have no attempt counter: the equivalent is REKEY_ATTEMPT_TIME /
        // REKEY_TIMEOUT = 90/5, which is how amneziawg-go defines its own
        // default (`MaxTimerHandshakes = 90 / 5`). Because `awg3_our_timer`
        // computes it, retuning either constant fails this assertion instead of
        // leaving the daemon claiming an agreement it no longer has -- which a
        // hardcoded 18 asserted against a literal 18 could never catch.
        assert_eq!(awg3_our_timer("max_handshake_attempts"), Some(18));
        assert_eq!(
            awg3_our_timer("max_handshake_attempts"),
            Some(REKEY_ATTEMPT_TIME.as_secs() / REKEY_TIMEOUT.as_secs())
        );

        // Every key the caller routes into the timer arm must have an entry
        // here. These are two hand-maintained lists on the UAPI parse path, and
        // this assertion is what stops them drifting: with `unreachable!` in
        // place of the `None`, adding a sixth tunable upstream and forgetting it
        // here turned `<newkey>=<anything>` into a panic in the API thread.
        for key in [
            "reject_after_time",
            "rekey_after_time",
            "rekey_timeout",
            "keepalive_timeout",
            "max_handshake_attempts",
        ] {
            assert!(
                awg3_our_timer(key).is_some(),
                "{} is routed into the timer arm but has no built-in equivalent",
                key
            );
        }

        // An unmapped key degrades to the warning, not to a panic and not to a
        // silent 0 that would make `<newkey>=0` look like agreement.
        assert_eq!(awg3_our_timer("some_future_tunable"), None);
        assert_eq!(
            handle_awg3_device_key("reject_after_time", "60"),
            Ok(()),
            "a disagreeing value is tolerated with a warning, not refused"
        );
    }

    #[test]
    fn an_awg3_device_key_is_tolerated_in_every_form_its_tools_emit() {
        // The whole point of the arm: a key we ignore must not abort the
        // transaction. amneziawg-go stores content_padding_addition as a
        // UintRange and re-picks per packet, and amneziawg-tools renders a
        // non-degenerate range as `lo-hi`, so the range form is the *intended*
        // spelling -- a bare u16 parse rejected it and killed the whole `set=1`,
        // which is the failure this arm exists to prevent.
        assert_eq!(
            handle_awg3_device_key("content_padding_addition", "0"),
            Ok(())
        );
        assert_eq!(
            handle_awg3_device_key("content_padding_addition", "64"),
            Ok(())
        );
        assert_eq!(
            handle_awg3_device_key("content_padding_addition", "1-100"),
            Ok(()),
            "the randomised form amneziawg-tools emits"
        );
        assert_eq!(
            handle_awg3_device_key("content_padding_addition", "100000"),
            Ok(()),
            "amneziawg-go parses these as u32, so a value over u16::MAX is legal"
        );

        // Timers: agreement and "unset" are silent, a real difference warns,
        // and all three are tolerated.
        for val in ["180", "0", "60", "120-200"] {
            assert_eq!(
                handle_awg3_device_key("reject_after_time", val),
                Ok(()),
                "reject_after_time={} must not abort the transaction",
                val
            );
        }
        for key in [
            "rekey_after_time",
            "rekey_timeout",
            "keepalive_timeout",
            "max_handshake_attempts",
        ] {
            assert_eq!(handle_awg3_device_key(key, "7"), Ok(()), "{}", key);
        }

        // Malformed values are still refused -- tolerance is about keys we do
        // not implement, not about input we cannot parse.
        assert_eq!(
            handle_awg3_device_key("content_padding_addition", "notanumber"),
            Err(EINVAL)
        );
        assert_eq!(
            handle_awg3_device_key("reject_after_time", "200-100"),
            Err(EINVAL),
            "inverted range"
        );
        // And the catch-all this function replaced still rejects everything it
        // does not list.
        assert_eq!(handle_awg3_device_key("not_a_real_key", "1"), Err(EINVAL));
        // A live `header_protection_key` is refused rather than tolerated. "0"
        // is a separate case and is refused for a different reason -- it is one
        // hex character, not a key at all. See the test below for the
        // distinction, which is why this assertion does not cover the all-zero
        // key despite looking like it might.
        assert_eq!(
            handle_awg3_device_key("header_protection_key", "0"),
            Err(EINVAL)
        );
    }

    /// An all-zero header-protection key means "off", which is what we do.
    ///
    /// This is the one AWG-3 key we refuse outright, because a peer that masks
    /// the message-type field is mutually unreachable rather than degraded. The
    /// zero key is not that peer: amneziawg-go accepts it and then builds no
    /// cipher from it, so header protection is off on both ends and the tunnel
    /// works. Refusing it would abort the whole `set=1` transaction over a line
    /// that asks nothing of us -- the exact failure mode this function exists to
    /// remove.
    #[test]
    fn a_zeroed_header_protection_key_means_off_and_is_tolerated() {
        assert_eq!(
            handle_awg3_device_key("header_protection_key", &"0".repeat(64)),
            Ok(()),
            "an all-zero key is amneziawg-go's 'off'"
        );
        // The same 32 zero bytes in base64; `KeyBytes` takes both spellings and
        // so does the UAPI.
        assert_eq!(
            handle_awg3_device_key(
                "header_protection_key",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            ),
            Ok(()),
            "base64 spells the same 32 zero bytes"
        );
        // A live key still aborts the transaction.
        assert_eq!(
            handle_awg3_device_key("header_protection_key", &"ab".repeat(32)),
            Err(EINVAL),
            "a live key is still refused"
        );
        // And a value that is not a key at all is still refused. "0" is one hex
        // character, not 32 zero bytes -- which is why the assertion above that
        // uses it never reached this case.
        assert_eq!(
            handle_awg3_device_key("header_protection_key", "0"),
            Err(EINVAL),
            "one hex char is not a key"
        );
    }

    #[test]
    fn a_keepalive_range_never_silently_disables_the_keepalive() {
        // A bare value is the common form and must round-trip exactly, 0
        // included -- that is vanilla WireGuard's "off".
        assert_eq!(parse_keepalive_interval("25"), Some(25));
        assert_eq!(parse_keepalive_interval("0"), Some(0));
        assert_eq!(parse_keepalive_interval("65535"), Some(65535));
        // The low end of a range, not the high end: sending keepalives more
        // often than asked is safe, sending them less often risks the NAT
        // mapping expiring.
        assert_eq!(parse_keepalive_interval("25-35"), Some(25));
        // ...except that 0 is not "more often", it is never. `Timers` gates the
        // keepalive on `persistent_keepalive > 0`, so taking the low end of
        // `0-30` literally would switch keepalives off for a peer that asked for
        // them -- the exact failure taking the low end is meant to avoid, and
        // invisible afterwards because `get=1` omits a zero keepalive.
        // amneziawg-go treats `0-30` as on.
        assert_eq!(parse_keepalive_interval("0-30"), Some(1));
        assert_eq!(parse_keepalive_interval("0-0"), Some(0), "0-0 is still off");
        // The u16 bound the vanilla `parse::<u16>()` used to enforce still
        // holds; without it these truncate to a plausible wrong interval
        // (70000 as u16 == 4464).
        assert_eq!(parse_keepalive_interval("70000"), None);
        assert_eq!(parse_keepalive_interval("25-70000"), None);
        assert_eq!(parse_keepalive_interval("35-25"), None, "inverted range");
        assert_eq!(parse_keepalive_interval("notanumber"), None);
    }

    #[test]
    fn parse_tag_range_accepts_bare_values_and_ranges() {
        // A bare value is a degenerate range, matching the kernel module's
        // mh_genspec, so single-value AmneziaWG configs map across unchanged.
        assert_eq!(parse_tag_range("1"), Some((1, 1)));
        assert_eq!(parse_tag_range("342871004"), Some((342871004, 342871004)));
        assert_eq!(
            parse_tag_range("342871004-442871003"),
            Some((342871004, 442871003))
        );
        assert_eq!(parse_tag_range(" 7 - 9 "), Some((7, 9)));
        assert_eq!(
            parse_tag_range(&u32::MAX.to_string()),
            Some((u32::MAX, u32::MAX))
        );
    }

    #[test]
    fn uapi_line_split_keeps_padding_in_base64_values() {
        // A base64-encoded 32-byte key is 44 chars ending in `=` padding.
        // Splitting on every `=` yields three fields and is rejected as EPROTO,
        // even though KeyBytes documents base64 as an accepted form.
        let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let line = format!("private_key={}", key);

        let parts: Vec<&str> = line.splitn(2, '=').collect();
        assert_eq!(parts.len(), 2, "must split into exactly key and value");
        assert_eq!(parts[0], "private_key");
        assert_eq!(parts[1], key, "padding must survive intact");
        assert!(
            parts[1].parse::<KeyBytes>().is_ok(),
            "value must still parse"
        );

        // A line with no separator is still rejected.
        assert_eq!("no_separator".splitn(2, '=').count(), 1);
    }

    #[test]
    fn parse_tag_range_rejects_malformed_input() {
        assert_eq!(parse_tag_range(""), None);
        assert_eq!(parse_tag_range("abc"), None);
        assert_eq!(parse_tag_range("9-7"), None, "inverted range");
        assert_eq!(parse_tag_range("1-"), None);
        assert_eq!(parse_tag_range("-1"), None);
        assert_eq!(parse_tag_range("4294967296"), None, "overflows u32");
        assert_eq!(parse_tag_range("1-2-3"), None);
    }

    #[test]
    fn parse_tag_range_rejects_zero_rather_than_silently_disabling() {
        // ObfuscationRanges::new treats an all-zero range as "unset" and
        // substitutes the vanilla WireGuard message type. Accepting h1=0 would
        // therefore turn obfuscation *off* for that packet kind while reporting
        // success -- the opposite of what the operator asked for.
        assert_eq!(parse_tag_range("0"), None);
        assert_eq!(parse_tag_range("0-0"), None);
        assert_eq!(parse_tag_range("0-5"), None);
        // Non-zero starts are unaffected.
        assert_eq!(parse_tag_range("1"), Some((1, 1)));
        assert_eq!(parse_tag_range("1-5"), Some((1, 5)));
    }
}
