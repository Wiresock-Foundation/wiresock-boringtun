// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::dev_lock::LockReadGuard;
use super::drop_privileges::get_saved_ids;
use super::{AllowedIP, Device, Error, SocketAddr};
use crate::device::Action;
use crate::noise::amnezia::{AmneziaConfig, AwgTimers};
use crate::noise::handshake::ObfuscationRanges;
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
    header_protection: Option<[u8; 32]>,
    content_padding: Option<(u32, u32)>,
    rekey_after_time: Option<(u32, u32)>,
    rekey_timeout: Option<(u32, u32)>,
    reject_after_time: Option<(u32, u32)>,
    keepalive_timeout: Option<(u32, u32)>,
    max_handshake_attempts: Option<(u32, u32)>,
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

    fn set_header_protection(&mut self, key: [u8; 32]) {
        self.header_protection = Some(key);
        self.seen = true;
    }

    fn set_content_padding(&mut self, range: (u32, u32)) {
        self.content_padding = Some(range);
        self.seen = true;
    }

    fn set_timer(&mut self, key: &str, range: (u32, u32)) {
        match key {
            "rekey_after_time" => self.rekey_after_time = Some(range),
            "rekey_timeout" => self.rekey_timeout = Some(range),
            "reject_after_time" => self.reject_after_time = Some(range),
            "keepalive_timeout" => self.keepalive_timeout = Some(range),
            "max_handshake_attempts" => self.max_handshake_attempts = Some(range),
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
        // The padding is clamped against the interface MTU. This snapshot is
        // one of three writers keeping it fresh: `Device::new` seeds it at
        // startup, `register_mtu_monitor` pushes a changed MTU once a second
        // (wg-quick sets the MTU *after* `wg setconf`, so a set=1-only
        // snapshot would be stale from the start), and every `set=1` lands
        // here. Saturated rather than truncated: `65536 as u16` is 0, which
        // `content_padding` reads as "no clamp at all" -- fail-open in the one
        // place that must fail closed.
        let mtu = device.mtu.load(Ordering::Relaxed).min(u16::MAX as usize) as u16;
        let (obf, amnezia) = self.merged(device.config.obf, &device.config.amnezia, mtu)?;
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
        mtu: u16,
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
        let mut amnezia = amnezia.with_pre_handshake_junk(
            self.jc.unwrap_or(cur_junk.packet_count),
            self.jmin.unwrap_or(cur_junk.packet_size_min),
            self.jmax.unwrap_or(cur_junk.packet_size_max),
            cur_junk.packet_delay_ms,
        );
        if let Some(key) = self.header_protection {
            amnezia = amnezia.with_header_protection(key);
        }
        // The range this transaction carried, else whatever is already set, so
        // a later `set=1` that does not mention padding keeps it. The MTU is
        // always refreshed from the interface -- it is not a UAPI value.
        let (pad_lo, pad_hi) = self
            .content_padding
            .unwrap_or(amnezia.content_padding_addition);
        amnezia = amnezia.with_content_padding_addition(pad_lo, pad_hi, mtu);

        // Timers: each range this transaction carried, else whatever is
        // already set. `(0, 0)` is amneziawg-go's "unset" -- the built-in
        // constant governs again -- which is also what a reapplied kernel
        // `awg showconf` dump sends, since it prints every unset timer as
        // `=0`.
        let cur = amnezia.timers;
        amnezia = amnezia.with_tunable_timers(AwgTimers {
            rekey_after_time: self.rekey_after_time.unwrap_or(cur.rekey_after_time),
            rekey_timeout: self.rekey_timeout.unwrap_or(cur.rekey_timeout),
            reject_after_time: self.reject_after_time.unwrap_or(cur.reject_after_time),
            keepalive_timeout: self.keepalive_timeout.unwrap_or(cur.keepalive_timeout),
            max_handshake_attempts: self
                .max_handshake_attempts
                .unwrap_or(cur.max_handshake_attempts),
        });

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

                Action::Continue
            }),
            std::time::Duration::from_millis(1000),
        )?;

        Ok(())
    }

    /// Refresh the interface MTU once a second, on every API path.
    ///
    /// Registered from `Device::new` rather than from `register_api_handler`,
    /// because the `--uapi-fd` path never registers the socket watchdog above
    /// -- parking the MTU refresh inside it froze `device.mtu` (and with it
    /// the content-padding clamp) at the startup snapshot for fd-activated
    /// daemons.
    ///
    /// The content-padding clamp is a *snapshot* in each peer's config
    /// (`content_padding_mtu`), while amneziawg-go reads the live MTU per
    /// packet (`device.tun.mtu.Load()` in RoutineEncryption) -- and wg-quick
    /// sets the MTU *after* `wg setconf`, so the snapshot a `set=1` takes is
    /// stale from the first second in the most common bring-up order. Push the
    /// refreshed value into the configs here. Not via `set_obfuscation`: the
    /// MTU is plumbing, not configuration -- that path drops every peer's
    /// queued pre-handshake junk and logs "parameters updated", both wrong for
    /// a value the operator did not change. Gated on inequality so the steady
    /// state stays read-only and the write-lock upgrade is paid only when the
    /// MTU actually moved.
    pub(crate) fn register_mtu_monitor(&self) -> Result<(), Error> {
        self.queue.new_periodic_event(
            Box::new(|d, _| {
                if let Ok(mtu) = d.iface.mtu() {
                    d.mtu.store(mtu, Ordering::Relaxed);

                    // Saturate rather than truncate: `65536 as u16` is 0, and
                    // 0 means "no clamp at all" to `content_padding` -- the
                    // one value whose job is bounding the padding must not
                    // fail open on a large reading.
                    let mtu = mtu.min(u16::MAX as usize) as u16;
                    if d.config.amnezia.content_padding_mtu != mtu {
                        d.try_writeable(
                            |device| device.trigger_yield(),
                            |device| {
                                device.cancel_yield();
                                device.config.amnezia.content_padding_mtu = mtu;
                                for peer in device.peers.values_mut() {
                                    peer.lock().tunnel.set_content_padding_mtu(mtu);
                                }
                            },
                        );
                    }
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

/// The AmneziaWG interface parameters `get=1` emits, in order.
///
/// Emitted only when they differ from plain WireGuard, so a vanilla device's
/// output is byte-identical to upstream's -- amneziawg-go's `IpcGetOperation`
/// guards every 3.0 tunable on `!IsZero()` the same way. (The kernel
/// amneziawg-tools differ: `awg showconf` prints `ContentPaddingAddition = 0`
/// and the five timers unconditionally, which is why the *set* side reads a
/// `=0` from a reapplied config dump as "unset" rather than as a request.)
/// Sizes are `%u`; magic headers and the padding range use the kernel's
/// `mh_genspec` convention -- a bare value when the range is degenerate,
/// `start-end` otherwise. The padding MTU is a runtime clamp, not a UAPI
/// value, so it is never emitted.
///
/// The header-protection key is emitted so a configuration round-trips: `awg
/// showconf` reads this to produce a file that `awg setconf` reapplies, and a
/// key dropped here would come back as a device with header protection
/// silently off -- mutually unreachable with every peer that still has it.
/// Yes, that writes a secret to the UAPI socket. That socket is root-only and
/// already carries `private_key` upstream; this fork does not emit the private
/// key, but that is a deliberate divergence about the *static* key, not a rule
/// that no shared secret may round-trip.
///
/// Split from `api_get` so the emit grammar is reachable from a test --
/// `api_get` itself wants a live `Device`, which wants root and a TUN.
#[allow(unused_must_use)]
fn write_awg_interface_params(
    writer: &mut impl std::io::Write,
    obf: &ObfuscationRanges,
    a: &AmneziaConfig,
) {
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

    if let Some(key) = a.header_protection_key_hex() {
        writeln!(writer, "header_protection_key={}", key);
    }

    // One renderer for the `mh_genspec` spelling, so the keys sharing the
    // grammar cannot drift apart the way two hand-copies of a parser once
    // did (see `parse_uint_range`'s history).
    #[allow(unused_must_use)]
    fn write_range(writer: &mut impl std::io::Write, key: &str, lo: u32, hi: u32) {
        if lo == hi {
            writeln!(writer, "{}={}", key, lo);
        } else {
            writeln!(writer, "{}={}-{}", key, lo, hi);
        }
    }

    let default = ObfuscationRanges::default();
    for (key, range, def) in [
        ("h1", obf.h1_init, default.h1_init),
        ("h2", obf.h2_resp, default.h2_resp),
        ("h3", obf.h3_cookie, default.h3_cookie),
        ("h4", obf.h4_data, default.h4_data),
    ] {
        if range != def {
            write_range(writer, key, range.start, range.end);
        }
    }

    // The padding range and the five tunable timers, when set. amneziawg-go
    // emits each of these only when non-zero (`!IsZero()` in
    // `IpcGetOperation`), so unset stays absent and a vanilla device's output
    // is unchanged. The two bool keys go emits *unconditionally*
    // (`random_trailers=0`, `disable_cookies=0`) are deliberately not
    // reproduced: this build does not implement either feature, and inventing
    // the keys would grow a vanilla device's `get=1` for nothing a peer can
    // act on.
    let t = &a.timers;
    for (key, range) in [
        ("content_padding_addition", a.content_padding_addition),
        ("rekey_after_time", t.rekey_after_time),
        ("rekey_timeout", t.rekey_timeout),
        ("reject_after_time", t.reject_after_time),
        ("keepalive_timeout", t.keepalive_timeout),
        ("max_handshake_attempts", t.max_handshake_attempts),
    ] {
        if range != (0, 0) {
            write_range(writer, key, range.0, range.1);
        }
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

    write_awg_interface_params(writer, &d.config.obf, &d.config.amnezia);

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
                        // AmneziaWG 3.0 content padding: a `(lo, hi)` range of
                        // zero bytes appended per transport packet. Implemented,
                        // so it is applied rather than warned about.
                        "content_padding_addition" => match parse_uint_range(val) {
                            Some(range) => awg.set_content_padding(range),
                            None => return EINVAL,
                        },
                        // AWG 2.0 signature packets. A responder only has to
                        // tolerate these; accept and ignore rather than failing
                        // the whole transaction on a config that carries them.
                        "i1" | "i2" | "i3" | "i4" | "i5" => {}
                        // Both ends must carry the same key: it is not negotiated
                        // and there is no in-band signal, so a mismatch is a
                        // tunnel that never forms rather than one that degrades.
                        // An all-zero key means off, matching amneziawg-go.
                        //
                        // This arm is what `handle_awg3_device_key` refuses when
                        // header protection is not compiled in; here it is, so
                        // the key is accepted before reaching that fallback.
                        "header_protection_key" => match val.parse::<KeyBytes>() {
                            Ok(key_bytes) => awg.set_header_protection(key_bytes.0),
                            Err(_) => return EINVAL,
                        },
                        // AmneziaWG 3.0 tunable timers, applied for real. The
                        // kernel module's `awg showconf` prints every unset
                        // timer as `=0`, so `(0, 0)` must mean -- and in
                        // `merged` does mean -- "back to the built-in
                        // constant". The floors live in
                        // `AmneziaConfig::validate`, reached through `merged`,
                        // so a violation fails the transaction with EINVAL and
                        // a log line naming the numbers.
                        "rekey_after_time"
                        | "rekey_timeout"
                        | "reject_after_time"
                        | "keepalive_timeout"
                        | "max_handshake_attempts" => match parse_uint_range(val) {
                            Some(range) => awg.set_timer(key, range),
                            None => return EINVAL,
                        },
                        // AmneziaWG device keys this build does not implement:
                        // tolerated where ignoring them is safe. Everything
                        // else still fails the transaction, because
                        // `handle_awg3_device_key` ends in the same EINVAL
                        // this arm used to be.
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

/// AmneziaWG device keys this build does not implement.
///
/// Tolerated rather than rejected because one unknown key aborts the rest of
/// the `set=1`: an AWG profile would otherwise lose every jc/s/h line it
/// carries, and every peer section after the offending one. (It does *not*
/// leave the device untouched -- `private_key`, `listen_port`, `fwmark`,
/// `replace_peers` and any peer already committed are applied as they are
/// parsed and there is no rollback, so an abort mid-stream can leave the
/// interface rekeyed with no peers. That is the pre-existing shape of
/// `api_set`, and it is the reason tolerating a key we can safely ignore is
/// worth doing.)
///
/// The two bool keys are here for a hard interop reason: amneziawg-go's
/// `get=1` emits `random_trailers=0` and `disable_cookies=0`
/// *unconditionally* -- its `boolf` has no is-set guard, unlike the five
/// timers it emits only when set -- so every reapplied go dump carries both
/// keys even for a configuration that never mentioned either. Refusing them
/// would abort every such transaction.
///
/// A value that asks for nothing (`0`/`false` -- off is what this build does)
/// is silent; a value that turns the feature on warns, because silently
/// ignoring it would change what the peer expects on the wire; junk is
/// EINVAL. Only the spellings the tools produce are accepted: go emits `0`
/// and `1`, its `ParseBool` also takes `true`/`false`, and amneziawg-tools
/// passes values through verbatim.
///
/// `header_protection_key`, `content_padding_addition` and the five tunable
/// timers deliberately do NOT appear here: `api_set` handles them above,
/// because this build implements them. They stay out of this fallback so that
/// removing a feature would surface as an unhandled key rather than as silent
/// tolerance.
///
/// `Ok(())` tolerates the key; `Err(code)` fails the transaction. Split out of
/// the `api_set` match so the acceptance policy is reachable from a test:
/// `api_set` itself needs a `Device`, which needs root and a TUN interface.
fn handle_awg3_device_key(key: &str, val: &str) -> Result<(), i32> {
    match key {
        "random_trailers" | "disable_cookies" => match val {
            "0" | "false" => {}
            "1" | "true" => tracing::warn!(
                message = "AmneziaWG key is not implemented; the feature stays off",
                key = key,
            ),
            _ => return Err(EINVAL),
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
/// Only the *low* end is bounded by the `u16` a peer stores, because only the
/// low end is ever applied -- and it is bounded by capping, not by refusing.
/// 65535 s is already 18 hours, an order of magnitude past any UDP NAT mapping
/// lifetime, so the cap and every value above it are equally "as good as off"
/// to every middlebox on the path; refusing instead aborts the whole
/// transaction.
///
/// Note this accepts surrounding whitespace where the previous `parse::<u16>()`
/// did not; no tool emits it, and the shared range parser has to trim for the
/// `min - max` form anyway.
fn parse_keepalive_interval(val: &str) -> Option<u16> {
    let (lo, hi) = parse_uint_range(val)?;
    // Cap the low end. The low end is the value we apply, so this is what
    // stops `lo as u16` truncating -- `65536-70000` would otherwise become 0,
    // switching the keepalive off for a peer that asked for one. The high end
    // is discarded, so its magnitude cannot matter at all.
    //
    // Capped and not refused, because refusing is the worse of the two errors.
    // amneziawg-go parses both ends as u32 (`UintRange::FromString` uses
    // `ParseUint(_, 10, 32)`), accepts a bare `70000`, re-emits it verbatim on
    // `get=1`, and applies it as `time.Duration(PickOne()) * time.Second` --
    // so `70000` is a config it can legitimately produce. Refusing it returns
    // EINVAL from `api_set_peer`, which aborts the whole `set=1` mid-stream,
    // after `replace_peers` may already have cleared the peer table. What that
    // abort bought was the difference between 65535 s and 70000 s -- two
    // intervals no NAT on the path can tell apart, both being far past any
    // UDP mapping lifetime.
    //
    // The cap errs in the safe direction, the same one the `max(1)` below errs
    // in: a keepalive sent more often than asked costs one 32-byte packet, one
    // sent less often costs the NAT mapping this setting exists to hold open.
    //
    // The u32 ceiling above this is still a refusal rather than a cap, and it
    // is the same refusal amneziawg-go makes (`strconv.ParseUint: value out of
    // range`), so the two accept exactly the same set of configuration lines.
    let capped = lo.min(u32::from(u16::MAX));
    if lo != hi {
        // Report the value applied, not a description of how it was chosen.
        // "Using the low end" was false for exactly the inputs where `lo == 0`:
        // the clamp below sends 1, not 0, and 0 is the one low end an operator
        // is likely to write. A field carrying the number cannot drift from the
        // arithmetic the way a sentence about it can.
        let fixed = capped.max(1) as u16;
        tracing::warn!(
            message = "randomised keepalive intervals are not implemented; \
                       the range is narrowed to a single interval",
            requested_low = lo,
            requested_high = hi,
            fixed_interval = fixed
        );
        return Some(fixed);
    }
    if capped != lo {
        // A bare value we cannot store. Silence would be the one outcome worse
        // than either alternative: the operator's interval quietly replaced by
        // a different one, invisible until someone diffs `get=1` against the
        // config that produced it. Two warn sites rather than one merged one,
        // because "range narrowed" and "value capped" are different diagnoses
        // and a bare 70000 must not be told its range was narrowed.
        tracing::warn!(
            message = "the keepalive interval is above the maximum this build \
                       stores; it is capped",
            requested_low = lo,
            requested_high = hi,
            fixed_interval = capped
        );
    }
    Some(capped as u16)
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
                        message = "removing a single allowed_ip is not implemented; the \
                                   prefix is unchanged and the request fails here; \
                                   anything this request already applied is not rolled back",
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
            .merged(ObfuscationRanges::default(), &current, 1420)
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

    /// The five tunable timers through a `set=1` merge: each range reaches the
    /// config, an unmentioned key keeps its old value, `(0, 0)` clears back to
    /// unset, and the floors fail the transaction with EINVAL.
    ///
    /// `(0, 0)` clearing is an interop requirement, not a courtesy: the kernel
    /// module's `awg showconf` prints every unset timer as `=0`, so a
    /// reapplied dump sends the zeros verbatim.
    #[test]
    fn tunable_timers_over_the_uapi_apply_and_round_trip() {
        let current = AmneziaConfig::default();

        // Two keys set, three left alone.
        let mut set = AwgParams::default();
        set.set_timer("rekey_after_time", (30, 40));
        set.set_timer("reject_after_time", (60, 80));
        let (_, cfg) = set
            .merged(ObfuscationRanges::default(), &current, 1420)
            .expect("a coherent tuning is valid");
        assert_eq!(cfg.timers.rekey_after_time, (30, 40));
        assert_eq!(cfg.timers.reject_after_time, (60, 80));
        assert_eq!(cfg.timers.rekey_timeout, (0, 0), "unmentioned stays unset");

        // A later transaction that does not mention timers keeps them.
        let mut untouched = AwgParams::default();
        untouched.set_size("s1", 120);
        let (_, kept) = untouched
            .merged(ObfuscationRanges::default(), &cfg, 1420)
            .expect("valid");
        assert_eq!(kept.timers.rekey_after_time, (30, 40), "must survive");

        // `(0, 0)` clears one key and leaves the other. Clearing reject is the
        // direction the floors allow: its 180-second default satisfies every
        // ordering.
        let mut clear = AwgParams::default();
        clear.set_timer("reject_after_time", (0, 0));
        let (_, cleared) = clear
            .merged(ObfuscationRanges::default(), &kept, 1420)
            .expect("valid");
        assert_eq!(cleared.timers.reject_after_time, (0, 0), "must clear");
        assert_eq!(cleared.timers.rekey_after_time, (30, 40), "must remain");

        // The reverse clear is refused: dropping rekey_after_time resurrects
        // its 120-second default, under which the kept 60-80 reject would
        // discard keys before the rekey replacing them completes. The floors
        // catch configurations that become incoherent by *clearing*, not just
        // by setting.
        let mut bad_clear = AwgParams::default();
        bad_clear.set_timer("rekey_after_time", (0, 0));
        assert_eq!(
            bad_clear
                .merged(ObfuscationRanges::default(), &kept, 1420)
                .err(),
            Some(EINVAL),
            "clearing rekey_after_time under a short reject must be refused"
        );

        // Floors fail the merge: a reject_after_time draw shorter than the
        // (default) rekey_after_time + rekey_timeout would reject keys before
        // the rekey replacing them completes.
        let mut low = AwgParams::default();
        low.set_timer("reject_after_time", (60, 80));
        assert_eq!(
            low.merged(ObfuscationRanges::default(), &current, 1420)
                .err(),
            Some(EINVAL),
            "reject 60 under default rekey_after 120 + rekey_timeout 5 must be refused"
        );

        // A zero inside a set range is a zero-second timer, not "unset".
        let mut zero = AwgParams::default();
        zero.set_timer("rekey_timeout", (0, 5));
        assert_eq!(
            zero.merged(ObfuscationRanges::default(), &current, 1420)
                .err(),
            Some(EINVAL),
            "a range containing 0 must be refused"
        );
    }

    #[test]
    fn an_awg3_device_key_is_tolerated_in_every_form_its_tools_emit() {
        // The two bool keys amneziawg-go's `get=1` emits *unconditionally*
        // (`boolf` has no is-set guard): a reapplied go dump always carries
        // `random_trailers=0` and `disable_cookies=0`, so refusing them would
        // abort every such transaction. Off -- what this build does -- is
        // silent agreement; on warns; junk is EINVAL.
        for key in ["random_trailers", "disable_cookies"] {
            for val in ["0", "false"] {
                assert_eq!(
                    handle_awg3_device_key(key, val),
                    Ok(()),
                    "{}={} must not abort the transaction",
                    key,
                    val
                );
            }
            for val in ["1", "true"] {
                assert_eq!(
                    handle_awg3_device_key(key, val),
                    Ok(()),
                    "{}={} is tolerated (with a warning)",
                    key,
                    val
                );
            }
            assert_eq!(handle_awg3_device_key(key, "maybe"), Err(EINVAL));
        }

        // And the catch-all this function replaced still rejects everything it
        // does not list.
        assert_eq!(handle_awg3_device_key("not_a_real_key", "1"), Err(EINVAL));
        // `header_protection_key` and the timers reach this fallback only if
        // the `api_set` arms above stop handling them, which is what makes
        // removing a feature surface as EINVAL rather than as silent
        // tolerance.
        assert_eq!(
            handle_awg3_device_key("header_protection_key", "0"),
            Err(EINVAL)
        );
        assert_eq!(
            handle_awg3_device_key("reject_after_time", "60"),
            Err(EINVAL)
        );
    }

    /// `content_padding_addition` through a `set=1` merge applies the range and
    /// the MTU, survives a merge that does not mention it, and clears on `(0,0)`.
    ///
    /// Pins the `set_content_padding` -> `merged` -> `content_padding_mtu`
    /// path: the range reaches the config, the MTU passed to `merged` is
    /// stored, and a later merge that does not mention padding keeps the range
    /// while refreshing the MTU. The `get=1` emit side is pinned separately by
    /// `the_get_emit_grammar_stays_byte_identical_for_a_vanilla_device`.
    #[test]
    fn content_padding_over_the_uapi_applies_and_round_trips() {
        let current = AmneziaConfig::default();

        // A range plus an MTU -> both land on the config.
        let mut set = AwgParams::default();
        set.set_content_padding((8, 24));
        let (_, cfg) = set
            .merged(ObfuscationRanges::default(), &current, 1280)
            .expect("a padding range is valid");
        assert_eq!(cfg.content_padding_addition, (8, 24));
        assert_eq!(cfg.content_padding_mtu, 1280);

        // A later transaction that does not mention padding keeps the range,
        // and refreshes the MTU from whatever the interface now reports.
        let mut untouched = AwgParams::default();
        untouched.set_size("s1", 120);
        let (_, kept) = untouched
            .merged(ObfuscationRanges::default(), &cfg, 1400)
            .expect("valid");
        assert_eq!(kept.content_padding_addition, (8, 24), "range must survive");
        assert_eq!(kept.content_padding_mtu, 1400, "MTU must refresh");

        // (0, 0) clears it.
        let mut cleared = AwgParams::default();
        cleared.set_content_padding((0, 0));
        let (_, off) = cleared
            .merged(ObfuscationRanges::default(), &cfg, 1400)
            .expect("valid");
        assert_eq!(off.content_padding_addition, (0, 0), "must clear to unset");
    }

    /// The `get=1` emit grammar, pinned against a plain buffer.
    ///
    /// The emit half of the feature previously had no coverage at all -- the
    /// merge test's doc admitted it. Two claims carry the interop story: a
    /// vanilla device emits *nothing* (its `get=1` output stays byte-identical
    /// to upstream boringtun, however much runtime state -- the learned MTU --
    /// it carries), and a configured one emits each key in the one spelling
    /// its tools reapply: bare value when the range is degenerate, `lo-hi`
    /// otherwise, absent when unset (amneziawg-go's `IpcGetOperation` omits
    /// every zero 3.0 tunable; the kernel tools print them at `=0` and our set
    /// side reads that back as unset).
    #[test]
    fn the_get_emit_grammar_stays_byte_identical_for_a_vanilla_device() {
        // Vanilla with a learned MTU: nothing at all.
        let mut out = Vec::new();
        let vanilla = AmneziaConfig::default().with_content_padding_addition(0, 0, 1420);
        write_awg_interface_params(&mut out, &ObfuscationRanges::default(), &vanilla);
        assert!(
            out.is_empty(),
            "a vanilla device's get=1 output grew: {:?}",
            String::from_utf8_lossy(&out)
        );

        // A configured device: sizes as %u, ranges in mh_genspec spelling.
        let mut out = Vec::new();
        let obf = ObfuscationRanges::new(
            169887817, 269887816, 390382747, 890382746, 1033691040, 1033691040, 1526332224,
            2026332223,
        )
        .expect("valid ranges");
        let cfg = AmneziaConfig::new(120, 130, 110, 80)
            .with_header_protection([0xab; 32])
            .with_content_padding_addition(8, 24, 1420);
        write_awg_interface_params(&mut out, &obf, &cfg);
        let text = String::from_utf8(out).expect("utf8");
        for line in [
            "s1=120\n",
            "s2=130\n",
            "s3=110\n",
            "s4=80\n",
            &format!("header_protection_key={}\n", "ab".repeat(32)),
            "h1=169887817-269887816\n",
            // A degenerate range is a bare value, matching `mh_genspec` and
            // amneziawg-go's `UintRange.ToString`.
            "h3=1033691040\n",
            "content_padding_addition=8-24\n",
        ] {
            assert!(text.contains(line), "missing {:?} in:\n{}", line, text);
        }
        assert!(
            !text.contains("content_padding_mtu"),
            "the MTU is a runtime clamp, not a UAPI value:\n{}",
            text
        );

        // A degenerate padding range is a bare value too, never `16-16`.
        let mut out = Vec::new();
        let cfg = AmneziaConfig::default().with_content_padding_addition(16, 16, 0);
        write_awg_interface_params(&mut out, &ObfuscationRanges::default(), &cfg);
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("content_padding_addition=16\n"), "{}", text);
        assert!(!text.contains("16-16"), "{}", text);

        // Set timers emit in the same grammar; unset ones stay absent, and the
        // two bool keys amneziawg-go invents unconditionally are never
        // emitted -- this build does not implement them, and a vanilla
        // device's output must not grow.
        let mut out = Vec::new();
        let cfg = AmneziaConfig::default().with_tunable_timers(AwgTimers {
            rekey_after_time: (30, 40),
            reject_after_time: (60, 60),
            ..AwgTimers::default()
        });
        write_awg_interface_params(&mut out, &ObfuscationRanges::default(), &cfg);
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("rekey_after_time=30-40\n"), "{}", text);
        assert!(text.contains("reject_after_time=60\n"), "{}", text);
        for absent in [
            "rekey_timeout",
            "keepalive_timeout",
            "max_handshake_attempts",
            "random_trailers",
            "disable_cookies",
        ] {
            assert!(
                !text.contains(absent),
                "{} leaked into get=1:\n{}",
                absent,
                text
            );
        }
    }

    /// An all-zero header-protection key means "off", not "reject".
    ///
    /// amneziawg-go accepts the key -- its `FromHex` is a length-checked hex
    /// decode with no zero test -- and then builds no cipher from it, so a peer
    /// sending 32 zero bytes has protection off and interoperates with a build
    /// that has it off too. Refusing the line would abort the whole `set=1`
    /// transaction mid-stream over a configuration that asks nothing of us.
    ///
    /// It is also the only way to turn protection off over UAPI, since `set=1`
    /// is seeded from the live device and an omitted key preserves the old one.
    /// So this pins two things at once: the zero key parses, and the merge that
    /// applies it leaves protection disabled rather than storing a "key" that
    /// masks with an all-zero keystream.
    #[test]
    fn a_zeroed_header_protection_key_means_off_not_a_key() {
        let current = AmneziaConfig::default();

        // A live key needs every junk size at or above `NONCE_SIZE`, because
        // the nonce is read out of the junk prefix. The default sizes are below
        // it, so a live key must be configured together with them.
        let mut live = AwgParams::default();
        live.set_size("s1", 16);
        live.set_size("s2", 16);
        live.set_size("s3", 16);
        live.set_size("s4", 16);
        live.set_header_protection([0xab; 32]);
        let (_, with_key) = live
            .merged(ObfuscationRanges::default(), &current, 1420)
            .expect("a live key with junk sizes >= NONCE_SIZE is valid");
        assert!(
            with_key.header_protection_enabled(),
            "precondition: a live key must enable protection, or the zero case \
             below proves nothing"
        );

        // The zero key carries no junk sizes at all, and is still accepted --
        // the nonce requirement applies only when protection is on, which is
        // also why amneziawg-go's UAPI skips that check for a zero key. If the
        // zero key were treated as set, this would fail the merge with EINVAL.
        let mut zeroed = AwgParams::default();
        zeroed.set_header_protection([0u8; 32]);
        let (_, merged) = zeroed
            .merged(ObfuscationRanges::default(), &current, 1420)
            .expect("an all-zero key does not require junk sizes");
        assert!(
            !merged.header_protection_enabled(),
            "32 zero bytes is amneziawg-go's 'off', not a key"
        );

        // And it clears a key the device already had -- the UAPI's only way to
        // turn protection off, since an omitted key preserves the old value.
        let (_, cleared) = zeroed
            .merged(ObfuscationRanges::default(), &with_key, 1420)
            .expect("an all-zero key does not require junk sizes");
        assert!(
            !cleared.header_protection_enabled(),
            "an all-zero key must clear a live one, not be ignored as 'unset'"
        );
    }

    /// The warning must report the interval it applied, not describe it.
    ///
    /// It used to say "using the low end of the range", which is false for
    /// exactly the inputs where `lo == 0` -- the clamp sends 1, and 0 is the
    /// one low end an operator is likely to write. A sentence about the
    /// arithmetic can drift from it; a field carrying the number cannot.
    #[test]
    fn the_keepalive_warning_reports_the_interval_it_applied() {
        use std::sync::{Arc, Mutex};
        use tracing::field::{Field, Visit};
        use tracing::Subscriber;
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;

        #[derive(Default)]
        struct Captured {
            message: String,
            fixed_interval: Option<u64>,
        }

        impl Visit for Captured {
            fn record_u64(&mut self, field: &Field, value: u64) {
                if field.name() == "fixed_interval" {
                    self.fixed_interval = Some(value);
                }
            }
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.message = format!("{:?}", value);
                }
            }
        }

        struct Capture(Arc<Mutex<Vec<Captured>>>);
        impl<S: Subscriber> Layer<S> for Capture {
            fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
                let mut c = Captured::default();
                event.record(&mut c);
                self.0.lock().unwrap().push(c);
            }
        }

        let capture = |val: &str| {
            let events = Arc::new(Mutex::new(Vec::new()));
            let subscriber = tracing_subscriber::registry().with(Capture(Arc::clone(&events)));
            let applied =
                tracing::subscriber::with_default(subscriber, || parse_keepalive_interval(val));
            let captured = std::mem::take(&mut *events.lock().unwrap());
            (applied, captured)
        };

        // (the value as it arrives over the UAPI, the interval applied, the
        // number of warnings the log gets, a word the diagnosis must contain --
        // "narrowed" and "capped" are different statements and a bare 70000
        // must not be told its range was narrowed)
        let cases: &[(&str, Option<u16>, usize, &str)] = &[
            // A range is narrowed, and the narrowed value is 1, not the 0 the
            // low end literally is.
            ("0-30", Some(1), 1, "narrowed"),
            // Narrowing a range we *can* apply verbatim is still a difference
            // from the peer -- it re-picks inside the range and we do not.
            ("25-35", Some(25), 1, "narrowed"),
            // A bare value we can store is applied verbatim and silently. A
            // warning on the common case is a warning that gets tuned out.
            ("25", Some(25), 0, ""),
            ("0", Some(0), 0, ""),
            ("65535", Some(65535), 0, ""),
            // A bare value we cannot store is capped, and a cap is a change to
            // the operator's number, so it says so.
            ("65536", Some(65535), 1, "capped"),
            ("70000", Some(65535), 1, "capped"),
            // Both at once: one warning, carrying what survived.
            ("70000-80000", Some(65535), 1, "narrowed"),
        ];

        for &(val, expected, warnings, diagnosis) in cases {
            let (applied, events) = capture(val);
            assert_eq!(applied, expected, "{} applied the wrong interval", val);
            let messages: Vec<&str> = events.iter().map(|e| e.message.as_str()).collect();
            assert_eq!(
                events.len(),
                warnings,
                "{} logged the wrong number of warnings: {:?}",
                val,
                messages
            );
            if warnings == 0 {
                continue;
            }
            assert_eq!(
                events[0].fixed_interval,
                expected.map(u64::from),
                "{}: the warning must carry the interval actually applied",
                val
            );
            assert!(
                events[0].message.contains(diagnosis),
                "{}: the warning gives the wrong diagnosis, expected {:?}: {}",
                val,
                diagnosis,
                events[0].message
            );
            assert!(
                !events[0].message.contains("low end"),
                "{}: the message claims the low end was used: {}",
                val,
                events[0].message
            );
        }
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
        // A bare value above u16::MAX is capped to what we can store, not
        // refused. amneziawg-go accepts it (`ParseUint(_, 10, 32)`), re-emits
        // it verbatim on `get=1`, and applies it as ~19.4 h; refusing it
        // returned EINVAL from `api_set_peer`, aborting a whole `set=1` over
        // the difference between two intervals that are equally "off" as far
        // as any NAT on the path is concerned.
        assert_eq!(parse_keepalive_interval("70000"), Some(65535));
        // Capped, not cast: `65536 as u16` is 0 -- the keepalive off for a
        // peer that asked for one, which is what this test is named after.
        assert_eq!(parse_keepalive_interval("65536"), Some(65535));
        assert_eq!(parse_keepalive_interval(&u32::MAX.to_string()), Some(65535));
        // The u32 ceiling is still a refusal, and it is the same one
        // amneziawg-go makes, so the two accept the same set of lines.
        assert_eq!(parse_keepalive_interval("4294967296"), None);
        assert_eq!(parse_keepalive_interval("25-4294967296"), None);
        // ...but the high end of a range is discarded, so it never has to fit.
        // amneziawg-go parses both ends as u32 and re-emits them on `get=1`, so
        // refusing these aborted a whole `set=1` over a number we do not read.
        assert_eq!(parse_keepalive_interval("25-70000"), Some(25));
        assert_eq!(parse_keepalive_interval("0-70000"), Some(1));
        assert_eq!(
            parse_keepalive_interval(&format!("65535-{}", u32::MAX)),
            Some(65535)
        );
        // The low end of a range is capped for the same reason, and by the
        // same expression.
        assert_eq!(
            parse_keepalive_interval("65536-70000"),
            Some(65535),
            "the low end is what we apply, so it is capped rather than cast"
        );
        assert_eq!(parse_keepalive_interval("70000-80000"), Some(65535));
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

    /// The acceptance policy for AmneziaWG device keys, pinned end to end.
    ///
    /// One sentence carries the fallback: a value that asks for behaviour this
    /// build does not have warns, a value that agrees with what it does is
    /// silent, and every implemented key is refused here because `api_set`
    /// consumes it first. All three are load-bearing. Losing the warning ships
    /// a daemon that ignores a feature the peer runs and says nothing; gaining
    /// one on a silent row fires a diagnostic on every reapplied amneziawg-go
    /// dump (which always carries `random_trailers=0`/`disable_cookies=0`),
    /// which is how a warning gets tuned out; and an implemented key slipping
    /// into the tolerance list is a feature silently vanishing instead of the
    /// transaction failing.
    ///
    /// The table below is the policy, and it is checked against the code
    /// rather than against the comments above it.
    #[test]
    fn an_awg3_device_key_warns_exactly_when_its_value_differs_from_ours() {
        const SILENT: &[tracing::Level] = &[];
        const WARNS: &[tracing::Level] = &[tracing::Level::WARN];

        let cases: &[PolicyRow] = &[
            // The unimplemented bool keys: off -- what this build does -- is
            // silent agreement in both spellings its tools produce, on warns,
            // junk is refused silently (EINVAL already answers the operator).
            ("random_trailers", "0", Ok(()), SILENT),
            ("random_trailers", "false", Ok(()), SILENT),
            ("random_trailers", "1", Ok(()), WARNS),
            ("random_trailers", "true", Ok(()), WARNS),
            ("random_trailers", "2", Err(EINVAL), SILENT),
            ("disable_cookies", "0", Ok(()), SILENT),
            ("disable_cookies", "1", Ok(()), WARNS),
            ("disable_cookies", "yes", Err(EINVAL), SILENT),
            // Implemented keys must not be quietly tolerated here -- `api_set`
            // consumes them before this fallback. If an `api_set` arm were
            // ever removed, these rows keep the fallback refusing the key, so
            // the whole `set=1` fails instead of the feature silently
            // vanishing: a peer masking the message-type field (or running
            // different timers) with our side ignoring it is mutually
            // unreachable or blackholed, not degraded.
            (
                "header_protection_key",
                "abababababababababababababababababababababababababababababababab",
                Err(EINVAL),
                SILENT,
            ),
            (
                "header_protection_key",
                "0000000000000000000000000000000000000000000000000000000000000000",
                Err(EINVAL),
                SILENT,
            ),
            ("content_padding_addition", "8-24", Err(EINVAL), SILENT),
            ("content_padding_addition", "0", Err(EINVAL), SILENT),
            ("reject_after_time", "180", Err(EINVAL), SILENT),
            ("reject_after_time", "0", Err(EINVAL), SILENT),
            ("rekey_after_time", "30-40", Err(EINVAL), SILENT),
            ("rekey_timeout", "5", Err(EINVAL), SILENT),
            ("keepalive_timeout", "10", Err(EINVAL), SILENT),
            ("max_handshake_attempts", "18", Err(EINVAL), SILENT),
            // A key from no list at all is still refused, and silently.
            ("not_a_real_key", "1", Err(EINVAL), SILENT),
        ];

        for &(key, val, expected_result, expected_levels) in cases {
            let (result, events) = capture_awg3_key(key, val);
            assert_eq!(
                result, expected_result,
                "{}={} was tolerated/refused against policy",
                key, val
            );
            let levels: Vec<tracing::Level> = events.iter().map(|e| e.level).collect();
            assert_eq!(
                levels.as_slice(),
                expected_levels,
                "{}={} logged the wrong thing: {:?}",
                key,
                val,
                events
            );

            if expected_levels != WARNS {
                continue;
            }
            // A warning that fires is only half the contract: it has to name
            // the key, because the operator's next question is which config
            // line was ignored.
            let warning = &events[0];
            assert_eq!(
                warning.key,
                Some(key.to_owned()),
                "the warning must name the key it is about"
            );
            assert!(
                warning.message.contains("not implemented"),
                "the warning must say the feature is not implemented: {}",
                warning.message
            );
        }
    }

    /// One row of the AWG-3 acceptance policy: the key and value as they arrive
    /// over the UAPI, the answer the transaction gets, and the events the log
    /// gets, in order.
    type PolicyRow = (
        &'static str,
        &'static str,
        Result<(), i32>,
        &'static [tracing::Level],
    );

    /// One `tracing` event, reduced to the fields the AWG-3 acceptance policy is
    /// stated in terms of.
    #[derive(Debug)]
    struct CapturedEvent {
        level: tracing::Level,
        message: String,
        key: Option<String>,
        requested_low: Option<u64>,
        requested_high: Option<u64>,
        ours: Option<String>,
    }

    impl tracing::field::Visit for CapturedEvent {
        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            match field.name() {
                "requested_low" => self.requested_low = Some(value),
                "requested_high" => self.requested_high = Some(value),
                _ => {}
            }
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            match field.name() {
                "key" => self.key = Some(value.to_owned()),
                "message" => self.message = value.to_owned(),
                _ => {}
            }
        }
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            match field.name() {
                "message" => self.message = format!("{:?}", value),
                "ours" => self.ours = Some(format!("{:?}", value)),
                _ => {}
            }
        }
    }

    /// Every event `handle_awg3_device_key` emits for one key/value, in order.
    ///
    /// Silence is a claim about behaviour like any other, and a subscriber is
    /// the only thing that can observe it. Same shape as
    /// `the_keepalive_warning_reports_the_interval_it_applied`; the default is
    /// thread-local, so this stays correct under the test harness's threads.
    fn capture_awg3_key(key: &str, val: &str) -> (Result<(), i32>, Vec<CapturedEvent>) {
        use std::sync::{Arc, Mutex};
        use tracing::Subscriber;
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;

        struct Capture(Arc<Mutex<Vec<CapturedEvent>>>);
        impl<S: Subscriber> Layer<S> for Capture {
            fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
                let mut captured = CapturedEvent {
                    level: *event.metadata().level(),
                    message: String::new(),
                    key: None,
                    requested_low: None,
                    requested_high: None,
                    ours: None,
                };
                event.record(&mut captured);
                self.0.lock().unwrap().push(captured);
            }
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Capture(Arc::clone(&events)));
        let result =
            tracing::subscriber::with_default(subscriber, || handle_awg3_device_key(key, val));
        let captured = std::mem::take(&mut *events.lock().unwrap());
        (result, captured)
    }
}
