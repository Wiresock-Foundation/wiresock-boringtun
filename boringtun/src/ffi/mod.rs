// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Requiring explicit per-fn "Safety" docs not worth it. Just pass in valid
// pointers and buffers/lengths to these, ok?
#![allow(clippy::missing_safety_doc)]

//! C bindings for the BoringTun library
use super::noise::{Tunn, TunnResult};
use crate::noise::amnezia::{
    AmneziaConfig, AmneziaImitationBrowser, AmneziaImitationProtocol, AwgTimers,
};
use crate::x25519::{PublicKey, StaticSecret};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hex::encode as encode_hex;
use libc::{raise, SIGSEGV};
use parking_lot::Mutex;
use rand_core::OsRng;
use tracing;
use tracing_subscriber::fmt;

use crate::serialization::KeyBytes;
use std::convert::TryFrom;
use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind, Write};
use std::os::raw::c_char;
use std::panic;
use std::ptr;
use std::ptr::null_mut;
use std::slice;
use std::sync::Once;

static PANIC_HOOK: Once = Once::new();

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
}

fn set_last_error(msg: &str) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(CString::new(msg).unwrap_or_else(|_| {
            CString::new("Invalid error message (contains null byte)").unwrap()
        }));
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

/// Returns a pointer to the last error message from any tunnel constructor, or
/// NULL if no error is stored.  The string is valid until the next constructor
/// call on the same thread, or until freed with `last_tunnel_error_free`.
#[no_mangle]
pub extern "C" fn last_tunnel_error() -> *const c_char {
    LAST_ERROR.with(|e| match *e.borrow() {
        Some(ref s) => s.as_ptr(),
        None => ptr::null(),
    })
}

/// Frees the last error string stored by a tunnel constructor.  After this call,
/// `last_tunnel_error` will return NULL until the next failure.
#[no_mangle]
pub extern "C" fn last_tunnel_error_free() {
    clear_last_error();
}

#[allow(non_camel_case_types)]
#[repr(C)]
/// Indicates the operation required from the caller
pub enum result_type {
    /// No operation is required.
    WIREGUARD_DONE = 0,
    /// Write dst buffer to network. Size indicates the number of bytes to write.
    WRITE_TO_NETWORK = 1,
    /// Some error occurred, no operation is required. Size indicates error code.
    WIREGUARD_ERROR = 2,
    /// Write dst buffer to the interface as an ipv4 packet. Size indicates the number of bytes to write.
    WRITE_TO_TUNNEL_IPV4 = 4,
    /// Write dst buffer to the interface as an ipv6 packet. Size indicates the number of bytes to write.
    WRITE_TO_TUNNEL_IPV6 = 6,
}

/// The return type of WireGuard functions
#[repr(C)]
pub struct wireguard_result {
    /// The operation to be performed by the caller
    pub op: result_type,
    /// Additional information, required to perform the operation
    pub size: usize,
}

#[repr(C)]
pub struct stats {
    pub time_since_last_handshake: i64,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    pub estimated_loss: f32,
    pub estimated_rtt: i32,
    reserved: [u8; 56], // Make sure to add new fields in this space, keeping total size constant
}

impl<'a> From<TunnResult<'a>> for wireguard_result {
    fn from(res: TunnResult<'a>) -> wireguard_result {
        match res {
            TunnResult::Done => wireguard_result {
                op: result_type::WIREGUARD_DONE,
                size: 0,
            },
            TunnResult::Err(e) => wireguard_result {
                op: result_type::WIREGUARD_ERROR,
                size: e as _,
            },
            TunnResult::WriteToNetwork(b) => wireguard_result {
                op: result_type::WRITE_TO_NETWORK,
                size: b.len(),
            },
            TunnResult::WriteToTunnelV4(b, _) => wireguard_result {
                op: result_type::WRITE_TO_TUNNEL_IPV4,
                size: b.len(),
            },
            TunnResult::WriteToTunnelV6(b, _) => wireguard_result {
                op: result_type::WRITE_TO_TUNNEL_IPV6,
                size: b.len(),
            },
        }
    }
}

#[repr(C)]
pub struct x25519_key {
    pub key: [u8; 32],
}

/// Generates a new x25519 secret key.
#[no_mangle]
pub extern "C" fn x25519_secret_key() -> x25519_key {
    x25519_key {
        key: StaticSecret::random_from_rng(OsRng).to_bytes(),
    }
}

/// Computes a public x25519 key from a secret key.
#[no_mangle]
pub extern "C" fn x25519_public_key(private_key: x25519_key) -> x25519_key {
    let private = StaticSecret::from(private_key.key);
    let public = PublicKey::from(&private);
    x25519_key {
        key: public.to_bytes(),
    }
}

/// Returns the base64 encoding of a key as a UTF8 C-string.
///
/// The memory has to be freed by calling `x25519_key_to_str_free`
#[no_mangle]
pub extern "C" fn x25519_key_to_base64(key: x25519_key) -> *const c_char {
    let encoded_key = BASE64.encode(key.key);
    CString::into_raw(CString::new(encoded_key).unwrap())
}

/// Returns the hex encoding of a key as a UTF8 C-string.
///
/// The memory has to be freed by calling `x25519_key_to_str_free`
#[no_mangle]
pub extern "C" fn x25519_key_to_hex(key: x25519_key) -> *const c_char {
    let encoded_key = encode_hex(key.key);
    CString::into_raw(CString::new(encoded_key).unwrap())
}

/// Frees memory of the string given by `x25519_key_to_hex` or `x25519_key_to_base64`
///
/// A NULL pointer is a no-op, as `free(NULL)` is in C.
///
/// `*const`, matching `wireguard_ffi.h`, which has always declared this as
/// `void x25519_key_to_str_free(const char *)` -- and matching the two
/// functions that produce the pointer, which return `*const c_char`. The
/// pointer is `*mut` underneath (it came from `CString::into_raw`), so the cast
/// back is sound; taking `*mut` here only forced every caller to cast away a
/// constness this library never really claimed. ABI is unchanged: both are thin
/// pointers.
#[no_mangle]
pub unsafe extern "C" fn x25519_key_to_str_free(stringified_key: *const c_char) {
    if stringified_key.is_null() {
        return;
    }
    drop(CString::from_raw(stringified_key as *mut c_char));
}

/// Check if the input C-string represents a valid base64 encoded x25519 key.
/// Return 1 if valid 0 otherwise.
#[no_mangle]
pub unsafe extern "C" fn check_base64_encoded_x25519_key(key: *const c_char) -> i32 {
    let c_str = CStr::from_ptr(key);
    let utf8_key = match c_str.to_str() {
        Err(_) => return 0,
        Ok(string) => string,
    };

    if let Ok(key) = BASE64.decode(utf8_key) {
        let len = key.len();
        let mut zero = 0u8;
        for b in key {
            zero |= b
        }
        if len == 32 && zero != 0 {
            1
        } else {
            0
        }
    } else {
        0
    }
}

/// Custom tracing_subscriber writer to an external function pointer
struct FFIFunctionPointerWriter {
    log_func: unsafe extern "C" fn(*const c_char),
}

/// Implements Write trait for use with tracing_subscriber
impl Write for FFIFunctionPointerWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        let out_str = String::from_utf8_lossy(buf).to_string();
        if let Ok(c_string) = CString::new(out_str) {
            unsafe { (self.log_func)(c_string.as_ptr()) }
            Ok(buf.len())
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "Failed to create CString from buffer.",
            ))
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        // no-op
        Ok(())
    }
}

/// Sets the default tracing_subscriber to write to `log_func`.
///
/// Uses Compact format without level, target, thread ids, thread names, or ansi control characters.
/// Subscribes to TRACE level events.
///
/// This function should only be called once as setting the default tracing_subscriber
/// more than once will result in an error.
///
/// Returns false on failure.
///
/// # Safety
///
/// `c_char` will be freed by the library after calling `log_func`. If the value needs
/// to be stored then `log_func` needs to create a copy, e.g. `strcpy`.
#[no_mangle]
pub unsafe extern "C" fn set_logging_function(
    log_func: unsafe extern "C" fn(*const c_char),
) -> bool {
    let result = std::panic::catch_unwind(|| -> bool {
        let writer = FFIFunctionPointerWriter { log_func };
        let format = fmt::format()
            // don't include levels in formatted output
            .with_level(false)
            // don't include targets
            .with_target(false)
            // don't 'include the thread ID of the current thread
            .with_thread_ids(false)
            // don't 'include the name of the current thread
            .with_thread_names(false)
            // use the `Compact` formatting style.
            .compact()
            // disable terminal escape codes
            .with_ansi(false);

        fmt()
            .event_format(format)
            .with_writer(std::sync::Mutex::new(writer))
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .try_init()
            .is_ok()
    });
    if let Ok(value) = result {
        value
    } else {
        false
    }
}

/// Allocate a new tunnel, return NULL on failure.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
) -> *mut Mutex<Tunn> {
    clear_last_error();
    new_tunnel_with_amnezia(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        0,
        0,
        0,
        0,
    )
}

// The shared body of the six `extern "C"` tunnel constructors below, which
// take these values as scalars because a C caller cannot pass a Rust type.
// Collapsing the list here would only move the widening one frame outward.
#[allow(clippy::too_many_arguments)]
unsafe fn new_tunnel_with_amnezia_config(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
    amnezia: AmneziaConfig,
) -> *mut Mutex<Tunn> {
    if static_private.is_null() {
        set_last_error("Missing static private key");
        return ptr::null_mut();
    }
    if server_static_public.is_null() {
        set_last_error("Missing server static public key");
        return ptr::null_mut();
    }

    let c_str = CStr::from_ptr(static_private);
    let static_private = match c_str.to_str() {
        Err(_) => {
            set_last_error("Invalid static private key: not UTF-8");
            return ptr::null_mut();
        }
        Ok(string) => string,
    };

    let c_str = CStr::from_ptr(server_static_public);
    let server_static_public = match c_str.to_str() {
        Err(_) => {
            set_last_error("Invalid server static public key: not UTF-8");
            return ptr::null_mut();
        }
        Ok(string) => string,
    };

    let preshared_key = if preshared_key.is_null() {
        None
    } else {
        let c_str = CStr::from_ptr(preshared_key);

        if let Ok(string) = c_str.to_str() {
            if let Ok(key) = string.parse::<KeyBytes>() {
                Some(key.0)
            } else {
                set_last_error("Invalid preshared key");
                return null_mut();
            }
        } else {
            set_last_error("Invalid preshared key: not UTF-8");
            return null_mut();
        }
    };

    let private_key = match static_private.parse::<KeyBytes>() {
        Err(_) => {
            set_last_error("Invalid static private key");
            return ptr::null_mut();
        }
        Ok(key) => StaticSecret::from(key.0),
    };

    let public_key = match server_static_public.parse::<KeyBytes>() {
        Err(_) => {
            set_last_error("Invalid server static public key");
            return ptr::null_mut();
        }
        Ok(key) => PublicKey::from(key.0),
    };

    let keep_alive = if keep_alive == 0 {
        None
    } else {
        Some(keep_alive)
    };

    let tunnel = match Tunn::new_with_amnezia(
        private_key,
        public_key,
        preshared_key,
        keep_alive,
        index,
        None,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        amnezia,
    ) {
        Ok(t) => Box::new(Mutex::new(t)),
        Err(e) => {
            tracing::error!(message = "Failed to create tunnel", error = %e);
            set_last_error(&e);
            return ptr::null_mut();
        }
    };

    PANIC_HOOK.call_once(|| {
        // FFI won't properly unwind on panic, but it will if we cause a segmentation fault
        panic::set_hook(Box::new(move |_| {
            raise(SIGSEGV);
        }));
    });

    Box::into_raw(tunnel)
}

/// Allocate a new tunnel with Amnezia S1-S4 junk prefix handling.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_with_amnezia(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
    s1_init_junk: u16,
    s2_response_junk: u16,
    s3_cookie_junk: u16,
    s4_transport_junk: u16,
) -> *mut Mutex<Tunn> {
    clear_last_error();
    new_tunnel_with_amnezia_config(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        AmneziaConfig::new(
            s1_init_junk,
            s2_response_junk,
            s3_cookie_junk,
            s4_transport_junk,
        ),
    )
}

/// Allocate a new tunnel with Amnezia pre-handshake junk and S1-S4 junk prefix handling.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_with_amnezia_junk(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
    s1_init_junk: u16,
    s2_response_junk: u16,
    s3_cookie_junk: u16,
    s4_transport_junk: u16,
    junk_packet_count: u16,
    junk_packet_size_min: u16,
    junk_packet_size_max: u16,
    junk_packet_delay_ms: u16,
) -> *mut Mutex<Tunn> {
    clear_last_error();
    new_tunnel_with_amnezia_config(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        AmneziaConfig::new(
            s1_init_junk,
            s2_response_junk,
            s3_cookie_junk,
            s4_transport_junk,
        )
        .with_pre_handshake_junk(
            junk_packet_count,
            junk_packet_size_min,
            junk_packet_size_max,
            junk_packet_delay_ms,
        ),
    )
}

unsafe fn parse_amnezia_imitation(
    imitation_protocol: u8,
    imitation_domain: *const c_char,
) -> Option<(AmneziaImitationProtocol, Option<String>)> {
    let imitation_protocol = match AmneziaImitationProtocol::try_from(imitation_protocol) {
        Ok(protocol) => protocol,
        Err(_) => {
            set_last_error("Invalid Amnezia imitation protocol");
            return None;
        }
    };

    let imitation_domain = if imitation_domain.is_null() {
        None
    } else {
        let c_str = CStr::from_ptr(imitation_domain);
        match c_str.to_str() {
            Ok(domain) => Some(domain.to_owned()),
            Err(_) => None,
        }
    };

    Some((imitation_protocol, imitation_domain))
}

fn parse_amnezia_browser(imitation_browser: u8) -> Option<AmneziaImitationBrowser> {
    match AmneziaImitationBrowser::try_from(imitation_browser) {
        Ok(browser) => Some(browser),
        Err(_) => {
            set_last_error("Invalid Amnezia imitation browser");
            None
        }
    }
}

/// Allocate a new tunnel with Amnezia S1-S4 junk prefix handling and protocol-shaped junk.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_with_amnezia_imitation(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
    s1_init_junk: u16,
    s2_response_junk: u16,
    s3_cookie_junk: u16,
    s4_transport_junk: u16,
    imitation_protocol: u8,
    imitation_domain: *const c_char,
) -> *mut Mutex<Tunn> {
    clear_last_error();
    let Some((imitation_protocol, imitation_domain)) =
        parse_amnezia_imitation(imitation_protocol, imitation_domain)
    else {
        return ptr::null_mut();
    };

    new_tunnel_with_amnezia_config(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        AmneziaConfig::new(
            s1_init_junk,
            s2_response_junk,
            s3_cookie_junk,
            s4_transport_junk,
        )
        .with_protocol_imitation(imitation_protocol, imitation_domain),
    )
}

/// Allocate a new tunnel with Amnezia pre-handshake junk, S1-S4 junk prefix
/// handling, and protocol-shaped junk.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_with_amnezia_junk_imitation(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
    s1_init_junk: u16,
    s2_response_junk: u16,
    s3_cookie_junk: u16,
    s4_transport_junk: u16,
    junk_packet_count: u16,
    junk_packet_size_min: u16,
    junk_packet_size_max: u16,
    junk_packet_delay_ms: u16,
    imitation_protocol: u8,
    imitation_domain: *const c_char,
) -> *mut Mutex<Tunn> {
    clear_last_error();
    let Some((imitation_protocol, imitation_domain)) =
        parse_amnezia_imitation(imitation_protocol, imitation_domain)
    else {
        return ptr::null_mut();
    };

    new_tunnel_with_amnezia_config(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        AmneziaConfig::new(
            s1_init_junk,
            s2_response_junk,
            s3_cookie_junk,
            s4_transport_junk,
        )
        .with_pre_handshake_junk(
            junk_packet_count,
            junk_packet_size_min,
            junk_packet_size_max,
            junk_packet_delay_ms,
        )
        .with_protocol_imitation(imitation_protocol, imitation_domain),
    )
}

/// Allocate a new tunnel with Amnezia S1-S4 junk prefix handling and a
/// browser-fingerprinted QUIC Initial imitation.
///
/// `imitation_browser` selects the QUIC ClientHello fingerprint (see
/// `enum wireguard_amnezia_browser_profile`); it is only meaningful when
/// `imitation_protocol` is QUIC. An omitted/DEFAULT browser resolves to curl, so
/// a configured QUIC domain always yields a full QUIC Initial.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_with_amnezia_imitation_browser(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
    s1_init_junk: u16,
    s2_response_junk: u16,
    s3_cookie_junk: u16,
    s4_transport_junk: u16,
    imitation_protocol: u8,
    imitation_domain: *const c_char,
    imitation_browser: u8,
) -> *mut Mutex<Tunn> {
    clear_last_error();
    let Some((imitation_protocol, imitation_domain)) =
        parse_amnezia_imitation(imitation_protocol, imitation_domain)
    else {
        return ptr::null_mut();
    };
    // The browser is only meaningful for QUIC; for other protocols its value is
    // ignored (AmneziaImitation::new forces Default), so don't reject an
    // out-of-range value there — that would be a surprising constructor failure.
    let imitation_browser = if imitation_protocol == AmneziaImitationProtocol::Quic {
        let Some(browser) = parse_amnezia_browser(imitation_browser) else {
            return ptr::null_mut();
        };
        browser
    } else {
        AmneziaImitationBrowser::Default
    };

    new_tunnel_with_amnezia_config(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        AmneziaConfig::new(
            s1_init_junk,
            s2_response_junk,
            s3_cookie_junk,
            s4_transport_junk,
        )
        .with_protocol_imitation_browser(
            imitation_protocol,
            imitation_domain,
            imitation_browser,
        ),
    )
}

/// Allocate a new tunnel with Amnezia pre-handshake junk, S1-S4 junk prefix
/// handling, and a browser-fingerprinted QUIC Initial imitation.
///
/// As `new_tunnel_with_amnezia_imitation_browser`, plus the Jc/Jmin/Jmax/Jd
/// pre-handshake junk knobs. When a QUIC browser is selected, the standalone
/// browser Initial(s) are emitted before the handshake regardless of Jc.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_with_amnezia_junk_imitation_browser(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
    s1_init_junk: u16,
    s2_response_junk: u16,
    s3_cookie_junk: u16,
    s4_transport_junk: u16,
    junk_packet_count: u16,
    junk_packet_size_min: u16,
    junk_packet_size_max: u16,
    junk_packet_delay_ms: u16,
    imitation_protocol: u8,
    imitation_domain: *const c_char,
    imitation_browser: u8,
) -> *mut Mutex<Tunn> {
    clear_last_error();
    let Some((imitation_protocol, imitation_domain)) =
        parse_amnezia_imitation(imitation_protocol, imitation_domain)
    else {
        return ptr::null_mut();
    };
    // The browser is only meaningful for QUIC; for other protocols its value is
    // ignored (AmneziaImitation::new forces Default), so don't reject an
    // out-of-range value there — that would be a surprising constructor failure.
    let imitation_browser = if imitation_protocol == AmneziaImitationProtocol::Quic {
        let Some(browser) = parse_amnezia_browser(imitation_browser) else {
            return ptr::null_mut();
        };
        browser
    } else {
        AmneziaImitationBrowser::Default
    };

    new_tunnel_with_amnezia_config(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        AmneziaConfig::new(
            s1_init_junk,
            s2_response_junk,
            s3_cookie_junk,
            s4_transport_junk,
        )
        .with_pre_handshake_junk(
            junk_packet_count,
            junk_packet_size_min,
            junk_packet_size_max,
            junk_packet_delay_ms,
        )
        .with_protocol_imitation_browser(
            imitation_protocol,
            imitation_domain,
            imitation_browser,
        ),
    )
}

/// An inclusive `[lo, hi]` range of unsigned values.
///
/// `{0, 0}` is the unset sentinel, exactly as it is in the AmneziaWG UAPI and
/// on the wire: the built-in default governs and nothing is drawn. A degenerate
/// range (`lo == hi`) is a fixed value.
///
/// Deliberately not a packed scalar. amneziawg-tools packs its equivalents into
/// a `uint32`/`uint64` (`u16_range_t`, `u32_range_t`), which saves nothing here
/// and costs a caller the chance to get the halves the wrong way round.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct wireguard_awg_range {
    pub lo: u32,
    pub hi: u32,
}

impl From<wireguard_awg_range> for (u32, u32) {
    fn from(r: wireguard_awg_range) -> (u32, u32) {
        (r.lo, r.hi)
    }
}

/// Every AmneziaWG parameter this build understands, in one extensible struct.
///
/// Passed to [`new_tunnel_with_awg_params`] instead of being spread across a
/// positional argument list. The six `new_tunnel_with_amnezia*` constructors
/// grew one variant per feature combination and reached twenty-four scalar
/// arguments; three more features would not have fit, and a transposed pair of
/// same-typed arguments in a list that long is a silent misconfiguration rather
/// than a compile error.
///
/// # Versioning
///
/// `size` must be set to `sizeof(struct wireguard_awg_params)` by the caller,
/// which is what lets this struct grow without another entry point:
///
/// * A **smaller** struct than the library knows is a caller built against an
///   older header. The missing tail is read as zero, i.e. unset, which is the
///   same thing that header's author asked for.
/// * A **larger** struct is a caller built against a newer header. It is
///   accepted only if every byte past what this library understands is zero --
///   a caller that is not using the new fields. If any of them is non-zero the
///   call fails rather than silently dropping a parameter the caller set:
///   ignoring, say, a header-protection key produces a tunnel that is mutually
///   unreachable with its peer, which is far worse than a refused constructor.
///
/// # Layout
///
/// Every field is a `uint32_t`, a fixed-size array of them, or a fixed byte
/// array, and there is no pointer and no sub-word type anywhere. The struct
/// therefore has no padding and an identical size and layout on i686 and
/// x86_64 -- both of which this crate ships (the Windows 7 targets) -- so
/// `size` means the same thing in a 32-bit and a 64-bit build. The imitation
/// domain is a string and is passed as its own argument for that reason.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct wireguard_awg_params {
    /// `sizeof(struct wireguard_awg_params)`. See the versioning note above.
    pub size: u32,

    /// S1-S4: junk prepended to handshake initiation, handshake response,
    /// cookie reply and transport packets. `0` disables that prefix.
    pub s1_init_junk: u32,
    pub s2_response_junk: u32,
    pub s3_cookie_junk: u32,
    pub s4_transport_junk: u32,

    /// Jc/Jmin/Jmax/Jd: the pre-handshake junk burst -- packet count, size
    /// bounds, and the delay between packets in milliseconds.
    pub junk_packet_count: u32,
    pub junk_packet_size_min: u32,
    pub junk_packet_size_max: u32,
    pub junk_packet_delay_ms: u32,

    /// H1-H4: the message-type tag ranges for initiation, response, cookie
    /// reply and transport packets. Unset leaves the vanilla WireGuard type.
    pub h1_init: wireguard_awg_range,
    pub h2_resp: wireguard_awg_range,
    pub h3_cookie: wireguard_awg_range,
    pub h4_data: wireguard_awg_range,

    /// Protocol imitation, and the browser profile QUIC imitates. The browser
    /// is ignored for every other protocol. Values are the same enums the
    /// legacy constructors take.
    pub imitation_protocol: u32,
    pub imitation_browser: u32,

    /// AmneziaWG 3.0 `content_padding_addition`: zero bytes appended to each
    /// transport plaintext, inside the AEAD. Unset still rounds the plaintext
    /// up to a 16-byte multiple, which is what every WireGuard implementation
    /// does.
    pub content_padding_addition: wireguard_awg_range,
    /// The MTU the padding is clamped against, so a full-MTU packet is not
    /// grown past what the link carries. `0` means "no MTU known", leaving the
    /// caller's buffer as the only bound.
    pub content_padding_mtu: u32,

    /// AmneziaWG 3.0 tunable timers, in seconds -- except
    /// `max_handshake_attempts`, which is a count. Unset means the classic
    /// WireGuard constant governs, so an all-zero block is vanilla timing.
    pub rekey_after_time: wireguard_awg_range,
    pub rekey_timeout: wireguard_awg_range,
    pub reject_after_time: wireguard_awg_range,
    pub keepalive_timeout: wireguard_awg_range,
    pub max_handshake_attempts: wireguard_awg_range,

    /// AmneziaWG 3.0 `header_protection_key`: a 32-byte key masking the
    /// message-type field. All zero means off, matching amneziawg-go, so this
    /// is also how it is disabled again. Both ends must carry the same key --
    /// it is not negotiated, so a mismatch is a tunnel that never forms.
    pub header_protection_key: [u8; 32],
}

/// The size of the first published version of [`wireguard_awg_params`].
///
/// A caller may pass a struct this small forever; the tail it does not have is
/// read as unset. Pinned as a literal, not as `size_of`, so that adding a field
/// cannot silently redefine what "the original struct" was and start rejecting
/// callers built against it.
const AWG_PARAMS_SIZE_VER0: usize = 160;

/// How many of a caller's bytes to copy: never more than they passed, never
/// more than this build understands.
///
/// Split out because it is the ABI's forward-compatibility rule and, today,
/// unreachable: `AWG_PARAMS_SIZE_VER0` equals this build's size, so a struct
/// that is valid *and* short cannot exist yet, and the clamp cannot be
/// exercised through [`read_awg_params`]. Extracting it makes the promise
/// testable now rather than in the release that first depends on it -- when
/// getting it wrong would read past a caller's allocation.
const fn awg_params_copy_len(caller_size: usize, our_size: usize) -> usize {
    if caller_size < our_size {
        caller_size
    } else {
        our_size
    }
}

/// Read a caller's [`wireguard_awg_params`] of any published size.
///
/// Copies the caller's bytes into a zeroed struct of the size this build
/// understands, so a short struct's absent tail reads as unset, and refuses a
/// longer one that carries anything non-zero past what we understand.
///
/// # Safety
///
/// `params` must be non-null and point to at least `params->size` readable
/// bytes.
unsafe fn read_awg_params(params: *const wireguard_awg_params) -> Option<wireguard_awg_params> {
    // Read only the leading `size` before trusting anything else: the caller's
    // allocation may be shorter than our struct, so reading the whole thing
    // first would be the very overrun `size` exists to prevent.
    let caller_size = ptr::read_unaligned(params as *const u32) as usize;
    let our_size = std::mem::size_of::<wireguard_awg_params>();

    if caller_size < AWG_PARAMS_SIZE_VER0 {
        set_last_error(&format!(
            "Invalid AmneziaWG parameters: size is {}, which is smaller than the {}-byte \
             minimum; set params.size = sizeof(struct wireguard_awg_params)",
            caller_size, AWG_PARAMS_SIZE_VER0
        ));
        return None;
    }

    if caller_size > our_size {
        // A newer caller. Accept it only if it is not actually using anything
        // this build does not understand.
        let tail =
            slice::from_raw_parts((params as *const u8).add(our_size), caller_size - our_size);
        if tail.iter().any(|&b| b != 0) {
            set_last_error(&format!(
                "Unsupported AmneziaWG parameters: size is {}, this build understands {}, and \
                 the extra bytes are not empty -- the caller is setting a parameter this \
                 library does not implement",
                caller_size, our_size
            ));
            return None;
        }
    }

    let mut out = wireguard_awg_params::default();
    let copy = awg_params_copy_len(caller_size, our_size);
    ptr::copy_nonoverlapping(
        params as *const u8,
        &mut out as *mut wireguard_awg_params as *mut u8,
        copy,
    );
    out.size = our_size as u32;
    Some(out)
}

/// Turn a caller's parameters into an [`AmneziaConfig`], or report why not.
///
/// The imitation domain arrives separately because it is a string: a pointer
/// inside the struct would make its size differ between the 32- and 64-bit
/// builds, which is exactly what the `size` field must not depend on.
fn awg_params_to_config(
    p: &wireguard_awg_params,
    imitation_domain: Option<String>,
) -> Option<AmneziaConfig> {
    // The sizes are `u16` in the config; a value that does not fit is a
    // caller error worth naming rather than truncating into a different
    // configuration.
    fn size16(label: &str, value: u32) -> Option<u16> {
        u16::try_from(value).ok().or_else(|| {
            set_last_error(&format!(
                "Invalid AmneziaWG parameters: {} is {}, which exceeds the {} maximum",
                label,
                value,
                u16::MAX
            ));
            None
        })
    }

    let s1 = size16("s1_init_junk", p.s1_init_junk)?;
    let s2 = size16("s2_response_junk", p.s2_response_junk)?;
    let s3 = size16("s3_cookie_junk", p.s3_cookie_junk)?;
    let s4 = size16("s4_transport_junk", p.s4_transport_junk)?;
    let jc = size16("junk_packet_count", p.junk_packet_count)?;
    let jmin = size16("junk_packet_size_min", p.junk_packet_size_min)?;
    let jmax = size16("junk_packet_size_max", p.junk_packet_size_max)?;
    let jd = size16("junk_packet_delay_ms", p.junk_packet_delay_ms)?;
    let mtu = size16("content_padding_mtu", p.content_padding_mtu)?;

    let protocol = match u8::try_from(p.imitation_protocol)
        .ok()
        .and_then(|v| AmneziaImitationProtocol::try_from(v).ok())
    {
        Some(protocol) => protocol,
        None => {
            set_last_error("Invalid Amnezia imitation protocol");
            return None;
        }
    };

    // The browser is only meaningful for QUIC; elsewhere its value is ignored
    // (`AmneziaImitation::new` forces Default), so an out-of-range value there
    // is not a constructor failure -- the same rule the legacy constructors
    // follow.
    let browser = if protocol == AmneziaImitationProtocol::Quic {
        match u8::try_from(p.imitation_browser)
            .ok()
            .and_then(|v| AmneziaImitationBrowser::try_from(v).ok())
        {
            Some(browser) => browser,
            None => {
                set_last_error("Invalid Amnezia imitation browser");
                return None;
            }
        }
    } else {
        AmneziaImitationBrowser::Default
    };

    Some(
        AmneziaConfig::new(s1, s2, s3, s4)
            .with_pre_handshake_junk(jc, jmin, jmax, jd)
            .with_protocol_imitation_browser(protocol, imitation_domain, browser)
            .with_header_protection(p.header_protection_key)
            .with_content_padding_addition(
                p.content_padding_addition.lo,
                p.content_padding_addition.hi,
                mtu,
            )
            .with_tunable_timers(AwgTimers {
                rekey_after_time: p.rekey_after_time.into(),
                rekey_timeout: p.rekey_timeout.into(),
                reject_after_time: p.reject_after_time.into(),
                keepalive_timeout: p.keepalive_timeout.into(),
                max_handshake_attempts: p.max_handshake_attempts.into(),
            }),
    )
}

/// Allocate a new tunnel from a full set of AmneziaWG parameters.
///
/// The one constructor that can express every AmneziaWG feature this build
/// implements, including the 3.0 additions -- header protection, content
/// padding and the tunable timers -- which no other entry point can reach.
/// Keys must be valid base64-encoded 32-byte keys.
///
/// `params` may be NULL, which is a plain WireGuard tunnel with no AmneziaWG
/// behaviour at all. Otherwise `params->size` must be set; see
/// [`wireguard_awg_params`]. `imitation_domain` may be NULL, and is ignored by
/// the protocols that do not carry a hostname.
///
/// Unlike the legacy constructors, the whole configuration is validated before
/// a tunnel exists: a set of parameters that could never emit a valid datagram,
/// or whose timers are ordered so that keys would be rejected before the rekey
/// replacing them completes, fails here with a message from
/// `last_tunnel_error()` rather than becoming a tunnel that silently never
/// works.
///
/// Returns NULL on failure, with the reason in `last_tunnel_error()`.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_with_awg_params(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    params: *const wireguard_awg_params,
    imitation_domain: *const c_char,
) -> *mut Mutex<Tunn> {
    clear_last_error();

    let (amnezia, h1, h2, h3, h4) = if params.is_null() {
        (
            AmneziaConfig::default(),
            wireguard_awg_range::default(),
            wireguard_awg_range::default(),
            wireguard_awg_range::default(),
            wireguard_awg_range::default(),
        )
    } else {
        let Some(p) = read_awg_params(params) else {
            return ptr::null_mut();
        };
        // A non-UTF-8 domain is refused rather than dropped. The legacy
        // constructors silently discard one (`parse_amnezia_imitation` maps the
        // error to `None`), which hands back a tunnel imitating the right
        // protocol with a randomly generated hostname -- a substitution the
        // caller can only discover in a packet capture.
        let domain = if imitation_domain.is_null() {
            None
        } else {
            match CStr::from_ptr(imitation_domain).to_str() {
                Ok(domain) => Some(domain.to_owned()),
                Err(_) => {
                    set_last_error("Invalid Amnezia imitation domain: not UTF-8");
                    return ptr::null_mut();
                }
            }
        };
        let Some(config) = awg_params_to_config(&p, domain) else {
            return ptr::null_mut();
        };
        (config, p.h1_init, p.h2_resp, p.h3_cookie, p.h4_data)
    };

    // Validated here rather than at the first datagram. The legacy
    // constructors predate this and only check the header-protection nonce
    // (through `Tunn::new_with_amnezia`), which was harmless while no FFI path
    // could set a key -- this one can set all three 3.0 features, which is
    // exactly what `validate` exists to catch.
    if let Err(e) = amnezia.validate() {
        set_last_error(&format!("Invalid AmneziaWG parameters: {}", e));
        return ptr::null_mut();
    }

    new_tunnel_with_amnezia_config(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1.lo,
        h1.hi,
        h2.lo,
        h2.hi,
        h3.lo,
        h3.hi,
        h4.lo,
        h4.hi,
        amnezia,
    )
}

/// Drops the Tunn object
///
/// A NULL pointer is a no-op, as `free(NULL)` is in C.
#[no_mangle]
pub unsafe extern "C" fn tunnel_free(tunnel: *mut Mutex<Tunn>) {
    if tunnel.is_null() {
        return;
    }
    drop(Box::from_raw(tunnel));
}

/// Write an IP packet from the tunnel interface.
/// For more details check noise::tunnel_to_network functions.
#[no_mangle]
pub unsafe extern "C" fn wireguard_write(
    tunnel: *const Mutex<Tunn>,
    src: *const u8,
    src_size: u32,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let mut tunnel = tunnel.as_ref().unwrap().lock();
    // Slices are not owned, and therefore will not be freed by Rust
    let src = slice::from_raw_parts(src, src_size as usize);
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.encapsulate(src, dst))
}

/// Read a UDP packet from the server.
/// For more details check noise::network_to_tunnel functions.
#[no_mangle]
pub unsafe extern "C" fn wireguard_read(
    tunnel: *const Mutex<Tunn>,
    src: *const u8,
    src_size: u32,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let mut tunnel = tunnel.as_ref().unwrap().lock();
    // Slices are not owned, and therefore will not be freed by Rust
    let src = slice::from_raw_parts(src, src_size as usize);
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.decapsulate(None, src, dst))
}

/// This is a state keeping function, that need to be called periodically.
/// Recommended interval: 100ms.
#[no_mangle]
pub unsafe extern "C" fn wireguard_tick(
    tunnel: *const Mutex<Tunn>,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let mut tunnel = tunnel.as_ref().unwrap().lock();
    // Slices are not owned, and therefore will not be freed by Rust
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.update_timers(dst))
}

/// Force the tunnel to initiate a new handshake, dst buffer must be at least 148 byte long.
#[no_mangle]
pub unsafe extern "C" fn wireguard_force_handshake(
    tunnel: *const Mutex<Tunn>,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let mut tunnel = tunnel.as_ref().unwrap().lock();
    // Slices are not owned, and therefore will not be freed by Rust
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.format_handshake_initiation(dst, true))
}

/// Returns stats from the tunnel:
/// Time of last handshake in seconds (or -1 if no handshake occurred)
/// Number of data bytes encapsulated
/// Number of data bytes decapsulated
#[no_mangle]
pub unsafe extern "C" fn wireguard_stats(tunnel: *const Mutex<Tunn>) -> stats {
    let tunnel = tunnel.as_ref().unwrap().lock();
    let (time, tx_bytes, rx_bytes, estimated_loss, estimated_rtt) = tunnel.stats();
    stats {
        time_since_last_handshake: time.map(|t| t.as_secs() as i64).unwrap_or(-1),
        tx_bytes,
        rx_bytes,
        estimated_loss,
        estimated_rtt: estimated_rtt.map(|r| r as i32).unwrap_or(-1),
        reserved: [0u8; 56],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn last_error_string() -> String {
        let error = last_tunnel_error();
        assert!(!error.is_null());
        unsafe { CStr::from_ptr(error) }
            .to_str()
            .unwrap()
            .to_owned()
    }

    /// The struct's size and field offsets, pinned as literals.
    ///
    /// `wireguard_ffi.h` is hand-written and nothing mechanically checks that
    /// it agrees with this file, so the C and Rust declarations can only drift
    /// apart silently -- and a layout disagreement is not a compile error, it
    /// is a caller's `reject_after_time` arriving as somebody else's field.
    /// These literals are what a reader can check the header against by
    /// counting, and they are what fails if a field is inserted rather than
    /// appended.
    ///
    /// The size is also the ABI's forward-compatibility anchor: it must be the
    /// same on a 32- and a 64-bit build, which is why the struct has no
    /// pointer and no sub-word field.
    #[test]
    fn awg_params_layout_is_pinned() {
        use std::mem::{align_of, size_of};

        assert_eq!(size_of::<wireguard_awg_range>(), 8);
        assert_eq!(align_of::<wireguard_awg_range>(), 4);
        assert_eq!(size_of::<wireguard_awg_params>(), 160);
        assert_eq!(align_of::<wireguard_awg_params>(), 4);
        assert_eq!(
            AWG_PARAMS_SIZE_VER0,
            size_of::<wireguard_awg_params>(),
            "the published version-0 size must be this build's size until a field is added"
        );

        // EVERY field offset, not a sample. Sampling is not enough: narrowing
        // one member to a 16-bit type only moves the two bytes after it into
        // padding, leaving both the total size and every later offset
        // untouched -- so a check that looks at sizeof and a few landmarks
        // passes while one field silently reinterprets another's bytes. (The
        // C-side guard had exactly that hole until a mutation exposed it.)
        // Consecutive offsets differing by the member's width is also what
        // makes "no padding" a real claim.
        let p = wireguard_awg_params::default();
        let base = &p as *const _ as usize;
        let offset = |f: *const u8| f as usize - base;
        for (name, actual, expected) in [
            ("size", offset(&p.size as *const u32 as *const u8), 0),
            (
                "s1_init_junk",
                offset(&p.s1_init_junk as *const u32 as *const u8),
                4,
            ),
            (
                "s2_response_junk",
                offset(&p.s2_response_junk as *const u32 as *const u8),
                8,
            ),
            (
                "s3_cookie_junk",
                offset(&p.s3_cookie_junk as *const u32 as *const u8),
                12,
            ),
            (
                "s4_transport_junk",
                offset(&p.s4_transport_junk as *const u32 as *const u8),
                16,
            ),
            (
                "junk_packet_count",
                offset(&p.junk_packet_count as *const u32 as *const u8),
                20,
            ),
            (
                "junk_packet_size_min",
                offset(&p.junk_packet_size_min as *const u32 as *const u8),
                24,
            ),
            (
                "junk_packet_size_max",
                offset(&p.junk_packet_size_max as *const u32 as *const u8),
                28,
            ),
            (
                "junk_packet_delay_ms",
                offset(&p.junk_packet_delay_ms as *const u32 as *const u8),
                32,
            ),
            ("h1_init", offset(&p.h1_init as *const _ as *const u8), 36),
            ("h2_resp", offset(&p.h2_resp as *const _ as *const u8), 44),
            (
                "h3_cookie",
                offset(&p.h3_cookie as *const _ as *const u8),
                52,
            ),
            ("h4_data", offset(&p.h4_data as *const _ as *const u8), 60),
            (
                "imitation_protocol",
                offset(&p.imitation_protocol as *const u32 as *const u8),
                68,
            ),
            (
                "imitation_browser",
                offset(&p.imitation_browser as *const u32 as *const u8),
                72,
            ),
            (
                "content_padding_addition",
                offset(&p.content_padding_addition as *const _ as *const u8),
                76,
            ),
            (
                "content_padding_mtu",
                offset(&p.content_padding_mtu as *const u32 as *const u8),
                84,
            ),
            (
                "rekey_after_time",
                offset(&p.rekey_after_time as *const _ as *const u8),
                88,
            ),
            (
                "rekey_timeout",
                offset(&p.rekey_timeout as *const _ as *const u8),
                96,
            ),
            (
                "reject_after_time",
                offset(&p.reject_after_time as *const _ as *const u8),
                104,
            ),
            (
                "keepalive_timeout",
                offset(&p.keepalive_timeout as *const _ as *const u8),
                112,
            ),
            (
                "max_handshake_attempts",
                offset(&p.max_handshake_attempts as *const _ as *const u8),
                120,
            ),
            (
                "header_protection_key",
                offset(&p.header_protection_key as *const u8),
                128,
            ),
        ] {
            assert_eq!(
                actual, expected,
                "{} is at offset {}, not {}: a field was inserted or retyped, and \
                 scripts/ffi-layout-check.c will disagree with this build",
                name, actual, expected
            );
        }

        // ...and every member's width, which the offsets cannot see. Narrowing
        // a member is absorbed by the padding after it: the total size and
        // every later offset stay put while the member reads fewer bytes. The
        // C guard missed exactly that until a mutation caught it, so both
        // sides check widths now.
        assert_eq!(std::mem::size_of_val(&p.size), 4);
        assert_eq!(std::mem::size_of_val(&p.s1_init_junk), 4);
        assert_eq!(std::mem::size_of_val(&p.s4_transport_junk), 4);
        assert_eq!(std::mem::size_of_val(&p.junk_packet_count), 4);
        assert_eq!(std::mem::size_of_val(&p.junk_packet_delay_ms), 4);
        assert_eq!(std::mem::size_of_val(&p.h1_init), 8);
        assert_eq!(std::mem::size_of_val(&p.h4_data), 8);
        assert_eq!(std::mem::size_of_val(&p.imitation_protocol), 4);
        assert_eq!(std::mem::size_of_val(&p.imitation_browser), 4);
        assert_eq!(std::mem::size_of_val(&p.content_padding_addition), 8);
        assert_eq!(std::mem::size_of_val(&p.content_padding_mtu), 4);
        assert_eq!(std::mem::size_of_val(&p.rekey_after_time), 8);
        assert_eq!(std::mem::size_of_val(&p.max_handshake_attempts), 8);
        assert_eq!(std::mem::size_of_val(&p.header_protection_key), 32);
    }

    /// A filled-in struct reaches every AmneziaWG feature, including the three
    /// 3.0 ones no other constructor can express.
    #[test]
    fn awg_params_reach_every_feature() {
        last_tunnel_error_free();
        let params = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            s1_init_junk: 120,
            s2_response_junk: 130,
            s3_cookie_junk: 110,
            s4_transport_junk: 80,
            junk_packet_count: 4,
            junk_packet_size_min: 50,
            junk_packet_size_max: 500,
            junk_packet_delay_ms: 10,
            content_padding_addition: wireguard_awg_range { lo: 8, hi: 24 },
            content_padding_mtu: 1420,
            rekey_after_time: wireguard_awg_range { lo: 30, hi: 40 },
            reject_after_time: wireguard_awg_range { lo: 300, hi: 400 },
            header_protection_key: [0xab; 32],
            ..Default::default()
        };
        let config = awg_params_to_config(&params, None).expect("valid parameters");

        assert_eq!(config.init_packet_junk_size, 120);
        assert_eq!(config.transport_packet_junk_size, 80);
        assert_eq!(config.pre_handshake_junk.packet_count, 4);
        // The three AWG 3.0 features, none of which any legacy constructor can
        // set at all.
        assert!(config.header_protection_enabled());
        assert_eq!(config.content_padding_addition, (8, 24));
        assert_eq!(config.content_padding_mtu, 1420);
        assert_eq!(config.timers.rekey_after_time, (30, 40));
        assert_eq!(config.timers.reject_after_time, (300, 400));

        // An all-zero struct is a plain WireGuard tunnel: every AmneziaWG
        // field unset, so the ABI's "nothing configured" is the crate's.
        let empty = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            ..Default::default()
        };
        assert_eq!(
            awg_params_to_config(&empty, None).expect("an empty struct is valid"),
            AmneziaConfig::default()
        );
    }

    /// The forward-compatibility clamp, checked directly.
    ///
    /// A caller shorter than this build is the case the versioning exists for,
    /// and it cannot occur until the struct grows: `AWG_PARAMS_SIZE_VER0` is
    /// this build's size, so a valid short struct is unrepresentable today and
    /// [`read_awg_params`] cannot exercise the clamp. Testing the rule itself
    /// pins it now instead of in the release that first relies on it -- where
    /// getting it wrong means reading past a caller's allocation.
    #[test]
    fn awg_params_copy_len_never_exceeds_either_side() {
        let our = std::mem::size_of::<wireguard_awg_params>();

        // A future, larger build reading today's struct: copy only what the
        // caller actually passed.
        assert_eq!(awg_params_copy_len(160, 200), 160);
        // A newer caller than this build: copy only what we understand.
        assert_eq!(awg_params_copy_len(200, 160), 160);
        // Equal, which is every call today.
        assert_eq!(awg_params_copy_len(our, our), our);
        // Never more than either bound, over the whole neighbourhood.
        for caller in 0..=(our * 2) {
            let copy = awg_params_copy_len(caller, our);
            assert!(
                copy <= caller && copy <= our,
                "copy {} for caller {}",
                copy,
                caller
            );
        }
    }

    /// The size field's three cases: a short struct, a zero-padded long one,
    /// and a long one that is actually using something we do not implement.
    #[test]
    fn awg_params_versioning_reads_short_and_refuses_used_unknown_fields() {
        last_tunnel_error_free();
        let full = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            s1_init_junk: 120,
            rekey_after_time: wireguard_awg_range { lo: 30, hi: 40 },
            header_protection_key: [0xcd; 32],
            ..Default::default()
        };

        // Exactly our size: everything survives.
        let read = unsafe { read_awg_params(&full) }.expect("our own size is valid");
        assert_eq!(read, full);

        // A shorter struct -- a caller built against an older header. Its
        // absent tail must read as unset, not as whatever was in memory, so
        // the buffer beyond the truncation point is deliberately non-zero.
        let mut buffer = [0xffu8; 256];
        let short_len = 40usize;
        unsafe {
            ptr::copy_nonoverlapping(
                &full as *const _ as *const u8,
                buffer.as_mut_ptr(),
                short_len,
            );
            ptr::write_unaligned(buffer.as_mut_ptr() as *mut u32, short_len as u32);
        }
        // A struct shorter than version 0 is refused outright.
        let short = unsafe { read_awg_params(buffer.as_ptr() as *const wireguard_awg_params) };
        assert!(short.is_none(), "a sub-version-0 size must be refused");
        assert!(
            last_error_string().contains("smaller than"),
            "{}",
            last_error_string()
        );

        // A longer struct whose extra bytes are all zero: a newer caller that
        // is not using the new fields.
        last_tunnel_error_free();
        let mut long = [0u8; 256];
        let long_len = AWG_PARAMS_SIZE_VER0 + 8;
        unsafe {
            ptr::copy_nonoverlapping(
                &full as *const _ as *const u8,
                long.as_mut_ptr(),
                AWG_PARAMS_SIZE_VER0,
            );
            ptr::write_unaligned(long.as_mut_ptr() as *mut u32, long_len as u32);
        }
        let read = unsafe { read_awg_params(long.as_ptr() as *const wireguard_awg_params) }
            .expect("a zero-padded newer struct is usable");
        assert_eq!(read.s1_init_junk, 120);
        assert_eq!(read.header_protection_key, [0xcd; 32]);

        // The same struct with one non-zero byte in the unknown tail: the
        // caller is setting something this build does not implement, and
        // dropping it silently is how a tunnel ends up mutually unreachable.
        long[AWG_PARAMS_SIZE_VER0 + 2] = 1;
        let refused = unsafe { read_awg_params(long.as_ptr() as *const wireguard_awg_params) };
        assert!(refused.is_none(), "a used unknown field must be refused");
        assert!(
            last_error_string().contains("does not implement"),
            "{}",
            last_error_string()
        );
    }

    /// The constructor validates the whole configuration before a tunnel
    /// exists, which no legacy constructor does.
    #[test]
    fn awg_params_are_validated_before_a_tunnel_exists() {
        last_tunnel_error_free();
        let private = CString::new("QOGr3GnKZlfhAQrJ2ZQaBRfhVAqYrHUpEE1QBLjHtF4=").unwrap();
        let public = CString::new("QOGr3GnKZlfhAQrJ2ZQaBRfhVAqYrHUpEE1QBLjHtF4=").unwrap();

        // reject_after_time far below rekey_after_time + rekey_timeout: keys
        // would be rejected before the rekey replacing them completes.
        let params = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            reject_after_time: wireguard_awg_range { lo: 20, hi: 20 },
            ..Default::default()
        };
        let tunnel = unsafe {
            new_tunnel_with_awg_params(
                private.as_ptr(),
                public.as_ptr(),
                ptr::null(),
                0,
                0,
                &params,
                ptr::null(),
            )
        };
        assert!(tunnel.is_null(), "an incoherent tuning must not build");
        let error = last_error_string();
        assert!(error.contains("reject_after_time"), "{}", error);

        // NULL parameters are a plain WireGuard tunnel, and must succeed.
        last_tunnel_error_free();
        let tunnel = unsafe {
            new_tunnel_with_awg_params(
                private.as_ptr(),
                public.as_ptr(),
                ptr::null(),
                0,
                0,
                ptr::null(),
                ptr::null(),
            )
        };
        assert!(!tunnel.is_null(), "NULL params must build a vanilla tunnel");
        unsafe { tunnel_free(tunnel) };
    }

    #[test]
    fn browser_parser_accepts_known_values_and_rejects_others() {
        last_tunnel_error_free();
        assert_eq!(
            parse_amnezia_browser(0),
            Some(AmneziaImitationBrowser::Default)
        );
        assert_eq!(
            parse_amnezia_browser(1),
            Some(AmneziaImitationBrowser::Chrome)
        );
        assert_eq!(
            parse_amnezia_browser(4),
            Some(AmneziaImitationBrowser::Random)
        );
        assert!(last_tunnel_error().is_null());

        assert_eq!(parse_amnezia_browser(99), None);
        assert_eq!(last_error_string(), "Invalid Amnezia imitation browser");
        last_tunnel_error_free();
    }

    #[test]
    fn browser_constructor_only_validates_browser_for_quic() {
        unsafe {
            let server = CString::new("unused").unwrap();

            // Non-QUIC protocol with an out-of-range browser: the browser is
            // ignored, so the failure is the (null) key, not the browser value.
            last_tunnel_error_free();
            let tunnel = new_tunnel_with_amnezia_imitation_browser(
                ptr::null(),
                server.as_ptr(),
                ptr::null(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                AmneziaImitationProtocol::Dns as u8,
                ptr::null(),
                99, // invalid browser, must be ignored for DNS
            );
            assert!(tunnel.is_null());
            assert_eq!(last_error_string(), "Missing static private key");

            // QUIC with an out-of-range browser still fails on the browser.
            last_tunnel_error_free();
            let tunnel = new_tunnel_with_amnezia_imitation_browser(
                ptr::null(),
                server.as_ptr(),
                ptr::null(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                AmneziaImitationProtocol::Quic as u8,
                ptr::null(),
                99,
            );
            assert!(tunnel.is_null());
            assert_eq!(last_error_string(), "Invalid Amnezia imitation browser");
            last_tunnel_error_free();
        }
    }

    #[test]
    fn imitation_parser_ignores_non_utf8_domain() {
        unsafe {
            last_tunnel_error_free();

            let invalid_domain = [0xffu8, 0];
            let (protocol, domain) = parse_amnezia_imitation(
                AmneziaImitationProtocol::Dns as u8,
                invalid_domain.as_ptr() as *const c_char,
            )
            .unwrap();

            assert_eq!(protocol, AmneziaImitationProtocol::Dns);
            assert_eq!(domain, None);
            assert!(last_tunnel_error().is_null());
            last_tunnel_error_free();
        }
    }

    #[test]
    fn constructor_sets_last_error_for_null_required_key() {
        unsafe {
            last_tunnel_error_free();

            let unused_public = CString::new("unused").unwrap();
            let tunnel = new_tunnel(
                ptr::null(),
                unused_public.as_ptr(),
                ptr::null(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            );

            assert!(tunnel.is_null());
            assert_eq!(last_error_string(), "Missing static private key");
            last_tunnel_error_free();
        }
    }

    #[test]
    fn constructor_sets_last_error_for_invalid_utf8_key() {
        unsafe {
            last_tunnel_error_free();

            let invalid_private = [0xffu8, 0];
            let unused_public = CString::new("unused").unwrap();
            let tunnel = new_tunnel(
                invalid_private.as_ptr() as *const c_char,
                unused_public.as_ptr(),
                ptr::null(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            );

            assert!(tunnel.is_null());
            assert_eq!(last_error_string(), "Invalid static private key: not UTF-8");
            last_tunnel_error_free();
        }
    }

    #[test]
    fn constructor_sets_last_error_for_invalid_key_text() {
        unsafe {
            last_tunnel_error_free();

            let invalid_private = CString::new("not-a-key").unwrap();
            let unused_public = CString::new("unused").unwrap();
            let tunnel = new_tunnel(
                invalid_private.as_ptr(),
                unused_public.as_ptr(),
                ptr::null(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            );

            assert!(tunnel.is_null());
            assert_eq!(last_error_string(), "Invalid static private key");
            last_tunnel_error_free();
        }
    }

    /// The free functions accept NULL, as `free(NULL)` does in C.
    ///
    /// A C caller that frees unconditionally is idiomatic, and the constructors
    /// here return NULL on every error path -- so `tunnel_free(new_tunnel(...))`
    /// after a bad key is a realistic sequence, not a contrived one. Without the
    /// guard these reconstruct a `Box`/`CString` from NULL, which is undefined
    /// behaviour rather than a panic: this test is the only thing standing
    /// between that and a caller who does the ordinary thing.
    #[test]
    fn the_free_functions_accept_null() {
        unsafe {
            tunnel_free(std::ptr::null_mut());
            x25519_key_to_str_free(std::ptr::null());
        }
    }

    /// And still free a real allocation, so the guard did not turn them into
    /// no-ops. Run under a leak detector this would also catch that; here it at
    /// least pins that the non-NULL path is still taken.
    #[test]
    fn the_free_functions_still_free_a_real_pointer() {
        let key = x25519_secret_key();
        // `x25519_key` is `#[repr(C)]` and not `Copy`, so hand each call its own.
        let public = x25519_public_key(x25519_key { key: key.key });

        let s = x25519_key_to_base64(key);
        assert!(!s.is_null());
        unsafe { x25519_key_to_str_free(s) };

        let h = x25519_key_to_hex(public);
        assert!(!h.is_null());
        unsafe { x25519_key_to_str_free(h) };
    }
}
