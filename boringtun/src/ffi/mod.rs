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
#[cfg(not(test))]
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
#[cfg(not(test))]
use std::sync::Once;

#[cfg(not(test))]
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

// The shared body of the seven `extern "C"` tunnel constructors below, which
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

    // Not in test builds. This hook replaces the default one process-wide --
    // including libtest's, which is what prints "thread panicked at" into a
    // failing test's report. With it installed, any test that fails after any
    // test has called a constructor reports FAILED with an *empty* output
    // section, which turned one real flake into three rounds of blind hunting
    // before anyone could read the assertion text. An embedder still gets the
    // hook: `cfg(test)` only strips it from this crate's own test binaries.
    #[cfg(not(test))]
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
/// # `{lo, 0}` means different things per field
///
/// One type, but the destination decides:
///
/// * **H1-H4** go to `ObfuscationRanges::new`, where `{n, 0}` with `n != 0` is
///   the *fixed tag* `n` -- not "n and above", and not unset.
/// * **Everything else** -- `content_padding_addition` and the five timers --
///   has no such shorthand. `{n, 0}` there is simply `lo > hi`.
///
/// # `lo > hi` is a hard error everywhere
///
/// [`new_tunnel_with_awg_params`] returns NULL naming the field, in *every*
/// slot. The two core builders behind these values
/// (`with_content_padding_addition`, `with_tunable_timers`) do normalise a
/// transposed pair with `(lo.min(hi), lo.max(hi))`, which is right for the
/// crate's long-standing Rust API and the embedders that rely on it; this entry
/// point exists to refuse the exact slip a long positional argument list
/// invited, so [`awg_params_to_config`] rejects rather than re-sorts. Write
/// `{n, n}` for a fixed value, never `{n, 0}`.
///
/// Write `{lo, hi}` with `lo <= hi`, or `{0, 0}` for unset, and none of this
/// applies.
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
/// One `AmneziaConfig` knob is deliberately absent: `suppress_pre_handshake`,
/// which `AmneziaConfig::as_responder` sets to stop a responder emitting the
/// client-only Jc burst and imitation sequence at its own peer. An FFI-built
/// tunnel is always the initiator shape, so a caller building the *server* side
/// with a non-zero `junk_packet_count` or `imitation_protocol` gets those
/// datagrams sent toward its own client, and nothing here can clear the flag.
///
/// `Default` is all-zero, which includes `size` -- the one value
/// [`read_awg_params`] always refuses. A Rust caller writing
/// `wireguard_awg_params { .., ..Default::default() }` must set `size`
/// explicitly. It is left that way on purpose: [`read_awg_params`] copies the
/// caller's bytes over a `Default` instance, so a non-zero default would put
/// non-zero bytes in the tail a short struct does not supply, breaking the
/// "absent tail reads as unset" rule the versioning depends on.
///
/// # Versioning
///
/// `size` must be set to `sizeof(struct wireguard_awg_params)` by the caller,
/// which is what lets this struct grow without another entry point:
///
/// * A **smaller** struct than the library knows is a caller built against an
///   older header. The missing tail is read as zero, i.e. unset, which is the
///   same thing that header's author asked for. It must be a size this library
///   has actually *published*, not merely a smaller one: a value landing inside
///   a field would copy that field's leading bytes and zero the rest, which for
///   a key is a tunnel mutually unreachable with its peer.
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
#[derive(Default, Copy, Clone, Eq)]
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
    ///
    /// Bounded, and out of bounds is a *refused constructor*, not a clamp:
    /// `junk_packet_count <= 128`, `junk_packet_delay_ms <= 200`, and a size
    /// pair that is either `{0, 0}` (meaning "use the defaults") or satisfies
    /// `1 <= min <= max <= 1280`. The underlying builder substitutes silently
    /// for anything else -- a count of 200 becomes 0, switching the burst off
    /// entirely -- which is the failure this entry point exists to turn into an
    /// error. The limits are pinned by
    /// `ffi::tests::awg_params_junk_bounds_are_where_the_docs_say`.
    ///
    /// Two exemptions and their edges, all narrower than they look:
    ///
    /// * With `junk_packet_count == 0` there is no burst, so those *bounds* are
    ///   not applied to the sizes and the delay. All four fields are still
    ///   narrowed to `u16` first, so a value above 65535 is refused whatever
    ///   the count -- pinned by
    ///   `ffi::tests::awg_params_size16_applies_regardless_of_the_burst`.
    /// * A `{0, 0}` size pair is a real request for the defaults.
    ///
    /// The size bounds are *not* exempted when `imitation_protocol` is
    /// non-zero, even though `pre_handshake_junk_size` then draws from the
    /// protocol's own constants and never reads Jmin/Jmax. A profile a legacy
    /// constructor accepts can therefore be refused here; that is deliberate
    /// strictness, not an oversight, and it is pinned by
    /// `ffi::tests::awg_params_refuse_out_of_range_junk_sizes_under_imitation`.
    ///
    /// A non-zero count also makes the tunnel emit that many *extra* datagrams
    /// before each handshake initiation, one per API call: the caller must keep
    /// calling `wireguard_tick` to drain them and release the initiation, and
    /// every output buffer must fit a standalone junk packet (up to 1280
    /// bytes).
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

    /// Protocol imitation, and the browser profile QUIC imitates. Values are
    /// the same `AmneziaImitationProtocol` / `AmneziaImitationBrowser`
    /// discriminants the legacy constructors take.
    ///
    /// `imitation_browser` is read *only* for QUIC. An out-of-range value is a
    /// refused constructor under QUIC and is silently reset to `Default` under
    /// every other protocol -- the same asymmetry the legacy constructors have.
    pub imitation_protocol: u32,
    pub imitation_browser: u32,

    /// AmneziaWG 3.0 `content_padding_addition`: zero bytes appended to each
    /// transport plaintext, inside the AEAD. Unset still rounds the plaintext
    /// up to a 16-byte multiple, which is what every WireGuard implementation
    /// does.
    ///
    /// The drawn amount is clamped, silently, to the room left in one
    /// `content_padding_mtu` unit after the plaintext
    /// (`AmneziaConfig::content_padding`). A range whose `lo` exceeds that room
    /// therefore degenerates to a constant "pad up to the MTU" on every packet:
    /// the variable-length fingerprint the caller configured becomes a fixed
    /// one, with no diagnostic. Keep `hi` small relative to the MTU.
    pub content_padding_addition: wireguard_awg_range,
    /// The **tunnel** MTU -- the MTU of the virtual interface whose packets the
    /// caller hands to `wireguard_write`, i.e. the size of the *inner* IP
    /// packet -- **not** the MTU of the physical link the encrypted datagram
    /// crosses. `content_padding` measures the draw against it
    /// (`src_len` there is the transport *plaintext*), and the device path sets
    /// it from `iface.mtu()` for exactly that reason.
    ///
    /// Passing the physical link MTU instead lets the padding eat the
    /// encapsulation overhead as well. Measured on a 1420-byte tunnel carrying
    /// a full-size inner packet, with `content_padding_addition = {8, 200}`:
    ///
    /// | `content_padding_mtu` | UDP payload | on the wire (+28 IPv4/UDP) |
    /// |-----------------------|-------------|----------------------------|
    /// | 1420 (the tunnel MTU) |        1452 |                       1480 |
    /// | 1500 (the link MTU)   |        1532 |                       1560 |
    /// | 1500, with `s4 = 40`  |        1572 |                       1600 |
    ///
    /// So the mistake costs 80 bytes plus S4, and puts the datagram 60-100
    /// bytes over the 1500-byte link -- the fragmentation this field exists to
    /// prevent. Pinned by
    /// `ffi::tests::content_padding_mtu_is_the_tunnel_mtu_not_the_link_mtu`.
    ///
    /// `0` means "no MTU known" and is only legal while
    /// `content_padding_addition` is unset -- with a range set the constructor
    /// refuses it, since it would disable the clamp and leave the caller's
    /// buffer (`MAX_UDP_SIZE` in a real embedder) as the only bound. It still
    /// matters when the range *is* unset: the always-on 16-byte rounding is
    /// capped by the MTU too, so `0` makes a full-MTU packet up to 15 bytes
    /// larger than amneziawg-go and the kernel module would send.
    ///
    /// A construction-time snapshot, but not a permanent one: call
    /// [`wireguard_set_content_padding_mtu`] when the MTU moves. An FFI tunnel
    /// whose interface MTU later changes does *not* have to be rebuilt.
    pub content_padding_mtu: u32,

    /// AmneziaWG 3.0 tunable timers, in seconds -- except
    /// `max_handshake_attempts`, which is a count. Unset means the classic
    /// WireGuard constant governs, so an all-zero block is vanilla timing.
    ///
    /// `keepalive_timeout` is *not* the persistent keepalive: it replaces
    /// WireGuard's 10-second passive `KEEPALIVE_TIMEOUT`. The persistent
    /// keepalive interval is the separate `keep_alive` *argument* of
    /// [`new_tunnel_with_awg_params`]. Setting this field when the caller meant
    /// that argument builds a tunnel with no persistent keepalive and no
    /// diagnostic.
    pub rekey_after_time: wireguard_awg_range,
    pub rekey_timeout: wireguard_awg_range,
    pub reject_after_time: wireguard_awg_range,
    pub keepalive_timeout: wireguard_awg_range,
    pub max_handshake_attempts: wireguard_awg_range,

    /// AmneziaWG 3.0 `header_protection_key`: a 32-byte key masking the
    /// message-type field. All zero means off, matching amneziawg-go, so this
    /// is also how it is disabled again. Both ends must carry the same key --
    /// it is not negotiated, so a mismatch is a tunnel that never forms.
    ///
    /// **Setting a key requires every one of `s1_init_junk`..`s4_transport_junk`
    /// to be at least 12.** The masking keystream is nonced from the S-prefix
    /// bytes of each datagram, so a prefix shorter than `NONCE_SIZE` cannot
    /// carry one; `AmneziaConfig::check_header_protection_nonce` refuses it and
    /// the constructor returns NULL naming the offending S value. A struct
    /// carrying only a key -- the obvious first use of the feature this entry
    /// point exists to expose -- is therefore refused. Pinned by
    /// `ffi::tests::awg_params_header_protection_needs_twelve_byte_s_prefixes`.
    ///
    /// A key combined with a non-zero `imitation_protocol` is *accepted* and
    /// weakens the masking: the imitation prefix is the nonce, so it repeats
    /// and an observer with two datagrams can undo the masking. Traffic is
    /// unaffected. That warning goes to `tracing`, not to
    /// `last_tunnel_error()`, so a C caller sees it only through
    /// `set_logging_function`.
    pub header_protection_key: [u8; 32],
}

impl PartialEq for wireguard_awg_params {
    /// Compares `header_protection_key` in constant time.
    ///
    /// Hand-written for the same reason `Debug` below is, applied to a
    /// different trait. `derive(PartialEq)` compares fields in declaration
    /// order and short-circuits, so the key -- 32 bytes of *shared secret* on a
    /// `pub` struct -- would be compared with the ordinary `[u8; 32]` impl,
    /// whose timing is a function of how many leading bytes match. An embedder
    /// caching configurations (`if new == current { return; }`) on an
    /// attacker-triggerable path would leak the key a byte at a time. The crate
    /// already pulls in `subtle` for exactly this class of comparison; see the
    /// note on the dependency in `Cargo.toml`.
    ///
    /// Every other field is public, caller-supplied, non-secret configuration,
    /// so those stay ordinary `==`.
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;

        // Destructured for the same reason `Debug` is: a field appended to the
        // struct and not compared here would make two different configurations
        // compare equal, and the pattern is what turns that into a compile
        // error.
        let Self {
            size,
            s1_init_junk,
            s2_response_junk,
            s3_cookie_junk,
            s4_transport_junk,
            junk_packet_count,
            junk_packet_size_min,
            junk_packet_size_max,
            junk_packet_delay_ms,
            h1_init,
            h2_resp,
            h3_cookie,
            h4_data,
            imitation_protocol,
            imitation_browser,
            content_padding_addition,
            content_padding_mtu,
            rekey_after_time,
            rekey_timeout,
            reject_after_time,
            keepalive_timeout,
            max_handshake_attempts,
            header_protection_key,
        } = self;

        *size == other.size
            && *s1_init_junk == other.s1_init_junk
            && *s2_response_junk == other.s2_response_junk
            && *s3_cookie_junk == other.s3_cookie_junk
            && *s4_transport_junk == other.s4_transport_junk
            && *junk_packet_count == other.junk_packet_count
            && *junk_packet_size_min == other.junk_packet_size_min
            && *junk_packet_size_max == other.junk_packet_size_max
            && *junk_packet_delay_ms == other.junk_packet_delay_ms
            && *h1_init == other.h1_init
            && *h2_resp == other.h2_resp
            && *h3_cookie == other.h3_cookie
            && *h4_data == other.h4_data
            && *imitation_protocol == other.imitation_protocol
            && *imitation_browser == other.imitation_browser
            && *content_padding_addition == other.content_padding_addition
            && *content_padding_mtu == other.content_padding_mtu
            && *rekey_after_time == other.rekey_after_time
            && *rekey_timeout == other.rekey_timeout
            && *reject_after_time == other.reject_after_time
            && *keepalive_timeout == other.keepalive_timeout
            && *max_handshake_attempts == other.max_handshake_attempts
            && bool::from(header_protection_key.ct_eq(&other.header_protection_key))
    }
}

impl std::fmt::Debug for wireguard_awg_params {
    /// Never prints `header_protection_key`, only whether one is set.
    ///
    /// Hand-written for the same reason `HeaderProtectionKey`'s impl is: the key
    /// is shared secret material, and this struct is `pub`, so a derived `Debug`
    /// would put all 32 bytes into any log line that formats a caller's
    /// parameters -- including the panic message of a failing `assert_eq!` on
    /// two of these. `HeaderProtectionKey` exists to keep the key out of
    /// `AmneziaConfig`'s derived `Debug`; deriving it here would have reopened
    /// that hole one struct earlier in the pipeline.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, and every `.field` below renders one of THESE bindings
        // rather than re-reading `self`. That coupling is the whole mechanism:
        // binding them all to `_` and hand-writing the chain -- the first shape
        // of this impl -- left the two lists unrelated, so the mechanical
        // repair for the E0027 a new field triggers (`new_field: _,`) satisfied
        // the compiler while the field silently stopped appearing in
        // diagnostics, which is exactly what the comment claimed to prevent.
        //
        // Precisely what it buys, verified by deleting a `.field` call: E0027
        // on the pattern when a field is added, and then an `unused_variable`
        // WARNING if the new binding is never rendered. A warning, not an
        // error -- weaker than the exhaustive `match` in
        // `AmneziaImitationProtocol::as_str`, where the arms *are* the output
        // and there is nothing to forget. It is as close as a `debug_struct`
        // chain gets without a macro.
        let Self {
            size,
            s1_init_junk,
            s2_response_junk,
            s3_cookie_junk,
            s4_transport_junk,
            junk_packet_count,
            junk_packet_size_min,
            junk_packet_size_max,
            junk_packet_delay_ms,
            h1_init,
            h2_resp,
            h3_cookie,
            h4_data,
            imitation_protocol,
            imitation_browser,
            content_padding_addition,
            content_padding_mtu,
            rekey_after_time,
            rekey_timeout,
            reject_after_time,
            keepalive_timeout,
            max_handshake_attempts,
            header_protection_key,
        } = self;

        f.debug_struct("wireguard_awg_params")
            .field("size", size)
            .field("s1_init_junk", s1_init_junk)
            .field("s2_response_junk", s2_response_junk)
            .field("s3_cookie_junk", s3_cookie_junk)
            .field("s4_transport_junk", s4_transport_junk)
            .field("junk_packet_count", junk_packet_count)
            .field("junk_packet_size_min", junk_packet_size_min)
            .field("junk_packet_size_max", junk_packet_size_max)
            .field("junk_packet_delay_ms", junk_packet_delay_ms)
            .field("h1_init", h1_init)
            .field("h2_resp", h2_resp)
            .field("h3_cookie", h3_cookie)
            .field("h4_data", h4_data)
            .field("imitation_protocol", imitation_protocol)
            .field("imitation_browser", imitation_browser)
            .field("content_padding_addition", content_padding_addition)
            .field("content_padding_mtu", content_padding_mtu)
            .field("rekey_after_time", rekey_after_time)
            .field("rekey_timeout", rekey_timeout)
            .field("reject_after_time", reject_after_time)
            .field("keepalive_timeout", keepalive_timeout)
            .field("max_handshake_attempts", max_handshake_attempts)
            .field(
                "header_protection_key",
                &if header_protection_key.iter().any(|&b| b != 0) {
                    "set"
                } else {
                    "unset"
                },
            )
            .finish()
    }
}

/// The size of the first published version of [`wireguard_awg_params`].
///
/// A caller may pass a struct this small forever; the tail it does not have is
/// read as unset. Pinned as a literal, not as `size_of`, so that adding a field
/// cannot silently redefine what "the original struct" was and start rejecting
/// callers built against it.
const AWG_PARAMS_SIZE_VER0: usize = 160;

/// Every size of [`wireguard_awg_params`] that has ever been published.
///
/// A caller's `size` must be one of these, or at least this build's own size (a
/// newer header, governed by the zero-tail rule). An arbitrary value *between*
/// two published sizes is refused, because the copy clamp would cut a member in
/// half: once a field is appended, a `size` landing inside it copies that
/// field's leading bytes and leaves the rest zero. For a key that is a tunnel
/// mutually unreachable with its peer and no diagnostic anywhere -- exactly the
/// outcome the zero-tail rule refuses in the other direction.
const AWG_PARAMS_PUBLISHED_SIZES: [usize; 1] = [AWG_PARAMS_SIZE_VER0];

/// The largest `size` this build will read.
///
/// `size` is four bytes of foreign memory, and it is the *only* bound the
/// unknown-tail scan has. Without a ceiling, a caller who wrote
/// `struct wireguard_awg_params p;` and forgot `p.size = sizeof(p)` hands over
/// stack garbage, and `slice::from_raw_parts` is asked for up to 4 GiB past a
/// 160-byte object: a segfault on x86_64, and above `isize::MAX` undefined
/// behaviour outright on the i686 build this crate ships.
///
/// This bounds the damage rather than eliminating it: garbage that happens to
/// land in `[AWG_PARAMS_SIZE_VER0, AWG_PARAMS_SIZE_MAX]` is still read past the
/// caller's object, and the ABI's contract -- `params` points to `params->size`
/// readable bytes -- is the only thing that can rule that out. What the ceiling
/// buys is that the *unbounded* case, which no contract can survive, becomes
/// the same named refusal every other malformed input gets. Kept close to the
/// struct (6x today's size, room for many releases) so the window is a few
/// hundred bytes rather than four gigabytes.
const AWG_PARAMS_SIZE_MAX: usize = 1024;

/// The ceiling has to stay above the struct it bounds, and nothing about the
/// two numbers makes that automatic: one is a literal chosen for the size of
/// the damage window, the other grows every time a field is appended. If the
/// struct ever passed the ceiling, `read_awg_params` would reject *every*
/// caller -- including one that did exactly what the header says, `p.size =
/// sizeof(p)` -- with a message blaming them for an uninitialised field. A
/// build failure at the moment the field is added is the only warning that
/// arrives in time.
const _: () = assert!(AWG_PARAMS_SIZE_MAX > std::mem::size_of::<wireguard_awg_params>());

/// Likewise, this build's own size must be a size we have published, or the
/// short-struct path refuses callers built against the current header. It
/// holds trivially today (the table is `[AWG_PARAMS_SIZE_VER0]` and that is
/// this build's size) and stops holding the moment a field is appended --
/// which is exactly when the table needs the old size added to it, and the
/// only repair that makes this compile again.
const _: () = assert!(awg_params_size_is_published(std::mem::size_of::<
    wireguard_awg_params,
>()));

/// `AWG_PARAMS_PUBLISHED_SIZES.contains`, as a `const fn` so the assertion
/// above can run at compile time (`slice::contains` is not const on MSRV).
const fn awg_params_size_is_published(size: usize) -> bool {
    let mut i = 0;
    while i < AWG_PARAMS_PUBLISHED_SIZES.len() {
        if AWG_PARAMS_PUBLISHED_SIZES[i] == size {
            return true;
        }
        i += 1;
    }
    false
}

/// How many of a caller's bytes to copy: never more than they passed, never
/// more than this build understands.
///
/// Split out because it is the ABI's forward-compatibility rule and, today,
/// unreachable: `AWG_PARAMS_SIZE_VER0` equals this build's size, so a struct
/// that is valid *and* short cannot exist yet, and the clamp cannot be
/// exercised through [`read_awg_params`]. Extracting it makes the promise
/// testable now rather than in the release that first depends on it -- when
/// getting it wrong would read past a caller's allocation.
fn awg_params_copy_len(caller_size: usize, our_size: usize) -> usize {
    caller_size.min(our_size)
}

/// May a caller's `size` be read at all, given what this build understands?
///
/// This build's own size and anything above it are fine -- the zero-tail rule
/// governs those. A *shorter* size must be one this library actually published:
/// [`awg_params_copy_len`] would otherwise copy a member in half, leaving its
/// leading bytes set and the rest zero, which for a key is a tunnel mutually
/// unreachable with its peer and no diagnostic anywhere.
///
/// Split out for the same reason `awg_params_copy_len` is, and it needs it
/// more: while `AWG_PARAMS_SIZE_VER0 == our_size` no size is both valid and
/// short, so [`read_awg_params`] cannot reach this rule and deleting it outright
/// leaves every other test green. A pure function can be pinned now instead of
/// in the release that first depends on it.
fn awg_params_size_is_readable(caller_size: usize, our_size: usize) -> bool {
    caller_size >= our_size || AWG_PARAMS_PUBLISHED_SIZES.contains(&caller_size)
}

/// Read a caller's [`wireguard_awg_params`] of any published size.
///
/// Copies the caller's bytes into a zeroed struct of the size this build
/// understands, so a short struct's absent tail reads as unset, and refuses a
/// longer one that carries anything non-zero past what we understand.
///
/// # Safety
///
/// `params` must be non-null and point to at least four readable bytes; call
/// that leading `u32` `n`. It must then point to at least `n` readable bytes,
/// all within a *single* allocated object -- the unknown-tail scan builds a
/// slice over `[params + our_size, params + n)`, and `slice::from_raw_parts`
/// requires that whole range to lie in one allocation, not merely to be mapped.
///
/// Stated in two steps on purpose: "at least `params->size` readable bytes" is
/// circular, since `size` is read *from* that memory and cannot be trusted
/// before the first four bytes are known readable.
///
/// [`AWG_PARAMS_SIZE_MAX`] bounds how far a garbage `n` can push that scan, but
/// it does not make the scan sound: an `n` landing anywhere in
/// `(AWG_PARAMS_SIZE_VER0, AWG_PARAMS_SIZE_MAX]` over a 160-byte object is an
/// out-of-bounds read, i.e. undefined behaviour that a sanitizer will report
/// and the optimiser may exploit -- just a small and quiet one rather than a
/// four-gigabyte segfault. Only the caller honouring this contract rules it
/// out.
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

    // Bound `size` from above before it is used as a length. See
    // `AWG_PARAMS_SIZE_MAX`: an uninitialised `size` is the same caller mistake
    // the floor above catches, and it must not be the one that reads 4 GiB.
    if caller_size > AWG_PARAMS_SIZE_MAX {
        set_last_error(&format!(
            "Invalid AmneziaWG parameters: size is {}, which exceeds the {}-byte maximum this \
             library will read -- the field is almost certainly uninitialised; set \
             params.size = sizeof(struct wireguard_awg_params)",
            caller_size, AWG_PARAMS_SIZE_MAX
        ));
        return None;
    }

    // A short struct must be a size we actually published, not merely a size
    // above the floor: the clamp below copies `caller_size` bytes, and a size
    // landing inside a field would copy that field in half. Unreachable while
    // `AWG_PARAMS_SIZE_VER0 == our_size`; it becomes the load-bearing check the
    // first time a field is appended.
    if !awg_params_size_is_readable(caller_size, our_size) {
        set_last_error(&format!(
            "Invalid AmneziaWG parameters: size is {}, which is not a published size of struct \
             wireguard_awg_params (this build understands {}); a size between two versions \
             would copy a field in half",
            caller_size, our_size
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

    // A transposed range is refused, not re-sorted.
    //
    // `with_content_padding_addition` and `with_tunable_timers` both normalize
    // `lo > hi` on the way in, which is right for them: they are the crate's
    // long-standing builders and an embedder relies on that leniency. It is
    // wrong here. This entry point exists because a positional argument list
    // long enough to transpose two same-typed values is a silent
    // misconfiguration, and a struct whose halves can be typed the wrong way
    // round reproduces exactly that hazard one level down -- `{40, 30}` for a
    // timer is the same slip as passing `hi` before `lo`, and the crate's own
    // UAPI refuses it (`parse_uint_range` returns None on `start > end`, as
    // amneziawg-go's `UintRange::FromString` does). The adapter already
    // refuses a transposed junk *size* pair a few lines above; these six were
    // the inconsistency.
    //
    // A brand-new interface with no callers can afford the strict answer.
    for (label, range) in [
        ("content_padding_addition", p.content_padding_addition),
        ("rekey_after_time", p.rekey_after_time),
        ("rekey_timeout", p.rekey_timeout),
        ("reject_after_time", p.reject_after_time),
        ("keepalive_timeout", p.keepalive_timeout),
        ("max_handshake_attempts", p.max_handshake_attempts),
    ] {
        if range.lo > range.hi {
            set_last_error(&format!(
                "Invalid AmneziaWG parameters: {} is {{{}, {}}}, whose lo exceeds its hi. Note \
                 that unlike h1_init..h4_data, {{n, 0}} is not a fixed value here -- write \
                 {{n, n}} for a fixed value, or {{0, 0}} to leave it unset",
                label, range.lo, range.hi
            ));
            return None;
        }
    }

    // Padding with no MTU is unbounded padding.
    //
    // `content_padding_mtu == 0` means "no MTU known", and `content_padding`
    // then skips both of its clamps -- the drawn amount is limited only by the
    // caller's `dst` buffer, which is `MAX_UDP_SIZE` in every real embedder.
    // A full-size packet grows past the link and fragments or blackholes,
    // which is precisely the `EMSGSIZE` the clamp exists to prevent. The
    // device path never meets this because it always feeds the interface MTU;
    // the FFI is the only path where an active range can meet a zero MTU, so
    // the caller has to say what their link carries.
    if p.content_padding_addition != wireguard_awg_range::default() && mtu == 0 {
        set_last_error(
            "Invalid AmneziaWG parameters: content_padding_addition is set but \
             content_padding_mtu is 0, which disables the clamp that keeps a padded packet \
             inside the link MTU -- set content_padding_mtu to the tunnel MTU",
        );
        return None;
    }

    let domain_supplied = imitation_domain.is_some();

    let config = AmneziaConfig::new(s1, s2, s3, s4)
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
        });

    // `AmneziaPreHandshakeJunk::new` substitutes silently rather than failing:
    // a Jc above its ceiling becomes 0 -- the burst switched off entirely --
    // and an out-of-range or transposed size pair becomes the built-in default.
    // `size16` above only rejects values past `u16::MAX`, so the API was louder
    // about `junk_packet_count = 70000` than about the likelier and far more
    // damaging `200`. The bounds are private to `noise::amnezia`, so the check
    // is "did the value survive?" rather than a second copy of the constants.
    //
    // Two allowances, both matching what the burst actually reads:
    //   * `(jmin, jmax) == (0, 0)` is a real request for the defaults, so only
    //     a size pair the caller actually set is held to this;
    //   * with `jc == 0` there is no burst, and neither the sizes nor the delay
    //     are ever read, so an out-of-range value in them is inert rather than
    //     a silently different configuration.
    //
    // Note the third case that is deliberately NOT exempted, because the same
    // reasoning would cover it: under any non-`None` `imitation_protocol`,
    // `pre_handshake_junk_size` draws from that protocol's own constants and
    // never reads Jmin/Jmax, so an out-of-range size pair is just as inert as
    // it is at `jc == 0` -- and is still refused. A profile
    // `new_tunnel_with_amnezia_junk_imitation` accepts therefore fails here.
    // Kept strict because the bounds are documented unconditionally on the
    // struct and a caller who later switches the protocol should not discover
    // then that their sizes were never valid; pinned by
    // `awg_params_refuse_out_of_range_junk_sizes_under_imitation` so the choice
    // is visible rather than accidental.
    let junk = &config.pre_handshake_junk;
    let burst = jc != 0;
    let junk_substituted = junk.packet_count != jc
        || (burst && junk.packet_delay_ms != jd)
        || (burst
            && (jmin, jmax) != (0, 0)
            && (junk.packet_size_min, junk.packet_size_max) != (jmin, jmax));
    if junk_substituted {
        set_last_error(&format!(
            "Invalid AmneziaWG parameters: the pre-handshake junk burst (junk_packet_count = \
             {}, junk_packet_size_min = {}, junk_packet_size_max = {}, junk_packet_delay_ms = \
             {}) is outside the supported bounds and would have been silently replaced by ({}, \
             {}, {}, {})",
            jc,
            jmin,
            jmax,
            jd,
            junk.packet_count,
            junk.packet_size_min,
            junk.packet_size_max,
            junk.packet_delay_ms
        ));
        return None;
    }

    // The same rule for the imitation domain. Refusing only non-UTF-8 (in
    // `new_tunnel_with_awg_params`) closed the rarest case and left the common
    // one: a perfectly decodable hostname that fails the validator its protocol
    // uses -- the strict LDH `is_valid_imitation_host` for DNS and SIP, the far
    // looser `is_valid_quic_sni` for QUIC -- is dropped by
    // `AmneziaImitation::new` and replaced with a randomly generated name at
    // emit time. Asking the config what survived, rather than re-deciding here,
    // is what keeps this correct for both: an underscore is fatal to a DNS
    // QNAME and fine in a TLS SNI. `uses_domain` separates all of that from
    // "this protocol carries no hostname, so the domain was never going to be
    // used".
    if domain_supplied && protocol.uses_domain() && config.imitation.domain().is_none() {
        set_last_error(
            "Invalid Amnezia imitation domain: not a valid hostname for this protocol -- it \
             would have been replaced by a randomly generated one",
        );
        return None;
    }

    Some(config)
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
/// `index` is the **24-bit** prefix for session indexes, as it is in
/// [`new_tunnel`]: it is shifted left by 8, so anything in the top byte is
/// discarded silently. Two peers whose indexes differ only above bit 23
/// collapse onto one prefix and the device demultiplexes their transport
/// packets to the wrong tunnel.
///
/// Unlike the legacy constructors, the whole configuration is validated before
/// a tunnel exists, and a failure is a NULL return with the reason in
/// `last_tunnel_error()` rather than a tunnel that silently never works. Five
/// classes are refused:
///
/// * parameters that could never emit a valid datagram, or that would be
///   silently rewritten into a different configuration (an out-of-range junk
///   burst, a hostname that is not a valid host for the imitated protocol).
///   This class is stricter here than anywhere else in the crate: the UAPI
///   `set=1` path takes the silent rewrite, so a profile refused here can still
///   load in `boringtun-cli`. Refusing is the point of this entry point -- the
///   rewrite is invisible until someone takes a packet capture;
/// * any range with `lo > hi`, in any field, named individually. The two core
///   builders re-sort a transposed pair; this refuses it, because a
///   transposition is the slip the struct was created to make impossible.
///   `{n, 0}` is a fixed value only for `h1_init`..`h4_data`;
/// * a `header_protection_key` set while any of `s1_init_junk`..
///   `s4_transport_junk` is below 12, the header-protection nonce length --
///   which makes a struct carrying *only* a key a refused call;
/// * `content_padding_addition` set while `content_padding_mtu` is 0;
/// * timers ordered so that keys would be rejected before the rekey replacing
///   them completes.
///
/// One class is deliberately **not** refused here, though the UAPI `set=1` path
/// does refuse it: S-value combinations that make the cookie reply larger than
/// the request it answers, i.e. an amplification reflector. Accepting it is
/// safe because the reflection is stopped where the packet is sent, not at
/// configuration time: `Tunn::decapsulate` refuses to emit a cookie reply
/// larger than the datagram that provoked it, for every tunnel however it was
/// built. (Through this ABI the reply path is doubly unreachable --
/// [`wireguard_read`] passes no source address, so `RateLimiter::verify_packet`
/// bails on `UnderLoad` before a cookie is even formatted.) And accepting it is
/// *necessary* because `s3_cookie_junk` is symmetric and interface-wide -- both
/// ends must configure the same value or cookie replies do not parse -- so it
/// is dictated by the server the caller is connecting to. Refusing would
/// decline a profile the caller cannot change, that the AmneziaWG kernel module
/// and amneziawg-go both run, and that the legacy `new_tunnel_with_amnezia*`
/// constructors accept. It is logged instead. A profile accepted here can
/// therefore still be refused by `boringtun-cli`, which is a responder choosing
/// its own reflection ratio; that divergence is intentional.
///
/// Returns NULL on failure, with the reason in `last_tunnel_error()`.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_with_awg_params(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    // The 24bit index prefix for session indexes.
    index: u32,
    params: *const wireguard_awg_params,
    imitation_domain: *const c_char,
) -> *mut Mutex<Tunn> {
    clear_last_error();

    // NULL parameters are a zeroed struct, not a separate path.
    //
    // Every field's unset encoding is already zero, so the two are the same
    // configuration -- and going through one path means the argument checks
    // apply to both. They did not before: with NULL params the domain was
    // never even decoded, so a non-UTF-8 hostname was accepted here where the
    // struct path refuses it.
    //
    // What this does NOT do, despite the shape of the fix: a *valid* hostname
    // passed with NULL params is still dropped without a word. A zeroed struct
    // means `imitation_protocol == None`, `uses_domain()` is false, and the
    // check in `awg_params_to_config` short-circuits before it can complain --
    // deliberately, since a protocol that carries no hostname ignoring one is
    // the long-standing behaviour of every legacy constructor and not a
    // substitution. Only the non-UTF-8 case genuinely changed.
    let (amnezia, h1, h2, h3, h4) = {
        let p = if params.is_null() {
            wireguard_awg_params::default()
        } else {
            let Some(p) = read_awg_params(params) else {
                return ptr::null_mut();
            };
            p
        };
        // A non-UTF-8 domain is refused rather than dropped. The legacy
        // constructors silently discard one (`parse_amnezia_imitation` maps the
        // error to `None`), which hands back a tunnel imitating the right
        // protocol with a randomly generated hostname -- a substitution the
        // caller can only discover in a packet capture.
        //
        // An EMPTY string is "no domain", not an invalid one. NULL and "" mean
        // the same thing to every legacy constructor, and marshalling layers
        // (C++/C#/Delphi/Go) routinely hand over "" for an absent string, so
        // treating it as a rejected hostname would fail the commonest way of
        // saying "I have nothing to pass here".
        let domain = if imitation_domain.is_null() {
            None
        } else {
            match CStr::from_ptr(imitation_domain).to_str() {
                Ok("") => None,
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
    // exactly what `validate` exists to catch. `validate` is universal -- every
    // rule in it holds for either end of the tunnel -- so calling it here
    // refuses nothing a client cannot fix.
    if let Err(e) = amnezia.validate() {
        set_last_error(&format!("Invalid AmneziaWG parameters: {}", e));
        return ptr::null_mut();
    }

    // The cookie-reflection policy: logged, not refused. The UAPI `set=1` path
    // refuses this same complaint, because a device is a responder choosing its
    // own reflection ratio; a tunnel built here is a client, and S3 is not this
    // caller's to change -- it is symmetric and interface-wide, so a client
    // must use whatever its server was configured with or fail to parse cookie
    // replies. Refusing would decline a profile the reference implementations
    // run and the operator cannot alter from this end. And warning is safe:
    // should this tunnel ever be driven as a responder, `Tunn::decapsulate`
    // refuses to emit an amplifying reply at the emit site itself.
    if let Some(complaint) = amnezia.cookie_amplification_complaint() {
        tracing::warn!(
            message = "AmneziaWG S sizes make cookie replies larger than the packets \
                       that provoke them; harmless for a client, but this port would \
                       reflect if it ever served handshakes",
            detail = %complaint
        );
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
    // The `None` is load-bearing, not just "the C ABI has no sockaddr".
    // `RateLimiter::verify_packet` returns `UnderLoad` on a `None` source
    // before it formats a cookie reply, which is the only reason
    // `new_tunnel_with_awg_params` can accept an amplifying S3 that `set=1`
    // refuses. Plumbing a real address through here (a `wireguard_read_from`)
    // re-opens that path and needs a reply-size guard at the emit site in
    // `noise::Tunn::decapsulate` first.
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

/// Refresh the tunnel MTU that `content_padding_addition` pads against.
///
/// `wireguard_awg_params::content_padding_mtu` is a construction-time
/// snapshot, and an embedder's MTU does not hold still: it is recomputed on
/// every reconnect and every roam between links, while the tunnel handle
/// lives on. Without this the padding keeps clamping to whatever the MTU was
/// when the tunnel was built -- too small wastes payload, too large emits
/// packets the path drops. The device daemon has always had this refresh
/// (it re-reads the interface MTU once a second and pushes any change into
/// every peer); this is the same operation for callers who own their own
/// event loop, and it is the reason an embedder no longer has to rebuild a
/// tunnel to track a link change.
///
/// Only the clamp moves. The configured padding range is untouched, live
/// sessions are kept, and any queued pre-handshake junk burst survives --
/// deliberately, because the MTU moves at exactly the moment the first
/// handshake's burst is most likely in flight.
///
/// `mtu` is the **tunnel** MTU -- the size of the packets handed to
/// `wireguard_write` -- not the link MTU. See `content_padding_mtu` in the
/// struct for what passing the link MTU costs.
///
/// Returns `true` if the clamp was updated. Returns `false`, changing nothing,
/// when `tunnel` is NULL, `mtu` is 0, or `mtu` exceeds `UINT16_MAX`.
///
/// Both numeric refusals are the same refusal: neither value can bound
/// anything. Zero does not mean "a zero-byte MTU", it means *no clamp at all*,
/// so the padding would run unbounded. 65535 and above is the same state
/// reached from the other end -- no real plaintext comes near it, so the
/// `want.min(mtu - last_unit)` term never binds -- and it is what a caller
/// lands on when `link_mtu - overhead` underflows to `u32::MAX` or an
/// uninitialised field arrives as a sentinel. `new_tunnel_with_awg_params`
/// already refuses an out-of-range `content_padding_mtu` through `size16`, and
/// a setter that answered `true` where the constructor answers NULL would let
/// a caller reach by the back door a state the front door rejects. Saturating
/// to 65535 and reporting success was the earlier behaviour here and was
/// wrong for exactly that reason.
///
/// This is stricter than the device, which saturates -- deliberately, because
/// there the value comes from `iface.mtu()` and is the kernel's to be trusted,
/// while this one is caller input.
///
/// Unlike the older entry points, a NULL tunnel is a `false` return rather
/// than an abort. Those call `as_ref().unwrap()`, and a panic cannot unwind
/// out of `extern "C"` -- since Rust 1.71 it is a defined abort rather than
/// undefined behaviour, and in this library it is louder still: the crate
/// installs a panic hook that calls `raise(SIGSEGV)`, so a NULL handed to an
/// older entry point takes the embedder's process down with a segfault. New
/// entry points return a value instead.
#[no_mangle]
pub unsafe extern "C" fn wireguard_set_content_padding_mtu(
    tunnel: *const Mutex<Tunn>,
    mtu: u32,
) -> bool {
    if mtu == 0 {
        return false;
    }
    // `try_from` rather than `as`, and rather than a saturating `min`: both of
    // those turn an out-of-range MTU into a value that is stored and reported
    // as success, and `65536 as u16` is `0` -- the one value this entry point
    // exists to refuse. Written this way, deleting the range check is a
    // compile error rather than a silent return of the fail-open clamp.
    let Ok(mtu) = u16::try_from(mtu) else {
        return false;
    };
    let Some(tunnel) = tunnel.as_ref() else {
        return false;
    };
    tunnel.lock().set_content_padding_mtu(mtu);
    true
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

        // The nested range, inside and out. `sizeof == 8` alone does not pin
        // it: swapping `lo` and `hi` in either declaration leaves the size, the
        // alignment, and every offset and width in the outer struct untouched,
        // so both guards passed while every range in the ABI arrived inverted.
        // For the timers and the padding that is silent -- `with_tunable_timers`
        // re-sorts a transposed pair -- so nothing downstream would complain.
        assert_eq!(size_of::<wireguard_awg_range>(), 8);
        assert_eq!(align_of::<wireguard_awg_range>(), 4);
        let r = wireguard_awg_range::default();
        let r_base = &r as *const _ as usize;
        assert_eq!(
            &r.lo as *const u32 as usize - r_base,
            0,
            "lo must lead wireguard_awg_range"
        );
        assert_eq!(
            &r.hi as *const u32 as usize - r_base,
            4,
            "hi must follow lo in wireguard_awg_range"
        );
        assert_eq!(std::mem::size_of_val(&r.lo), 4);
        assert_eq!(std::mem::size_of_val(&r.hi), 4);

        assert_eq!(size_of::<wireguard_awg_params>(), 160);
        assert_eq!(align_of::<wireguard_awg_params>(), 4);
        // This build's size must be a *published* size -- not specifically
        // version 0's.
        //
        // The earlier form asserted `AWG_PARAMS_SIZE_VER0 == size_of`, which
        // fails on the first appended field and invites the obvious repair for
        // a failing equality: bump `VER0`. That is the one edit that must never
        // happen -- it lifts the floor in `read_awg_params` above 160 and
        // refuses every client compiled against the shipped header, i.e. the
        // mechanism turning on the callers it exists to protect. This form
        // fails on the same day, and its only repair is to append the *old*
        // size to the table, which is precisely the edit that must not be
        // forgotten.
        assert!(
            AWG_PARAMS_PUBLISHED_SIZES.contains(&size_of::<wireguard_awg_params>()),
            "this build's struct size {} is not in AWG_PARAMS_PUBLISHED_SIZES {:?}: append the \
             previous size to the table rather than raising AWG_PARAMS_SIZE_VER0, which would \
             refuse every caller built against the header that shipped it",
            size_of::<wireguard_awg_params>(),
            AWG_PARAMS_PUBLISHED_SIZES
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
        // All twenty-three, matching `scripts/ffi-layout-check.c` one for one.
        // This list used to hold fourteen while the comment above claimed
        // "both sides check widths now" -- and the nine it omitted included
        // `reject_after_time`, the field every rationale in this commit names
        // as the disaster case.
        assert_eq!(std::mem::size_of_val(&p.size), 4);
        assert_eq!(std::mem::size_of_val(&p.s1_init_junk), 4);
        assert_eq!(std::mem::size_of_val(&p.s2_response_junk), 4);
        assert_eq!(std::mem::size_of_val(&p.s3_cookie_junk), 4);
        assert_eq!(std::mem::size_of_val(&p.s4_transport_junk), 4);
        assert_eq!(std::mem::size_of_val(&p.junk_packet_count), 4);
        assert_eq!(std::mem::size_of_val(&p.junk_packet_size_min), 4);
        assert_eq!(std::mem::size_of_val(&p.junk_packet_size_max), 4);
        assert_eq!(std::mem::size_of_val(&p.junk_packet_delay_ms), 4);
        assert_eq!(std::mem::size_of_val(&p.h1_init), 8);
        assert_eq!(std::mem::size_of_val(&p.h2_resp), 8);
        assert_eq!(std::mem::size_of_val(&p.h3_cookie), 8);
        assert_eq!(std::mem::size_of_val(&p.h4_data), 8);
        assert_eq!(std::mem::size_of_val(&p.imitation_protocol), 4);
        assert_eq!(std::mem::size_of_val(&p.imitation_browser), 4);
        assert_eq!(std::mem::size_of_val(&p.content_padding_addition), 8);
        assert_eq!(std::mem::size_of_val(&p.content_padding_mtu), 4);
        assert_eq!(std::mem::size_of_val(&p.rekey_after_time), 8);
        assert_eq!(std::mem::size_of_val(&p.rekey_timeout), 8);
        assert_eq!(std::mem::size_of_val(&p.reject_after_time), 8);
        assert_eq!(std::mem::size_of_val(&p.keepalive_timeout), 8);
        assert_eq!(std::mem::size_of_val(&p.max_handshake_attempts), 8);
        assert_eq!(std::mem::size_of_val(&p.header_protection_key), 32);
    }

    /// The two by-value return structs, pinned against the same answer
    /// `scripts/ffi-layout-check.c` pins on the C side.
    ///
    /// `wireguard_result` and `stats` are the only structs in the header whose
    /// layout really does change with the word size -- both hold `usize`, so
    /// they are 16/88 bytes on LP64 and 8/80 on ILP32 -- and both are returned
    /// *by value* across the ABI, the most layout-sensitive crossing there is.
    /// The C guard was added without a Rust counterpart, which made it a
    /// one-sided check: it caught a header edit and not the Rust edit on the
    /// other side of the same boundary. Expressed relative to `size_of::<usize>`
    /// so one set of literals holds on both targets.
    #[test]
    fn by_value_return_structs_are_pinned() {
        use std::mem::size_of;
        let word = size_of::<usize>();

        assert_eq!(size_of::<wireguard_result>(), 2 * word);
        let r = wireguard_result {
            op: result_type::WIREGUARD_DONE,
            size: 0,
        };
        let r_base = &r as *const _ as usize;
        assert_eq!(&r.size as *const usize as usize - r_base, word);
        assert_eq!(std::mem::size_of_val(&r.size), word);
        // `op`'s WIDTH, which neither the total nor `size`'s offset can see:
        // `#[repr(u8)]` on `result_type` shrinks it to one byte, and the seven
        // bytes of padding that open up in front of `size` leave both the total
        // and that offset exactly where they were. The C side already asserts
        // `sizeof(op) == sizeof(int)`, so without this a Rust-only edit passes
        // while the identical header edit fails -- and a C caller would read
        // four bytes of which three are uninitialised padding, then dispatch on
        // the result. (Found by mutating the enum and watching the test pass.)
        assert_eq!(std::mem::size_of_val(&r.op), 4);

        // `reserved`'s position is deliberately not pinned: shrinking it to
        // make room for a new field is the documented, size-preserving way to
        // extend this struct. The TOTAL is what must not move.
        assert_eq!(size_of::<stats>(), 16 + 2 * word + 56);
        let s = stats {
            time_since_last_handshake: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            estimated_loss: 0.0,
            estimated_rtt: 0,
            reserved: [0u8; 56],
        };
        let base = &s as *const _ as usize;
        assert_eq!(
            &s.time_since_last_handshake as *const i64 as usize - base,
            0
        );
        assert_eq!(&s.tx_bytes as *const usize as usize - base, 8);
        assert_eq!(&s.rx_bytes as *const usize as usize - base, 8 + word);
        assert_eq!(
            &s.estimated_loss as *const f32 as usize - base,
            8 + 2 * word
        );
        assert_eq!(
            &s.estimated_rtt as *const i32 as usize - base,
            12 + 2 * word
        );
        assert_eq!(std::mem::size_of_val(&s.time_since_last_handshake), 8);
        assert_eq!(std::mem::size_of_val(&s.tx_bytes), word);
        assert_eq!(std::mem::size_of_val(&s.rx_bytes), word);
        assert_eq!(std::mem::size_of_val(&s.estimated_loss), 4);
        assert_eq!(std::mem::size_of_val(&s.estimated_rtt), 4);
        assert_eq!(std::mem::size_of_val(&s.reserved), 56);
    }

    /// A filled-in struct reaches every AmneziaWG feature, including the three
    /// 3.0 ones no other constructor can express.
    ///
    /// EVERY forwarded value is observed, with a distinct value per field. A
    /// version of this test asserted eight of them, which let a transposition in
    /// the adapter pass: swapping `s2`/`s3` in `AmneziaConfig::new`, or
    /// `rekey_timeout`/`keepalive_timeout` in the `AwgTimers` literal, changed
    /// nothing the test looked at. That is the exact hazard the struct exists to
    /// remove, so the test has to be able to see it.
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
            imitation_protocol: AmneziaImitationProtocol::Quic as u32,
            imitation_browser: AmneziaImitationBrowser::Firefox as u32,
            content_padding_addition: wireguard_awg_range { lo: 8, hi: 24 },
            content_padding_mtu: 1420,
            rekey_after_time: wireguard_awg_range { lo: 30, hi: 40 },
            rekey_timeout: wireguard_awg_range { lo: 5, hi: 7 },
            reject_after_time: wireguard_awg_range { lo: 300, hi: 400 },
            keepalive_timeout: wireguard_awg_range { lo: 20, hi: 25 },
            max_handshake_attempts: wireguard_awg_range { lo: 9, hi: 11 },
            // Thirty-two DISTINCT bytes, not a uniform fill. A `[0xab; 32]` key
            // is its own reverse, its own rotation and its own byte swap, so no
            // ordering error in the key path could ever be seen -- and the key
            // is the one parameter where order is the whole of the value: it is
            // not negotiated, so a peer that receives it permuted has a tunnel
            // that never forms.
            header_protection_key: [
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
                0x2c, 0x2d, 0x2e, 0x2f,
            ],
            ..Default::default()
        };
        let config = awg_params_to_config(&params, Some("example.com".to_owned()))
            .expect("valid parameters");

        // S1-S4, each distinct, so a transposed pair is visible.
        assert_eq!(config.init_packet_junk_size, 120);
        assert_eq!(config.response_packet_junk_size, 130);
        assert_eq!(config.cookie_packet_junk_size, 110);
        assert_eq!(config.transport_packet_junk_size, 80);
        // Jc/Jmin/Jmax/Jd.
        assert_eq!(config.pre_handshake_junk.packet_count, 4);
        assert_eq!(config.pre_handshake_junk.packet_size_min, 50);
        assert_eq!(config.pre_handshake_junk.packet_size_max, 500);
        assert_eq!(config.pre_handshake_junk.packet_delay_ms, 10);
        // Imitation, including the domain and the QUIC-only browser.
        assert_eq!(config.imitation.protocol, AmneziaImitationProtocol::Quic);
        assert_eq!(config.imitation.browser, AmneziaImitationBrowser::Firefox);
        assert_eq!(config.imitation.domain(), Some("example.com"));
        // The three AWG 3.0 features, none of which any legacy constructor can
        // set at all.
        // The key's BYTES, not just "a key is set". `header_protection_enabled`
        // is a bool, so on its own it certifies only that the 32 bytes were not
        // all zero: replacing them wholesale, reversing them, or copying half
        // of them all leave it true. That is the failure this struct's rustdoc
        // names three separate times as the one worth refusing a constructor
        // over, so the test has to be able to see it.
        assert_eq!(
            config.header_protection_key_hex().as_deref(),
            Some("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
        );
        assert!(config.header_protection_enabled());
        assert_eq!(config.content_padding_addition, (8, 24));
        assert_eq!(config.content_padding_mtu, 1420);
        assert_eq!(config.timers.rekey_after_time, (30, 40));
        assert_eq!(config.timers.rekey_timeout, (5, 7));
        assert_eq!(config.timers.reject_after_time, (300, 400));
        assert_eq!(config.timers.keepalive_timeout, (20, 25));
        assert_eq!(config.timers.max_handshake_attempts, (9, 11));

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

    /// The short-`size` acceptability rule, and the ceiling that bounds the
    /// tail scan -- both checked directly, for the reason above.
    ///
    /// Neither is reachable through [`read_awg_params`] in a way any other test
    /// observes: `AWG_PARAMS_SIZE_VER0` equals this build's size, so no size is
    /// both valid and short, and disabling the published-size guard outright
    /// left the whole suite green. The ceiling's *value* was equally unpinned --
    /// raising it to four billion changed nothing any test looked at, which is
    /// precisely the four-gigabyte read its own rustdoc says it exists to
    /// prevent.
    #[test]
    // Two of the assertions below compare two `const usize`s, so clippy
    // const-evaluates them and suggests moving them to an anonymous constant.
    // They already exist as `const _` guards at the definitions; the whole
    // point of restating them here is that a compile-time guard for a state no
    // input can reach is invisible to mutation. Silenced deliberately rather
    // than "fixed" by deleting the restatement.
    #[allow(clippy::assertions_on_constants)]
    fn awg_params_size_bounds_are_pinned() {
        let our = std::mem::size_of::<wireguard_awg_params>();

        // The ceiling has to stay above the struct it bounds, and this build's
        // size has to be one we have published. Both are `const _` assertions
        // at the definitions, and both are restated here on purpose: a
        // compile-time guard for a state no current input can reach is
        // invisible to mutation -- weakening `AWG_PARAMS_SIZE_MAX > size_of`
        // to `> 0` keeps compiling, because both are true today. Asserting the
        // relationship in two places is what makes weakening either one fail.
        assert!(
            AWG_PARAMS_SIZE_MAX > our,
            "the ceiling {} must stay above the struct it bounds ({}), or every correct caller \
             is refused for a mistake the library made",
            AWG_PARAMS_SIZE_MAX,
            our
        );
        assert!(
            AWG_PARAMS_PUBLISHED_SIZES.contains(&our),
            "this build's size {} must be a published size {:?}",
            our,
            AWG_PARAMS_PUBLISHED_SIZES
        );

        // This build's own size, and anything longer (where the zero-tail rule
        // takes over), are readable.
        assert!(awg_params_size_is_readable(our, our));
        assert!(awg_params_size_is_readable(our + 8, our));

        // A published shorter size stays readable once the struct grows -- the
        // whole promise the `size` field makes to an older caller.
        for &published in AWG_PARAMS_PUBLISHED_SIZES.iter() {
            assert!(
                awg_params_size_is_readable(published, published + 16),
                "published size {} must stay readable after the struct grows",
                published
            );
        }

        // A size that is short but was never published would cut a member in
        // half, so it is refused however plausible it looks.
        let future = our + 16;
        assert!(
            !awg_params_size_is_readable(our + 4, future),
            "an unpublished size between two versions must be refused"
        );
        assert!(!awg_params_size_is_readable(
            AWG_PARAMS_SIZE_VER0 + 1,
            future
        ));

        // The ceiling is a bound on how far past a 160-byte object the tail
        // scan may read. Its rustdoc promises "a few hundred bytes rather than
        // four gigabytes"; this is that promise, as an assertion.
        assert!(
            AWG_PARAMS_SIZE_MAX >= AWG_PARAMS_SIZE_VER0,
            "the ceiling must not sit below the floor"
        );
        assert!(
            AWG_PARAMS_SIZE_MAX <= 8 * AWG_PARAMS_SIZE_VER0,
            "AWG_PARAMS_SIZE_MAX is {}, which is no longer close to the {}-byte struct it \
             bounds: the window a garbage `size` can read past the caller's object is meant \
             to be a few hundred bytes",
            AWG_PARAMS_SIZE_MAX,
            AWG_PARAMS_SIZE_VER0
        );
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

        // A struct shorter than version 0 is refused outright. Note what this
        // does NOT test: "a short struct's absent tail reads as unset" is
        // unreachable today, because `AWG_PARAMS_SIZE_VER0` is this build's
        // size, so no size is both valid and short. `awg_params_copy_len_*`
        // pins the arithmetic; the copy that uses it has only ever run at
        // `copy == our_size`. An earlier version of this test dressed the
        // buffer up with a 0xff fill and a partial copy as though the tail were
        // being observed -- setup that nothing could read, in front of an
        // assertion about a different rule.
        let mut buffer = [0u8; 256];
        let short_len = 40usize;
        unsafe {
            ptr::write_unaligned(buffer.as_mut_ptr() as *mut u32, short_len as u32);
        }
        let short = unsafe { read_awg_params(buffer.as_ptr() as *const wireguard_awg_params) };
        assert!(short.is_none(), "a sub-version-0 size must be refused");
        assert!(
            last_error_string().contains("smaller than"),
            "{}",
            last_error_string()
        );

        // An absurd size is refused by name rather than being used as a length.
        // Before the ceiling existed this asked `slice::from_raw_parts` for
        // ~4 GiB starting just past a 160-byte object.
        last_tunnel_error_free();
        unsafe {
            ptr::write_unaligned(buffer.as_mut_ptr() as *mut u32, u32::MAX);
        }
        let huge = unsafe { read_awg_params(buffer.as_ptr() as *const wireguard_awg_params) };
        assert!(huge.is_none(), "an uninitialised size must be refused");
        assert!(
            last_error_string().contains("exceeds the"),
            "{}",
            last_error_string()
        );

        // Both sides of the ceiling, so `>` cannot become `>=` unnoticed. The
        // allocation really is `AWG_PARAMS_SIZE_MAX` bytes, since the accepted
        // case reads its whole zero tail.
        last_tunnel_error_free();
        let mut at_max = vec![0u8; AWG_PARAMS_SIZE_MAX];
        unsafe {
            ptr::write_unaligned(at_max.as_mut_ptr() as *mut u32, AWG_PARAMS_SIZE_MAX as u32);
        }
        assert!(
            unsafe { read_awg_params(at_max.as_ptr() as *const wireguard_awg_params) }.is_some(),
            "a size of exactly the ceiling is still accepted: {}",
            last_error_string()
        );
        last_tunnel_error_free();
        unsafe {
            ptr::write_unaligned(
                at_max.as_mut_ptr() as *mut u32,
                AWG_PARAMS_SIZE_MAX as u32 + 1,
            );
        }
        assert!(
            unsafe { read_awg_params(at_max.as_ptr() as *const wireguard_awg_params) }.is_none(),
            "one byte over the ceiling must be refused"
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

    /// Each H range reaches the slot it is named for.
    ///
    /// The four ranges are the one part of the struct that bypasses
    /// `awg_params_to_config`: `new_tunnel_with_awg_params` unpacks them back
    /// into eight positional `u32`s for `new_tunnel_with_amnezia_config`. That
    /// is the transposition hazard the struct exists to remove, reintroduced in
    /// the one line the constructor still writes, and no test used to set an H
    /// range to anything but zero -- so swapping two of the eight passed the
    /// whole suite. An inverted range is refused by `ObfuscationRanges::new`
    /// with the field's name in the message, which is what makes the routing
    /// observable from out here.
    #[test]
    fn awg_params_route_each_h_range_to_its_own_slot() {
        let private = CString::new("QOGr3GnKZlfhAQrJ2ZQaBRfhVAqYrHUpEE1QBLjHtF4=").unwrap();
        let public = CString::new("QOGr3GnKZlfhAQrJ2ZQaBRfhVAqYrHUpEE1QBLjHtF4=").unwrap();

        // An inverted range in one slot at a time; the error must name that
        // slot and no other.
        let inverted = wireguard_awg_range { lo: 400, hi: 300 };
        for (name, params) in [
            (
                "H1",
                wireguard_awg_params {
                    h1_init: inverted,
                    ..Default::default()
                },
            ),
            (
                "H2",
                wireguard_awg_params {
                    h2_resp: inverted,
                    ..Default::default()
                },
            ),
            (
                "H3",
                wireguard_awg_params {
                    h3_cookie: inverted,
                    ..Default::default()
                },
            ),
            (
                "H4",
                wireguard_awg_params {
                    h4_data: inverted,
                    ..Default::default()
                },
            ),
        ] {
            last_tunnel_error_free();
            let params = wireguard_awg_params {
                size: AWG_PARAMS_SIZE_VER0 as u32,
                ..params
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
            assert!(tunnel.is_null(), "{} inverted must not build", name);
            let error = last_error_string();
            assert!(
                error.contains(name),
                "{} was routed to another slot: {}",
                name,
                error
            );
            // ...and no OTHER slot is named, which is what makes this a routing
            // check rather than a "something went wrong" check.
            for other in ["H1", "H2", "H3", "H4"].iter().filter(|o| **o != name) {
                assert!(
                    !error.contains(other),
                    "{} inverted, but the error names {}: {}",
                    name,
                    other,
                    error
                );
            }
        }

        // And four valid, non-overlapping ranges build.
        last_tunnel_error_free();
        let params = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            h1_init: wireguard_awg_range { lo: 100, hi: 110 },
            h2_resp: wireguard_awg_range { lo: 200, hi: 210 },
            h3_cookie: wireguard_awg_range { lo: 300, hi: 310 },
            h4_data: wireguard_awg_range { lo: 400, hi: 410 },
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
        assert!(
            !tunnel.is_null(),
            "four disjoint H ranges must build: {}",
            last_error_string()
        );
        unsafe { tunnel_free(tunnel) };
    }

    /// A transposed range is refused, not silently re-sorted.
    ///
    /// `with_content_padding_addition` and `with_tunable_timers` normalize
    /// `lo > hi` on the way in, which is right for the crate's long-standing
    /// builders and wrong for this entry point: `{40, 30}` is the same slip as
    /// passing `hi` before `lo`, which is the whole reason the positional
    /// constructors were replaced. The UAPI refuses it too
    /// (`parse_uint_range`), and the adapter already refused a transposed junk
    /// size pair -- these six were the inconsistency.
    #[test]
    fn awg_params_refuse_a_transposed_range() {
        for (label, mutate) in [
            (
                "content_padding_addition",
                (|p: &mut wireguard_awg_params| {
                    p.content_padding_addition = wireguard_awg_range { lo: 40, hi: 30 };
                    p.content_padding_mtu = 1420;
                }) as fn(&mut wireguard_awg_params),
            ),
            ("rekey_after_time", |p| {
                p.rekey_after_time = wireguard_awg_range { lo: 40, hi: 30 }
            }),
            ("rekey_timeout", |p| {
                p.rekey_timeout = wireguard_awg_range { lo: 9, hi: 2 }
            }),
            ("reject_after_time", |p| {
                p.reject_after_time = wireguard_awg_range { lo: 400, hi: 300 }
            }),
            ("keepalive_timeout", |p| {
                p.keepalive_timeout = wireguard_awg_range { lo: 20, hi: 10 }
            }),
            // The one the `{n, 0}` confusion actually reaches: `validate`
            // exempts the count from the zero-in-a-range rule, so before this
            // check `{9, 0}` became a draw from 0..=9 with no diagnostic.
            ("max_handshake_attempts", |p| {
                p.max_handshake_attempts = wireguard_awg_range { lo: 9, hi: 0 }
            }),
        ] {
            last_tunnel_error_free();
            let mut params = wireguard_awg_params {
                size: AWG_PARAMS_SIZE_VER0 as u32,
                ..Default::default()
            };
            mutate(&mut params);
            assert!(
                awg_params_to_config(&params, None).is_none(),
                "{} accepted a transposed range",
                label
            );
            let error = last_error_string();
            assert!(error.contains(label), "{} not named in: {}", label, error);
        }

        // The same values the right way round are fine, so the check refuses
        // transposition rather than the values.
        last_tunnel_error_free();
        let ok = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            rekey_after_time: wireguard_awg_range { lo: 30, hi: 40 },
            reject_after_time: wireguard_awg_range { lo: 300, hi: 400 },
            max_handshake_attempts: wireguard_awg_range { lo: 0, hi: 9 },
            ..Default::default()
        };
        assert!(awg_params_to_config(&ok, None).is_some());
    }

    /// An active padding range with no MTU is refused.
    ///
    /// `content_padding_mtu == 0` means "no MTU known", and `content_padding`
    /// then skips both clamps -- the draw is bounded only by the caller's
    /// buffer, which is 64 KiB in a real embedder, so full-size packets grow
    /// past the link and blackhole. The device path always feeds a real
    /// interface MTU; the FFI is the only way to reach this combination.
    #[test]
    fn awg_params_refuse_padding_without_an_mtu() {
        last_tunnel_error_free();
        let no_mtu = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            content_padding_addition: wireguard_awg_range { lo: 100, hi: 200 },
            ..Default::default()
        };
        assert!(awg_params_to_config(&no_mtu, None).is_none());
        let error = last_error_string();
        assert!(
            error.contains("content_padding_mtu"),
            "the error must name the field to set: {}",
            error
        );

        // With an MTU it is accepted, and the range reaches the config.
        last_tunnel_error_free();
        let with_mtu = wireguard_awg_params {
            content_padding_mtu: 1420,
            ..no_mtu
        };
        let config = awg_params_to_config(&with_mtu, None).expect("valid with an MTU");
        assert_eq!(config.content_padding_addition, (100, 200));
        assert_eq!(config.content_padding_mtu, 1420);

        // An unset range with no MTU stays fine: that is a vanilla tunnel, and
        // the 16-byte rounding it does get is MTU-independent.
        last_tunnel_error_free();
        let unset = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            ..Default::default()
        };
        assert!(awg_params_to_config(&unset, None).is_some());
    }

    /// A parameter that would have been silently rewritten is refused instead.
    ///
    /// `AmneziaPreHandshakeJunk::new` substitutes rather than fails, and
    /// `validate` never looks at the junk burst, so `junk_packet_count = 200`
    /// used to build a tunnel with the burst switched off entirely and no error
    /// -- while the harmless `70000` produced a clear message.
    #[test]
    fn awg_params_refuse_a_silently_rewritten_junk_burst() {
        last_tunnel_error_free();
        let over_ceiling = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            junk_packet_count: 200,
            ..Default::default()
        };
        assert!(
            awg_params_to_config(&over_ceiling, None).is_none(),
            "a Jc that would be zeroed must be refused"
        );
        assert!(
            last_error_string().contains("junk_packet_count"),
            "{}",
            last_error_string()
        );

        // The delay has its own ceiling, and its own silent zeroing.
        last_tunnel_error_free();
        let slow = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            junk_packet_count: 4,
            junk_packet_delay_ms: 500,
            ..Default::default()
        };
        assert!(
            awg_params_to_config(&slow, None).is_none(),
            "a Jd that would be zeroed must be refused"
        );

        // A transposed size pair would become the built-in default.
        last_tunnel_error_free();
        let transposed = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            junk_packet_count: 4,
            junk_packet_size_min: 500,
            junk_packet_size_max: 50,
            ..Default::default()
        };
        assert!(
            awg_params_to_config(&transposed, None).is_none(),
            "a size pair that would be replaced must be refused"
        );

        // But leaving the size pair unset with a burst configured is a real
        // request for the defaults, and must still work.
        last_tunnel_error_free();
        let defaults = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            junk_packet_count: 4,
            ..Default::default()
        };
        let config = awg_params_to_config(&defaults, None)
            .expect("an unset size pair means 'use the defaults'");
        assert_eq!(config.pre_handshake_junk.packet_count, 4);
        assert!(config.pre_handshake_junk.packet_size_max > 0);

        // With no burst there is nothing to rewrite: the sizes and the delay
        // are never read, so an out-of-range value in them is inert and must
        // not be an error.
        last_tunnel_error_free();
        let no_burst = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            junk_packet_count: 0,
            junk_packet_size_min: 5000,
            junk_packet_size_max: 9000,
            junk_packet_delay_ms: 5000,
            ..Default::default()
        };
        assert!(
            awg_params_to_config(&no_burst, None).is_some(),
            "with Jc = 0 the unread fields must not be an error: {}",
            last_error_string()
        );
    }

    /// The junk-burst limits the header states are exactly where they are.
    ///
    /// The bounds live as private constants in `noise::amnezia`, so the numbers
    /// in `wireguard_awg_params`'s rustdoc and in `wireguard_ffi.h` are a claim
    /// about another module. This pins them: a caller cannot act on a bound
    /// nobody checks, and the doc must not be the only thing asserting it.
    #[test]
    fn awg_params_junk_bounds_are_where_the_docs_say() {
        let at = |jc: u32, jmin: u32, jmax: u32, jd: u32| {
            last_tunnel_error_free();
            let p = wireguard_awg_params {
                size: AWG_PARAMS_SIZE_VER0 as u32,
                junk_packet_count: jc,
                junk_packet_size_min: jmin,
                junk_packet_size_max: jmax,
                junk_packet_delay_ms: jd,
                ..Default::default()
            };
            awg_params_to_config(&p, None).is_some()
        };

        // junk_packet_count <= 128
        assert!(at(128, 50, 500, 10), "Jc = 128 is the documented ceiling");
        assert!(!at(129, 50, 500, 10), "Jc = 129 must be refused");
        // junk_packet_delay_ms <= 200
        assert!(at(4, 50, 500, 200), "Jd = 200 is the documented ceiling");
        assert!(!at(4, 50, 500, 201), "Jd = 201 must be refused");
        // 1 <= min <= max <= 1280
        assert!(at(4, 1, 1280, 10), "the full documented size range");
        assert!(!at(4, 1, 1281, 10), "Jmax = 1281 must be refused");
        assert!(!at(4, 0, 500, 10), "Jmin = 0 with a burst must be refused");
        assert!(!at(4, 500, 499, 10), "Jmin > Jmax must be refused");
        // {0, 0} is "use the defaults", not a violation of `1 <= min`.
        assert!(at(4, 0, 0, 10), "an unset size pair means the defaults");
    }

    /// A hostname that is valid UTF-8 but not a valid host is refused, not
    /// swapped for a random one.
    ///
    /// The non-UTF-8 check covered the rarest case; `is_valid_imitation_host`
    /// rejects the common ones (an underscore, a trailing dot, an over-long
    /// label) and `AmneziaImitation::new` then drops the name and generates a
    /// random one at emit time -- a substitution visible only in a capture.
    ///
    /// Both validators are exercised, because they disagree: QUIC's SNI goes
    /// through the far looser `is_valid_quic_sni`, so the underscore that is
    /// fatal to a DNS QNAME is perfectly good there. A test that only drove
    /// DNS would leave the QUIC arm of this check unvisited while reading as
    /// though it covered "the imitation domain".
    #[test]
    fn awg_params_refuse_a_domain_that_would_be_replaced() {
        last_tunnel_error_free();
        let params = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            imitation_protocol: AmneziaImitationProtocol::Dns as u32,
            ..Default::default()
        };
        assert!(
            awg_params_to_config(&params, Some("my_host.example.com".to_owned())).is_none(),
            "an invalid hostname must be refused rather than replaced"
        );
        assert!(
            last_error_string().contains("imitation domain"),
            "{}",
            last_error_string()
        );

        // A valid one survives, and is reported as kept.
        last_tunnel_error_free();
        let config = awg_params_to_config(&params, Some("example.com".to_owned()))
            .expect("a valid hostname is accepted");
        assert_eq!(config.imitation.domain(), Some("example.com"));

        // QUIC, whose SNI goes through the other validator. The underscore
        // that DNS refuses above is legal here, so this arm must ACCEPT it --
        // and a control character, which no SNI may carry, must still be
        // refused. Without both, the QUIC arm of `uses_domain` was untested and
        // the check could have been hard-wired to the DNS rules unnoticed.
        last_tunnel_error_free();
        let quic = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            imitation_protocol: AmneziaImitationProtocol::Quic as u32,
            ..Default::default()
        };
        let config = awg_params_to_config(&quic, Some("my_host.example.com".to_owned()))
            .expect("an underscore is a legal SNI, whatever DNS thinks");
        assert_eq!(config.imitation.domain(), Some("my_host.example.com"));
        last_tunnel_error_free();
        assert!(
            awg_params_to_config(&quic, Some("bad\u{7f}host".to_owned())).is_none(),
            "an SNI that would be replaced must still be refused for QUIC"
        );

        // A protocol that carries no hostname ignores the domain, as it always
        // has -- that is not a substitution, so it is not an error.
        last_tunnel_error_free();
        let stun = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            imitation_protocol: AmneziaImitationProtocol::Stun as u32,
            ..Default::default()
        };
        assert!(
            awg_params_to_config(&stun, Some("example.com".to_owned())).is_some(),
            "a hostname-free protocol must still accept a domain: {}",
            last_error_string()
        );

        // An EMPTY domain is "none supplied", exactly as NULL is. Marshalling
        // layers hand over "" for an absent string all the time, and the legacy
        // constructors have always treated the two alike -- so the new refusal
        // must not turn the commonest way of saying "nothing here" into a NULL
        // return. Driven through the constructor, since that is where the
        // C string is decoded.
        let private = CString::new("QOGr3GnKZlfhAQrJ2ZQaBRfhVAqYrHUpEE1QBLjHtF4=").unwrap();
        let public = CString::new("QOGr3GnKZlfhAQrJ2ZQaBRfhVAqYrHUpEE1QBLjHtF4=").unwrap();
        let empty_domain = CString::new("").unwrap();
        for (label, domain) in [
            ("NULL", ptr::null()),
            ("empty", empty_domain.as_ptr() as *const c_char),
        ] {
            last_tunnel_error_free();
            let tunnel = unsafe {
                new_tunnel_with_awg_params(
                    private.as_ptr(),
                    public.as_ptr(),
                    ptr::null(),
                    0,
                    0,
                    &params,
                    domain,
                )
            };
            assert!(
                !tunnel.is_null(),
                "a {} domain must build a tunnel, not fail: {}",
                label,
                last_error_string()
            );
            unsafe { tunnel_free(tunnel) };
        }
    }

    /// A header-protection key forces every S prefix to at least `NONCE_SIZE`.
    ///
    /// The headline 3.0 feature's most natural first call -- a zeroed struct
    /// with nothing but a key -- is a NULL return, and nothing in the suite
    /// went near it: `awg_params_reach_every_feature` sets a key but calls
    /// `awg_params_to_config` directly, which never runs `validate`, and its
    /// S values are 120/130/110/80 anyway. So the refusal that a caller is
    /// most likely to hit first was pinned by nothing at all, and neither the
    /// rustdoc nor `wireguard_ffi.h` mentioned the rule.
    ///
    /// Driven through the constructor, since `validate` is what enforces it.
    #[test]
    fn awg_params_header_protection_needs_twelve_byte_s_prefixes() {
        let private = CString::new("QOGr3GnKZlfhAQrJ2ZQaBRfhVAqYrHUpEE1QBLjHtF4=").unwrap();
        let public = CString::new("QOGr3GnKZlfhAQrJ2ZQaBRfhVAqYrHUpEE1QBLjHtF4=").unwrap();
        let build = |s: u32| {
            last_tunnel_error_free();
            let params = wireguard_awg_params {
                size: AWG_PARAMS_SIZE_VER0 as u32,
                s1_init_junk: s,
                s2_response_junk: s,
                s3_cookie_junk: s,
                s4_transport_junk: s,
                header_protection_key: [0xab; 32],
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
            let built = !tunnel.is_null();
            if built {
                unsafe { tunnel_free(tunnel) };
            }
            built
        };

        // A key and nothing else: refused, and the message names the S value
        // the caller has to raise.
        assert!(!build(0), "a key with no S prefix must be refused");
        let error = last_error_string();
        assert!(error.contains("S1"), "{}", error);
        assert!(error.contains("12"), "{}", error);

        // Both sides of the boundary, so the 12 cannot drift unnoticed.
        assert!(!build(11), "11 is one byte short of the nonce");
        assert!(
            build(12),
            "12 is the documented minimum: {}",
            last_error_string()
        );

        // ...and with no key the same S values are unremarkable, so the rule
        // really is the key's and not a floor on S.
        last_tunnel_error_free();
        let no_key = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            ..Default::default()
        };
        assert!(
            awg_params_to_config(&no_key, None).is_some(),
            "{}",
            last_error_string()
        );
    }

    /// The junk `u16` narrowing applies whether or not there is a burst.
    ///
    /// The rustdoc used to say the sizes and the delay were "unread and
    /// unchecked" at `junk_packet_count == 0`. Only the *bounds* are skipped:
    /// `size16` runs on all four fields before `jc` is consulted, so 70000 is
    /// refused with no burst configured. The existing coverage
    /// (`awg_params_refuse_a_silently_rewritten_junk_burst`) uses 5000/9000/5000
    /// -- all inside `u16` -- so it could not see the difference.
    #[test]
    fn awg_params_size16_applies_regardless_of_the_burst() {
        for (label, params) in [
            (
                "junk_packet_size_max",
                wireguard_awg_params {
                    junk_packet_size_max: 70_000,
                    ..Default::default()
                },
            ),
            (
                "junk_packet_size_min",
                wireguard_awg_params {
                    junk_packet_size_min: 70_000,
                    ..Default::default()
                },
            ),
            (
                "junk_packet_delay_ms",
                wireguard_awg_params {
                    junk_packet_delay_ms: 70_000,
                    ..Default::default()
                },
            ),
        ] {
            last_tunnel_error_free();
            let params = wireguard_awg_params {
                size: AWG_PARAMS_SIZE_VER0 as u32,
                junk_packet_count: 0,
                ..params
            };
            assert!(
                awg_params_to_config(&params, None).is_none(),
                "{} above u16::MAX must be refused even with no burst",
                label
            );
            let error = last_error_string();
            assert!(error.contains(label), "{} not named in: {}", label, error);
        }
    }

    /// Out-of-range junk sizes are refused under imitation, where they are
    /// never read.
    ///
    /// `pre_handshake_junk_size` draws from the protocol's own constants for
    /// every non-`None` imitation, so Jmin/Jmax are as inert there as they are
    /// at `jc == 0` -- which the adapter *does* exempt. This pins the
    /// asymmetry as a deliberate choice: a profile
    /// `new_tunnel_with_amnezia_junk_imitation` builds is refused here, so the
    /// difference cannot be changed by accident in either direction.
    #[test]
    fn awg_params_refuse_out_of_range_junk_sizes_under_imitation() {
        last_tunnel_error_free();
        let params = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            imitation_protocol: AmneziaImitationProtocol::Dns as u32,
            junk_packet_count: 4,
            junk_packet_size_min: 5_000,
            junk_packet_size_max: 9_000,
            ..Default::default()
        };
        assert!(
            awg_params_to_config(&params, None).is_none(),
            "an out-of-range size pair is refused even though DNS imitation \
             never reads it"
        );
        assert!(
            last_error_string().contains("junk_packet_size_min"),
            "{}",
            last_error_string()
        );

        // The same burst with sizes inside the bounds builds, so the refusal is
        // about the values and not about combining a burst with imitation.
        last_tunnel_error_free();
        let ok = wireguard_awg_params {
            junk_packet_size_min: 50,
            junk_packet_size_max: 500,
            ..params
        };
        assert!(
            awg_params_to_config(&ok, None).is_some(),
            "{}",
            last_error_string()
        );
    }

    /// `==` still distinguishes every field, the key included.
    ///
    /// `PartialEq` is hand-written so the key is compared in constant time,
    /// and a hand-written impl can drop a field where a derive cannot. Nothing
    /// covered that: replacing the key comparison with `true` outright left the
    /// whole suite green, including `awg_params_versioning_*`, which is the one
    /// test that compares two of these -- it happens to compare structs that
    /// are equal, so an impl that returns "equal" too readily is invisible to
    /// it.
    ///
    /// Every field gets its own mutator, so a member missing from the impl
    /// fails here by name.
    #[test]
    fn awg_params_equality_compares_every_field() {
        /// One named field-bumper. Aliased so the array below is not the
        /// "very complex type" clippy flags.
        type Mutator = (&'static str, fn(&mut wireguard_awg_params));

        let one = wireguard_awg_range { lo: 1, hi: 1 };
        let mutators: [Mutator; 23] = [
            ("size", |p| p.size += 1),
            ("s1_init_junk", |p| p.s1_init_junk += 1),
            ("s2_response_junk", |p| p.s2_response_junk += 1),
            ("s3_cookie_junk", |p| p.s3_cookie_junk += 1),
            ("s4_transport_junk", |p| p.s4_transport_junk += 1),
            ("junk_packet_count", |p| p.junk_packet_count += 1),
            ("junk_packet_size_min", |p| p.junk_packet_size_min += 1),
            ("junk_packet_size_max", |p| p.junk_packet_size_max += 1),
            ("junk_packet_delay_ms", |p| p.junk_packet_delay_ms += 1),
            ("h1_init", |p| p.h1_init.lo += 1),
            ("h2_resp", |p| p.h2_resp.lo += 1),
            ("h3_cookie", |p| p.h3_cookie.lo += 1),
            ("h4_data", |p| p.h4_data.lo += 1),
            ("imitation_protocol", |p| p.imitation_protocol += 1),
            ("imitation_browser", |p| p.imitation_browser += 1),
            ("content_padding_addition", |p| {
                p.content_padding_addition.lo += 1
            }),
            ("content_padding_mtu", |p| p.content_padding_mtu += 1),
            ("rekey_after_time", |p| p.rekey_after_time.lo += 1),
            ("rekey_timeout", |p| p.rekey_timeout.lo += 1),
            ("reject_after_time", |p| p.reject_after_time.lo += 1),
            ("keepalive_timeout", |p| p.keepalive_timeout.lo += 1),
            ("max_handshake_attempts", |p| {
                p.max_handshake_attempts.lo += 1
            }),
            ("header_protection_key", |p| {
                p.header_protection_key[31] ^= 1
            }),
        ];

        // A base with every field non-zero, so `hi` cannot be left behind by a
        // mutator that only bumps `lo`, and so the key differs in its LAST byte
        // -- the byte a comparison that stops early is likeliest to skip.
        let base = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            s1_init_junk: 12,
            s2_response_junk: 12,
            s3_cookie_junk: 12,
            s4_transport_junk: 12,
            junk_packet_count: 4,
            junk_packet_size_min: 50,
            junk_packet_size_max: 500,
            junk_packet_delay_ms: 10,
            h1_init: one,
            h2_resp: one,
            h3_cookie: one,
            h4_data: one,
            imitation_protocol: 1,
            imitation_browser: 1,
            content_padding_addition: one,
            content_padding_mtu: 1420,
            rekey_after_time: one,
            rekey_timeout: one,
            reject_after_time: one,
            keepalive_timeout: one,
            max_handshake_attempts: one,
            header_protection_key: [7u8; 32],
        };
        assert_eq!(base, base, "a struct must equal itself");

        for (name, mutate) in mutators {
            let mut other = base;
            mutate(&mut other);
            assert_ne!(
                base, other,
                "{} is not compared by PartialEq: two different configurations \
                 look identical",
                name
            );
        }
    }

    /// The redacting `Debug` keeps the header-protection key out of logs.
    #[test]
    fn awg_params_debug_never_prints_the_header_protection_key() {
        let params = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            s1_init_junk: 120,
            header_protection_key: [0xab; 32],
            ..Default::default()
        };
        let rendered = format!("{:?}", params);
        assert!(
            !rendered.contains("171") && !rendered.contains("ab, ab"),
            "the key must not appear in Debug output: {}",
            rendered
        );
        assert!(rendered.contains("\"set\""), "{}", rendered);
        assert!(rendered.contains("s1_init_junk: 120"), "{}", rendered);

        let unset = wireguard_awg_params::default();
        assert!(format!("{:?}", unset).contains("\"unset\""));
    }

    /// An amplifying S3 is a server's choice, so this constructor builds it.
    ///
    /// S1=65, S2=86, S3=120 is an ordinary AmneziaWG 2.0 profile: the kernel
    /// module and amneziawg-go both run it, and so do the legacy
    /// `new_tunnel_with_amnezia*` constructors. It trips the cookie-reflection
    /// rule on the S2 bound (64 + 120 = 184 > 92 + 86 = 178) -- the tighter of
    /// the two -- which `validate` refuses and this entry point must not,
    /// because S3 is symmetric and interface-wide: a client that lowered it to
    /// satisfy the rule could no longer parse its server's cookie replies.
    ///
    /// Constructed at *both* ends and driven through a real handshake and a
    /// data packet rather than asserted non-NULL, because a constructor-only
    /// check would also pass if the fix accepted the configuration and then
    /// dropped or mis-sized the prefixes.
    ///
    /// What the two size assertions prove is that **S1 and S2** survived and
    /// the session works -- not S3, which leaves no trace here. S3 sizes cookie
    /// replies, a `Tunn` never formats one (`format_cookie_reply` is reachable
    /// only from `device`), and nothing in this test provokes one, so a change
    /// that dropped `s3_cookie_junk` on the floor would still pass: S3 = 0 does
    /// not amplify, and the initiation and response would be unchanged. That
    /// the value reaches the config at all is pinned by
    /// [`awg_params_reach_every_feature`]; this test's job is that the
    /// constructor no longer *refuses* the profile and that the tunnel it
    /// returns actually works.
    #[test]
    fn an_amplifying_s3_builds_and_carries_traffic_through_the_awg_constructor() {
        last_tunnel_error_free();
        let params = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            s1_init_junk: 65,
            s2_response_junk: 86,
            s3_cookie_junk: 120,
            ..Default::default()
        };

        let secret = |k: &x25519_key| x25519_key { key: k.key };
        let c_sec = x25519_secret_key();
        let c_pub = x25519_public_key(secret(&c_sec));
        let s_sec = x25519_secret_key();
        let s_pub = x25519_public_key(secret(&s_sec));
        let b64 = |k: x25519_key| unsafe {
            let p = x25519_key_to_base64(k);
            let s = CStr::from_ptr(p).to_owned();
            x25519_key_to_str_free(p);
            s
        };
        let (c_sec, c_pub, s_sec, s_pub) = (b64(c_sec), b64(c_pub), b64(s_sec), b64(s_pub));

        let build = |private: &CString, public: &CString, index: u32| unsafe {
            let t = new_tunnel_with_awg_params(
                private.as_ptr(),
                public.as_ptr(),
                ptr::null(),
                0,
                index,
                &params,
                ptr::null(),
            );
            assert!(
                !t.is_null(),
                "a server-dictated S3 must not be refused here: {}",
                last_error_string()
            );
            t
        };
        let client = build(&c_sec, &s_pub, 1);
        let server = build(&s_sec, &c_pub, 2);

        // The complaint is logged, never stored. Both docs state that a
        // non-NULL return means there is nothing to read, so pin it here:
        // routing the warning through `set_last_error` would leave a stale
        // string that a caller checking the error after a *successful* build
        // would read as a failure.
        assert!(
            last_tunnel_error().is_null(),
            "an accepted profile must not leave a message in last_tunnel_error()"
        );

        let mut a = vec![0u8; 65536 + 64];
        let mut b = vec![0u8; 65536 + 64];

        let r = unsafe { wireguard_force_handshake(client, a.as_mut_ptr(), a.len() as u32) };
        assert!(matches!(r.op, result_type::WRITE_TO_NETWORK));
        assert_eq!(
            r.size,
            148 + 65,
            "the initiation must carry its S1 prefix, or the profile was not applied"
        );
        let init = a[..r.size].to_vec();

        let r = unsafe {
            wireguard_read(
                server,
                init.as_ptr(),
                init.len() as u32,
                b.as_mut_ptr(),
                b.len() as u32,
            )
        };
        assert!(matches!(r.op, result_type::WRITE_TO_NETWORK));
        assert_eq!(
            r.size,
            92 + 86,
            "the response must carry its S2 prefix, or the profile was not applied"
        );
        let resp = b[..r.size].to_vec();

        let r = unsafe {
            wireguard_read(
                client,
                resp.as_ptr(),
                resp.len() as u32,
                a.as_mut_ptr(),
                a.len() as u32,
            )
        };
        assert!(matches!(
            r.op,
            result_type::WRITE_TO_NETWORK | result_type::WIREGUARD_DONE
        ));

        // A data packet all the way through, so "the session works" is measured
        // rather than inferred from the handshake completing.
        let mut pkt = [0u8; 60];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&60u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);

        let r = unsafe {
            wireguard_write(
                client,
                pkt.as_ptr(),
                pkt.len() as u32,
                a.as_mut_ptr(),
                a.len() as u32,
            )
        };
        assert!(matches!(r.op, result_type::WRITE_TO_NETWORK));
        let data = a[..r.size].to_vec();

        let r = unsafe {
            wireguard_read(
                server,
                data.as_ptr(),
                data.len() as u32,
                b.as_mut_ptr(),
                b.len() as u32,
            )
        };
        assert!(
            matches!(r.op, result_type::WRITE_TO_TUNNEL_IPV4),
            "the payload must arrive as plaintext"
        );
        assert_eq!(&b[..r.size], &pkt[..], "the payload must round-trip intact");

        unsafe {
            tunnel_free(client);
            tunnel_free(server);
        }
    }

    /// The amplifying-S3 warning is actually emitted.
    ///
    /// The header promises it: having stopped refusing this configuration, the
    /// WARN is the entire remaining operator-visible signal, and it is stated
    /// as contract next to the prototype. Nothing else pins it -- the two-doors
    /// test asserts only that `cookie_amplification_complaint` returns `Some`,
    /// which is that there is something to log, not that anything logs it, so
    /// deleting the `tracing::warn!` left every other test green.
    ///
    /// Also pins the other half of the same sentence: that the complaint does
    /// NOT go through `last_tunnel_error()`. A non-NULL return must never mean
    /// "read the error", or an embedder checking the error slot after a
    /// successful build reads a message about a tunnel it just built fine.
    #[test]
    fn an_amplifying_s3_warns_and_leaves_the_error_slot_empty() {
        // Failed once on macOS CI when another `with_default` test's dispatcher
        // churn raced this one's `warn!` -- see `tracing_test_lock`.
        let _serialized = crate::tracing_test_lock();
        use std::sync::{Arc, Mutex as StdMutex};
        use tracing::field::{Field, Visit};
        use tracing::Subscriber;
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;

        #[derive(Default)]
        struct Captured {
            message: String,
            detail: String,
        }
        impl Visit for Captured {
            fn record_str(&mut self, field: &Field, value: &str) {
                match field.name() {
                    "message" => self.message = value.to_owned(),
                    "detail" => self.detail = value.to_owned(),
                    _ => {}
                }
            }
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                let slot = match field.name() {
                    "message" => &mut self.message,
                    "detail" => &mut self.detail,
                    _ => return,
                };
                if slot.is_empty() {
                    *slot = format!("{:?}", value);
                }
            }
        }
        struct Capture(Arc<StdMutex<Vec<Captured>>>);
        impl<S: Subscriber> Layer<S> for Capture {
            fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
                let mut c = Captured::default();
                event.record(&mut c);
                self.0.lock().unwrap().push(c);
            }
        }

        let build = |s3: u32| -> Vec<Captured> {
            let events: Arc<StdMutex<Vec<Captured>>> = Arc::new(StdMutex::new(Vec::new()));
            {
                let subscriber = tracing_subscriber::registry().with(Capture(Arc::clone(&events)));
                tracing::subscriber::with_default(subscriber, || {
                    last_tunnel_error_free();
                    let params = wireguard_awg_params {
                        size: AWG_PARAMS_SIZE_VER0 as u32,
                        s1_init_junk: 65,
                        s2_response_junk: 86,
                        s3_cookie_junk: s3,
                        ..Default::default()
                    };
                    let key = CString::new("QOGr3GnKZlfhAQrJ2ZQaBRfhVAqYrHUpEE1QBLjHtF4=").unwrap();
                    let tunnel = unsafe {
                        new_tunnel_with_awg_params(
                            key.as_ptr(),
                            key.as_ptr(),
                            ptr::null(),
                            0,
                            1,
                            &params,
                            ptr::null(),
                        )
                    };
                    assert!(!tunnel.is_null(), "{}", last_error_string());
                    assert!(
                        last_tunnel_error().is_null(),
                        "a non-NULL return must leave the error slot empty"
                    );
                    unsafe { tunnel_free(tunnel) };
                });
            }
            // Read through the lock rather than `Arc::try_unwrap`: tracing's
            // dispatcher registry can keep the subscriber -- and with it the
            // other clone of this Arc -- alive for a moment past the scope
            // above, and `try_unwrap` turns that latency into a panic that has
            // nothing to do with what this test asserts.
            let captured = std::mem::take(&mut *events.lock().unwrap());
            captured
        };

        // 64 + 120 = 184 > 92 + 86 = 178.
        //
        // Bounded retry, and only on this half. tracing caches per-callsite
        // interest in a process-global table; other tests hit this same
        // `warn!` callsite from threads with no subscriber (caching "never"),
        // and a registration racing the rebuild that `with_default` triggers
        // can clobber it back -- the event is then dropped with this test's
        // subscriber installed and active, which was measured here as
        // `captured: []` roughly once per twenty runs. Real embedders never
        // see this: they install one global subscriber at startup, before any
        // callsite is hit, and nothing churns afterwards. A retry keeps the
        // mutation kill intact -- a deleted `warn!` captures nothing on every
        // attempt -- while a lost cache update wins the next round. The clean
        // half below stays single-shot: a dropped event can only *lose* a
        // warning, never invent one.
        let amplifying = (0..5)
            .map(|attempt| {
                if attempt > 0 {
                    tracing::callsite::rebuild_interest_cache();
                }
                build(120)
            })
            .find(|events| {
                events
                    .iter()
                    .any(|c| c.detail.contains("makes a cookie reply"))
            })
            .unwrap_or_else(|| {
                panic!("the constructor must log the complaint; nothing captured in 5 attempts")
            });
        let warned = amplifying
            .iter()
            .find(|c| c.detail.contains("makes a cookie reply"))
            .expect("the winning attempt carries the event");
        assert!(
            warned.message.contains("reflect"),
            "the message must say what is wrong: {}",
            warned.message
        );
        assert!(
            warned.detail.contains("S3 = 120") && warned.detail.contains("178"),
            "and carry the arithmetic the operator acts on: {}",
            warned.detail
        );

        // One byte under the bound: the same build must say nothing, or the
        // assertion above would pass on any configuration at all.
        assert!(
            build(114)
                .iter()
                .all(|c| !c.detail.contains("makes a cookie reply")),
            "a clean profile must not warn"
        );
    }

    /// A live tunnel whose MTU moved pads to the new clamp, not the old one.
    ///
    /// This is the reason the entry point exists: `content_padding_mtu` is a
    /// construction-time snapshot, an embedder's MTU is recomputed on every
    /// reconnect and roam, and the tunnel handle outlives both. Measured on
    /// the wire rather than by reading the field back, because the field being
    /// right is not the claim -- the claim is that the *packets* get smaller.
    ///
    /// Drawn repeatedly at 1420 because the addition is a random range and the
    /// clamp only binds on a draw of 140 or more: one sample lands under that
    /// 68% of the time and would measure the draw rather than the clamp. The
    /// 1280 side needs no repetition at all -- the packet is exactly 1280, so
    /// `content_padding`'s `want.min(mtu - last_unit)` is `min(want, 0)` and
    /// every draw is clamped to zero -- but it runs through the same closure,
    /// which is cheaper than a second one.
    #[test]
    fn refreshing_the_mtu_moves_the_padding_clamp_on_a_live_tunnel() {
        last_tunnel_error_free();
        let params = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            content_padding_addition: wireguard_awg_range { lo: 8, hi: 200 },
            content_padding_mtu: 1420,
            ..Default::default()
        };

        let secret = |k: &x25519_key| x25519_key { key: k.key };
        let c_sec = x25519_secret_key();
        let c_pub = x25519_public_key(secret(&c_sec));
        let s_sec = x25519_secret_key();
        let s_pub = x25519_public_key(secret(&s_sec));
        let b64 = |k: x25519_key| unsafe {
            let p = x25519_key_to_base64(k);
            let s = CStr::from_ptr(p).to_owned();
            x25519_key_to_str_free(p);
            s
        };
        let (c_sec, c_pub, s_sec, s_pub) = (b64(c_sec), b64(c_pub), b64(s_sec), b64(s_pub));

        let build = |private: &CString, public: &CString, index: u32| unsafe {
            let t = new_tunnel_with_awg_params(
                private.as_ptr(),
                public.as_ptr(),
                ptr::null(),
                0,
                index,
                &params,
                ptr::null(),
            );
            assert!(!t.is_null(), "{}", last_error_string());
            t
        };
        let client = build(&c_sec, &s_pub, 1);
        let server = build(&s_sec, &c_pub, 2);

        let mut a = vec![0u8; 65536 + 64];
        let mut b = vec![0u8; 65536 + 64];

        // A real handshake, because content padding only runs once a session
        // exists.
        let r = unsafe { wireguard_force_handshake(client, a.as_mut_ptr(), a.len() as u32) };
        assert!(matches!(r.op, result_type::WRITE_TO_NETWORK));
        let init = a[..r.size].to_vec();
        let r = unsafe {
            wireguard_read(
                server,
                init.as_ptr(),
                init.len() as u32,
                b.as_mut_ptr(),
                b.len() as u32,
            )
        };
        assert!(matches!(r.op, result_type::WRITE_TO_NETWORK));
        let resp = b[..r.size].to_vec();
        let _ = unsafe {
            wireguard_read(
                client,
                resp.as_ptr(),
                resp.len() as u32,
                a.as_mut_ptr(),
                a.len() as u32,
            )
        };

        // A full-size inner packet for the *smaller* of the two MTUs, so the
        // same payload is legal before and after and the only variable is the
        // clamp.
        let mut pkt = vec![0u8; 1280];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&1280u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);

        let mut max_datagram = || {
            let mut max = 0usize;
            for _ in 0..300 {
                let r = unsafe {
                    wireguard_write(
                        client,
                        pkt.as_ptr(),
                        pkt.len() as u32,
                        a.as_mut_ptr(),
                        a.len() as u32,
                    )
                };
                assert!(matches!(r.op, result_type::WRITE_TO_NETWORK));
                max = max.max(r.size);
            }
            max
        };

        let before = max_datagram();

        assert!(
            unsafe { wireguard_set_content_padding_mtu(client, 1280) },
            "a live tunnel must accept an MTU refresh"
        );

        let after = max_datagram();

        assert!(
            after < before,
            "the clamp must follow the MTU down: {} bytes before, {} after",
            before,
            after
        );
        // And it must land on exactly the MTU asked for, not merely somewhere
        // smaller -- a change that clamped to any lesser value would pass the
        // assertion above. Checked on the field because the wire cannot show
        // it: the padding is a random draw, so no datagram size distinguishes
        // "clamped to 1280" from "clamped to something under 1280".
        assert_eq!(unsafe { (*client).lock().content_padding_mtu() }, 1280);

        unsafe {
            tunnel_free(client);
            tunnel_free(server);
        }
    }

    /// The refusals that keep the clamp from failing open.
    ///
    /// Zero is the dangerous input: it does not mean "a zero-byte MTU", it
    /// means no clamp at all, so storing it would unbound the padding -- and
    /// it is the one state `new_tunnel_with_awg_params` already refuses to
    /// construct, so accepting it here would open by the back door a state the
    /// front door rejects. Saturation covers the same hazard from the other
    /// end: `65536 as u16` is `0`, so a truncating implementation turns the
    /// largest possible MTU into no clamp at all.
    #[test]
    fn the_mtu_setter_refuses_the_values_that_would_unbound_the_padding() {
        last_tunnel_error_free();
        let params = wireguard_awg_params {
            size: AWG_PARAMS_SIZE_VER0 as u32,
            content_padding_addition: wireguard_awg_range { lo: 8, hi: 200 },
            content_padding_mtu: 1420,
            ..Default::default()
        };
        let key = CString::new("QOGr3GnKZlfhAQrJ2ZQaBRfhVAqYrHUpEE1QBLjHtF4=").unwrap();
        let tunnel = unsafe {
            new_tunnel_with_awg_params(
                key.as_ptr(),
                key.as_ptr(),
                ptr::null(),
                0,
                1,
                &params,
                ptr::null(),
            )
        };
        assert!(!tunnel.is_null(), "{}", last_error_string());

        let clamp = || unsafe { (*tunnel).lock().content_padding_mtu() };

        assert!(
            !unsafe { wireguard_set_content_padding_mtu(tunnel, 0) },
            "0 means no clamp at all and must be refused"
        );
        assert_eq!(clamp(), 1420, "a refused value must not have been stored");

        // A NULL tunnel is a `false` return, not an abort. In an embedder's
        // build the difference is stark: the older entry points `unwrap()`,
        // and this module's panic hook (production builds only -- it is
        // `cfg(not(test))` so test failures keep their messages) turns that
        // panic into a raised SIGSEGV, taking the host process down. Measured
        // as exactly that before the hook was gated: mutating this to the
        // older style killed the test harness with signal 11 rather than
        // failing cleanly.
        assert!(
            !unsafe { wireguard_set_content_padding_mtu(ptr::null(), 1280) },
            "a NULL tunnel must be refused"
        );

        assert!(unsafe { wireguard_set_content_padding_mtu(tunnel, 1280) });
        assert_eq!(clamp(), 1280);

        // Out of range is refused, not saturated. 65535 clamps no real
        // plaintext, so storing it and answering `true` would report success
        // for the same fail-open state that 0 is refused for -- and would
        // accept through this door a value `new_tunnel_with_awg_params`
        // refuses through the other one.
        for oversize in [65536u32, u32::MAX] {
            assert!(
                !unsafe { wireguard_set_content_padding_mtu(tunnel, oversize) },
                "an MTU above u16::MAX must be refused, not saturated: {}",
                oversize
            );
            assert_eq!(
                clamp(),
                1280,
                "a refused MTU must leave the previous clamp alone: {}",
                oversize
            );
        }

        // The largest value that IS in range still applies, so the refusal
        // above is a bound and not a blanket rejection of large MTUs.
        assert!(unsafe { wireguard_set_content_padding_mtu(tunnel, u16::MAX as u32) });
        assert_eq!(clamp(), u16::MAX);

        unsafe { tunnel_free(tunnel) };
    }

    /// `content_padding_mtu` bounds the *plaintext*, so it is the tunnel MTU
    /// and not the link MTU -- pinned as datagram sizes, end to end.
    ///
    /// The field's rustdoc quotes these four numbers to tell a caller what
    /// passing the wrong MTU costs. Every other test here stops at
    /// `awg_params_to_config`, which never reaches `content_padding`, so
    /// without this the numbers were prose: the doc could name any figure and
    /// nothing would disagree. It says 1500 rather than 1420 puts the datagram
    /// over a 1500-byte link, and that is the claim, so that is the assertion.
    #[test]
    fn content_padding_mtu_is_the_tunnel_mtu_not_the_link_mtu() {
        /// The largest UDP payload a full-MTU inner packet produces. Drawn
        /// repeatedly because the addition is a random range: one sample would
        /// pin whatever the RNG happened to give.
        fn max_datagram(mtu: u32, s4: u32) -> usize {
            let params = wireguard_awg_params {
                size: AWG_PARAMS_SIZE_VER0 as u32,
                s4_transport_junk: s4,
                content_padding_addition: wireguard_awg_range { lo: 8, hi: 200 },
                content_padding_mtu: mtu,
                ..Default::default()
            };

            let secret = |k: &x25519_key| x25519_key { key: k.key };
            let c_sec = x25519_secret_key();
            let c_pub = x25519_public_key(secret(&c_sec));
            let s_sec = x25519_secret_key();
            let s_pub = x25519_public_key(secret(&s_sec));
            let b64 = |k: x25519_key| unsafe {
                let p = x25519_key_to_base64(k);
                let s = CStr::from_ptr(p).to_owned();
                x25519_key_to_str_free(p);
                s
            };
            let (c_sec, c_pub, s_sec, s_pub) = (b64(c_sec), b64(c_pub), b64(s_sec), b64(s_pub));

            let build = |private: &CString, public: &CString, index: u32| unsafe {
                let t = new_tunnel_with_awg_params(
                    private.as_ptr(),
                    public.as_ptr(),
                    ptr::null(),
                    0,
                    index,
                    &params,
                    ptr::null(),
                );
                assert!(!t.is_null(), "{}", last_error_string());
                t
            };
            let client = build(&c_sec, &s_pub, 1);
            let server = build(&s_sec, &c_pub, 2);

            let mut a = vec![0u8; 65536 + 64];
            let mut b = vec![0u8; 65536 + 64];

            // A real handshake, because `content_padding` only runs once a
            // session exists.
            let r = unsafe { wireguard_force_handshake(client, a.as_mut_ptr(), a.len() as u32) };
            assert!(matches!(r.op, result_type::WRITE_TO_NETWORK));
            let init = a[..r.size].to_vec();
            let r = unsafe {
                wireguard_read(
                    server,
                    init.as_ptr(),
                    init.len() as u32,
                    b.as_mut_ptr(),
                    b.len() as u32,
                )
            };
            assert!(matches!(r.op, result_type::WRITE_TO_NETWORK));
            let resp = b[..r.size].to_vec();
            let _ = unsafe {
                wireguard_read(
                    client,
                    resp.as_ptr(),
                    resp.len() as u32,
                    a.as_mut_ptr(),
                    a.len() as u32,
                )
            };

            // A full-size inner packet for a 1420-byte tunnel.
            let mut pkt = vec![0u8; 1420];
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&1420u16.to_be_bytes());
            pkt[8] = 64;
            pkt[9] = 17;
            pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
            pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);

            let mut max = 0usize;
            for _ in 0..300 {
                let r = unsafe {
                    wireguard_write(
                        client,
                        pkt.as_ptr(),
                        pkt.len() as u32,
                        a.as_mut_ptr(),
                        a.len() as u32,
                    )
                };
                if matches!(r.op, result_type::WRITE_TO_NETWORK) {
                    max = max.max(r.size);
                }
            }
            unsafe {
                tunnel_free(client);
                tunnel_free(server);
            }
            max
        }

        // The tunnel MTU: padding is clamped to zero on a full-MTU packet, so
        // the datagram is the plaintext plus the 32-byte transport overhead.
        assert_eq!(max_datagram(1420, 0), 1452);
        // The link MTU by mistake: the clamp now permits the padding to eat the
        // 80 bytes of headroom the encapsulation was using.
        assert_eq!(max_datagram(1500, 0), 1532);
        // ...and S4 rides on top of that, so the overshoot grows with it.
        assert_eq!(max_datagram(1500, 40), 1572);
        // The claim the rustdoc actually makes: 1420 fits inside a 1500-byte
        // link once the outer IPv4+UDP headers are added, and 1500 does not.
        assert!(max_datagram(1420, 0) + 28 <= 1500);
        assert!(max_datagram(1500, 0) + 28 > 1500);
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
