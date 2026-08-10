// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// temporary, we need to do some verification around these bindings later
#![allow(clippy::missing_safety_doc)]

//! JNI bindings for BoringTun library
//!
//! jni 0.22 split `JNIEnv` into two types. What a native method receives is an
//! [`EnvUnowned`], which is FFI-safe and has no JNI methods of its own; the
//! usable [`jni::Env`] is obtained by calling [`EnvUnowned::with_env`], which
//! also catches panics so they cannot unwind into the JVM and abort the
//! process. Every entry point below therefore wraps its body in a closure.
//!
//! The closure's outcome is resolved with [`LogErrorAndDefault`], which logs
//! and returns `Default::default()` -- a null handle or `0`. That is
//! deliberately the same contract these functions had before the migration:
//! they returned null or 0 on failure and never threw. `ThrowRuntimeExAndDefault`
//! would raise a Java exception instead, which no current caller is written to
//! catch, so switching to it is a decision for the Java side rather than a
//! side effect of a dependency bump. The logging is new, and replaces silence.

use std::ffi::CStr;

use jni::errors::LogErrorAndDefault;
use jni::objects::{JByteArray, JByteBuffer, JClass, JString};
use jni::sys::{jint, jlong, jshort};
use jni::EnvUnowned;
use parking_lot::Mutex;
use std::os::raw::c_char;

use crate::ffi::new_tunnel;
use crate::ffi::wireguard_read;
use crate::ffi::wireguard_result;
use crate::ffi::wireguard_tick;
use crate::ffi::wireguard_write;
use crate::ffi::x25519_key;
use crate::ffi::x25519_key_to_base64;
use crate::ffi::x25519_key_to_hex;
use crate::ffi::x25519_key_to_str_free;
use crate::ffi::x25519_public_key;
use crate::ffi::x25519_secret_key;

use crate::noise::Tunn;

pub extern "C" fn log_print(_log_string: *const c_char) {
    /*
    XXX:
    Define callback function in app.
    */
}

/// Copy a C string produced by the FFI layer into a Rust `String`, then free it.
///
/// `x25519_key_to_hex` and `x25519_key_to_base64` hand back a pointer from
/// `CString::into_raw`, which the caller owns. The pre-0.22 code here never
/// freed them, so every call leaked the encoded key. Taking ownership at the
/// boundary keeps that from depending on whoever edits the call site next.
///
/// # Safety
///
/// `ptr` must be a non-null pointer returned by one of those two functions and
/// not yet freed.
unsafe fn take_ffi_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let owned = CStr::from_ptr(ptr).to_str().ok().map(str::to_owned);
    x25519_key_to_str_free(ptr);
    owned
}

/// Generates new x25519 secret key and converts into java byte array.
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_x25519_1secret_1key"]
pub extern "C" fn generate_secret_key<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> JByteArray<'local> {
    env.with_env(|env| -> jni::errors::Result<_> {
        env.byte_array_from_slice(&x25519_secret_key().key)
    })
    .resolve::<LogErrorAndDefault>()
}

/// Computes public x25519 key from secret key and converts into java byte array.
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_x25519_1public_1key"]
pub extern "C" fn generate_public_key1<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    arg_secret_key: JByteArray<'local>,
) -> JByteArray<'local> {
    env.with_env(|env| -> jni::errors::Result<_> {
        let mut key_inner = [0i8; 32];
        arg_secret_key.get_region(env, 0, &mut key_inner)?;

        // `as u8` per element rather than a `transmute` of the whole array:
        // same bytes, no `unsafe`.
        let secret_key = x25519_key {
            key: key_inner.map(|b| b as u8),
        };

        env.byte_array_from_slice(&x25519_public_key(secret_key).key)
    })
    .resolve::<LogErrorAndDefault>()
}

/// Converts x25519 key to hex string.
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_x25519_1key_1to_1hex"]
pub extern "C" fn convert_x25519_key_to_hex<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    arg_key: JByteArray<'local>,
) -> JString<'local> {
    env.with_env(|env| -> jni::errors::Result<_> {
        let mut key = [0i8; 32];
        arg_key.get_region(env, 0, &mut key)?;

        let x25519_key = x25519_key {
            key: key.map(|b| b as u8),
        };

        let hex = unsafe { take_ffi_string(x25519_key_to_hex(x25519_key)) }
            .ok_or(jni::errors::Error::NullPtr("x25519_key_to_hex"))?;

        env.new_string(hex)
    })
    .resolve::<LogErrorAndDefault>()
}

/// Converts x25519 key to base64 string.
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_x25519_1key_1to_1base64"]
pub extern "C" fn convert_x25519_key_to_base64<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    arg_key: JByteArray<'local>,
) -> JString<'local> {
    env.with_env(|env| -> jni::errors::Result<_> {
        let mut key = [0i8; 32];
        arg_key.get_region(env, 0, &mut key)?;

        let x25519_key = x25519_key {
            key: key.map(|b| b as u8),
        };

        let b64 = unsafe { take_ffi_string(x25519_key_to_base64(x25519_key)) }
            .ok_or(jni::errors::Error::NullPtr("x25519_key_to_base64"))?;

        env.new_string(b64)
    })
    .resolve::<LogErrorAndDefault>()
}

/// Creates new tunnel
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_new_1tunnel"]
pub extern "C" fn create_new_tunnel<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    arg_secret_key: JString<'local>,
    arg_public_key: JString<'local>,
    arg_preshared_key: JString<'local>,
    keep_alive: jshort,
    index: jint,
) -> jlong {
    env.with_env(|env| -> jni::errors::Result<_> {
        // These guards own the JVM's UTF-8 character arrays and release them on
        // drop. 0.19's `get_string_utf_chars` returned a bare pointer that the
        // caller had to hand back with `release_string_utf_chars`, and this
        // function never did -- so each call leaked three of them. They are
        // bound to locals rather than used inline because `new_tunnel` borrows
        // the pointers: a temporary would be dropped, and freed, too early.
        let secret_key = arg_secret_key.mutf8_chars(env)?;
        let public_key = arg_public_key.mutf8_chars(env)?;
        let preshared_key = if arg_preshared_key.is_null() {
            None
        } else {
            Some(arg_preshared_key.mutf8_chars(env)?)
        };

        let tunnel = unsafe {
            new_tunnel(
                secret_key.as_ptr(),
                public_key.as_ptr(),
                preshared_key
                    .as_ref()
                    .map_or(std::ptr::null(), |k| k.as_ptr()),
                keep_alive as u16,
                index as u32,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            )
        };

        Ok(if tunnel.is_null() { 0 } else { tunnel as jlong })
    })
    .resolve::<LogErrorAndDefault>()
}

/// Encrypts raw IP packets into WG formatted packets.
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_wireguard_1write"]
pub extern "C" fn encrypt_raw_packet<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
    src: JByteArray<'local>,
    src_size: jint,
    dst: JByteBuffer<'local>,
    dst_size: jint,
    op: JByteBuffer<'local>,
) -> jint {
    env.with_env(|env| -> jni::errors::Result<_> {
        // 0.22 returns the address directly; 0.19 returned a slice that this
        // code then took `.as_mut_ptr()` of.
        let dst_ptr = env.get_direct_buffer_address(&dst)?;
        let op_ptr = env.get_direct_buffer_address(&op)?;

        // Bound to a local: the pointer must not outlive the Vec that owns it.
        let mut src_bytes = env.convert_byte_array(&src)?;

        let output: wireguard_result = unsafe {
            wireguard_write(
                tunnel as *const Mutex<Tunn>,
                src_bytes.as_mut_ptr(),
                src_size as u32,
                dst_ptr,
                dst_size as u32,
            )
        };
        unsafe { *op_ptr = output.op as u8 };

        Ok(output.size as jint)
    })
    .resolve::<LogErrorAndDefault>()
}

/// Decrypts WG formatted packets into raw IP packets.
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_wireguard_1read"]
pub extern "C" fn decrypt_to_raw_packet<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
    src: JByteArray<'local>,
    src_size: jint,
    dst: JByteBuffer<'local>,
    dst_size: jint,
    op: JByteBuffer<'local>,
) -> jint {
    env.with_env(|env| -> jni::errors::Result<_> {
        let dst_ptr = env.get_direct_buffer_address(&dst)?;
        let op_ptr = env.get_direct_buffer_address(&op)?;

        let mut src_bytes = env.convert_byte_array(&src)?;

        let output: wireguard_result = unsafe {
            wireguard_read(
                tunnel as *const Mutex<Tunn>,
                src_bytes.as_mut_ptr(),
                src_size as u32,
                dst_ptr,
                dst_size as u32,
            )
        };
        unsafe { *op_ptr = output.op as u8 };

        Ok(output.size as jint)
    })
    .resolve::<LogErrorAndDefault>()
}

/// Periodic function that writes WG formatted packets into destination buffer
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_wireguard_1tick"]
pub extern "C" fn run_periodic_task<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
    dst: JByteBuffer<'local>,
    dst_size: jint,
    op: JByteBuffer<'local>,
) -> jint {
    env.with_env(|env| -> jni::errors::Result<_> {
        let dst_ptr = env.get_direct_buffer_address(&dst)?;
        let op_ptr = env.get_direct_buffer_address(&op)?;

        let output: wireguard_result =
            unsafe { wireguard_tick(tunnel as *const Mutex<Tunn>, dst_ptr, dst_size as u32) };

        unsafe { *op_ptr = output.op as u8 };

        Ok(output.size as jint)
    })
    .resolve::<LogErrorAndDefault>()
}
