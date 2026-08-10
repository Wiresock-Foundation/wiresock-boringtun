// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// temporary, we need to do some verification around these bindings later
#![allow(clippy::missing_safety_doc)]

//! JNI bindings for BoringTun library
//!
//! jni 0.22 split `JNIEnv` into two types. What a native method receives is an
//! [`EnvUnowned`], which is FFI-safe and has no JNI methods of its own; the
//! usable [`jni::Env`] is obtained by calling [`EnvUnowned::with_env`], which
//! also catches panics raised in the closure body. Every entry point below
//! therefore wraps its body in a closure.
//!
//! That catch stops at the closure, and it is worth being precise about where.
//! `ffi::wireguard_write` and its siblings are `extern "C"`, so a panic inside
//! *them* aborts the process before control can return here -- rustc's own
//! words are `panic in a function that cannot unwind`. Nothing at this layer
//! can catch it, so anything a caller can do to make those panic has to be
//! rejected before the call: see [`checked_len`] and [`checked_tunnel`].
//!
//! The closure's outcome is resolved with [`LogErrorAndDefault`], which logs
//! and returns `Default::default()` -- a null handle or `0`.
//! `ThrowRuntimeExAndDefault` would raise a Java `RuntimeException` on every
//! error path instead, which no current caller is written to catch; making
//! errors throw is a change to the Java contract and belongs with the Android
//! work rather than with a dependency bump.
//!
//! That is *not* the whole contract, though, and the difference cost a
//! regression here before review caught it. Three entry points take a `byte[]`
//! key, and under 0.19 a wrong-length array did reach Java as an
//! `ArrayIndexOutOfBoundsException` -- not because the code threw it, but
//! because `check_exception!` returned `Err` without clearing the JVM's pending
//! exception. 0.22 catches and clears it, so `LogErrorAndDefault` alone would
//! have turned a thrown exception into a silent `null`. [`read_key_region`]
//! re-throws it. See its comment.

use std::ffi::CStr;

use jni::errors::LogErrorAndDefault;
use jni::objects::{JByteArray, JByteBuffer, JClass, JString};
use jni::sys::{jint, jlong, jshort};
use jni::{jni_str, Env, EnvUnowned};
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

/// Read a 32-byte key out of a Java byte array, preserving the Java-visible
/// failure contract.
///
/// This is not a convenience wrapper. jni 0.19's `get_byte_array_region` went
/// through `check_exception!`, which returns `Err` *without* calling
/// `ExceptionClear` -- so a short array left the JVM's
/// `ArrayIndexOutOfBoundsException` pending, and the Java caller saw it thrown.
/// 0.22's `get_region` uses `jni_call_with_catch!`, which catches that
/// exception, clears it, and hands back `Error::IndexOutOfBounds`. Combined
/// with `LogErrorAndDefault` the exception would vanish and Java would silently
/// receive null -- a caller passing a 31-byte key would get no diagnostic at
/// all. Re-throwing restores what Java used to observe.
fn read_key_region<'local>(
    env: &mut Env<'local>,
    array: &JByteArray<'local>,
) -> jni::errors::Result<[u8; 32]> {
    // Checked before `get_region`, which would otherwise report a null array as
    // an out-of-bounds one -- the wrong diagnostic for the wrong mistake.
    if array.is_null() {
        let _ = env.throw_new(
            jni_str!("java/lang/NullPointerException"),
            jni_str!("key must not be null"),
        );
        return Err(jni::errors::Error::NullPtr("key array"));
    }

    let mut buf = [0i8; 32];
    match array.get_region(env, 0, &mut buf) {
        // `as u8` per element rather than a `transmute` of the whole array:
        // same bytes, no `unsafe`.
        Ok(()) => Ok(buf.map(|b| b as u8)),
        Err(e) => {
            // 0.22 has already cleared the JVM's exception, so throwing here
            // cannot collide with a pending one.
            let _ = env.throw_new(
                jni_str!("java/lang/ArrayIndexOutOfBoundsException"),
                jni_str!("key must be 32 bytes"),
            );
            Err(e)
        }
    }
}

/// A caller-supplied length, checked against the buffer it actually indexes.
///
/// `jint` is signed and these values come straight from Java, while the FFI
/// layer builds `slice::from_raw_parts(ptr, size as usize)` out of them
/// (`ffi::wireguard_write` and friends). So `-1` becomes a slice of about four
/// billion bytes, and a length merely *larger than the array* is just as bad:
/// `encapsulate` copies the whole claimed range into the packet it seals, so
/// adjacent heap goes out over the wire encrypted. Neither is exotic -- passing
/// an MTU where the filled length was wanted is an ordinary mistake.
///
/// Throws `IllegalArgumentException`, because this is the caller's error and a
/// silent `0` would leave them guessing.
fn checked_len(
    env: &mut Env<'_>,
    size: jint,
    capacity: usize,
    what: &'static jni::strings::JNIStr,
) -> jni::errors::Result<u32> {
    if size < 0 || size as usize > capacity {
        let _ = env.throw_new(jni_str!("java/lang/IllegalArgumentException"), what);
        // An exception is now pending, which is exactly what this variant means.
        return Err(jni::errors::Error::JavaException);
    }
    Ok(size as u32)
}

/// A caller-supplied tunnel handle, checked before it crosses the FFI boundary.
///
/// `create_new_tunnel` hands back `0` when creation fails, so a caller who does
/// not check its return value arrives here with `0` -- an ordinary mistake, not
/// a hostile one. `ffi::wireguard_write` and its siblings open with
/// `tunnel.as_ref().unwrap()`, and because they are `extern "C"` that panic
/// cannot unwind back to `with_env`: the process aborts, taking the JVM with it.
///
/// The check is on the *pointer*, after the cast, not on the `jlong`. On a
/// 32-bit target -- this crate builds `i686-pc-windows-msvc` -- the cast
/// truncates, so `0x1_0000_0000` is a nonzero handle that becomes a null
/// pointer. Nothing rejects a negative handle: a pointer widened to `jlong` is
/// never negative on the targets built here, so `< 0` would risk rejecting
/// something valid without catching anything `is_null` misses.
///
/// This does not make the entry points panic-free. A `dst` buffer that is legal
/// per [`checked_len`] but too small for what the tunnel is about to write still
/// reaches an unconditional `panic!` in `noise::session`, by the same route.
/// That one cannot be fixed from here and is not fixed here.
fn checked_tunnel(env: &mut Env<'_>, tunnel: jlong) -> jni::errors::Result<*const Mutex<Tunn>> {
    let ptr = tunnel as *const Mutex<Tunn>;
    if ptr.is_null() {
        let _ = env.throw_new(
            jni_str!("java/lang/IllegalArgumentException"),
            jni_str!("tunnel handle is not a tunnel; new_tunnel returns 0 on failure"),
        );
        return Err(jni::errors::Error::JavaException);
    }
    Ok(ptr)
}

/// The address *and* capacity of a direct buffer.
///
/// 0.19's `get_direct_buffer_address` returned a `&mut [u8]` built from
/// `get_direct_buffer_capacity`, so the bound travelled with the pointer and
/// the old code threw it away with `.as_mut_ptr()`. 0.22 returns a bare
/// pointer, so the capacity has to be asked for separately -- and it must be,
/// or nothing here knows how big the buffer is.
fn direct_buffer<'local>(
    env: &mut Env<'local>,
    buf: &JByteBuffer<'local>,
) -> jni::errors::Result<(*mut u8, usize)> {
    let ptr = env.get_direct_buffer_address(buf)?;
    let capacity = env.get_direct_buffer_capacity(buf)?;
    Ok((ptr, capacity))
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
        let secret_key = x25519_key {
            key: read_key_region(env, &arg_secret_key)?,
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
        let x25519_key = x25519_key {
            key: read_key_region(env, &arg_key)?,
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
        let x25519_key = x25519_key {
            key: read_key_region(env, &arg_key)?,
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
        let tunnel = checked_tunnel(env, tunnel)?;
        let (dst_ptr, dst_cap) = direct_buffer(env, &dst)?;
        let (op_ptr, op_cap) = direct_buffer(env, &op)?;

        // Bound to a local: the pointer must not outlive the Vec that owns it.
        let mut src_bytes = env.convert_byte_array(&src)?;

        let src_len = checked_len(
            env,
            src_size,
            src_bytes.len(),
            jni_str!("src_size is negative or larger than the source array"),
        )?;
        let dst_len = checked_len(
            env,
            dst_size,
            dst_cap,
            jni_str!("dst_size is negative or larger than the destination buffer"),
        )?;
        // One byte is written to `op` below; a zero-capacity direct buffer is
        // non-null, so the null check alone would not catch it.
        checked_len(env, 1, op_cap, jni_str!("the op buffer must hold one byte"))?;

        let output: wireguard_result =
            unsafe { wireguard_write(tunnel, src_bytes.as_mut_ptr(), src_len, dst_ptr, dst_len) };
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
        let tunnel = checked_tunnel(env, tunnel)?;
        let (dst_ptr, dst_cap) = direct_buffer(env, &dst)?;
        let (op_ptr, op_cap) = direct_buffer(env, &op)?;

        // Bound to a local: the pointer must not outlive the Vec that owns it.
        let mut src_bytes = env.convert_byte_array(&src)?;

        let src_len = checked_len(
            env,
            src_size,
            src_bytes.len(),
            jni_str!("src_size is negative or larger than the source array"),
        )?;
        let dst_len = checked_len(
            env,
            dst_size,
            dst_cap,
            jni_str!("dst_size is negative or larger than the destination buffer"),
        )?;
        // One byte is written to `op` below; a zero-capacity direct buffer is
        // non-null, so the null check alone would not catch it.
        checked_len(env, 1, op_cap, jni_str!("the op buffer must hold one byte"))?;

        let output: wireguard_result =
            unsafe { wireguard_read(tunnel, src_bytes.as_mut_ptr(), src_len, dst_ptr, dst_len) };
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
        let tunnel = checked_tunnel(env, tunnel)?;
        let (dst_ptr, dst_cap) = direct_buffer(env, &dst)?;
        let (op_ptr, op_cap) = direct_buffer(env, &op)?;

        let dst_len = checked_len(
            env,
            dst_size,
            dst_cap,
            jni_str!("dst_size is negative or larger than the destination buffer"),
        )?;
        checked_len(env, 1, op_cap, jni_str!("the op buffer must hold one byte"))?;

        let output: wireguard_result = unsafe { wireguard_tick(tunnel, dst_ptr, dst_len) };

        unsafe { *op_ptr = output.op as u8 };

        Ok(output.size as jint)
    })
    .resolve::<LogErrorAndDefault>()
}
