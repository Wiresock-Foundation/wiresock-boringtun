// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Simple implementation of the client-side of the WireGuard protocol.
//!
//! <code>git clone https://github.com/cloudflare/boringtun.git</code>

#[cfg(feature = "device")]
pub mod device;

#[cfg(feature = "ffi-bindings")]
pub mod ffi;
#[cfg(feature = "jni-bindings")]
pub mod jni;
pub mod noise;

#[cfg(not(feature = "mock-instant"))]
pub(crate) mod sleepyinstant;

pub(crate) mod serialization;

/// Serializes the tests that swap the thread-local tracing dispatcher.
///
/// Every test that captures log output does it through
/// `tracing::subscriber::with_default`, and entering or leaving that guard
/// rebuilds tracing's *global* callsite-interest cache. Two such tests running
/// concurrently open a transient window in which a `warn!` callsite is cached
/// as not-interested while the other thread's event fires -- the event is
/// silently dropped, and the capturing test fails claiming nothing was logged.
/// Observed exactly once, on macOS CI under `--features jni-bindings`, where
/// scheduling happened to overlap two of these tests; five Linux runs of the
/// same combination never reproduced it, which is what "transient window"
/// means in practice.
///
/// So every `with_default` test takes this lock first. Serializing them closes
/// the window without touching what any of them asserts; the cost is that a
/// handful of sub-millisecond tests no longer run in parallel.
///
/// The gate lists the features whose test modules hold capture tests -- every
/// caller lives behind one of them, so in a bare `cargo test` this would be
/// the dead code the crate gates against elsewhere.
#[cfg(all(
    test,
    any(feature = "device", feature = "ffi-bindings", feature = "mock-instant")
))]
pub(crate) fn tracing_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // A poisoned lock means an earlier test panicked while holding it, which
    // has no bearing on the dispatcher state this lock exists to serialize.
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}
