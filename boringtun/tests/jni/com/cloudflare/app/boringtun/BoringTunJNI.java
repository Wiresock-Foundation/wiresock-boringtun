// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// A smoke test for the JNI bindings, run against a real JVM.
//
// src/jni.rs has no Rust test coverage and cannot have any: its entry points
// take a `JNIEnv` and are only reachable through JNI dispatch. `cargo test`
// therefore proves that the bindings compile and nothing else, which is how a
// migration to jni 0.22 silently turned a thrown ArrayIndexOutOfBoundsException
// into a null return -- caught in review, by hand, with a harness like this one.
// This is that harness, kept.
//
// The package must be `com.cloudflare.app.boringtun` because that is what the
// `#[export_name]` attributes in src/jni.rs spell. If those exports are ever
// renamed for WireSock, this file moves with them -- and fails loudly first,
// which is the intended coupling.

package com.cloudflare.app.boringtun;

import java.nio.ByteBuffer;
import java.util.HexFormat;

public class BoringTunJNI {
    static { System.loadLibrary("boringtun"); }

    public static native byte[] x25519_secret_key();
    public static native byte[] x25519_public_key(byte[] secretKey);
    public static native String x25519_key_to_hex(byte[] key);
    public static native String x25519_key_to_base64(byte[] key);
    public static native long new_tunnel(
        String secretKey, String publicKey, String presharedKey, short keepAlive, int index);
    public static native int wireguard_write(
        long tunnel, byte[] src, int srcSize, ByteBuffer dst, int dstSize, ByteBuffer op);
    public static native int wireguard_read(
        long tunnel, byte[] src, int srcSize, ByteBuffer dst, int dstSize, ByteBuffer op);
    public static native int wireguard_tick(
        long tunnel, ByteBuffer dst, int dstSize, ByteBuffer op);

    private static int failures = 0;

    private static void check(boolean ok, String what) {
        if (ok) {
            System.out.println("  PASS  " + what);
        } else {
            System.out.println("  FAIL  " + what);
            failures++;
        }
    }

    /** The bytes of a key whose hex and base64 forms are known, so encoding is pinned. */
    private static final byte[] KNOWN = new byte[32];
    static { for (int i = 0; i < 32; i++) KNOWN[i] = (byte) 0xab; }
    private static final String KNOWN_HEX =
        "abababababababababababababababababababababababababababababababab";
    private static final String KNOWN_B64 =
        "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=";

    public static void main(String[] args) {
        System.out.println("== key generation ==");
        byte[] secret = x25519_secret_key();
        check(secret != null && secret.length == 32, "x25519_secret_key returns 32 bytes");

        byte[] pub = x25519_public_key(secret);
        check(pub != null && pub.length == 32, "x25519_public_key returns 32 bytes");
        check(java.util.Arrays.equals(pub, x25519_public_key(secret)),
              "x25519_public_key is deterministic for one secret");

        System.out.println("== encoding ==");
        // Pins the alphabet and padding, not merely the length: a switch to the
        // URL-safe alphabet or to NO_PAD would still produce a 44-char string.
        check(KNOWN_HEX.equals(x25519_key_to_hex(KNOWN)),
              "x25519_key_to_hex matches the known vector");
        check(KNOWN_B64.equals(x25519_key_to_base64(KNOWN)),
              "x25519_key_to_base64 matches the known vector");

        // Called repeatedly because both of these used to leak the C string they
        // were handed; a leak will not fail here, but it gives a leak checker
        // something to observe.
        for (int i = 0; i < 1000; i++) {
            x25519_key_to_hex(KNOWN);
            x25519_key_to_base64(KNOWN);
        }
        check(KNOWN_HEX.equals(x25519_key_to_hex(KNOWN)),
              "x25519_key_to_hex still correct after 1000 calls");

        System.out.println("== a wrong-length key must THROW, not return null ==");
        // This is the regression the jni 0.22 migration introduced and review
        // caught. 0.19 left the JVM's exception pending so Java saw it; 0.22
        // catches and clears it, so without an explicit re-throw the caller gets
        // a silent null. Each of the three entry points that read a byte[] key.
        check(throwsAIOOBE(() -> x25519_public_key(new byte[16])),
              "x25519_public_key(byte[16]) throws ArrayIndexOutOfBoundsException");
        check(throwsAIOOBE(() -> x25519_key_to_hex(new byte[16])),
              "x25519_key_to_hex(byte[16]) throws ArrayIndexOutOfBoundsException");
        check(throwsAIOOBE(() -> x25519_key_to_base64(new byte[16])),
              "x25519_key_to_base64(byte[16]) throws ArrayIndexOutOfBoundsException");

        System.out.println("== tunnel creation ==");
        String secretB64 = x25519_key_to_base64(secret);
        String peerB64 = x25519_key_to_base64(x25519_public_key(x25519_secret_key()));

        long tunnel = new_tunnel(secretB64, peerB64, null, (short) 25, 0);
        check(tunnel != 0, "new_tunnel with a null preshared key returns a handle");

        long tunnel2 = new_tunnel(secretB64, peerB64, KNOWN_B64, (short) 25, 1);
        check(tunnel2 != 0, "new_tunnel with a preshared key returns a handle");

        // The three UTF-8 arrays this used to leak per call.
        for (int i = 0; i < 1000; i++) {
            new_tunnel(secretB64, peerB64, KNOWN_B64, (short) 25, 2);
        }
        check(new_tunnel(secretB64, peerB64, null, (short) 25, 3) != 0,
              "new_tunnel still works after 1000 calls");

        check(new_tunnel("not-a-key", peerB64, null, (short) 25, 4) == 0,
              "new_tunnel with a malformed key returns 0");

        System.out.println("== a null key must be an NPE, not an index error ==");
        check(throwsNPE(() -> x25519_public_key(null)),
              "x25519_public_key(null) throws NullPointerException");

        System.out.println("== caller-supplied lengths must be rejected, not trusted ==");
        // These lengths reach slice::from_raw_parts in the FFI layer. Before
        // validation, a negative wrapped to ~4 GiB and an oversized one copied
        // adjacent heap into the sealed packet.
        ByteBuffer dstBuf = ByteBuffer.allocateDirect(2048);
        ByteBuffer opBuf = ByteBuffer.allocateDirect(4);
        byte[] small = new byte[64];

        check(throwsIAE(() -> wireguard_write(tunnel, small, -1, dstBuf, 2048, opBuf)),
              "wireguard_write rejects a negative src_size");
        check(throwsIAE(() -> wireguard_write(tunnel, small, 1500, dstBuf, 2048, opBuf)),
              "wireguard_write rejects src_size larger than the array");
        check(throwsIAE(() -> wireguard_write(tunnel, small, 64, dstBuf, -1, opBuf)),
              "wireguard_write rejects a negative dst_size");
        check(throwsIAE(() -> wireguard_write(tunnel, small, 64, dstBuf, 99999, opBuf)),
              "wireguard_write rejects dst_size larger than the buffer");
        check(throwsIAE(() -> wireguard_read(tunnel, small, 1500, dstBuf, 2048, opBuf)),
              "wireguard_read rejects src_size larger than the array");
        check(throwsIAE(() -> wireguard_tick(tunnel, dstBuf, -1, opBuf)),
              "wireguard_tick rejects a negative dst_size");

        // A zero-capacity direct buffer is non-null, so a null check alone would
        // let the one-byte `op` write run off the end.
        ByteBuffer emptyOp = ByteBuffer.allocateDirect(0);
        check(throwsIAE(() -> wireguard_tick(tunnel, dstBuf, 2048, emptyOp)),
              "wireguard_tick rejects a zero-capacity op buffer");

        // ... and a well-formed call must still be accepted.
        check(wireguard_tick(tunnel, dstBuf, 2048, opBuf) >= 0,
              "wireguard_tick accepts valid sizes");

        System.out.println();
        if (failures == 0) {
            System.out.println("ALL JNI SMOKE CHECKS PASSED");
        } else {
            System.out.println(failures + " JNI SMOKE CHECK(S) FAILED");
            System.exit(1);
        }
    }

    private static boolean throwsAIOOBE(Runnable r) {
        return throwsExactly(r, ArrayIndexOutOfBoundsException.class);
    }

    private static boolean throwsNPE(Runnable r) {
        return throwsExactly(r, NullPointerException.class);
    }

    private static boolean throwsIAE(Runnable r) {
        return throwsExactly(r, IllegalArgumentException.class);
    }

    /// Returns false, loudly, when nothing was thrown or the wrong type was --
    /// a silent return is precisely the failure these checks exist to catch.
    private static boolean throwsExactly(Runnable r, Class<? extends Throwable> expected) {
        try {
            r.run();
            System.out.println("        (returned normally, threw nothing)");
            return false;
        } catch (Throwable t) {
            if (expected.isInstance(t)) {
                return true;
            }
            System.out.println("        (threw " + t.getClass().getName() + " instead)");
            return false;
        }
    }
}
