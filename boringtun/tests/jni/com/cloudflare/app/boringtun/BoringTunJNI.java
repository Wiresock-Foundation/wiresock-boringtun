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

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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

    /** `result_type` in src/ffi/mod.rs. */
    private static final byte WIREGUARD_DONE = 0;
    private static final byte WRITE_TO_NETWORK = 1;
    private static final byte WIREGUARD_ERROR = 2;
    private static final byte WRITE_TO_TUNNEL_IPV4 = 4;
    private static final byte WRITE_TO_TUNNEL_IPV6 = 6;

    /**
     * A value no `result_type` can hold, written into the op buffer before every
     * call. `LogErrorAndDefault` returns 0 when the native body fails, and 0 is a
     * legal size *and* a legal op code, so the return value alone cannot
     * distinguish "worked" from "failed silently". Whether this byte survived can.
     */
    private static final byte OP_SENTINEL = 0x7f;

    private static void armOp(ByteBuffer op) {
        op.put(0, OP_SENTINEL);
    }

    private static byte opOf(ByteBuffer op) {
        return op.get(0);
    }

    private static boolean isRealOp(byte op) {
        return op == WIREGUARD_DONE || op == WRITE_TO_NETWORK || op == WIREGUARD_ERROR
            || op == WRITE_TO_TUNNEL_IPV4 || op == WRITE_TO_TUNNEL_IPV6;
    }

    /** The first {@code n} bytes of a direct buffer, without disturbing its position. */
    private static byte[] taken(ByteBuffer b, int n) {
        byte[] out = new byte[n];
        ByteBuffer view = b.duplicate();
        view.position(0);
        view.get(out);
        return out;
    }

    /**
     * A well-formed IPv4 packet of exactly {@code totalLen} bytes.
     *
     * boringtun's decapsulate reads the version nibble and the total-length field
     * and hands back {@code &packet[..len]}, so the length written here has to be
     * the real one for the round trip to compare equal.
     */
    private static byte[] ipv4Packet(int totalLen) {
        byte[] p = new byte[totalLen];
        p[0] = 0x45;                                  // IPv4, IHL 5
        p[2] = (byte) (totalLen >> 8);
        p[3] = (byte) totalLen;
        p[8] = 64;                                    // TTL
        p[9] = 17;                                    // UDP
        p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 1;  // 10.0.0.1
        p[16] = 10; p[17] = 0; p[18] = 0; p[19] = 2;  // 10.0.0.2
        for (int i = 20; i < totalLen; i++) {
            p[i] = (byte) (i * 31);                   // recognisable body
        }
        return p;
    }

    public static void main(String[] args) {
        if (args.length > 0 && "nullhandle".equals(args[0])) {
            nullHandleChild();
            return;
        }

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

        check(new_tunnel("not-a-key", peerB64, null, (short) 25, 4) == 0,
              "new_tunnel with a malformed key returns 0");

        // Exercise the three UTF-8 arrays that create_new_tunnel used to leak.
        //
        // A *malformed* secret key is used deliberately. All three MUTF8Chars
        // guards are acquired before new_tunnel is reached, so the acquire and
        // release path is covered either way -- but a malformed key returns 0
        // without allocating. Looping on valid keys would leak 1000 Tunn
        // objects (ffi/mod.rs hands them out via Box::into_raw, and the JNI
        // surface exposes no tunnel_free), which is a far larger leak than the
        // one this loop exists to make visible.
        for (int i = 0; i < 1000; i++) {
            if (new_tunnel("not-a-key", peerB64, KNOWN_B64, (short) 25, 2) != 0) {
                check(false, "a malformed key must never produce a tunnel");
                break;
            }
        }
        check(new_tunnel(secretB64, peerB64, null, (short) 25, 3) != 0,
              "new_tunnel still works after 1000 guard acquire/release cycles");

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

        armOp(opBuf);
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

        // Every rejection above must short-circuit *before* the FFI call and its
        // trailing `op` write. Throwing afterwards would still pass the seven
        // checks above while having already done the unsafe thing.
        check(opOf(opBuf) == OP_SENTINEL,
              "a rejected call never reaches the op write");

        System.out.println("== the success path must actually reach the FFI ==");
        // Everything above returns from checked_len before the migrated FFI calls
        // are reached, so on its own it would stay green through a regression in
        // wireguard_write/read/tick themselves -- including src_bytes being
        // dropped before its pointer is used. Two tunnels are handshaked against
        // each other here and a packet is carried A->B, so the bytes are the
        // proof; the return code cannot be, because 0 means both "empty" and
        // "the native body failed and LogErrorAndDefault swallowed it".

        armOp(opBuf);
        int tickN = wireguard_tick(tunnel, dstBuf, 2048, opBuf);
        check(opOf(opBuf) != OP_SENTINEL, "wireguard_tick reaches the op write");
        check(isRealOp(opOf(opBuf)),
              "wireguard_tick reports a real result_type"
                  + " (op " + opOf(opBuf) + ", size " + tickN + ")");

        byte[] secretA = x25519_secret_key();
        byte[] secretB = x25519_secret_key();
        long tunA = new_tunnel(x25519_key_to_base64(secretA),
                               x25519_key_to_base64(x25519_public_key(secretB)),
                               null, (short) 0, 10);
        long tunB = new_tunnel(x25519_key_to_base64(secretB),
                               x25519_key_to_base64(x25519_public_key(secretA)),
                               null, (short) 0, 11);
        check(tunA != 0 && tunB != 0, "two mutually-configured peer tunnels were created");

        ByteBuffer netA = ByteBuffer.allocateDirect(2048);
        ByteBuffer netB = ByteBuffer.allocateDirect(2048);
        ByteBuffer opA = ByteBuffer.allocateDirect(1);
        ByteBuffer opB = ByteBuffer.allocateDirect(1);
        byte[] payload = ipv4Packet(64);

        // A has no session, so this queues the packet and emits a handshake init.
        armOp(opA);
        int n1 = wireguard_write(tunA, payload, payload.length, netA, netA.capacity(), opA);
        check(opOf(opA) == WRITE_TO_NETWORK,
              "wireguard_write on a fresh tunnel asks for a handshake initiation");
        check(n1 == 148, "the initiation is 148 bytes (got " + n1 + ")");
        check(taken(netA, 1)[0] == 1, "the initiation carries WireGuard message type 1");

        // B answers it.
        armOp(opB);
        int n2 = wireguard_read(tunB, taken(netA, n1), n1, netB, netB.capacity(), opB);
        check(opOf(opB) == WRITE_TO_NETWORK,
              "wireguard_read turns the initiation into a response");
        check(n2 == 92, "the response is 92 bytes (got " + n2 + ")");
        check(taken(netB, 1)[0] == 2, "the response carries WireGuard message type 2");

        // A consumes the response; the session is now up on both sides.
        armOp(opA);
        int n3 = wireguard_read(tunA, taken(netB, n2), n2, netA, netA.capacity(), opA);
        check(opOf(opA) != OP_SENTINEL,
              "wireguard_read reaches the op write on the handshake-response path");

        // Now carry the payload. Whatever A has to send goes to B until B hands
        // a tunnel packet back. Equality with `payload` is the assertion that
        // matters: nothing else in this file would notice src being read from
        // freed memory, because a wrong pointer still produces *some* ciphertext.
        boolean roundTripped = false;
        byte[] inFlight = (opOf(opA) == WRITE_TO_NETWORK && n3 > 0) ? taken(netA, n3) : null;
        for (int round = 0; round < 4 && !roundTripped; round++) {
            if (inFlight == null) {
                armOp(opA);
                int m = wireguard_write(tunA, payload, payload.length, netA, netA.capacity(), opA);
                if (opOf(opA) != WRITE_TO_NETWORK || m <= 0) {
                    break;
                }
                inFlight = taken(netA, m);
            }
            armOp(opB);
            int got = wireguard_read(tunB, inFlight, inFlight.length, netB, netB.capacity(), opB);
            inFlight = null;
            if (opOf(opB) == WRITE_TO_TUNNEL_IPV4 && got > 0) {
                roundTripped = java.util.Arrays.equals(payload, taken(netB, got));
            }
        }
        check(roundTripped, "a packet written by A arrives at B byte-for-byte identical");

        System.out.println("== a zero tunnel handle must not kill the JVM ==");
        check(nullHandleChildSurvives(),
              "a zero tunnel handle throws instead of aborting the process");

        System.out.println();
        if (failures == 0) {
            System.out.println("ALL JNI SMOKE CHECKS PASSED");
        } else {
            System.out.println(failures + " JNI SMOKE CHECK(S) FAILED");
            System.exit(1);
        }
    }

    /**
     * The zero-handle checks, run in a JVM of their own.
     *
     * They cannot run inline. `create_new_tunnel` returns 0 when creation fails,
     * and an unguarded 0 reaches `tunnel.as_ref().unwrap()` inside
     * `ffi::wireguard_write` -- an `extern "C"` function, so the panic cannot
     * unwind back to `with_env` and the process aborts. Inline, that would not
     * fail this check; it would delete the harness mid-run, and every check
     * after it, and report an exit code indistinguishable from a build problem.
     *
     * A child process turns process death back into an observable value. It also
     * keeps the guard mutation-testable: remove the check in jni.rs and the child
     * dies, the parent sees a nonzero exit, and this reports FAIL like anything
     * else.
     */
    private static void nullHandleChild() {
        ByteBuffer dst = ByteBuffer.allocateDirect(2048);
        ByteBuffer op = ByteBuffer.allocateDirect(1);
        byte[] src = ipv4Packet(64);

        int rejected = 0;
        if (throwsIAE(() -> wireguard_write(0L, src, src.length, dst, 2048, op))) rejected++;
        if (throwsIAE(() -> wireguard_read(0L, src, src.length, dst, 2048, op))) rejected++;
        if (throwsIAE(() -> wireguard_tick(0L, dst, 2048, op))) rejected++;

        // Reaching this line at all is most of the point.
        if (rejected == 3) {
            System.out.println("NULL_HANDLE_REJECTED");
        }
    }

    private static boolean nullHandleChildSurvives() {
        try {
            String java = System.getProperty("java.home")
                + File.separator + "bin" + File.separator + "java";
            ProcessBuilder pb = new ProcessBuilder(
                java,
                "-Djava.library.path=" + System.getProperty("java.library.path"),
                "-cp", System.getProperty("java.class.path"),
                BoringTunJNI.class.getName(),
                "nullhandle");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int code = p.waitFor();
            if (code == 0 && out.contains("NULL_HANDLE_REJECTED")) {
                return true;
            }
            System.out.println("        (child exited " + code + "; output: "
                + out.trim().replace('\n', '|') + ")");
            return false;
        } catch (Exception e) {
            System.out.println("        (could not run the child JVM: " + e + ")");
            return false;
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
    ///
    /// The comparison is on the exact runtime class rather than `isInstance`,
    /// which would accept a subclass: NumberFormatException is-an
    /// IllegalArgumentException, so `isInstance` would let a regression that
    /// throws a related-but-wrong type pass a check named `throwsExactly`. What
    /// is being pinned here is the precise type Java callers see.
    private static boolean throwsExactly(Runnable r, Class<? extends Throwable> expected) {
        try {
            r.run();
            System.out.println("        (returned normally, threw nothing)");
            return false;
        } catch (Throwable t) {
            if (t.getClass() == expected) {
                return true;
            }
            System.out.println("        (threw " + t.getClass().getName() + " instead)");
            return false;
        }
    }
}
