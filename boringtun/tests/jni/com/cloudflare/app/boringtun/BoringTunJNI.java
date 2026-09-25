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
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class BoringTunJNI {
    static { System.loadLibrary("boringtun"); }

    public static native byte[] x25519_secret_key();
    public static native byte[] x25519_public_key(byte[] secretKey);
    public static native String x25519_key_to_hex(byte[] key);
    public static native String x25519_key_to_base64(byte[] key);
    public static native long new_tunnel(
        String secretKey, String publicKey, String presharedKey, short keepAlive, int index);
    public static native long new_tunnel_with_awg_params(
        String secretKey, String publicKey, String presharedKey, short keepAlive, int index,
        byte[] awgParams, String imitationDomain);
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

    /** `DATA_OVERHEAD_SZ` in src/noise/mod.rs: 16 bytes of header plus a 16-byte AEAD tag. */
    private static final int DATA_OVERHEAD_SZ = 32;

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
        if (args.length > 0 && "fatal-inputs".equals(args[0])) {
            fatalInputChild();
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

        awgParamsChecks();

        System.out.println("== inputs that used to kill the JVM ==");
        check(fatalInputChildSurvives(),
              "a zero handle, a too-small dst, and an awgParams array shorter than its size"
                  + " are errors, not process death");

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
    private static void fatalInputChild() {
        ByteBuffer dst = ByteBuffer.allocateDirect(2048);
        ByteBuffer op = ByteBuffer.allocateDirect(1);
        byte[] src = ipv4Packet(64);

        int survived = 0;

        // 1. A zero handle, rejected in jni.rs before the FFI call.
        if (throwsIAE(() -> wireguard_write(0L, src, src.length, dst, 2048, op))) survived++;
        if (throwsIAE(() -> wireguard_read(0L, src, src.length, dst, 2048, op))) survived++;
        if (throwsIAE(() -> wireguard_tick(0L, dst, 2048, op))) survived++;

        // 2. A dst too small for the packet the tunnel wants to write. These
        //    reach noise::session, which used to panic! -- and a panic inside
        //    an extern "C" callee aborts instead of unwinding, so these were
        //    process kills rather than errors. They must come back as
        //    WIREGUARD_ERROR now.
        //
        //    The update_timers keepalive case from the same family is covered
        //    in noise/mod.rs instead: reaching it needs a persistent keepalive
        //    to fall due, which is deterministic under mock-instant and a real
        //    1s sleep here.
        ByteBuffer netA = ByteBuffer.allocateDirect(2048);
        ByteBuffer netB = ByteBuffer.allocateDirect(2048);
        ByteBuffer opA = ByteBuffer.allocateDirect(1);
        ByteBuffer tiny = ByteBuffer.allocateDirect(64);

        // A handshake response into a dst one byte short of the 32-byte
        // keepalive the response path emits. A fresh pair, because this leaves
        // the initiator without a stored session.
        long[] pair = peerPair(30);
        int n = wireguard_write(pair[0], src, src.length, netA, netA.capacity(), opA);
        int n2 = wireguard_read(pair[1], taken(netA, n), n, netB, netB.capacity(), opA);
        armOp(opA);
        wireguard_read(pair[0], taken(netB, n2), n2, tiny, DATA_OVERHEAD_SZ - 1, opA);
        if (opOf(opA) == WIREGUARD_ERROR) survived++;

        // Now a completed handshake, and the two established-session cases.
        pair = peerPair(32);
        n = wireguard_write(pair[0], src, src.length, netA, netA.capacity(), opA);
        n2 = wireguard_read(pair[1], taken(netA, n), n, netB, netB.capacity(), opA);
        wireguard_read(pair[0], taken(netB, n2), n2, netA, netA.capacity(), opA);

        // Sending at the tunnel MTU: 1420 bytes of payload needs 1452.
        ByteBuffer mtu = ByteBuffer.allocateDirect(1420);
        armOp(opA);
        wireguard_write(pair[0], new byte[1420], 1420, mtu, 1420, opA);
        if (opOf(opA) == WIREGUARD_ERROR) survived++;

        // Receiving into a dst sized for the plaintext rather than the frame.
        armOp(opA);
        int m = wireguard_write(pair[0], src, src.length, netA, netA.capacity(), opA);
        if (opOf(opA) == WRITE_TO_NETWORK && m > 0) {
            armOp(opA);
            wireguard_read(pair[1], taken(netA, m), m, tiny, src.length, opA);
            if (opOf(opA) == WIREGUARD_ERROR) survived++;
        }

        // 3. An awgParams array shorter than the 4-byte size field, or than the
        //    size it declares. jni.rs must throw before the FFI call: the C
        //    constructor trusts `size` as the length of the caller's
        //    allocation, so an unguarded call reads past the copied array.
        String sa = x25519_key_to_base64(x25519_secret_key());
        String pb = x25519_key_to_base64(x25519_public_key(x25519_secret_key()));
        byte[][] short_ = {
            new byte[0],
            new byte[3],
            awg31Profile(1).image(AwgParams.SIZE_V2, 100),
            awg31Profile(1).image(AwgParams.SIZE_V2 + 1, AwgParams.SIZE_V2),
            awg31Profile(1).image(0xffffffffL, AwgParams.SIZE_V2),
            awg31Profile(1).image(1000, 999),
        };
        String[] what = {
            "an empty array", "a 3-byte array", "size 168 in 100 bytes",
            "size 169 in 168 bytes", "size 0xffffffff in 168 bytes", "size 1000 in 999 bytes",
        };
        int awgSurvived = 0;
        for (int i = 0; i < short_.length; i++) {
            byte[] params = short_[i];
            if (throwsIAE(() -> awgTunnel(sa, pb, params, null, 34))) {
                awgSurvived++;
            } else {
                System.out.println("awgParams " + what[i] + " did not throw IllegalArgumentException");
            }
        }

        // Reaching this line at all is most of the point.
        if (survived == 6 && awgSurvived == short_.length) {
            System.out.println("FATAL_INPUTS_SURVIVED");
        } else {
            System.out.println("only " + survived + " of 6 and " + awgSurvived + " of "
                + short_.length + " awgParams cases survived");
        }
    }

    /**
     * {@code struct wireguard_awg_params}, as the native byte image
     * {@code new_tunnel_with_awg_params} reads -- a test helper, not API.
     *
     * Every offset below is the one boringtun/src/wireguard_ffi.h declares and
     * scripts/ffi-layout-check.c pins, kept in this one table. The byte order is
     * {@code ByteOrder.nativeOrder()} because the array IS the C struct, not a
     * second serialization of it; the shared corpus is little-endian, like every
     * target the library is built for.
     */
    static final class AwgParams {
        static final int SIZE_V0 = 160;   // the first published version
        static final int SIZE_V1 = 164;   // + random_trailers
        static final int SIZE_V2 = 168;   // + disable_cookies

        static final int SIZE = 0;
        static final int S1_INIT_JUNK = 4;
        static final int S2_RESPONSE_JUNK = 8;
        static final int S3_COOKIE_JUNK = 12;
        static final int S4_TRANSPORT_JUNK = 16;
        static final int JUNK_PACKET_COUNT = 20;
        static final int JUNK_PACKET_SIZE_MIN = 24;
        static final int JUNK_PACKET_SIZE_MAX = 28;
        static final int JUNK_PACKET_DELAY_MS = 32;
        static final int H1_INIT = 36;                // wireguard_awg_range: lo, hi
        static final int H2_RESP = 44;
        static final int H3_COOKIE = 52;
        static final int H4_DATA = 60;
        static final int IMITATION_PROTOCOL = 68;
        static final int IMITATION_BROWSER = 72;
        static final int CONTENT_PADDING_ADDITION = 76;
        static final int CONTENT_PADDING_MTU = 84;
        static final int REKEY_AFTER_TIME = 88;
        static final int REKEY_TIMEOUT = 96;
        static final int REJECT_AFTER_TIME = 104;
        static final int KEEPALIVE_TIMEOUT = 112;
        static final int MAX_HANDSHAKE_ATTEMPTS = 120;
        static final int HEADER_PROTECTION_KEY = 128; // uint8_t[32]
        static final int RANDOM_TRAILERS = 160;
        static final int DISABLE_COOKIES = 164;

        private final ByteBuffer b = ByteBuffer.allocate(SIZE_V2).order(ByteOrder.nativeOrder());

        AwgParams u32(int offset, long value) {
            b.putInt(offset, (int) value);
            return this;
        }

        AwgParams range(int offset, long lo, long hi) {
            return u32(offset, lo).u32(offset + 4, hi);
        }

        AwgParams key(byte[] key) {
            for (int i = 0; i < 32; i++) b.put(HEADER_PROTECTION_KEY + i, key[i]);
            return this;
        }

        /** The struct in an array of {@code arrayLen} bytes (zero past the struct), declaring {@code size}. */
        byte[] image(long size, int arrayLen) {
            byte[] out = Arrays.copyOf(b.array(), arrayLen);
            ByteBuffer.wrap(out).order(ByteOrder.nativeOrder()).putInt(SIZE, (int) size);
            return out;
        }

        byte[] image(int size) {
            return image(size, size);
        }
    }

    static final byte[] AWG_HP_KEY = new byte[32];
    static { for (int i = 0; i < 32; i++) AWG_HP_KEY[i] = (byte) (0x40 + i); }
    static final int S1 = 40, S2 = 36, S3 = 28, S4 = 20;
    static final long[][] H = {
        {100_000, 199_999}, {200_000, 299_999}, {300_000, 399_999}, {400_000, 499_999}};

    /** The AWG 3.1 profile the corpus's v2-full-awg31 case carries, with DisableCookies as given. */
    static AwgParams awg31Profile(long disableCookies) {
        return new AwgParams()
            .u32(AwgParams.S1_INIT_JUNK, S1)
            .u32(AwgParams.S2_RESPONSE_JUNK, S2)
            .u32(AwgParams.S3_COOKIE_JUNK, S3)
            .u32(AwgParams.S4_TRANSPORT_JUNK, S4)
            .range(AwgParams.H1_INIT, H[0][0], H[0][1])
            .range(AwgParams.H2_RESP, H[1][0], H[1][1])
            .range(AwgParams.H3_COOKIE, H[2][0], H[2][1])
            .range(AwgParams.H4_DATA, H[3][0], H[3][1])
            .range(AwgParams.CONTENT_PADDING_ADDITION, 8, 24)
            .u32(AwgParams.CONTENT_PADDING_MTU, 1420)
            .range(AwgParams.KEEPALIVE_TIMEOUT, 20, 25)
            .key(AWG_HP_KEY)
            .u32(AwgParams.RANDOM_TRAILERS, 1)
            .u32(AwgParams.DISABLE_COOKIES, disableCookies);
    }

    /**
     * The message-type tag an AmneziaWG receiver reads at {@code offset}: the
     * four bytes there, XORed with the first four bytes of the header-protection
     * keystream (ChaCha20, block 0, the datagram's first 12 bytes as nonce).
     * Computed with the JDK's own ChaCha20, independently of the library.
     */
    static long decodedTag(byte[] datagram, int offset) {
        try {
            Cipher c = Cipher.getInstance("ChaCha20");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(AWG_HP_KEY, "ChaCha20"),
                   new ChaCha20ParameterSpec(Arrays.copyOf(datagram, 12), 0));
            byte[] ks = c.doFinal(new byte[4]);
            long tag = 0;
            for (int i = 3; i >= 0; i--) {
                tag = (tag << 8) | ((datagram[offset + i] ^ ks[i]) & 0xff);
            }
            return tag;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static boolean tagIn(byte[] datagram, int offset, int kind) {
        long tag = decodedTag(datagram, offset);
        return tag >= H[kind][0] && tag <= H[kind][1];
    }

    private static long awgTunnel(String secret, String peer, byte[] params, String domain, int index) {
        return new_tunnel_with_awg_params(secret, peer, null, (short) 0, index, params, domain);
    }

    private static byte[] unhex(String s) {
        return HexFormat.of().parseHex(s);
    }

    /**
     * {@code new_tunnel_with_awg_params} over JNI: every published struct
     * version, the RandomTrailers/DisableCookies parsers, the params-array
     * marshalling guard, the corpus shared with the C door, and a real AWG 3.1
     * session between two JNI-built peers.
     */
    private static void awgParamsChecks() {
        String sa = x25519_key_to_base64(x25519_secret_key());
        byte[] sbRaw = x25519_secret_key();
        String pb = x25519_key_to_base64(x25519_public_key(sbRaw));

        System.out.println("== AWG params: every published struct version ==");
        // Each shorter version sits in a 168-byte array whose absent fields are
        // 0xffffffff -- a value both switches refuse -- so acceptance proves the
        // bytes past `size` were not read, i.e. the fields defaulted to off.
        byte[] v0 = awg31Profile(0xffffffffL).u32(AwgParams.RANDOM_TRAILERS, 0xffffffffL)
            .image(AwgParams.SIZE_V0, AwgParams.SIZE_V2);
        check(awgTunnel(sa, pb, v0, null, 40) != 0,
              "the 160-byte version is accepted, random_trailers and disable_cookies unread (off)");
        byte[] v1 = awg31Profile(0xffffffffL).image(AwgParams.SIZE_V1, AwgParams.SIZE_V2);
        check(awgTunnel(sa, pb, v1, null, 41) != 0,
              "the 164-byte version with random_trailers=1 is accepted, disable_cookies unread (off)");
        check(awgTunnel(sa, pb, awg31Profile(1).image(AwgParams.SIZE_V2), null, 42) != 0,
              "the 168-byte version with random_trailers=1, disable_cookies=1 is accepted");
        check(awgTunnel(sa, pb, null, null, 43) != 0,
              "null awgParams builds a plain WireGuard tunnel, as NULL params does in C");

        System.out.println("== AWG params: RandomTrailers and DisableCookies are 0 or 1 ==");
        for (long v : new long[] {0, 1}) {
            check(awgTunnel(sa, pb, awg31Profile(0).u32(AwgParams.RANDOM_TRAILERS, v)
                                        .image(AwgParams.SIZE_V2), null, 44) != 0,
                  "random_trailers=" + v + " is accepted");
            check(awgTunnel(sa, pb, awg31Profile(v).image(AwgParams.SIZE_V2), null, 45) != 0,
                  "disable_cookies=" + v + " is accepted");
        }
        check(awgTunnel(sa, pb, awg31Profile(0).u32(AwgParams.RANDOM_TRAILERS, 2)
                                    .image(AwgParams.SIZE_V2), null, 46) == 0,
              "random_trailers=2 is refused (0, not an exception)");
        check(awgTunnel(sa, pb, awg31Profile(2).image(AwgParams.SIZE_V2), null, 47) == 0,
              "disable_cookies=2 is refused (0, not an exception)");

        System.out.println("== AWG params: the array must hold what it declares ==");
        // Marshalling mistakes throw; everything the array can actually carry is
        // the library's to judge and comes back as 0. The arrays SHORTER than
        // their own `size` run in the fatal-inputs child below: without the
        // guard in jni.rs they are an out-of-bounds read inside an extern "C"
        // function, which kills the process rather than failing a check.
        check(awgTunnel(sa, pb, awg31Profile(1).image(1000, 1000), null, 49) != 0,
              "size 1000 in a 1000-byte array with a zero tail is a newer caller, accepted");
        check(awgTunnel(sa, pb, awg31Profile(1).image(1025, 1025), null, 50) == 0,
              "size 1025 is over the library's ceiling: refused with 0, not read");
        check(throwsIAE(() -> awgTunnel(sa, pb, null, "exa\u0000mple.com", 51)),
              "an imitation domain containing U+0000 throws IllegalArgumentException");
        // An unpaired surrogate has no UTF-8 form at all. A lossy conversion
        // would turn it into U+FFFD -- and, because modified UTF-8 spells U+0000
        // as C0 80, which is not valid UTF-8 either, turn a NUL beside it into
        // U+FFFD too, so the NUL check above would never see it.
        check(throwsIAE(() -> awgTunnel(sa, pb, null, "\uD800\u0000.example", 51)),
              "U+0000 next to an unpaired surrogate still throws IllegalArgumentException");
        check(throwsIAE(() -> awgTunnel(sa, pb, null, "\uD800.example", 51)),
              "an unpaired high surrogate throws IllegalArgumentException");
        check(throwsIAE(() -> awgTunnel(sa, pb, null, "example\uDC00", 51)),
              "an unpaired low surrogate throws IllegalArgumentException");
        check(throwsIAE(() -> awgTunnel(sa, pb, null, "\uDC00\uD800.example", 51)),
              "a reversed surrogate pair throws IllegalArgumentException");
        check(awgTunnel(sa, pb, null, "😀.example", 51) != 0,
              "a proper surrogate pair (U+1F600) is valid Unicode and is not a marshalling error");

        System.out.println("== AWG params: the JNI door reaches the C door's verdict on the shared corpus ==");
        String corpusPath = System.getProperty("awg.corpus");
        check(corpusPath != null, "the corpus path is passed in (-Dawg.corpus)");
        check(ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN,
              "this JVM is little-endian, like the corpus");
        if (corpusPath != null) {
            try {
                List<String> lines = Files.readAllLines(Path.of(corpusPath), StandardCharsets.UTF_8);
                int cases = 0, agreed = 0;
                byte[] full = null, rtOnly = null, base = null;
                for (String line : lines) {
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    String[] f = line.split(" ");
                    boolean accept = f[1].equals("accept");
                    String domain = f[2].equals("-") ? null
                        : new String(unhex(f[2].substring(2)), StandardCharsets.UTF_8);
                    byte[] image = f[3].equals("-") ? null : unhex(f[3]);
                    if (f[0].equals("v2-full-awg31")) full = image;
                    if (f[0].equals("v1-rt-only")) rtOnly = image;
                    if (f[0].equals("v0-base")) base = image;
                    long t = awgTunnel(sa, pb, image, domain, 60 + cases);
                    cases++;
                    if ((t != 0) == accept) {
                        agreed++;
                    } else {
                        System.out.println("        (" + f[0] + ": JNI " + (t != 0 ? "accepted" : "refused")
                            + ", the C door " + (accept ? "accepts" : "refuses") + ")");
                    }
                }
                check(cases == 22 && agreed == cases,
                      "all " + cases + " corpus cases reach the C door's verdict (" + agreed + " agreed)");
                // The corpus is generated from the Rust struct; the builder above
                // is hand-written from the header. Equal bytes pin the builder's
                // offsets to the real layout.
                check(Arrays.equals(full, awg31Profile(1).image(AwgParams.SIZE_V2)),
                      "the Java builder's 168-byte image equals the Rust struct's (v2-full-awg31)");
                check(Arrays.equals(rtOnly, awg31Profile(0).image(AwgParams.SIZE_V1)),
                      "the Java builder's 164-byte image equals the Rust struct's (v1-rt-only)");
                check(Arrays.equals(base, awg31Profile(0).u32(AwgParams.RANDOM_TRAILERS, 0)
                                                     .image(AwgParams.SIZE_V0)),
                      "the Java builder's 160-byte image equals the Rust struct's (v0-base)");
            } catch (java.io.IOException e) {
                check(false, "the corpus is readable (" + e + ")");
            }
        }

        System.out.println("== AWG 3.1 session between two JNI-built peers ==");
        byte[] secretA = x25519_secret_key();
        byte[] secretB = x25519_secret_key();
        String aSec = x25519_key_to_base64(secretA), aPub = x25519_key_to_base64(x25519_public_key(secretA));
        String bSec = x25519_key_to_base64(secretB), bPub = x25519_key_to_base64(x25519_public_key(secretB));
        // DisableCookies is local policy, so the two ends differ on purpose.
        long tunA = awgTunnel(aSec, bPub, awg31Profile(1).image(AwgParams.SIZE_V2), null, 90);
        long tunB = awgTunnel(bSec, aPub, awg31Profile(0).image(AwgParams.SIZE_V2), null, 91);
        check(tunA != 0 && tunB != 0, "two AWG 3.1 peers (A: disable_cookies=1, B: 0) were created");
        if (tunA == 0 || tunB == 0) return;

        ByteBuffer netA = ByteBuffer.allocateDirect(2048);
        ByteBuffer netB = ByteBuffer.allocateDirect(2048);
        ByteBuffer opA = ByteBuffer.allocateDirect(1);
        ByteBuffer opB = ByteBuffer.allocateDirect(1);
        byte[] payload = ipv4Packet(64);

        armOp(opA);
        int n = wireguard_write(tunA, payload, payload.length, netA, netA.capacity(), opA);
        byte[] init = taken(netA, Math.max(n, 0));
        check(opOf(opA) == WRITE_TO_NETWORK && n >= S1 + 148,
              "the initiation is at least S1 + 148 bytes (got " + n + ")");
        check(n >= S1 + 148 && tagIn(init, S1, 0),
              "under the header-protection key, the tag at S1 is in H1");

        armOp(opB);
        n = wireguard_read(tunB, init, init.length, netB, netB.capacity(), opB);
        byte[] resp = taken(netB, Math.max(n, 0));
        check(opOf(opB) == WRITE_TO_NETWORK && n >= S2 + 92,
              "B answers with a response of at least S2 + 92 bytes (got " + n + ")");
        check(n >= S2 + 92 && tagIn(resp, S2, 1),
              "under the header-protection key, the tag at S2 is in H2");

        armOp(opA);
        n = wireguard_read(tunA, resp, resp.length, netA, netA.capacity(), opA);
        byte[] keepalive = taken(netA, Math.max(n, 0));
        // A keepalive is padded like data: S4 + 32 + a draw from the 8..24 range.
        check(opOf(opA) == WRITE_TO_NETWORK && n >= S4 + 32 + 8 && n <= S4 + 32 + 24,
              "A confirms with a keepalive of S4 + 32 + 8..24 bytes (got " + n + ")");
        check(n >= S4 + 32 && tagIn(keepalive, S4, 3),
              "under the header-protection key, the keepalive's tag at S4 is in H4");

        armOp(opB);
        wireguard_read(tunB, keepalive, keepalive.length, netB, netB.capacity(), opB);
        check(opOf(opB) == WIREGUARD_DONE, "B accepts the confirmation keepalive");

        armOp(opA);
        n = wireguard_write(tunA, payload, payload.length, netA, netA.capacity(), opA);
        byte[] data = taken(netA, Math.max(n, 0));
        int base = S4 + 32 + payload.length;
        check(opOf(opA) == WRITE_TO_NETWORK && n >= base + 8 && n <= base + 24,
              "the data frame is S4 + 32 + 64 + a draw from the configured 8..24 padding (got " + n + ")");
        check(n >= S4 + 32 && tagIn(data, S4, 3),
              "under the header-protection key, the data frame's tag at S4 is in H4");

        armOp(opB);
        n = wireguard_read(tunB, data, data.length, netB, netB.capacity(), opB);
        check(opOf(opB) == WRITE_TO_TUNNEL_IPV4 && n == payload.length
                  && Arrays.equals(payload, taken(netB, n)),
              "B decrypts the original 64-byte IPv4 packet, byte-for-byte");
    }

    /** A pair of tunnels configured as each other's peer, as raw handles. */
    private static long[] peerPair(int baseIndex) {
        byte[] sa = x25519_secret_key();
        byte[] sb = x25519_secret_key();
        return new long[] {
            new_tunnel(x25519_key_to_base64(sa),
                       x25519_key_to_base64(x25519_public_key(sb)),
                       null, (short) 0, baseIndex),
            new_tunnel(x25519_key_to_base64(sb),
                       x25519_key_to_base64(x25519_public_key(sa)),
                       null, (short) 0, baseIndex + 1),
        };
    }

    private static boolean fatalInputChildSurvives() {
        try {
            String java = System.getProperty("java.home")
                + File.separator + "bin" + File.separator + "java";
            ProcessBuilder pb = new ProcessBuilder(
                java,
                "-Djava.library.path=" + System.getProperty("java.library.path"),
                "-cp", System.getProperty("java.class.path"),
                BoringTunJNI.class.getName(),
                "fatal-inputs");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int code = p.waitFor();
            if (code == 0 && out.contains("FATAL_INPUTS_SURVIVED")) {
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
