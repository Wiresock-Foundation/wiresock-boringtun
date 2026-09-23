#!/usr/bin/env python3
"""Judge one awg31-interop.sh capture: does each sender emit the AmneziaWG 3.1
wire it is configured for?

The capture is what a raw socket saw on the responder's veth, one datagram per
line: ``<in|out> <udp payload length> <hex of the first 256 payload bytes>``.
"in" was sent by the initiator, "out" by the responder, and the harness says
which implementation each of those is -- so every verdict below is per SENDER.
Pooling both directions would let one implementation's trailers stand in for
the other's; that is the false positive this checker exists to rule out.

Each datagram is classified by its message-type tag, read at each kind's own S
offset -- through the header-protection keystream when a key is set, the same
way a receiver reads it. The harness's H values are single tags, so a match is
not a guess. Then:

  * bounds: a handshake message is exactly S + 148 / 92 / 64 with
    RandomTrailers off, and at least that and below the UDP window with it on;
    transport is at least S4 + 32 and at most the window. The window is the
    harness's DEFAULT_UDP_WINDOW: every frame the harness sends is small enough
    that neither implementation's window grows past it. Anything else that is
    not Jc junk is a violation, not a curiosity.
  * RandomTrailers evidence, per sender: with it on, a sender's handshake
    messages must not all be exactly base size (a zero trailer is valid, so one
    exact message proves nothing -- at least two are required), and with
    content padding off its transport must take several sizes. Content padding
    varies transport by itself, so that profile is never counted as trailer
    evidence. With RandomTrailers and content padding both off, transport must
    NOT vary beyond the ping frame and the keepalive.
  * rekey: handshakes are paired by index (the response's receiver index is the
    initiation's sender index). At least two must complete, and after the last,
    transport in BOTH directions must address the new session -- the initiator
    sending to the response's sender index, the responder to the initiation's.
    A responder that recorded a handshake the initiator never took up fails here.

Exit status: 0 = every assertion held; 1 = a protocol violation, each printed
on stdout; 2 = the checker itself failed (malformed capture, bad arguments, an
exception). The harness counts only 0 as a pass.

``--self-test`` runs the synthetic captures at the bottom of this file, each of
which must produce its expected exit status.
"""

import argparse
import os
import struct
import sys
import traceback

INIT_SZ, RESP_SZ, COOKIE_SZ, DATA_MIN = 148, 92, 64, 32


def keystream(key, head, n):
    """The first ``n`` header-protection keystream bytes for a datagram: IETF
    ChaCha20, counter 0, nonce = the datagram's first 12 bytes."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    enc = Cipher(algorithms.ChaCha20(key, b"\0" * 4 + head[:12]), mode=None).encryptor()
    return enc.update(b"\0" * n)


class Wire:
    def __init__(self, s, h, hp_key):
        self.s1, self.s2, self.s3, self.s4 = s
        self.h1, self.h2, self.h3, self.h4 = h
        self.key = hp_key

    def fields(self, head, offset, n):
        """``n`` bytes of message at ``offset``, unmasked when a key is set."""
        raw = head[offset:offset + n]
        if len(raw) < n:
            return None
        if self.key is None:
            return raw
        ks = keystream(self.key, head, n)
        return bytes(a ^ b for a, b in zip(raw, ks))

    def classify(self, n, head):
        """(kind, fields dict) or (None, None)."""
        found = []
        for kind, off, base, tag, width in (
            ("init", self.s1, INIT_SZ, self.h1, 8),
            ("resp", self.s2, RESP_SZ, self.h2, 12),
            ("cookie", self.s3, COOKIE_SZ, self.h3, 8),
            ("data", self.s4, DATA_MIN, self.h4, 8),
        ):
            if n < off + base:
                continue
            f = self.fields(head, off, width)
            if f is None or struct.unpack("<I", f[:4])[0] != tag:
                continue
            if kind == "init":
                found.append((kind, {"sender": struct.unpack("<I", f[4:8])[0]}))
            elif kind == "resp":
                sender, receiver = struct.unpack("<II", f[4:12])
                found.append((kind, {"sender": sender, "receiver": receiver}))
            elif kind == "cookie":
                found.append((kind, {"receiver": struct.unpack("<I", f[4:8])[0]}))
            else:
                found.append((kind, {"receiver": struct.unpack("<I", f[4:8])[0]}))
        if len(found) > 1:
            raise ValueError("a datagram matched %d kinds: %r" % (len(found), found))
        return found[0] if found else (None, None)


def judge(rows, a):
    """Return (violations, summary) for parsed capture rows."""
    wire = Wire(a.s, a.h, a.hp_key)
    sender_of = {"in": a.in_sender, "out": a.out_sender}
    per = {name: {"init": [], "resp": [], "data": []} for name in (a.in_sender, a.out_sender)}
    events = []  # (kind, direction, fields) in capture order
    problems = []

    bases = {
        "init": wire.s1 + INIT_SZ,
        "resp": wire.s2 + RESP_SZ,
        "cookie": wire.s3 + COOKIE_SZ,
    }
    for i, (direction, n, head) in enumerate(rows):
        sender = sender_of[direction]
        kind, f = wire.classify(n, head)
        if kind is None:
            if n > a.jmax:
                problems.append(
                    "%s sent an unclassifiable %d-byte datagram (#%d), larger than any Jc junk"
                    % (sender, n, i))
            continue
        if kind in bases:
            base = bases[kind]
            if not a.rt and n != base:
                problems.append("RandomTrailers off, yet %s sent a %d-byte %s (exactly %d required)"
                                % (sender, n, kind, base))
            if a.rt and not (base <= n < a.window):
                problems.append("%s sent a %d-byte %s, outside [%d, %d)"
                                % (sender, n, kind, base, a.window))
        else:
            if not (wire.s4 + DATA_MIN <= n <= a.window):
                problems.append("%s sent a %d-byte transport frame, outside [%d, %d]"
                                % (sender, n, wire.s4 + DATA_MIN, a.window))
        if kind in per[sender]:
            per[sender][kind].append(n)
        events.append((kind, direction, f))

    # RandomTrailers evidence, sender by sender.
    for sender, seen in per.items():
        control = [("init", n) for n in seen["init"]] + [("resp", n) for n in seen["resp"]]
        if a.rt:
            if len(control) < 2:
                problems.append("%s sent only %d handshake message(s); two are needed to show "
                                "trailers" % (sender, len(control)))
            elif all(n == bases[k] for k, n in control):
                problems.append("RandomTrailers on, yet every handshake message %s sent was "
                                "exactly base size: %r" % (sender, control))
            if not a.cpa and len(set(seen["data"])) < 3:
                problems.append("RandomTrailers on without content padding, yet %s's transport "
                                "took only %d size(s): %r"
                                % (sender, len(set(seen["data"])), sorted(set(seen["data"]))))
        elif not a.cpa and len(set(seen["data"])) > 2:
            problems.append("RandomTrailers and content padding off, yet %s's transport took %d "
                            "sizes: %r" % (sender, len(set(seen["data"])), sorted(set(seen["data"]))))

    # Handshakes, paired by index, and the session each side sends on after the last.
    pending = {}
    completed = []  # (index into events, init_dir, init_sender_idx, resp_sender_idx)
    for pos, (kind, direction, f) in enumerate(events):
        if kind == "init":
            pending[f["sender"]] = direction
        elif kind == "resp" and f["receiver"] in pending:
            init_dir = pending.pop(f["receiver"])
            if init_dir != direction:
                completed.append((pos, init_dir, f["receiver"], f["sender"]))
    if len(completed) < 2:
        problems.append("only %d completed handshake(s) on the wire; the initial one and a "
                        "rekey are required" % len(completed))
    else:
        pos, init_dir, init_idx, resp_idx = completed[-1]
        resp_dir = "out" if init_dir == "in" else "in"
        after = [(d, f["receiver"]) for kind, d, f in events[pos + 1:] if kind == "data"]
        # The initiating side addresses the responder's new index, and back.
        if not any(d == init_dir and r == resp_idx for d, r in after):
            problems.append("after the last handshake, %s never sent on the new session "
                            "(receiver index %#x) -- the rekey did not complete there"
                            % (sender_of[init_dir], resp_idx))
        if not any(d == resp_dir and r == init_idx for d, r in after):
            problems.append("after the last handshake, %s never sent on the new session "
                            "(receiver index %#x) -- the rekey did not complete there"
                            % (sender_of[resp_dir], init_idx))

    summary = "; ".join(
        "%s: inits=%r resps=%r transport sizes=%d (%s)" % (
            name, seen["init"], seen["resp"], len(set(seen["data"])),
            "%d..%d" % (min(seen["data"]), max(seen["data"])) if seen["data"] else "none")
        for name, seen in per.items()) + "; handshakes=%d" % len(completed)
    return problems, summary


def parse_capture(path):
    rows = []
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) != 3 or parts[0] not in ("in", "out"):
                raise ValueError("capture line %d is malformed: %r" % (lineno, line[:80]))
            rows.append((parts[0], int(parts[1]), bytes.fromhex(parts[2])))
    return rows


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--capture")
    p.add_argument("--rt", type=int, choices=(0, 1))
    p.add_argument("--cpa", type=int, choices=(0, 1))
    p.add_argument("--hp-key", help="hex; omit when header protection is off")
    p.add_argument("--in-sender")
    p.add_argument("--out-sender")
    p.add_argument("--s", help="S1,S2,S3,S4")
    p.add_argument("--h", help="H1,H2,H3,H4")
    p.add_argument("--window", type=int, default=500)
    p.add_argument("--jmax", type=int)
    p.add_argument("--self-test", action="store_true")
    a = p.parse_args(argv)
    if a.self_test:
        return a
    for name in ("capture", "rt", "cpa", "in_sender", "out_sender", "s", "h", "jmax"):
        if getattr(a, name) is None:
            p.error("--%s is required" % name.replace("_", "-"))
    a.s = tuple(int(x) for x in a.s.split(","))
    a.h = tuple(int(x) for x in a.h.split(","))
    a.rt, a.cpa = bool(a.rt), bool(a.cpa)
    a.hp_key = bytes.fromhex(a.hp_key) if a.hp_key else None
    if len(a.s) != 4 or len(a.h) != 4 or a.in_sender == a.out_sender:
        p.error("need four S, four H, and two distinct senders")
    return a


def main(argv):
    try:
        a = parse_args(argv)
        if a.self_test:
            return self_test()
        problems, summary = judge(parse_capture(a.capture), a)
    except SystemExit as e:  # argparse
        return 2 if e.code else 0
    except Exception:
        traceback.print_exc()
        print("checker error: see stderr", flush=True)
        return 2
    for problem in problems:
        print(problem)
    print(summary, file=sys.stderr)
    return 1 if problems else 0


# --- self-test -------------------------------------------------------------
#
# Synthetic captures, built with the same layout and masking the checker reads,
# for every false-positive mode the checker has to rule out. Each must produce
# its expected exit status; a checker that passes them all is the one the
# harness is allowed to trust.

S = (40, 24, 32, 160)
H = (169887817, 390382747, 1033691040, 1526332224)
KEY = bytes.fromhex("5a" * 32)
PING = 84


def build(kind, fields, trailer, key, rnd, plaintext=0):
    """A datagram of ``kind`` in the harness's configuration."""
    s1, s2, s3, s4 = S
    off, tag = {"init": (s1, H[0]), "resp": (s2, H[1]), "data": (s4, H[3])}[kind]
    if kind == "init":
        core = struct.pack("<II", tag, fields["sender"]) + rnd(INIT_SZ - 8)
        masked = INIT_SZ
    elif kind == "resp":
        core = struct.pack("<III", tag, fields["sender"], fields["receiver"]) + rnd(RESP_SZ - 12)
        masked = RESP_SZ
    else:
        core = struct.pack("<IIQ", tag, fields["receiver"], 0) + rnd(plaintext + 16)
        masked = 16
    junk = rnd(off)
    if key is not None:
        ks = keystream(key, junk, masked)
        core = bytes(a ^ b for a, b in zip(core[:masked], ks)) + core[masked:]
    return junk + core + rnd(trailer)


def capture(key, rust_rt, go_rt, rust_pad, go_pad, *, rekey_taken=True,
            oversize=None, rt_off_extension=False):
    """A two-handshake exchange: go initiates ("in"), rust responds ("out")."""
    import random
    r = random.Random(7)

    def rnd(n):
        return bytes(r.getrandbits(8) for _ in range(n))

    lines = []

    def add(direction, pkt):
        lines.append("%s %d %s" % (direction, len(pkt), pkt[:256].hex()))

    trailer = {"go": go_rt, "rust": rust_rt}
    pad = {"go": go_pad, "rust": rust_pad}
    sessions = [(0x1001, 0x2001), (0x1002, 0x2002)]  # (initiator idx, responder idx)
    for n, (i_idx, r_idx) in enumerate(sessions):
        add("in", rnd(60))  # Jc junk
        t = trailer["go"][n] if trailer["go"] else 0
        if rt_off_extension and n == 1:
            t = 7
        add("in", build("init", {"sender": i_idx}, t, key, rnd))
        t = trailer["rust"][n] if trailer["rust"] else 0
        add("out", build("resp", {"sender": r_idx, "receiver": i_idx}, t, key, rnd))
        for k in range(6):
            use_new = rekey_taken or n == 0
            go_to = r_idx if use_new else sessions[0][1]
            add("in", build("data", {"receiver": go_to}, 0, key, rnd,
                            plaintext=PING + pad["go"](k)))
            add("out", build("data", {"receiver": i_idx}, 0, key, rnd,
                             plaintext=PING + pad["rust"](k)))
    if oversize:
        kind, size = oversize
        base = {"init": S[0] + INIT_SZ, "data": S[3] + DATA_MIN + PING}[kind]
        fields = {"sender": 0x3003} if kind == "init" else {"receiver": 0x2002}
        add("out", build(kind, fields, size - base, key, rnd) if kind == "init"
            else build(kind, fields, 0, key, rnd, plaintext=size - S[3] - 32))
    return "\n".join(lines) + "\n"


def self_test():
    import tempfile

    varied = lambda k: (k * 37) % 150  # noqa: E731 -- several distinct paddings
    fixed = lambda k: 12  # noqa: E731 -- the 16-byte rounding of an 84-byte ping
    rt = [200, 90]

    cases = [
        # (name, capture text, rt, cpa, key, expected exit, stdout must contain)
        ("both senders emit RandomTrailers", capture(None, rt, rt, varied, varied), 1, 0, None, 0, ""),
        ("header protection: both correct",
         capture(KEY, rt, rt, varied, varied), 1, 0, KEY, 0, ""),
        ("only go emits trailers", capture(None, None, rt, fixed, varied), 1, 0, None, 1,
         "every handshake message rust sent"),
        ("only rust emits trailers", capture(None, rt, None, varied, fixed), 1, 0, None, 1,
         "every handshake message go sent"),
        ("oversized handshake message",
         capture(None, rt, rt, varied, varied, oversize=("init", 1000)), 1, 0, None, 1, "outside"),
        ("oversized transport",
         capture(None, rt, rt, varied, varied, oversize=("data", 2000)), 1, 0, None, 1, "outside"),
        ("RandomTrailers off, extended initiation",
         capture(None, None, None, fixed, fixed, rt_off_extension=True), 0, 0, None, 1, "exactly"),
        ("RandomTrailers off, exact everywhere",
         capture(None, None, None, fixed, fixed), 0, 0, None, 0, ""),
        ("rekey the initiator never took up",
         capture(None, rt, rt, varied, varied, rekey_taken=False), 1, 0, None, 1, "new session"),
        ("masked capture judged without the key",
         capture(KEY, rt, rt, varied, varied), 1, 0, None, 1, ""),
        ("malformed capture", "in not-a-number zz\n", 1, 0, None, 2, "checker error"),
    ]
    failures = 0
    with tempfile.TemporaryDirectory() as d:
        for name, text, rt_on, cpa, key, want, needle in cases:
            path = os.path.join(d, "capture")
            with open(path, "w") as f:
                f.write(text)
            argv = ["--capture", path, "--rt", str(rt_on), "--cpa", str(cpa),
                    "--in-sender", "go", "--out-sender", "rust",
                    "--s", ",".join(map(str, S)), "--h", ",".join(map(str, H)),
                    "--jmax", "90"]
            if key:
                argv += ["--hp-key", key.hex()]
            import contextlib
            import io
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                got = main(argv)
            ok = got == want and needle in out.getvalue()
            failures += not ok
            print("  %s self-test: %s (exit %d, want %d)%s" % (
                "PASS" if ok else "FAIL", name, got, want,
                "" if ok else "\n      " + out.getvalue().strip().replace("\n", "\n      ")))
    print("self-test: %s" % ("all passed" if not failures else "%d FAILED" % failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
