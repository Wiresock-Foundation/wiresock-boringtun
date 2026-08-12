#!/usr/bin/env python3
"""AmneziaWG 3.0 header-protection interop against an INDEPENDENT implementation.

This is the only external oracle for the header-protection wire format. Every
in-crate test round-trips our masking against itself, so a wrong constant --
the 16-byte transport header, the 12-byte nonce, the per-kind masked length,
the keystream offsets -- stays self-consistent and the suite stays green while
the format silently diverges. Nothing but a real amneziawg-go peer catches that.

Four cases, and the order matters:

  A  go  <-> go   with the key    -- the POSITIVE CONTROL. If this fails, header
                                     protection is broken upstream and every
                                     other result here is meaningless.
  B  go  <-> go   without the key -- proves the harness works independent of HP.
  C  bt  <-> go   with the key    -- the claim.
  D  bt  <-> go   key on one end  -- must FAIL, or C proves nothing: a masking
                                     that is a no-op at both ends also "works".

A and D are what stop this being a test that cannot fail. Both have been
observed failing for real reasons during development.

Requires: root (creates network namespaces), python3, iproute2, ping, the
python `cryptography` module, a built boringtun-cli, and amneziawg-go v3:

    go install github.com/amnezia-vpn/amneziawg-go/v3@latest   # needs Go >= 1.25

The /v3 suffix is required, not cosmetic -- see the note in awg-go-interop.sh.

SAFETY: everything lives in throwaway network namespaces prefixed `hpa-`/`hpb-`,
plus two UAPI sockets under /run/{amneziawg,wireguard} -- /run is not network
namespaced, so those are the one piece of state outside them. Every name carries
a suffix taken from an exclusive `mkdtemp` reservation, so nothing this script
deletes can belong to anything else; the host's own interfaces, routes and
WireGuard devices are never touched, and cleanup runs on every exit path.

Usage: hp-interop.py <boringtun-cli> <amneziawg-go>
Exit 0 if all four cases behave as expected, 1 otherwise.
"""
import os
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time

BT, GO = sys.argv[1], sys.argv[2]
# TOKEN comes out of the mkdtemp reservation rather than a second random draw.
# `teardown` deletes namespaces, links and sockets by name before setup, to
# clear a crashed previous run -- so those names must be provably ours. mkdtemp
# retries until the kernel accepts an exclusive create, which proves the suffix
# unique against every concurrent run for as long as the directory lives;
# `token_hex(3)` is 24 bits and proves nothing. Same argument as
# awg-go-interop.sh. The suffix is [a-z0-9_]{8}, so it stays safe in the
# unquoted interpolations below and `hva-<8>` is 12 chars, inside the kernel's
# 15-character interface-name limit.
WORK = tempfile.mkdtemp(prefix="hpi-")
TOKEN = os.path.basename(WORK)[len("hpi-") :]

# S sizes all >= 12: amneziawg-go refuses header protection below that, and so
# do we. H ranges must not overlap or go rejects the whole set=.
S = dict(s1=120, s2=130, s3=110, s4=80)
H = dict(h1=169887817, h2=390382747, h3=1033691040, h4=1526332224)
J = dict(jc=4, jmin=50, jmax=1000)

passed, failed = [], []
def ok(m):  print(f"  PASS {m}"); passed.append(m)
def bad(m): print(f"  FAIL {m}"); failed.append(m)

def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)

def x25519_pub(priv_hex: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    k = X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return k.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()

def genkey() -> str:
    b = bytearray(secrets.token_bytes(32))
    b[0] &= 248; b[31] &= 127; b[31] |= 64
    return bytes(b).hex()

NS_A, NS_B = f"hpa-{TOKEN}", f"hpb-{TOKEN}"
VETH_A, VETH_B = f"hva-{TOKEN}", f"hvb-{TOKEN}"
# Distinct names per side: UAPI sockets live under /run, which is NOT network
# namespaced, so two daemons sharing an interface name collide on one path.
IF_A, IF_B = f"wga{TOKEN}", f"wgb{TOKEN}"
# amneziawg-go publishes to /run/amneziawg/, our boringtun to /run/wireguard/
# with a symlink in /run/amneziawg/. Search both rather than assume.
SOCK_DIRS = ("/run/amneziawg", "/run/wireguard")
PORT = 51820
LINK_A, LINK_B = "10.55.0.1", "10.55.0.2"
TUN_A, TUN_B = "10.77.0.1", "10.77.0.2"

def teardown():
    for ns in (NS_A, NS_B):
        sh(f"ip netns pids {ns} 2>/dev/null | xargs -r kill")
        sh(f"ip netns del {ns} 2>/dev/null")
    sh(f"ip link del {VETH_A} 2>/dev/null")
    for d in SOCK_DIRS:
        for i in (IF_A, IF_B):
            sh(f"rm -f {d}/{i}.sock")

def underlay():
    teardown()
    time.sleep(0.3)
    for ns in (NS_A, NS_B):
        sh(f"ip netns add {ns}")
    sh(f"ip link add {VETH_A} type veth peer name {VETH_B}")
    sh(f"ip link set {VETH_A} netns {NS_A} && ip link set {VETH_B} netns {NS_B}")
    sh(f"ip netns exec {NS_A} ip addr add {LINK_A}/24 dev {VETH_A}")
    sh(f"ip netns exec {NS_B} ip addr add {LINK_B}/24 dev {VETH_B}")
    for ns, dev in ((NS_A, VETH_A), (NS_B, VETH_B)):
        sh(f"ip netns exec {ns} ip link set {dev} up")
        sh(f"ip netns exec {ns} ip link set lo up")

def sock_path(iface):
    for d in SOCK_DIRS:
        p = f"{d}/{iface}.sock"
        if os.path.exists(p):
            return p
    return None

def uapi(iface, payload):
    """Talk to a daemon's UAPI socket. The socket is a filesystem path and /run
    is not network namespaced, so this needs no netns entry."""
    p = sock_path(iface)
    if not p:
        return ""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(p)
    s.sendall(payload.encode())
    s.shutdown(socket.SHUT_WR)
    out = b""
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            out += c
    except socket.timeout:
        pass
    s.close()
    return out.decode(errors="replace")

def launch(cmd, log):
    """Start a daemon in the background, and fail loudly if the launch itself
    did not work. Without this a start failure is indistinguishable from a
    daemon that started and then would not listen."""
    r = sh(cmd)
    if r.returncode != 0:
        print(f"      LAUNCH FAILED rc={r.returncode} cmd={cmd}")
        print(f"      stderr={r.stderr.strip()[:200]}")
    if not os.path.exists(log):
        print(f"      LAUNCH produced no log at {log} (WORK exists: {os.path.isdir(WORK)})")
    return log

# `GO` and `BT` come from argv and `log` sits under `tempfile.mkdtemp()`, i.e.
# under $TMPDIR -- none of the three is ours to trust, and `sh` runs as root.
# Unquoted, a path with a space does not merely fail to launch: the shell splits
# the redirect too, so `>` truncates at the *prefix*, creating a root-owned file
# there or erasing whatever is already at that name, outside the namespaces this
# script tears down. The trailing `&` makes the shell exit 0, so `launch`'s
# returncode check never sees it either -- only the missing-log check does.
#
# Quoted here and nowhere else on purpose: every other interpolation in this
# file is a TOKEN-derived name or a module-level literal.
def start_go(ns, iface, logname):
    log = os.path.join(WORK, logname)
    return launch(
        f"ip netns exec {ns} env LOG_LEVEL=verbose "
        f"{shlex.quote(GO)} -f {iface} > {shlex.quote(log)} 2>&1 &",
        log,
    )

def start_bt(ns, iface, logname):
    log = os.path.join(WORK, logname)
    return launch(
        f"ip netns exec {ns} env WG_LOG_LEVEL=debug "
        f"{shlex.quote(BT)} --foreground --disable-drop-privileges {iface} "
        f"> {shlex.quote(log)} 2>&1 &",
        log,
    )

def wait_sock(iface, timeout=8):
    for _ in range(int(timeout * 10)):
        if sock_path(iface):
            return True
        time.sleep(0.1)
    return False

def configure(iface, priv, peer_pub, endpoint, allowed, hp_key, keepalive=True):
    cfg = ["set=1", f"private_key={priv}", f"listen_port={PORT}"]
    cfg += [f"{k}={v}" for k, v in J.items()]
    cfg += [f"{k}={v}" for k, v in S.items()]
    cfg += [f"{k}={v}" for k, v in H.items()]
    if hp_key:
        cfg.append(f"header_protection_key={hp_key}")
    cfg += [f"public_key={peer_pub}", f"allowed_ip={allowed}"]
    if endpoint:
        cfg.append(f"endpoint={endpoint}")
    if keepalive:
        cfg.append("persistent_keepalive_interval=1")
    return uapi(iface, "\n".join(cfg) + "\n\n")

def bring_up(ns, iface, addr):
    sh(f"ip netns exec {ns} ip addr add {addr}/24 dev {iface}")
    sh(f"ip netns exec {ns} ip link set {iface} up mtu 1420")

def run_case(name, a_impl, b_impl, hp_a, hp_b, expect_pass):
    print(f"==> {name}")
    # The log filename is a SLUG, not the display name: these go into an
    # unquoted shell redirect, and the case names contain spaces and `<->` --
    # which the shell reads as two more redirections, not as characters.
    slug = "".join(c if c.isalnum() else "_" for c in name)
    underlay()
    ka, kb = genkey(), genkey()
    pa, pb = x25519_pub(ka), x25519_pub(kb)

    la = (start_go if a_impl == "go" else start_bt)(NS_A, IF_A, f"{slug}-a.log")
    lb = (start_go if b_impl == "go" else start_bt)(NS_B, IF_B, f"{slug}-b.log")
    for side, iface, lg in (("A", IF_A, la), ("B", IF_B, lb)):
        if not wait_sock(iface):
            bad(f"{name}: side {side} never created its socket")
            if os.path.exists(lg):
                for t in open(lg, errors="replace").read().splitlines()[-4:]:
                    print(f"      {t[:130]}")
            return

    ra = configure(IF_A, ka, pb, f"{LINK_B}:{PORT}", f"{TUN_B}/32", hp_a)
    bring_up(NS_A, IF_A, TUN_A)
    rb = configure(IF_B, kb, pa, f"{LINK_A}:{PORT}", f"{TUN_A}/32", hp_b)
    bring_up(NS_B, IF_B, TUN_B)

    if "errno=0" not in ra or "errno=0" not in rb:
        bad(f"{name}: configuration refused (A={ra.strip()[:40]!r} B={rb.strip()[:40]!r})")
        return

    r = sh(f"ip netns exec {NS_A} ping -c 3 -W 2 -i 0.4 {TUN_B}")
    got = r.returncode == 0
    if got == expect_pass:
        ok(f"{name}: ping {'succeeded' if got else 'failed'}, as expected")
    else:
        bad(f"{name}: ping {'succeeded' if got else 'failed'}, expected the opposite")
        for lg in (la, lb):
            if os.path.exists(lg):
                tail = open(lg, errors="replace").read().strip().splitlines()[-4:]
                for t in tail:
                    print(f"      {os.path.basename(lg)}: {t[:130]}")

try:
    HP = secrets.token_bytes(32).hex()
    run_case("A go<->go WITH key",    "go", "go", HP,   HP,   True)
    run_case("B go<->go WITHOUT key", "go", "go", None, None, True)
    run_case("C bt<->go WITH key",    "bt", "go", HP,   HP,   True)
    run_case("D bt<->go key one end", "bt", "go", HP,   None, False)
    print(f"\nSUMMARY: {len(passed)} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)
finally:
    teardown()
    shutil.rmtree(WORK, ignore_errors=True)
