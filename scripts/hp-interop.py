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

`@latest` on purpose, not a pinned tag. This harness exists to notice the wire
format moving under us; pinning would freeze the one external oracle we have
into a second copy of our own constants, green forever for the same reason the
in-crate tests are. The build actually tested is read out of the binary's Go
module metadata and printed with the results, so every run names its oracle. To
reproduce an older run, install that exact version and then go back to @latest:

    go install github.com/amnezia-vpn/amneziawg-go/v3@v3.0.20260805

The /v3 suffix is required, not cosmetic -- see the note in awg-go-interop.sh.

SAFETY: everything lives in throwaway network namespaces prefixed `hpa-`/`hpb-`,
plus two UAPI sockets under /run/{amneziawg,wireguard} -- /run is not network
namespaced, so those are the one piece of state outside them. Teardown deletes
only names this run claimed: the namespaces and links whose create command
reported success, and the two UAPI socket paths of a daemon this run launched.
So nothing it deletes can belong to anything else; the host's own interfaces,
routes and WireGuard devices are never touched, and cleanup runs on every exit
path. The `mkdtemp` suffix keeps two concurrent runs off each other's names; it
says nothing about the netns and link name spaces, which are separate and
host-global, so ownership tracking and not the suffix is what makes teardown
safe. A name that already exists is refused before anything is created.

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
# mkdtemp retries until the kernel accepts an exclusive create, so two runs
# sharing $TMPDIR cannot draw the same suffix and can therefore run at once;
# `token_hex(3)` is 24 bits and would not reliably give even that. What mkdtemp
# does NOT give is any claim on the `ip netns` or link name spaces: those are
# separate, host-global, and a name matching ours there is improbable, not
# impossible -- a crashed run whose /tmp was reaped can leave a stale netns for
# a future run to re-draw. So the suffix is not what makes teardown safe;
# `OWNED_*` is. Same split as awg-go-interop.sh. The suffix is [a-z0-9_]{8}, so
# it stays safe in the unquoted interpolations below and `hva-<8>` is 12 chars,
# inside the kernel's 15-character interface-name limit.
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

class SetupError(Exception):
    """The topology, not the wire format. Never a header-protection result."""

def must(cmd):
    """sh, but a nonzero exit ends the case instead of vanishing.

    Setup ran through bare sh, whose CompletedProcess nobody read. That is
    survivable for the three cases that expect the ping to SUCCEED -- a broken
    topology fails them loudly. It is not survivable for D, which expects the
    ping to FAIL: there, every setup command that quietly did nothing produced
    exactly the result D was looking for. Measured on the unfixed script, six
    separate sabotages -- no link address, link down, no tunnel address, a
    misspelled ping binary, a bogus device name, and killing side B's daemon --
    every one reported "PASS D ...: ping failed, as expected" and exit 0.
    """
    r = sh(cmd)
    if r.returncode != 0:
        detail = (r.stderr or r.stdout).strip().splitlines()
        raise SetupError(
            "%s exited %d: %s" % (cmd, r.returncode, detail[0][:120] if detail else "")
        )
    return r

def ping(ns, dst, count=3):
    """One place that runs ping, so a ping that cannot RUN is never scored.

    ping returns nonzero both for "no reply" and for "no such binary" or "no
    such device". Sharing this between the preconditions and the test means a
    broken invocation breaks a precondition instead of reading as the mismatch
    case D is looking for.
    """
    return sh(f"ip netns exec {ns} ping -c {count} -W 2 -i 0.4 {dst}")

def go_module_version(path):
    """The module version amneziawg-go was built from.

    NOT `--version`: upstream's version constant still reads 0.0.20250522 on the
    v3 line, so the binary under-reports itself by more than a year. `go version
    -m` reads the module metadata the linker embeds, which is the real answer.
    Falls back to the raw path when the Go toolchain is absent -- naming the
    oracle is worth having, not worth failing the run over.
    """
    r = sh(f"go version -m {shlex.quote(path)}")
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "mod" and "amneziawg-go" in parts[1]:
            return f"{parts[1]} {parts[2]}"
    return f"{path} (version unknown: `go version -m` said nothing)"

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

# What this run has actually created, appended to only after the creating
# command reported success. A name we did not create stays unclaimed and so is
# unreachable from `teardown` -- including the one case that matters, an
# `ip netns add` that failed *because the name was already taken*. Emptied at
# the end of `teardown`, so each rebuild has to acquire its names again.
OWNED_NS, OWNED_LINKS, OWNED_SOCKS = [], [], []

def own_socks(iface):
    """Claim a daemon's socket names at launch rather than on create: a daemon
    that starts and then hangs still has to be cleaned up after, and
    `wait_sock` giving up does not mean nothing was created."""
    OWNED_SOCKS.extend(f"{d}/{iface}.sock" for d in SOCK_DIRS)

def teardown():
    for ns in OWNED_NS:
        sh(f"ip netns pids {ns} 2>/dev/null | xargs -r kill")
        sh(f"ip netns del {ns} 2>/dev/null")
    for link in OWNED_LINKS:
        sh(f"ip link del {link} 2>/dev/null")
    for p in OWNED_SOCKS:
        sh(f"rm -f {p}")
    for owned in (OWNED_NS, OWNED_LINKS, OWNED_SOCKS):
        owned.clear()

def underlay():
    teardown()
    time.sleep(0.3)
    for ns in (NS_A, NS_B):
        must(f"ip netns add {ns}")
        OWNED_NS.append(ns)
    must(f"ip link add {VETH_A} type veth peer name {VETH_B}")
    # Deleting either end takes the pair; the peer is claimed as well so that a
    # veth stranded by a failed `netns` move is still reachable.
    OWNED_LINKS.extend((VETH_A, VETH_B))
    must(f"ip link set {VETH_A} netns {NS_A} && ip link set {VETH_B} netns {NS_B}")
    must(f"ip netns exec {NS_A} ip addr add {LINK_A}/24 dev {VETH_A}")
    must(f"ip netns exec {NS_B} ip addr add {LINK_B}/24 dev {VETH_B}")
    for ns, dev in ((NS_A, VETH_A), (NS_B, VETH_B)):
        must(f"ip netns exec {ns} ip link set {dev} up")
        must(f"ip netns exec {ns} ip link set lo up")

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
    own_socks(iface)
    return launch(
        f"ip netns exec {ns} env LOG_LEVEL=verbose "
        f"{shlex.quote(GO)} -f {iface} > {shlex.quote(log)} 2>&1 &",
        log,
    )

def start_bt(ns, iface, logname):
    log = os.path.join(WORK, logname)
    own_socks(iface)
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
    must(f"ip netns exec {ns} ip addr add {addr}/24 dev {iface}")
    must(f"ip netns exec {ns} ip link set {iface} up mtu 1420")

def assert_plumbing():
    """Everything except the tunnel, proved working, right before the test.

    Case D scores a FAILED ping as the expected header-protection mismatch, so
    every other reason a ping can fail has to be excluded first. Otherwise D is
    a test that cannot fail, which defeats the only thing it is for: showing
    that C passing means something.

    Three positive controls, none of which traverses the tunnel, so all must
    hold identically in every case:
      1. the underlay ping -- namespaces, veth, addresses, link state, and that
         ping itself runs at all;
      2. both namespaces still contain a live process -- a daemon that died
         after set=1 would otherwise read as a mismatch;
      3. each side answers on its OWN tunnel address -- local, so it does not
         need the tunnel, and it catches a bring_up that never took, which the
         underlay ping is blind to.

    What this does NOT prove: that UDP reached the peer daemon (ICMP on the
    veth and the daemon's socket are different paths), and it cannot tell a
    header-protection mismatch from any other tunnel-layer disagreement -- only
    from a broken topology, which is what D needs.
    """
    if ping(NS_A, LINK_B, count=2).returncode != 0:
        raise SetupError(f"underlay {LINK_A} -> {LINK_B} is not reachable")
    for ns, addr in ((NS_A, TUN_A), (NS_B, TUN_B)):
        if not sh(f"ip netns pids {ns}").stdout.strip():
            raise SetupError(f"no process left alive in {ns}")
        if ping(ns, addr, count=1).returncode != 0:
            raise SetupError(f"{addr} does not answer locally; bring_up did not take")

def run_case(name, a_impl, b_impl, hp_a, hp_b, expect_pass):
    """A broken setup is a FAIL, never a PASS -- see `assert_plumbing`."""
    print(f"==> {name}")
    try:
        _run_case(name, a_impl, b_impl, hp_a, hp_b, expect_pass)
    except SetupError as e:
        bad(f"{name}: setup failed, not an interop result -- {e}")

def _run_case(name, a_impl, b_impl, hp_a, hp_b, expect_pass):
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

    # Everything but the tunnel, proved working, before a failed ping is
    # allowed to mean "header protection mismatched".
    assert_plumbing()

    r = ping(NS_A, TUN_B)
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

# Module level and BEFORE the `try:` below, on purpose: `sys.exit` here raises
# SystemExit before that block is entered, so its `finally: teardown()` never
# runs and the refusal cannot turn into the deletion it is refusing to make.
# Nowhere inside works -- a `SetupError` raised from `_run_case` is caught by
# `run_case`, scored a FAIL, and execution still reaches the `finally`.
#
# Every name carries this run's mkdtemp suffix, so a hit means a stale run that
# drew the same suffix, or an unrelated workload; neither is ours to delete.
# This is the clear diagnostic, not the safety mechanism -- `OWNED_*` is that,
# and it also covers a name that appears after this check has passed.
def refuse(what):
    print(f"preflight: {what} already exists; refusing to touch it", file=sys.stderr)
    shutil.rmtree(WORK, ignore_errors=True)
    sys.exit(2)

for _n in (NS_A, NS_B):
    if sh(f"ip netns list | grep -qw {_n}").returncode == 0:
        refuse(f"namespace {_n}")
for _l in (VETH_A, VETH_B):
    if sh(f"ip link show {_l} >/dev/null 2>&1").returncode == 0:
        refuse(f"interface {_l}")
for _d in SOCK_DIRS:
    for _i in (IF_A, IF_B):
        # lexists, not exists: this asks "is the NAME taken", and a dangling
        # symlink takes the name (bind through it fails EADDRINUSE) while
        # exists() follows it and reports absent. A dangler here is realistic:
        # boringtun publishes /run/amneziawg/<i>.sock as a symlink and removes
        # target before link at exit, so a kill inside that window leaves one.
        # (`sock_path` keeps exists() -- it asks for a live socket, not a name.)
        if os.path.lexists(f"{_d}/{_i}.sock"):
            refuse(f"{_d}/{_i}.sock")

try:
    HP = secrets.token_bytes(32).hex()
    run_case("A go<->go WITH key",    "go", "go", HP,   HP,   True)
    run_case("B go<->go WITHOUT key", "go", "go", None, None, True)
    run_case("C bt<->go WITH key",    "bt", "go", HP,   HP,   True)
    run_case("D bt<->go key one end", "bt", "go", HP,   None, False)
    print(f"\nORACLE: {go_module_version(GO)}")
    print(f"SUMMARY: {len(passed)} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)
finally:
    teardown()
    shutil.rmtree(WORK, ignore_errors=True)
