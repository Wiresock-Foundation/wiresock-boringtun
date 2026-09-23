#!/usr/bin/env bash
#
# AmneziaWG 3.1 RandomTrailers interoperability against a PINNED amneziawg-go.
#
# scripts/awg-go-interop.sh proves the 3.0 wire against whatever amneziawg-go
# is current. This one proves the 3.1 RandomTrailers wire against one exact
# release, because 3.1 changed shape twice after it first shipped (the cookie
# trailer length, then the padding window) and "latest" is not a reference:
#
#   amneziawg-go v3.1.20260828 (commit b5928efb6ca19f0153958460c3d141f04abc5c2e)
#
#   git clone https://github.com/amnezia-vpn/amneziawg-go
#   cd amneziawg-go && git checkout b5928efb6ca19f0153958460c3d141f04abc5c2e
#   go build -o amneziawg-go-v3.1.20260828 .        # needs Go >= 1.25
#
# The script refuses a binary built from anything else (`go version -m`).
#
# For each configuration below, and for BOTH roles -- amneziawg-go initiating
# to boringtun, and boringtun initiating to amneziawg-go -- it checks:
#
#   * the handshake completes and traffic passes in both directions;
#   * a second handshake (a rekey, forced by a short rekey_after_time) completes;
#   * the wire shape, read off the responder's veth with a raw socket:
#       RandomTrailers off -> initiation and response at exactly S + 148 / 92;
#       RandomTrailers on  -> both at least that, and not all exactly that;
#       RandomTrailers on  -> transport carrying identical pings varies in size
#                             (the addition is padding inside the AEAD).
#
# The S sizes are deliberately unequal, so the receive side's candidate
# readings genuinely differ per packet kind. What this does NOT cover: the
# cookie reply's trailer, which needs a responder under load and is pinned by
# the unit tests (`noise::random_trailers_tests`), and WireSock's CPA policy
# with RandomTrailers off, which cannot be told apart on the wire from inside a
# single run and is pinned by `amnezia::tests` with concrete values.
#
# Requires: root, iproute2, python3 with `cryptography`, ping, a built
# boringtun-cli, and the amneziawg-go above. Everything lives in throwaway
# network namespaces prefixed `a31-`; cleanup runs on every exit path.
#
# Usage: awg31-interop.sh <boringtun-cli> <amneziawg-go v3.1.20260828>
set -uo pipefail

BT=${1:?path to boringtun-cli}
GO=${2:?path to amneziawg-go v3.1.20260828}
readonly PINNED_COMMIT=b5928efb6ca19f0153958460c3d141f04abc5c2e
readonly PINNED_VERSION=v3.1.20260828

PORT=51820
RESP_TUN=10.78.0.1; INIT_TUN=10.78.0.2
RESP_LINK=10.56.0.1; INIT_LINK=10.56.0.2

# Unequal on purpose: every packet kind sits at its own offset.
readonly JC=2 JMIN=40 JMAX=90
readonly S1=40 S2=24 S3=32 S4=160
readonly H1=169887817 H2=390382747 H3=1033691040 H4=1526332224
readonly HP_KEY=5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
readonly INIT_SZ=148 RESP_SZ=92 DATA_MIN=32

awg_block() { # <rt 0|1> <cpa 0|1> <hp 0|1>
  local b
  b=$'jc='"$JC"$'\njmin='"$JMIN"$'\njmax='"$JMAX"$'\ns1='"$S1"$'\ns2='"$S2"$'\ns3='"$S3"$'\ns4='"$S4"$'\nh1='"$H1"$'\nh2='"$H2"$'\nh3='"$H3"$'\nh4='"$H4"$'\n'
  # A short rekey, so each leg sees a second handshake inside its run time.
  b+=$'rekey_after_time=12\n'
  [ "$1" = 1 ] && b+=$'random_trailers=1\n'
  [ "$2" = 1 ] && b+=$'content_padding_addition=8-120\n'
  [ "$3" = 1 ] && b+=$'header_protection_key='"$HP_KEY"$'\n'
  printf '%s' "$b"
}

genkey() { head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

umask 077
WORKDIR=$(mktemp -d /tmp/awg31-interop.XXXXXX) || { echo "no temp dir" >&2; exit 2; }
readonly WORKDIR
RUN=${WORKDIR##*.}
NS_R="a31-r-$RUN"; NS_I="a31-i-$RUN"
IF_R="a31r-$RUN";  IF_I="a31i-$RUN"
VETH_R="a31-vr-$RUN"; VETH_I="a31-vi-$RUN"
readonly RUN NS_R NS_I IF_R IF_I VETH_R VETH_I

PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
info() { printf '\033[1m==> %s\033[0m\n' "$1"; }

OWNED_NS=(); OWNED_LINKS=(); OWNED_SOCKS=()
own_socks() { OWNED_SOCKS+=("/var/run/wireguard/$1.sock" "/var/run/amneziawg/$1.sock"); }

teardown() {
  local ns link sock p killed=0
  for ns in ${OWNED_NS[@]+"${OWNED_NS[@]}"}; do
    p=$(ip netns pids "$ns" 2>/dev/null)
    [ -n "$p" ] && { kill $p 2>/dev/null; killed=1; }
  done
  [ "$killed" -eq 1 ] && sleep 0.4
  for ns in ${OWNED_NS[@]+"${OWNED_NS[@]}"}; do ip netns del "$ns" 2>/dev/null; done
  for link in ${OWNED_LINKS[@]+"${OWNED_LINKS[@]}"}; do ip link del "$link" 2>/dev/null; done
  for sock in ${OWNED_SOCKS[@]+"${OWNED_SOCKS[@]}"}; do rm -f "$sock"; done
  OWNED_NS=(); OWNED_LINKS=(); OWNED_SOCKS=()
  return 0
}
cleanup_workdir() {
  [ -n "${WORKDIR:-}" ] && [ -d "$WORKDIR" ] || return 0
  rm -rf "$WORKDIR" || echo "could not remove $WORKDIR" >&2
}
trap 'teardown; cleanup_workdir' EXIT

die() { printf '\033[31mpreflight: %s\033[0m\n' "$1" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || die "must run as root (creates network namespaces)"
[ -x "$BT" ] || die "boringtun-cli not found or not executable: $BT"
[ -x "$GO" ] || die "amneziawg-go not found or not executable: $GO"

# The reference is pinned; a binary built from anything else is refused rather
# than reported on. `go version -m` reads the module version the linker
# recorded, which for a build from the tagged commit is the tag.
if command -v go >/dev/null 2>&1; then
  built=$(go version -m "$GO" 2>/dev/null | awk '$1 == "mod" { print $3 }')
  [ "$built" = "$PINNED_VERSION" ] ||
    die "amneziawg-go is '$built', not $PINNED_VERSION ($PINNED_COMMIT); build the pinned commit"
else
  die "go is needed to verify the amneziawg-go build (go version -m)"
fi

uapi() { # <ns> <iface>; request on stdin
  ip netns exec "$1" python3 -c '
import socket, sys, os
iface = sys.argv[1]
path = next((p for p in ("/var/run/amneziawg/%s.sock" % iface, "/var/run/wireguard/%s.sock" % iface)
             if os.path.exists(p)), None)
if path is None:
    sys.exit("no UAPI socket for " + iface)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(path)
s.sendall(sys.stdin.read().encode())
d = b""
while True:
    b = s.recv(4096)
    if not b: break
    d += b
    if d.endswith(b"\n\n"): break
sys.stdout.write(d.decode())
' "$2"
}

pubkey() { python3 -c '
import sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
k = X25519PrivateKey.from_private_bytes(bytes.fromhex(sys.argv[1]))
print(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
' "$1"; }

wait_sock() {
  local w=0
  while [ ! -e "/var/run/amneziawg/$1.sock" ] && [ ! -e "/var/run/wireguard/$1.sock" ]; do
    sleep 0.2; w=$((w+1)); [ "$w" -ge 60 ] && return 1
  done
  # Explicit: otherwise the loop's last test is the status, and a socket that
  # took one poll to appear reads as one that never did.
  return 0
}

build_underlay() {
  ip netns add "$NS_R" || return 1; OWNED_NS+=("$NS_R")
  ip netns add "$NS_I" || return 1; OWNED_NS+=("$NS_I")
  ip link add "$VETH_R" type veth peer name "$VETH_I" || return 1
  OWNED_LINKS+=("$VETH_R" "$VETH_I")
  ip link set "$VETH_R" netns "$NS_R" || return 1
  ip link set "$VETH_I" netns "$NS_I" || return 1
  ip netns exec "$NS_R" ip link set lo up || return 1
  ip netns exec "$NS_I" ip link set lo up || return 1
  ip netns exec "$NS_R" ip addr add "$RESP_LINK/30" dev "$VETH_R" || return 1
  ip netns exec "$NS_I" ip addr add "$INIT_LINK/30" dev "$VETH_I" || return 1
  ip netns exec "$NS_R" ip link set "$VETH_R" up || return 1
  ip netns exec "$NS_I" ip link set "$VETH_I" up || return 1
  ip netns exec "$NS_I" ping -c1 -w 5 -q "$RESP_LINK" >/dev/null 2>&1 || {
    echo "underlay ping failed; the link is broken, not the tunnel"; return 1; }
}

# Record every UDP datagram on the responder's veth that involves $PORT, as
# "<in|out> <udp payload length> <hex of the first 256 payload bytes>" lines,
# until killed. A raw AF_PACKET socket rather than tcpdump, so the harness needs
# nothing beyond python3.
start_sniffer() { # <outfile>
  ip netns exec "$NS_R" python3 -u -c '
import socket, struct, sys
port, iface = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
s.bind((iface, 0))
while True:
    f = s.recv(65535)
    if len(f) < 14 + 20 + 8 or f[12:14] != b"\x08\x00":
        continue
    ip = f[14:]
    if ip[9] != 17:
        continue
    ihl = (ip[0] & 0x0f) * 4
    sport, dport, ulen = struct.unpack("!HHH", ip[ihl:ihl + 6])
    head = ip[ihl + 8:ihl + 8 + 256].hex()
    if dport == port:
        print("in", ulen - 8, head, flush=True)
    elif sport == port:
        print("out", ulen - 8, head, flush=True)
' "$PORT" "$VETH_R" >"$1" 2>/dev/null &
  SNIFFER=$!
  sleep 0.3
}

# $1 = which implementation responds (go|bt); $2 = the AmneziaWG block.
start_leg() {
  local resp_impl=$1 block=$2
  teardown
  build_underlay || return 1
  R_KEY=$(genkey); I_KEY=$(genkey)
  R_PUB=$(pubkey "$R_KEY"); I_PUB=$(pubkey "$I_KEY")

  launch() { # <ns> <iface> <impl> <log>
    own_socks "$2"
    if [ "$3" = go ]; then
      ip netns exec "$1" env LOG_LEVEL=verbose "$GO" -f "$2" >"$4" 2>&1 &
    else
      ip netns exec "$1" env WG_LOG_FILE="$4" WG_LOG_LEVEL=debug \
        "$BT" --disable-drop-privileges "$2" >/dev/null 2>&1
    fi
  }
  local init_impl=bt; [ "$resp_impl" = bt ] && init_impl=go
  R_LOG="$WORKDIR/resp-$resp_impl.log"; I_LOG="$WORKDIR/init-$init_impl.log"
  launch "$NS_R" "$IF_R" "$resp_impl" "$R_LOG"
  launch "$NS_I" "$IF_I" "$init_impl" "$I_LOG"
  wait_sock "$IF_R" || { echo "responder socket never appeared: $(tail -5 "$R_LOG" 2>/dev/null | tr '\n' ' ')"; return 1; }
  wait_sock "$IF_I" || { echo "initiator socket never appeared: $(tail -5 "$I_LOG" 2>/dev/null | tr '\n' ' ')"; return 1; }

  local rset="$WORKDIR/rset" iset="$WORKDIR/iset"
  uapi "$NS_R" "$IF_R" >"$rset" <<EOF
set=1
private_key=$R_KEY
listen_port=$PORT
${block}
public_key=$I_PUB
allowed_ip=$INIT_TUN/32

EOF
  uapi "$NS_I" "$IF_I" >"$iset" <<EOF
set=1
private_key=$I_KEY
listen_port=51821
${block}
public_key=$R_PUB
endpoint=$RESP_LINK:$PORT
persistent_keepalive_interval=5
allowed_ip=$RESP_TUN/32

EOF
  grep -q '^errno=0$' "$rset" || { echo "responder set=1 failed: $(cat "$rset")"; return 1; }
  grep -q '^errno=0$' "$iset" || { echo "initiator set=1 failed: $(cat "$iset")"; return 1; }

  CAPTURE="$WORKDIR/capture-$RANDOM"
  start_sniffer "$CAPTURE"

  ip netns exec "$NS_R" sh -c "ip addr add $RESP_TUN/24 dev $IF_R && ip link set $IF_R up mtu 1420" || return 1
  ip netns exec "$NS_I" sh -c "ip addr add $INIT_TUN/32 dev $IF_I && ip link set $IF_I up mtu 1420 && ip route add $RESP_TUN/32 dev $IF_I" || return 1
}

handshake_time() { # -> the responder's last_handshake_time_sec, or 0
  local hs
  hs=$(uapi "$NS_R" "$IF_R" <<< $'get=1\n\n' | grep '^last_handshake_time_sec=' | head -1 | cut -d= -f2)
  case "${hs:-}" in ""|*[!0-9]*) hs=0 ;; esac
  echo "$hs"
}

wait_handshake() { # [after] -> 0 once the responder records one newer than $1
  local after=${1:-0} hs
  for _ in $(seq 1 60); do
    hs=$(handshake_time)
    [ "$hs" -gt "$after" ] && return 0
    sleep 0.5
  done
  return 1
}

# Judge the captured wire. Prints one reason per violation; silent on success.
#
# Each datagram is classified by its message-type tag, read at each kind's own
# S offset -- through the header-protection keystream when a key is set -- the
# same way a receiver reads it. The H values are single tags, so a match is not
# a guess. Only the kinds matter here: initiations (in), responses (out), and
# transport either way.
judge_wire() { # <rt 0|1> <hp 0|1> <capture>
  python3 - "$1" "$2" "$3" "$S1" "$S2" "$S4" "$H1" "$H2" "$H4" "$HP_KEY" \
    "$INIT_SZ" "$RESP_SZ" "$DATA_MIN" <<'PY'
import struct, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

rt, hp = sys.argv[1] == "1", sys.argv[2] == "1"
rows = [l.split() for l in open(sys.argv[3]) if l.strip()]
s1, s2, s4, h1, h2, h4 = map(int, sys.argv[4:10])
key = bytes.fromhex(sys.argv[10])
init_sz, resp_sz, data_min = map(int, sys.argv[11:14])


def tag_at(head, offset):
    if len(head) < offset + 4:
        return None
    tag = bytearray(head[offset:offset + 4])
    if hp:
        # IETF ChaCha20 (32-bit counter, 12-byte nonce): the 16-byte IV is the
        # little-endian counter, 0, then the datagram's first 12 bytes.
        ks = Cipher(algorithms.ChaCha20(key, b"\0" * 4 + head[:12]), mode=None).encryptor()
        mask = ks.update(b"\0" * 4)
        tag = bytearray(t ^ m for t, m in zip(tag, mask))
    return struct.unpack("<I", bytes(tag))[0]


inits, resps, transport = [], [], []
for direction, n, head in rows:
    n, head = int(n), bytes.fromhex(head)
    if direction == "in" and n >= s1 + init_sz and tag_at(head, s1) == h1:
        inits.append(n)
    elif direction == "out" and n >= s2 + resp_sz and tag_at(head, s2) == h2:
        resps.append(n)
    elif n >= s4 + data_min and tag_at(head, s4) == h4:
        transport.append(n)

init_base, resp_base = s1 + init_sz, s2 + resp_sz
problems = []
if not inits or not resps:
    problems.append("no handshake recognised on the wire (%d datagrams)" % len(rows))
if not transport:
    problems.append("no transport recognised on the wire")
if rt:
    if all(n == init_base for n in inits) and all(n == resp_base for n in resps):
        problems.append("RandomTrailers on, yet no handshake message had a suffix: %r %r" % (inits, resps))
    if len(set(transport)) < 3:
        problems.append("RandomTrailers on, yet transport sizes barely vary: %r" % sorted(set(transport)))
else:
    if any(n != init_base for n in inits) or any(n != resp_base for n in resps):
        problems.append("RandomTrailers off, yet a handshake message was not exact: %r %r" % (inits, resps))
for problem in problems:
    print(problem)
print("inits=%r resps=%r distinct transport sizes=%d" % (inits, resps, len(set(transport))), file=sys.stderr)
PY
}

run_leg() { # <label> <resp impl go|bt> <rt> <cpa> <hp>
  local label=$1 resp=$2 rt=$3 cpa=$4 hp=$5
  local init=bt; [ "$resp" = bt ] && init=go
  info "$label: $init initiates, $resp responds (rt=$rt cpa=$cpa hp=$hp)"
  if ! start_leg "$resp" "$(awg_block "$rt" "$cpa" "$hp")"; then
    bad "$label: setup failed -- not an interop result"; return
  fi
  ip netns exec "$NS_I" ping -c2 -w 10 -q "$RESP_TUN" >/dev/null 2>&1
  if wait_handshake 0; then
    ok "$label: handshake"
  else
    bad "$label: no handshake"
    echo "    resp: $(tail -3 "$R_LOG" 2>/dev/null | tr '\n' ' ')"
    echo "    init: $(tail -3 "$I_LOG" 2>/dev/null | tr '\n' ' ')"
    kill "$SNIFFER" 2>/dev/null; return
  fi
  if ip netns exec "$NS_I" ping -c5 -i 0.3 -w 10 -q "$RESP_TUN" >/dev/null 2>&1 &&
     ip netns exec "$NS_R" ping -c5 -i 0.3 -w 10 -q "$INIT_TUN" >/dev/null 2>&1; then
    ok "$label: traffic both directions"
  else
    bad "$label: handshake but no traffic"
  fi
  # Keep traffic flowing past rekey_after_time so the initiator rekeys.
  local first; first=$(handshake_time)
  ip netns exec "$NS_I" ping -c 30 -i 0.6 -w 25 -q "$RESP_TUN" >/dev/null 2>&1 &
  local pinger=$!
  if wait_handshake "$first"; then
    ok "$label: second handshake (rekey)"
  else
    bad "$label: no second handshake after rekey_after_time"
  fi
  kill "$pinger" 2>/dev/null; wait "$pinger" 2>/dev/null
  kill "$SNIFFER" 2>/dev/null; wait "$SNIFFER" 2>/dev/null
  local verdict
  verdict=$(judge_wire "$rt" "$hp" "$CAPTURE" 2>"$WORKDIR/judge.txt")
  if [ -z "$verdict" ]; then
    ok "$label: wire shape ($(cat "$WORKDIR/judge.txt"))"
  else
    bad "$label: wire shape -- $verdict"
  fi
}

echo "boringtun    : $BT"
echo "amneziawg-go : $GO ($PINNED_VERSION, $PINNED_COMMIT)"
echo "S1..S4       : $S1 $S2 $S3 $S4"
echo

for cfg in "0 0 0" "0 1 0" "1 0 0" "1 1 0" "1 1 1"; do
  set -- $cfg
  name="rt=$1 cpa=$2 hp=$3"
  run_leg "[$name] go->bt" bt "$1" "$2" "$3"
  run_leg "[$name] bt->go" go "$1" "$2" "$3"
done

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32mSUMMARY: all %d checks passed\033[0m\n' "$PASS"; exit 0
else
  printf '\033[31mSUMMARY: %d passed, %d FAILED\033[0m\n' "$PASS" "$FAIL"; exit 1
fi
