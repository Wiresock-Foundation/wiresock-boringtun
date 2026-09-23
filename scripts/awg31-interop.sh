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
# The script refuses a binary built from anything else: `go version -m` must
# report the module path, the tag, `vcs.revision` equal to that commit, and
# `vcs.modified=false`. A build without VCS metadata is refused too, since it
# cannot prove its revision. `--check-go <binary>` runs that check alone.
#
# For each configuration below, and for BOTH roles -- amneziawg-go initiating
# to boringtun, and boringtun initiating to amneziawg-go -- it checks:
#
#   * the handshake completes and traffic passes in both directions;
#   * a rekey (forced by a short rekey_after_time) completes on BOTH peers --
#     each one's own last-handshake time advances -- with the traffic that
#     spans it and the traffic after it both getting through;
#   * the wire, read off the responder's veth with a raw socket and judged by
#     scripts/awg31-wire-check.py, PER SENDER: exact handshake sizes with
#     RandomTrailers off; with it on, each implementation's own handshake
#     messages carry suffixes and, without content padding, its own transport
#     varies; every datagram within the bounds the configuration allows; and
#     after the rekey, both directions sending on the new session;
#   * each daemon accepted the configuration's `disable_cookies` and reports
#     it back in a `get=1` that itself succeeded -- exit 0, a well-formed dump,
#     `errno=0` -- as `disable_cookies=1` exactly when it was set.
#
# The DisableCookies legs run the ordinary profile with the flag on at both
# ends -- alone, with RandomTrailers, and with everything -- and hold them to
# every check above: the flag must not disturb the handshake, the traffic, the
# rekey or the wire.
#
# `--self-test` checks the checker and the verdict plumbing against synthetic
# inputs, including ones that must fail; it needs no root and no binaries.
#
# With AWG31_EVIDENCE_DIR set, a run keeps what a reviewer needs to check its
# result independently -- the `go version -m` output, and per leg the capture,
# the checker's verdict and summary, both daemons' logs and the rekey figures --
# in that directory, which must not already exist. Without it, everything is
# removed on exit as before.
#
# The S sizes are deliberately unequal, so the receive side's candidate
# readings genuinely differ per packet kind. What this does NOT cover:
# anything that needs a responder under load, because neither implementation
# can be put there deterministically from outside without flooding it -- the
# cookie reply's trailer (`noise::random_trailers_tests`) and DisableCookies'
# actual bypass of the cookie defense (`noise::disable_cookies_tests`, which
# starve the limiter instead); and WireSock's CPA policy with RandomTrailers
# off, which cannot be told apart on the wire from inside a single run and is
# pinned by `amnezia::tests` with concrete values.
#
# Requires: root, iproute2, python3 with `cryptography`, ping, a built
# boringtun-cli, and the amneziawg-go above. Everything lives in throwaway
# network namespaces prefixed `a31-`; cleanup runs on every exit path.
#
# Usage: awg31-interop.sh <boringtun-cli> <amneziawg-go v3.1.20260828>
#        awg31-interop.sh --check-go <amneziawg-go>
#        awg31-interop.sh --self-test
set -uo pipefail

readonly PINNED_MODULE=github.com/amnezia-vpn/amneziawg-go/v3
readonly PINNED_COMMIT=b5928efb6ca19f0153958460c3d141f04abc5c2e
readonly PINNED_VERSION=v3.1.20260828
readonly CHECKER="$(cd "$(dirname "$0")" && pwd)/awg31-wire-check.py"

MODE=run
case "${1:-}" in
  --self-test) MODE=self-test ;;
  --check-go) MODE=check-go; GO=${2:?path to amneziawg-go} ;;
  *)
    BT=${1:?path to boringtun-cli}
    GO=${2:?path to amneziawg-go v3.1.20260828}
    ;;
esac

PORT=51820
RESP_TUN=10.78.0.1; INIT_TUN=10.78.0.2
RESP_LINK=10.56.0.1; INIT_LINK=10.56.0.2

# Unequal on purpose: every packet kind sits at its own offset.
readonly JC=2 JMIN=40 JMAX=90
readonly S1=40 S2=24 S3=32 S4=160
readonly H1=169887817 H2=390382747 H3=1033691040 H4=1526332224
readonly HP_KEY=5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
readonly INIT_SZ=148 RESP_SZ=92 DATA_MIN=32
# amneziawg-go's DefaultUdpWindow. Every frame this harness sends is a ping or a
# keepalive, small enough that neither implementation's window grows past it, so
# it bounds every handshake message (below it) and every transport frame (at
# most it) the checker sees.
readonly WINDOW=500

awg_block() { # <rt 0|1> <cpa 0|1> <hp 0|1> <dc 0|1>
  local b
  b=$'jc='"$JC"$'\njmin='"$JMIN"$'\njmax='"$JMAX"$'\ns1='"$S1"$'\ns2='"$S2"$'\ns3='"$S3"$'\ns4='"$S4"$'\nh1='"$H1"$'\nh2='"$H2"$'\nh3='"$H3"$'\nh4='"$H4"$'\n'
  # A short rekey, so each leg sees a second handshake inside its run time.
  b+=$'rekey_after_time=12\n'
  [ "$1" = 1 ] && b+=$'random_trailers=1\n'
  [ "$2" = 1 ] && b+=$'content_padding_addition=8-120\n'
  [ "$3" = 1 ] && b+=$'header_protection_key='"$HP_KEY"$'\n'
  [ "$4" = 1 ] && b+=$'disable_cookies=1\n'
  printf '%s' "$b"
}

genkey() { head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# Is this `go version -m` output the pinned build? Prints the reason and fails
# if not; silent success. Missing VCS metadata is a refusal: without it the
# binary cannot prove which commit it was built from.
go_pin_verdict() { # metadata on stdin
  awk -v want_mod="$PINNED_MODULE" -v want_ver="$PINNED_VERSION" -v want_rev="$PINNED_COMMIT" '
    $1 == "mod" { mod = $2; ver = $3 }
    $1 == "build" && index($2, "vcs.revision=") == 1 { rev = substr($2, 14) }
    $1 == "build" && index($2, "vcs.modified=") == 1 { modified = substr($2, 14) }
    END {
      if (mod != want_mod) { print "module is \"" mod "\", not " want_mod; exit 1 }
      if (ver != want_ver) { print "version is \"" ver "\", not " want_ver; exit 1 }
      if (rev == "") {
        print "no vcs.revision in the build metadata (built with -buildvcs=false, or"
        print "outside the git checkout), so the commit cannot be proven; rebuild in a"
        print "clean checkout of " want_rev
        exit 1
      }
      if (rev != want_rev) { print "vcs.revision is " rev ", not " want_rev; exit 1 }
      if (modified != "false") { print "vcs.modified is \"" modified "\": the tree was not clean"; exit 1 }
    }'
}

check_go() {
  command -v go >/dev/null 2>&1 ||
    { echo "go is needed to read the build metadata (go version -m)"; return 1; }
  local meta
  meta=$(go version -m "$GO" 2>&1) || { echo "go version -m failed: $meta"; return 1; }
  printf '%s\n' "$meta" | go_pin_verdict
}

# Did a rekey complete on both peers? Each one's own last-handshake time must
# have moved: a responder that recorded a handshake the initiator never took
# up has advanced alone, and that is not a completed rekey.
rekey_verdict() { # <resp before> <resp after> <init before> <init after>
  [ "$2" -gt "$1" ] && [ "$4" -gt "$3" ]
}

# 0 when one daemon's `get=1` succeeded and reports DisableCookies as it was
# configured. The response is on stdin; <status> is the exit status of the
# command that fetched it.
#
# The state is read only from a response that proves it is one: the fetch
# exited 0, every line is `key=value`, the dump carries the `listen_port`
# every leg sets, and it ends in `errno=0` -- the UAPI's own success marker.
# Without that, "no `disable_cookies=1`" would read a refused request, an
# empty reply or a daemon that never answered as DisableCookies being off.
#
# Then: on requires the line `disable_cookies=1`; off requires its absence
# (boringtun omits the key) or `disable_cookies=0` (amneziawg-go prints it
# unconditionally), and nothing else.
dc_get_verdict() { # <want 0|1> <status>; get=1 response on stdin
  local want=$1 status=$2 response
  response=$(cat)
  [ "$status" = 0 ] || { echo "the get=1 request failed (exit $status)"; return 1; }
  [ -n "$response" ] || { echo "empty get=1 response"; return 1; }
  if printf '%s\n' "$response" | grep -v '^$' | grep -qvE '^[a-z0-9_]+=.*$'; then
    echo "malformed get=1 response: $(printf '%s\n' "$response" | grep -v '^$' | grep -vE '^[a-z0-9_]+=' | head -1)"
    return 1
  fi
  local last
  last=$(printf '%s\n' "$response" | grep -v '^$' | tail -1)
  [ "$last" = errno=0 ] || { echo "get=1 did not end in errno=0 (last line: ${last:-none})"; return 1; }
  printf '%s\n' "$response" | grep -qE '^listen_port=[0-9]+$' ||
    { echo "get=1 response carries no listen_port: not an interface dump"; return 1; }
  local dc_lines
  dc_lines=$(printf '%s\n' "$response" | grep '^disable_cookies=' || true)
  if [ "$want" = 1 ]; then
    [ "$dc_lines" = disable_cookies=1 ] ||
      { echo "want disable_cookies=1, got: ${dc_lines:-absent}"; return 1; }
  else
    [ -z "$dc_lines" ] || [ "$dc_lines" = disable_cookies=0 ] ||
      { echo "want disable_cookies off, got: $dc_lines"; return 1; }
  fi
}

# Fetch one daemon's `get=1` into <out>. Returns the fetch's own exit status
# -- `uapi`'s, not that of the `printf` feeding it.
fetch_get() { # <ns> <iface> <out>
  printf 'get=1\n\n' | uapi "$1" "$2" >"$3" 2>&1
  return "${PIPESTATUS[1]}"
}

# Judge BOTH daemons' fetched `get=1` for one leg, each on its own. Prints one
# `PASS|FAIL<tab>responder|initiator<tab>detail` line per daemon and returns 0
# only when both pass. The live leg turns each line into its own assertion;
# the self-test drives the same function, so dropping a daemon from it fails
# there.
judge_dc_daemons() { # <want 0|1> <resp status> <resp file> <init status> <init file>
  local want=$1 rc=0 who status file why
  for who in responder initiator; do
    if [ "$who" = responder ]; then status=$2 file=$3; else status=$4 file=$5; fi
    if why=$(dc_get_verdict "$want" "$status" <"$file"); then
      printf 'PASS\t%s\t%s\n' "$who" "$(grep '^disable_cookies=' "$file" || echo 'disable_cookies absent'), errno=0"
    else
      printf 'FAIL\t%s\t%s\n' "$who" "$why"
      rc=1
    fi
  done
  return $rc
}

# Judge a capture with the wire checker. Only its exit status decides: 0 is a
# pass; a violation (1) or a checker failure (2, an exception or a malformed
# capture) is not. Output goes to files for the caller to show.
judge_leg() { # <capture> <rt> <cpa> <hp> <in-sender> <out-sender> <out> <err>
  local key=()
  [ "$4" = 1 ] && key=(--hp-key "$HP_KEY")
  python3 "$CHECKER" --capture "$1" --rt "$2" --cpa "$3" "${key[@]}" \
    --in-sender "$5" --out-sender "$6" \
    --s "$S1,$S2,$S3,$S4" --h "$H1,$H2,$H3,$H4" --window "$WINDOW" --jmax "$JMAX" \
    >"$7" 2>"$8"
}

umask 077
WORKDIR=$(mktemp -d /tmp/awg31-interop.XXXXXX) || { echo "no temp dir" >&2; exit 2; }
readonly WORKDIR
RUN=${WORKDIR##*.}
NS_R="a31-r-$RUN"; NS_I="a31-i-$RUN"
IF_R="a31r-$RUN";  IF_I="a31i-$RUN"
VETH_R="a31-vr-$RUN"; VETH_I="a31-vi-$RUN"
readonly RUN NS_R NS_I IF_R IF_I VETH_R VETH_I

PASS=0; FAIL=0
R_GET=; I_GET=
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

self_test() {
  local failures=0
  expect() { # <name> <want status> <command...>
    local name=$1 want=$2; shift 2
    "$@" >"$WORKDIR/st.out" 2>&1
    local got=$?
    if { [ "$want" = 0 ] && [ "$got" -eq 0 ]; } || { [ "$want" = fail ] && [ "$got" -ne 0 ]; }; then
      ok "self-test: $name"
    else
      bad "self-test: $name (status $got, wanted $want): $(head -3 "$WORKDIR/st.out" | tr '\n' ' ')"
      failures=$((failures + 1))
    fi
  }
  local meta_ok
  meta_ok=$(printf '%s\n' \
    "x: go1.27.1" \
    "	path	$PINNED_MODULE" \
    "	mod	$PINNED_MODULE	$PINNED_VERSION	" \
    "	build	vcs=git" \
    "	build	vcs.revision=$PINNED_COMMIT" \
    "	build	vcs.modified=false")
  expect "the pinned build is accepted" 0 go_pin_verdict <<<"$meta_ok"
  expect "a wrong revision is refused" fail go_pin_verdict \
    <<<"${meta_ok/$PINNED_COMMIT/da11c9f0000000000000000000000000000000000}"
  expect "a modified tree is refused" fail go_pin_verdict \
    <<<"${meta_ok/vcs.modified=false/vcs.modified=true}"
  expect "missing VCS metadata is refused" fail go_pin_verdict \
    <<<"$(printf '%s\n' "$meta_ok" | grep -v vcs)"
  expect "a different tag is refused" fail go_pin_verdict \
    <<<"${meta_ok/$PINNED_VERSION/v3.1.20260812}"

  expect "a rekey both peers took up passes" 0 rekey_verdict 100 113 100 113
  expect "a rekey only the responder recorded fails" fail rekey_verdict 100 113 100 100
  expect "a rekey only the initiator recorded fails" fail rekey_verdict 100 100 100 113
  expect "no rekey fails" fail rekey_verdict 100 100 100 100

  # get=1 dumps shaped like each implementation's: amneziawg-go prints both
  # 3.1 bools unconditionally, boringtun only when on.
  local go_on go_off bt_on bt_off
  go_on=$'private_key=aa\nlisten_port=51820\nrandom_trailers=1\ndisable_cookies=1\npublic_key=bb\nerrno=0\n'
  go_off=$'private_key=aa\nlisten_port=51820\nrandom_trailers=0\ndisable_cookies=0\npublic_key=bb\nerrno=0\n'
  bt_on=$'own_public_key=cc\nlisten_port=51821\ns1=40\ndisable_cookies=1\npublic_key=dd\nerrno=0\n'
  bt_off=$'own_public_key=cc\nlisten_port=51821\ns1=40\npublic_key=dd\nerrno=0\n'
  expect "dc=1: amneziawg-go dump passes" 0 dc_get_verdict 1 0 <<<"$go_on"
  expect "dc=1: boringtun dump passes" 0 dc_get_verdict 1 0 <<<"$bt_on"
  expect "dc=0: amneziawg-go dump (=0) passes" 0 dc_get_verdict 0 0 <<<"$go_off"
  expect "dc=0: boringtun dump (absent) passes" 0 dc_get_verdict 0 0 <<<"$bt_off"
  expect "dc=1 but the key is missing fails" fail dc_get_verdict 1 0 <<<"$bt_off"
  expect "dc=1 but reported =0 fails" fail dc_get_verdict 1 0 <<<"$go_off"
  expect "dc=0 but reported =1 fails" fail dc_get_verdict 0 0 <<<"$bt_on"
  expect "dc=0 but reported =1 (amneziawg-go) fails" fail dc_get_verdict 0 0 <<<"$go_on"
  expect "dc=0 with a failed get=1 fails" fail dc_get_verdict 0 1 <<<"$bt_off"
  expect "dc=0 with an empty response fails" fail dc_get_verdict 0 0 <<<''
  expect "dc=0 with errno=22 fails" fail dc_get_verdict 0 0 <<<$'errno=22\n'
  expect "dc=0 with an otherwise good dump ending errno=22 fails" fail dc_get_verdict 0 0 \
    <<<"${bt_off/errno=0/errno=22}"
  expect "dc=0 with a truncated dump (no errno) fails" fail dc_get_verdict 0 0 \
    <<<"${bt_off%errno=0*}"
  expect "dc=0 with a malformed line fails" fail dc_get_verdict 0 0 \
    <<<$'listen_port=51820\nno socket for a31r\nerrno=0\n'
  expect "dc=0 with only errno=0 (no interface dump) fails" fail dc_get_verdict 0 0 <<<$'errno=0\n'
  expect "dc=1 with a second, contradicting line fails" fail dc_get_verdict 1 0 \
    <<<"${go_on/public_key=bb/disable_cookies=0}"
  # The fetch's own status is what reaches the verdict: a daemon with no
  # socket (here, no namespace at all) is a failed fetch, not a pass.
  expect "a get=1 fetch that cannot reach the daemon exits nonzero" fail \
    fetch_get "a31-selftest-no-such-ns" "a31-none" "$WORKDIR/st.get"
  fetch_get "a31-selftest-no-such-ns" "a31-none" "$WORKDIR/st.get"
  local fetched=$?
  expect "that failed fetch fails the leg even for dc=0" fail judge_dc_daemons 0 \
    "$fetched" "$WORKDIR/st.get" 0 <(printf '%s' "$go_off")
  # Both daemons are judged, each on its own: one right and one wrong is a
  # failed leg whichever way round.
  expect "only the responder right fails the leg" fail judge_dc_daemons 1 \
    0 <(printf '%s' "$bt_on") 0 <(printf '%s' "$go_off")
  expect "only the initiator right fails the leg" fail judge_dc_daemons 1 \
    0 <(printf '%s' "$bt_off") 0 <(printf '%s' "$go_on")
  expect "only the initiator's fetch failing fails the leg" fail judge_dc_daemons 0 \
    0 <(printf '%s' "$bt_off") 1 <(printf '%s' "$go_off")
  expect "both right passes the leg" 0 judge_dc_daemons 1 \
    0 <(printf '%s' "$bt_on") 0 <(printf '%s' "$go_on")

  # The verdict plumbing: a checker that throws, or cannot parse the capture,
  # must fail the leg -- empty output is not a pass.
  printf 'in not-a-number zz\n' >"$WORKDIR/bad.capture"
  expect "a malformed capture fails the leg" fail \
    judge_leg "$WORKDIR/bad.capture" 1 0 0 go rust "$WORKDIR/j.out" "$WORKDIR/j.err"
  expect "a missing capture fails the leg" fail \
    judge_leg "$WORKDIR/nonexistent" 1 0 0 go rust "$WORKDIR/j.out" "$WORKDIR/j.err"
  : >"$WORKDIR/empty.capture"
  expect "an empty capture fails the leg" fail \
    judge_leg "$WORKDIR/empty.capture" 1 0 0 go rust "$WORKDIR/j.out" "$WORKDIR/j.err"

  # And the checker's own synthetic captures, positive and negative.
  expect "wire checker self-test" 0 python3 "$CHECKER" --self-test
  [ "$failures" -eq 0 ] || sed 's/^/    /' "$WORKDIR/st.out"
  echo
  if [ "$failures" -eq 0 ]; then
    printf '\033[32mSELF-TEST: all %d passed\033[0m\n' "$PASS"; exit 0
  fi
  printf '\033[31mSELF-TEST: %d FAILED\033[0m\n' "$failures"; exit 1
}

case "$MODE" in
  self-test) self_test ;;
  check-go)
    if reason=$(check_go); then echo "amneziawg-go is the pinned $PINNED_VERSION ($PINNED_COMMIT)"; exit 0; fi
    printf 'refused: %s\n' "$reason"; exit 1 ;;
esac

[ "$(id -u)" -eq 0 ] || die "must run as root (creates network namespaces)"
[ -x "$BT" ] || die "boringtun-cli not found or not executable: $BT"
[ -x "$GO" ] || die "amneziawg-go not found or not executable: $GO"
[ -f "$CHECKER" ] || die "wire checker not found: $CHECKER"
reason=$(check_go) || die "amneziawg-go is not the pinned build: $reason"

EVIDENCE=${AWG31_EVIDENCE_DIR:-}
if [ -n "$EVIDENCE" ]; then
  [ -e "$EVIDENCE" ] && die "AWG31_EVIDENCE_DIR $EVIDENCE already exists; refusing to mix runs"
  mkdir -p "$EVIDENCE" || die "cannot create $EVIDENCE"
  {
    echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "boringtun-cli: $BT"
    echo "amneziawg-go: $GO"
    echo "S1..S4: $S1 $S2 $S3 $S4   H1..H4: $H1 $H2 $H3 $H4   window: $WINDOW"
    echo
    go version -m "$GO"
  } >"$EVIDENCE/meta.txt"
fi

# Copy one leg's artifacts into the evidence directory, when there is one.
keep_leg() { # <slug> <summary line>...
  [ -n "$EVIDENCE" ] || return 0
  local slug=$1 d; shift
  d="$EVIDENCE/$slug"
  mkdir -p "$d"
  printf '%s\n' "$@" >"$d/summary.txt"
  cp "$CAPTURE" "$d/capture.txt" 2>/dev/null
  cp "$WORKDIR/judge.out" "$d/judge.stdout.txt" 2>/dev/null
  cp "$WORKDIR/judge.err" "$d/judge.stderr.txt" 2>/dev/null
  cp "$R_LOG" "$d/responder.log" 2>/dev/null
  cp "$I_LOG" "$d/initiator.log" 2>/dev/null
  cp "$R_GET" "$d/responder.get.txt" 2>/dev/null
  cp "$I_GET" "$d/initiator.get.txt" 2>/dev/null
  return 0
}

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

  # Capture from before either peer is configured: amneziawg-go initiates the
  # moment `set=1` hands it a peer with an endpoint and a persistent
  # keepalive, before the interface is even up, so a sniffer started any
  # later misses the first handshake.
  CAPTURE="$WORKDIR/capture-$RANDOM"
  start_sniffer "$CAPTURE"

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

  ip netns exec "$NS_R" sh -c "ip addr add $RESP_TUN/24 dev $IF_R && ip link set $IF_R up mtu 1420" || return 1
  ip netns exec "$NS_I" sh -c "ip addr add $INIT_TUN/32 dev $IF_I && ip link set $IF_I up mtu 1420 && ip route add $RESP_TUN/32 dev $IF_I" || return 1
}

handshake_time() { # <ns> <iface> -> that peer's last_handshake_time_sec, or 0
  local hs
  hs=$(printf 'get=1\n\n' | uapi "$1" "$2" | grep '^last_handshake_time_sec=' | head -1 | cut -d= -f2)
  case "${hs:-}" in ""|*[!0-9]*) hs=0 ;; esac
  echo "$hs"
}

# 0 once BOTH peers record a handshake newer than their own $1 / $2.
wait_both_handshakes() { # <resp after> <init after>
  for _ in $(seq 1 70); do
    rekey_verdict "$1" "$(handshake_time "$NS_R" "$IF_R")" \
      "$2" "$(handshake_time "$NS_I" "$IF_I")" && return 0
    sleep 0.5
  done
  return 1
}

run_leg() { # <label> <resp impl go|bt> <rt> <cpa> <hp> <dc>
  local label=$1 resp=$2 rt=$3 cpa=$4 hp=$5 dc=$6
  local init=bt; [ "$resp" = bt ] && init=go
  # The names the wire checker attributes each direction to.
  local in_sender=rust out_sender=rust
  [ "$init" = go ] && in_sender=go
  [ "$resp" = go ] && out_sender=go
  info "$label: $init initiates, $resp responds (rt=$rt cpa=$cpa hp=$hp dc=$dc)"
  if ! start_leg "$resp" "$(awg_block "$rt" "$cpa" "$hp" "$dc")"; then
    bad "$label: setup failed -- not an interop result"; return
  fi
  # Both daemons took the configuration -- `set=1` answered errno=0 in
  # `start_leg` -- and each reports DisableCookies as it was set, in a get=1
  # that itself succeeded. One assertion per daemon.
  R_GET="$WORKDIR/r.get"; I_GET="$WORKDIR/i.get"
  local r_status i_status verdict who detail impl dc_line="disable_cookies get=1:"
  fetch_get "$NS_R" "$IF_R" "$R_GET"; r_status=$?
  fetch_get "$NS_I" "$IF_I" "$I_GET"; i_status=$?
  while IFS=$'\t' read -r verdict who detail; do
    impl=$init; [ "$who" = responder ] && impl=$resp
    if [ "$verdict" = PASS ]; then
      ok "$label: $who ($impl) accepted disable_cookies=$dc and reports it ($detail)"
    else
      bad "$label: $who ($impl) disable_cookies=$dc: $detail"
    fi
    dc_line+=" $who $verdict ($detail);"
  done < <(judge_dc_daemons "$dc" "$r_status" "$R_GET" "$i_status" "$I_GET")
  # A nudge to start the handshake; its status is not the assertion.
  ip netns exec "$NS_I" ping -c2 -w 10 -q "$RESP_TUN" >/dev/null 2>&1
  if wait_both_handshakes 0 0; then
    ok "$label: handshake (both peers)"
  else
    bad "$label: no handshake on both peers"
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

  # The rekey. Traffic runs past rekey_after_time so the initiator rekeys; it
  # must succeed throughout (every ping answered), both peers must record the
  # new handshake, and traffic must pass in both directions afterwards. The
  # wire checker then shows both directions actually sending on the new
  # session.
  local r0 i0 r1 i1 ping_rc
  r0=$(handshake_time "$NS_R" "$IF_R"); i0=$(handshake_time "$NS_I" "$IF_I")
  ip netns exec "$NS_I" ping -c 30 -i 0.6 -w 25 -q "$RESP_TUN" >/dev/null 2>&1 &
  local pinger=$!
  wait_both_handshakes "$r0" "$i0"
  wait "$pinger"; ping_rc=$?
  r1=$(handshake_time "$NS_R" "$IF_R"); i1=$(handshake_time "$NS_I" "$IF_I")
  local rekey_line="rekey: responder $r0->$r1, initiator $i0->$i1, spanning ping exit $ping_rc"
  if ! rekey_verdict "$r0" "$r1" "$i0" "$i1"; then
    bad "$label: rekey not completed on both peers (responder $r0->$r1, initiator $i0->$i1)"
  elif [ "$ping_rc" -ne 0 ]; then
    bad "$label: traffic across the rekey lost packets (ping exit $ping_rc)"
  elif ! ip netns exec "$NS_I" ping -c3 -i 0.3 -w 10 -q "$RESP_TUN" >/dev/null 2>&1 ||
       ! ip netns exec "$NS_R" ping -c3 -i 0.3 -w 10 -q "$INIT_TUN" >/dev/null 2>&1; then
    bad "$label: no traffic after the rekey"
  else
    ok "$label: rekey on both peers (responder $r0->$r1, initiator $i0->$i1), traffic across and after it"
  fi

  kill "$SNIFFER" 2>/dev/null; wait "$SNIFFER" 2>/dev/null
  local jout="$WORKDIR/judge.out" jerr="$WORKDIR/judge.err" wire_verdict
  if judge_leg "$CAPTURE" "$rt" "$cpa" "$hp" "$in_sender" "$out_sender" "$jout" "$jerr"; then
    wire_verdict=PASS
    ok "$label: wire, per sender ($(tail -1 "$jerr"))"
  else
    wire_verdict=FAIL
    bad "$label: wire, per sender:"
    sed 's/^/      /' "$jout" "$jerr"
  fi
  keep_leg "rt$rt-cpa$cpa-hp$hp-dc$dc.$init-initiates" \
    "leg: $label ($init initiates as $in_sender, $resp responds as $out_sender)" \
    "$dc_line" \
    "$rekey_line" \
    "wire: $wire_verdict -- $(tail -1 "$jerr")"
}

echo "boringtun    : $BT"
echo "amneziawg-go : $GO ($PINNED_VERSION, vcs.revision $PINNED_COMMIT, verified)"
echo "S1..S4       : $S1 $S2 $S3 $S4"
echo

# RandomTrailers/CPA/HP with DisableCookies off, then DisableCookies on alone,
# with RandomTrailers, and with everything.
for cfg in "0 0 0 0" "0 1 0 0" "1 0 0 0" "1 1 0 0" "1 1 1 0" "0 0 0 1" "1 0 0 1" "1 1 1 1"; do
  set -- $cfg
  name="rt=$1 cpa=$2 hp=$3 dc=$4"
  run_leg "[$name] go->bt" bt "$1" "$2" "$3" "$4"
  run_leg "[$name] bt->go" go "$1" "$2" "$3" "$4"
done

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32mSUMMARY: all %d checks passed\033[0m\n' "$PASS"; exit 0
else
  printf '\033[31mSUMMARY: %d passed, %d FAILED\033[0m\n' "$PASS" "$FAIL"; exit 1
fi
