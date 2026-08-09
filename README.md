# WireSock BoringTun

A WireSock-maintained fork of [Cloudflare BoringTun](https://github.com/cloudflare/boringtun)
with AmneziaWG and WireSock protocol extensions.

BoringTun is a userspace [WireGuard®](https://www.wireguard.com/) implementation in
Rust. This fork keeps that intact and adds obfuscation: the AmneziaWG parameters, and a
protocol-imitation layer of our own.

## What this adds

**AmneziaWG extensions** — the parameters an `awg` configuration carries, on both the initiator
and the responder path:

| | |
|---|---|
| `S1`–`S4` | junk prepended to the initiation, response, cookie reply and transport packets |
| `H1`–`H4` | message-type tag values, as single values or as ranges |
| `Jc`, `Jmin`, `Jmax` | junk packets sent before the handshake |

**WireSock extensions** — beyond what AmneziaWG specifies:

- **Protocol imitation** (`--imitate-protocol dns\|quic\|sip\|stun`). The S-junk is not random
  filler but a well-formed message of the chosen protocol, so the prefix survives a parser
  rather than merely a length check. AmneziaWG implementations fill this with random bytes.
- **A probe responder.** The listen port answers an unsolicited probe with a plausible reply for
  the protocol it imitates — a DNS SERVFAIL, a QUIC Version Negotiation, a STUN Binding Success
  — so a scan sees a service rather than a silent port. Replies are only sent where they are
  truthful for that protocol.
- **A reply budget.** An aggregate ceiling on bytes sent in response to unauthenticated traffic,
  so the responder cannot be used as an amplifier.

Classification order is load-bearing and deliberate: a datagram is matched against the
configured AmneziaWG shapes *before* it is considered as a probe. A DNS-shaped initiation from
one of our own peers is tunnel traffic, not a query to answer.

## Relationship to upstream

Derived from `cloudflare/boringtun` at
[`6dcc889`](https://github.com/cloudflare/boringtun/commit/6dcc889) (2026-06-15), which is the
current upstream `master`. The delta is 24 commits over 42 files.

Upstream's copyright notices are retained on every file that carries them, as the BSD-3-Clause
licence requires. Files added by this fork carry their own.

This fork does not aim to be upstreamed: the obfuscation layer is outside BoringTun's scope.
Upstream fixes are merged in the other direction.

## What this does not claim

- It is **not** the AmneziaWG implementation. It implements the AmneziaWG *extensions* so that
  it interoperates with one; it is not affiliated with, sponsored by, or endorsed by the
  AmneziaWG project.
- It is **not** a Cloudflare product, and is not sponsored or endorsed by Cloudflare.
- The probe responder is a plausibility measure, not a proof against a determined analyst. It
  answers a scan in the shape of the protocol it imitates; it does not claim to defeat traffic
  analysis, timing correlation, or an active prober that knows what to look for.

## Interoperability

Unit tests can only show that our client agrees with our server. Two harnesses in `scripts/`
check the claim that actually matters — that an independent AmneziaWG implementation agrees
with our wire format:

- **`awg-go-interop.sh`** — 5 checks against
  [`amneziawg-go`](https://github.com/amnezia-vpn/amneziawg-go), the reference userspace
  implementation. Needs no kernel module, so it runs anywhere.
- **`awg-interop-poc.sh`** — 8 checks against the AmneziaWG **kernel module** with `awg` from
  amneziawg-tools, covering the kernel datapath and `awg setconf`/`showconf` round-tripping.

Both include a negative control: a vanilla WireGuard server must *fail* to serve an obfuscated
client, or the positive results would prove nothing about the obfuscation.

Both are root-only, create throwaway network namespaces under run-unique names, and remove only
what they created.

## Building

```bash
cargo build --release --bin boringtun-cli --features device
```

The `device` feature — the tunnel, the UAPI and the ingress path — is **unix-only**, so a
Windows build silently excludes it. Feature flags:

| feature | |
|---|---|
| `device` | the userspace tunnel and its UAPI (unix only) |
| `ffi-bindings` | the C API in `src/ffi` |
| `jni-bindings` | the Java Native Interface bindings in `src/jni.rs` |
| `mock-instant` | replaces the clock, for tests that need to control time |

## Running

```bash
boringtun-cli [-f/--foreground] <INTERFACE-NAME>
```

Configure it with `wg`, or with `awg` from amneziawg-tools for the AmneziaWG parameters. The
UAPI socket is published in both `/var/run/wireguard/` and `/var/run/amneziawg/`, because `wg`
searches the first and `awg` the second.

Logging goes to `WG_LOG_FILE` at `WG_LOG_LEVEL`. Note that a daemonised process loses its log
writer — use `--foreground` when you need output.

## Testing

```bash
cargo test --features device
```

CI runs `rustfmt`, `cargo hack check --each-feature`, `cargo hack clippy --each-feature`,
`cargo hack test --each-feature`, the ignored integration tests, and a Windows build.

## License

[3-Clause BSD](https://opensource.org/licenses/BSD-3-Clause), as upstream. Contributions are
licensed the same way unless you state otherwise.

---

<sub>WireGuard is a registered trademark of Jason A. Donenfeld. WireSock BoringTun is not
sponsored or endorsed by Jason A. Donenfeld.</sub>

<sub>BoringTun is a project of Cloudflare, Inc. WireSock BoringTun is an independently
maintained fork and is not sponsored or endorsed by Cloudflare.</sub>

<sub>AmneziaWG is a project of AmneziaVPN. WireSock BoringTun implements its protocol
extensions for interoperability and is not sponsored or endorsed by AmneziaVPN.</sub>
