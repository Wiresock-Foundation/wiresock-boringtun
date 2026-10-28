# Required fwmark: proposed contract

Status: design proposal for #110, not an implemented option or an approved
supervisor integration. Existing `fwmark=` behavior remains unchanged.

## Purpose

Some supervisors depend on a particular mark to route encrypted UDP traffic and
avoid routing loops or unintended egress. The existing UAPI can return an error
while the engine continues running. Its initial sockets have no mark, and a
failed live update can leave different sockets with different marks. Ordering
the `fwmark=` key first cannot close either gap.

## Recommended interface and lifecycle

Propose a Linux-only startup option `--require-fwmark=<u32>` and an equivalent
library setting. Requiring the expected value at startup is preferable to a
boolean that waits for an unspecified future UAPI update. The value would be
immutable for the device lifetime. The default would preserve existing behavior.
Whether zero should be accepted as an explicitly required unmarked state, or
rejected to require a nonzero routing mark, remains an API decision.

Prepare the TUN/UAPI and establish the final credentials first. Create every
network-facing socket with the required mark before binding, connecting,
registering it for packet dispatch or starting workers. Check every relevant
socket operation. Initial failure returns an error without starting packet
processing; no unmarked listener or probe responder is published. The supervisor
must retain its external egress gate until startup and configuration succeed.

For later listener rebinds and connected-peer upgrades, apply and verify the same
mark on candidate sockets before making them usable. A failed candidate must
close. Existing sockets whose required mark remains established may continue
serving traffic; a failed connected upgrade may use only such a listener. If the
required mark on an active socket becomes uncertain, suspend all outbound paths
and terminate with an observable failure. This includes timers, handshakes,
cookie/probe replies, queued data and fallback sends, not only TUN ingress.

In this mode, reject a UAPI request for a different mark before it mutates device
state. Repeating the required value may verify the invariant, but must not use
the current partial-update/rollback path as a safety guarantee. Changing the
required mark should mean replacing the device while the supervisor holds its
egress gate closed. Readiness reporting must identify the expected mark and the
successful initialization generation, not merely repeat the stored UAPI value.

## Decisions before implementation

- Final CLI spelling, library field/API compatibility, and treatment of zero.
- Exact readiness and terminal-error reporting to an inherited-UAPI supervisor.
- The boundary for runtime verification: when socket state is checked, which
  failures trigger suspension, and how all send paths observe suspension.
- Credential provisioning for future marked sockets. No automatic capability
  escalation or retention is implied; Linux SO_MARK needs CAP_NET_ADMIN or,
  since 5.17, CAP_NET_RAW.

A boolean “exit after a refused UAPI mark” would report failure but leave the
initial unmarked interval open. Making live mark changes transactional would
require a separate socket-replacement design: best-effort rollback of socket
options is insufficient. The immutable startup value avoids both contracts.

## Required verification

Use disposable test environments to prove that initial failures send no UDP;
accepted marked startup sends only with the required mark; failed rebinds and
connected upgrades cannot expose an unmarked candidate; and every send path
observes terminal suspension. Include IPv4/IPv6, both UAPI modes, privilege
transitions, denied mark operations and failed state reads. Test first startup,
restarts and replacement while the supervisor gate remains closed. The current
`get=1` output alone is not evidence of packet marks.

References: [Linux SO_MARK documentation](https://man7.org/linux/man-pages/man7/socket.7.html),
[issue #110](https://github.com/Wiresock-Foundation/wiresock-boringtun/issues/110),
and the current `set_fwmark`, `restore_marks`, `mark_listener` and
`Peer::connect_endpoint` implementations.
