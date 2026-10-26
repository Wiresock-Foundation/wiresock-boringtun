# BoringTun artifact helpers

The fork-owned workflow and its remaining activation gates are documented in
[BORINGTUN_MIGRATION.md](BORINGTUN_MIGRATION.md). Exact runtime/native notice
inputs, distribution hashes and inventories are documented in
[BORINGTUN_NOTICES.md](BORINGTUN_NOTICES.md). Publication remains disabled.

`scripts/boringtun-artifact.sh` builds, packages and verifies the five reviewed
targets. Run it without arguments to list commands. It reads the source pin as
strict data, requires an exact clean checkout and preserves the four-member
archive format. Merged-PR and candidate workflows derive their own temporary
pins; the checked-in `packaging/boringtun/pin.env` is a retained historical
reference. Historical sources must satisfy the current source and notice
policy before they can be built: the old pin's license does not satisfy the
new fork-notice requirement. A successful helper command does not authorize
publication or establish release provenance.

The source license gate uses Rust 1.98.1, cargo-deny 0.20.2 and cargo-about 0.9.2,
as selected by the build and candidate workflows. `licenses` checks the exact
source, audits dependencies, generates crate notices and adds the verified
runtime/native profile for the selected target. Missing or unexpected inputs
fail the gate. Install the tools at those exact versions before invoking the
helper locally; the helper itself installs nothing.

`packaging/boringtun/deny.toml` retains the earlier advisory exception for
`RUSTSEC-2025-0069`, the unmaintained `daemonize` 0.5.0 dependency. The documented
exception concerns maintenance status and has no available replacement fix;
WireSock's service invokes the CLI in foreground mode. It does not suppress
other advisories or assert that daemon mode has been validated. Reassess this
exception before activation and remove it when the dependency is replaced.

Candidate CI artifacts have distinct names and no attestations. Release
adoption requires the signed descriptor, exact workflow/run/attempt identity
and complete five-platform contract described in the migration document.
