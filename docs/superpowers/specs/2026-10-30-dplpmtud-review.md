# DPLPMTUD proposal review record

Date: 2026-10-30. Baseline: `ea0f5f85946ed69fcb0ad2f4dadfb46a672e1c0d`.

Scope: [design proposal](2026-10-30-dplpmtud-design.md) and [conditional implementation plan](../plans/2026-10-30-dplpmtud.md). This is a documentation review, not implementation or protocol approval by the owner.

## Initial independent review (commit 88423bb)

A fresh reviewer agent, `/root/dplpmtud_review`, was given the two documents, repository/source baseline, the original request and constraints, and asked to assess correctness, security and implementability. It did not inherit the author's conversation or modify files. It read relevant repository code and checked primary references including RFC 8899, WireGuard's protocol, Linux socket documentation and IPv6 requirements.

The first review found four material issues. A second pass verified their corrections and identified a timer/search interaction. The author addressed all five and requested a final recheck of the resulting text.

| Finding | Resolution and required future test |
| --- | --- |
| P1: recovery to configured 1200 could increase an already-confirmed smaller IPv4 limit after failure | Separate initial base from recovery target. Same-path failure/expiry/rekey never raises operational cap. Task 1 tests confirmed U=1000 with base=1200 through timeout, deferral, idle resume and rekey. |
| P2: local/configured/peer maximum below base could prevent every send, so the transmitted-attempt counter never reached fallback | Initial target is clamped to current maximum; below-floor/mandatory profiles fail explicitly. Task 1 tests maximum U=1000 and invalid lower bounds. |
| P2: confirmation scheduled only after SEARCH could leave size evidence stale during search or rekey | Independent evidence lease applies in SEARCH/COMPLETE and survives rekey; only matched full-size/larger delivery evidence renews it. Task 1 tests mid-search black holes and deadline/rekey races. |
| P2: placing inner-packet processing in Unix Device made Windows FFI reuse impossible | Shared pure parsing/feedback/fragment generation moves to proposed `pmtu/inner.rs`; Device/host owns addressing/injection. Task 3 runs without Device on Windows and Unix; FFI input/quote lifetimes are explicit. |
| P2: 30-second maintenance could repeatedly interrupt the three 16-second candidate attempts | Due confirmation blocks new upward attempts; accepted current attempt may finish within the evidence lease. Completed candidate timeouts survive maintenance/rekey; cancellation adds no loss. Task 1 checks eventual completion, counter preservation and the explicitly conditioned five-sends-per-candidate bound. |

Additional author checks made pending-send time origins/expiry precedence, application activity versus discovery traffic, scheduler pressure and bounded host-buffer lifetime explicit. Evidence expiry is separate from network-loss counters. The document labels algorithm values as proposals, not owner-approved defaults or deployed behavior.

## Decisions still owned by the user

1. Deployment priority is now resolved by the owner's 2026-10-30 13:59:19 UTC clarification: two BoringTun endpoints first, useful one-sided capability where reliable. Select the concrete secondary responder/echo contracts and initial shipping scope; do not reopen the resolved primary-versus-secondary priority.
2. Select initial platform/host scope; recommendation is Linux CLI first with shared core/additive FFI, followed by separate real-socket qualification of each host.
3. Accept explicit unsupported-inner-IPv6 status when a 1280-byte inner packet cannot fit, or fund a separate encapsulation mechanism.
4. Task 0 must approve byte-level protocol/ABI contracts and operating policy: timer latency, probe budget/active-peer capacity, fallback and incompatible AWG bootstrap behavior.

Nothing in independent review substitutes for these decisions. No implementation may start from the illustrative control discriminator or API names before task 0 is complete.

## Validation and release boundary

The documentation change includes three Markdown files plus the repository-required release-intent metadata. The new intent uses ordinary schema 1 with `bump: none`, base/version `0.8.0`; the previous one-off schema-2 `release-presentation` scope is removed. Cargo manifests, lockfile, product source, workflows and published release content are unchanged.

Documentation validation checks local links, Markdown fences/encoding, whitespace, exact changed paths and the repository's version-transition validator. Product builds, implementation tests and privileged network tests are not part of this documentation change and have not been claimed as passing. No push, PR, merge, release or deployment is included.

## Initial independent verdict and snapshot

After the third pass, the reviewer reported: **"Approved as a sound conditional proposal. No remaining material contradictions found."** It verified all four original corrections and the timer/search repair. The five-send bound has explicit assumptions and a required deterministic proof during implementation. The reviewer reiterated that its verdict does not approve a wire extension or implementation; owner choices and task-0 protocol/ABI review remain mandatory.

Reviewed document SHA-256 values at `88423bb210a63abc65d9a9e40424dbe6a76d4df7` (UTF-8/LF source bytes; historical, not the current refined documents):

- Design: `71c42a60b099040058c71f92c577983234e371184e5c49b76f0c494357a5de88`.
- Plan: `f92bd4e17874bd7437691500f0ed0fa5160ffa7c49b170bc424b35829439d216`.

Initial documentation validation passed: three Markdown documents, 12 links inspected (local targets exist), balanced fences and valid encoding, clean whitespace, exact docs-plus-intent changed-path allowlist, and `boringtun_version.check_transition` accepting schema 1 / `none` / `0.8.0` against the baseline. The immutable transition and stored document hashes also passed for commit `88423bb210a63abc65d9a9e40424dbe6a76d4df7`. Product tests were not run for that docs-only change.

## Compatibility refinement following the owner's clarification

The owner stated: "Основной насчет на то что на обоих концах будет boringtun. Но если что-то можно сделать только с одной стороны, то имеет смысл тоже так уметь." The revised documents record this deployment priority without treating it as permission to implement a wire protocol.

The proposal now distinguishes E (negotiated endpoint ACK), R (configured small-ACK service through an unchanged tunnel peer), I (existing inner echo with conservative request/response scope) and L (local/OS assistance with no positive confirmation). Old BoringTun versions are explicitly legacy until authenticated capability negotiation succeeds. Preferred versus required policies, visible downgrade reasons, independent evidence generations and no cap increase on same-path fallback are specified. Task 7 plans the secondary adapters and their separate qualification; primary E does not depend on ICMP ingestion or secondary adapter delivery.

Research checked the WireGuard protocol, RFC 8899 application feedback requirements, RFC 792 / RFC 4443 echo matching, Linux PMTU socket documentation and the baseline's inner-length trimming and asynchronous-error diagnostics. Echo can reuse an already-running remote function, but it is not discovery without a responder. Local limits and validated ICMP hints never become verified PMTU.

Fresh reviewer `/root/dplpmtud_compatibility_review` inspected the refinement versus `88423bb`, relevant source and primary standards without author history. Its verdict: **"Approved as a sound conditional proposal. No material contradictions found in the refinement versus 88423bb."** No correction was requested. The reviewer specifically confirmed:

- R/I's positive lower-bound inference is conditional on unique/full matching, a trusted configured responder/path, one unfragmented outgoing datagram and a qualified fixed WG/AWG serialization profile. Remote observed UDP length remains absent.
- I failure cannot establish the forward upper bound; R's small inner ACK can have a large AWG outer envelope and needs return-path qualification for stronger timing/asymmetry claims.
- Old BoringTun versions, version disagreement and unconfirmed capabilities are distinct; tier changes invalidate evidence, and same-path downgrade does not raise the operational ceiling.
- Secondary controller/FFI ownership and task-7 tests preserve evidence provenance, expiry, rate limits, legacy interoperability and host transport responsibilities.

Reviewed refinement SHA-256 values (UTF-8/LF Git source bytes):

- Design: `cfea76f61c4e523b5b0f6f655a30a1507c2bf9f5c4d643fe11658a12ccc763b9`.
- Plan: `7f122889e1ed9879e2a24fdcc8263900780b53fcc73c01eb7277feff812e3964`.

Refinement validation passed against `88423bb`: three Markdown documents, 15 links inspected with all local targets present, balanced fences/valid encoding, clean whitespace, exact docs-plus-intent change scope and schema-1 no-release transition at `0.8.0`. The commit is local only. Product tests and privileged network tests were not run, and no runtime support is claimed by this review. Remaining secondary-adapter/platform/IPv6 choices and the wire/ABI contract are still implementation gates.
