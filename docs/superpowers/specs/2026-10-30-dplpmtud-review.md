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

Reviewed refinement SHA-256 values at `66d0d343860036eab50fdcc24fe45803c967bcec` (UTF-8/LF Git source bytes, before the coordinator-prompt publication update):

- Design: `cfea76f61c4e523b5b0f6f655a30a1507c2bf9f5c4d643fe11658a12ccc763b9`.
- Plan: `7f122889e1ed9879e2a24fdcc8263900780b53fcc73c01eb7277feff812e3964`.

Refinement validation passed against `88423bb`: three Markdown documents, 15 links inspected with all local targets present, balanced fences/valid encoding, clean whitespace, exact docs-plus-intent change scope and schema-1 no-release transition at `0.8.0`. At completion of that refinement the commit was local only. Product tests and privileged network tests were not run, and no runtime support is claimed by this review. Remaining secondary-adapter/platform/IPv6 choices and the wire/ABI contract are still implementation gates.

## Coordinator starter and authorized documentation publication

At 2026-10-30 14:29:48 UTC the owner requested pushing the plan and creating the first prompt for a coordinator-reviewer that generates prompts and reviews coding-agent results. This explicitly authorizes publication of the documentation branch; it does not start the coordinator or implement the proposal. Historical no-push statements above describe the earlier tasks. No PR, merge, release, deployment or network/security setting change is included.

The [starter prompt](../plans/2026-10-30-dplpmtud-coordinator-prompt.md) supplies repository context, stage-0 decision and approval gates, E/R/I/L evidence limits, actual-diff/test review, bounded corrections, reusable agent handoffs and review verdicts. It requires independent review for major protocol decisions and honest reporting of unverified coverage. No model/version is selected. The implementation plan changes only its publication note; its technical tasks and the design are unchanged.

Fresh reviewer `/root/dplpmtud_coordinator_review` inspected the actual prompt, design, plan and four changed files against `66d0d343860036eab50fdcc24fe45803c967bcec`, without inheriting the author's conversation history or modifying files. Verdict: **"Sound as a documentation-only coordinator starter. No material contradictions, misleading permissions, critical omissions, or usability problems found."** It confirmed the stage-0 approvals, evidence-tier boundaries, actual-diff verification, bounded handoffs and execution restrictions. No correction was requested; the verdict does not approve protocol execution.

Reviewed UTF-8/LF SHA-256 values:

- Starter prompt: `87103d5c447fc37dddb438dd62d3404e098e802824aeb60ad844afff51669978`.
- Plan with publication note: `22993c991023a1a9bac0c5104d765a2559db10754aad9315023531f757b728cc`.
- Design is unchanged from the compatibility refinement above.

Author verification passed for four Markdown documents and 20 links, local target existence, UTF-8/fences, whitespace, the exact four changed paths and schema-1 `bump: none` / `0.8.0` version transition. The reviewer independently checked local links, whitespace, change scope and the version validator. Source, Cargo/lockfiles, workflows, release content and network settings are unchanged. No product or network tests were run or claimed. The existing artifact workflow only accepts a `master` push; its release promotion also requires that branch and run provenance. Publishing this docs branch does not request those workflows. The publishing executor must separately verify the pushed remote SHA and readable GitHub documents before reporting success.
