# Readable Releases Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Explicit semantic versions and reviewed human release notes without changing installer identities or publication trust.

**Architecture:** Validate committed version intent against base/source snapshots, render source Markdown with hidden signed metadata, and reconcile Latest in a separate serialized job.

**Tech Stack:** Python standard library, GitHub Actions, Rust/Cargo.

**Spec:** `docs/superpowers/specs/2026-10-29-readable-releases-design.md`

## Global Constraints

- Automatic per-merge publication; this task only creates a draft PR.
- Start at 0.8.0; patch/minor/none are explicit reviewed choices.
- Preserve technical tags, archive names, schema 2, seven assets and signed bytes.
- Never execute source code in the trusted promoter; source files are data.
- No AWG repository modifications or existing release/tag changes.

## Review Focus

- A second PR based on an outdated version must fail before duplicate publication.
- A none intent must skip artifact/signing work, including a docs-only push retry.
- Prose or metadata tampering must fail readback, including an empty draft.
- A later promoter retry must preserve an earlier publisher's descriptor bytes.
- A slow old build and canceled pending reconciliation must not regress Latest.

## Tasks

### 1. Version intent and source consistency

Files: new `scripts/boringtun_version.py`, `tests/test_release_version.py`, intent JSON,
notes, PR template; update Cargo manifests/lock and workflows.
Interface: `check_transition(read_base, read_source, changed_paths)` returns validated
intent; `check_versions(read_source)` returns the common literal version.

- [x] Write and run failing tests for patch/minor/none, stale bases, unchanged
  intent, source changes under none, duplicate/mismatched lock entries.
- [x] Implement read-only local Git and API snapshot validation and workflow gates.
- [x] Set 0.8.0 and write notes distinguishing accumulated changes from b114.
- [x] Run release suite and Cargo metadata/build checks; commit.

### 2. Human bodies with recoverable hidden metadata

Files: `scripts/boringtun_release.py`, new `tests/test_release_notes.py`.
Interfaces: `release_body(api, descriptor) -> str`,
`recorded_descriptor(body) -> (descriptor, exact_bytes)`; publication takes a
body factory so retained descriptors render deterministically.

- [x] Add failing tests for legacy/new bodies, malformed/duplicate blocks,
  tampering, empty-draft recovery and uncertain writes with human notes.
- [x] Implement strict parser/rendering/readback and human titles without adding assets.
- [x] Run full release/security suite and consumer compatibility proof; commit.

### 3. Monotonic Latest and verification

Files: `scripts/boringtun_release.py`, release workflow,
`tests/test_release_latest.py`, maintainer documentation.
Interface: `reconcile_latest(api, verify, gate, dry_run=True)` selects and verifies
the highest stable release, updates only Latest when authorized and reads back.

- [x] Write failing tests for reversed publication order, retries, duplicate
  versions, invalid higher releases, higher current Latest and uncertain PATCH.
- [x] Implement separate serialized reconciliation, preserving per-PR publication.
- [x] Run full Python suites, lint/format, affected Rust checks; commit.
- [x] Fresh independent branch review; fix important findings with regression tests.
- [ ] Push branch, open draft PR, attach it and monitor exact-head CI to terminal.

## Execution evidence

Baseline: 189 Python release/security tests ran successfully, 8 skipped on Windows.
Native worktree tools unavailable; fresh isolated clone created in this task's
workspace, branch `feat/readable-release-versioning`, base
`60f5f278c2f7c0e91b96b898ef887dd859ec9887`. Existing checkouts untouched.

Local validation on 2026-10-29:

- Linux: 215 release/security tests, 16 notices tests and 16 platform-packaging
  tests passed; attribution check passed for 42 files. Windows: 215 tests ran
  successfully with 8 platform skips. Version, body and Latest regressions were first
  observed failing, then passed with the implementation.
- Rust workspace tests: 657 passed, 70 ignored. Used the unprivileged `env`
  runner in WSL; privileged/platform integration coverage is left to CI.
  `cargo fmt --all --check` and the repository's MSRV clippy gate passed;
  clippy retained existing warnings. CLI reports `boringtun 0.8.0`.
- Actionlint 1.7.12 passed for all three affected workflows (optional shellcheck
  and pyflakes integrations unavailable and disabled). `git diff --check` passed.
- The unchanged AWG consumer policy at commit
  `bc8849cd30a9ffcbd9fd1a1596d0737a359df655` is byte-identical to the producer
  Git blob (SHA256 `fd51e3487b8e75d0bc7de2c87584708fc51d800da4f26823af0b9a024856ee04`).
  It accepts a synthetic 0.8.0 schema-2 descriptor and all seven asset hashes.
  This proves the format contract, not live publication/signing.
- Local Markdown rendering preserves sections and links while hiding machine
  metadata; parsing still recovers exact descriptor bytes. Actual publication,
  signing and Latest mutation were intentionally not executed in this task.

Independent review and dispositions:

- Fresh branch review found a multi-commit rebase boundary defect. Red tests
  reproduced a valid release rejection and a docs-only final commit hiding an
  earlier product change. The validator now uses the canonical merged PR's
  recorded base, checks merge ancestry, and binds the source push `before` SHA.
  Full-diff, squash/rebase, renamed-path and truncation regressions pass.
- A separate review of the expanded cumulative 0.8.0 description found missing
  C/Rust constructor breaks and an overbroad SIP fallback claim. Both are
  corrected; JNI boundary hardening, capacity/error guidance and standalone
  imitation/QUIC profiles were added. The b114/runtime distinction, supervisor
  lifecycle, asynchronous reclamation and fwmark caveats were checked against
  source/history. Review did not claim live platform execution.
- External/manual Latest writers cannot be made atomic by GitHub's API; the
  coordination requirement is documented. No host, branch-protection or
  consumer-repository settings were changed.

The draft PR and exact-head CI results are recorded in the delivery report;
the final task remains pending until those checks reach terminal states.

CI follow-up: draft PR #115 initially passed PR Status Checks and Semgrep but
the candidate notice gate rejected the changed Cargo.lock checksum. Inspection
confirmed that the lock diff changes only the two workspace versions, with no
dependency/native runtime changes. Added the new exact Git-blob hash to the
reviewed notice allowlist, retaining historical hashes. A failing regression
now makes the early version gate catch a missing/stale notice binding; the full
notice gate remains unchanged. Maintainer instructions and PR template include
this required step for future version bumps.
