# Readable Releases Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

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

- [ ] Write and run failing tests for patch/minor/none, stale bases, unchanged
  intent, source changes under none, duplicate/mismatched lock entries.
- [ ] Implement read-only local Git and API snapshot validation and workflow gates.
- [ ] Set 0.8.0 and write notes distinguishing accumulated changes from b114.
- [ ] Run release suite and Cargo metadata/build checks; commit.

### 2. Human bodies with recoverable hidden metadata

Files: `scripts/boringtun_release.py`, new `tests/test_release_notes.py`.
Interfaces: `release_body(api, descriptor) -> str`,
`recorded_descriptor(body) -> (descriptor, exact_bytes)`; publication takes a
body factory so retained descriptors render deterministically.

- [ ] Add failing tests for legacy/new bodies, malformed/duplicate blocks,
  tampering, empty-draft recovery and uncertain writes with human notes.
- [ ] Implement strict parser/rendering/readback and human titles without adding assets.
- [ ] Run full release/security suite and consumer compatibility proof; commit.

### 3. Monotonic Latest and verification

Files: `scripts/boringtun_release.py`, release workflow,
`tests/test_release_latest.py`, maintainer documentation.
Interface: `reconcile_latest(api, verify, gate, dry_run=True)` selects and verifies
the highest stable release, updates only Latest when authorized and reads back.

- [ ] Write failing tests for reversed publication order, retries, duplicate
  versions, invalid higher releases, higher current Latest and uncertain PATCH.
- [ ] Implement separate serialized reconciliation, preserving per-PR publication.
- [ ] Run full Python suites, lint/format, affected Rust checks; commit.
- [ ] Fresh independent branch review; fix important findings with regression tests.
- [ ] Push branch, open draft PR, attach it and monitor exact-head CI to terminal.

## Execution evidence

Baseline: 189 Python release/security tests passed, 8 skipped on Windows.
Native worktree tools unavailable; fresh isolated clone created in this task's
workspace, branch `feat/readable-release-versioning`, base
`60f5f278c2f7c0e91b96b898ef887dd859ec9887`. Existing checkouts untouched.
