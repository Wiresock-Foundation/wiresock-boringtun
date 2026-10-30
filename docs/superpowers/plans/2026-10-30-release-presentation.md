# Release Presentation Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for inline execution and a fresh independent review before publication.

**Goal:** Correct 0.8.0 wrapping while preserving all artifact identities and issuing no new release.

**Architecture:** Exact, reviewed published-body hash pair; strict existing metadata/assets verification; explicit scoped no-release maintenance intent.

**Tech Stack:** Python standard library, existing GitHub Actions and GitHub CLI.

**Spec:** ../specs/2026-10-30-release-presentation-design.md

## Constraints and review focus

- Preserve seven assets, descriptor bytes, source/tag identity, all facts and 29 links.
- Reject arbitrary whitespace, link, text, hidden-block and descriptor changes.
- Accept the reviewed variant only for published state; keep draft recovery exact.
- Scoped none must reject runtime/build/workflow paths and produce no release artifacts.
- Old pinned retries cannot accept the new body; document this before the live change.

## Tasks

- [ ] Add failing tests for the actual body hash pair and preserved content/links; test published retry and Latest with an amended body, unchanged draft strictness and tampering rejection.
- [ ] Add the small published-body acceptance helper in scripts/boringtun_release.py; do not change rendering or metadata parsing.
- [ ] Add failing schema-2 scope/version/path tests and none resolver/completion tests; implement the strict scope in scripts/boringtun_version.py.
- [ ] Update release intent and maintainer documentation; retain the local reflowed 0.8.0 notes.
- [ ] Run the complete release/security suite, scoped version gate, formatting proof and whitespace checks. Have a fresh reviewer inspect the complete branch and fix findings.
- [ ] Commit, push, create draft PR, attach it, and monitor exact-head checks. Mark ready and merge only after review/check success.
- [ ] Verify terminal post-merge none behavior and unchanged release inventory before the one body-only amendment.
- [ ] Back up, preflight, amend and read back the actual release. Reverify signatures/assets/Latest with current code and inspect public HTML/narrow rendering. Report the old-workflow limitation.
