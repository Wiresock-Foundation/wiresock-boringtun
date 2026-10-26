# Release activation preparation

This is a local, disabled proposal. No push, activation, new signing run, release,
tag or deployment is authorized by this document. Base: master
`1cee1afadd6be4251d6a19273b1882090bd2038e`.

## Implementation sequence

1. Archive the untouched pinned-gh verification output, exact descriptor and
   evidence receipt from the completed one-shot trial. Add real-schema policy
   regressions for all six subjects and mutated run/attempt/recipe identities.
2. Add a fail-closed future-source activation boundary. Test late pre-activation
   sources, the baseline itself, unrelated histories, changed generations and
   current-master revocation before implementing the gate. Keep policy disabled.
3. Refresh the owner-authenticated read-only legacy audit; replace stale completed
   blockers with the remaining activation/recovery decisions. Document hosted
   compiler/SDK trust and signed versus supplemental evidence explicitly.
4. Review a minimal recovery design for missing, batched and token-suppressed
   events. Do not claim every merged PR until that route is implemented and
   reviewed in both producer and consumer. Do not add remote permissions here.
5. Independently review the final local diff, run release tests and workflow lint,
   then report the exact activation approval request and first-release/adoption/
   Lisbon rollback sequence. No enabling patch is pushed in this stage.

## Validation

Run all Python release-policy/orchestration/transport tests, notice/platform
tests and actionlint. The real fixture is a semantic replay of already verified
JSON, not a new cryptographic verification or signing attempt. Native builds are
unchanged; retain the actual canonical trial's native and ARMv7/QEMU evidence
without describing QEMU as a physical Raspberry Pi test.
