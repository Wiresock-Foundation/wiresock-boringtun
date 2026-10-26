# Canonical compare transport repair

The first installed master push after PR97 (source
`4145b2d954e60e9a1d1b5f547b7f4552756beab0`, run `40375495699`, attempt 1)
passed the ordinary-push guard but stopped in the resolver with `unsafe API path`.
The REST adapter rejected GitHub's legitimate `C...master` compare syntax before
making an HTTP request. Earlier tests replaced `api.get` and missed this boundary.

Implementation and verification:

1. Reproduce at the real REST adapter with only the HTTP opener replaced. Verify
   allowed canonical and legacy compares plus hostile path/ref/encoding cases.
2. Permit only GET of a full lowercase source SHA compared to canonical `master`
   or legacy `main`; retain exact repository/host restrictions and reject path
   normalization, encoded separators, query/fragment/ref substitution, and writes.
3. Replay the production `main resolve` against actual GitHub public APIs through
   context, merge policy, transport, source metadata and envelope validation.
4. Run all release regression suites, independently review, open a scoped repair
   PR and synchronize PR98 using a normal merge. Do not activate or sign.

The six transport tests initially failed (13 negative subcases accepted and both
valid compare cases rejected); all pass with the repair. The complete Linux
Python suite passed 122 tests, plus 16 notice and 16 platform tests.

The first live replay passed with eight public GETs, no credentials and no
mutation. The current canonical commit's API association selected PR97; its
comparison to master was identical. The actual production CLI generated a valid
request for version 0.7.1. Local receipts retain response hashes and public JSON.
The raw original `GITHUB_EVENT_PATH` was not archived: the diagnostic push context
was reconstructed from the real run, merge first parent and previously successful
ordinary-push guard. This is explicitly **not** CI, attestation or release proof.
The optional `tests/live_resolve_preflight.py` repeats this check with a supplied
event and real source checkout, saves a hash receipt and deletes temporary request
outputs. A later installed canonical workflow still needs to pass normally.

Example (use a clean checkout at the source commit; choose a new receipt path):

```sh
python3 -B tests/live_resolve_preflight.py \
  --source-checkout /path/to/source-C --run-id 40375495699 --attempt 1 \
  --event /path/to/reconstructed-push-event.json --context-kind reconstructed \
  --receipt /path/to/new-read-only-receipt.json
```

AWG's separate pinned-`gh` GET adapter already passes the compare expression as
one argv value and has no substring-dot filter; shared policy and artifact
contracts are unchanged, so no AWG code synchronization is needed for this fix.
Postmerge standard CI completed: fork 16/16 jobs and AWG 9/9 test jobs passed.
The failed canonical artifact run remains failed; it has not been rerun or signed.
