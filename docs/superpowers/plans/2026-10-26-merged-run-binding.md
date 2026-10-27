# Merged-source binding repair plan

Goal: repair the first real merged-PR build without weakening source, workflow,
run, attempt or publication identity. The independent design review approved a
canonical master-push binding for implementation; a fresh final diff review is
required before integration. Publication remains disabled.

## Evidence and design

PR96 closed-event run40344057429 reports PR head H and no PR associations,
while its checkout executes merged source C. A title is not authoritative proof
of the workflow revision that executed. A master push instead records C as
head_sha. The resolver verifies ordinary canonical push context and C before
source execution, then fully paginates commits/C/pulls and selects exactly one
closed, merged master PR with merge_commit_sha C. Fresh PR and ancestry reads
remain required. Display names and downloaded REQUEST.json cannot select C.

Normal merge, squash and rebase use the REST postmerge merge_commit_sha contract;
no parent-count or H==C assumption is made. Real captured evidence currently
covers a normal merge. Unmerged direct pushes, alternate bases and manual
dispatches are ineligible. Replaying an already eligible C retains its original
immutable tag; this proves merged-source eligibility, not that a particular
push caused that merge. No branch-wide cancellation is introduced.

## Implementation and verification

1. Capture actual PR and attempt fixtures. Add negative event/ref/source,
   time, repository and ambiguity tests before changing the binding.
2. Use trusted push metadata in resolve, prepare, verify and reconciliation.
   Keep exact run/attempt/artifact/job checks and C-to-trusted-R workflow-byte
   comparison. Pin all build actions and installed workflow IDs.
3. Synchronize the AWG pure policy and independently repeat commit discovery,
   fresh PR, ancestry and exact attempt checks. Test paginated unrelated PRs,
   empty associations, malformed/duplicate/ambiguous entries and deleted repos.
4. Preserve existing attribution notices, record owner testimony as testimony,
   remove only the reviewed date-only blocker. Document actual source/toolchain
   coverage and preparation for recovery; do not invent a recovery publisher.
5. Run affected Python suites, attribution and workflow lint, obtain fresh
   independent review, fix findings, commit and open scoped draft PRs. Run exact
   head nonpublishing CI. Report review before any merge of this security change.

No remote settings, OIDC attestation, release, installer defaults or host changes
are part of this repair. Attestation-only validation needs separate approval.
See ../../BORINGTUN_ACTIVATION_AUDIT.md for the practical remaining gates.
