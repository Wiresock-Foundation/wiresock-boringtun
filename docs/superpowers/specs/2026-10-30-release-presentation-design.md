# Reviewed release presentation amendment

The owner approved a PR, merge without a new release, and a formatting-only
update of the published 0.8.0 body. Preserve its seven assets, tag, source,
descriptor, signatures and every prose fact/link. Earlier pinned workflows
cannot acquire the new policy and will reject the amended body on retry.

## Approach

Use one explicit pair of full-body SHA-256 values in the trusted publisher:
the original source-rendered 0.8.0 body and its reviewed unwrapped form.
Accept either only for an already-published release. Continue to parse the
hidden metadata strictly, compare its exact canonical descriptor bytes and
verify every asset/signature/source binding. Draft recovery and create
readbacks stay exact. Generic whitespace normalization is rejected because
it could hide Markdown structure or meaning changes. Releasing 0.8.1 is
excluded by the owner's explicit no-new-release requirement.

Original body: `c399060ac8860b5b494c7d49ab193aebba48705610ba0d064b454b71b1ca89e7`.
Amended body: `84172db7d08d1c91ec12f5e4d246fe863de1b3a55b67386bc799a63e8bccd792`.
Descriptor: `52a3f22cbc87b9ab8a25d61bc55a0a207cf35a8d706c6e60c2a04208da8765b8`.

## No-release maintenance

Keep schema-1 intent behavior unchanged. Add schema 2 with mandatory scope
`release-presentation`, usable only with `bump: none` and unchanged versions.
In addition to existing docs/tests paths, that scope allows exactly
`scripts/boringtun_release.py` and `scripts/boringtun_version.py`.
Runtime, dependency, build/packaging and workflow paths still require a bump.
The explicit scope is reviewed intent, not a semantic classifier of Python
diffs. No workflow changes are needed: source resolution emits release=false
and no artifact; completion emits publishable=false and no prepared content.

## Live amendment

After independent review, exact-head CI, merge and terminal no-release runs,
back up the complete release inventory/body. Verify all current identities,
body hash, descriptor bytes, assets and Latest against the approved snapshot.
Send a single body-only PATCH through the authorized CLI identity. Read back
the body, assets/tag/source and inventory; an uncertain outcome requires a
readback before any retry. GitHub does not offer an atomic body compare-and-set,
so an immediately preceding check narrows but cannot eliminate an external
editor race. No other writer is coordinated or disabled by this task.

Use the current verifier for later 0.8.0 checks. Old pinned publication/Latest
runs remain obsolete for the amended body; do not rerun them expecting success.
This compatibility limit is explicit and does not weaken cryptographic checks.
