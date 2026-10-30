# Release versions and notes

Each meaningful merged PR still creates its own automatic release. Releases
start at **WireSock BoringTun 0.8.0**; technical tags retain
`boringtun-cli-X.Y.Z-g<12-character-source-sha>-b<PR>` and archive identities and
the seven-asset contract remain unchanged.

## Preparing a PR

Update `packaging/boringtun/release-intent.json` in every PR. Choose:

- `patch`: a fix, advancing `X.Y.Z` to `X.Y.(Z+1)`.
- `minor`: a feature or significant contract change, advancing to `X.(Y+1).0`.
- `none`: documentation/tests only, with no package version change or release.
  Allowed paths are `docs/`, `tests/`, `README.md`, `CHANGELOG.md` and the intent
  file. A production-code change, including a Rust file with embedded tests,
  requires a release choice. Build/publisher changes also require a release,
  except for the explicit presentation-maintenance scope below.

There is one explicit maintenance scope: schema 2, `bump: none`,
`scope: release-presentation`. It keeps all versions unchanged and additionally
allows `scripts/boringtun_release.py` and `scripts/boringtun_version.py`.
Runtime, dependency, build/packaging and workflow paths remain forbidden.
Reviewers must confirm the diff concerns presentation: the path gate is not a
semantic Python classifier. Source resolution and completion still emit no
request/prepared artifact and never build, sign or publish a new release.

Set `base_version` to the current base version and explain the choice in
`reason`. Set `version`, both package versions, the CLI's library dependency
and the two workspace package entries in Cargo.lock to the same new version.
No dependency resolution change is needed. The historical `pin.env` describes
its historical commit and stays paired with that commit; automatic builds and
PR candidates derive a temporary pin from their exact source and version.

After reviewing the Cargo.lock diff for dependency/native-notice changes, add
its Git-blob SHA256 to `source_lock_sha256` in
`packaging/boringtun/notice-policy.json`. Even a package-version-only change
changes that hash. The early version gate checks this binding; the full notice
gate still validates all policy fields and exact license text. Keep earlier
reviewed hashes for historical builds; never auto-allow an unreviewed lockfile.
For the committed snapshot, compute the exact bytes with:

```sh
git show HEAD:Cargo.lock | sha256sum
```

For a release, add `docs/releases/<version>.md`. Write English prose with a
short impact summary, New / Fixed / Security sections as applicable, and
`## Compatibility & upgrade notes`. Explain upgrade requirements and limits;
do not paste raw commit titles. Notes must be UTF-8, at most 20 KB, without raw
HTML or the reserved machine metadata markers. PR, source comparison,
descriptor, checksums and verification-guide links are added deterministically.

Keep each prose paragraph and list item on one physical source line; use blank
lines between paragraphs. Do not wrap release prose at an editor column limit:
GitHub Releases renders those newlines as forced breaks, leaving ragged short
lines on narrow screens. Preview with soft breaks rendered as hard breaks, at
both narrow and wide widths; the regular `.md` file preview is not sufficient.
This authoring rule alone does not authorize editing an already-published body;
the reviewed amendment procedure below applies.

After committing, validate against an exact base SHA:

```sh
python3 scripts/boringtun_version.py --base "$(git rev-parse origin/master)" --source "$(git rev-parse HEAD)"
python3 -m unittest discover -s tests -p 'test_*.py'
```

PR checks validate the candidate merge against its base snapshot. If another
release merges first, refresh the PR's versions, intent and notes before merging.
The trusted resolver and promoter validate again against GitHub's **recorded
merged-PR base SHA**. It must be the first parent for a merge commit and a strict
ancestor for squash/rebase. The source builder also requires that it match the
server push event's `before` SHA. This covers every rebased commit, not just
the final commit's diff. An outdated PR cannot publish a duplicate
semantic version, even if an old PR check was green. The build fails closed
until a corrective reviewed PR supplies a valid transition. Retries always
reuse the committed version; they never bump, amend or create source commits.
Repositories should require the `Release version intent` check and up-to-date
branches. This change does not modify branch-protection settings.

A valid `none` emits no request artifact. All build and signing jobs skip,
and the completion handler reports `none` without preparing a release. The
source path inventory is bounded: comparisons reaching GitHub's 300-file limit
stop for explicit review instead of assuming omitted paths are harmless.

## Signed metadata and retries

New release bodies contain human Markdown followed by exactly one hidden
`boringtun-release-metadata:v1` HTML comment. It contains the same canonical
signed descriptor bytes and digest used by the legacy two-line body. The
parser rejects duplicate, malformed, oversized or conflicting metadata. Every
publication readback also compares the full body to notes from the immutable
source commit. Prose is reviewed source data; it is not executable input and
does not select the source, signer or artifact.

The `RELEASE.json` asset remains authoritative for installers and cryptographic
verification. No schema fields or assets have been added. Empty drafts can
still recover their exact original signed descriptor after an uncertain create.
Published retries verify the original descriptor/assets and do not rewrite
them. Historical releases keep their exact old bodies: old pinned workflows
still use their original parsers and must not be broken by cosmetic edits.

### Reviewed 0.8.0 presentation amendment

The owner authorized one exception: remove source-column wraps from 0.8.0
without changing its wording, links, structure or signed metadata. The current
verifier accepts only the exact original body or its exact reviewed amended
hash, after parsing and comparing the canonical descriptor. All asset,
signature, source and workflow checks remain required. Draft recovery and
creation readbacks retain exact-body checks. Other edits are rejected.

The original body hash is
`c399060ac8860b5b494c7d49ab193aebba48705610ba0d064b454b71b1ca89e7`;
the approved amended body hash is
`84172db7d08d1c91ec12f5e4d246fe863de1b3a55b67386bc799a63e8bccd792`.
After the policy is merged, back up the current body/inventory, immediately
recheck the original body and immutable identities, then make a body-only
update and read it back. An uncertain write must be reconciled before retry.
GitHub has no atomic body compare-and-set; coordinate any external editor.

Old pinned publication and Latest workflows still compare the original body
exactly and will reject the amended text. They cannot be changed retroactively:
use the current verifier, and do not rerun those obsolete workflows expecting
success. This explicit compatibility exception does not change the descriptor,
assets, tag, binary versions, source identity or signatures. All other released
bodies remain immutable.

## Latest ordering

Publication retains the per-PR lock and `make_latest:false`. After successful
publication or an already-published retry, a separate `boringtun-stable-latest`
job lock serializes reconciliation. Each job inventories all stable releases
from 0.8.0 onward, selects the highest numeric semantic version and verifies
its complete assets, source, notes, signing provenance and live release gates.
A duplicate semantic identity or invalid highest candidate stops the operation;
it does not silently choose a lower version. An existing higher Latest is never
replaced. The only mutation is `make_latest:true`, followed by exact ID/tag
readback, including after an uncertain response.

Pending reconciliation jobs may be coalesced by GitHub concurrency: the surviving
job reads the whole inventory, so it also covers intervening published releases.
Publication jobs themselves are not coalesced across PRs. This guarantees
monotonic ordering among these workflows; GitHub provides no compare-and-set
for Latest, so manual/external Latest writers must coordinate with this lock.
An interrupted/failed reconciliation is repaired by retrying its publisher run;
published release bytes remain immutable. No historical release is promoted by
this new selector, and this implementation PR does not change live Latest.
