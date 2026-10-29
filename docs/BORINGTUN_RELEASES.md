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
  requires a release choice. Build/publisher changes also require a release.

Set `base_version` to the current base version and explain the choice in
`reason`. Set `version`, both package versions, the CLI's library dependency
and the two workspace package entries in Cargo.lock to the same new version.
No dependency resolution change is needed. The historical `pin.env` describes
its historical commit and stays paired with that commit; automatic builds and
PR candidates derive a temporary pin from their exact source and version.

For a release, add `docs/releases/<version>.md`. Write English prose with a
short impact summary, New / Fixed / Security sections as applicable, and
`## Compatibility & upgrade notes`. Explain upgrade requirements and limits;
do not paste raw commit titles. Notes must be UTF-8, at most 20 KB, without raw
HTML or the reserved machine metadata markers. PR, source comparison,
descriptor, checksums and verification-guide links are added deterministically.

After committing, validate against an exact base SHA:

```sh
python3 scripts/boringtun_version.py --base "$(git rev-parse origin/master)" --source "$(git rev-parse HEAD)"
python3 -m unittest discover -s tests -p 'test_*.py'
```

PR checks validate the candidate merge against its base snapshot. If another
release merges first, refresh the PR's versions, intent and notes before merging.
The trusted resolver and promoter validate again against the **actual first
parent of the merged source**. An outdated PR cannot publish a duplicate
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
