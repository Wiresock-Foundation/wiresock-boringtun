## Change

Describe the user-visible behavior and compatibility impact.

## Release intent

- Update `packaging/boringtun/release-intent.json`: `patch` for fixes, `minor`
  for new features or significant contract changes, `none` for docs/tests only.
- Set `base_version` to the current base; commit the matching versions in both
  Cargo manifests, the CLI library dependency and Cargo.lock.
- Review the lockfile diff and add its exact Git-blob SHA256 to the notice-policy
  allowlist, updating notice coverage if dependencies changed.
- For a release, add `docs/releases/<version>.md`: summary, New / Fixed /
  Security as applicable, and Compatibility & upgrade notes. Explain user
  impact. Keep technical references concise.
- Refresh after another version change merges; never reuse a semantic version.

## Validation

Describe tests run and any platform limitations.
