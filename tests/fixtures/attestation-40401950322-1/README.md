# Real pinned-gh output

`gh-verification.json` is unchanged stdout from the successful installed
gh 2.100.0 verification of RELEASE.json in
[job 121850244631](https://github.com/Wiresock-Foundation/wiresock-boringtun/actions/runs/40401950322/job/121850244631).
Its SHA-256 is
`5c64aae36e1281173993c11b12e4115f714225c3be83e2dad27cc46afc04adb0`.
The five archive verification commands returned the exact same bytes, covering
the same six-subject statement. The receipt records all six digests, CI identity
and downloaded artifact digests. RELEASE.json is the exact signed descriptor.

The fixture contains public hashes, certificates and provenance only. It is
semantic regression evidence, not an offline replacement for cryptographic
verification. No signing or cryptographic validation is performed by these tests.
The single approved attestation-only run is complete; tests do not authorize
another run or publication. Full raw files/ZIPs are archived on MS-A2 and in the
[verification artifact](https://github.com/Wiresock-Foundation/wiresock-boringtun/actions/runs/40401950322/artifacts/12689855439).
