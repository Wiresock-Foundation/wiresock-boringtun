# Actions artifact download media-type repair

Canonical PR99 build40383601645 attempt1 completed all13 jobs successfully.
Its promoter40387588688 failed read-only preparation with HTTP415; both signing
and publication jobs were skipped. The transport chose octet-stream for every
binary response, but GitHub's Actions ZIP endpoint requires the JSON API media
type before redirecting to blob storage. The exact live artifact12681307359
reproduced415 with octet-stream and downloaded successfully with the JSON media
type. Release asset downloads separately require octet-stream.

References: [Actions artifact download](https://docs.github.com/en/rest/actions/artifacts#download-an-artifact)
and [release asset download](https://docs.github.com/en/rest/releases/assets#get-a-release-asset).

Plan and implemented scope:

1. Reproduce the415 at the actual API and at the real REST adapter's opener
   boundary, including the authenticated API-to-unauthenticated-storage redirect.
2. Choose octet-stream only for the exact release-asset route. Keep raw response
   decoding independent; Actions ZIPs use the normal JSON API media type.
3. Preserve storage-host/HTTPS restrictions and credential stripping. Close the
   consumed API error/redirect response before continuing; regression tests
   demonstrated the previously unclosed response.
4. Exercise the complete production prepare CLI against actual retained API
   metadata, artifact bytes and static archive validation, with GET-only transport,
   no publication, and no retained prepared artifacts or credentials.
5. Independently review, open a scoped repair PR and synchronize PR98 normally;
   keep signing and publication disabled pending staged installation validation.

Validation:132 Python tests,16 notice tests and16 platform tests passed on Linux;
12 transport tests also passed on Windows. The complete live prepare replay
returned exit0 and publishable:false for source/recipe
d5e0e648a895d01551bdb5f01ce2452c36da9796, build40383601645 attempt1 and
publisher40387588688 attempt1. It verified the real artifact ZIP digest/size,
request envelope, all five archives, descriptor and disabled publication gate.
The original CI promoter remains failed; a successful diagnostic is not a CI
retry or installed-workflow proof.

The optional tests/live_prepare_preflight.py reconstructs workflow_run context
from real retained metadata and labels its receipt diagnostic-only. It uses an
existing read credential supplied on stdin, permits only GET, checks the pinned
gh archive/binary, and deletes downloaded/prepared data with its temporary
directory. Independent review identified that the documented clean checkout
requirement needed enforcement. The helper now rejects tracked, staged, untracked
and ignored changes before accepting a credential and rechecks before preparation.
Git and static verification subprocesses receive an environment without GitHub
or Actions authentication tokens. The full live replay passed again after these
changes. The receipt retains only public identities, paths and response hashes.
Use a clean Linux checkout at the actual recipe and do not upload its temporary
output as workflow evidence. Existing signing/run/attempt/asset checks and AWG's
separate pinned-gh adapter are unchanged.
