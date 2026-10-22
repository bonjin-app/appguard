# Archive verification without filesystem restore

2026-10-21; experimental Apache-2.0 CLI. No archive format change or published
release is introduced.

## Behavior

`verify-archive --archive FILE --key-file FILE` checks an existing
`appguard-vault-v0` archive without a plaintext filesystem restore. Success exits
0 with only `verified`, `buildId`, `fileCount` and `plaintextBytes` in JSON on
stdout. `verified` is true only after authentication and complete validation.
Zero-length files are valid and contribute zero plaintext bytes.

Verification and restore use the same validation path: bounded regular-file
read; exact envelope/version/build-ID shape; canonical Base64 and length limits;
AES-256-GCM authentication with version/build-ID associated data; exact payload
and entry schemas; decoded byte and file count limits; and portable-path checks.
Those path checks cover traversal, reserved names, duplicate/Unicode/case
collisions and file/directory prefix conflicts. Every entry must pass before
verification can return success or restore can create a destination.

The existing limits remain 1000 files, 64 MiB decoded file data, 96 MiB encrypted
payload and 128 MiB archive bytes. The supplied key must remain exactly 32 bytes
in a regular, leaf-nonsymlink file, with owner/private POSIX permissions. The
shared file reader retains its bounded reads, no-follow open where supported,
descriptor identity and observed-change checks. Ancestor path resolution follows
the operating system; this is not filesystem isolation from a hostile local
writer or compromised account.

Wrong keys, tampering, malformed or unsafe manifests and rejected file inputs
produce the existing fixed CLI error envelope on stderr, exit 1 and no success
report. Missing, duplicate or unknown options likewise reject. No file names,
contents, key data, input paths or raw parser/crypto/filesystem errors are added
to the verification report. The returned build ID is authenticated archive
metadata and is intentionally included.

## Security and operational limits

The command decrypts and validates data in process memory. It does not create a
destination, temporary plaintext directory, receipt file or repaired archive,
and does not overwrite, rotate, delete or upload input files or keys. Filesystem
reads can update access times. JavaScript immutable strings, native crypto state
and garbage-collected copies prevent a complete memory-erasure guarantee even
when owned byte buffers are cleared.

Success means the bytes read authenticate under the supplied key and satisfy
the supported archive rules. It does not prove freshness, the identity of the
producer, correspondence to a particular application release, remote backup
durability, later key availability or the ability to write to a chosen restore
destination. There is no expected-build-ID comparison, trusted external digest,
key rotation, KMS, repair, archive migration or public upload in this command.
Retain the matching tool version and an independent key backup; test actual
restore behavior separately in a private location.

Verification is a local point-in-time operation. Keep files under exclusive
local control; the existing metadata checks do not establish an atomic snapshot
against all concurrent mutations. Existing archive encryption, restore output
fields, no-overwrite behavior and private destination modes are retained.

## Verification evidence

Source regression tests and separately installed package probes exercise real
CLI subprocesses, authenticated malformed fixtures and input tree snapshots
excluding access times. A synthetic archive produced by the previous main
commit tests compatibility without relying only on a new-writer/new-reader
round trip. All fixture keys are disposable public test material; no application
key or provider account is used.

Raw logs, the local package, source/file hashes and independent review receipt
are retained under `.superpowers/evidence/2026-10-21-vault-verify/` on local main.
These results do not establish production, provider, device, hosted CI, public
registry or Windows runtime behavior. Other SDKs and protocols are unchanged.

## Local verification and review

Reviewed runtime/package source:
`4de896e9135a44bfb68e9a31f67af2bbbc2d73eb`, Node 22.23.2 on macOS
as local user 501.

- Baseline whole CLI suite: 32 passed, one Windows-only skip. Selected RED tests
  before implementation: 11 cases, seven expected assertion failures and four
  existing passes. Nested validation cases are not counted as individually
  executed RED failures before the missing API was implemented.
- Final whole suite: 75 leaf cases, 74 passed, zero failed, one Windows-only skip.
  The TAP summary also counts four successful parent containers (79 total events,
  78 pass); these containers are excluded from the leaf count. Parent and reviewer
  freshly reran the whole suite. `git diff --check` passed.
- Offline, lifecycle-scripts-disabled local npm pack/install: all 10 file bytes
  and modes match committed source, tarball and installed copy. Archive SHA-256:
  `b2474d936ec576861195ba9f324401c9d1559f38dea08eb4b71befa7034581b8`.
  Eight installed subprocess probes passed, including a synthetic v0 archive
  created by previous main `f43f872f7fe1119f33e12bf68e423791f60cd7be`.
- Independent security review found no blocking findings. The reviewer freshly
  reran source and installed probes, plus eight independently written installed
  boundary cases. All passed; a targeted rollback rerun is a subset of those
  eight. The base archive also restored byte-for-byte. Checks included 1000 empty
  files, 1001-file rejection, binary/empty restore and private modes, late invalid
  entries, filesystem guards, existing destinations and post-first-write cleanup.

These test tiers overlap; parent containers, repeated executions and consumer
probes are not added into one distinct-case total. Review inspected baseline/RED
records without rerunning them, and rehashed the existing package rather than
packing/installing another copy. Buffer clearing was reviewed in control flow,
not established through memory forensics. Large decoded/payload limit arithmetic
was inspected without allocating full 64/96 MiB boundary fixtures; an oversized
sparse archive rejection was exercised.

Two initial independent review-fixture attempts failed because of filesystem
assumptions: this volume accepted a Unicode filename that the fixture expected
to reject, and restore destination create/remove legitimately changes its
parent's directory timestamps. Direct host probes established the actual path
limit; corrected rollback assertions check retained entries/bytes/modes while
allowing parent timestamp changes. Both failed logs, probe versions and the final
passing results are retained. Neither required a production change.

The final verification-record commit only changes this root security document;
reviewed CLI source and package remain unchanged. No real platform build,
provider/device validation, remote CI, publication, deployment or global Codex
configuration operation was performed. Other SDK runtime suites were not repeated
for this CLI-only stage.
