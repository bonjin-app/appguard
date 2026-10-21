# CLI initialization input preservation

Observed 2026-10-21 using Node22.23.2/npm, from local main base
`b5e19b6b0cf57b63fd453e839e980d1602787c05` in a separate managed worktree.
This repair is independent of the pending Unity physical-device branch.

## Reproduced behavior and repair

The optional project-file reader previously decoded directly with UTF-8 replacement
semantics. An invalid byte in `.gitignore` or a Gradle file could become U+FFFD when
initialization appended configuration. The supposedly original backup was written
from the same decoded string, so it could also lose the original byte. Invalid
UTF-8 inside otherwise parseable Expo metadata could similarly pass detection.

The reader now checks raw file bytes with Node's built-in `buffer.isUtf8` before
decoding and checks the actual read length against its existing size limit.
Invalid input returns `INVALID_FILE` before application/config/backup writes;
the invocation-owned initialization lock is released. No new dependency or
encoding conversion is added. Symlink, file type, permissions and project
preconditions retain their existing behavior.

Valid UTF-8 remains byte-preserving: BOM, multilingual text, emoji, combining
characters, literal U+FFFD and existing CRLF bytes survive in original content
and original backups. Generated additions retain their existing formatting.
Existing JSON parser rules are unchanged; BOM-bearing JSON is not newly accepted.
The package still requires Node22+ and remains experimental/unpublished.

## Verification

- Baseline complete CLI suite: **19/19**.
- RED complete suite: **23 tests, 20 passed, 3 failed**. Malformed ignore/project
  input unexpectedly initialized successfully; the actual CLI returned success.
- GREEN complete suite: **23/23**, zero skipped/cancelled. Cases include invalid
  leading/continuation bytes, overlong/truncated sequences, encoded surrogates and
  out-of-range code points; Android Groovy/Kotlin, Expo and Flutter detection;
  unchanged source/no config/no backup/no retained lock; fixed redacted CLI output;
  and valid BOM/Unicode/CRLF with byte-identical backup originals.
- Isolated local npm tarball installed **offline**, with scripts disabled and no
  registry dependencies. The installed executable rejected invalid input with the
  exact error, preserved source bytes and created no configuration or backups.
  A subsequent valid BOM/CRLF project initialized and retained its exact backup.
  Installed `src/files.js` bytes were compared with the repaired source.

The documented/CI `npm --prefix tools/cli pack` command also failed under the
installed npm10.9.8: it attempted to open the repository-root `package.json`.
The guide and CI now use `npm pack ./tools/cli --pack-destination <existing-dir>`,
an explicit local package argument. The first failure is retained, followed by
the successful actual pack/install checks. No remote CI success is inferred.

Run `npm --prefix tools/cli test` from the repository root. Existing CI already
runs that complete suite. Local passing tests are not remote CI results, a live
application build, published package, device test or provider verification.
Archive encryption/format, server/native SDKs and signing credentials are unchanged.

## Integration boundary

One fresh read-only security review found **0 Critical, 0 Important, 0 Minor**
findings and approved this CLI-only repair for local integration. The reviewer
reran all23 tests and independently compared production JS/package metadata across
source, tarball and offline-installed consumer. Exclusive filesystem control,
remote CI, publication and unrelated device/provider/archive assurances were
explicitly outside that review.

Local integration uses clean-main/fast-forward checks and a complete CLI test run
on the merged tree. Source hashes, tarball hash, review and actual integration
readback are retained under `.superpowers/evidence/2026-10-21-cli-input-preservation/`
in the primary checkout. Unity iPhone installation/runtime and Android physical validation remain
pending in the preserved `codex/unity-physical-runtime` worktree; none of those
changes or evidence tiers is promoted by this repair. No remote push, publication,
device operation or provider mutation is part of this stage.
