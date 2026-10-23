# Maintained development-tool derivatives

This directory retains two private, unpublished derivatives for reviewed future
AppGuard development-tool integration. Nothing here changes an SDK consumer lock,
override, scanner policy or installed dependency. These are not upstream fixed
releases. Original ancestry findings remain unresolved and must remain visible.

| Derivative | Upstream | License | Result files |
| --- | --- | --- | --- |
| `@appguard/braces@3.0.3-appguard.1` | `braces@3.0.3` | MIT | 10 |
| `@appguard/node-forge@1.4.0-appguard.1` | `node-forge@1.4.0` | BSD-3-Clause OR GPL-2.0 | 62 |

Run from the repository root using Python 3.11 or later:

```sh
python3 -I -B scripts/dependencies/build-backports.py --check
python3 -I -B scripts/dependencies/build-backports.py --output /path/to/new-private-directory
python3 -I -B .github/tests/test_tool_backports.py
```

The output directory must not already exist. It is created with mode `0700` and
its two files with mode `0600`. Both commands read only local data; they never
resolve, install, import or execute JavaScript, lifecycle scripts or a compiler.
Errors and JSON summaries deliberately contain fixed status fields and package
IDs/digests/counts, without caller environment values or local input paths.
`verified=true` means archive assembly and payload integrity only.

`manifest.json` binds the retained registry archives by SHA256, size and exact
npm SHA512 SRI. Each package retains its complete original manifest and LICENSE,
a canonical readable source patch, provenance, modified manifest and changed
source. Forge also retains six JavaScript distributions and three source maps in
`replacements/distribution/`, mapped to logical `package/dist/*` archive members.
The compact distribution record binds those nine files and identifies the prior
private artifacts-record digest without copying its private paths or raw logs.

The builder reads all published regular members directly from `upstream.tgz`,
then applies the exact declared replacements or additions. The complete
`result_files` inventory binds every resulting byte. Every unchanged published
file, including Forge's Flash assets, is retained. The 62 Forge files include
three declared additional distribution members beyond the original 59 files.
Assets being retained does not establish Flash execution or support.

Fork manifest changes are limited to the scoped name/version, `private: true`,
removal of scripts and devDependencies, and Node `>=22.13.0`. Existing runtime
entrypoint/dependency/other engine fields remain unchanged. Every changed field
is recorded against the original manifest in `provenance.json`. No original
license or copyright is replaced by AppGuard's Apache-2.0 license. Read each full
package LICENSE and original metadata; legal approval remains false.

Archives use sorted USTAR regular files under `package/`, mode `0644`, zero
mtime/uid/gid and empty owner names. Gzip has a fixed header and stored DEFLATE
blocks of at most 65535 bytes, followed by CRC32/ISIZE; archive bytes do not depend
on a host compression level or zlib compressor version. The builder checks exact
schema/identities, input/result/archive hashes and SRI, preserves the full original
payload, and refuses unsupported archive members, omitted files and inventory
mismatches. Limits are 16 MiB per compressed/archive file, 32 MiB expanded payload
and 512 files. Physical input directories deliberately avoid excluded
`build`, `dist`, `vendor` and `artifacts` components; the existing source-candidate
allowlist covers them without exceptions.

## Verification boundaries

Both records and command summaries retain:

```json
{
  "compilation_reproduction_verified": false,
  "producer_closure_verified": false,
  "consumer_adoption_verified": false,
  "source_gate_passed": false,
  "release_ready": false
}
```

Forge distributions are exact previously reviewed output bytes; deterministic
archive reassembly does **not** reproduce their compilation. Before production
adoption, the readable modern Webpack recipe, full producer lock/config, exact
Node/npm/tool pins and source/output joins must be retained under
`node-forge/producer/`. An independent rebuild of all six JS files and three maps
must match every expected digest, or reproduction remains unverified. Static
retention or a private execution receipt alone cannot qualify the producer.
Previous unit results had four pending cases; previous main minified compilation
had three warnings per build. Browser/mobile/DOM scope and lenient-parser
interoperability remain unverified; there is no universal cryptography claim.

Braces retains original parser quote/comma behavior with the reviewed five-file
backport. Depth and parent-chain changes do not establish a general work budget,
all malformed-object behavior, or protection of the separate bundled resolver.
The resolver derivative, real consumer installs, scanner-visible ancestry catalog,
required unsuppressed scans and public producer rebuild are later work. This
unit runs no vulnerability payloads and closes no advisory. External audit,
provider/deployment approval, publication and release readiness remain false.
