# Maintained development-tool derivatives

This directory retains three private, unpublished derivatives for reviewed
AppGuard development-tool integration. The resolver source phase stages consumer
metadata; actual lock/install qualification remains separate. These are not upstream fixed
releases. Original ancestry findings remain unresolved and must remain visible.

| Derivative | Upstream | License | Result files |
| --- | --- | --- | --- |
| `@appguard/braces@3.0.3-appguard.1` | `braces@3.0.3` | MIT | 10 |
| `@appguard/node-forge@1.4.0-appguard.1` | `node-forge@1.4.0` | BSD-3-Clause OR GPL-2.0 | 62 |
| `@appguard/resolve-workspace-root@2.0.1-appguard.1` | `resolve-workspace-root@2.0.1` | MIT | 9 |

Run from the repository root using Python 3.11 or later:

```sh
python3 -I -B scripts/dependencies/build-backports.py --check
python3 -I -B scripts/dependencies/build-backports.py --output /path/to/new-private-directory
python3 -I -B .github/tests/test_tool_backports.py
node scripts/dependencies/build-resolver.cjs --check
python3 -I -B .github/tests/test_resolver_backport.py
```

The output directory must not already exist. It is created with mode `0700` and
its three files with mode `0600`. The two Python builder commands read only local data; they never
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
entrypoint/dependency/other engine fields remain unchanged for braces and Forge. Resolver
also changes `files` to `["build"]` and declares exactly `js-yaml: 4.3.2` and
`micromatch: 4.0.8`; its original `main` and `types` remain unchanged. Every changed field
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

All records and command summaries retain:

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
The resolver retains the official five-member archive, four unchanged publisher
TypeScript files, original declaration/README/LICENSE.md, and identical added LICENSE.
`resolver/recipe.json` pins the public compiler script, TypeScript 6.0.3 manifest,
runtime compiler and license bytes/SRI, fixed CommonJS/ES2020/esModuleInterop options,
and all four source/output joins. `build-resolver.cjs` discovers only the normal
`sdk/expo/node_modules/typescript` installation. Its `--check` recomputes the four
outputs; `--output NEW_DIRECTORY` writes an independent private build. This is new
controlled transpilation, not publisher ncc/Bun build reproduction or a typecheck.
Physical outputs under `resolver/compiled/` map to logical `package/build/` members.
No opaque original bundle is included in the derivative payload.

Normal fixtures copy only the seven pinned nonaffected runtime dependency packages
from the project's installed dependencies and patched braces from the tracked archive.
Each independent fixture root declares its own archive specs and `$` override policy,
checks payload hashes and import origins, and uses no `NODE_PATH` bypass. These are
copied semantic fixtures, not npm install evidence. They cover all four exports,
sync/async agreement, npm/Yarn/pnpm forms, precedence/options, nested/absent workspaces,
ordinary read/parse failures, and original declaration consumers. The selected-version
license/metadata and four named advisory-range readbacks are bounded, not an exhaustive
advisory inventory.

The catalog retains original resolver bundled-braces ancestry and its unknown embedded
version, even when a local derivative lock no longer records the original bundle.
Current registry-lock observations remain unresolved until actual adoption is qualified.
Real consumer installs, required unsuppressed scans and full producer qualification
are separate work. Historical statements in the two immutable provenance records
remain historical; those records and all original retained bytes are unchanged. This
unit runs no vulnerability payloads and closes no advisory. External audit,
provider/deployment approval, publication and release readiness remain false.
