# Maintained tool backports design

Design proposal only, based on393a524. Replace affected installed tool bytes through reviewed local derivatives;
renaming packages must never clear source findings. Product adoption, new execution and publication are not authorized here.

## Choice and staged scope

Recommend deterministic local archives with explicit npm consumer-root overrides, provenance and ancestry scanning.
This works with `npm ci --ignore-scripts`; postinstall patching would leave that supported path unmodified.
First package and verify braces/Forge without adoption. Add ancestry catalog/scanning next, before any consumer overrides.
Then verify real consumer integration and propose an unbundled resolver derivative,
which removes its embedded unguarded braces copy without editing an opaque bundle or reviving the old ncc/Bun graph.
This is the author's proposed build choice, pending root review; two derivatives alone never establish full braces closure.

## Tracked packages and build contract

Use `tools/dependency-backports/{manifest.json,README.md,archives/,braces/,node-forge/,resolver/}`.
Each package directory retains its SRI-bound `upstream.tgz`, readable original manifest/license, exact patch/provenance,
and readable changed source under `replacements/source/`; do not duplicate the entire original59-file Forge tree.
Keep the rebuilt six JS/three map replacements physically under `replacements/distribution/`, mapping to logical archive `package/dist/*`.
Resolver outputs later live physically in `resolver/compiled/`, mapping to `package/build/*`; preserve its four input TS files separately.
Candidate filtering forbids any physical build/dist/vendor/artifacts path component. Use these safe paths without broad allowlist exceptions.
The builder assembles all original members directly from `upstream.tgz`, then applies only declared replacements/additions and inventories every result.
`archives/` contains `appguard-braces-3.0.3-appguard.1.tgz`, `appguard-node-forge-1.4.0-appguard.1.tgz`, and later
`appguard-resolve-workspace-root-2.0.1-appguard.1.tgz`; package names are respectively `@appguard/braces`,
`@appguard/node-forge`, `@appguard/resolve-workspace-root`, with the matching version suffix and private=true.
These are maintained derivatives, not upstream fixed releases. Preserve runtime main/browser/types contracts and dependencies.
Explicit metadata-only changes remove all original scripts and devDependencies, set the supported Node floor to22.13,
and record every field change against the retained original manifest; do not rely on a lifecycle hook or registry publication.
Preserve every published payload file, including Forge Flash assets, except the enumerated code/manifest/distribution replacements.
Keep original copyrights and full licenses: braces MIT, Forge `(BSD-3-Clause OR GPL-2.0)`, resolver MIT; no relicensing/legal approval.

`scripts/dependencies/build-backports.py --check` verifies inputs, exact replacements and tracked archive bytes without execution;
explicit `--output DIR` produces new artifacts only. Use sorted USTAR files under `package/`, mode0644, mtime/uid/gid0,
empty owner names, then fixed-header gzip with stored DEFLATE blocks of at most65535 bytes and fixed CRC32/ISIZE encoding.
This avoids host-zlib byte drift. Refuse unsupported names/types, duplicates, links, omissions and unexpected additions;
cap each archive16MiB, expanded payload32MiB and512 files. Repeated independent assembly must match SHA256 and npm SHA512 SRI.
The first unit has exactly top-level `{schema:1,packages:[...]}`, with the two ordered IDs `braces`, `node-forge`.
Each package record has exactly `id,upstream,fork,inputs,replacements,result_files,archive,provenance`:

- `upstream`: `{name,version,url,path,sha256,integrity,size}`; integrity is exact npm SHA512 SRI and path is the retained original archive.
- `fork`: `{name,version}`; replacement package.json must match it, private=true and the declared metadata/API policy above.
- `inputs`: physical relative regular-file path → `{sha256,size}`, covering readable source/patch/license/manifest and replacement/producer records.
- `replacements`: ordered `{path,input}` entries mapping unique logical `package/*` members to a declared physical input; additions are explicit here too.
- `result_files`: complete logical `package/*` regular-file path → `{sha256,size}`; all unchanged upstream members must remain byte-identical.
- `archive`: `{path,sha256,integrity,size}` for the deterministic result; `provenance` is a declared-input JSON path retaining immutable refs/licenses/limitations.

Reject unknown/missing keys, Boolean sizes, malformed hashes/SRI, identity disagreement or inconsistent inventories. No network lookup or candidate code runs.
Minimal Python interfaces: `load_manifest(root:Path)->dict`, `assemble_package(root:Path,record:dict)->bytes`,
`check_archives(root:Path,manifest:dict)->dict`, `write_archives(root:Path,manifest:dict,output:Path)->dict`.
Check reconstructs both byte streams and compares tracked archives; write uses a new private owned directory and never overwrites existing files.
Only fixed IDs/digests/counts/Boolean results are emitted, with fixed public errors. Catalog classifications/consumer bindings belong to the next unit.

## Exact candidate lineage and resolver proposal

Braces starts from frozen `braces-backport-evaluation-static-a860ca301a8b`; its `candidate.json` report SHA256 is
6505c74aec1a2b44cd34470c7a994912e1cb8feaf5fac3349631747b35f0ad9f, not a source-tree identity:
five guard files changed, original parser quote/comma semantics preserved. Its later12-source normal release proof passed764,
pending0, child attempts0; this is no fresh Bash oracle, general work-budget proof or new depth/cycle authorization.
Forge uses published1.4.0 plus PR1159 head `db05494352dd3c9a5a07c5270333dcc78866cad2` and the reviewed round2 candidate
six JS distributions/three maps, not the earlier source-only copy with stale dist. Bind its artifacts manifest
24f38e2e49350673b3b9a9d9ea8809fec019109f065cff9713423075aa346b02 and the later12-case/380-outcome execution receipt.
First-unit README/provenance must set `compilation_reproduction_verified=false` and `producer_closure_verified=false` for Forge.
Deterministic archive assembly and installed-payload equality prove neither compilation reproduction nor complete producer inputs.
Before production adoption, retain the readable reviewed modern Webpack recipe, full producer lock/config, exact Node/npm/tool pins
and source/output joins under `node-forge/producer/`; static retention or a private receipt alone cannot establish reproduction.
Independently rebuild all six JS/three maps from those public tracked inputs and match every expected digest, or stop with reproduction unverified.
This is required reproducibility work, not upstream-build reproduction or legal approval; all other approval boundaries remain unchanged.
Retain warnings, pending/skipped upstream cases, lax-parser/interop limits and unverified browser/mobile scope; no universal crypto claim.

Proposed resolver inputs: publisher gitHead `72f675ae9ea952e832c63f1138346406b0d8630b`, unchanged `src/index.ts` and
`src/utils/{dirs,files,workspaces}.ts`, original LICENSE.md and exact published `build/index.d.ts`.
The captured official2.0.1 archive is31755 bytes/SHA256161fd5f13b2fc116b4332c25bb1d4983a2f983b15e01d647d5ac1209fd309694;
registry SRI/SHA1, five members and source/declaration joins are retained. Original bundle SHA starts ee3be37c; do not ship it in the derivative.
`scripts/dependencies/build-resolver.cjs` uses already-pinned TypeScript6.0.3 `transpileModule`, CommonJS/ES2020/esModuleInterop,
four separate JS outputs and original declarations; this is a controlled new build, not publisher reproduction or type-check proof.
Declare current Expo-lock js-yaml4.3.2/micromatch4.0.8 runtime dependencies after exact integrity/license/advisory review;
they differ from historical Bun pins. Preserve four exports, defaults, pnpm precedence, sync/async errors and matching semantics.
Require normal filesystem/export/type-consumer comparisons before adoption; types/package routing and semantic equivalence remain unverified.

## Consumer and honest source scanning

Packaging alone changes no consumer lock, scanner policy or gate. Only after ancestry catalog/scanning is reviewed,
put logical-name overrides in `sdk/expo/package.json`, regenerate only its reviewed lock delta, and require local-archive SRI joins.
Paths are `file:../../tools/dependency-backports/archives/...`; there is no repository-root package.json to inherit overrides from.
Every separate test/producer consumer root must declare the same policy; overrides inside transitive packages do not protect consumers.
Verify fresh/relocated same-lock installs, original logical require paths, actual fork metadata/origins and complete installed file hashes.
All npm/build/test/pack routes use `scripts/dependencies/verify-backports.cjs`; `verify.yml` and `sdk/expo` scripts/README wire that check.
The benign synthetic resolver proof1b9ab5fc4c753874b19e3c0b0a64f7dd022e71e2501dfa6065a00f601f898e8a proves the mechanism only.

Add `scripts/release/tool_backport_catalog.py`: `prepare_tool_backport_catalog(source,reports)` writes a dedicated
`sbom-tool-backports.cdx.json` and `tool-backport-provenance.json`; `validate_tool_backport_catalog(source,reports)` reconstructs both.
Preserve original Syft/raw/source components and the existing exact Python overlay validation; do not rewrite their documents in place.
Catalog actual archive identities separately from original affected `pkg:npm/braces@3.0.3` and `pkg:npm/node-forge@1.4.0`,
classified `upstream-ancestry-not-installed-runtime`; retain resolver ancestry and unresolved bundled-copy provenance too.
Use scanner-visible library components with non-excluded scope and explicit ancestry properties, not an excluded component or VEX.
`source_catalog.py` accepts supplemental local-lock coverage only through reconstructed hash/SRI/location-bound catalog records.
`scan.py` adds unsuppressed `trivy-tool-backports` and `trivy-tool-backports-licenses` inputs, report bindings and required-command validation.
Missing catalog/ancestry, tampered archive, ignored command or mismatch fails closed; raw source and ancestry findings both remain visible.
GHSA-vfj7-8cjw-p6xm and GHSA-86w9-cpqp-85rv remain unsuppressed; all required scan results determine the gate, never a fork-name scan alone.
Full graph/native coverage, external/legal/release approval stay false; maintenance means owning review, upgrades and regressions, not auto-clearing advisories.
