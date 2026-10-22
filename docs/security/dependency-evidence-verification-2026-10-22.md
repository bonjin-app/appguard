# Dependency evidence verification — 2026-10-22

This phase hardens unpublished-candidate evidence and artifact staging. SDK
request verification, SDK dependency versions, physical-device evidence and
external provider accounts are outside the change. Base: `5f52f7657e2de6c547fed35a4bc1d4fb5624b98d`.

## Reproduced defects and fixes

- An empty source SBOM passed while uv recorded cryptography. Python, NuGet,
  Go require and Composer records now need matching library identity, version,
  original location and safe input hashes. Local project exclusions are verified.
- Source file/excluded components, malformed PURLs and ambiguous JSON could
  masquerade as cataloged packages. Both npm and server records use the stricter
  shared observation boundary.
- Syft's raw Maven BOM cataloged only 35 of 37 primary GAVs accurately. Actual
  JAR hashes, independent raw outer-file hashes, the Maven dependency list and
  repository layout now bind two explicit supplements, preserving all 76 raw
  components. The resulting BOM has 78 components and 37 exact primary GAVs.
- A claimed aggregate pass with only two check records authorized copying.
  Staging now requires all eight distinct expected checks and consistent raw
  Trivy schemas, counts and zero vulnerability/secret findings.
- A zero-secret filesystem report substituted for a vulnerability report was
  accepted. Each command now captures input hash before execution, exact target
  and final report hash; artifact type/target and those hashes are rechecked.
- A report changed after validation could be adopted by late hash pinning.
  All report bytes are pinned before validation and compared again afterward.
- Staged license/dependency inventories were not compared with the manifest.
  Every copied candidate artifact and report is checked before completion.

The last three defects were independently reproduced in a separate read-only
security review, fixed, and independently rechecked. Denied cases retained only
`public-status.json`; private markers, paths and scanner errors did not appear.

## Local verification

The release suite passes **85 tests**, including real pinned Syft regressions,
with no skips in the configured local run. The same suite passes under Python
optimization (`-O`), so assertions are not security enforcement. Tests cover
missing/wrong identities, malformed inputs, type/scope/PURL tricks, unsafe paths,
changed JARs and overlays, missing/duplicate steps, replaced reports and mutations
around validation/copying. The source scan compares 631 npm plus 83 external
server records across eight server inputs, with six verified local exclusions.

An exact committed candidate and fresh Trivy scan are still required for each
integration; local regression success does not establish a hosted CI result.
See the matching commit's Actions runs and local receipt for that observation.
The full scanner retains raw evidence locally, but denied hosted artifacts
contain sanitized status only.

## Remaining boundaries

The pinned Syft version omits Composer `packages-dev`; nonempty development
records therefore block coverage instead of silently passing. Current Composer
arrays are empty. Go checksum history is not a selected dependency graph.
Supplemental Maven components have no guessed license metadata and remain part
of the manual license inventory. Recorded source/runtime scope does not prove
native, container or installed consumer closure.

The [known upstream HIGH findings](dependency-advisories-2026-10-22.md) remain
release blockers; no suppression or package substitution was introduced. License
review, independent external audit, provider/deployment qualification, device
validation where claimed, and explicit registry publication remain separate.
Local hash receipts are pipeline integrity evidence, not independent signed
attestation. `release_ready` remains false.
