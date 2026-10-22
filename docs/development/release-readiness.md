# Unpublished candidate and supply chain checks

These tools prepare reviewable local/CI evidence. They create no tags, GitHub
releases, registry uploads, signing keys or account resources. A passing scan is
not an external security audit or approval for production use.

## Create a source candidate

Requirements: Git and Python 3.11 or later (the lock validator uses standard-library `tomllib`). Run from a **clean committed checkout**,
including no untracked files. Ignored build outputs do not affect the snapshot.
Use an existing directory outside the checkout; the output directory must not
exist. Avoid symlink aliases (on macOS, prefer the resolved temporary path).

```sh
python3 -m unittest discover -s scripts/release/tests -v
candidate_parent="$(python3 -c 'import tempfile,pathlib; print(pathlib.Path(tempfile.mkdtemp(prefix="appguard-review-")).resolve())')"
python3 scripts/release/candidate.py --output "$candidate_parent/candidate"
python3 scripts/release/scan.py --candidate "$candidate_parent/candidate" --output "$candidate_parent/scans"
```

The source snapshot ignores Git replacement objects, verifies every blob object
identity, reads immutable Git HEAD blobs, checks clean state and HEAD
again before completion, rejects included symlinks/submodules/special files and
unsafe paths, and atomically renames a complete staged directory. Existing
outputs are never replaced. It does not commit, clean or modify the input.
`source.tar.gz` uses sorted names, normalized mode/owner/time and deterministic
gzip metadata. `manifest.json` records the exact commit, excluded tracked paths
and SHA-256 for every candidate file except the manifest itself. The archive is
rooted at `appguard/`. Keep the manifest with the archive; hashes alone do not
authenticate who prepared it.

The tracked-source allowlist includes root README/license/security/contribution
files and `sdk/`, `reference/`, `scripts/`, `tools/`, `docs/`, `conformance/`, `protocol/`, `examples/`, and
`.github/` and `deploy/`. VCS state, toolchains, dependencies, build outputs, `.evidence`/`.artifacts`, private folders,
credential-like names and common private key formats (including Apple `.p8`)
are excluded. CLI `bin/`
is explicitly included source. This policy is defense in depth, not a secret
classifier; review `excluded` and run secret checks. Public fake PEM fixtures
remain source and may trigger findings requiring documented review.

## Scanner provenance and coverage

`scan.py` downloads **Syft 1.54.1** and **Trivy 0.76.1** from official release
assets, validates hardcoded SHA-256 digests before extracting only the named
regular executable, and uses a bounded temporary home/cache. Reviewed pins are
provided for Linux x86-64 and macOS arm64; other hosts fail without guessing.
There is no remote shell installer, scanner action, floating tag or runtime
`latest` lookup. Pins were checked against the official GitHub release asset
API on 2026-10-22:

- [Syft release](https://github.com/anchore/syft/releases/tag/v1.54.1)
- [Trivy release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1)
- [Anchore verification guidance](https://oss.anchore.com/docs/installation/verification/)

Review upstream security advisories and asset provenance when updating pins.
Checksum verification protects the reviewed bytes; this tool does not claim
independent verification of release signatures. Network access to GitHub release
assets and Trivy's public vulnerability database registries is required. No
registry login is performed. Database updates are time dependent; scanner
results and SBOM timestamps are not expected to be byte reproducible.

Syft emits `sbom.cdx.json` (CycloneDX) from all candidate source/lockfiles,
including recorded Python/npm/Go/NuGet/PHP inputs. Trivy scans that SBOM with
`--scanners vuln`, without re-resolving Maven POMs.

Source Syft configuration explicitly sets `javascript.include-dev-dependencies:
true` ([official option](https://oss.anchore.com/docs/capabilities/javascript/)).
This includes the framework/Redis and Expo peer-test graphs recorded as npm
development dependencies, rather than cataloging only the root projects.
Only `lockfileVersion: 3` is supported. Missing/malformed package maps, root
records, package objects, non-link versions or flag types fail with a coverage
validation error. Explicit links require a resolved target and are recorded
separately, without inventing a package version.
After cataloging, every versioned `package-lock.json` record must appear at its
original lockfile location in the SBOM with matching npm purl name/version
(including percent-encoded scoped packages); any omission fails the automated gate.
`source-lock-coverage.json` pins the SBOM and each source lock by SHA-256 and
retains the original development, optional and peer flags for each record.
Syft CycloneDX output does not encode those npm development flags as component
scope, so the linked coverage report preserves their classification without
relabelling development records as runtime dependencies. Unversioned/link
records and native/platform resolution remain explicit limitations.

The reviewed Trivy 0.76.1 `sbom` command explicitly disables `--include-dev-deps`
([official tagged command source](https://github.com/aquasecurity/trivy/blob/v0.76.1/pkg/commands/app.go));
passing that flag fails. It scans the supplied Syft-cataloged npm records,
including development records, without that flag.

The same source coverage gate now independently compares recorded **Python uv
v1/revision 5**, **NuGet lock v1**, **Composer** and declared **Go require** packages.
Each external record needs the same package identity/version and original input
location on a cataloged library component. `source-lock-coverage.json` retains
per-input SHA-256, per-target/direct/transitive/dev/optional classification where
recorded, and verified local-project exclusions. Python editable/directory/virtual
projects need a matching in-tree `pyproject.toml`; NuGet Project records need a
matching in-tree project reference. Unsupported formats, malformed identities,
unsafe paths or missing packages fail closed. No resolver or package script runs.

Go coverage requires each selected `require` version and its archive plus
`go.mod` checksum records. Other `go.sum` entries are historical/test metadata,
not a runtime lock graph. This conservative parser supports module/go/toolchain/
require directives; replacements, exclusions, retractions or unsupported syntax
fail rather than inventing a resolved graph. Composer checks both `packages` and
`packages-dev`, with platform requirements recorded separately. The pinned Syft
1.54.1 cataloger currently omits Composer development packages
([tagged upstream parser](https://github.com/anchore/syft/blob/v1.54.1/syft/pkg/cataloger/php/parse_composer_lock.go));
adding any such dependency therefore causes a visible coverage failure. The
current Composer arrays are empty; this is not proof of PHP installed closure.

`all_recorded_packages_cataloged` and the scanner's
`recorded_source_lock_coverage_passed` flag cover these supported recorded inputs.
The older npm-only flag remains for diagnostics and cannot authorize publication.
Source manifests without a supported recorded graph remain explicitly incomplete
in `dependency-coverage.json`. Cataloging does not establish installed, native or
universal dependency closure.
An opt-in regression against a reviewed real Syft binary can be run with
`APPGUARD_SYFT=/absolute/path/to/reviewed/syft python3 -m unittest discover -s scripts/release/tests -v`.
The actual source scan always executes this comparison.


The primary Java gate uses actual Maven-exported libraries rather than guessed
POM versions:

1. Copy the candidate Spring Boot module into bounded temporary state.
2. Run the pinned `maven-dependency-plugin:3.8.1:copy-dependencies` and `:list`
   goals with `-DincludeScope=runtime` and repository-layout output paths.
3. Hash the exported JARs in `maven-runtime-manifest.json`, and retain the exact
   resolved list in `maven-runtime-dependencies.txt`.
4. Preserve Syft's actual output as `sbom-maven-runtime.raw.cdx.json`. Require
   each outer JAR's exact location and SHA-256 to be independently observed.
5. Compare repository-layout coordinates against the full Maven dependency list.
   If Syft omits a primary Maven coordinate, add a marked component only when
   both sources agree on the same hash-verified JAR. Preserve **every raw component**,
   including embedded and incorrect upstream identities, in the final
   `sbom-maven-runtime.cdx.json`; nothing is dropped to hide findings.
6. Record the raw BOM, JAR, manifest, dependency-list and final BOM hashes and
   supplements in `runtime-catalog-overlay.json` and `runtime-lock-coverage.json`.
   Recompute this provenance and require an exact scannable library GAV for every
   exported JAR (including its classifier). Then scan the final BOM with Trivy.

Syft 1.54.1 uses the OSGi Bundle-SymbolicName as a namespace when some JARs lack
embedded Maven metadata. For the current export this misidentifies jspecify and
reactor-core. The explicit supplemental components retain the authoritative
Maven coordinates alongside the untouched scanner evidence; classifier omissions
are handled by the same bound procedure. Empty raw BOMs, absent file hashes,
changed JARs, conflicting coordinates and tampered provenance remain failures.

Maven and Java are required. Set `APPGUARD_MAVEN_CMD` to one Maven executable
path if `mvn` is not on PATH. The default Maven cache lives in temporary state.
For a previously resolved cache, explicitly set `APPGUARD_MAVEN_REPOSITORY` to
its absolute path; Maven may add downloaded artifacts to that selected cache.
No settings or credentials are copied or reset. The JVM home and scanner home
are temporary. Missing Maven, missing dependencies, network failures, missing
exports, or scanner failures remain nonpassing. Maven runtime scope excludes
provided/container and test dependencies, which must be assessed in the actual
consumer deployment. No filesystem vulnerability pass redundantly re-resolves
the same Maven graph.

Secret-only filesystem scanning uses `--offline-scan` to prevent unrelated
POM lookups; this does not imply offline dependency coverage. All severity
levels are enabled and no findings are ignored by this wrapper. License
discovery runs in separate `--scanners license --exit-code 0` passes
with all severity levels retained. This exit code separates inventory from
security gating; it does not approve any SPDX identifier or legal terms.
Every NOTICE or unknown/other license finding remains pending in
`license-review.json`, alongside missing license metadata and hashes linking
back to full license JSON and SBOM inputs. `THIRD_PARTY_NOTICES.review.md`
is an unapproved review index; original copyright/license texts still require
maintainer inspection and complete distribution notices remain a release gate.
Every vulnerability or secret finding (at any severity), scanner failure,
checksum failure, timeout or candidate mutation fails the automated gate.
License scanner execution/report failures also fail; license findings remain
visible manual obligations rather than vulnerability failures. Independent
available scanner passes still run after a Maven resolution failure. `status.json` includes exit codes, finding counts and
`automated_checks_passed`. The process can exit zero for completed technical
checks while `release_ready` remains false with explicit independent-audit,
license/notice review, native/deployment consumer coverage, dependency coverage
and maintainer governance/publication gates. It never reports license compliance.
Full `trivy-sbom.json`, `trivy-maven-runtime.json`, separate license JSON,
raw `trivy-secrets.json` and logs remain in the new output directory even on failure. Inspect raw reports
locally; they can contain secret snippets and should not be published or pasted
into public issues. Temporary binaries/caches are deleted after each run;
exported Maven libraries remain in the local report directory for review.

`dependency-coverage.json` enumerates recognized manifests/lockfiles throughout
the allowlisted source and explicitly reports `complete_resolved_graph: false`.
Per-manifest entries identify colocated recorded lockfiles and missing locks.
It is a source input inventory, **not a substitute SBOM**. Neither cataloging nor
lockfiles prove that all runtime/native/transitive dependencies were resolved
or bundled. Swift/Gradle/Flutter/Unity/native platform resolution and resulting
binary SBOMs require their actual toolchains. Package manager resolution and
consumer tests are separate evidence. `licenses.json` locates source license
texts; maintainers must review dependency licenses and notices in the scanner
output, including unknown or missing licenses. A scanner's default license
policy is not a legal determination or an approved project license policy.

## Package and consumer verification

Run the existing verification jobs against the **same candidate commit** before
accepting its artifacts. Required toolchains, isolated dependency installation,
disposable Redis and detailed commands are in the verify workflow and SDK docs:

```sh
# Requires a fresh disposable loopback Redis and the documented toolchains.
APPGUARD_TEST_REDIS_URL=redis://127.0.0.1:6379/0 bash scripts/test-server-sdks.sh
bash scripts/test-extended-server-sdks.sh
npm --prefix tools/cli test
npm pack ./tools/cli --json --pack-destination "$candidate_parent"
npm --prefix sdk/expo ci --ignore-scripts
npm --prefix sdk/expo test
npm --prefix sdk/expo run typecheck
npm --prefix sdk/expo run verify:pack
swift test --package-path sdk/apple
```

The core runner builds Python/Java and runs Node package installation consumers;
the extended runner verifies Go/.NET/PHP; Expo verifies a relocated package.
Use package-manager JSON output or explicit configured filenames to identify
artifacts; never select a guessed wildcard or upload an entire SDK build tree.
Platform-specific Android, Flutter, Unity, device and provider requirements
remain separate. Building a package does not authorize its registry publication.

## CI and maintainer gates

`.github/workflows/release-readiness.yml` runs on pushes, pull requests and manual
requests with read-only repository permission. It creates an unpublished source
candidate and executes scanner checks. Artifact staging independently requires
all eight distinct expected checks (Maven export, both catalogs and five Trivy
passes), integer zero exit codes, and raw vulnerability/secret/license JSON
whose counts agree with the recorded command evidence. Each Trivy command
records the exact input hash before execution, target name and final report hash.
The gate checks the report's artifact type/target against its recorded role and
rechecks these hashes against the current BOM or candidate manifest. Swapping a
zero-secret filesystem report into a vulnerability report cannot satisfy this
binding. These are local pipeline integrity receipts, not signed attestation of
an independently trusted scanner. Claimed aggregate success,
missing/duplicate checks, boolean exit codes, malformed reports, or any actual
vulnerability/secret finding cannot authorize copying. The gate also requires
matching candidate/expected commit identities, the initial manifest SHA-256,
source coverage revalidated against current locks/SBOM, and runtime coverage
recomputed from actual JARs, raw/final BOMs, the dependency list and overlay.
The Maven POM hash must match the candidate. It checks candidate/report integrity
again after copying and revalidates the JAR evidence before completing staging. The scanner requires the exact initial manifest bytes to remain
unchanged throughout all scans, so rewriting both source and manifest cannot
adopt a new input snapshot.
Only after that verification can archives, inventories, SBOMs, license JSON and
other source-bearing metadata be retained for seven days. Raw secret reports
and logs are never included.

If any automated check fails, or secret evidence is unavailable, malformed or
disagrees with the candidate, the upload contains only `public-status.json`: fixed booleans,
an integer result code where verified and opaque hashes under fixed labels.
Fixed `reason` codes distinguish `vulnerability_findings`, `secret_findings`,
`scan_checks_failed`, unverified scan/candidate/source/runtime evidence and copy
failure. They never contain scanner messages or source metadata. No source/archive,
filenames, package inventory, raw error messages or scanner snippets are copied.
The workflow uploads only this staged directory, including under `always()`;
it never uploads candidate/scanner paths directly. A passing secret scan is a
bounded automated check, not proof that all sensitive content was detected.
Repository administrators still need to enable Actions, allow the pinned
checkout/Python/artifact actions, provide outbound scanner/database access,
review artifact visibility/retention, and configure required branch checks.
No hosted run or branch protection is implied by adding the workflow.

Before any public release, a maintainer must reconcile findings, verify a fresh
same-commit build/consumer and supported-platform matrix, resolve dependency
coverage gaps and license obligations, review package contents/checksums,
complete an independent security audit appropriate to the intended deployment,
and explicitly approve versions, registry ownership, signing/provenance and
publication. Device/provider evidence remains required wherever the product
claims depend on it. This tooling does not establish a support SLA or security
reporting contact; see the existing security policy for its actual limits.

The scanner CLI emits only fixed check names, exit codes and numeric finding
counts to CI stdout. This makes a blocked source vulnerability gate visible
without publishing raw secret reports, component paths or parser errors. The
full reports remain local; artifact staging still requires all technical checks
and zero-secret evidence to pass. A count summary never overrides a failed gate.

See the [2026-10-22 evidence hardening review](../security/dependency-evidence-verification-2026-10-22.md) for reproduced defects, regression coverage and current limitations.

## Separate readiness assessment

Generate a fixed-schema gate ledger from the same candidate and scan evidence:

```sh
python3 scripts/release/assess.py \
  --candidate "$candidate_parent/candidate" --scans "$candidate_parent/scans" \
  --expected-commit "$(git rev-parse HEAD)" --output "$candidate_parent/assessment"
```

The normal command reports blocked/pending gates without failing report creation.
Add `--check` to exit2 while any required gate remains blocked or pending.
`--profile mobile-attested` adds provider-account requirements; the default
`server-signature` profile makes no physical-device claim. Optional
`--qualification /absolute/path/to/receipt.json` references the narrow local
[Spring mTLS qualification](../deployment/spring-ingress.md).

The assessor reuses the complete publication validator and pins input bytes.
An untrusted qualification JSON, even with every check or `approved` set true,
cannot grant production approval. Local receipts are referenced as unverified;
external audit, license approval, hosted/deployed validation and maintainer
approval remain pending until a supported trusted verification process exists.
Every v1 assessment retains `release_ready:false`. `doctor --check` continues
to mean local tool prerequisites only.

The hosted workflow retains only this fixed-schema assessment separately from
the existing gated publication artifact. It never includes scanner exceptions,
raw requests, arbitrary input fields or approval text in that report.

`--hosted-run-id NUMERIC_RUN_ID` now verifies a completed main push run directly
through the fixed GitHub HTTPS API and binds its entire source tree/archive to
this candidate. This can satisfy the hosted CI gate; it does not import a saved
approval or pass other gates. The final release decision is derived from all
required gate states and remains false while unsupported external approvals or
findings remain. See the [production goal and commands](production-release.md).
