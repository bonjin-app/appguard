# Unpublished candidate and supply chain checks

These tools prepare reviewable local/CI evidence. They create no tags, GitHub
releases, registry uploads, signing keys or account resources. A passing scan is
not an external security audit or approval for production use.

## Create a source candidate

Requirements: Git and Python 3.9 or later. Run from a **clean committed checkout**,
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
`.github/`. VCS state, toolchains, dependencies, build outputs, `.evidence`/`.artifacts`, private folders,
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
including development records, without that flag. Existing Python, NuGet,
Go and PHP source catalogers continue cataloging their recorded inputs;
this setting does not establish universal or native dependency closure.
An opt-in real-scanner regression can be run with
`APPGUARD_SYFT=/absolute/path/to/reviewed/syft python3 -m unittest discover -s scripts/release/tests -p test_source_catalog.py -v`.
The actual source scan always executes lock-to-SBOM coverage validation.


The primary Java gate uses actual Maven-exported libraries rather than guessed
POM versions:

1. Copy the candidate Spring Boot module into bounded temporary state.
2. Run the pinned `maven-dependency-plugin:3.8.1:copy-dependencies` and `:list`
   goals with `-DincludeScope=runtime` and repository-layout output paths.
3. Hash the exported JARs in `maven-runtime-manifest.json`, and retain the exact
   resolved list in `maven-runtime-dependencies.txt`.
4. Catalog those actual libraries into `sbom-maven-runtime.cdx.json` with Syft,
   then run `trivy sbom --scanners vuln` into `trivy-maven-runtime.json`.

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
passing automated checks and an explicit successful secret pass with zero
findings, matching candidate and
expected commit identities, the scanner-pinned initial manifest SHA-256, a successful source coverage flag,
a pinned coverage report that revalidates against the SBOM and current locks, and an unchanged checksum-verified
candidate. The scanner requires the exact initial manifest bytes to remain
unchanged throughout all scans, so rewriting both source and manifest cannot
adopt a new input snapshot.
Only after that verification can archives, inventories, SBOMs, license JSON and
other source-bearing metadata be retained for seven days. Raw secret reports
and logs are never included.

If any automated check fails, or secret evidence is unavailable, malformed or
disagrees with the candidate, the upload contains only `public-status.json`: fixed booleans,
an integer result code and opaque hashes under fixed labels. No source/archive,
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
