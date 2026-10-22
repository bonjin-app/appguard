# Diagnostic immutable-image vulnerability comparisons

This is a diagnostic measurement path. It neither substitutes a production
runtime nor produces a qualification receipt or native dependency closure.
The existing three-service `scan_container_images.py` CLI, required receipt,
role policy, public result schema, and accepted production scanner hosts remain
unchanged. The shared tool table gains a reviewed native Linux AArch64 Trivy
pin; the production scanner explicitly retains its prior host set.

## Interface and evidence

```sh
python3 scripts/qualification/scan_diagnostic_images.py \
  --image sha256:<baseline-local-image-id> \
  --image sha256:<candidate-local-image-id> \
  --platform linux/arm64 \
  --docker-context default \
  --output "$RUNNER_TEMP/appguard-java-comparison/scan"
```

Accept one or two distinct immutable local image IDs and one of `linux/amd64`
or `linux/arm64`. The image order is preserved in `diagnostic.json.images`;
the top-level `platform` is the join key for the separately collected native
reports. No service-role aliases, qualification receipts, caller-supplied
reports, scanner binaries, databases, or transport implementations are accepted.
The scanner inspects and reads existing images only. It does not build, pull,
run, remove, or relabel images or create containers.

Exit 0 means a complete zero-finding measurement with the applicable control;
1 means a complete positive-finding measurement; 2 means incomplete or
unverified measurement. Only `diagnostic.json` is intended for artifact upload.
Private raw image/control reports and logs remain in the new output directory.
The public report projects validated identifiers, package versions, severity,
source class/type and occurrence hashes, preserving duplicate and unfixed
occurrences across every severity. Raw paths, URLs, environment, logs and error
messages are not copied into it. Detail/count mismatch, unknown scanner exit,
missing inventory, truncation, or integrity failure cannot produce completeness.

`release_ready`, `external_approval`, `native_binary_coverage`,
`coverage_complete` and `complete_resolved_graph` are always false. No secret
scan is performed (`secrets: null`). A separately implemented comparison binder
may hash-bind exact-image native reports and this measurement; that join does
not transfer proof from separately built images or reverify all their semantics.

## Shared fixed session and limits

`TrivySession` reuses existing reviewed bounded commands, descriptor-owned
publication, checksum installation, database identities and finding projection.
It is used only by the diagnostic path. The installer runs in an owned child
process group using the existing official-archive checksum/extraction helper.
Linux AArch64 uses Trivy 0.76.1 archive SHA-256
`e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f`,
from the official `trivy_0.76.1_Linux-ARM64.tar.gz` release asset. The existing
Linux x86_64 and Darwin arm64 pins are unchanged. This is checksum evidence,
not a Sigstore assertion.

One private HOME, Docker configuration, empty Trivy config/ignore file,
executable and both downloaded databases serve the entire comparison and control.
The Docker context must be `default` with a local Unix endpoint. Inherited
Docker/Trivy credentials and overrides are excluded. All scans use vulnerability
scanning, every severity, list-all-packages, no ignore-unfixed filter, disabled
DB updates, `--offline-scan`, and parallelism 2. Offline scan disables dependency
API lookups; it is not an OS network isolation claim.

The output parent must belong to the current UID and disallow group/other
writes. The diagnostic wrapper checks this policy on the adopted parent
descriptor, with the existing path/descriptor identity check, before entering
the private session. Both final guards recheck the descriptor policy, including
for incomplete results. The shared publication implementation is unchanged.

The session gives commands a shared 2,760-second deadline. Installation and
each DB download/image scan have at most 660 seconds; the metadata control has
75 seconds; Docker commands have 30 seconds. Hash/identity checks have their
existing per-file bounds and can add overhead outside command deadlines.
At most two images of at most 2 GiB each are accepted. Existing bounds remain
16 MiB per raw report, 2 MiB per command output/log and public JSON, 1,024 projected
finding occurrences, 4 GiB per DB, 64 KiB DB metadata, and 512 MiB executable
and downloaded tool archive. OS inventory additionally limits result rows to
4,096 and packages to 100,000. Host process RSS is not hard capped. These are
workload, elapsed-command, file and output bounds, not a hard RAM/disk quota.

Pre/post image inspections bind the exact ID, Linux architecture, OS and size.
The report must identify the same image. Config/executable/DB hashes, empty
ignore identity, fixture identity and raw report identity are checked before
publication and at publication readback. A final integrity exception clears
calibration interpretation flags; a publication-time mutation aborts publication.
If the sanitized envelope exceeds its bound, findings are omitted with detail
completeness and zero-finding interpretation both cleared; actual counts remain.
Cleanup terminates only owned child process groups and removes only the private
temporary state and descriptor-owned unpublished output. Shared images and
caches are untouched. Actual tool/DB identities remain in the public report.

## Debian 13 feed control

Create a fresh private metadata-only rootfs containing exactly:

- `/etc/os-release`: Debian 13 / trixie.
- `/etc/debian_version`: `13.0` (the pinned Trivy Debian OS parser reads this).
- `/var/lib/dpkg/status`: installed `openssl` version `3.5.1-1`, matching source
  package/version and requested architecture, explicitly described as metadata.

No package binaries are installed or executed. Scan it with the same executable,
frozen DB files and offline flags as the images. Require exactly the intended
OS/package/source identity and an actual Debian result for `CVE-2025-9230`,
installed `3.5.1-1`, fixed `3.5.1-1+deb13u1`, data source `debian` / `Debian
Security Tracker`. The fixture and report hashes are retained separately from
image identities; it must never be described as a runtime artifact.

This establishes recognition of that selected Debian advisory only. It does
not establish all-CVE completeness, Ubuntu feed coverage, equal vendor policy,
or bundled JRE/native binary coverage. Per-image `debian13_control_observed`
applies only to a Debian-major-13 image. `zero_findings_interpretable` requires
that applicability plus valid package inventory, complete detail and exit 0.
An uncalibrated zero makes the overall measurement incomplete. Positive Ubuntu
findings can be collected as counts with both interpretation flags false.
Missing/unknown control blocks completeness while preserving parsed image
finding counts. A zero must never be described as verified clean.

Primary implementation/advisory references:

- [Debian CVE-2025-9230 tracker](https://security-tracker.debian.org/tracker/CVE-2025-9230)
  records the trixie fixed version and DSA-6015-1.
- [Trivy 0.76.1 Debian OS parser](https://github.com/aquasecurity/trivy/blob/v0.76.1/pkg/fanal/analyzer/os/debian/debian.go)
  and [dpkg parser](https://github.com/aquasecurity/trivy/blob/v0.76.1/pkg/fanal/analyzer/pkg/dpkg/dpkg.go)
  define the fixture inputs and split Version/Release and source fields.
- [Trivy 0.76.1 Debian detector](https://github.com/aquasecurity/trivy/blob/v0.76.1/pkg/detector/ospkg/debian/debian.go)
  supports Debian 13 and queries by source package/version and major OS release.
- [Pinned trivy-db Debian source](https://github.com/aquasecurity/trivy-db/blob/cbebf2ecd6df/pkg/vulnsrc/debian/debian.go)
  defines the Debian data-source identity.
- [Official Trivy 0.76.1 release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1)
  supplies the reviewed platform archives and checksums.

## Verification and limits

Tests exercise the real private publication/file primitives with bounded fake
Docker/Trivy commands. Meaningful fail-first regressions cover an uncalibrated
Ubuntu zero, native installer wall deadline, and post-control image mutation
clearing interpretation flags. Additional checks cover one shared DB snapshot,
actual dpkg split fields, all-severity duplicate/unfixed findings, wrong source
or fixed version, invalid/missing inventory, immutable image/platform binding,
late report/DB mutation, redaction, CLI exits and private cleanup. Existing
production scanner tests retain the original receipt/role/host policy.

A real Darwin arm64 metadata control was observed using the pinned Trivy and
fresh frozen DBs, with expected Debian 13, source package and fixed advisory.
The retained private report contains only calibration findings; these are not
runtime image counts. A repetition after installer hardening is retained
separately from the initial observation. Actual Linux image comparison
and native architecture execution remain CI work; local mocked tests or the
metadata calibration do not establish them.

Before the final envelope correction, 22 diagnostic tests, 48 existing
production scanner tests, 263 tooling tests (one existing skip), and 228 release
tests with the reviewed pinned Syft all passed. Independent review then found
that oversized projection could retain a zero-interpretation flag after clearing
details. The fail-first regression uses one zero image and a second image with
350 valid findings, each with 32 bounded fixed versions. The correction clears
only zero interpretation alongside detail completeness and preserves the 350
occurrences. A second review found that the initial parent permission decision
preceded descriptor adoption. Added fail-first handoff tests independently
simulate a bad descriptor UID and writable mode, plus an owned-directory mode
change after publication. The new diagnostic-only descriptor check rejects
before session creation and removes output on the final policy failure.
The updated 25 diagnostic and 48 production scanner tests pass;
combined full-suite revalidation is performed by the integrating agent.

The actual metadata control completed in 129.28 seconds before the final CLI
flag and output-parent policy corrections; the shared session, calibration parser and report commands
are unchanged. Its private status SHA-256 is
`cefed638181633ae10a4186795a6274804ba9213e9b16771c8b9f250087a9a8a`;
the raw control report SHA-256 is
`44b92e42b6ba743356d431c045e6c1b74a2903b9dc929a26ace7d3398ac911a5`.
The retained proof records scanner, database and source hashes. The calibration
findings belong solely to the synthetic metadata control, not either image.
