# Fixed-snapshot Debian Java diagnostic closure

The third `debian-closure` diagnostic target preserves the complete vendor JRE
and the existing baseline and intentionally incomplete Debian comparison. It
adds the six measured missing SONAME providers, fontconfig and DejaVu core from
the historical `20261022T200000Z` Debian/trixie and Debian-security/trixie-security
archives. Production images and release approval remain unchanged.

Implementation checked locally; actual APT/solver/native proof remains pending.

## Trust and installation

- [x] Record exact eight direct versions, architecture, archive sizes and SHA256
  from the independently retained snapshot indexes in a bounded TSV lock.
- [x] Use only the two historical HTTP snapshot sources, each signed by the
  immutable Debian base's archive keyring. HTTP bootstraps without adding CA
  packages; APT signature verification and fixed InRelease SHA256 anchor the
  metadata/archive hash chain. Disable Valid-Until only on these past sources.
- [x] Require successful APT signature verification and both exact InRelease
  hashes before downloading/installing. Never enable insecure APT options.
- [x] Download exact direct versions without recommends/removals, verify every
  downloaded archive identity/hash against authenticated APT metadata and direct
  lock pins, recheck before `--no-download` installation, then verify all archive
  identities against installed versions. Preserve dpkg, copyright and licenses.
- [x] Retain lock, releases, keyring identity, archive and complete installed
  package manifests. Their successful build-time checks are diagnostic evidence,
  not independently authenticated installation or native vulnerability closure.

## Readback and verification

- [x] Add explicit `--dependency-closure`: require fixed manifest files in the
  existing owned isolated container, validate their bounded grammar/hashes and
  compare the complete installed manifest to both live dpkg and main inventory.
  Schema3 includes this evidence; default schema1 and features-only schema2 stay
  unchanged. Missing/unverified evidence cannot silently complete collection.
- [x] TDD parser/identity/hash/duplicate/architecture/missing/signature rejection;
  meaningful installer validation tests; existing complete qualifier tests.
- [x] Extend native workflow to six jobs, retaining the broken comparison and
  requiring closure only for the new target. Two additional native-architecture
  comparison jobs collect native results for the same baseline/closure image IDs
  passed to one scanner session; `comparison.json` binds those three original
  report hashes, exact image IDs, architecture and the source lock. It verifies
  identity bindings, not all native/vulnerability report semantics. Run shell syntax/actionlint/full
  relevant local tests. Actual APT/signature/solver/native behavior requires CI.

The selected fonts exercise the existing headless check; no CA/locales or Java
features are removed or added speculatively. All production, complete/native
coverage and external-approval flags remain false. No CVE-clean claim follows
from this diagnostic increment.

## Pending actual evidence

- [ ] Run APT authentication/solver/install and all native architecture jobs in CI.
- [ ] Inspect the same-image comparison artifacts and independently calibrated
  vulnerability measurements; neither package installation nor a zero count
  establishes complete native coverage, licensing or production approval.

Local evidence is under `.superpowers/sdd/debian-runtime-closure-2026-10-23/`: an
initial failing parser/integration/workflow/installer/comparison regression was
observed before its implementation, followed by focused and full tooling checks.
The shell archive tests use owned bytes with fake Linux metadata commands; they
do not substitute for real APT signature verification or dependency solving.
