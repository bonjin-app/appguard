# Container finding detail evidence plan

> Use bounded delegated tasks, tests before implementation, and independent internal review. No recursive delegation.

**Goal:** Make positive runtime image findings actionable without publishing raw scanner reports, paths, URLs, descriptions, credentials or logs. Preserve the running main113 long-duration job and every independent release gate.

**Baseline:** main and the managed implementation branch start at 113167d. Run 39828223212 is in progress; do not update main while it runs. Existing image status schema 1 remains readable and does not acquire a finding-detail claim.

## Schema 2 contract

Retain the three artifact members and binding schema 1. Image status retains every schema-1 field, changes schema to integer 2 and adds exactly `scanner`, `databases`, and `finding_details_complete`. Every image row additionally has `findings` and `finding_details_complete`.

- `scanner`: null on setup failure, otherwise exact object `name`, `version`, `platform`, `archive_sha256`, `executable_sha256`. Name is `trivy`; version is `0.76.1`; platform is `Linux-x86_64` or `Darwin-arm64`; archive digest must equal the reviewed platform pin in scan.py. Executable digest records the installed bytes and is rechecked before/after commands.
- `databases`: null on setup failure, otherwise exact object `vulnerability`, `java`. Each exact row has `schema`, `metadata_sha256`, `database_sha256`, `updated_at`, `next_update`, `downloaded_at`. Vulnerability DB schema is 2, Java DB schema is 1. Timestamps are bounded UTC RFC3339 with up to nine fractional digits, `updated_at <= downloaded_at` and `updated_at < next_update`. These identify observed bytes; they do not prove database completeness or external approval.
- Explicitly download both databases into the private fresh cache before scanning, using pinned Trivy and sanitized environment. Vulnerability cache files are `db/metadata.json`, `db/trivy.db`; Java cache files are `java-db/metadata.json`, `java-db/trivy-java.db`. Hash regular stable files through bounded streaming, reject symlinks and changing identities, bound each database at 4 GiB and metadata at 64 KiB. Scan all three exact images with `--skip-db-update --skip-java-db-update`, and recheck the same database and executable identities across scans/publication. No suppression flags.
- Each finding has exactly `vulnerability_id`, `package`, `installed_version`, `fixed_versions`, `severity`, `source_class`, `package_type`, `occurrence_sha256`. Preserve every raw vulnerability row, including duplicate occurrences, unfixed, UNKNOWN and LOW severity findings. No deduplication. The occurrence digest hashes canonical raw result Target, PkgID, PkgPath and raw result/finding indexes, never publishing them.
- IDs: bounded `[A-Z][A-Z0-9]{1,19}(?:-[A-Za-z0-9]+){1,9}` (maximum 200). Package: maximum 200 ASCII characters, ordinary `[A-Za-z0-9][A-Za-z0-9._+:-]*` or npm `@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+`. Versions: maximum 200, `[A-Za-z0-9][A-Za-z0-9._+~:!*-]*`. Fixed versions are an ordered array of at most 32 such strings parsed from comma-separated FixedVersion; missing/empty becomes an empty array (only means no fixed version reported). Severity is exactly UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL. Source class is os-pkgs/lang-pkgs, package type is bounded `[a-z][a-z0-9-]{0,39}`. Maximum 1024 findings per image.
- If a raw finding cannot be projected or the bound is exceeded, keep the aggregate count, set that image's findings to an empty array and detail flag false; do not drop malformed rows from counts or invent zero findings. All setup, scanner version and database checks must also pass for the top-level detail flag. A setup/integrity failure remains container_scan_unverified. A positive aggregate keeps findings_present unless a stronger scanner/integrity failure occurred. Automated pass additionally requires complete details. A zero count without verifiable detail provenance cannot pass.
- Producer validates both schemas independently using stdlib and exact fields; partial schema-2 evidence can be staged only with internally consistent false flags. New verifier accepts complete schema 2 and independently validates its bounded lexical/count/database/scanner contract; schema 1 continues to support the existing operating gate and explicitly reports finding details unverified. New schema 2 detail fields do not clear image findings, native coverage, consumer, operator, legal or external gates. Do not import candidate code into the verifier or broaden network endpoints.

## Ownership and verification

1. Deep implementation worker owns scan_container_images.py, a new pure detail/DB helper if useful, and .github/tests/test_container_image_scan.py (plus focused new helper tests). Tests first; local synthetic reports and regular tiny DB fixtures; real Docker proof comes from CI.
2. Routine implementation worker owns bind_container_evidence.py and its tests. Keep schema 1 compatibility; no upload layout or privacy expansion.
3. Parent owns verify_container.py/tests, documentation and integration. Keep main113 verifier available for its ongoing run. Follow exact source/test evidence before any passing claim.
4. Independent internal review focuses on count conservation, privacy, stable tool/database binding, legacy compatibility, partial-failure flags and bounded resources. The previously rejected independent dynamic transport/ZIP probing is not repeated; this increment does not change that boundary.
5. Run complete appropriate tooling/release tests and workflow lint; use isolated branch CI for actual Docker and new status. Observe and authenticate the existing main113 long-run original ZIP before main moves. Merge only reviewed passing implementation checks; finding-positive scans remain failures and release_ready stays false. Follow with exact-main CI and fresh evidence.

Physical devices, registry publication, provider provisioning, actual production deployment, external approvals, and global Codex configuration are excluded. No existing evidence snapshot is mutated.

## Local implementation and review result

The scanner and producer each retain failing-before-implementation evidence.
All 191 tooling tests and 220 release tests pass with zero skips, including
42 scanner, 27 producer and 38 consumer tests. Tests include independent
producer validation of actual scanner-returned clean, finding-positive,
unprojectable-row, DB-failure, unknown-exit and missing-inventory statuses.
Workflow lint and diff checks pass. Scanner and producer internal reviewers
reran their focused tests and reported no confirmed findings. Consumer review
was static source/existing-assertion inspection only and reported no confirmed
findings. The previously rejected dynamic transport/ZIP review was not retried.

Actual Docker/Trivy downloads and image scans require the isolated-branch CI,
then fresh exact-main evidence after integration. Local test success is not an
image vulnerability pass, external audit, native-closure proof or production
approval. The existing 113167d sustained run must be observed without moving
main first. Its observations remain specific to that older commit.
