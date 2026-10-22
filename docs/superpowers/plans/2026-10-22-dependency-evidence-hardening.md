# Dependency evidence hardening

Continue the approved non-device security work in the existing isolated checkout.
No physical-device work, credential provisioning or registry release is included.

The current npm-only comparison accepts an empty SBOM when a Python lock records
cryptography. Publication also accepts a partial check set and reports an ordinary
vulnerability failure as an unverified secret scan. These are evidence-integrity
and diagnostic defects, not proof of an SDK request-verification bypass.

- [x] Reject missing/wrong Python, NuGet, Go and Composer recorded packages in source SBOMs; preserve exact origin, version and input hashes.
- [x] Reject missing/wrong resolved Maven runtime JARs in the runtime SBOM.
- [x] Require the complete expected check set and consistent raw scan reports before artifact publication.
- [x] Report distinct fixed denial reasons without exposing paths, errors or findings on denied publication.
- [x] Run regression suites, actual pinned cataloging and an independent security review.
- [x] Update the four README languages and release guide.

After committing this implementation, create and scan an exact-commit candidate,
verify both supplemental GAVs in Trivy package output, integrate the verified
commit into main, and inspect hosted checks plus the sanitized denial artifact.
Those point-in-time results belong to the matching commit receipt/Actions run,
rather than changing the candidate source to record its own future results.

Use the existing fail-closed publication boundary. Go sums are checksum ledgers,
not runtime lockfiles; local/project records and unsupported schemas need explicit
handling. Recorded dependency coverage never establishes installed/native closure.
Existing upstream HIGH advisories remain visible and keep the release gate blocked
until an actual supported remedy is verified. Do not suppress them to obtain a pass.
