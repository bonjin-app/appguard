# Non-device production-readiness execution plan

Proceed under the user's existing authorization, in the reusable isolated worktree.

- [x] Implement/test Go Redis adapter; verify concurrency/backend failures and canonical namespace.
- [x] Implement/test .NET Redis adapter; verify package consumers, backend failure/cancellation and namespace.
- [x] Implement/test PHP Redis adapter; verify actual configured client and strict return/error behavior.
- [x] Implement/test Apple initial metadata, assertions, atomic persistent counters/challenges and receipt lifecycle helpers.
- [x] Implement/test explicit Google OAuth token lifecycle.
- [x] Add a real bounded TLS Python ingress integration and exact-byte network tests.
- [x] Add deterministic fuzz/adversarial and owned Redis durability/fault/load runners.
- [x] Add release-candidate/SBOM/license/checksum preparation, scanner and artifact CI.
- [x] Run cross-language and isolated package consumers; run all affected suites.
- [x] Perform independent read-only review and resolve concrete findings.
- [x] Update English/Korean/Japanese/Chinese documentation and readiness boundaries.
- [ ] Merge/push SDK-verified main; inspect hosted technical jobs and the explicit release gate to completion and retain evidence.

Do not publish registries, provision credentials, use physical devices, merge the physical candidate or claim an external security audit. Track account-dependent/provider validations explicitly.

Expanded npm development-dependency coverage exposed pre-existing upstream HIGH
advisories in Expo build tooling (`braces`, `node-forge`) without fixed upstream
releases. The compatible config-plugins/xcode update removes the UUID finding.
Keep all findings visible and keep release qualification blocked; do not confuse
passing SDK integration with a production release or override the security gate.
See `docs/security/dependency-advisories-2026-10-22.md`.
