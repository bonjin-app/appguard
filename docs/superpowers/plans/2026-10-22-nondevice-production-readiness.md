# Non-device production-readiness execution plan

Proceed under the user's existing authorization, in the reusable isolated worktree.

- [ ] Implement/test Go Redis adapter; verify concurrency/backend failures and canonical namespace.
- [ ] Implement/test .NET Redis adapter; verify package consumers, backend failure/cancellation and namespace.
- [ ] Implement/test PHP Redis adapter; verify actual configured client and strict return/error behavior.
- [ ] Implement/test Apple initial metadata, assertions, atomic persistent counters/challenges and receipt lifecycle helpers.
- [ ] Implement/test explicit Google OAuth token lifecycle.
- [ ] Add a real bounded TLS Python ingress integration and exact-byte network tests.
- [ ] Add deterministic fuzz/adversarial and owned Redis durability/fault/load runners.
- [ ] Add release-candidate/SBOM/license/checksum preparation, scanner and artifact CI.
- [ ] Run cross-language and isolated package consumers; run all affected suites.
- [ ] Perform independent read-only review and resolve concrete findings.
- [ ] Update English/Korean/Japanese/Chinese documentation and readiness boundaries.
- [ ] Merge/push only verified main; inspect hosted CI to completion and retain evidence.

Do not publish registries, provision credentials, use physical devices, merge the physical candidate or claim an external security audit. Track account-dependent/provider validations explicitly.
