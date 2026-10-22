# Security policy

AppGuard is a draft reference project, not an audited or production-supported security product. No released versions currently carry security support commitments.

## Reporting vulnerabilities

Use [GitHub private vulnerability reporting](https://github.com/bonjin-app/appguard/security/advisories/new).
It was enabled and its enabled status read back through GitHub's repository API
on 2026-10-22. Sign in to GitHub to use the private report form. If it is unavailable,
request a private reporting channel from the maintainers without publishing
exploit details, credentials, personal data or production request captures.
No separate private email contact is established by this repository.

Do not send live secrets, private signing keys or customer data. Prefer a minimal reproduction using the public fake fixtures. There is no promised response SLA or bounty program.

## Intended boundary

Request signatures do not authenticate Bearer tokens, enroll trustworthy device keys, prove Apple/Google approval, or grant resource access. Do not connect the reference verifier to a production API as a substitute for those controls. See the threat model and protocol for limitations and error handling.

## Verification and release scope

The [non-device qualification](docs/development/nondevice-readiness.md) documents
software, transport, operating-failure and release-candidate checks. Automated
vulnerability/secret checks fail on reported findings; license and notice output
remains an unapproved review inventory. Passing checks do not confer independent
audit, complete native dependency coverage, provider approval or production support.
No physical-device or live provider-account result is inferred from synthetic
fixtures, host tests or hosted CI.
