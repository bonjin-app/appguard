# Security policy

AppGuard is a draft reference project, not an audited or production-supported security product. No released versions currently carry security support commitments.

## Reporting vulnerabilities

Use this repository's private vulnerability reporting feature **if it is enabled and visible to you**. This document does not assert that the feature is configured. If it is unavailable, request a private reporting channel from the maintainers without publishing exploit details, credentials, personal data or production request captures. No private contact address is established by this repository yet.

Do not send live secrets, private signing keys or customer data. Prefer a minimal reproduction using the public fake fixtures. There is no promised response SLA or bounty program.

## Intended boundary

Request signatures do not authenticate Bearer tokens, enroll trustworthy device keys, prove Apple/Google approval, or grant resource access. Do not connect the reference verifier to a production API as a substitute for those controls. See the threat model and protocol for limitations and error handling.
