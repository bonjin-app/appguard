# Spring Principal subject binding

2026-10-21; base `c1f7004bd51603973011c271f6b16a03b7d2d55c`;
experimental Apache-2.0 server SDK.

## Reproduced adapter inconsistency

`IdentityResolver.fromPrincipal` previously evaluated `Principal.getName()` inside
the key-lookup call, then again when constructing `Identity`. With a custom
mutable Principal or a lookup callback that changes its state, those values can
differ. Tests using valid P-256 signed requests reproduced legitimate-key
rejection and, when the callback also returned another subject's key, acceptance
against that replacement subject instead of the one used for lookup. Principal
getter failures were also caught as key-repository failures because the first
getter evaluation occurred inside the key callback's `try` block.

These are controlled trusted-host fixtures, not evidence of a remote bypass of
immutable Spring Security principals. Existing authentication must finish before
AppGuard; a correct, stable host authentication context remains required.

## Change and boundaries

The adapter now reads the name once inside each invocation and checks the same
identifier contract already enforced by the filter: 1–128 ASCII letters, digits,
period, underscore, colon or hyphen. A malformed value is rejected before key
lookup. The same String is used for the lookup and returned Identity. This does
not add cross-request caching, change the Principal object or override later
application reads of its state.

Name-getter exceptions are classified by their origin rather than trusting a
dependency's exception code. Both direct adapter calls and the filter receive
the fixed identity reason without retaining a private dependency cause.

The existing verifier still binds the key to the captured subject, configured app
and signed key ID. A key for a different subject rejects before nonce claims or
dispatch. Error responses remain fixed:

| Condition | HTTP/code |
| --- | --- |
| No Principal | 401 `AUTHENTICATION_REQUIRED` |
| Principal getter failure or malformed subject | 503 `IDENTITY_UNAVAILABLE` |
| Key callback exception or malformed non-null key contract | 503 `KEY_RESOLVER_UNAVAILABLE` |
| Unknown or mismatched subject key | 403 `KEY_REJECTED` |

Wire format, cryptography, replay storage, public API/configuration, dependency
versions and synchronous servlet execution are unchanged. This does not add
timeouts, forced callback termination, token authentication, enrollment or
business-resource authorization. Host code owns Principal lifecycle and any
mutation/concurrency outside this adapter invocation.

The official [Java 17 Principal documentation](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/Principal.html)
defines the name getter. The consistent snapshot is AppGuard's adapter choice;
the fixtures do not assert that normal Spring principals mutate in production.
Local mock/embedded-container or copied-JAR evidence is separate from deployed
ingress/load/failover, hosted CI, external audit, provider or physical-device proof.

## Local verification and independent review

Runtime and regression commit `1b708a7a8120769e6682a4e4f26015a28968739c`
was reviewed independently with no actionable findings. The subsequent record
commit changes only this guide.

- Baseline: 211 Java tests passed. Before the fix, five of the first six new
  regressions failed. Two added getter-origin/direct-adapter cases then failed
  against the intermediate snapshot implementation, exposing the remaining
  exception-boundary issue.
- Final Maven package: 219 tests passed with zero failures, errors or skips,
  including eight new Principal regressions, the shared corpus, embedded
  Tomcat/Spring Security and an isolated local Redis instance.
- A standalone consumer compiled and ran all eight regressions against a copied
  SDK JAR with project output directories excluded. All 37 compiled class/resource
  entries and the embedded POM matched the built artifact. This is local artifact
  verification, not registry publication or deployment.
- The independent reviewer freshly passed 18 selected Maven tests, eight
  copied-JAR regressions and eight independent copied-JAR probes. These covered
  adapter reuse, concurrent invocation isolation, valid subject-length boundaries,
  failure classification/privacy and deliberate fatal-Error propagation. The
  reviewer inventoried the 219-test report rather than rerunning that full suite.

These counts overlap and must not be added as unique tests. Python and Node.js
runtimes and the common protocol were unchanged; their suites were not rerun for
this Java-only change. Controlled mutable-host fixtures establish the adapter
behavior, not a remote bypass of immutable Spring Security principals.

Local commands, reports, source/artifact hashes, review receipt and integration
readback are retained under
`.superpowers/evidence/2026-10-21-spring-principal-binding/` in the main checkout.
