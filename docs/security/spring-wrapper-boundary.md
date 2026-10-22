# Spring initial request wrapper consistency

2026-10-22; base `89e5464d4b90a1753c98a4760da35f67e2949b7b`.
Experimental Apache-2.0 Servlet SDK; no wire protocol or dependency change.

## Problem and behavior

The filter captures the unwrapped connector request, then preserves the outer
request's authentication behavior for the application. Previously an upstream
wrapper could change `/public` to `/admin`, the HTTP method, or header accessors
while the original signed envelope still passed. The application then observed
a different initial request carrying successful verification metadata.

The filter now rejects divergent initial wrapper views with HTTP 400 and exactly
`{"code":"INVALID_REQUEST"}`, before identity lookup, clock sampling, replay
claim, proof attachment or downstream execution. It compares method, request URI,
query string, context path, servlet path, path info, content type and character
encoding. Absent and explicit empty query strings remain distinct. The raw method
is captured alongside URI/query/headers and used by the verifier.

Complete header name/value maps must agree: names are case-insensitive and name
ordering is irrelevant; value ordering, multiplicity and bytes remain exact.
Direct `getHeader` and `getHeaders` lookups (original and lowercase names) must also agree with the
captured values. Outer enumeration uses the existing 64-value/16-KiB budget.
Missing evidence and ordinary getter exceptions use the same fixed failure.
This conservative rule also rejects rewriting/hiding unsigned headers.

[Jakarta's wrapper contract](https://jakarta.ee/specifications/servlet/6.0/apidocs/jakarta.servlet/jakarta/servlet/http/httpservletrequestwrapper)
explains that getters delegate unless overridden. No wrapper is discarded:
identity-only Spring Security wrappers still supply the Principal and roles;
captured body replay and async startup behavior remain unchanged.

## Trust boundary

This guard applies only to the initial `REQUEST`. Existing per-filter proof
continues to support trusted async/error/forward/include redispatch without a
second nonce claim. Internal dispatch may change its route; the application must
authorize the destination and must not interpret original request proof as a new
external signature for that destination.

All host Java code remains trusted. This is a consistency check, not a sandbox
against wrappers/callbacks mutating after capture, downstream replacement
wrappers, overridden parameter APIs, custom servlet mapping APIs, or changes
before the SDK's capture point. Applications must preserve their trusted filter
chain, raw connector evidence and normal Servlet getter contracts. Query parsing
and application authorization remain the host's responsibility. Fatal JVM errors,
resource exhaustion, production transport and shutdown behavior are not covered.

## Local verification

Runtime commits `72c16a72a6f090429a7fbf53cb5abd6e5c967429` and
`8f79bc0da65fcbff90c332f0920ac7dda3e3ddde` were verified locally using
JDK 17.0.20+8 and offline Maven 3.10.0. Subsequent changes to this guide only
record verification.

- Baseline: 229 tests passed with no failures/errors/skips.
- Corrected regression run against baseline: 21 cases, 18 expected failures and
  three passing controls. A separate actual Tomcat route-rewrite regression
  returned HTTP 200 before the fix where HTTP 400 was required.
- Independent review found an original-case-only `getHeaders` bypass when the
  wrapper's name enumeration was lowercase. A new regression failed before the
  follow-up fix (one failure among 22 cases). Both original and lowercase plural
  lookups are now checked; the independent probe confirms rejection before any
  identity/nonce/downstream work.
- Final full Maven package: **252 tests passed**, no failures/errors/skips,
  including shared vectors, real Tomcat/Spring Security and a task-owned
  persistence-disabled loopback Redis. Every owned Redis child was stopped.
- Final copied-JAR consumer: **30 cases passed**, including 22 focused cases and
  eight embedded HTTP methods. Project SDK output directories were excluded;
  SDK code-source locations were checked. All 37 compiled class/resource entries
  and the embedded POM matched the packaged artifact.
- Final independent review: **42 additional probes passed**, plus a fresh run of
  the 30-case JAR consumer. It verified header budget equality/overflow, duplicate
  value order, getter/enumeration failures and fixed error privacy, healthy
  same-envelope retry/replay, identity/roles, all trusted dispatcher types and
  unverified redispatch rejection. The reviewer verified 52 source files and 86
  dependency hashes, independently recompiled the filter classes and matched
  both generated entries to the JAR. It did not rerun the entire Maven suite.

Final JAR SHA-256:
`d9d168e649f6f553c96519838564659bd523f84f671c45373600d710d0369d94`.
Review receipt SHA-256:
`b47e45d2481195b9aea8cd9858af492cce9396fded0c36758d5e9ad25551cc3d`.
No unresolved blockers remain within the reviewed scope. Counts overlap; they
must not be summed as unique tests.

Initial harness corrections are retained: one collector included stale Surefire
reports, and a replay fixture reused a consumed mock body before its body stream
was reset. Final counts come from fresh XML and raw logs. Earlier artifacts and
all diagnostic failures remain distinct from the final reviewed artifact.

Commands, reports, source/JAR hashes and independent review are retained in the
main checkout under `.superpowers/evidence/2026-10-22-spring-boundary/` after local
integration. Physical Android/iPhone Release IL2CPP validation remains pending
separately; local HTTP tests are not physical-device or deployed evidence.
