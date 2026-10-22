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

Verification results, artifact identity, independent review and integration
readback will be recorded here after execution. Physical Android/iPhone Release
IL2CPP validation remains pending separately.
