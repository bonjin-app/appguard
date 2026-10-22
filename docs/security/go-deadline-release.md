# Go body read deadline release

2026-10-22; experimental Apache-2.0 standard-library-only Go SDK. No public API,
module dependency, timeout default, wire protocol or other SDK change.

## Reproduced defect and change

The middleware installed a native body read deadline, read bounded body bytes,
then ignored the error returned while clearing that deadline. A writer wrapper
could accept setup but fail reset, and a valid signed request would still invoke
authentication, claim its nonce and dispatch the application with the read
deadline potentially active. A body reader panic also bypassed the reset entirely,
although the existing outer recovery returned an unavailable error.

After successful setup, a scoped defer now attempts exactly one zero-time reset
when body capture returns or unwinds through panic. A returned reset error becomes
fixed 503 `VERIFICATION_UNAVAILABLE`; reset or read panics retain the existing
redacted recovery response. No later trusted dependency, replay claim, proof
attachment or downstream handler runs on failed reset. Reset failure takes
precedence over a simultaneous read failure, cancellation observation or captured
body overflow. With successful reset, existing read-error 400 and overflow 413
behavior is preserved. Metadata rejected before capture never installs a deadline.

The initial setup error/panic still rejects before reading and does not claim a
successful installation or start a reset. The original request scope and evidence,
native framing validation, signature binding, body limit and replay policy remain
unchanged. An ordinary successful capture clears its deadline before authentication.

This closes an integration-wrapper failure path; it does not establish an
untrusted-client authentication bypass. The host still owns trusted raw ingress,
response-writer capabilities and application authorization.

## Verification scope and limits

Public-API tests use genuine independently constructed P-256 signatures, byte
readers, real local replay storage and controlled writer deadline failures. Cases
cover returned and panicking cleanup errors, misleading SDK errors, read errors
and panics, chunked overflow, initial setup failures, nested writer `Unwrap`,
empty/binary/maximum content, exact raw targets and existing context identity.
A failed reset must leave the nonce unused; a fresh same-nonce request succeeds,
and a subsequent duplicate is rejected. Owned input remains undisposed in the
direct middleware fixture, and failed capture does not replace its body or attach
proof. These controlled fixtures are not a production writer/ingress deployment.

The runtime's bundled `net/http.ResponseController` implementation documents that
zero means no read deadline and that an exceeded deadline cannot simply be
extended. This change does not promise to revive an expired/closed connection,
restore a prior host deadline, guarantee a reset succeeded when the writer rejected
it, or force an uncooperative reader/setter to return. It does not add goroutines,
hard cancellation, retries, host concurrency limits or a production raw collector.
HTTP server resources, response delivery and connection cleanup remain host-owned.

Only local toolchain/module/HTTP checks are in scope. Physical devices, provider
accounts, hosted CI, TLS/HTTP2/HTTP3/framework deployment, shared replay backends,
external security audit and public module publication remain unverified by this
stage. The existing physical-runtime candidate stays separate and unchanged.
