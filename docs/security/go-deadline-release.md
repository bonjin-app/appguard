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

## Local verification and independent review (2026-10-22)

The reviewed runtime commit is `4ff2e7fef311e2ffbc5be578f3830a374b2b8c3f` on local-main
base `006db575385a457328b4dbc29a51f30358bea579`. Existing local Go 1.27.3 on macOS ARM64 ran with
`GOTOOLCHAIN=local`, a private task build cache/GOPATH, read-only module flags
and no workspace overlay. Source checks disabled module proxy/checksum-network
access; no installer or new toolchain was invoked. The module still declares
Go 1.26; that minimum version was not newly executed. There are no external
module dependencies and the tracked `go.mod` is unchanged.

The source baseline passed 264 leaf cases. Eighteen new public-API cases first
produced 9 expected failures and 9 passing controls against the old runtime.
After the fix all 18 passed. The complete SDK passed 282 leaf cases under both
ordinary and race execution, with no failures or skips; vet and build passed.

Separate consumer projects downloaded baseline/fixed Go module ZIPs from a
private file-only proxy into fresh task-owned module caches. No `replace` or
source-tree project reference is used. The baseline repeated the same 9 expected
failures, with 10 controls passing including the actual loaded-module-origin check.
The corrected consumer passed 19 leaf cases under ordinary and race execution:
18 shared regressions plus one origin control. These counts overlap with the
source suite and must not be added as independent security scenarios.

The corrected ZIP SHA-256 is
`a6e974320e9c6386c4af4f803ce1e3d606d5093ad452a52cf96fdcbc88d51c41`. All 20 entries match reviewed Git, ZIP bytes,
retained snapshots and downloaded module-cache bytes. `go mod verify`, local
module sums, listed version/directory and runtime loaded-source origin were
checked. The local `v0.0.0-local.*` versions and disabled checksum-network access
prove local archive integrity, not public registry transparency or publication.

Raw JSON test logs, RED results, module/lock hashes, ZIPs, consumer sources and
independent review evidence are retained in
`.superpowers/evidence/2026-10-22-go-deadline-release/` in the primary checkout.
The final verification record changes only this document, preserving reviewed
SDK source, README and retained module ZIP bytes.

Independent security review found no scoped blockers. Fresh source ordinary/race
runs passed all 282 leaves, and vet/build passed. The downloaded regression
consumer passed 19 leaves under ordinary/race execution. A second, independently
downloaded module consumer passed seven leaves under ordinary/race execution:
one compiled-origin control and six loopback scenarios making eight actual
HTTP requests per run. These cover failed native reset followed by same-nonce
success/replay, reader panic cleanup, combined reader/reset panic, cancellation
with reset failure, and successful-reset cancellation preserving the 400 result.
All 20 archive entries match Git, retained source snapshots and both module caches;
local module checksums and compiled origins were independently verified.

An initial reviewer collector classified formatted non-test JSON as test JSONL.
Only count metadata was corrected; raw process outputs and successful exit codes
were unchanged. Original metadata/runner are retained, and there were no fixture
or SDK test failures in the final review runs. Historical RED was inspected
without rerunning and is not counted as fresh passing evidence.

Environment provenance distinguishes the supplied `GOTELEMETRY=off` value from
the Go tool's observed effective `local` mode. The bundled Go source documents
this as a non-settable environment value: local mode may collect local counters
but does not upload them. No global telemetry or Codex configuration was changed.
This is not a claim that telemetry was disabled, that tools wrote only inside
task directories, or that a packet-level network audit was performed.

Independent review receipt SHA-256:
`bf4fa88dcddca9190f2cfa39cbe7e18db2857fbd64e5e821edd1b7a32f0953eb`.
Review artifact manifest SHA-256:
`e2b453a13e82201b489f0e478e7f02af3b965d9a3adbdd51968f67c60e6d1bea`.
The disposable HTTP servers were closed by their fixture cleanup and successful
test processes. No deployed ingress, external audit, public release, provider or
physical-device verification is claimed.
