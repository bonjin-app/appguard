# Node captured-body copy exception containment

2026-10-22; experimental Apache-2.0 Node SDK. No public API, TypeScript,
dependency, wire-protocol, configured limit or other SDK change.

## Reproduced defect and change

The final `Buffer.concat(chunks, size)` runs in the native request's `end`
listener, after the body-capture Promise executor has returned. A JavaScript
exception thrown by that copy therefore escaped event dispatch instead of
rejecting the capture Promise. Without a host uncaught-exception handler, the
request could terminate the Node process.

The copy now catches recoverable JavaScript exceptions and settles capture
through the existing fixed 400 `INVALID_REQUEST` path. The original error object,
message, code and status are not used as an authorization or error-response
decision. Existing cleanup removes SDK-owned body listeners, clears its timer
and pauses the rejected stream. The connection observer is disposed by the
existing enforcement `finally`. No identity/key resolver, trusted clock, replay
claim, verification attachment, downstream parser or application handler runs
for that failed capture. A fresh request can reuse its unclaimed nonce; once a
successful request claims it, the existing replay protection still rejects it.

The catch surrounds only the final copy. Existing monotonic body deadline and
framing checks still apply after a successful copy. The 1 MiB content limit,
oversize 413 response, exact signed bytes/target and authentication policy are
unchanged. Express, NestJS with Express and Fastify share this collector.

## Verification boundaries

Regression tests run actual framework HTTP adapters, native loopback sockets,
P-256 verification and the real in-memory replay store in disposable child Node
processes. A test-only wrapper observes the native `end` event and throws only
at the final copy of the exact captured chunk references. RangeError, generic
Error and an error with a misleading verification code/status exercise the
same failure boundary. It is restored before the following healthy request.
There is no uncaught-exception suppression. Empty and maximum 1 MiB valid bodies
are positive controls; binary retry requests preserve raw and parsed bytes and
the duplicate-query target exactly. Tests also check fixed response headers,
zero trusted/downstream calls, capture-listener removal, stream pause and absence
of verification attachment on rejection.

The faults are deterministic JavaScript exceptions, not physical low-memory or
stress evidence. Fatal V8 out-of-memory termination, native aborts, OS process
kills and allocations at other boundaries remain outside this containment.
This does not provide ingress admission/concurrency control, guarantee resource
cleanup for the host, or establish production resilience under exhaustion.
No new provider, physical-device, remote CI, deployment or publication evidence
is collected by these local checks. The physical-runtime candidate remains
separate, with hardware verification pending.

## Local verification and independent review (2026-10-22)

The reviewed runtime commit is `067cdd93f182338209f40fdb4c2d7e197e133cdf` on local-main
base `e68f4d85bd2042a13df096a9497623acd37783e6`. A frozen offline dependency install passed before
verification; Node 22.23.2 and npm 10.9.8 used the unchanged dependency lock.
A task-owned disposable loopback Redis 7.2.10 ran without persistence. These
local offline checks are not an external vulnerability-feed audit.

The unmodified source baseline passed 606 tests. The new 15-case suite first
produced nine expected failures: the unhandled native-end copy exception
terminated each child instead of returning a controlled rejection. Six normal
empty/maximum-body controls passed. After the fix, all 15 passed; the complete
SDK suite passed 621 tests with no failures, skips or cancellations. TypeScript
checks and the documented isolated npm install/import/signature smoke passed.

The final regression fixtures were also run through actual frozen npm consumers
with their own dependency installations and no SDK source link. The baseline
package reproduced the same nine failing exception cases with six controls
passing; the corrected package passed all 15. The source suite includes these
15 cases, so source/consumer counts must not be summed as independent scenarios.
The consumer's non-SDK dependency-lock entries equal the original SDK lock.

The corrected tarball SHA-256 is
`85fbc0ef245356fe4eb7aa8f6e4f47554fd0e2a3486bf1c82be8652c927f1ee8`. All 15 archive entries match the reviewed Git
source, retained source snapshots and installed package bytes; the install-smoke
tarball has the same SHA-256. Package manifests, dependency lock, TypeScript
declarations and the wire protocol are unchanged, with zero package runtime
dependencies. The package remains an unpublished experimental local artifact.

Raw logs, frozen consumer inputs, baseline/fixed archives and source snapshots,
package/lock hashes and the independent review receipt are retained under
`.superpowers/evidence/2026-10-22-node-body-copy/` in the primary checkout.
The final record commit changes only this document, preserving the reviewed
runtime and tarball bytes.

Independent security review found no blocking findings. Fresh review runs passed
621 source tests, type checks, 15 installed-package regression tests and three
independently written installed-package boundary probes. Those probes covered
split uploads with RangeError/primitive throw and an empty Fastify body with a
misleading verification error/status. All final runs had zero failures, skips
or cancellations. They verified five capture listeners and three connection
observers removed, the capture timer cleared, SDK pause invoked, no trusted or
downstream calls/verification attachment, same-nonce retry and later replay
rejection. All 15 package entries and 152 frozen non-SDK dependency-lock entries
were checked independently.

An initial independent harness expected the empty Fastify stream to remain
paused after response completion. Its failing run and debugging reproduction
are preserved: tracing showed SDK pause(true), followed by native Node
IncomingMessage._dump/resOnFinish resuming the already-ended raw stream. The
corrected probes assert the SDK's actual pause invocation and owned cleanup,
and retain the final host stream state. This was a fixture assumption, with no
additional runtime change; the original harness attempts are not counted as
passing product checks.

Independent review receipt SHA-256:
`ca4f74630040c81529c6fd600d90b38adadac73ffb15267846d77cc7ca108515`.
No fatal out-of-memory, production-exhaustion, physical-device, remote CI or
deployment evidence is claimed.
