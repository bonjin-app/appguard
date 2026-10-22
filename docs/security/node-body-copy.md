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
