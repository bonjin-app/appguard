# Node body capture deadline hardening

2026-10-22; experimental Apache-2.0 Node SDK. No public option, TypeScript API,
dependency, wire-protocol or other SDK change.

## Reproduced behavior

The HTTP body collector previously enforced `bodyTimeoutMs` only with a timer.
The `end` callback concatenated captured chunks synchronously and then cleared
that timer. If the copy crossed the deadline while JavaScript was blocking the
event loop, the timer could not run before success settled. That late body could
reach authentication, key lookup, replay and the downstream application.

The existing default remains 30,000 ms. A single monotonic deadline now covers
body chunks, end handling, the final byte copy, the asynchronous capture handoff
and final framing validation before authentication. At or beyond the deadline,
the HTTP adapters return existing fixed 400 `INVALID_REQUEST` when the connection
still permits a response. Late bodies cannot invoke identity/key resolvers, the
trusted Unix clock, replay or downstream code. Each request receives its own
budget. Unexpired overflow retains the existing 1 MiB limit and 413 response.

The timer remains active for an incomplete asynchronous body. Settlement clears
only SDK-owned timers and listeners; rejection pauses the stream. Existing native
evidence, disconnect handling, exact body/target preservation and framework
integration remain in place. Express, Nest/Express and Fastify share this body
capture implementation. No authentication, replay, transport or provider default
becomes permissive.

## Limits

This is elapsed-budget enforcement when JavaScript can run, not synchronous
preemption. It cannot stop an in-progress copy, repair lost raw bytes, drain every
rejected stream, cap outstanding sockets/tasks or guarantee host resource cleanup.
Initial envelope parsing, later authentication/replay, post-verification body
replay and downstream application/parser work are outside this body budget.
Configure server header/read/backend timeouts, concurrency/admission limits and
shutdown behavior in the hosting application. A body timeout does not supply
business idempotency or authorize a request.

Local tests use genuine P-256 signatures, synthetic identities, actual loopback
HTTP and controlled test-only monotonic/copy instrumentation. Installed-package
checks additionally use a real monotonic clock and a blocking final-copy fixture.
They do not establish production performance, proxy/ingress behavior, remote CI,
live provider/device verification, package publication or a supported production
release. The physical-device candidate remains separate and unchanged.

## Local verification and independent review (2026-10-22)

The reviewed runtime commit is
`816b25267b82f503dfd942751e0d6814ab612e97`. A fresh frozen dependency install
passed the 561-test source baseline against a new task-owned disposable loopback
Redis instance. The final 45-case regression file was run against an independently
staged baseline runtime: 24 cases failed with the expected missing deadline
rejection, while 21 positive/compatibility controls passed. After the fix, all
45 passed; the complete SDK passed 606 tests with zero failures, skips or
cancellations, and TypeScript checks passed.

A separately packed baseline SDK reproduced four late HTTP 200 responses where
400 was required; three positive/timer/import controls passed. The corrected
package passed all seven installed probes, including actual loopback HTTP, native
P-256 verification, an actual-clock blocking final-copy fixture and a fresh-budget
retry after rejection. These consumer probes exercise the exported Express
middleware on native HTTP; complete Express/Fastify/Nest integration is covered
by the source framework tests. The documented `npm run test:install` smoke also
passed offline.

The corrected npm tarball SHA-256 is
`582138a026a0d513078565f872d6eee7137fba6b3abd6c679bab12921091f451`. All 15 package entries match committed source, tar bytes,
installed bytes and retained installed-source snapshots. The package has no
runtime dependencies; package manifests, lockfile and TypeScript declarations
remain unchanged.

Initial fixture failures are preserved rather than counted as product failures:
six source cleanup assertions counted a later Node-owned listener; three source
upload cases encountered EPIPE after an early rejection; six initial consumer
requests omitted Host and failed JSON decoding after Node's empty parser response.
Only the fixtures were corrected. Final source RED and package RED runs used the
corrected fixtures and demonstrate the actual old-runtime deadline acceptance.
The reviewer inspected historical RED/error evidence without rerunning it; those
records are reproduction history, not fresh passing checks.

Raw logs, TAP/JUnit where produced, source/package/lock hashes, isolated probes
and the independent review receipt are retained under
`.superpowers/evidence/2026-10-22-node-request-boundary/` in the primary checkout.
The final verification-record commit changes only this document, preserving the
reviewed runtime, packaged README/deployment guide and tarball bytes.

Independent review reported no substantive findings in this five-file scope.
Fresh review runs passed 606 source tests, seven installed-package tests and
three independent cases, with zero failures, skips or cancellations; type and
diff checks passed. The independent cases exercise source and installed entry
points, cumulative chunk/copy/microtask budgets, a real in-memory replay store,
retry behavior, owned cleanup and restoration of test instrumentation. Counts
overlap and must not be summed as distinct scenarios. Pre-existing allocation
exceptions from `Buffer.concat` in an event callback remain outside this deadline
fix; no allocation-failure recovery or supported production release is claimed.
