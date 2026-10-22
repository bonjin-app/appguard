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
