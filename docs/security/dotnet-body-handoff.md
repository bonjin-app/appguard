# ASP.NET Core cancellation at the body-to-identity handoff

2026-10-22; experimental Apache-2.0 .NET SDK. No public API, package version,
dependency, cancellation-token scope or wire-protocol change.

## Reproduced boundary and fix

The middleware already captured `HttpContext.RequestAborted` at invocation entry
and checked it after the input read loop. Final framing validation, host request
feature getters and body/request materialization ran after that checkpoint.
Cancellation arriving during this work could therefore start the application's
authentication callback with an already-canceled token. A later checkpoint
stopped key lookup, but could not undo authentication work already started.

The middleware now checks the same captured token after this final materialization,
immediately before authentication. An already-observed cancellation at this gate
prevents identity/key callbacks, the trusted clock, replay, verification-feature
publication and downstream dispatch. The existing canceled error path sets 400
without writing a JSON body; it disposes only the SDK-owned captured stream.
The caller's original input remains undisposed and is not rewound. Successful
requests retain exact signed bytes, caller identity and original-stream restoration.
An independent healthy request can use its own token and body normally.

## Evidence boundaries

Regression tests run the real middleware and P-256 verification with actual
memory streams. Test-only request-feature wrappers return unchanged method and
target values and trigger cancellation after EOF while the final request snapshot
is built. The wrappers introduce no SDK hooks, delays or probabilistic races.
Both original-token cancellation and replacing the context property after cancel
are covered, with positive signed binary-body controls and a real in-memory
nonce store for independent-request/replay checks.

This deterministic host-feature fixture establishes the handoff checkpoint; it
is not proof of a physical device or a new production ingress adapter. Existing
loopback Kestrel cases remain part of the full SDK suite. A local NuGet consumer
tests the packaged assembly independently of a source project reference.

## Limits

Cancellation is cooperative. The guard neither abandons an in-progress read or
callback nor interrupts synchronous copying/validation. Work ignoring the token
may keep the SDK pending until it returns. Cancellation after the last check but
before callback entry remains a check-and-dispatch race; callbacks must honor their
supplied token and enforce their own backend deadlines and admission limits.
No new body timeout or total request deadline is introduced.

Already-dispatched application work, host response delivery, committed nonce
claims, token notification latency and production resource limits remain host-owned.
The original stream can have been consumed to EOF; remaining readable does not
mean its position was restored. Local framework/fixture/package evidence does not
establish remote CI, production performance, external audit, live provider/device
verification, package publication or deployment.
