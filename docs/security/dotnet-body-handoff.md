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

## Local verification and independent review (2026-10-22)

The reviewed runtime commit is
`f7dd5f1687e2f73b0c589f662f2399aac9f04c06`, on the independent local-main base
`7983d9aea57cdd8b805a64a81e098102a7f6b227`. SDK 10.0.402 ran locked restores
from a private copy of already cached NuGet dependencies, excluding older local
AppGuard packages. Development certificate generation and telemetry were disabled;
no runtime installer or external package service was invoked. Local restores
disabled NuGet audit network access; these checks are not a vulnerability-feed audit.

The baseline passed all 216 SDK tests. Seven new cases first produced five
expected failures because authentication ran once instead of zero times, with
two valid-body controls passing. The same seven cases passed after the checkpoint
was added. The complete Release suite passed 223 tests with zero failures, errors
or skips, and the solution build completed without warnings or errors. After the
runtime commit, the tested Release assembly was packed without rebuilding.

The local NuGet SHA-256 is
`bf01c3ae62002315f5819f2fa3b8a786a9583a13d4cb8e4f8dae475a1e91d99b`; its library DLL SHA-256 is
`2c3ff5e67ba35d97fc0ea411ffb957061f79bd1e1af3e6dba2883b3988d5c6f7`. All seven archive entries and retained unpacked snapshots were
verified. README/LICENSE match the source, and the package DLL equals the reviewed
source build, installed-cache DLL and actual loaded consumer DLL. The consumer
lock's SHA-512 content hash matches the complete NuGet archive.

The locked NuGet consumer has no source project reference and passed 224 tests:
the same 223 behavioral tests plus one actual assembly-origin/hash control. These
counts overlap and must not be summed as independent security scenarios. Existing
Kestrel loopback cases run in both suites; the new seven cases specifically prove
the deterministic host-feature handoff, rather than a new physical disconnect
or deployed ingress guarantee.

Raw logs, TRX results, locked consumer sources, package/DLL/lock hashes and the
independent review receipt are retained under
`.superpowers/evidence/2026-10-22-dotnet-body-handoff/` in the primary checkout.
The final verification-record commit changes only this document; reviewed runtime,
SDK README and the retained NuGet artifact remain unchanged. Assembly byte identity
is checked for the reviewed build/package/consumer. Builds in other checkouts or
a later Git revision can have different metadata or source paths.

An independent security reviewer found no actionable findings. Fresh review runs
passed 223 source tests, 224 installed-consumer tests and five independently
written installed-package controls, with no failures, skips or harness errors.
The Release solution build had zero warnings/errors. Independent controls covered
after-EOF cancellation with a replaced context token and throwing dependencies,
exact empty and maximum 1 MiB signed bodies with the live captured token,
downstream-exception stream ownership, and installed assembly provenance.
The reviewer also verified all seven NuGet entries, dependency-lock hashes and
source-build/cache/consumer/probe DLL identity.

The independent receipt SHA-256 is
`a1098b51130ed8481ed001060117d364bf86043825ce62e19ccfeb8d316b4cea`.
Cancellation remains cooperative, including the documented check-and-dispatch
race. No remote CI, deployment, provider, physical-device or external audit
evidence was collected in this stage.
