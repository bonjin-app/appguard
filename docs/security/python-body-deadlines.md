# Python ASGI body deadline hardening

2026-10-21; base `a4cbc5fe363e2b0a6fdc6a5591585298938324b3`;
experimental Apache-2.0 SDK.

## Reproduced issue and change

Body capture already calculated a cumulative `body_timeout`, but each read used
`asyncio.wait_for`. A host ASGI `receive` that suppresses cancellation can keep
the SDK waiting beyond that budget, or delay propagation of caller cancellation.
A non-yielding receive can also supply a final event after its deadline, allowing
body capture to continue into authentication. Tests also reproduced invocation
of a receive that did not get its first scheduling turn until after expiry.

Each read now has an owned task and a bounded `asyncio.wait`, with one monotonic
deadline covering all chunks, framing validation and the final byte copy. Both
the parent and read task check expiry before initiating host work; the parent
checks again before processing the returned event. On timeout the SDK requests
best-effort cancellation without awaiting resistant cleanup, returns existing
400 `INVALID_REQUEST`, and initiates no further body reads. Late events do not
reach authentication, the trusted clock, core verification, replay or dispatch.
Caller ASGI-task cancellation propagates without an SDK response.

Pending read tasks stay strongly referenced until completion; their eventual
exceptions are retrieved without logging private details. A wrapper coroutine
preserves receive callables returning Futures or other awaitables. Existing
1 MiB/body framing checks, 413 errors, defaults (30s body, 10s identity), public
configuration, protocol, dependencies and identity/resolver behavior are unchanged.

## Limits and reference

The host must provide a correct ASGI receive implementation. The SDK does not
preempt blocking code, forcibly terminate an already-running read, drain a stream
or close the transport. A pending host receive can continue internally even after
the SDK has stopped initiating new calls. Late result rejection occurs when the
event loop can run; this is not a real-time response guarantee.

Pending host work can outlive requests or never finish, consume resources and
delay shutdown. The guard supplies no outstanding-task or connection cap. Configure
ASGI-server/ingress read timeouts, admission/concurrency limits and lifecycle
cleanup. Body and identity budgets are separate; this adds no verification/replay
or total request deadline, and no background HTTP-disconnect monitor.

The [Python 3.11 task documentation](https://docs.python.org/3.11/library/asyncio-task.html)
describes `wait_for` cancellation waits, `wait`, cancellation and task retention.
Local checks use CPython 3.11.15 and in-process ASGI transports. Deployed ingress,
load/failover, hosted CI, external audit, provider and physical-device verification
remain separate gates. The Unity physical candidate stays separate and pending.

## Local verification and independent review

Independent security review approved
`ad04c913b8a364f9513c701cfe7b88ec759fbb3a` with no unresolved findings.
The initial receiver fixture yielded to the HTTPX stream after blocking, which
let three overrun cases reject already. The strengthened fixture returns a final
event without yielding again; final RED reproduces 17 failures with three
existing-contract controls passing. All 20 new cases then pass after the fix.

Recorded local checks, with zero skipped tests:

- Baseline Python SDK: 600 pass; final Python SDK: 620 pass.
- Body/ASGI/identity/sync-cleanup regressions: 122 pass.
- Common runner: reference Python 209, Python SDK 620, Node SDK 561 and Java SDK
  211 (1,601 total); package/type checks and cross-SDK Redis sequential/concurrent
  replay checks also pass.
- Isolated offline-installed wheel: 122 regressions pass; 21 packaged source/assets
  match reviewed source and installed files, with README metadata readback.
- Independent fresh review: 122 focused tests and four additional probes pass.
  Probes cover SDK-only retention through GC and late private failure, independent
  request progress while an old receive resists cancellation, one cumulative
  budget across individually timely chunks, and a deliberately slowed final copy.

Counts overlap. These are local CPython 3.11.15/in-process ASGI and package/Redis
checks, not deployed ingress/TLS, load/failover, hosted CI, external audit or
physical-device proof. Raw RED/GREEN logs, hashes, packages and the review receipt
are retained in the primary checkout under
`.superpowers/evidence/2026-10-21-python-body-deadlines/`.
