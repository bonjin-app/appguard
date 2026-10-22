# Python synchronous audit callback boundary

2026-10-22; base `bac1dff4ae793f7c36a3ddb2ed99cd79a4ddbbf4`;
experimental Apache-2.0 SDK. No wire protocol or dependency change.

## Reproduced silent loss

`JsonAuditSink.emit()` previously discarded every callback return value. Passing
an ordinary `async def` function, async callable object, partial or synchronous
wrapper returning a coroutine created async work without running it. The API
returned normally although the audit writer had not received the event.

The callback must complete its delivery work synchronously. A returned awaitable
or `concurrent.futures.Future` now raises fixed `AuditUnavailable` with
`AUDIT_UNAVAILABLE`. This also rejects completed Futures; the sink neither waits
for them nor inspects their result/exception. Ordinary synchronous non-awaitable
return values remain ignored. Existing event validation and allowlisted compact
JSON remain unchanged; callback exceptions retain the existing redacted failure.

[Python's inspection API](https://docs.python.org/3.11/library/inspect.html#inspect.isawaitable)
recognizes native and generator-based coroutines and other awaitable objects.
The sink does not await, schedule or iterate a rejected result. It closes only
an exact native coroutine whose state is `CORO_CREATED`, to release its frame
and avoid an unawaited-coroutine warning. Returning such an unstarted coroutine
transfers ownership to the sink; do not share it with another consumer.

Tasks, Futures, custom awaitables, generator-based coroutines and already-started
native coroutines remain host-owned. Their `close`, `cancel`, `__await__`, result
and exception methods are not called. Native coroutine closure can release
captured objects and invoke their finalizers; there is no hard cleanup deadline.

## Application responsibilities

This is a synchronous callback contract, not an asynchronous audit queue. Use a
synchronous writer that reports failures before returning; applications with an
async writer must manage and await it explicitly in their own async flow.
`emit()` returning normally means only that the callback returned synchronously
without a recognized async result or exception. It does not prove durable storage
or detect callbacks that intentionally discard data, return an unrecognized work
handle, or launch background work and return `None`.

A callback may already have written/queued an event before returning a rejected
async result or raising. The SDK does not roll it back, retry it or cancel host
work. The caller owns idempotency, storage, retention, availability policy and
whether an audit failure blocks application processing. Fatal/process/cancellation
`BaseException` signals are not translated by this change. Callback exceptions
caught by `emit()` are not chained to `AuditUnavailable`. If the caller invokes
`emit()` inside its own active `except` handler, Python can attach that ambient
caller exception as `__context__`. Applications must separately control that
context, traceback-local logging and their callback's own logs.

## Verification

Runtime commit `3d10ec2f65a051fd71fc59c54103f6b39ad4297c` was tested on
Python 3.11.15 with pytest 9.1.1 and cryptography 50.0.2.

- Baseline SDK: 678 tests passed without failure or skip.
- First regression run: 16 cases, 11 expected failures and five synchronous
  controls. Adding thread-pool Futures reproduced two further failures among
  18 cases before the additional Future guard.
- Final SDK: **696 tests passed**, no failure or skip, with task-owned loopback
  Redis and persistence disabled. Owned Redis processes were stopped after use.
- Reference implementation: **209 tests passed**, no failure or skip.
- Built wheel installed offline into a fresh environment with hash-locked
  dependencies: **19 tests passed** (18 functional cases and one import-origin
  control). All 21 package entries matched committed source and installed bytes;
  the README metadata matched the package input. No reference checkout module
  was available to that consumer.

Reviewed wheel SHA-256:
`c8d2d8a6302ccd6d93c3ab3a78923d13410f9725a284cd8d0eff77393d12a38f`.

Independent review found no scoped runtime blocker. It ran **25 independently
written edge cases and 31 copied audit cases on each of source and installed
wheel**, all passing without skip. These are 112 executions of 56 cases per
target, not 112 distinct cases. Three baseline controls independently produced
two expected failures and one passing synchronous control. Review covered
running/cancelled/failed Futures and Tasks, coroutine frame release and ownership,
validation before callbacks, fixed callback-error output, and uncertain writes.
It verified all 21 package entries against committed source, wheel and installed
bytes, nine command/log records and six probe-input hashes. It did not rerun the
entire SDK/reference suites.

The review identified a documentation overclaim about exception chaining; the
ambient caller-exception limitation above was corrected and read back. That
Python behavior was also reproduced on baseline, so no caller exception semantic
change was made. The final commit changes this guide only.

Review receipt SHA-256:
`696d15827246c171d8959bbab245827f8b0e4c94179017e527996c0ec34cc8de`.
Final review readback SHA-256:
`5306935377bd601a17c5bb1b5df8f9d8ee440228b41c55042444b0c569f82b49`.

Commands, raw reports, source/artifact hashes and integration receipt are retained
in the main checkout at
`.superpowers/evidence/2026-10-22-python-audit-callback/` after local integration.
Counts overlap and must not be added as unique test cases. Physical devices and
real provider evidence remain separate from these local tests.
