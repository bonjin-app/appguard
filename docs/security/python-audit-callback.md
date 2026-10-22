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
`BaseException` signals are not translated by this change. Public exception
chains are redacted for SDK-handled failures; applications must separately
control traceback-local logging and their callback's own logs.

## Verification

Local source, wheel-consumer and independent review results will be recorded
after execution. Physical devices and real provider evidence remain separate.
