# Python abandoned resolver result cleanup

2026-10-21; base `0c6e27a09acb39519c4113044af91d7eaee14d6e`;
experimental Apache-2.0 server SDK.

## Reproduced issue and change

The existing identity deadline rejects late authentication results, but canceling
the await of `asyncio.to_thread` cannot terminate an already-running callback.
If that callback later returns a newly created native coroutine, the canceled
future can discard it without awaiting or closing it. Previous security review
recorded this lifetime gap separately from authorization correctness.

The synchronous resolver now uses a per-call lock around a result handoff. The
worker publishes its result before returning; cancellation either atomically
takes that published result or leaves disposal to the worker if it returns later.
Host callback execution, type/state inspection and disposal occur outside the
lock. No additional background task, shield or global retention set is added.
`asyncio.to_thread` continues to propagate the request context to the worker.

Only an exact `types.CoroutineType` in `inspect.CORO_CREATED` state is closed,
best effort. It is never awaited during disposal. A custom object's `__class__`
can spoof an `isinstance` check, so `inspect.iscoroutine` alone is not a sufficient
type boundary. Host Tasks, Futures, custom awaitables and already-started native
coroutines are left untouched. Healthy supported awaitable results retain their
existing path. Native coroutine results transfer ownership to the SDK; the host
must not concurrently share or start those returned objects elsewhere.

Caller cancellation is re-raised unchanged. Existing fixed 503 errors, the total
identity budget, trusted-clock/core/replay/downstream fences, protocol, defaults,
dependencies and public configuration remain unchanged.

## Limits and reference

This is narrow result disposal, not forced thread or backend cancellation. A host
callback can continue or never return. Disposal may occur on the worker or loop
thread and does not depend on the event loop remaining open after abandonment.
Closing a never-started native coroutine does not execute its body, but clearing
its frame can release captured objects and invoke their finalizers. Cleanup can
therefore block and has no hard time bound. It does not change host ownership of
other returned objects or provide a resource cap, process-shutdown guarantee,
HTTP-disconnect monitor or total request/replay deadline.

This handles cancellation-abandoned results; it does not claim that every
chronologically late value is disposed before execution when cancellation has
not yet been delivered. The existing elapsed-budget checks still reject late
authentication before verification. Blocking loop work delays scheduling.

The official Python 3.11 documentation describes
[thread execution and cancellation](https://docs.python.org/3.11/library/asyncio-task.html),
[coroutine states](https://docs.python.org/3.11/library/inspect.html#inspect.getcoroutinestate)
and [native coroutine close](https://docs.python.org/3.11/reference/datamodel.html#coroutine.close).
Local verification uses CPython 3.11.15; newer documentation is not additional
runtime coverage. Deployed load/failover, hosted CI, external audit, provider and
physical-device verification remain separate gates.

## Local verification and independent review

Independent security review approved
`e91c0cf6fe12ee446b9469441153372a6cd79952` with no unresolved findings.
Design review reproduced custom `__class__` spoofing; the exact-type boundary
was added and the spoof regression changed from failure to pass. The initial
16-test suite reproduced nine abandoned-result failures with seven existing
contract controls passing. The final new suite contains 17 cases.

Recorded checks, all with zero skipped tests:

- Baseline Python SDK: 583 pass; final Python SDK: 600 pass.
- Focused cleanup/deadline/ASGI tests: 102 pass.
- Common server runner: reference Python 209, Python SDK 600, Node SDK 561 and
  Java SDK 211 (1,581 total); packaging/types and cross-SDK Redis sequential and
  concurrent replay checks also passed.
- Isolated offline-installed wheel: 45 regressions pass; 21 packaged source/assets
  match reviewed source and installed files, including README metadata readback.
- Independent fresh review: 102 focused tests and five additional probes pass.
  The probes cover both finalizer/lock handoff orderings, late sync exception
  privacy under timeout/caller cancellation, and untouched hostile object hooks.

These counts overlap. Framework requests run in-process through ASGI, not a
production ingress or TLS endpoint. Loop-close evidence lets a bounded test
worker return after its request loop closes; it is not proof that all workers
finish during process shutdown. Full logs, RED/GREEN results, package/source
hashes and the independent review receipt are retained in the primary checkout:
`.superpowers/evidence/2026-10-21-python-resolver-cleanup/`.
