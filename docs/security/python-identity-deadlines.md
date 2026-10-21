# Python identity deadline hardening

2026-10-21; independent main base
`03dc7765814b72c012e50697be7b87a927ebfae7`; experimental Apache-2.0 SDK.

## Reproduced behavior and change

Python already runs synchronous identity callbacks and verification/replay off
the ASGI event loop. The reproduced issue was the existing async identity wait:
`asyncio.wait_for` can wait for cancellation cleanup, and a resolver that ignores
cancellation can keep waiting or return a successful identity past its budget.
A blocking async callback or slow trusted-identity validation could likewise
finish late and still authorize verification. Cooperative-cancellation tests did
not exercise these cases.

The existing `identity_timeout` (default 10 seconds) now uses an owned task and a
bounded wait, with one monotonic deadline through identity validation. Once the
loop can execute, expiry returns the existing fixed 503 `IDENTITY_UNAVAILABLE`
without awaiting resistant cleanup. A pending resolver receives a cancellation
request; unfinished tasks stay strongly referenced until completion and their
eventual exceptions are retrieved without logging private details. Late results
do not continue to trusted-clock sampling, core verification, replay or application
dispatch. Caller ASGI cancellation propagates promptly without an SDK response.

Public options/defaults, synchronous core/replay behavior, request protocol,
error codes and dependencies are unchanged. FastAPI and the Django/Flask ASGI
wrappers share this middleware; plain WSGI is not supported.

## Limits and references

This is not real-time preemption. Blocking event-loop work delays all scheduling;
an elapsed-deadline check rejects after control returns. Threads and resistant
coroutines can outlive requests and delay process shutdown. The guard does not
cap outstanding tasks/threads, cancel backend side effects, install a total
request/verification/replay deadline or monitor HTTP disconnects. Hosting code
must configure backend timeouts, admission/concurrency limits and shutdown.

The [Python 3.11 asyncio task documentation](https://docs.python.org/3.11/library/asyncio-task.html)
describes waiting and cancellation behavior and the need to retain pending tasks.
The recorded local tests establish this implementation's behavior; newer upstream
documentation alone does not establish additional runtime support.

Deployed ingress/load/failover, hosted CI, external audit, a supported production
release, genuine provider and physical-device validation remain separate work.
The Unity physical candidate and its historical receipts are preserved separately.
