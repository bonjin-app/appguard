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

## Local verification and independent review

The runtime change was built and tested at
`a4b2cd39757bed710a497896cdbb543ac53e2e89`. An independent local security
review approved `00184c39f20ca8b3c8b5ababdcb640b05b5a5a14` with no unresolved
findings. Review found a Django test-order dependency; the follow-up scopes each
existing Django ASGI test's URL settings. Both 84-test orders pass. This was a
test-only fix; packaged runtime and README bytes stayed unchanged.

The recorded CPython 3.11.15 checks include:

- 27 new deadline regressions: 22 failed before the runtime fix; all 27 pass after.
- Common server runner: reference Python 209, Python SDK 582, Node SDK 561 and
  Java SDK 211 (1,563 total), with zero skipped tests. Packaging/type smoke and
  cross-SDK Redis sequential/concurrent replay checks also passed.
- Isolated, offline-installed wheel: 27 regressions pass; all 21 packaged
  source/assets match the reviewed source and installed files.
- Independent review: full Python 582, targeted tests/probes 104 and reverse
  order 84 pass with zero failures, errors or skips. These counts overlap.

Framework requests use in-process ASGI transports, not a deployed server or
TLS endpoint. Review also confirmed a preexisting limitation: if a synchronous
resolver returns a coroutine after its thread await was canceled, that coroutine
can remain unawaited. This patch does not add thread-result disposal or force
termination; host callback/backend lifecycle controls remain necessary.

Raw logs, test-order failures and fixes, package/source hashes and the independent
review receipt are retained under
`.superpowers/evidence/2026-10-21-python-identity-deadlines/` in the primary
checkout. They are local evidence, not hosted CI, external audit or device proof.

A subsequent merged-checkout run found a test scheduling assumption: one of
582 tests correctly received pre-start expiry before its resolver could start.
The test-only follow-up uses 200ms scheduling headroom, explicit start/release
gates and a 1s watchdog, and adds a separate pre-start-expiry regression. Finite
real-clock budgets still cannot guarantee scheduling under arbitrary suspension.
Independent review approved `4eebb4f8d35c8e100c186a3f27850f731c79aded` with no
unresolved findings: full Python **583**, reverse-order **85** and installed-wheel
**28** checks pass, with zero skipped tests. The relevant 16 tests still fail the
old runtime. Original failures and both review receipts are retained. Runtime,
README and packaged source bytes are unchanged by these test-only follow-ups.

The later [synchronous resolver cleanup follow-up](python-resolver-cleanup.md)
addresses the abandoned never-started native coroutine limitation recorded
above. The original deadline-stage receipts remain historical evidence.
