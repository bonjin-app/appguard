# .NET canceled-request handoff checks

2026-10-21; base `e70ec3f9ff3735175b811e9bac94e860558575a3`;
experimental Apache-2.0 server SDK.

## Reproduced late-callback behavior

The ASP.NET Core middleware previously checked cancellation at request entry,
and the core verifier checked it before replay. A body reader returning EOF or
an authentication/key callback returning normally after cancellation could still
advance to another host dependency. More seriously, a replay store that ignored
its supplied token and returned late could produce `VERIFIED` and dispatch an
already-aborted request. Direct verifier calls could also accept the late result.

The regressions synchronize on callback entry, cancel the supplied request token,
then release a deliberately uncooperative callback. Actual localhost Kestrel
HTTP/1 tests reset the owned TCP connection while authentication/replay is
pending, wait for the server token to report cancellation, then release the
callback. They reproduced extra key lookup and downstream execution respectively.
These are cancellation/availability boundary failures, not a signature or
authentication bypass: the requests carry valid signed proofs and trusted keys.

## Changed behavior

The middleware captures `HttpContext.RequestAborted` once at invocation entry,
passes that same token to body reads and host callbacks, and rechecks it after
body capture, authentication, key lookup and core verification. A host callback
replacing the context property cannot erase cancellation of that captured scope.
Set up any intentional request-token scope before entering AppGuard; changing the
property later does not replace the token used by this invocation.

At these SDK-owned checkpoints, observed cancellation prevents the next phase,
verification-feature publication and downstream dispatch. The SDK disposes its
captured body on rejection and retains the original request body. The error path
does not write a response body when the captured token is canceled. No delivery
of an HTTP error to an aborted connection is promised. Existing fixed errors for
callbacks that throw remain unchanged and omit dependency exception details.

The core verifier also checks its supplied token after a replay callback returns,
before accepting either `true` or `false`. If cancellation is then observed it
throws `OperationCanceledException` with that token, matching its existing entry
and pre-claim cancellation checks. A store that throws remains translated to the
existing fixed `REPLAY_STORE_UNAVAILABLE` error; exceptions are not exposed or
inspected for private cancellation causes.

Cancellation does not undo an already-committed nonce. The tests conservatively
retain a claim whose result arrived after cancellation. The SDK does not retry,
delete a claim or provide business idempotency. For an uncertain outcome, apply
application recovery/idempotency and prepare a fresh signed request as needed.

## Operator responsibilities and evidence limits

This adds checkpoints, not callback abandonment, forced termination, new
timeouts, a total request deadline or a concurrency/resource cap. An uncooperative
callback can keep the middleware pending until it returns. Supply dependency
timeouts and cancellation-aware clients and bound host concurrency. Work already
dispatched to application code remains host-owned. Cancellation can race with
the final check; these checks are not an atomic promise to prevent every action
after the instant a peer disconnects. Server/network notification may be delayed.

Microsoft documents [cooperative cancellation](https://learn.microsoft.com/en-us/dotnet/standard/threading/cancellation-in-managed-threads)
and the [RequestAborted contract](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.httpcontext.requestaborted?view=aspnetcore-10.0).
The SDK's original-token scope and handoff checks are AppGuard implementation
choices within that model.

The local Kestrel fixture still captures only one HTTP/1 request at the connection
boundary. It is not a production original-header collector and proves no TLS,
HTTP/2/3, ingress/proxy, load, distributed-store failover, supported release,
hosted CI, external audit, provider or physical-device behavior. Public APIs,
protocol/corpora, package versions, dependencies and signature/key rules remain
unchanged. Other server SDK runtimes are outside this correction.
