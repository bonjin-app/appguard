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

## Local verification and independent review

Runtime/test commit `bcfdcb955fe5dcda50c7416c03131402ea3a6cab` received an
independent local security/correctness review with no blocking or unresolved
source findings. The following record commit changes only this guide.

- Locked offline baseline: 199 .NET tests passed. The 17 new regression/control
  cases initially produced 13 expected failures and four passes, including two
  actual Kestrel disconnect cases. After the fix all 17 passed.
- Clean committed-source Release verification: all 216 tests passed with zero
  failures/skips; solution build reported zero warnings/errors and NuGet pack
  completed. No NuGet vulnerability-feed audit was run by the offline restore.
- A fresh local NuGet cache/consumer using only PackageReference passed all 216
  cases plus one loaded-DLL hash/commit-provenance control (217 total). There were
  no project references. Package DLL, installed DLL and loaded copy matched.
- The reviewer freshly repeated source216 and final consumer217 and passed 13
  independent probes: 11 behavior cases plus two provenance/compiled-code
  controls. The independent source rebuild had zero warnings/errors; all 251
  method bodies, 254 method signatures and 151 fields matched the packaged code.
  One optional reviewer PathMap CLI setup failed before compilation; the corrected
  rebuild passed, and both attempts remain in the receipt.

The first package was built before the source commit, so its informational and
SourceLink metadata referenced the base commit. That artifact is superseded.
The final package was rebuilt at the clean runtime commit and installed into a
fresh cache; DLL informational version, NuGet repository commit and SourceLink
all reference `bcfdcb955fe5dcda50c7416c03131402ea3a6cab`. Earlier evidence is
retained with its superseded status. Local metadata binding does not establish
publication or public availability of the commit.

Counts overlap and must not be added as unique tests. Runtime source bytes remain
identical through the subsequent documentation-only integration record; merged
main is verified separately. Other server SDKs and shared protocol/corpora were
unchanged and were not rerun in this .NET-only correction.

Commands, TRX reports, package/source hashes, old/new provenance, review receipt
and integration readback are retained in the primary main checkout under
`.superpowers/evidence/2026-10-21-dotnet-cancellation/`.
