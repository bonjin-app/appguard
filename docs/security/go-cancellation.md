# Go HTTP canceled-request handoffs

2026-10-21; base `169066f09ad01a4cb2598aa27f807d4034b6231d`;
experimental Apache-2.0 server SDK.

## Reproduced extra work

The Go core already rejects a canceled context before and after a replay claim.
That safeguard remains unchanged. The HTTP middleware, however, could accept a
late authentication result and call the key registry after cancellation; a late
key result could reach the clock and further validation. A canceled evidence
callback could also trigger body capture before the existing body-end check.

Public-API regressions synchronize on callback entry, cancel the request context,
then release a deliberately uncooperative callback. Actual localhost net/http
tests reset an owned TCP connection, wait for the server request context to report
cancellation, then release authentication/key lookup. They reproduced extra key
or clock calls. With an unchanged host context, the existing core still prevented
nonce claims/downstream execution: this finding does not establish a remote
signature/authentication bypass.

Separate controlled trusted-host fixtures replace the request's context inside a
callback. They show why re-reading the mutable request after a callback can lose
the original cancellation scope. Such host mutation is not a demonstrated remote
attacker capability. The tests avoid concurrent request mutation.

## Changed behavior

The HTTP handler captures the original request context at entry and passes it
through evidence, body-end checks, authentication, key lookup and core verification.
The same scope supplies existing host values and the added proof to downstream.
Set up intentional derived/linked scopes before AppGuard; replacing the request
context inside a callback does not replace this invocation's captured scope.

At SDK-owned checkpoints, observed cancellation prevents the next handoff:

| Checkpoint | Fixed HTTP failure |
| --- | --- |
| Entry, returned evidence, body capture | 400 `INVALID_REQUEST` |
| Returned authentication | 503 `IDENTITY_UNAVAILABLE` |
| Returned key lookup | 503 `KEY_RESOLVER_UNAVAILABLE` |
| Returned clock, final downstream handoff | 503 `VERIFICATION_UNAVAILABLE` |
| Core pre/post replay claim (existing behavior) | 503 `REPLAY_STORE_UNAVAILABLE` |

Callback errors/panics retain their existing fixed phase failures. Neither private
callback text nor `context.Cause` enters responses. The middleware retains its
existing fixed error response path; successful delivery after a disconnect is
not promised. The verification context is added only after success and the final
cancellation check. Healthy signed bodies and host context values remain intact.

## Limits

These are handoff checks, not forced callback termination, abandoned waits, new
goroutines, timeouts, a total request deadline or a concurrency cap. An
uncooperative synchronous callback keeps its handler pending until it returns.
Configure cancellation-aware clients, dependency timeouts and host concurrency.
The existing body read deadline is unchanged. Application work already handed
off remains host-owned; cancellation can race after the last checkpoint and
network/server notification can be delayed.

No nonce rollback, deletion or retry is added. A failed/canceled claim may already
have committed; application idempotency and recovery remain necessary.
The [Go context contract](https://pkg.go.dev/context#Context) and
[server request context contract](https://pkg.go.dev/net/http#Request.Context)
describe the cooperative signal. AppGuard's captured scope/checkpoints implement
its own handoff policy within that model.

The test collector supports only one local HTTP/1 request before parsing. It is
not a production original-header collector and proves no ingress/proxy, TLS,
HTTP/2/3, Gin/Echo, load, distributed-store failover, hosted CI, external audit,
release support, provider or physical-device behavior. The core, protocol/corpora,
public API, dependencies and other server SDKs are unchanged.
