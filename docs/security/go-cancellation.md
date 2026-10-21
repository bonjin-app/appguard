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
## Local verification and review

The reviewed SDK source is commit
`5c91d1165764b31f47976e19947cb67922def1f7`. Go 1.27.3 ran with a
private cache, local toolchain and read-only module mode.

- Baseline: 246 leaf cases in 26 top-level tests.
- Regression RED: 18 leaf cases, 10 failures and 8 passes. GREEN: all 18 passed.
- Full source: 264 leaf cases in 32 top-level tests passed both ordinary and
  race-enabled runs, with zero failures/skips. `go vet` and `go build` passed.
- A private local module ZIP contains all 19 tracked Go-module files from the
  reviewed commit. Every entry matches committed source and the downloaded
  module. A separate consumer uses its exact version without a `replace`
  directive: 19 leaf cases passed ordinary/race runs, comprising the same 18
  cancellation cases and one loaded-module origin control. `go mod verify`
  passed. This is local package integrity evidence, not public publication.
- Independent security review found no blocking findings. The reviewer freshly
  reran source ordinary/race (264 each), consumer ordinary/race (19 each), vet,
  build and module verification. Sixteen independent public-API probes passed
  ordinary/race runs; these comprise 15 desired-behavior cases and one explicit
  unsupported host-context boundary observation. Two real localhost disconnect
  cases passed 20 race-enabled repetitions (40 leaf executions).

These counts overlap and are not added across evidence tiers. The reviewer
inspected baseline/RED evidence without rerunning it, and reused the downloaded
consumer cache after fresh byte-for-byte integrity verification. Independent
checks covered final dispatch, callback precedence/privacy, body deadline reset,
original scope, nil/expired entry and preservation of an already committed nonce.

Supported contexts obey Go's `Context.Err` contract. A deliberately
contract-violating host context that panics at the final outer checkpoint can
propagate that panic; the independent synthetic probe records this nonblocking
host limitation. It does not establish a remote attacker capability or alter the
supported callback panic-handling guarantee.

Raw logs, local archive, source hashes and review receipt are preserved under
`.superpowers/evidence/2026-10-21-go-cancellation/` on local main. The reviewed
runtime is unchanged by this documentation-only verification record. Other SDK
runtime suites were not repeated for this Go-only change. Production ingress,
external audit, hosted CI and physical-device gates remain separate.
