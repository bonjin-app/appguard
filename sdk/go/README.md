# AppGuard Go SDK (experimental, unpublished)

Standard-library-only implementation of `appguard-request-v0`, its strict HTTP
wire envelope, and deterministic policy/audit v0. Apache-2.0; see [LICENSE](LICENSE).
The module path is `github.com/bonjin-app/appguard/sdk/go`. No module version has
been published. For a local checkout, use a Go `replace` directive to `sdk/go`.
The module declares Go 1.26; verification currently covers Go 1.27.3 on macOS ARM64.
There are no third-party modules, so no `go.sum` is generated.

## Trust boundary

Callers explicitly supply authenticated subject, pre-enrolled trusted key record,
configured external HTTPS origin, trusted clock, and a long-lived atomic replay
store. A signature does not authenticate a token, authorize access, enroll a key,
verify platform attestation, or establish provider approval. Revocation distribution
and application resource authorization remain application responsibilities.

`VerifyRequest` validates syntax/limits, time, trusted key bindings, digest, raw64
P-256 signature, then atomic replay claim. It never sorts/re-encodes URLs,
normalizes signed fields, reserializes/decompresses bodies, or falls back to an
implicit identity/store. Core typed models are Go values; the strict wire parser
is the required boundary for untrusted Signature/Signature-Input metadata.

## net/http integration

```go
import (
    "net/http"
    appguard "github.com/bonjin-app/appguard/sdk/go"
)

// All dependencies are existing, trusted application/ingress implementations.
func Protect(next http.Handler, ingress appguard.EvidenceSource,
    auth appguard.Authenticator, keys appguard.KeyResolver,
    replay appguard.ReplayStore) (http.Handler, error) {
    return appguard.NewMiddleware(appguard.HTTPOptions{
        AppID: "your-app",
        Origin: "https://api.example.test",
        Evidence: ingress,
        Authenticator: auth,
        KeyResolver: keys,
        Replay: replay,
    }, next)
}
```

Install at the application root before body parsers and URI/header rewrites.
Existing authentication may populate request context before AppGuard; the explicit
`Authenticator` must validate the signed Bearer token or resolve that trusted
application state. It returns an authenticated subject or an empty string for
missing authentication. `KeyResolver` returns a trusted `KeyRecord` bound to that
subject/app/key, nil for an expected unknown key, or an error for an outage. Neither
callback may interpret client-provided subject/attestation fields as trusted state.
Callback inputs have separate header copies. Returned keys and all core inputs
must not be mutated concurrently by the application.

**Raw evidence is required.** Go documents `RequestURI` as the original target;
`Header` is a parsed map and cannot prove the original duplicate/whitespace/framing
evidence. `EvidenceSource` must return `RawEvidence{Method, Target, Headers}` from a
trusted ingress capture before parsing and rewriting. Include every original field
occurrence, including Host, framing, and unrelated fields. Preserve exact field
values; never reconstruct evidence from `r.Header`, forwarding headers, decoded
paths, JSON, or another client-provided assertion. Missing evidence fails closed.
The SDK cross-checks that snapshot against `RequestURI`, method, observable headers,
Host, ContentLength and TransferEncoding, and rejects declared trailers.

This package supplies middleware, **not a production raw-ingress collector**.
Its test-only collector supports one HTTP/1 request per connection and must not be
copied into production for keep-alive, pipelining, TLS, or HTTP/2. An ordinary
`net/http` deployment without an independently trustworthy capture boundary is
insufficient and will reject requests. Official API/source references:
[Request](https://pkg.go.dev/net/http#Request),
[textproto parsing](https://pkg.go.dev/net/textproto#Reader.ReadMIMEHeader).

The middleware reads `RequestURI` verbatim, including escape case, query order and
an explicit empty query. It captures at most 1 MiB + 1 byte, rejects incomplete or
oversized content, and installs an exact bounded byte reader only after verification.
Body parsing beforehand rejects when native form evidence is present. Installation
order and ingress ownership must ensure the original content stream is still
available; the SDK cannot recover a stream another handler consumed/replaced.
`BodyReadTimeout` defaults to 30 seconds and applies a native read deadline for
capture, then clears it. Configure server header/connection timeouts separately;
wrappers must support `ResponseController.SetReadDeadline` (or `Unwrap`), otherwise
verification rejects as unavailable. The request context and existing authenticated
identity remain intact. `VerificationFromContext` reads separate verification
metadata; downstream authorization is still required.

The middleware captures the entry request context and uses that same scope across
host callbacks and downstream proof attachment. Cancellation observed after
evidence, authentication, key lookup, the clock or verification prevents the next
SDK handoff. Install intentional context scopes before AppGuard; a callback
replacing the request context cannot mask cancellation of the captured scope.
Core pre/post replay cancellation checks remain unchanged. Callback errors/panics
and cancellation use fixed phase errors without private cause data. See the
source-checkout [cancellation verification](../../docs/security/go-cancellation.md).

These checks do not terminate or abandon a callback. An uncooperative callback
can remain pending until it returns. Supply dependency timeouts, cooperative
clients and concurrency limits in the host. Network notification/final-check
races, work already dispatched and response delivery remain host-owned; no
atomic promise to stop all activity at the instant a client disconnects is made.

TLS is required by default (`r.TLS != nil`); forwarding headers never enable it.
`AllowInsecureTransport: true` is only an explicit local-testing or externally
verified TLS-termination boundary. Actual local integration tests cover HTTP/1.1
with that opt-in and trusted raw capture. TLS deployment, HTTP/2, HTTP/3, Gin and
Echo integrations have not been exercised. Gin/Echo can compose `net/http` handlers,
but no framework-specific wrapper/support claim is made.

SDK error bodies contain only `{"code":"FIXED_REASON"}` with no backend/input
strings. The native HTTP server may reject malformed framing before the middleware
and controls its own response for those requests. No downstream handler runs on
SDK verification failure. Auth/key/source/store errors and panics are redacted.
Clock time is read after authentication/key resolution.

## Replay storage

`ReplayStore.Claim(ctx, ReplayScope{AppID, KeyID, Nonce}, expires, now)` must atomically
accept one new tuple until expiry, reject live duplicates with `(false, nil)`, and
return an error on outage, capacity, or cancellation. Never claim before crypto
verification and never substitute a fallback store on error. An ambiguous/cancelled
backend outcome may have committed a claim: verification fails, and the SDK never
unclaims/retries it. Use a new signed nonce for a subsequent operation.

`NewLocalReplayStore(capacity)` requires a positive explicit capacity, uses a mutex,
and evicts only expired entries. It is **volatile, single-process development/test
state**. Restarts erase protection and different processes do not share it. It is
never automatically installed. No Redis adapter or distributed-store claim is
included because no real shared backend was tested for this Go SDK. Implementations
of a shared store must follow the compact JSON scope hash/atomic relative-expiry
contract in [http-v0](../../protocol/http-v0.md), including `SET ... NX EX` in one
operation, with TTL in 1..150 seconds, and operator-managed eviction/durability.

## Policy and audit

`EvaluatePolicy(Policy{}, PolicyContext{}, now)` denies missing authentication.
`Policy{}` defaults to Basic and required signatures. Only Basic accepts an explicit
`RequireSignature: &falseValue`. `PolicyContext` accepts trusted server verdicts;
client risk signals are bounded hints and cannot upgrade trust. `PermitsProcessing`
is true only for valid `allow`/`observe` decisions; `step_up` remains blocked until a
separate trusted flow completes. Rate limiting consumes an application's verdict;
the module installs no counters or external attestation verifier.

`AuditEvent` constructs an allowlisted `AuditRecord`; call `JSON()` for compact JSON.
Only schema/event/app/time/decision/profile and optional risk count/attestation state
are recorded. Event/app IDs must be opaque configured identifiers, never secrets or
user identifiers. Tokens, subject/key/nonce/IP/body, raw hints and provider evidence
have no fields. `NewJSONAuditSink` requires an explicit context-aware callback;
`Emit` redacts callback errors/panics as `AUDIT_UNAVAILABLE`. The application owns
privacy, retention and how sink failures affect operation processing.

## Verification

From this directory in the repository checkout (tests consume the shared corpora):

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
```

See [VERIFICATION.md](VERIFICATION.md) for exact runtime, corpus counts, actual
integration coverage and unverified deployment boundaries.

### Public fixture consumer (test only)

The command below consumes public request fixtures from the native Android/Apple
probes (one conformance-shaped JSON object or an array of 1..100 objects; at most
2 MiB per file). It uses exported wire/framing/core APIs and fresh explicit replay
stores, checks wire/typed metadata equality, verifies each request, rejects replay,
and rejects body, target and token mutations. It reads only public key records;
private-key PEM input rejects and no key/token/body data is printed.

```sh
go run ./tools/verify-fixture /absolute/path/to/native-public-fixtures.json
```

For this task-local runtime use `.tools/go/bin/go` and set `GOTOOLCHAIN=local`,
`GOCACHE="$PWD/.tools/cache"`, `GOPATH="$PWD/.tools/gopath"`. The command emits
`GO_NATIVE_CLIENT_VERIFIED_REPLAY_AND_MUTATIONS_REJECTED` for each passing fixture.
A nonzero exit means verification failed. Fixture identity/context/clock values are
explicit **test inputs**, not proof of real authentication, current key enrollment,
platform attestation, authorization, hardware backing, or a production deployment.
The probe is outside the runtime library and is not a public/private key generator.
