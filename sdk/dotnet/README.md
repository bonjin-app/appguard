# AppGuard .NET / ASP.NET Core

Experimental, unpublished `AppGuard.Experimental` **0.0.0-experimental.1**, targeting **.NET 10 / ASP.NET Core 10**. Implements the strict [request](../../protocol/request-v0.md), [HTTP envelope](../../protocol/http-v0.md), and [policy/audit](../../protocol/policy-v0.md) v0 contracts. No service, provider, AI call, runtime downloader, token authentication, key enrollment, or platform attestation is installed.

A verified request proves possession of a trusted pre-enrolled P-256 key over specific request bytes. The host must separately authenticate the user, bind that subject to the key record, and authorize the operation.

## Build and package locally

Use SDK **10.0.402** pinned in `global.json`. .NET 10 is an [active LTS release](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core). The SDK project uses framework crypto and ASP.NET Core, plus pinned StackExchange.Redis for the opt-in shared replay adapter. Runtime and test dependencies use checked-in NuGet locks.

```sh
# Uses an already installed SDK; never installs a runtime or trusts a certificate.
./scripts/verify.sh
# Or use an explicit SDK executable:
APPGUARD_DOTNET="$PWD/.tools/dotnet/dotnet" ./scripts/verify.sh
```

The script disables automatic development certificate generation and telemetry, and uses task-local CLI/package caches. It runs locked restore, the complete Release test suite, build and pack. The result is a local `artifacts/AppGuard.Experimental.0.0.0-experimental.1.nupkg`; nothing is published. See [VERIFICATION.md](VERIFICATION.md) for actual evidence and limits. License: Apache-2.0, copied from the repository root.

## Core API

`RequestData(method, target, headers, body)` copies exact body bytes and ordered `HeaderPair` values; byte getters return defensive copies. `SignatureParameters`, `KeyRecord`, `VerificationContext`, replay scope and policy models are immutable. Scalar types are native .NET types: strings, `long` integer seconds and booleans; there is no permissive object/JSON conversion. Timestamp domains are checked at core verification; negative timestamps may parse in the strict wire grammar and then fail `INVALID_TIME`.

```csharp
var envelope = Wire.Parse(originalHeaderPairs);
Wire.ValidateFraming(originalHeaderPairs, originalBodyBytes.Length);
var request = new RequestData(method, originalTarget, originalHeaderPairs, originalBodyBytes);
var result = await Verifier.VerifyAsync(request, envelope.Parameters, envelope.Signature,
    new VerificationContext("https://api.example.test", "my-app",
        authenticatedSubject, trustedKeyRecord, trustedNow, sharedReplayStore), cancellationToken);
// result.Code == "VERIFIED"; continue with the application's resource authorization.
```

`KeyRecord` binds app ID, key ID, authenticated subject, SPKI `PUBLIC KEY` PEM, algorithm and revocation state. Its optional exclusive `notAfter` supports a trusted enrollment expiry. PEM must contain exactly one P-256 SPKI public key, at most 4096 UTF-8 bytes; private keys, other curves, trailing DER/PEM material and malformed keys reject. Signatures are exactly 64-byte unsigned big-endian `r || s`; DER signatures reject.

Verification order is syntax/limits → time → key binding/expiry/revocation → raw-body digest → signature → atomic nonce claim. Failed crypto, key lookup or time validation never claims a nonce. All protocol failures use a fixed `AppGuardException.Code` without raw input or inner exceptions.

Limits: 1 MiB body; 8192-character ASCII origin-form target; 64 header pairs / 16 KiB ASCII header-name and value bytes including unrelated and signature fields; 512-character configured HTTPS DNS origin; 1..128-character restricted IDs; canonical 16-byte base64url nonce; timestamps `0..999999999999999`; signature lifetime ≤120 seconds, future skew ≤30 seconds and rejection at expiry.

## ASP.NET Core middleware

Supply **all** of app ID, configured external HTTPS origin, replay store, authenticated subject callback, trusted key callback and trusted original header capture through `IAppGuardRawHeadersFeature`. Neither callback is inferred from client fields. A subject must come from existing authenticated application state or a trusted authenticator that actually validates the Bearer token. The key callback must look up pre-enrolled keys bound to that subject; never accept a client-supplied PEM.

The following is an integration fragment: `sharedReplayStore` and `trustedKeys` are host-provided deployment services. The host/ingress must already have installed a same-request `IAppGuardRawHeadersFeature` from pre-parser evidence. The middleware rejects every request lacking it; this snippet alone does not configure capture.

```csharp
using AppGuard;
using AppGuard.AspNetCore;

app.UseAuthentication(); // Must preserve the original target, headers and body.
app.UseAppGuard(new AppGuardOptions(
    appId: "my-app",
    origin: "https://api.example.test",
    replay: sharedReplayStore,
    authenticate: (context, ct) => ValueTask.FromResult(
        context.User.Identity?.IsAuthenticated == true
            ? context.User.FindFirst("sub")?.Value : null),
    resolveKey: (context, subject, parameters, ct) =>
        trustedKeys.FindAsync(subject, parameters.KeyId, ct),
    bodyReadTimeout: TimeSpan.FromSeconds(30)));
app.UseAuthorization();
```

Install before request decompression, body parsing, URI rewriting or any middleware that consumes/discards required evidence. Every request reaching this middleware is protected; install it on the intended application/branch. No path bypasses are added. Avoid body-consuming authentication; the subject callback runs after the SDK has captured the body. Applications remain responsible for their routing and resource authorization policies.

The middleware takes [IHttpRequestFeature.RawTarget](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.features.ihttprequestfeature.rawtarget?view=aspnetcore-10.0) directly, preserving percent-escape case, query order and an explicit empty query. Missing feature or target, an unreadable/already-consumed seekable body, stream error, length mismatch or overflow rejects. Body capture reads at most 1 MiB + one byte. Successful downstream handlers receive a fresh stream of the captured exact bytes. Existing `HttpContext.User` is preserved, and `IAppGuardVerificationFeature` stores the verified result separately. Downstream exceptions keep their normal application behavior.

TLS is required by default: both HTTPS scheme and [ITlsConnectionFeature](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.features.itlsconnectionfeature?view=aspnetcore-10.0) must be supplied by the trusted server. A rewritten scheme alone is insufficient. `Host`, `Forwarded` and `X-Forwarded-*` never define the signed origin or establish TLS. `allowInsecureTransport: true` is an explicit operator trust boundary for controlled local tests or externally enforced TLS termination. It does not change the configured external HTTPS origin.

Headers must come from `IAppGuardRawHeadersFeature.Headers`, an original ordered duplicate-preserving list of `HeaderPair` values captured by a trusted host/ingress adapter **before normalization** and bound to this same request. Ordinary `IHttpRequestFeature.Headers` is insufficient: Kestrel can trim whitespace, canonicalize `Content-Length: 02` to `2`, or discard Content-Length when Transfer-Encoding is present. Never populate the feature from that parsed collection or client-supplied metadata. The SDK snapshots and bounds the supplied original pairs before authentication, parsing or a nonce claim. Missing evidence fails400 `INVALID_REQUEST`.

Singleton duplicates, extra signature metadata, unsupported encodings, Content-Length/Transfer-Encoding conflicts, noncanonical lengths and bad framing reject. Kestrel still owns HTTP framing. The SDK cannot recover bytes or duplicate evidence discarded by a proxy, server or earlier middleware. No production ingress collector is included. The test fixture captures one HTTP/1 request at the Kestrel connection boundary; it is not a keep-alive/TLS/HTTP2 production collector. HTTP/2, HTTP/3, reverse proxy, IIS/HTTP.sys, decompression and production TLS deployments remain untested. Hosts unable to supply this evidence must use a compatible trusted ingress or retain the fail-closed result.

HTTP failures are compact `{"code":"FIXED_REASON"}`: 400 invalid input, 413 overflow, 401 missing authentication, 403 rejected proof/key/replay, and 503 dependency failure. Expected unknown keys return 403 `KEY_REJECTED`; thrown key callbacks return 503 `KEY_RESOLVER_UNAVAILABLE`; malformed subject callback results return 503 `IDENTITY_UNAVAILABLE`. Clock is read after authentication and key lookup. No token, body, PEM or backend exception text enters a failure response.

The middleware captures `RequestAborted` at invocation entry and observes that
token during body capture, authentication, key lookup and verification. Cancellation
observed after those phases prevents further SDK handoff and verification-feature
publication; no response body is written on its canceled error path. Configure
intentional token scopes before AppGuard. Replacing the context property inside
a callback cannot erase cancellation of the captured token.

Body capture has an absolute, monotonic **30-second** deadline by default,
including the EOF check and final request snapshot. The optional configuration
uses a separate `AppGuardOptions` overload with required `TimeSpan bodyReadTimeout`
before the optional clock/transport arguments; any positive value up to five
minutes is accepted. The original constructor remains available for existing
compiled consumers. Progress does not reset the deadline. Expiry rejects with
400 `INVALID_REQUEST` before authentication, key lookup, the trusted clock, replay
or downstream handling; body overflow still rejects with 413.

Each asynchronous read is independently awaited for the remaining capture time
and the captured request token. Reads receive a separate body-scoped token;
expiry or request cancellation requests that token's cancellation asynchronously.
The middleware does not wait for an uncooperative stream or its cancellation
callback, and keeps the cancellation source alive until those callbacks finish.
Late stream/cancellation faults are consumed without publishing private details.
An outstanding read retains its own unpooled input array, which the SDK never
reuses or clears. The caller-owned stream stays undisposed. Authentication, key,
replay and downstream work retain the original request token and do not inherit
the body deadline.

This bounds awaiting supported asynchronous host I/O; it cannot interrupt a
`ReadAsync` implementation that blocks synchronously before returning a task,
force a host operation/callback to stop, or provide a hard real-time guarantee
under scheduler starvation. Once such a synchronous call returns, the monotonic
checkpoint still rejects a late body before authentication. Configure host read
timeouts, concurrency/resource limits and cancellation-aware I/O independently.

After final framing validation and request/body materialization, the middleware
checks that captured token again before invoking authentication. Cancellation in
this handoff window cannot start identity/key lookup, the trusted clock, replay,
verification-feature publication or downstream handling. Its canceled error path
sets status 400 without writing a response body and leaves the caller-owned input
stream undisposed. This is an observed cancellation checkpoint, not an atomic
check-and-dispatch guarantee; see the
[body handoff verification](../../docs/security/dotnet-body-handoff.md).

The direct verifier checks its supplied token after replay returns, before
accepting `true` or `false`; observed cancellation throws `OperationCanceledException`
with that token. Store exceptions keep their fixed `REPLAY_STORE_UNAVAILABLE`
mapping. No authentication, key or replay callback is abandoned or forcibly stopped: ignoring cancellation can
keep the SDK pending until the callback returns. Configure dependency timeouts,
cancellation-aware clients and concurrency limits in the host. Work already
dispatched, token-notification/final-check races and HTTP response delivery remain
host-owned. Source-checkout evidence: [cancellation verification](../../docs/security/dotnet-cancellation.md).

## Replay deployment boundary

`IReplayStore.ClaimAsync(ReplayScope scope, long expires, long now, CancellationToken ct)` must atomically return true for exactly one live claim and false for a prior live claim. Throw on errors/capacity failure. A deployment-wide store must preserve this property across all instances, restarts and cancellation/timeout outcomes; do not retry an uncertain claim permissively. A backend may have committed before a timeout, so a failed request can conservatively retain its nonce.

`InMemoryReplayStore(capacity: 10000)` is **explicit opt-in, volatile and process-local**, intended for tests/development. Its lock provides single-winner claims and bounded capacity, expiry cleanup and cancellation before mutation. There is no implicit middleware store. For multi-instance deployments, explicitly supply `RedisReplayStore` with a configured StackExchange.Redis database, or another real shared store.

`RedisReplayStore(IDatabaseAsync database)` uses the pinned StackExchange.Redis **3.4.5** client. The host creates, configures, reuses and disposes the connection; the adapter never connects, reads credentials, changes Redis configuration or falls back to process-local state. Follow the client's [connection reuse guidance](https://seredis.dev/Basics.html) and [configuration reference](https://seredis.dev/Configuration.html) for TLS, credentials, connection/command timeouts and deployment topology.

```csharp
using AppGuard;
using StackExchange.Redis;

// Host-owned, trusted configuration; create once for the application lifecycle.
using var connection = await ConnectionMultiplexer.ConnectAsync(hostRedisOptions);
IReplayStore sharedReplayStore = new RedisReplayStore(connection.GetDatabase());
// Supply sharedReplayStore to AppGuardOptions / VerificationContext.
```

`ReplayScope.StorageKey` supplies the portable `appguard:v0:replay:<sha256(compact_json_scope)>` key shared with the Python, Node, Java and Go SDKs. The adapter validates the scope and Unix-second timestamps and performs exactly one atomic `SET key 1 NX EX (expires-now)` with TTL in `1..150` seconds. Only the Redis simple-string `OK` succeeds; a Redis null response means replay. Unexpected responses and backend errors produce fixed `REPLAY_STORE_UNAVAILABLE` without backend exception details.

Pre-canceled calls issue no command. Cancellation while awaiting Redis prevents a successful return, but **cannot retract a command already sent**: the claim may remain until expiry. The direct adapter throws cancellation with the supplied token; the existing verifier maps store failures to `REPLAY_STORE_UNAVAILABLE`, and middleware retains its canceled-request response behavior. A late backend fault after cancellation is consumed without logging or exposing its private details through the host's unobserved-task exception event. Client timeouts bound backend work even after request cancellation. Never retry an uncertain claim permissively.

A shared atomic claim does not by itself provide persistence or replication guarantees. Operators must secure transport/access, provision capacity, prevent eviction of live claims, and configure/test Redis persistence, failover, restart and outage behavior for their deployment. No production Redis configuration or restart/failover proof is included.

To enable the three live tests, set `APPGUARD_TEST_REDIS_URL=redis://127.0.0.1:PORT/DB` to an **owned disposable credential-free loopback Redis**, database `0..15`, before running `scripts/verify.sh`. Without it the live tests explicitly skip. They use independent connections and random scopes; cleanup deletes only their own hashed keys. Unit contract tests always run. Tests cover a 48-way single-winner race, shared visibility, app/key/nonce isolation, bounded TTL, expiry and redacted closed-client failure through the verifier and middleware. These are local server tests, separate from production, CI, device and provider evidence.

The test-only independent-process probe accepts `URL APP KEY NONCE NOW EXPIRES`:

```sh
# Build the solution first; apply the same .NET environment guards as scripts/verify.sh.
dotnet tools/RedisProbe/bin/Release/net10.0/RedisProbe.dll \
  "$APPGUARD_TEST_REDIS_URL" test-app test-key AAECAwQFBgcICQoLDA0ODw 100 130
```

It prints exactly `CLAIMED` or `REPLAY`; failures print fixed `REPLAY_STORE_UNAVAILABLE` to stderr and exit 2. It never deletes keys. The probe is excluded from the NuGet package.

## Policy and audit

```csharp
var policy = new Policy("balanced");
var context = new PolicyContext(
    authentication: "authenticated", // Trusted server result; default is missing.
    verification: "verified",       // Only after actual request verification.
    attestation: "missing",         // Provider verification is a separate integration.
    riskSignals: new[] { "debugger" }); // Bounded untrusted hints.
var decision = PolicyEngine.Evaluate(policy, context, trustedNow);
if (!decision.PermitsProcessing) { /* reject or complete a trusted step-up */ }
await auditSink.EmitAsync(decision, opaqueEventId, "my-app", trustedNow, context);
```

Profiles are basic/balanced/strict. Signatures are required by default; only explicit `new Policy("basic", requireSignature: false)` permits server-only mode with existing authentication. Missing authentication always denies. `observe` permits processing with an observation; `step_up` never permits processing. A supplied `rateLimited` boolean consumes an existing limiter's result; this package does not install a limiter. Risk codes (≤32 unique bounded codes) cannot upgrade trust or override failed authentication/proof/attestation.

`AuditEvent` is a closed allowlist: schema, opaque event ID, configured app ID, timestamp, decision action/code/profile, and optional risk count/attestation state. No user identity, risk values, tokens, nonce, key, body, fingerprint, IP or provider payload is copied. IDs must themselves be opaque and contain no secrets or user IDs. `JsonAuditSink` accepts an explicit `Func<string, CancellationToken, ValueTask>` callback, emits compact JSON and maps callback failures to `AuditUnavailableException` (`AUDIT_UNAVAILABLE`, no inner exception). The host chooses sink availability behavior, storage, privacy and retention.

## Interoperability probe

`tools/InteropProbe` is a test-only console fixture runner for independently generated, explicit trusted request fixtures in the existing request corpus JSON shape. Pass one fixture object or an array; it checks public wire parsing against the fixture, verifies the signature, rejects replay and body/target/token substitutions, and proves that rejected mutations do not consume the nonce. It uses explicit process-local test stores and accepts only valid baseline client fixtures. Never expose this trusted-context runner to clients.

```sh
DOTNET_GENERATE_ASPNET_CERTIFICATE=false dotnet run --project tools/InteropProbe -- fixture.json
```
