# AppGuard .NET / ASP.NET Core

Experimental, unpublished `AppGuard.Experimental` **0.0.0-experimental.1**, targeting **.NET 10 / ASP.NET Core 10**. Implements the strict [request](../../protocol/request-v0.md), [HTTP envelope](../../protocol/http-v0.md), and [policy/audit](../../protocol/policy-v0.md) v0 contracts. No service, provider, AI call, runtime downloader, token authentication, key enrollment, or platform attestation is installed.

A verified request proves possession of a trusted pre-enrolled P-256 key over specific request bytes. The host must separately authenticate the user, bind that subject to the key record, and authorize the operation.

## Build and package locally

Use SDK **10.0.402** pinned in `global.json`. .NET 10 is an [active LTS release](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core). The SDK project uses framework crypto and ASP.NET Core, with no third party runtime package dependencies. Test dependencies have exact versions and checked-in NuGet locks.

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

Supply **all** of app ID, configured external HTTPS origin, replay store, authenticated subject callback and trusted key callback. Neither callback is inferred from client fields. A subject must come from existing authenticated application state or a trusted authenticator that actually validates the Bearer token. The key callback must look up pre-enrolled keys bound to that subject; never accept a client-supplied PEM.

The following is an integration fragment: `sharedReplayStore` and `trustedKeys` are host-provided deployment services.

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
        trustedKeys.FindAsync(subject, parameters.KeyId, ct)));
app.UseAuthorization();
```

Install before request decompression, body parsing, URI rewriting or any middleware that consumes/discards required evidence. Every request reaching this middleware is protected; install it on the intended application/branch. No path bypasses are added. Avoid body-consuming authentication; the subject callback runs after the SDK has captured the body. Applications remain responsible for their routing and resource authorization policies.

The middleware takes [IHttpRequestFeature.RawTarget](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.features.ihttprequestfeature.rawtarget?view=aspnetcore-10.0) directly, preserving percent-escape case, query order and an explicit empty query. Missing feature or target, an unreadable/already-consumed seekable body, stream error, length mismatch or overflow rejects. Body capture reads at most 1 MiB + one byte. Successful downstream handlers receive a fresh stream of the captured exact bytes. Existing `HttpContext.User` is preserved, and `IAppGuardVerificationFeature` stores the verified result separately. Downstream exceptions keep their normal application behavior.

TLS is required by default: both HTTPS scheme and [ITlsConnectionFeature](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.features.itlsconnectionfeature?view=aspnetcore-10.0) must be supplied by the trusted server. A rewritten scheme alone is insufficient. `Host`, `Forwarded` and `X-Forwarded-*` never define the signed origin or establish TLS. `allowInsecureTransport: true` is an explicit operator trust boundary for controlled local tests or externally enforced TLS termination. It does not change the configured external HTTPS origin.

Headers are captured from the server's feature header collection, enumerating **each** `StringValues` entry before extraction. Singleton duplicates, extra signature metadata, unsupported encodings, Content-Length/Transfer-Encoding conflicts, noncanonical lengths and bad framing reject. Kestrel remains responsible for HTTP framing and any normalization performed before middleware. The SDK cannot recover bytes or duplicate evidence discarded by a proxy, server, earlier middleware or custom feature. Do not claim verification of a normalized/reconstructed target/body; unsupported hosts must retain the required feature evidence or fail closed. HTTP/2, HTTP/3, reverse proxy, IIS/HTTP.sys, decompression and production TLS deployments have not been integration-tested here.

HTTP failures are compact `{"code":"FIXED_REASON"}`: 400 invalid input, 413 overflow, 401 missing authentication, 403 rejected proof/key/replay, and 503 dependency failure. Expected unknown keys return 403 `KEY_REJECTED`; thrown key callbacks return 503 `KEY_RESOLVER_UNAVAILABLE`; malformed subject callback results return 503 `IDENTITY_UNAVAILABLE`. Clock is read after authentication and key lookup. No token, body, PEM or backend exception text enters a failure response.

## Replay deployment boundary

`IReplayStore.ClaimAsync(ReplayScope scope, long expires, long now, CancellationToken ct)` must atomically return true for exactly one live claim and false for a prior live claim. Throw on errors/capacity failure. A deployment-wide store must preserve this property across all instances, restarts and cancellation/timeout outcomes; do not retry an uncertain claim permissively. A backend may have committed before a timeout, so a failed request can conservatively retain its nonce.

`InMemoryReplayStore(capacity: 10000)` is **explicit opt-in, volatile and process-local**, intended for tests/development. Its lock provides single-winner claims and bounded capacity, expiry cleanup and cancellation before mutation. There is no implicit middleware store. **No distributed/Redis backend is included or tested.** Supply a real shared store for a multi-instance deployment; an adapter-shaped stub is not sufficient.

`ReplayScope.StorageKey` supplies the portable `appguard:v0:replay:<sha256(compact_json_scope)>` key. Shared Redis implementations must use a single atomic `SET key 1 NX EX (expires-now)` operation and remaining TTL in `1..150` seconds. Durability, no eviction of live claims, capacity, transport security and restart guarantees belong to the deployment.

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
