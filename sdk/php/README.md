# AppGuard PHP server SDK (experimental, local and unpublished)

Requires 64-bit PHP 8.2+ and the OpenSSL, hash and JSON extensions. There are no Composer runtime dependencies and no mandatory AppGuard service. This implements the repository's restricted `appguard-request-v0`, `http-v0`, and `policy-v0` contracts. A verified installation signature does not authenticate a user, authorize a resource, or prove platform attestation.

Install this local package through a Composer path repository or copy the versioned package through your own release process. Load `vendor/autoload.php`. The package is not published to Packagist.

## Explicit trust boundaries

`RequestInput` retains the exact method, original ASCII target, ordered duplicate-preserving header pairs and raw body bytes. `SignatureParameters` retains the six exact protocol parameters. `KeyRecord` must come from a trusted pre-enrolled registry and bind configured app, key ID and authenticated subject; revocation and optional key expiry are checked. `Verifier::verify` requires a caller-provided `ReplayStore` and trusted integer clock value. The application validates Bearer credentials first and still enforces resource authorization after verification.

`HttpAdapter` is a native PHP callback adapter. It requires all of: configured external HTTPS origin/app ID, trusted authentication callback, key resolver, replay store and clock. Its evidence callback must return `HttpEvidence` captured before normalization/body processing. `handle($nativeRequest, $capture, $next)` invokes `$next($nativeRequest, $verifiedRequest)` only after verification; the native object and existing identity remain intact. `VerifiedRequest` carries captured bytes plus verification metadata separately. Failures return `HttpFailure` with a fixed status and compact `{"code":"FIXED_REASON"}` body. The application maps that to its response framework.

`VerificationError` derives its HTTP status from the normalized fixed reason:
400 for `INVALID_REQUEST`, 401 for missing authentication, 503 for dependency
failures, and 403 for the remaining verification failures. Its optional status
argument permits only 413 with normalized `INVALID_REQUEST`, for content overflow.
Other overrides are ignored, including success, redirect and out-of-range values.
The adapter normalizes caught SDK errors again before publishing a failure,
including subclass fields and missing initialization. An uninitialized error
falls back to 400 `INVALID_REQUEST`; subclass reason text is never copied raw.
The constructor signature is unchanged; callers that previously used arbitrary
overrides must implement unrelated response policy in their application. See the
[error-status verification](../../docs/security/php-error-status.md).

```php
use AppGuard\{HttpAdapter, HttpEvidence};

$guard = new HttpAdapter(
    origin: 'https://api.example.test',
    app_id: 'my-app',
    authenticate: fn ($native, $captured) => $existingAuth->authenticatedSubject($native),
    resolveKey: fn ($subject, $keyId, $appId) => $registry->find($appId, $keyId, $subject),
    replay: $atomicReplayStore,
    clock: fn () => time(),
);
$result = $guard->handle(
    $nativeRequest,
    fn ($native) => $trustedServerCapture->evidence($native),
    fn ($native, $verified) => $application($native, $verified->request->body),
);
```

Authentication callback: return an authenticated subject string, `null` for missing identity, or throw on failure. Key resolver: return `KeyRecord`, `null` for unknown key, or throw on failure. Malformed non-null callback results reject as dependency failures. Clock is read after authentication/key resolution, at verification. Replay callbacks must return exactly `true` for a new atomic claim, exactly `false` for conflict, and throw for failures. No permissive fallback exists.

### Raw evidence cannot be reconstructed

`$_SERVER`, `getallheaders()`, decoded routes and common PSR/server request normalization cannot prove original duplicate header evidence. Do not manufacture `HttpEvidence` from those values or from an untrusted `X-Original-URL`/forwarding header. A deployment must capture the original target and duplicate-preserving header pairs in its trusted server ingress, or this adapter cannot be installed safely. Missing evidence rejects. Explicit empty query, percent-escape case, query ordering and raw body bytes matter. `HttpEvidence::fromStream` offers bounded exact stream capture when this trusted evidence is available. Incomplete reads, nonblocking streams and body overflow reject. The server remains responsible for malformed HTTP framing that it discarded before capture.

HTTPS is required by default from a trusted transport indication; forwarded headers are ignored. `allowInsecure: true` is only for local tests or an operator-established TLS termination boundary. This is a tested native PHP adapter API; it does not claim tested Laravel, Symfony, PSR-7/15, FPM or Apache integration.

## Replay scope

`InMemoryReplayStore` is bounded (default 10,000 live entries), volatile and process-local. It accepts each `[app_id, key_id, nonce]` once until expiry, removes expired entries and fails closed at capacity without evicting live claims. Its synchronous claim has no callback or Fiber suspension point. It is for a single PHP interpreter in development/tests, not PHP-FPM workers, processes, hosts, restarts, or distributed deployments. A new store for every HTTP request gives no replay protection. The SDK never silently installs a store.

`CallbackReplayStore` can wrap an existing atomic callback; it validates the scope/deadline, requires an exact boolean result and redacts failures. Atomicity of the injected backend remains the caller's responsibility.

Implement `ReplayStore::claim(array $scope, mixed $expires, mixed $now): mixed` using an atomic backend for production; remaining TTL must be 1..150 seconds. Follow `protocol/http-v0.md` for the shared compact-JSON SHA-256 replay key and one `SET ... NX EX` command if using Redis. The optional `RedisReplayStore` below implements that contract. Backend persistence, eviction policy and failover remain deployment responsibilities.

## Policy and audit

`PolicyEngine::evaluate(new Policy(profile: 'balanced'), $trustedContext, $now)` returns `allow`, `observe`, `step_up` or `deny`. Only allow/observe permit processing. Context defaults to missing authentication and denies. Only explicit Basic `require_signature: false` permits server-only mode with existing authentication. Client risk hints cannot upgrade trust. These functions do not install a rate limiter or verify attestation.

Readonly policy/context/decision objects copy bounded signals. `Audit::event` constructs a fresh allowlisted event with opaque event/app IDs, time, decision/profile and optional risk count/attestation state. It never merges arbitrary request payloads or includes subjects, tokens, nonce/key, body, raw signals, IP or provider evidence. IDs must themselves be opaque and free of personal data. `JsonAuditSink` calls an explicit callback and redacts failures to `AUDIT_UNAVAILABLE`; the application owns availability/retention/privacy choices.

## Verification

Run `php -n tests/run-all.php` (with Python 3 for the loopback test harness) from this package in the repository. The suite loads all 40 request, 43 wire and 42 policy vectors and adds independent OpenSSL-generated signatures, strict DER/scalar/curve checks, resource/type/identity/replay errors, policy/audit redaction, exact-byte stream capture and native adapter integration. See `VERIFICATION.md` for the executed runtime, commands and evidence limits.


## Optional shared Redis replay store

The package keeps Redis optional. Install maintained [phpredis](https://github.com/phpredis/phpredis) (`ext-redis`, suggested by Composer) in the application runtime. Supply an already configured, connected `Redis` object:

```php
use AppGuard\{RedisReplayStore, ExtRedisCommandClient};

// $redis is host-owned: configure TLS/auth/DB and finite connect/read timeouts first.
$redis->setOption(\Redis::OPT_REPLY_LITERAL, true); // Required: preserve OK versus QUEUED.
$replay = new RedisReplayStore(new ExtRedisCommandClient($redis));
// Pass $replay to Verifier or HttpAdapter as the required replay store.
```

The SDK never connects, discovers credentials, selects a DB, changes Redis options, or installs a fallback. `RedisReplayStore::key($scope)` produces the shared compact-JSON SHA-256 key. Each valid claim issues exactly `SET key 1 NX EX ttl`, with TTL 1..150 seconds. The phpredis bridge uses `rawCommand` so client serializers, compression and prefixes cannot rewrite the protocol key/value; it rejects transaction/pipeline mode on every call. The host must enable `Redis::OPT_REPLY_LITERAL=true`; the bridge checks this setting before each command and accepts only the literal `'OK'` success, with `false`/`null` representing nil conflicts. phpredis's default boolean status conversion cannot distinguish `OK` from `QUEUED`, so default mode fails before issuing a claim. A queued response is never accepted, including transactions started through `rawCommand('MULTI')` that bypass phpredis's local mode tracking. Backend errors expose only fixed `REPLAY_STORE_UNAVAILABLE` failures without a previous exception. Other configured clients can implement `RedisCommandClient::execute(array $command): mixed`, returning exactly `'OK'` or `null`; unexpected results fail closed.

Use a dedicated connection; do not share it with application transactions/pipelines. Configure finite synchronous connection/read timeouts in the host. Provision no eviction of live claims and persistence/failover consistent with your replay guarantees. A Redis restart, eviction or asynchronous replication loss can lose claims; the SDK cannot establish those operational guarantees.

Run the separate integration harness only against a new **owned disposable** Redis URL, never a production database. It uses random scoped keys, deletes only its own keys, and makes no FLUSH or server configuration changes:

```sh
# Supply APPGUARD_TEST_REDIS_URL in the environment (redis:// or rediss://).
python3 tests/redis_integration.py /absolute/path/php -n -d extension=/absolute/path/redis.so
```

This fails if the extension or server is unavailable; it is not silently skipped by the unit suite. The harness covers eight independent simultaneous clients, one winner, cross-process rejection, exact canonical storage/TTL, expiry, literal responses/prefix bypass, default nonliteral-mode denial without mutation, raw-MULTI/QUEUED rejection, pipeline, backend errors and unconnected-client denial. The harness and cross-language probe explicitly enable literal replies as host configuration. For cross-language probes, use the same explicit PHP options with `tests/redis_live.php cross APP_ID KEY_ID NONCE`; stdout is only `CLAIMED` or `REPLAY`, with a fixed error on stderr. Probe TTL defaults to 30 seconds; the shared harness may pass explicit `NOW EXPIRES` arguments.
