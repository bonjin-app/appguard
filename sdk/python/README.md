# AppGuard Python server SDK

Experimental Apache-2.0 package implementing the common [request](../../protocol/request-v0.md) and [HTTP](../../protocol/http-v0.md) contracts. No package has been published. Authentication, resource authorization, key enrollment/revocation and platform attestation remain application responsibilities.

## Local installation and tests

Python 3.11+ and uv, from the repository root:

```sh
uv sync --locked --project sdk/python
uv run --frozen --project sdk/python pytest sdk/python/tests -q
uv build --project sdk/python
```

For an existing application, install the local source with the desired extras, for example `pip install './sdk/python[fastapi,redis]'`. The built wheel is independent of `appguard_reference`; the reference package now re-exports this SDK's core. Optional extras are `fastapi`, `django`, `flask` and `redis`.

Set `APPGUARD_TEST_REDIS_URL=redis://127.0.0.1:DISPOSABLE_PORT/0` to enable the three live Redis tests. Use a new disposable local Redis instance; tests delete only their uniquely scoped keys. Without this variable those tests explicitly skip. The root [verification command](../../README.md) requires live Redis.

## Integrating existing authentication

Install the pure ASGI verifier before routing, decoding, decompression and body parsing. Provide an application-owned resolver that authenticates the exact Bearer token, then looks up a trusted enrolled public key for the authenticated subject and supplied key ID:

```python
from fastapi import FastAPI
from appguard.asgi import AppGuardMiddleware, Identity
from appguard.redis import RedisReplayStore

api = FastAPI()

async def identity(scope, key_id):
    # These services are application-owned, not supplied by the SDK.
    subject = await authentication.authenticate_asgi(scope)
    if subject is None:
        return None
    key = await enrollment.find_key(subject, key_id)
    return Identity(subject=subject, key=key)

application = AppGuardMiddleware(
    api,
    app_id="my-app",
    origin="https://api.example.com",
    identity_resolver=identity,
    replay=RedisReplayStore(configured_sync_redis_client),
)
```

`authentication`, `enrollment` and `configured_sync_redis_client` represent the application's existing services. Keys are `appguard.types.KeyRecord(app_id, key_id, subject, public_key_pem_bytes, "ecdsa-p256-sha256", revoked)`. A successful token lookup with an unknown key returns `Identity(subject, None)` and fails with `KEY_REJECTED`. Never accept subjects/public keys from request fields as trusted enrollment evidence.

Resolvers may be synchronous or asynchronous. Synchronous callbacks and verification/Redis claims run off the ASGI event loop. Authentication has a configurable total `identity_timeout` (default 10 seconds); bounded body capture has `body_timeout` (30 seconds). Configure Redis connection and command timeouts on the supplied client as well. A timed-out synchronous callback may continue in its worker thread; the SDK cannot forcibly cancel application code. The clock is read after authentication; optionally pass a trusted `clock` returning integer Unix seconds.

The body budget uses one monotonic deadline across all chunks, framing checks
and the final byte copy. Expiry returns fixed 400 `INVALID_REQUEST` before
authentication when the loop can run. The SDK requests cancellation without
waiting for a resistant host `receive` to finish; it does not initiate another
read or use late events for authentication. Pending reads remain strongly held
until completion and late exceptions are consumed without logging private data.
Caller ASGI-task cancellation propagates without an SDK response. A running host
receive can continue; the SDK does not drain the stream or close its transport.
See the [body deadline verification](../../docs/security/python-body-deadlines.md).

The identity budget uses one monotonic event-loop deadline covering resolver
completion and trusted identity validation. If it expires, the SDK returns fixed
503 `IDENTITY_UNAVAILABLE` when the event loop can run, without waiting for a
resolver to acknowledge cancellation. A late identity, authentication rejection
or exception cannot sample the clock, claim a nonce or reach the application.
Pending resolver tasks are retained until completion and their eventual failures
are consumed. Caller ASGI-task cancellation propagates without an SDK response
and requests resolver cancellation as well.

If a synchronous resolver's thread returns after its wait was canceled, a
lock-protected handoff disposes an abandoned, never-started native coroutine
without awaiting its body. Native coroutine results transfer ownership to the
SDK and must not be shared with another consumer. Exact type/state checks leave
host Tasks, Futures, custom awaitables and already-started coroutines untouched.
Disposal can run on the worker or event-loop thread; closing clears the native
frame and can invoke captured-object finalizers. It is best effort and adds no
hard cleanup/shutdown deadline. See the [cleanup review](../../docs/security/python-resolver-cleanup.md).

Cancellation is best effort. A resolver can suppress it, a worker thread can
continue, and blocking event-loop work cannot be preempted. After blocking work
returns, elapsed-budget checks reject late success, including slow identity
validation. Pending body reads and resolver work may outlive their requests and
delay process shutdown.
These phase budgets do not cap outstanding tasks/threads, bound verification/
replay or downstream time, or install a total request deadline or HTTP-disconnect
monitoring. Configure server read/backend timeouts,
admission/concurrency limits and shutdown behavior in the hosting application.

All requests reaching the wrapper are protected; install it on the intended application surface. A successful check preserves the exact captured body and existing ASGI state, and stores `VerificationResult` in `scope["state"]["appguard"]`. Application exceptions after verification retain application handling. WebSocket connections reject; lifespan events pass through.

For Django, wrap the result of `get_asgi_application()` with `appguard.django.protect_django(app, **configuration)`. The resolver must authenticate before Django's internal middleware runs, or use trusted authentication state established by an outer ASGI layer. For Flask use `appguard.flask.protect_flask(flask_app, **configuration)` and an ASGI server: verification runs before `asgiref.wsgi.WsgiToAsgi` loses duplicate-header evidence. Plain WSGI middleware is not supported. `appguard.fastapi` also re-exports `AppGuardMiddleware` and `Identity`.

The Flask bridge rejects distinct header spellings that would collide after WSGI dash/underscore conversion, before authentication or nonce consumption. After verification and buffering it marks only the completed WSGI input stream as terminated, so Flask can read chunked/no-Content-Length bodies and JSON without changing the original framing headers. Wrapping plain `WsgiToAsgi` manually does not supply these Flask-specific safeguards; use `protect_flask`.

## Exact target and transport evidence

The wrapper requires duplicate-preserving ASGI headers, `raw_path` and `query_string` bytes, and unchanged body bytes. For a nonempty query it can construct the exact target from those bytes. ASGI does not distinguish `/path` from `/path?` when `query_string` is empty. For **every request with an empty query string**, the server integration must therefore provide a trusted `scope["appguard.raw_target"]` byte string, or a synchronous `raw_target_resolver(scope)` returning that exact target. The SDK checks it agrees with raw path/query evidence. Missing evidence rejects with 400; never reconstruct it from a decoded path, guess an absent `?`, or read it from client-controlled headers. No universal ASGI-server capture extension is bundled in this milestone.

HTTPS is required by default. The origin is explicitly configured and never derived from Host/Forwarded headers. `scope["scheme"]` must come from a trusted server integration; disable untrusted proxy-header rewriting before the verifier. For controlled local tests or independently enforced TLS termination only, explicitly set `allow_insecure_transport=True` and own that boundary. Production proxy/TLS deployments require separate verification.

The parser rejects missing/duplicate singleton fields, ambiguous framing, extra signature labels/parameters, noncanonical encodings and unsupported content encoding. Captured content is limited to 1 MiB and must match Content-Length if present. No request normalization is performed to rescue a signature.

## Replay storage and errors

Trusted public-key PEM input must be one complete ASCII `PUBLIC KEY` envelope,
with LF or CRLF line endings. A final newline is optional; trailing ASCII spaces,
tabs and line endings are allowed. Leading junk/BOM, multiple or nested envelopes,
legacy headers and trailing non-whitespace data reject as `KEY_REJECTED` before a
nonce claim. The existing cryptography parser validates the complete DER key and
P-256 curve. Compressed-point SPKI keys remain supported. This validates registry
encoding; it does not establish that a key is trusted or enrolled.

`RedisReplayStore` accepts a long-lived configured synchronous redis-py client; no connection is created automatically. Claims use the shared hashed namespace and a single atomic `SET key 1 NX EX ttl`, where `ttl=expires-now` in `1..150`. A duplicate claim rejects and backend faults fail closed. Provision capacity, prevent live-key eviction, secure the connection, and configure the persistence/replication/restart guarantees needed for your deployment. Redis does not create those guarantees automatically.

For explicit single-process tests/development only, `appguard.replay.InMemoryReplayStore()` is bounded, thread-safe and volatile. Never create a store per request or use it for distributed guarantees. No store or permissive identity callback is selected by default.

SDK failures contain fixed JSON codes only: 400 malformed request/evidence, 413 oversized body, 401 authentication rejection, 403 verification rejection, 503 dependency/internal-verification failure. Tokens, bodies, PEM material and exception details are not returned. A valid signature grants no resource permissions.

In ordinary calls, handled replay backend failures are raised after the exception
handler unwinds: core `REPLAY_STORE_UNAVAILABLE` and Redis adapter failures retain
neither the backend `__context__` nor `__cause__`, including nested/grouped errors.
This does not sanitize application-owned active exception state or captured frame
locals, or promise the same for every unrelated SDK error. Serialize fixed codes
and configure your application's error reporting accordingly.

## Verified scope

Locally tested on Python 3.11.15 with cryptography 50.0.2, FastAPI 0.150.0 / Starlette 1.9.0, Django 5.2.18, Flask 3.1.3 / asgiref 3.12.1, redis-py 8.1.0 and Redis 7.2.10. The SDK suite uses actual framework applications through HTTPX ASGITransport plus direct ASGI stream-boundary checks. These are in-process framework tests, not live ASGI-server/TLS deployment evidence. The 209 reference tests exercise the promoted core, including all 40 shared request scenarios. The SDK separately consumes all 43 HTTP-envelope scenarios and tests authentication failures, exact target/body preservation, limits, Redis concurrency and failure redaction. A standalone wheel install is checked without reference checkout imports. See [verification evidence](../../docs/security/server-sdk-verification.md).


## Optional enrollment, policy and provider backends

The explicit experimental SQLite-backed enrollment service, deterministic policy
presets and allowlisted audit API are documented in
[enrollment/policy integration](../../docs/security/enrollment-policy.md).
For account-security flows, `SqliteEnrollmentStore.revoke_subject(app_id,
subject)` atomically revokes that subject's active keys and cancels all matching
pending challenges, returning immutable `SubjectRevocationResult` counts. It
preserves key-ID tombstones and exact app/subject scope. The application still
owns authorization, token/session blocking, cache invalidation and whether a new
post-revocation challenge may be issued. See the
[subject-wide revocation contract](../../docs/security/enrollment-policy.md#subject-wide-revocation).

[Google Standard](../../docs/security/google-provider.md) and
[Apple initial attestation](../../docs/security/apple-provider.md) can supply its
trusted provider callback. They do not acquire deployment credentials or establish
provider/device approval. Apple uses a conservative iOS-only compatibility pin;
its assertion/receipt/counter lifecycle remains incomplete. Importing a provider
performs no network or credential discovery.

The full integrated SDK suite passed474 tests with a disposable Redis after the
provider review fix; all223 provider tests also run from a separately installed
wheel. See [provider verification](../../docs/security/provider-verification.md)
for exact offline proof and remaining external checks.
