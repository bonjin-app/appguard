# AppGuard Node server SDK (experimental v0)

Private, locally installable ESM package, Apache-2.0. Implements the repository's
`protocol/request-v0.md` and `protocol/http-v0.md` with Node's native P-256/SHA-256
crypto and IEEE P1363 signatures. This is a restricted canonical profile, not a
general RFC 9421 or Structured Fields parser. No package publication is configured.

The SDK verifies a request signature bound to a caller-authenticated subject and
an already trusted key. Authentication, resource authorization, key enrollment,
revocation distribution, platform attestation and TLS topology remain application
responsibilities. There is no default token validator, key resolver, replay store
or automatic path exclusion.

## Install locally

From this directory, with Node 22 and npm:

```sh
npm ci --ignore-scripts
npm test
npm run test:types
npm run test:install
npm pack --ignore-scripts --pack-destination artifacts
```

In a consuming Node ESM project:

```sh
npm install /absolute/path/to/appguard-server-0.0.0-experimental.0.tgz
# Choose only the application/framework dependencies you actually use:
npm install express@5.3.0 redis@6.3.0
```

The package has no runtime npm dependencies. Redis clients and frameworks are
supplied by the application. TypeScript declarations are included; Node TypeScript
applications should install their normal `@types/node` development dependency.
Only ESM imports are exported; CommonJS `require` is not a supported entry point.

## Mandatory authentication and key lookup

Build one long-lived options object. The functions imported below are your existing
application security code, not SDK functions or illustrative token acceptance:

```js
import { RedisReplayStore } from '@appguard/server';
import { createClient } from 'redis';
import {
  authenticateBearerToken,
  findTrustedEnrolledKey,
} from './application-security.js';

const redis = createClient({ url: process.env.REDIS_URL });
redis.on('error', () => { /* report dependency health without request secrets */ });
await redis.connect();

const options = {
  app_id: 'your-app',
  origin: 'https://api.example.test', // trusted external HTTPS origin, no path
  replay: new RedisReplayStore(redis),
  identityResolver: async ({ headers }) => {
    const authorization = headers.find(([name]) =>
      name.toLowerCase() === 'authorization')[1];
    const identity = await authenticateBearerToken(authorization);
    return identity?.subject ?? null;
  },
  keyResolver: async ({ app_id, key_id, subject }) =>
    findTrustedEnrolledKey({ app_id, key_id, subject }),
};
```

`authenticateBearerToken` must actually validate the signed Bearer token. Never
accept a client-provided subject as proof of identity. `findTrustedEnrolledKey`
returns a pre-enrolled record shaped as:

```ts
{
  app_id: string;
  key_id: string;
  subject: string;
  public_key_pem: string | Buffer; // P-256 SPKI PUBLIC KEY PEM, at most 4096 bytes
  algorithm: 'ecdsa-p256-sha256';
  revoked: boolean;
}
```

A completed key lookup with no matching trusted key returns `null`/`undefined` and
rejects with `KEY_REJECTED`. Lookup exceptions and malformed non-null records are
dependency failures. A combined `identityResolver` can instead return
`{ subject, key }` (with `key: null` for an unknown key); omit `keyResolver` then.
Return `null`/`false` from `identityResolver` for unauthenticated requests. Callback
exceptions never become successful verification or leak their text in responses.
The trusted clock is read after asynchronous authentication/key lookup completes.

The frozen successful verification result retains the key ID and expiry used
for the replay claim. Changes to caller-owned key records or parameters while
that claim is pending do not change the result. Replay must still return strict
`true` before verification succeeds. This does not recheck the clock or key
revocation after awaiting the store.

## Express 5

Install the guard first at the application root, before routers, URL rewrites,
body readers, decompression, JSON parsing or form parsing:

```js
import express from 'express';
import https from 'node:https';
import { expressMiddleware } from '@appguard/server';

const app = express();
app.use(expressMiddleware(options));
app.use(express.json()); // reads the verified, replayed bytes normally
app.post('/items', (req, res) => {
  // Enforce resource authorization here using your authenticated identity.
  res.json({ body: req.body, verification: req.appguard.code });
});
https.createServer(tlsKeyAndCertificate, app).listen(443);
```

The middleware captures `req.url`, Express `originalUrl` evidence and duplicate-
preserving `rawHeaders` before reading bytes. Mounting the guard inside a router
with an already trimmed URL, known prior URL rewriting, any prior body consumption
or body parser, or missing raw evidence rejects. Applications must retain this
installation order; arbitrary application code can overwrite Express's original
URL/header evidence and is outside the trusted capture boundary.

After verification the middleware delegates public request readable-stream methods
to a bounded replay stream. It preserves the request object, socket, headers and
existing authenticated identity. Normal Express JSON and raw body parsers are
exercised by the integration suite. Private `IncomingMessage._readableState` is not
modified. Unusual middleware that consumes stream internals or native stream state
rather than public readable APIs is not supported by this replay boundary.

## Fastify 5

Install synchronously on the intended Fastify instance before other hooks and
routes. Fastify encapsulation defines which routes receive its hooks:

```js
import Fastify from 'fastify';
import { installFastify } from '@appguard/server';

const app = Fastify({ https: tlsKeyAndCertificate });
installFastify(app, options);
app.post('/items', async request => {
  // Apply resource authorization before using the verified request.
  return { body: request.body, verification: request.appguard.code };
});
await app.listen({ port: 443 });
```

A prepended native server `request` listener snapshots target/method/rawHeaders
before framework hooks. The `onRequest` hook captures and verifies bytes; a
`preParsing` hook returns their unchanged replay stream with
`receivedEncodedLength`. Earlier target/header rewrites, already consumed payloads
and transformed preParsing streams reject. Fastify's `inject()` bypasses the native
HTTP server event and therefore deliberately fails closed: use real localhost
HTTP/HTTPS tests for this adapter. HTTP/2 is not a tested/supported integration.

## NestJS 12 with the Express platform

Disable Nest's automatic body parser, install global middleware, and then install
application parsers before initialization/listening:

```js
import express from 'express';
import { NestFactory } from '@nestjs/core';
import { nestMiddleware } from '@appguard/server';

const app = await NestFactory.create(AppModule, {
  bodyParser: false,
  httpsOptions: tlsKeyAndCertificate,
});
app.use(nestMiddleware(options));
app.use(express.json());
await app.listen(443);
```

Controllers receive their usual parsed body and `request.appguard` metadata. This
adapter is tested with the Nest Express platform, not Nest's Fastify platform. The
same first-at-root and public readable-stream requirements as Express apply.

## Transport, bounds and errors

Direct secure transport (`request.socket.encrypted === true`) is required by
default. Forwarded/Host/X-Forwarded-* headers do not establish HTTPS or determine
the signing origin. Set `allowInsecureTransport: true` explicitly only for local
tests or where an operator separately enforces TLS termination and backend access.

Before hashing/signature verification, the SDK checks the exact profile and limits:
1 MiB content bytes; 8 KiB target; 64 duplicate-preserving header pairs and 16 KiB
ASCII header name/value bytes, including unrelated/signature headers. Only identity
content encoding is accepted. Framing is checked, including duplicate fields,
canonical Content-Length, exact byte count and conflicting Content-Length/
Transfer-Encoding. Capture is bounded; overflow is rejected without retaining the
excess chunk. Incomplete, aborted, previously consumed or timed-out streams fail
closed. `bodyTimeoutMs` defaults to 30,000 and must be a positive integer.

Node's HTTP server parses HTTP framing and exposes parsed raw-header values; its
own parser/limits may reject a request before middleware runs. Such server-level
responses are outside SDK JSON mapping. The adapter cannot recover socket bytes,
header whitespace/normalization or evidence discarded by an upstream proxy or
application. Deploy a trusted HTTP stack that preserves the signed target and
content bytes; do not enable a normalizing/decompressing step before the guard.

SDK failures contain only `{"code":"FIXED_REASON"}`:

| HTTP | Code |
| --- | --- |
| 400 | INVALID_REQUEST (including insecure transport or lost raw evidence) |
| 413 | INVALID_REQUEST (body overflow) |
| 401 | AUTHENTICATION_REQUIRED |
| 403 | UNSUPPORTED_PROFILE, INVALID_TIME, KEY_REJECTED, DIGEST_MISMATCH, INVALID_SIGNATURE, REPLAY_DETECTED |
| 503 | IDENTITY_UNAVAILABLE, KEY_RESOLVER_UNAVAILABLE, REPLAY_STORE_UNAVAILABLE |

Success adds dedicated `appguard`, `appguardRawBody` (Buffer) and `appguardTarget`
attributes to the request; it does not overwrite `user` or another authenticated
identity. Fastify exposes the attributes on both its request and raw request.
`VERIFIED` permits downstream handling and does not grant resource authorization.

## Replay deployment

`new InMemoryReplayStore({ capacity: 10000 })` is an explicit development/test
choice: volatile, single process, no restart protection. It never evicts live
claims to make room; exhausted capacity fails closed. Share one long-lived store
across requests. Do not instantiate stores inside a middleware callback.

`new RedisReplayStore(client)` requires a long-lived connected node-redis-compatible
client implementing `sendCommand`. It issues exactly one atomic command:

```text
SET appguard:v0:replay:<lowercase SHA256(compact JSON [app_id,key_id,nonce])> 1 NX EX <expires-now>
```

TTL must be an integer in 1..150 seconds. Only `OK` means a new claim; `null` means
an existing claim; errors and unexpected responses fail closed. The namespace is
shared with the Python/Java SDKs. Operators must provide capacity, prevent live-key
eviction, secure connections and configure persistence/replication according to
their restart/failure requirements. These guarantees are not installed by the SDK.

## Verification evidence and limits

Locally tested on Node 22.23.2, npm 10.9.8, Express 5.3.0, Fastify 5.12.7,
NestJS 12.2.0 (Express), node-redis 6.3.0 and disposable Redis 7.2.10.
Tests use all 40 typed request vectors and 43 strict HTTP vectors, native P-256
verification, actual HTTP/HTTPS servers, ordinary JSON/raw downstream parsers,
query encoding/empty queries, body tampering, missing/duplicate metadata,
async callback faults, unknown keys, replay/store faults, 32 simultaneous requests,
one-byte UTF-8 chunks, overflow, consumed bodies and disconnected/truncated streams.
The self-signed localhost TLS fixtures in `test/fixtures` are test-only credentials.

```sh
# This variable must point only at an owned disposable Redis instance.
APPGUARD_TEST_REDIS_URL=redis://127.0.0.1:PORT/0 npm test
npm run test:types
npm run test:install
```

Without that variable only the live-Redis test is skipped; injected-client contract
checks still run. Live tests delete only their exact owned nonce key. RED/GREEN logs,
tarballs and isolated-install artifacts are local ignored evidence under `logs/`
and `artifacts/`. Unit/core evidence, actual local framework HTTP/HTTPS evidence and
local Redis concurrency evidence do not establish production deployment, upstream
proxy preservation, durable Redis consistency, authentication correctness,
platform/device attestation or a security certification.

## Explicit policy and audit (experimental v0)

The pure policy API matches the 42 shared `conformance/v0/policy.json` cases. It
is independent of HTTP adapter installation. The application must supply trusted
server authentication, request-verification and platform-attestation verdicts.
Never construct `authenticated` or `verified` from a client-reported status.
`risk_signals` are bounded untrusted hints; `rate_limited` consumes an existing
application limiter result. This module installs no limiter or provider verifier.

```js
import { Policy, PolicyContext, evaluatePolicy, JsonAuditSink } from '@appguard/server';
const policy = new Policy({ profile: 'balanced' });
// These verdicts must come from your existing trusted server checks.
const context = new PolicyContext({
  authentication: 'authenticated', verification: 'verified',
  attestation: 'verified', attestation_expires: 101, risk_signals: []
});
const decision = evaluatePolicy(policy, context, { now: 100 });
const sink = new JsonAuditSink(json => applicationAuditWriter(json));
await sink.emit(decision, { event_id: 'opaque-event-1', app_id: 'my-app', now: 100, context });
if (decision.action === 'allow' || decision.action === 'observe') {
  // Continue only after the application's authorization checks also succeed.
} else {
  // deny blocks; step_up blocks until a separate trusted flow succeeds.
}
```

All context verdicts default to missing; missing authentication always denies.
Signatures default to required. Only explicit
`new Policy({profile:'basic', require_signature:false})` disables that requirement.
Fresh attestation requires `now < attestation_expires`; equality is expired.
Unavailable/missing/unsupported/expired attestation and configured risk hints
produce `observe` in Basic, `step_up` in Balanced, and `deny` in Strict.
Authentication failures, rejected/unavailable request verification, rejected
attestation and rate limiting deny in all profiles with the specified precedence.

Policy/context/decision objects and copied signal arrays are immutable. Signal
lists contain at most 32 unique `[a-z][a-z0-9_]{0,63}` codes. Clocks are integers
from 0 through 999999999999999. Unknown fields and malformed input reject with
fixed `PolicyError` codes. Custom classes and structural lookalikes are rejected.

`auditEvent(decision, metadata)` returns a frozen allowlisted event. Its optional
context contributes only `risk_count` and `attestation_state`; raw hints, tokens,
bodies, subjects, keys, nonces and IPs are excluded. IDs must be opaque application
and event IDs (1–128 ASCII letters/digits or `._:-`), never credentials or user IDs.
The caller owns audit availability, storage, retention and privacy policy.
`JsonAuditSink` accepts a synchronous or asynchronous callback. **Always await
`emit`**, which returns `Promise<void>`; callback throws and rejections become
fixed `AUDIT_UNAVAILABLE` errors without an original cause. Metadata errors use
`INVALID_AUDIT_EVENT`. No arbitrary event objects are accepted by the sink.
