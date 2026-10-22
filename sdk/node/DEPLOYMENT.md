# Server deployment verification

AppGuard remains experimental and unpublished. Local hardening and scoped code
reviews are evidence for the behaviors below, not a supported production release
or external security audit. The repository's `SECURITY.md` describes its current
security-support boundary; no supported production release is established.

## Dependency deadlines and overload

For Express, Nest/Express or Fastify, set `identityTimeoutMs` on the existing
adapter options when the default 10-second total authentication/key-lookup budget
does not match the application's service budget. `bodyTimeoutMs` is separately
30 seconds by default. `replayTimeoutMs` is a separate 10-second default for
the verified request's replay claim, including direct `verifyRequest` calls.
All three accept integers from 1 through 2147483647; omit an option to use its
default. Authentication starts after body capture; replay starts after signature
verification. These phases do not establish a single total request deadline.

The body budget spans chunk capture, the final synchronous copy, capture handoff
and final framing validation before authentication, using one monotonic deadline.
Reaching the deadline rejects with fixed 400 `INVALID_REQUEST`; an unexpired body
overflow retains 413. Blocking JavaScript can delay the timer, so the adapter also
checks elapsed time after control returns. This cannot preempt a copy, cap all
outstanding requests or replace host header/socket/admission limits. Initial
envelope parsing and later authentication/replay/application work have separate
boundaries. See [body deadline evidence](../../docs/security/node-body-deadlines.md).

The authentication budget spans both callbacks and is checked with a monotonic
clock after asynchronous returns and before continuing SDK work. Expiry returns
503 with the active phase's fixed code. After expiry, the SDK does not pass late
results to replay or the downstream application. Other requests keep their own
budgets. Actual localhost tests cover
all three Node adapters, hung/late callbacks and successful verification.

SDK deadlines do not terminate application work or interrupt synchronous code.
Configure connection/query timeouts and concurrency limits in the application's
authentication and key-registry clients. Configure HTTP connection/body/header
limits and edge rate limits for the deployment. The SDK's policy API consumes a
trusted rate-limit verdict; it does not install a distributed limiter or prevent
all resource exhaustion. Local deadline tests are not capacity/latency benchmarks.

## Replay failure and recovery

Use a shared replay store for multiple processes/hosts, with explicit client
connection/command timeouts. Node's separate `replayTimeoutMs` guard rejects hung
or late claims with `REPLAY_STORE_UNAVAILABLE` and prevents late SDK success.
It does not cancel the backend command or guard a direct `ReplayStore.claim`
invocation. A timed-out command may still consume its nonce; do not delete that
claim or retry with the same signed request. Prepare a fresh request/nonce and
preserve application-level idempotency/recovery. Python's adapter likewise needs
configured synchronous Redis client timeouts; its authentication timeout cannot
stop a running worker thread.

Keep replay storage unavailable failures as failures. Switching to a per-request
or process-local fallback loses distributed replay protection. Provision no-live-
key eviction and the persistence/replication/failover behavior the deployment
requires. The local runner checks one disposable Redis instance, atomic claims
and cross-process conflicts; it does not prove survival of a production failover.

A failed backend response does not prove that its operation rolled back. Nonce
claims also do not provide business idempotency. Apply the application's normal
idempotency and authenticated recovery/readback rules when outcomes are uncertain.

## Connection closure

Node HTTP adapters stop their own verification waits after an observed response
or socket close, or an already-ended response. Late identity/key/replay outcomes
cannot dispatch downstream application work. The guard clears owned timers and
listeners; normal completed request bodies and keepalive remain supported.
At the SDK-owned Fastify `onRequest` and `preParsing` checkpoints, observed
closure hijacks the reply and stops subsequent processing. Host hook chains
already handed off may continue until the next SDK-owned checkpoint. The guard
does not continuously wrap arbitrary application hooks.

This neither cancels an already-issued backend command nor rolls back its nonce.
Runtime-observed closure is the boundary: OS/network notification can be delayed
and synchronous JavaScript cannot be preempted. Work already dispatched to the
application is host-owned; event listeners and framework response cleanup may
still run. Direct core/store calls have no HTTP disconnect
context. Test actual ingress disconnect/timeout behavior and application-level
idempotency during deployment; local loopback checks do not prove proxy behavior.

## Authentication, transport and rollout

Supply validated subjects and trusted enrolled key records; a request signature
does not validate a Bearer token or grant resource permissions. Keep application
authorization after verification. Key enrollment, rotation/revocation delivery
and any Apple/Google provider verification need their own deployment evidence.

Use a configured external HTTPS origin and preserve the exact signed target,
duplicate-preserving header evidence and raw body through the actual ingress.
Run the SDK before rewrites/body parsers as each SDK guide specifies. An insecure
transport opt-in requires separately enforced TLS termination and backend access
control; forwarding headers alone do not establish that trust.

Before promoting a deployment, exercise valid/replayed/tampered requests, empty
queries and percent-escape case through its actual ingress, and verify that
authentication/key/replay outages deny without reaching the application. Validate
rollback against the same authentication, keys and shared replay state. Those
environment checks are separate from the repository's local test evidence.

## Reproduction and remaining release gates

From a source checkout, use `scripts/test-server-sdks.sh` with a new owned disposable loopback Redis as
documented in the root README. Node's focused operational regressions run with
`node --test sdk/node/test/authentication-deadlines.test.js` after its frozen
dependency install. The repository's `docs/security/authentication-deadlines.md`
records the actual runs and package consumer results. Source tests and their
toolchains are not bundled in the installed npm package.

Hosted CI execution, deployed ingress/failover/load tests, a supported version and
release/security-response process, external audit, genuine provider verification
and physical-device execution remain separate gates. They must not be marked
complete from a local unit/HTTP test, compiled mobile build or draft CI workflow.
