# Python enrollment expiry after SQLite lock acquisition

2026-10-22; experimental Apache-2.0 Python SDK. No schema, wire-protocol,
dependency, provider-configuration or other server SDK change.

## Reproduced boundary

`EnrollmentService.complete` checked the clock after proof/provider work, then
passed that integer timestamp to the SQLite store. The final `BEGIN IMMEDIATE`
can wait for another writer, using the existing five-second SQLite busy timeout.
The previous implementation reused the pre-wait timestamp after obtaining the
lock. A challenge or provider verdict that expired during this interval could
therefore be enrolled using a stale validity decision.

Completion now supplies its trusted, validated clock to the final store
transaction. After the write lock is acquired, the store samples that clock
before credential mutation and checks both challenge expiry and a verified
credential's provider expiry. At or beyond the challenge deadline the operation
rejects with `CHALLENGE_REJECTED`; an expired provider verdict rejects with
`ATTESTATION_REJECTED`. A failed or invalid service clock yields the existing
fixed `CLOCK_UNAVAILABLE` error. The transaction cleanup/redaction boundary
preserves pending challenge state and inserts no credential on these failures.

Proof/provider callbacks remain outside the write transaction. Existing
single-use, exact app/subject/key scope, key-ID tombstones and subject-wide
revocation behavior are retained. A valid completion released before both
deadlines can still succeed. A provider-expiry rejection can be retried with a
fresh valid provider verdict while the challenge remains valid and host policy
still authorizes the operation.

## Limits

This is a sampled validity gate, not a real-time deadline or an atomic guarantee
that commit or response delivery completes before either expiry. SQLite commit,
filesystem work and host scheduling can take additional time. A previously
returned credential can become stale; authenticate callers and use fresh registry
and policy decisions for subsequent requests. The host owns clock accuracy,
timeouts, admission limits, private local database storage, authorization,
token/session/cache lifecycle and provider configuration.

The existing integer `now` form of the low-level store completion remains
compatible. Its caller owns that snapshot's freshness; use `EnrollmentService`
for the live-clock completion path. The added clock is trusted application code
and must be fast and side-effect-free; its transaction invocation must not
re-enter the enrollment store. No provider network work is moved into SQLite.

`STORE_UNAVAILABLE` does not prove a transaction rolled back: commit may succeed
before a close/response error. Use authenticated readback to reconcile uncertain
outcomes. Existing redaction covers handled error chains, not application-owned
ambient exceptions or captured traceback locals.

Local tests use real temporary SQLite connections, P-256 possession proofs,
explicit synchronization gates, synthetic clocks and synthetic provider verdicts.
They establish no live provider/device result, multi-host database guarantee,
production performance, remote CI, deployment or published package support.
