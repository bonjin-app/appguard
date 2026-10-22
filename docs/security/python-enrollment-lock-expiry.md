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

## Local verification and independent review (2026-10-22)

The reviewed runtime commit is
`e1bb3d95fcdad81f9e703180fd66456dac6f0239`. The source baseline passed 659
SDK tests. Of the 19 new regression cases, 15 failed against the previous runtime
with the expected missing rejection; four compatibility/positive controls passed.
All 19 passed after the fix, and the complete SDK passed 678 tests with no skips,
including three live cases on a new disposable loopback Redis instance.
Reference verification passed 209 tests with no skips.

The previously built wheel was independently installed in an isolated environment.
Its 21 package entries match the base commit. Of seven cross-process/import
probes, five failed because stale completion was accepted, while the valid
completion and isolated import controls passed. The same seven probes all passed
against the rebuilt wheel, whose SHA-256 is
`ab7570473fba9457513a8849ab5910711be8552054e88442784860e214c2a46e`. All 21 package entries match committed source, wheel bytes,
installed bytes and a preserved installed-source snapshot. Package README metadata
and a frozen, hash-checked dependency installation were verified.

Independent review freshly passed 678 SDK tests, 209 reference tests and the
seven installed-wheel probes, plus 12 additional probes on source and the same
12 on the isolated installed package. Those cases cover strict profile with a
separate-process SQLite lock holder, expiry precedence, provider/final-clock
retry, immutable/cancelled challenge checks, provider work outside the transaction,
direct integer-time completion and real trigger-induced rollback. All fresh
checks had zero failures, errors and skips. These counts overlap and must not
be summed as distinct scenario counts. The initial RED results are historical
reproduction evidence, not passing checks.

The independent review found no actionable issues within this scope. Its receipt,
raw logs/JUnit, historical RED results, package/lock hashes and retained source
are preserved under `.superpowers/evidence/2026-10-22-enrollment-lock-expiry/`
in the primary checkout. The final verification-record commit changes only this
document; reviewed runtime, SDK README and wheel bytes stay unchanged.

This evidence is local CPython 3.11/macOS/SQLite behavior with synthetic provider
evidence. Other operating systems/versions, production performance, host policy
and authorization, real providers/devices, remote CI, deployment and publication
remain separate evidence tiers.
