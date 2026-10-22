# Python subject-wide enrollment revocation

2026-10-22; experimental Apache-2.0 Python SQLite enrollment API. No wire
protocol, schema or provider configuration change.

## Contract

`SqliteEnrollmentStore.revoke_subject(app_id, subject)` validates the existing
identifier grammar and performs one transaction on the dedicated local database:

1. Mark matching active credentials revoked for that exact app and subject.
2. Delete all matching pending enrollment challenges, including expired rows
   still retained in the database.
3. Return an immutable `SubjectRevocationResult` with `revoked_keys` and
   `cancelled_challenges` counts only after the transaction boundary succeeds.

`revoked_keys` counts newly revoked credentials, not already revoked rows.
`cancelled_challenges` counts deleted rows. An unchanged repeat returns zero/zero;
missing subjects also return zero/zero. Other apps and subjects are unaffected.
Credential rows remain as key-ID tombstones: revocation never permits reusing an
existing app/key ID. Single-key `revoke` retains its existing behavior.

The result type is available from `appguard.enrollment`, alongside the existing
enrollment APIs. Its two count fields contain no subject, key material, provider
evidence or challenge nonce. This synchronous API does not install an HTTP route,
authenticate an operator or configure an administrative authorization policy.

## Race and trust boundaries

SQLite transactions serialize this operation with enrollment writes on the same
local database. A completion that committed first leaves a credential that the
revocation transaction marks revoked. A completion still working on a pre-cut
challenge must recheck it in `finish`; deletion makes that completion reject
without inserting a credential. Provider work already running is not forcibly
stopped. The operation changes database state, not previously returned credential
objects or an application-owned identity/key cache.

This is a point-in-time state change, not a persistent account suspension. A
new challenge issued after the transaction can enroll under a new key ID if the
application still authorizes it. The host must authorize the target operation,
block authentication and new enrollment when appropriate, invalidate caches, and
enforce resource permissions. Tokens, sessions and already-dispatched application
requests are not canceled by this API. A prior active `Credential` must not be
reused as fresh proof that its key remains active.

The backend remains one dedicated private SQLite database, coordinating local
connections/processes rather than distributed enrollment services. No schema
migration, account-status table, index migration, provider lifecycle or audit
delivery service is added. Large-population throughput and production-host
behavior are not established by local concurrency fixtures.

## Failures and recovery

The existing `_db` transaction and redaction boundaries cover both statements.
If a statement fails before commit, rollback is attempted; partial key/challenge
changes must not be treated as success. Fixed `STORE_UNAVAILABLE` errors retain
the existing cleanup/redaction contract, with rollback and close attempted
independently. Invalid identifiers retain `INVALID_ENROLLMENT` behavior.

A commit can succeed before close or response delivery fails. Such an error
returns no success counts and does not prove that state was rolled back. Perform
authenticated readback and follow the host recovery policy. A later successful
zero/zero result can mean an earlier uncertain operation already persisted; it
does not prove that authentication was disabled or that the account never had
credentials. Existing application-owned ambient exception context and traceback
locals are outside the SDK's fixed-error-chain boundary.

## Verification boundary

Tests use dedicated temporary SQLite databases, real P-256 possession proofs and
controlled synthetic provider callbacks. They check exact scope, counts,
durability, tombstones, late completion, rollback and error behavior. The full
Python SDK suite runs against a new disposable loopback Redis instance; no shared
Redis database is supplied or flushed. Reference protocol checks and a separately
installed wheel test source/package boundaries.

Raw logs, source and wheel hashes, consumer evidence and independent security
review are retained in
`.superpowers/evidence/2026-10-22-subject-revocation/` on local main. These tests
do not establish real provider/device verification, production account controls,
remote CI, deployment or public package publication. Other server SDKs and the
common protocol remain unchanged.

## Local verification record (2026-10-22)

The reviewed runtime commit is
`b7131927b7b70829714c33fcd45ec93b4d9547fa`. The SDK baseline passed 620 tests;
the new regression suite first produced 39 expected missing-method failures,
then passed all 39 cases after implementation. The complete SDK passed 659 tests
with no skips, including three live tests against the task-owned disposable
Redis instance. Parent reference verification passed 209 tests with no skips.

A separately built wheel has SHA-256
`f45ee5a856695008c5bdb9cc675b8dca6ab9545fc388ac12183aef48e791f009`.
All 21 package entries match committed source, wheel bytes and installed bytes.
Package README metadata, all 24 hashed wheel RECORD entries and the frozen,
hash-checked dependency installation were verified. The isolated installed-wheel
suite passed seven probes: six behavioral cases and one import-origin check.

Independent security review reported no findings in this Python SQLite scope.
Fresh review runs passed 659 SDK tests, 209 reference tests, seven installed-wheel
probes and seven additional independent probes, all without skips. Independent
cases cover separate-process completion/revocation ordering, four concurrent
processes, exact subject scope, tombstones, fresh authorized enrollment, rollback
cleanup and persisted state after a post-commit close failure. These evidence
sets overlap and must not be added as distinct scenario counts. Historical
baseline and failing regression logs were inspected, not rerun by the reviewer.

Initial review harness attempts had collection errors from an incompatible
pytest import mode and fixture errors from a missing temporary parent directory.
The reviewer corrected the ignored harness and reran successfully; the original
logs remain preserved separately. These corrections changed no product source.
The final documentation-only record does not change the reviewed SDK or wheel.

This evidence establishes local Python/SQLite behavior and package integrity;
it does not establish production throughput, host authorization/session/cache
integration, distributed coordination, live provider verification, physical-device
results, remote CI or deployment. Subject revocation remains a point-in-time
operation rather than an ongoing account suspension.
