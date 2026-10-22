# Atomic Apple initial enrollment and verified receipt state

`appguard.providers.apple_enrollment.AppleEnrollmentService` is an explicit opt-in
integration of ordinary request-key proof, [initial App Attest verification](apple-provider.md),
[independent CMS receipt verification](apple-receipts.md), and [assertion state](apple-lifecycle.md).
It activates all linked state in one dedicated private SQLite transaction.
Generic `EnrollmentService`, existing callbacks and standalone stores retain their
existing behavior. This integration performs no device/account/key provisioning.

```python
from appguard.providers.apple import AppleAppAttestVerifier
from appguard.providers.apple_enrollment import (
    AppleEnrollmentService, SqliteAppleEnrollmentStore,
)

backend = AppleAppAttestVerifier(
    app_id="my-app", apple_app_id="ABCDEFGHIJ.co.example.app",
    platform="ios", environment="production",
    allowed_validation_categories={4}, allowed_bundle_versions={"42"},
)
store = SqliteAppleEnrollmentStore("/private/appguard/apple-enrollment.sqlite")
enrollment = AppleEnrollmentService(store=store, verifier=backend)

# Authenticate the caller and derive subject/app/origin from trusted host policy.
challenge = enrollment.issue(
    app_id="my-app", subject=authenticated_subject, key_id=request_signing_key_id,
    origin="https://api.example.test", public_key_pem=request_public_key_pem,
)
# Native initial attestation uses SHA256(enrollment_message(challenge)).
# proof is the existing request-key enrollment proof, not an App Attest signature.
credential = enrollment.complete(
    challenge.nonce, app_id="my-app", subject=authenticated_subject,
    proof=raw_request_key_proof, evidence=initial_app_attest_json,
)
apple_key = store.apple_key("my-app", authenticated_subject, request_signing_key_id)
verified_receipt = store.verified_receipt("my-app", authenticated_subject, apple_key.key_id)

# The assertion service uses the same private database through its `.apple` view.
assertion_challenge = enrollment.assertions.issue(
    subject=authenticated_subject, key_id=apple_key.key_id, request=exact_operation_bytes,
)
```

The service fixes the enrollment profile to strict. It validates the existing
request key's proof first, then the pinned-root initial attestation, and then a
fresh `ATTEST` CMS receipt. The expected signed receipt field 4 is the 32-byte
`SHA256(enrollment_message(challenge))`, derived from authenticated server state.
App ID, environment, attested SPKI, receipt type, creation/expiry and CMS trust
must all match. Initial attestation and receipt roots remain independent and
unchanged. Provider/receipt parsing occurs before the write transaction; no
provider or credential network request occurs during initial verification.

Only an internal in-process verdict carries this verified metadata into the
protected commit hook. Inside one `BEGIN IMMEDIATE` transaction, the store checks
the clock again after obtaining its writer lock, checks the exact unconsumed
server challenge, existing request-key tombstone, initial verdict expiry and
receipt freshness/expiry, and verifies the time ordering
`initial.verified_at <= receipt.verified_at <= final_now`. It inserts all of the following:

- The request-signing credential using the ordinary enrollment schema and proof.
- The App Attest key, immutable app/Apple App ID/environment/subject association,
  initial message hash, counter zero and active revocation state.
- A unique link between request-key enrollment and App Attest key.
- The independently verified initial receipt, signed metadata and receipt hash.

The transaction also consumes the enrollment challenge. Any uniqueness,
validation, storage or commit failure rolls back every mutation. An Apple key
cannot be assigned to another request-key enrollment or subject, including after
revocation. Multiple distinct Apple/request-key pairs for a user remain supported.
The generic store's public `finish` and standalone Apple `register` are disabled
on the combined store, so ordinary basic enrollment cannot accidentally activate
half an association. There is no caller-supplied transaction callback.

`SqliteAppleEnrollmentStore` uses a **new** explicit database path and its own exact
combined schema. Reopening checks every schema object and its complete SQLite
creation SQL, including column types, NOT NULL, primary/unique keys, foreign keys
and CHECK constraints, against the same recipe in a transient in-memory database.
It rejects a changed schema or existing standalone enrollment/Apple databases
without mutating them, and performs no automatic migration or merging. Its
mode-0600 file, ownership, regular-file, hardlink/symlink, file identity and
missing-file protections are the same as the assertion store. Keep the containing
directory private and stable. Foreign keys, full synchronous commits and a bounded
five-second lock timeout apply. Every worker handling these keys must use the same
host-local database; copied databases, network filesystems and stale snapshot
rollback are unsupported.

`store.lookup(app_id, subject, request_key_id)` retains the ordinary credential
lookup signature. `store.apple_key(app_id, subject, request_key_id)` returns the
linked immutable App Attest record. `store.verified_receipt(app_id, subject,
apple_key_id)` returns the stored verified snapshot or `None` for a missing or
cross-scope key. Snapshot freshness describes its recorded `verified_at`, not its
freshness at every later read. Raw receipts, client hashes, subjects and key bytes
are excluded from value representations. Do not log them or expose receipts to
clients. The `opaque_receipt` in the Apple key record remains the original raw
initial input; verified refreshes replace the separate verified-receipt record.

Request-key revocation through `store.revoke`/`revoke_subject` atomically revokes
linked Apple keys and cancels their pending assertions. Apple revocation through
`enrollment.assertions.revoke`/`revoke_subject` revokes linked request keys in the
same transaction. Account-wide `store.revoke_subject` also cancels in-flight
initial challenges; a completion already verifying CMS then fails its final
challenge check. Apple-only subject revocation affects its exact existing
app/Apple App ID/environment associations and their assertions; it preserves
unassociated initial challenges, whose generic format has no environment field.
Use the account-wide store method to cancel pending enrollment. Records
remain as non-reusable tombstones. A later fresh authorized issuance follows the
existing point-in-time revocation policy; this library does not ban accounts or
replace authentication/authorization.

For an explicitly configured fraud-assessment refresh:

```python
new_receipt = enrollment.refresh_receipt(
    subject=authenticated_subject, apple_key_id=apple_key.key_id,
    token_provider=operator_supplied_devicecheck_jwt_callback,
    timeout=5,
)
```

The method loads the latest verified snapshot, then releases SQLite before
revalidating it, invoking the explicit token callback and contacting the fixed
Apple environment host through `AppleReceiptRefreshClient`. It verifies the
replacement CMS as a fresh `RECEIPT` with the same app/key/environment and exact
initial client-data hash. A new transaction then rechecks both key types are
active, the full scope, old receipt hash, old receipt eligibility/expiry, strictly
newer creation time, and replacement freshness/expiry. Only that compare-and-swap
can replace the stored receipt. Concurrent refreshes from the same old hash have
one winner; a slower response cannot overwrite newer verified state. A refresh
cannot reactivate a revoked key or reset an assertion counter. There are no
network calls or JWT callbacks while the receipt replacement transaction is open.

HTTP success alone does not establish persisted refresh success. A provider can
issue a receipt and a local storage failure can still prevent its replacement;
the method reports failure and retains the old local snapshot. An error after a
successful SQLite commit (for example, a connection-close failure) is also
ambiguous to the caller. After an ambiguous completion/refresh result, read back
the linked credential/Apple key and verified receipt hash before retrying or
re-attesting. Do not reset counters, delete tombstones, or manufacture replacement
history to recover. Operators need an explicit recovery policy if the last locally
stored receipt can no longer be refreshed.

Errors use the existing fixed `EnrollmentError` codes, including
`PROOF_REJECTED`, `CHALLENGE_REJECTED`, `ATTESTATION_REQUIRED`,
`ATTESTATION_UNAVAILABLE`, `ATTESTATION_REJECTED`, `KEY_ID_IN_USE` and
`STORE_UNAVAILABLE`; provider/parser/database exceptions have no retained cause or
context. A verified assertion or receipt does not authorize a business operation.
Fraud-metric thresholds and actions remain explicit host policy.

Tests use independent synthetic attestation and CMS PKI, actual SQLite process
concurrency/restart, abrupt process death before commit and hot-journal recovery,
every insertion/deletion/commit failure, writer-lock expiry, synchronized
revocation, scoped readback, receipt CAS races and failed refresh rollback. Generic
enrollment regressions verify the protected-hook extraction preserves its existing
semantics. These are local software/storage tests, not genuine current-device,
live Apple-account/provider or physical power-loss certification.
