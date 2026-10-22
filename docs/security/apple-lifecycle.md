# App Attest initial association and assertion state

This optional Python API adds software-verifiable assertion handling to the
[initial verifier](apple-provider.md). It performs no Apple, account or credential
network operations. Synthetic PKI/signatures and local SQLite processes establish
implementation behavior; genuine native acquisition/provider acceptance remains
unverified. For request-key enrollment, use the explicit [combined enrollment
service](apple-enrollment.md): it verifies the initial receipt and commits request
key, Apple key, verified receipt and challenge consumption atomically. The
standalone API below remains available for independently managed associations.

```python
from appguard.providers.apple import AppleAppAttestVerifier
from appguard.providers.apple_lifecycle import (
    AppleAppAttestLifecycle, SqliteAppleAppAttestStore, assertion_client_data,
)

backend = AppleAppAttestVerifier(
    app_id="my-app", apple_app_id="ABCDEFGHIJ.co.example.app",
    platform="ios", environment="production",
    allowed_validation_categories={4}, allowed_bundle_versions={"42"},
)
state = SqliteAppleAppAttestStore("/private/appguard/apple.sqlite")
apple = AppleAppAttestLifecycle(
    verifier=backend, store=state, challenge_ttl=60, max_pending=10000,
)

# initial_challenge must come from authenticated server state, not request JSON.
# Complete EnrollmentService's existing proof/consumption flow independently.
key = apple.register(initial_challenge, initial_evidence_json)

# Derive operation from the trusted request boundary, including all security-
# relevant method, origin/raw target, body digest and business context fields.
operation = b"POST\nhttps://api.example.test/premium?\nbody-sha256:..."
challenge = apple.issue(subject=authenticated_subject, key_id=key.key_id, request=operation)
client_data = assertion_client_data(challenge)
# Send these exact client_data bytes to the native client over authenticated TLS.
# Native: generateAssertion(keyID, clientDataHash: SHA256(client_data)).

result = apple.verify(
    received_nonce, subject=authenticated_subject, key_id=received_apple_key_id,
    request=operation, assertion=received_raw_assertion_cbor,
)
# Continue normal authentication/authorization/business checks before serving data.
```

`AppleAppAttestLifecycle.register` verifies the initial object itself, then
atomically stores its attested P-256 public key, Apple and AppGuard identities,
authenticated subject, environment, verified signed category/version, initial
message hash, timestamp, opaque receipt, initial counter zero and revocation flag.
A key ID has one permanent association in the database, across all app/subject/
environment scopes. A verified initial enrollment-message hash can register only
one attested key. Existing or revoked IDs cannot be re-registered to reset state.
Multiple distinct device keys per user are supported; a legitimate new key does
not invalidate that user's prior keys. There is no privacy-sensitive permanent
hardware identifier or claim that key ID identifies physical hardware.

The standalone service does not issue or consume `EnrollmentService` challenges
or verify the separate request-signing key's enrollment proof. The [combined
service](apple-enrollment.md) closes that integration boundary in one private
SQLite transaction, without changing this API or generic enrollment callers.
Do not accept a client-created `Challenge` or metadata object as authoritative.
`verify_initial` remains useful as a pure metadata handoff and the original
`__call__` contract remains unchanged.

`issue` returns an immutable `AppleAssertionChallenge` with 32 random nonce bytes,
all five identity fields, the operation's SHA-256, issue time and expiry. Subject is
always the authenticated principal. `verify` loads that stored value by nonce,
reconstructs its exact [versioned client message](../../protocol/apple-assertion-v0.md),
and checks the host's actual operation bytes. Supplying the original client
operation bytes in place of the received request would defeat request binding.
The operation is bounded to 1..1,048,576 bytes and must include every field whose
substitution changes authorization or business meaning. This library intentionally
does not guess a canonical representation for arbitrary application requests.

Raw assertion CBOR is limited to 8 KiB and must contain exactly `signature` and
`authenticatorData`. Authenticator data is 37..4,096 bytes: configured RP ID hash,
flags `0x00`/`0x80`, a big-endian counter, and an optional signed CBOR dictionary.
AT, UP, UV, reserved flags, duplicate/nonminimal CBOR, unknown fields, trailing
bytes and malformed/oversized DER signatures reject. ECDSA uses P-256/SHA-256 with
`nonce = SHA256(authenticatorData || SHA256(client_data))` as the **prehashed**
digest, avoiding an extra SHA-256. Both valid high-S and low-S signatures work.

The signed extension names, category byte order and allowlists are identical to
the initial verifier. A configured category/version policy requires ED and both
`apple_validation_category_01` (little-endian four-byte UInt32) and
`apple_bundle_version_01` (string). Unknown/missing properties reject. No policy
accepts only the explicit legacy shape without ED. A previously registered key
with signed properties cannot downgrade to an extension-free assertion when a
host reconstructs its verifier with a legacy policy. Accepted updated bundle
versions are controlled by the host's current allowlist, not frozen to the initial
app version. The original iOS root/ACL conservatism is unchanged.

After signature verification, one SQLite `BEGIN IMMEDIATE` transaction re-reads
the key, challenge, scope, revocation and counter, and checks the clock **after**
obtaining the writer lock. Only a strictly increasing counter can update the key
and consume the exact challenge. Both changes commit together. Invalid proofs,
wrong requests, expiry, stale counters and transaction failures leave the counter
unchanged. A failed valid-looking assertion does not consume another pending
challenge. Concurrent requests may arrive out of order; an older counter then
fails and the client needs a fresh assertion. Counter exhaustion requires a new
attested key, never wraparound/reset. Consuming an assertion is not an atomic
commit of the application's business transaction; hosts must handle retries and
idempotency at that boundary.

`lookup(subject=..., key_id=...)` returns an immutable record or `None` for a
missing/cross-scope association. `revoke` marks one key and cancels its challenges;
`revoke_subject(subject=...)` does this for every key in this exact app/Apple App
ID/environment/subject scope and returns the number newly revoked. Revoked records
are retained so keys cannot be reused. Revocation racing signature verification
is rechecked inside the final transaction. Both records and counter/challenge
updates survive closing and reopening the same database and independent process
restarts.

Use one dedicated private database for all processes that handle these keys.
Construction creates a mode-0600 file, rejects unrelated schemas, symlinks,
hardlinks, insecure ownership/permissions and nonregular files. Operations reject
removed/replaced files and never recreate a missing database. Keep the parent
directory trusted, private, stable and protected against replacement. SQLite
uses foreign keys, full synchronous commits, a bounded five-second lock timeout
and a global pending-challenge cap; expired challenges are pruned on issue. This
is a host-local store, not a distributed database or a network-filesystem design.
The implementation does not protect against rollback of the entire trusted
filesystem or stale backups. A rollback/restore must trigger operator revocation
and re-attestation; independent copied databases defeat monotonic counters.
Hardware power-loss durability and arbitrary deployment/storage behavior are
unverified. Apply authentication, admission/rate limits, backup/access/retention
policy and safe expiry-clock operation in the host.

Public lifecycle errors have fixed `AppleLifecycleError.code` values:
`APPLE_LIFECYCLE_CONFIGURATION`, `APPLE_ASSERTION_REJECTED`,
`APPLE_STATE_REJECTED`, `APPLE_STORE_UNAVAILABLE`. They preserve no exception cause
or context containing parser data, database details or callback failures. Subject,
nonce, receipt and public-key bytes are omitted from value representations. This
does not configure the host's own logs, tracebacks with local-variable capture or
telemetry. Never log request evidence/receipts or credential material.

Apple's [server verification guide](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
and [WWDC26 assertion guidance](https://developer.apple.com/videos/play/wwdc2026/201/)
were refreshed on 2026-10-22. The WWDC26 guidance says assertion extensions follow
the same profile as initial attestation. Apple's
[fraud-risk guide](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk)
says to verify receipts separately. Its current sample CMS receipt chains through
Apple Application Integration CA 5 - G1 to Apple Root CA - G3, while the text links
the App Attest root. This requires an explicit, independently reviewed receipt
trust profile; widening the initial-attestation trust anchor is not an acceptable
fallback. The [receipt verifier](apple-receipts.md) implements that separate
conservative profile. `opaque_receipt` remains unverified in the standalone
initial/assertion APIs. The combined enrollment service independently verifies it
before activation and supports verified receipt CAS refresh. The standalone
assertion modules themselves send no refresh request.
