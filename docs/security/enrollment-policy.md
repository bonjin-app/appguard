# Local enrollment, policy and audit integration

These experimental Python modules complement the server signature SDK; they do not automatically expose routes, authenticate users or configure platform providers.

## Key lifecycle

Use a dedicated database in a trusted directory owned by the server user. `SqliteEnrollmentStore(path)` creates a private0600 local file, rejects symlinks, public permissions and unrelated databases, and never deletes existing application tables. Back up and protect this directory. SQLite transactions coordinate connections/processes on one local host; this is not a distributed enrollment backend.

```python
from appguard.enrollment import EnrollmentService, SqliteEnrollmentStore

store = SqliteEnrollmentStore("/private/appguard/enrollment.sqlite")
service = EnrollmentService(store, profile="balanced", attestation_verifier=provider_verifier)
challenge = service.issue(
    app_id=configured_app_id,
    subject=authenticated_subject,
    key_id=server_assigned_key_id,
    origin=configured_https_origin,
    public_key_pem=submitted_public_key_pem,
)
# Send the bound challenge to the client; receive its installation-key proof.
credential = service.complete(
    challenge_nonce, app_id=configured_app_id, subject=authenticated_subject,
    proof=decoded_64_byte_proof, evidence=opaque_provider_evidence,
)
```

`provider_verifier`, identifiers, authentication, routing, TLS and rate limits above are application-owned dependencies, not functions bundled by AppGuard. The callback must authenticate the actual provider evidence, enforce configured package/bundle/team/environment/key/challenge bindings and return the typed `AttestationVerdict`. Optional experimental [Apple initial-attestation](apple-provider.md) and [Google Standard](google-provider.md) modules can supply that callback; current-device/provider access and Apple's full assertion/receipt lifecycle remain unverified. With no verifier, Balanced/Strict cannot enroll attested credentials. Never create a verifier that returns `verified` from a client status or test fixture in production.

For explicit local proof-only development use `profile="basic"` without evidence. Its record is `attestation="missing"`; possessing an enrolled key is not platform attestation. Failed proof/backend checks do not consume challenges. Challenges expire after120seconds by default (at most300); final completion rechecks the clock after provider work. A successful challenge is consumed atomically with insertion, and an existing app/key ID cannot be replaced, including after revocation. Rotate by issuing a new server-assigned key ID, enroll it, then revoke the old key through your authorized account flow.

`store.lookup(app_id, authenticated_subject, key_id)` returns a `Credential` or `None`. Supply its `key` to the existing server SDK's trusted identity resolver. That `KeyRecord` contains the revocation flag checked by request verification. `store.revoke(app_id, authenticated_subject, key_id)` updates only the matching credential. Avoid unbounded enrollment/key caches that hide revocation. Origin is bound into the enrollment challenge; request verification separately pins the configured origin.

## Policy after authentication and verification

```python
from appguard.policy import PolicyContext, evaluate_policy
from appguard.audit import JsonAuditSink

context = PolicyContext(
    authentication="authenticated",  # from your token authenticator
    verification="verified",         # from the actual SDK result
    attestation=credential.attestation,
    attestation_expires=credential.attestation_expires,
    risk_signals=validated_bounded_hint_codes,
    rate_limited=existing_limiter_result,
)
decision = evaluate_policy("balanced", context, now=trusted_unix_seconds)
audit.emit(decision, event_id=opaque_event_id, app_id=configured_app_id,
           now=trusted_unix_seconds, context=context)
if decision.action in {"allow", "observe"}:
    # Still perform application resource authorization before data access.
    pass
else:
    # Deny, or finish an additional trusted verification flow for step_up.
    pass
```

`audit` is an explicitly configured `JsonAuditSink(callback)` whose lifecycle/retention the application owns. The example's trusted state must not be populated from submitted JSON/header labels. Default `PolicyContext()` has missing authentication and verification, so it cannot permit a request. Only explicit Basic signature opt-out supports an existing authenticated server without a Client SDK; it still requires actual authentication and resource authorization.

The policy's `rate_limited` field consumes an existing limiter's verdict; it does not install a limiter. Local root/debugger/hook hints can cause observation/step-up/denial but cannot create trusted identity or attestation. All six server SDKs now pass the same42 portable policy cases. Their explicit APIs remain independent of signature middleware and do not silently select these presets.

## Verification boundary

Local tests use real ephemeral P-256 keys, real SQLite files and concurrent independent connections. They exercise challenge substitutions, signature failure, replay, atomic one-use, expiry during a verifier callback, capacity, persistence, revocation, private files, unrelated-database preservation, existing request verification and malformed provider contracts. Provider callbacks in these tests are explicitly synthetic; no successful Apple/Google attestation is claimed. Deterministic policy cases and allowlisted audit-output tests require no AI model or paid service.


## Redaction and uncertain storage outcomes

In a normal call, enrollment fixed errors discard cause/context references to
the clock, provider, validation and SQLite dependency failure handled by the SDK. Cleanup failures return `STORE_UNAVAILABLE`;
rollback and close are attempted independently so a rollback exception does not
skip connection closure. This protects the public exception-chain boundary,
not arbitrary application logs, traceback-local capture or a compromised process.
Python can attach an application-owned exception that is already being handled
when the caller invokes the SDK inside an `except` block. This ambient caller
context is not sanitized; structured reporters must serialize the fixed code
rather than traverse arbitrary exception chains.

A storage error is not proof of rollback. In particular, a successful commit can
be followed by a failing close or a lost response. Authenticate the caller and
read back the same app/subject/key credential and pending challenge state before
choosing a recovery flow. Never overwrite an existing key or treat an error as
permission. The local tests exercise both pre-commit rollback and post-commit
failure with an already persisted credential; see [hardening evidence](hardening-verification.md).
