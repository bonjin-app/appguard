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

`provider_verifier`, identifiers, authentication, routing, TLS and rate limits above are application-owned dependencies, not functions bundled by AppGuard. The callback must authenticate the actual provider evidence, enforce configured package/bundle/team/environment/key/challenge bindings and return the typed `AttestationVerdict`. This milestone does not implement Apple's certificate-chain/assertion verifier or Google's authenticated decode API client. With no verifier, Balanced/Strict cannot enroll attested credentials. Never create a verifier that returns `verified` from a client status or test fixture in production.

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

The policy's `rate_limited` field consumes an existing limiter's verdict; it does not install a limiter. Local root/debugger/hook hints can cause observation/step-up/denial but cannot create trusted identity or attestation. Policy support currently lives in Python with42 portable cases for future language ports. Java/Node SDK signatures remain independent and do not silently select these presets.

## Verification boundary

Local tests use real ephemeral P-256 keys, real SQLite files and concurrent independent connections. They exercise challenge substitutions, signature failure, replay, atomic one-use, expiry during a verifier callback, capacity, persistence, revocation, private files, unrelated-database preservation, existing request verification and malformed provider contracts. Provider callbacks in these tests are explicitly synthetic; no successful Apple/Google attestation is claimed. Deterministic policy cases and allowlisted audit-output tests require no AI model or paid service.
