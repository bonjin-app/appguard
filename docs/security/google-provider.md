# Google Play Integrity provider

Experimental backend for Play Integrity **Standard** requests, integrated through the Python `EnrollmentService` trusted verifier callback. The optional Android acquisition module is `sdk/android-play-integrity`; existing SDKs do not automatically package it. Local tests use synthetic trusted HTTP/manager boundaries. No Google account, service account, real token, emulator, or device was used during this implementation.

## Deployment-owned configuration

Configure the trusted AppGuard app ID, exact Android package name and a nonempty allowlist of the Play-distributed signing certificate SHA256 digests. Digests use canonical unpadded base64url of 32 bytes. This is the signing certificate for the distributed app, including the applicable Play App Signing certificate, not automatically the upload certificate. During certificate rotation, explicitly allow the expected certificates. Every certificate reported by Google must be in this allowlist.

```python
from appguard.providers.google import GooglePlayIntegrityTransport, GooglePlayIntegrityVerifier

transport = GooglePlayIntegrityTransport(
    access_token_provider=deployment_fresh_playintegrity_access_token,
    timeout_seconds=5,
)
verify_google = GooglePlayIntegrityVerifier(
    app_id="configured-app",
    package_name="com.example.app",
    certificate_sha256_digests={configured_canonical_certificate_sha256},
    transport=transport,
    # Defaults shown explicitly for policy review:
    max_age_seconds=120,
    future_skew_seconds=5,
    verdict_ttl_seconds=300,
    required_device_labels={"MEETS_DEVICE_INTEGRITY"},
    require_licensed=True,
)
# EnrollmentService(store, profile="strict", attestation_verifier=verify_google)
```

`deployment_fresh_playintegrity_access_token` is an explicit trusted server callback that returns a fresh OAuth access token for `https://www.googleapis.com/auth/playintegrity`. Google documents a service account in the Cloud project linked to the app; the deployment must grant the necessary provider access. Credential storage, refreshing, scope selection, callback deadlines, and access policy are deployment responsibilities. The SDK never reads service-account files, discovers Application Default Credentials, searches environment credentials, or contacts Google at import/construction. Do not accept access tokens, callback functions, decoded response objects, or transport configuration from clients.

A separate deployment integration can explicitly load a Google service account with `google.oauth2.service_account.Credentials.from_service_account_info(server_secret, scopes=["https://www.googleapis.com/auth/playintegrity"])`, refresh it through a deployment-controlled authenticated/timeout-bounded transport, and return `credentials.token`. This optional deployment integration is outside the SDK and is not exercised by offline tests. The SDK itself has no `google-auth` dependency or default credential integration.

The explicit production transport sends authenticated `POST https://playintegrity.googleapis.com/v1/{configured_package}:decodeIntegrityToken` with `{"integrityToken": "opaque_token"}`. It uses verified system TLS trust and a fixed host with strict package path syntax; it does not follow redirects, use environment proxy discovery, retry requests, or call other endpoints. Socket operations have an explicit finite timeout (0.1–30 seconds); this is not an overall wall-clock deadline for credential refresh or the entire request. The response is bounded to 128 KiB, successful status 200 only, uncompressed, and valid strict JSON. Deployment request execution should impose its own overall deadline and rate limits.

## Evidence and decisions

Enrollment evidence is **only** the nonempty opaque token encoded as UTF8, at most 64 KiB, without control characters. Clients do not send decoded JSON as a shortcut. The backend submits the opaque text to the authenticated decode endpoint, then parses the raw response bytes. An injected transport is a trusted server boundary intended for controlled tests or an equally authenticated server integration; injecting a fixture transport does not prove Google verification.

The callback enforces:

- Configured app ID matches the issued challenge. `requestPackageName` and recognized app `packageName` both match the configured Android package.
- `requestHash` exactly equals canonical unpadded base64url(SHA256(`enrollment_message(challenge)`)). The enrollment domain-separated message includes authenticated subject, app, origin, signing SPKI hash, key ID, nonce and expiry. Another context cannot reuse its token response.
- `timestampMillis` is a canonical decimal string and is fresh after provider work, with the configured future skew. The default maximum age is 120 seconds; the exact stale boundary is rejected. The challenge must remain unexpired before and after decoding.
- Google `testingDetails.isTestingResponse` overrides are rejected; if a testing-details section is present, its flag must be exactly `false`.
- `appRecognitionVerdict` is `PLAY_RECOGNIZED`; signer digests are canonical and all allowlisted. Missing/unevaluated app, device, or account sections fail closed.
- All configured device labels are present; default is `MEETS_DEVICE_INTEGRITY`. Requiring `MEETS_STRONG_INTEGRITY` is an explicit policy choice and may require Play Console configuration. The code does not infer request-key hardware backing from a device label.
- Account licensing is `LICENSED` by default. `require_licensed=False` is an explicit deployment policy relaxation, not an outage fallback. Balanced/Strict still require successful authenticated verification.

Duplicate JSON keys at any depth, nonfinite values, trailing bytes, invalid UTF8, excessive nesting/count/size, malformed sections, unknown required policy labels, empty signer allowlists and invalid clock/configuration types are rejected. Only authenticated provider response data can drive a verdict.

A successful callback returns `AttestationVerdict(provider="google", status="verified", ...)` bound to the exact challenge app, subject, signing SPKI hash and message SHA256. Expiry is finite and no later than the challenge expiry, token freshness window, or configured verdict TTL. `EnrollmentService` separately validates the signing proof, rechecks its own clock after provider work, and atomically consumes the challenge once. Google Standard replay protections supplement this application-owned one-use challenge; they do not replace it.

## Errors and remaining proof

Public provider errors are fixed `GOOGLE_CONFIGURATION_INVALID`, `GOOGLE_PROVIDER_UNAVAILABLE`, and `GOOGLE_ATTESTATION_REJECTED`. The verifier deliberately collapses transport/credential/parse/policy failures into a fixed rejection; the enrollment service maps callback exceptions to its existing `ATTESTATION_UNAVAILABLE` response. No raw provider response, token, credential exception, cause or context is retained in these public exception objects. Do not log frame locals or application credential callbacks; logging/tracing integrations must redact those separately.

Offline tests exercise authenticated-request shape, bounded transport, redacted failure paths, policy/request/context rejection, and the real enrollment store's one-use path with generated request-signing keys. Android JVM tests exercise injected official Google manager/Task APIs; compile checks resolve the official artifact. None of this is genuine Google attestation proof. Pending external work includes Play/Cloud linking and account access, secret provisioning/refresh, release signing and Play distribution, genuine-device acquisition, real authenticated decode, provider quota/replay behavior, and app policy decisions. No physical-device, secure-hardware, store, release, account approval or production readiness claim follows from local tests.

Official references, checked 2026-10-20: [Standard request and server decoding](https://developer.android.com/google/play/integrity/standard), [request/app/device/license verdict fields](https://developer.android.com/google/play/integrity/verdicts), [official API REST discovery](https://playintegrity.googleapis.com/$discovery/rest?version=v1), [Android setup/version](https://developer.android.com/google/play/integrity/setup), and [official 1.6.0 artifact](https://dl.google.com/dl/android/maven2/com/google/android/play/integrity/1.6.0/integrity-1.6.0.pom).
