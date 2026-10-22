# Experimental Apple attestation and assertion backend

`appguard.providers.apple.AppleAppAttestVerifier` is an optional callable backend for
the Python `EnrollmentService`. It authenticates an **initial App Attest object**
against the bundled, pinned Apple App Attestation Root CA. It performs no Apple
account, entitlement, Keychain, device, receipt-assessment or attestation network
operations. Importing the module does not access credentials or the network.
The opt-in [assertion lifecycle](apple-lifecycle.md) adds durable key association,
request-bound one-use challenges, revocation and monotonic assertion counters.

```python
from appguard.providers.apple import AppleAppAttestVerifier
from appguard.enrollment import EnrollmentService

backend = AppleAppAttestVerifier(
    app_id="my-app",                         # trusted AppGuard route identity
    apple_app_id="ABCDEFGHIJ.co.example.app", # provisioned App ID prefix + bundle ID
    platform="ios",                         # only supported deployment profile
    environment="production",               # explicit provisioned App Attest environment
    allowed_validation_categories={4},        # example: App Store, exact server policy
    allowed_bundle_versions={"42"},          # example CFBundleVersion, exact server policy
    verdict_ttl=120,                          # 1..300 seconds, capped at challenge expiry
    allow_legacy_without_acl=False,           # default; see compatibility policy below
)
service = EnrollmentService(store, profile="balanced", attestation_verifier=backend)
```

The Apple App ID prefix is not always the Team ID. Configure its provisioned value
from the Apple identifier. The expected App ID must be reserved for this configured
iOS deployment; do not share the accepted identity with unsupported platforms.
`platform="ios"` is trusted operator configuration, not an OS fact inferred from
a client label or from the opaque ACL blob. macOS and other platform configuration
values are rejected. The module does not implement macOS ACL/security policy.

## Evidence envelope and native integration

The callback takes `(Challenge, evidence: bytes)`. Evidence is a UTF-8 JSON object
of at most **65,536 bytes**, with exactly these two string fields:

```json
{"keyId":"CANONICAL_STANDARD_BASE64_KEY_ID","attestationObject":"CANONICAL_STANDARD_BASE64_CBOR"}
```

Both values use standard RFC 4648 base64 with required padding and no whitespace,
URL alphabet, alternate pad bits or alternate encodings. `keyId` decodes to exactly
32 bytes. Apple already returns the key ID in this base64 format; do not base64
encode its text a second time. JSON field order and whitespace do not matter.
Duplicate, missing and unknown fields, malformed UTF-8/JSON and non-string values
are rejected. Client `status`, `appID`, `environment` or `operation` labels cannot
create a verified verdict.

For the native Swift acquisition API:

1. Obtain the authenticated server's challenge and the exact
   [`enrollment-v0` message](../../protocol/enrollment-v0.md).
2. Set `challengeHash = SHA256(enrollment_message)` and pass those **32 bytes** as
   `AppAttestClient.attest(keyID:challengeHash:)`'s `challengeHash`.
3. Send `AppAttestEvidence.keyID` as `keyId`, and standard padded base64 of
   `AppAttestEvidence.opaqueObject` as `attestationObject` in the envelope above.
4. Separately supply the request-signing installation key's proof to enrollment.

The App Attest key and request-signing key are distinct. The certificate's P-256
key is matched to App Attest `keyId`; the enrollment message binds the other
request key's canonical SPKI SHA-256, app, authenticated subject, origin, key ID,
challenge nonce and expiry. This binding does **not** establish that the request
key is nonexportable or backed by secure hardware.

## Authenticated checks and bounds

The verifier enforces all of the following before returning a verdict:

- A leaf-first, non-repeating chain with 2..4 evidence certificates, ending only
  at the bundled anchor. Evidence cannot supply its own trusted root. The module
  uses no system TLS/OS trust roots for this decision and fetches no issuers.
- Actual certificate signatures and issuer names; validity at the server clock;
  CA/basic-constraints/path-length and key-usage rules; P-256/P-384 EC certificate
  keys and SHA-256/SHA-384 ECDSA certificate signatures; a P-256 credential key.
  Unsupported constraints and unknown critical extensions fail closed. Unrelated
  noncritical Apple metadata does not define an additional trust policy.
- Exact nonce extension OID `1.2.840.113635.100.8.2` DER structure and value
  `SHA256(authData || SHA256(exact_enrollment_message))`.
- `SHA256(configured_apple_app_id)` RP ID, configured environment's exact AAGUID,
  initial counter zero, AT present with no UP/UV/reserved flags, and ED consistent
  with the optional extension dictionary. Accepted flags are `0x40` and `0xC0`.
- A 32-byte credential ID matching decoded `keyId`, and `keyId` matching SHA-256
  of the leaf public key's X9.62 uncompressed point. The COSE key must be exactly
  EC2/ES256/P-256 with 32-byte X/Y coordinates matching that same leaf key.
- Exact signed authenticator extension names when ED is set:
  `apple_validation_category_01` is a 4-byte little-endian UInt32 byte string,
  and `apple_bundle_version_01` is a string. Both must match the configured
  allowlists. Supported category choices are 2 (TestFlight), 3 (development),
  4 (App Store), and 5 (enterprise/ad hoc). Unknown extensions/types reject.
  Configure both allowlists together. With an allowlist policy, missing ED rejects;
  without one, any ED dictionary rejects. Objects lacking ED can be accepted only
  when neither allowlist is configured.
- The conservative certificate ACL compatibility profile below.

CBOR is an intentionally small bounded profile: definite-length bytes/text,
integers, arrays and maps with integer/text keys; shortest integer/length
encodings; valid UTF-8; no tags, floats, booleans, nulls, duplicate keys or trailing
data. Map ordering is unrestricted because Apple does not promise deterministic
ordering. Limits are depth 8, 256 decoded items and 64 entries per collection;
each certificate is at most 8 KiB, `authData` at most 4 KiB and the opaque receipt
at most 32 KiB. Whole-input strict certificate DER parsing and exact nonce/ACL
DER wrappers reject nonminimal lengths and trailing/extra structures.

The returned `AttestationVerdict` expires at the earlier of the server's configured
TTL and challenge expiry. It binds provider, app, subject, request-key SPKI hash
and the exact enrollment-message hash. `EnrollmentService` independently verifies
proof, rechecks time after backend work, and atomically consumes the challenge;
failed verification leaves it unconsumed. Public errors are fixed
`APPLE_ATTESTATION_CONFIGURATION` or `APPLE_ATTESTATION_REJECTED`, with suppressed
exception chaining and no evidence/token material. Enrollment maps a backend
exception to its existing fixed `ATTESTATION_UNAVAILABLE` code.

`backend.verify_initial(challenge, evidence)` performs the same checks and returns
an immutable `VerifiedAppleAttestation`. It retains the verdict, canonical App
Attest key ID, canonical DER SPKI public key, configured Apple App ID/environment,
verification time, and verified signed category/version when present. Its
`opaque_receipt` bytes are bounded **unverified** CMS input. The object is a trusted
in-process handoff; never deserialize client JSON into it. Calling the existing
`backend(challenge, evidence)` still returns only `AttestationVerdict`. Neither
pure verification method consumes server state. Persistent initial association
and assertions require the separate lifecycle service explicitly.
For atomic request-key enrollment with verified receipt storage, use the opt-in
[AppleEnrollmentService](apple-enrollment.md). It leaves this callback contract
unchanged and uses a dedicated combined SQLite store.

## Pinned provenance and conservative iOS compatibility

The bundled public root was fetched on **2026-10-20**, only from Apple's official
HTTPS [App Attestation Root CA URL](https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem).
Its DER SHA-256 is
`1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932`;
the downloaded PEM SHA-256 is
`c778d09ac341f7fd9f8f3b19e2b815af6aed4ad4490e1e92c05cb355212a5013`.
Construction checks the DER pin; certificate validity/constraints are checked on
each verification. Anchor rotation requires an explicit reviewed package update.

The current official [iPhone validation example](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide)
contains noncritical OID `1.2.840.113635.100.8.6`. Its exact DER is a SEQUENCE,
explicit context `[3]`, single OCTET STRING. This verifier unwraps that structure
strictly and accepts **only** the exact 69-byte opaque ACL blob from that example:

```text
MEMMAjExMD0wCgwDb2tkoQMBAf8wCQwCb2GhAwEB/zALDARvc2duoQMBAf8wCwwEb2RlbKEDAQH/MAoMA29ja6EDAQH/
```

The blob SHA-256 is
`a71a166db83ac886fdf586337bb5588b9f23c145c04966672d080c5225236f2a`;
the whole extension DER SHA-256 is
`7db346a6a4c741cc72b464c716914c52f28290c382a7cc27b9064be22b0e8c48`.
This is a **compatibility pin**, not an interpretation of undocumented ACL
operations, an OS/hardware inference, or SIP/full-security proof. It differs from
the macOS full-security/SIP constant in Apple's guide. Other ACL blobs fail
closed, even with the legacy option enabled. By default, missing ACL also rejects;
`allow_legacy_without_acl=True` explicitly permits absence for legacy iOS objects.
There is no claim that this conservative profile supports every current/future
iOS certificate. Future legitimate profiles require source-grounded review and
an explicit implementation update.

## Verification evidence and remaining provider gates

Tests generate real synthetic root/intermediate/leaf certificates and P-256 keys,
then replace a **private trust-loader only in the tests**. The deployable public
constructor accepts no alternate trust anchor. The real production pin rejects
those synthetic chains. Tests cover signatures, constraints, nonce/context/key
bindings, environments, ACL and signed extension policies, malformed/duplicate/
nonminimal/oversized inputs, bounded random parser inputs and actual concurrent
Basic/Balanced enrollment with one-use/expiry enforcement.

A separate offline check verified the public documentation example's genuine
leaf/intermediate chain against the bundled root at a historical certificate-valid
timestamp. Its example certificate is expired at implementation time. That check
proves the sample chain parsing/signature and pinned ACL path only. The public example has flags `0x40` plus a trailing extension dictionary and therefore rejects at this verifier's ED/trailing-data guard; no successful whole-sample validation is claimed. It is not a successful full
enrollment, current provider-account connection or device-attestation test.

Synthetic tests also verify [persistent key association and assertion
verification](apple-lifecycle.md), including real independent SQLite processes,
restart, strict ECDSA/CBOR/DER, request/subject/environment isolation, monotonic
counters, revocation, final expiry checks and atomic rollback after storage faults.

**Pending:** genuine current-device acquisition and end-to-end verification;
live receipt/assessment provider validation; and deployment fraud-risk policy.
The separate [receipt verifier](apple-receipts.md) and [atomic enrollment service](apple-enrollment.md)
provide software verification and durable verified receipt replacement. Retained
receipts in this pure initial verifier remain bounded opaque input, not trusted
fraud metrics. A finite initial verdict is not continuous app integrity, jailbreak
detection or hardware-backed request-key proof. The assertion lifecycle is an
explicit independent guard and does not change existing enrollment callbacks or
automatically authorize application requests.

The verification rules follow Apple's current
[server verification guide](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
and [public validation example](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide),
refreshed on 2026-10-22. This experimental backend must not be presented as a
complete App Attest lifecycle or broad production/device certification.


## Parent review follow-up

One fresh whole-provider review found0 Critical,1 Important and0 Minor issues.
A malformed JSON evidence envelope left its complete contents in
`AppleAttestationError.__context__.doc`; throwing clock/trust-loader callbacks
also retained their original exception despite `from None`. Three behavioral
regressions failed before the fix. Both public error boundaries now raise only
after leaving the exception handler, so the fixed error has no cause or context.
All provider rejection helper assertions also require absent context. The full
Python suite passed474 tests with live disposable Redis and no skips after this
fix. This protects the documented structured-error boundary; it does not prevent
application code from logging its own inputs or callback exceptions separately.
