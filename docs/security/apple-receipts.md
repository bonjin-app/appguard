# Apple App Attest receipts

The optional Python `appguard.providers.apple_receipts` module independently
verifies receipt CMS and its signed identity, key, environment, binding, dates,
and risk count. Install `appguard-server[apple]` to include `asn1crypto`.
Initial App Attest verification and assertion verification do not implicitly
verify receipts. Receipt verification does not authorize application requests.

## Trust profile and provenance

The default trust anchor is the bundled `apple_receipt_root_g3.pem`, downloaded
from [Apple PKI](https://www.apple.com/certificateauthority/AppleRootCA-G3.cer)
on 2026-10-22 and checked against this DER SHA-256:

```text
63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179
```

The module checks this pin every time it loads the anchor. It never trusts a root
because it appears in the message, uses the system certificate store for CMS,
fetches certificates from an AIA URL, or accepts caller-provided trust roots.
The system trust store is used separately for HTTPS.

This is a **conservative profile of Apple's current public receipt sample**,
not a general Apple CMS validator. The sample comes from the current
[Attestation Object Validation Guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide).
Its complete CMS is embedded as a public test fixture with SHA-256:

```text
26a7ef09ab4cff17140e02780c57bec69672f4933d1a175ee84229b0107b6de0
```

The sample chains through Apple Application Integration CA 5 - G1 to Apple Root
CA - G3. Its leaf has the common name `Application Attestation Fraud Receipt
Signing`, Apple policy `1.2.840.113635.100.5.1`, and receipt marker
`1.2.840.113635.100.12.15` containing ASN.1 NULL. Its intermediate carries marker
`1.2.840.113635.100.6.2.3`, also NULL. These observed restrictions are required;
an unrelated Apple signing certificate is insufficient.

Apple's [fraud-risk guidance](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk)
links the App Attest root, while the current downloadable example uses the
separate G3 receipt chain. AppGuard keeps the receipt profile separate from
`AppleAppAttestVerifier` and its App Attestation root. It never silently expands
the initial attestation trust store to resolve this discrepancy. A provider
rotation or additional profile requires review and fresh compatibility evidence.

## Verification contract

`AppleReceiptVerifier` is configured with the trusted server's Apple App ID,
stored P-256 public key in DER SubjectPublicKeyInfo form, and explicit
`production` or `development` environment. It accepts the raw decoded CMS bytes:

```python
from appguard.providers.apple_receipts import AppleReceiptVerifier

# key is an authenticated server-side AppleAttestedKey, loaded from your store.
verifier = AppleReceiptVerifier(
    apple_app_id=key.apple_app_id,
    public_key_der=key.public_key_der,
    environment=key.environment,
)
receipt = verifier.verify(
    key.opaque_receipt,
    expected_client_hash=bytes.fromhex(key.initial_challenge_sha256),
    expected_type="ATTEST",
)
```

Perform fresh initial receipt verification within five minutes of its signed
creation. An expired receipt, future creation, wrong type, app, key, signed
environment, or exact field-4 binding is rejected. The caller must obtain
`expected_client_hash` from the server's verified initial attestation context;
extracting that expectation from the receipt would remove the binding check.
AppGuard does not guess whether field 4 should be raw, hex, Base64, or hashed.
The public example uses placeholder challenge bytes, so the generic verifier
accepts explicit binding bytes of 1–1024 bytes. AppGuard enrollment uses its
32-byte verified enrollment-message digest.

The sample's field 3 is a full attested X.509 certificate. AppGuard extracts its
P-256 public key and compares canonical DER SPKI with the configured stored key;
it also accepts a bare DER SPKI. This extraction does not validate or trust the
embedded attestation certificate's issuer and cannot replace initial attestation
verification. The receipt CMS authenticates the field itself.

`ATTEST` has no risk metric or refresh-not-before date. `RECEIPT` must contain a
nonnegative canonical decimal risk count, with creation ≤ not-before < expiry.
The count is returned for the operator's risk policy; it does not prove that a
device is uncompromised. There is no built-in allow/deny count threshold.

The parser limits decoded CMS to 256 KiB, ASN.1 depth to 24, tree nodes to 2048,
receipt attributes to 16, and individual field values to 16 KiB. It rejects
trailing bytes, duplicate fields/certificates/attributes/signers, unknown receipt
fields or extra fields in supported ASN.1 sequences, primitive indefinite lengths, unknown critical certificate extensions,
unsupported restriction extensions and nonminimal field integers. Constructed
BER indefinite lengths are supported because Apple's sample uses them. Receipt
payload SET ordering is unrestricted because that sample is not DER-sorted.
Signed attributes, when present, must be DER with one content-type and one
matching SHA-256 digest; an optional signing time is not a trust clock. The
sample has no signed attributes, so direct payload signatures are also verified.

Only SHA-256/ECDSA CMS with one signer and a two-certificate chain (optionally
including the exact pinned root) is supported. Certificate validity is checked
at the supplied server clock, never at an attacker-selected signing time.
Certificates require appropriate CA/leaf constraints and key usage, signature
verification, and the receipt purpose above. There is no online OCSP/CRL check.

Results are immutable `VerifiedAppleReceipt` values. Receipt bytes, public key,
client hash, Apple App ID and receipt digest are excluded from `repr`.
`AppleReceiptError` exposes fixed codes with neither a private exception cause
nor context. Applications must still avoid serializing result evidence or
logging callback tokens, HTTP bodies, or object internals.

## Refresh contract

```python
from appguard.providers.apple_receipts import AppleReceiptRefreshClient

client = AppleReceiptRefreshClient(
    verifier=verifier,
    token_provider=your_explicit_jwt_callback,
    timeout=5,
)
replacement = client.refresh(
    key.opaque_receipt,
    expected_client_hash=bytes.fromhex(key.initial_challenge_sha256),
)
# Persist only after an atomic compare-and-swap against the receipt read above,
# with the host's app/environment/subject/key and revocation checks.
```

The callback supplies the JWT for the `Authorization` header; the client does not
issue keys or discover credentials. Apple's guidance requires a key enabled for
DeviceCheck and describes APNs-style provider JWT generation. No private-key
signing helper is supplied here.

The old receipt is independently reverified with the same bindings and current
certificate/receipt validity before the callback is invoked. Only its
five-minute freshness rule is waived for refresh. The client refuses refresh
before the signed not-before date and after expiry. It POSTs only the Base64
receipt to `/v1/attestationData` on the fixed `data.appattest.apple.com` or
`data-development.appattest.apple.com` host. It uses verified system TLS,
no environment proxies, redirects, endpoint overrides, retries or discovery.
After the credential callback it revalidates the old receipt and certificate
lifetimes before constructing a network connection. A clock rollback during the
callback or provider exchange fails closed.

A bounded response must be HTTP 200 and canonical Base64. Its decoded receipt
must independently pass fresh `RECEIPT` verification with the same app, key,
environment and field-4 binding. Its creation time must strictly advance;
repeated/older receipts are rejected. Other status codes, including 304, return
a fixed refresh failure without exposing the response body. Schedule from the
verified dates and apply operator retry/backoff policy outside the client.

Socket timeouts and a transport watchdog bound TLS/request/header/body work,
including continuously arriving slow headers or bodies. The timeout range is
0.1–30 seconds. The operating system's synchronous DNS resolution and the
operator's token callback cannot be forcibly cancelled by this module; bound
those separately at the hosting-process/job boundary if a hard end-to-end
service deadline is required. No persistence happens inside this client.

## Evidence and remaining limits

The tests generate independent synthetic PKI/CMS for positive and adversarial
cases. A real owned local TLS listener verifies the fixed hostname, exact POST
body, authentication header, certificate validation and slow-response deadline.
The public Apple CMS verifies without injected trust at a clock inside its
historical lifetime; that sample is expired at today's clock. These establish
local software compatibility, not a current device-generated receipt or a
successful authenticated call to Apple's live service.

Live credentials, current genuine receipts, account/provider availability,
physical-device behavior, revocation service state and external security review
remain separate operator evidence. Preserve the newest verified receipt in a
subject/key-scoped durable store with atomic replacement and revocation checks;
a standalone successful refresh is not proof that persistence or race handling
has occurred.
