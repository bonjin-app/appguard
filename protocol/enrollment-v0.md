# AppGuard enrollment v0

Experimental server-side proof-of-possession enrollment. An HTTP API is deliberately application-owned: authenticate before issuing/completing a challenge, take the app ID from trusted route configuration and subject from authentication, and apply resource authorization/rate limits. Do not trust a submitted subject/app or expose this service as an anonymous key-registration endpoint.

1. The client creates an installation-specific P-256 key and exports only its public SubjectPublicKeyInfo PEM.
2. The server accepts app/subject/key ID/origin/public key through its authenticated enrollment flow and issues a CSPRNG 32-byte challenge, canonical unpadded base64url (43 characters), with a server-set expiry of at most300seconds. The database binds the entire challenge to that identity, origin and SHA-256 of canonical SPKI DER.
3. The client signs the exact ASCII message below with that installation key using P-256/SHA256; proof is raw64-byte r||s. If platform evidence is required, Apple clientDataHash is SHA256(message), Google Standard requestHash is canonical unpadded base64url(SHA256(message)). The platform evidence must also be verified against configured app identity and key binding on the server.
4. The server verifies proof, trusted provider verdict if required, rechecks its clock, then atomically consumes the challenge and inserts the credential. Any failed proof/provider check leaves it unconsumed. No existing app/key ID can be overwritten, even after revocation. Rotation uses a new key ID.

The exact message has LF separators, no trailing LF, and the fixed field order below. Identifiers and origin use request-v0 validation; the fingerprint is64 lowercase hex characters, expiry canonical decimal Unix seconds.

```text
appguard-enrollment-v0
app-id: test-app
origin: https://api.example.test
subject: test-user
key-id: test-key
public-key-sha256: HEX_SHA256_CANONICAL_SPKI_DER
challenge: CANONICAL_43_CHARACTER_BASE64URL
expires: 1700000120
```

Proof of possession proves control of a key, not app authenticity. Basic policy can explicitly accept an enrolled proof without attestation; Balanced and Strict require a server-verified attestation verdict. Missing, unsupported, rejected and unavailable provider evidence are distinct states. Arbitrary client JSON, a local risk signal, or successful request signing must never create `verified` attestation.

The experimental Python enrollment service accepts an injected **trusted server verifier**, not a client verdict. Its result binds provider (`apple`/`google`), app, authenticated subject, SPKI fingerprint, challenge SHA256 and a fresh expiry. The callback must actually authenticate/decode the provider evidence and enforce configured bundle/package/team/signing identity/environment and replay/counter policy. No Apple certificate-chain or Google decode service implementation is included in this local enrollment service. Without that configured backend, attestation-required enrollment fails closed. Tests use explicitly synthetic verifier boundaries and do not claim provider verification.

The dedicated SQLite store uses private local files, per-operation connections and immediate transactions for single-use/credential insertion. It supports concurrent processes on one local filesystem, not network filesystems or distributed replication. The server owns clock accuracy, file directory security, backup, capacity, authentication, transport, provider backend and revocation propagation. Read fresh records rather than caching revocation indefinitely.
