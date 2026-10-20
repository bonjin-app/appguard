# AppGuard request profile v0

Status: experimental draft `appguard-request-v0`. Normative words MUST/MUST NOT specify this restricted profile, not general RFC conformance. No wire parser or production SDK is shipped.

## Parsed interface and caller responsibilities

Input is an uppercase HTTP method, an unmodified ASCII origin-form request target, ordered header pairs retaining duplicates, raw body bytes, typed signature parameters, and a 64-byte signature. The caller MUST supply an authenticated subject and a trusted pre-enrolled key record. It MUST configure the externally visible HTTPS origin and MUST NOT derive it from arbitrary Host/Forwarded/X-Forwarded-* fields.

The reference constructs the one supported covered-component list. Parsing `Signature-Input` and `Signature` is outside its API. Future adapters MUST reject missing/extra parameters, changed component lists and unsupported tags before producing typed inputs; they MUST NOT discard unsupported wire metadata to make it fit this API.

Requests MUST use TLS. Method is an uppercase HTTP token of at most 32 characters. Origin is a lowercase HTTPS DNS origin, with an optional non-default port in 1..65535, and no path, credentials, query or fragment. Request target starts with one slash, uses RFC 3986 origin-form characters, and contains no fragment, backslash, whitespace, control character, malformed percent escape, or dot path segment. Reject percent-encoded controls/backslashes and dot segments after percent decoding for validation only. Preserve percent-escape case, duplicate query keys, query order and an explicit empty query; never sort, decode or re-encode the signed target. A normalized/lost original target or body cannot be verified by an adapter.

All header names MUST be HTTP token characters. All values MUST be printable ASCII without leading/trailing whitespace. The required singleton fields are `content-type`, `content-digest`, `authorization`, `appguard-app-id`; name comparison is case-insensitive. Repeated `content-encoding` is also rejected; if present its value MUST be `identity`. Empty content type is invalid. Authorization MUST match a nonempty RFC 6750-style `Bearer` token; the scheme is case-insensitive and the signed bytes retain their original case. Token validation is the caller's responsibility.

Limits checked before hashing/signature work: body 1 MiB; target 8 KiB; 64 header pairs; sum of ASCII header-name and header-value lengths 16 KiB. App, key and subject identifiers are 1..128 characters from `[A-Za-z0-9._:-]`. Origin length is at most 512 characters. Public key PEM length is at most 4096 bytes. Nonce is exactly 16 bytes encoded as canonical unpadded base64url (22 characters).

## Digest and signature base

Content-Digest MUST be the exact canonical field `sha-256=:BASE64:` with the standard padded base64 SHA-256 digest of raw body bytes, including zero bytes for an empty body. No JSON reserialization, decompression, alternative algorithms or dictionary members are accepted in this profile.

Use RFC 9421 component derivation. Each component is one line with LF separators and no trailing LF. No field trimming or whitespace normalization is needed because the restricted input rejects surrounding whitespace and controls.

```text
"@method": POST
"@target-uri": https://api.example.test/v1/items?b=2&a=1
"content-type": application/json
"content-digest": sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:
"authorization": Bearer TEST_ONLY_TOKEN
"appguard-app-id": test-app
"@signature-params": ("@method" "@target-uri" "content-type" "content-digest" "authorization" "appguard-app-id");created=1700000000;expires=1700000120;nonce="AAECAwQFBgcICQoLDA0ODw";keyid="test-key";alg="ecdsa-p256-sha256";tag="appguard-request-v0"
```

The example body is exactly `{}` (2 bytes). Signature parameters are serialized in the order shown. Tag and algorithm are fixed. `created` and `expires` are integer Unix seconds (booleans are invalid), within 0..999999999999999, and `created < expires`. Signature lifetime is at most 120 seconds; future creation is allowed by at most 30 seconds. Reject at `now >= expires`. The trusted `now` uses the same integer range; use it unchanged throughout a verification call.

Use `ecdsa-p256-sha256` only: P-256 ECDSA over the signature-base bytes with SHA-256. Wire signature is two 32-byte unsigned big-endian integers, `r || s`, as in RFC 9421 section 3.3.4. Cryptography's DER format is an implementation detail converted at its API boundary. Reject invalid lengths, other curves, malformed public keys and other algorithms. ECDSA signatures are not assumed to be deterministic. Do not index replay state by signature bytes, because equivalent ECDSA signatures can differ.

## Verification and state

Order: (1) syntax/profile/limits, (2) time, (3) trusted key binding, (4) content digest, (5) signature, (6) atomic replay claim. Reasons are the first failed check; they do not include request data.

The signed app ID, configured app ID and key record app ID MUST match. The authenticated subject and record subject MUST match. Parameter key ID and record key ID MUST match, algorithm MUST be the supported pinned algorithm, and revoked records MUST reject. A result carries app ID, key ID, expiry and code `VERIFIED`; it proves neither authorization nor platform attestation.

Replay storage exposes `claim((app_id, key_id, nonce), expires=expires, now=now) -> bool`. It MUST atomically accept a new claim only once until expiry, reject an existing unexpired claim, and raise on backend unavailability or exhausted capacity. Do not claim state before all preceding verification succeeds. The reference local store uses a lock, removes expired entries, and defaults to 10000 live entries. It is single-process, volatile and reference-only. No middleware, distributed consistency, durable store or restart protection is included.

| Code | Meaning |
| --- | --- |
| INVALID_REQUEST | Input type, syntax, identifier or resource limit rejected |
| UNSUPPORTED_PROFILE | Unsupported tag or algorithm |
| INVALID_TIME | Invalid integer timestamp, lifetime, skew or expiry |
| KEY_REJECTED | Untrusted binding, revoked/invalid key or wrong curve |
| DIGEST_MISMATCH | Canonical digest differs from supplied body |
| INVALID_SIGNATURE | Invalid signature encoding or cryptographic check |
| REPLAY_DETECTED | Prior live claim for this app/key/nonce |
| REPLAY_STORE_UNAVAILABLE | Store failure or capacity exhaustion |
| VERIFIED | Reference checks passed; caller still enforces authorization |

## Sources

- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html): components, signature parameters, ECDSA format, replay considerations.
- [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html): Content-Digest.
- [cryptography EC API](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ec/): supported P-256 verification and DER conversion boundary.
