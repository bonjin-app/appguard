# HTTP envelope and server SDK contract v0

Status: experimental server integration of [request-v0](request-v0.md). This profile is a strict canonical subset of RFC 9421, not a general Structured Fields implementation. SDK installation does not authenticate users or enroll trustworthy keys.

## Wire grammar

The label is exactly `appguard`. Exactly one `Signature-Input` and one `Signature` field are required; names compare case-insensitively. Field values have no surrounding whitespace. The inner list and parameter order are exact:

```text
Signature-Input: appguard=("@method" "@target-uri" "content-type" "content-digest" "authorization" "appguard-app-id");created=1700000000;expires=1700000120;nonce="AAECAwQFBgcICQoLDA0ODw";keyid="test-key";alg="ecdsa-p256-sha256";tag="appguard-request-v0"
Signature: appguard=:STANDARD_PADDED_BASE64_OF_64_SIGNATURE_BYTES:
```

Timestamp lexical form is `0` or an optionally negative nonzero decimal integer, with at most 15 digits excluding a minus sign; no plus sign, leading zero, boolean, decimal point, exponent or negative zero. A parsed negative integer still fails the core time rules. nonce and keyid use request-v0's constrained syntax. Algorithm/tag values are 1..64 characters from `[A-Za-z0-9._:-]`; unsupported values yield `UNSUPPORTED_PROFILE`. No escaping, additional components, parameters, labels, comma-joined values or additional dictionary members are accepted. The parser returns typed parameters plus signature bytes; successfully parsing metadata alone never verifies a request.

Signature bytes use strict standard base64, canonical padding/pad bits, and decoded length exactly 64. Invalid syntax, encoding, missing/extra metadata and altered coverage return `INVALID_REQUEST` at the wire layer. Core verification reasons remain unchanged for syntactically valid envelopes.

## Header evidence and framing

SDK adapters MUST retain duplicate-preserving header pairs before extracting fields. At most 64 pairs and 16 KiB total header-name/value ASCII bytes are permitted, including signature fields and all unrelated headers. Header names are HTTP tokens; values are printable ASCII with no surrounding whitespace. No duplicate of `signature-input`, `signature`, `authorization`, `content-type`, `content-digest`, `appguard-app-id`, `content-encoding`, `content-length`, `transfer-encoding` or `host` is permitted.

If supplied, Content-Length is canonical nonnegative decimal and MUST equal the captured content-byte count. Transfer-Encoding and Content-Length together reject. Only `chunked` is accepted as a Transfer-Encoding value, with framing removed by the trusted HTTP server before SDK capture. Only identity Content-Encoding is accepted. HTTP servers remain responsible for rejecting malformed framing before the SDK; an adapter cannot reconstruct evidence its server discarded.

Capture the unmodified ASCII origin-form target with the exact query order/encoding, including an explicit empty query. Never reconstruct from decoded framework paths or untrusted forwarding headers. Capture body bytes before decompression, JSON parsing or form parsing; stop at 1 MiB plus one byte and reject overflow. Replay the captured bytes to downstream handlers only after verification succeeds. An aborted/incomplete stream, absent original-target evidence or unavailable raw bytes fails closed.

## Identity and transport integration

Every installed adapter protects all HTTP requests that reach it. Install it on the intended application/router; path exclusions are application policy, not an SDK default. HTTP origin is trusted server configuration. Require a secure transport indication by default and ignore Forwarded/X-Forwarded-* for this decision. Explicit insecure opt-in is reserved for controlled local testing or externally enforced TLS termination; that trust boundary must be configured by the operator.

Require app ID, external HTTPS origin, a caller-provided replay store and trusted identity/key resolution. The application's existing authentication layer validates the Bearer token. Its resolver returns authenticated subject and trusted KeyRecord, or a separate subject/key callback with equivalent binding; a client-provided subject is never sufficient. Resolver failures reject without exception text or raw input in responses. Key registration, revocation distribution and platform attestation are external.

Time must be read from the trusted clock at verification after authentication completes. A `VERIFIED` result permits downstream processing only; the application must still enforce resource authorization. Store verification metadata in a dedicated request attribute/state rather than overwriting its authenticated identity.

Python integrations retain ASGI headers/raw_path before framework processing. ASGI cannot distinguish an absent query from an explicit empty query. With a nonempty query the SDK can combine the raw path and raw query losslessly; with an empty `query_string`, the Python adapter requires trusted complete-target bytes in `scope["appguard.raw_target"]` or a synchronous `raw_target_resolver(scope)` callback, and otherwise fails closed. A complete-target capture must agree with the observable path/query; it must not come from an untrusted header. Flask is wrapped through WsgiToAsgi *after* verification; a plain normalized WSGI environ is insufficient to establish duplicate evidence. Node integrations capture original URL/rawHeaders before body parsing or route rewriting. Java uses original servlet request URI/query and all enumerated field values; container-level normalization/rejection remains part of deployment behavior.

## HTTP failure mapping

- 400 `INVALID_REQUEST`: malformed/ambiguous metadata or unavailable raw evidence.
- 413 `INVALID_REQUEST`: content exceeds 1 MiB.
- 401 `AUTHENTICATION_REQUIRED`: no authenticated identity; no automatic token acceptance.
- 403: unsupported profile, invalid time, rejected key, digest/signature failure or replay, using the original core code.
- 503 `IDENTITY_UNAVAILABLE`, `KEY_RESOLVER_UNAVAILABLE`, `VERIFICATION_UNAVAILABLE`, or `REPLAY_STORE_UNAVAILABLE`: dependency or contract failure. Exact exception details never enter a response.

An expected unknown-key lookup (null/missing result) returns 403 `KEY_REJECTED`; it is not a backend outage. A thrown resolver exception or malformed non-null resolver contract returns 503. A combined Python Identity with `key=None` represents an expected unknown key.

Error JSON is `{"code":"FIXED_REASON"}`. Do not include tokens, request bodies, PEM values, signature bases or backend details. Do not call downstream handlers or claim nonces on pre-verification failures.

## Redis replay interoperability

For scope `[app_id,key_id,nonce]`, serialize a JSON array with no spaces, UTF-8 (all values are restricted ASCII), hash it with SHA-256, and use lowercase hexadecimal:

```text
appguard:v0:replay:<sha256(compact_json_scope)>
```

Atomically issue `SET key 1 NX EX ttl`, where `ttl = expires - now` is an integer in 1..150 seconds. Relative expiry avoids requiring Redis and application epoch clocks to be identical and conservatively retains state through the signature's remaining lifetime. The key is identical across languages and instances. Return true only for a successful new claim; a nil/conflict result returns false. Errors, unexpected return types and invalid scope/deadlines fail closed. Never use separate SETNX and EXPIRE operations or accept a claim before verification.

Use a long-lived client and store. Operators must prevent eviction of live security keys, provision capacity, secure Redis connections and configure persistence/replication according to their restart/failure requirements. SDKs do not establish those deployment guarantees. Volatile local stores remain explicitly test/development-only.
