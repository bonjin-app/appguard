# Native client bridge v0

Experimental bridge contract for Unity, Expo/React Native and Flutter bindings under development. Native request preparation signs raw bytes once; bridges must not reconstruct signed data or handle private key material. See each package's verification evidence before assuming runtime support.

Operations:

- `publicKey(alias, hardwareRequirement)` gets or creates only that installation key; returns public SPKI PEM and an explicit storage class. Invalid existing entries reject instead of being replaced. Hardware requirements never silently downgrade.
- `prepare(alias, request)` receives configured HTTPS `origin`, uppercase `method`, exact ASCII origin-form `target`, canonical standard-base64 `bodyBase64`, `contentType`, full `authorization` Bearer field, `appId`, enrolled `keyId`, integer `created`/`expires`, canonical16-byte base64url `nonce`. Native SDKs may supply trusted-clock/CSPRNG defaults through their typed APIs; bridge encodings must remain explicit.
- Result: unchanged `method`, `target`, `bodyBase64`, `keyId`, ordered `headers` pairs including the six v0 fields. Send those exact bytes/field values to `origin + target`. Prevent automatic redirects or target rewriting in the actual HTTP integration; do not replay Authorization to another origin.
- Provider evidence acquisition remains a separate operation with explicit support/error state and a server-supplied challenge hash. It never returns `verified` or a server authorization decision.

Fixed errors must not contain authorization/body/private-key/native exception text. A JS/Dart/C# caller cannot export/import private keys, select arbitrary signing algorithms, or ask the protected key API to sign arbitrary unvalidated request bytes. Runtime key storage and transport constraints remain platform-specific and must be documented rather than emulated with a shared JS secret.

## JSON boundary

All bindings call one native `invoke(operation, payloadJSON) -> responseJSON` operation. Supported operations are exactly `publicKey`, `prepare`, `enrollmentProof`. Payloads are objects with `alias` and `hardwareRequirement` (`any`, `hardware`, `strongbox`); Apple rejects `strongbox`, and `hardware` requires Secure Enclave. Unknown operations/fields, wrong types, malformed/noncanonical encodings, and oversized payloads reject. Limit JSON UTF-8 input to 1500000 bytes; raw body remains at most 1048576 bytes. Native wall-clock time is used to validate supplied timestamps. No bridge-supplied trusted clock or key material is accepted.

- `publicKey`: only the two common fields. Result `{publicKeyPem, backing}`; backing uses native SDK storage labels and never implies remote attestation.
- `prepare`: common fields plus `origin`, `method`, `target`, `bodyBase64`, `contentType`, `authorization`, `appId`, `keyId`, `created`, `expires`, `nonce`, all required. Result `{origin, method, target, bodyBase64, keyId, headers}`; headers are ordered arrays of two strings. Numbers are integers in the request-v0 range. Standard padded canonical base64 is required, including the empty string for an empty body.
- `enrollmentProof`: common fields plus `challenge` object (`appId`, `origin`, `subject`, `keyId`, `publicKeySha256`, `nonce`, `expires`) and separate `expectedAppId`, `expectedOrigin`, `expectedSubject`, `expectedKeyId`. Result `{proofBase64, clientDataHashBase64, googleRequestHash}`. These are possession proof/hash outputs only.

Every response is either `{ "ok": true, "result": { ... } }` or `{ "ok": false, "error": { "code": "..." } }`. Fixed codes: `APPGUARD_INVALID_INPUT`, `APPGUARD_KEY_UNAVAILABLE`, `APPGUARD_UNSUPPORTED`, `APPGUARD_OPERATION_FAILED`. Bindings may add `APPGUARD_NATIVE_UNAVAILABLE` when no native module exists. Unexpected native exception text must never cross the boundary. Private keys, arbitrary-message signing, attestation verdicts, automatic enrollment and network requests are absent from this API.
