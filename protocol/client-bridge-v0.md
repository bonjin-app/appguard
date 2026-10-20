# Native client bridge v0

Experimental bridge contract for future Unity, Expo/React Native and Flutter bindings. This document does not implement those packages. Native request preparation signs raw bytes once; bridges must not reconstruct signed data or handle private key material.

Operations:

- `publicKey(alias, hardwareRequirement)` gets or creates only that installation key; returns public SPKI PEM and an explicit storage class. Invalid existing entries reject instead of being replaced. Hardware requirements never silently downgrade.
- `prepare(alias, request)` receives configured HTTPS `origin`, uppercase `method`, exact ASCII origin-form `target`, canonical standard-base64 `bodyBase64`, `contentType`, full `authorization` Bearer field, `appId`, enrolled `keyId`, integer `created`/`expires`, canonical16-byte base64url `nonce`. Native SDKs may supply trusted-clock/CSPRNG defaults through their typed APIs; bridge encodings must remain explicit.
- Result: unchanged `method`, `target`, `bodyBase64`, `keyId`, ordered `headers` pairs including the six v0 fields. Send those exact bytes/field values to `origin + target`. Prevent automatic redirects or target rewriting in the actual HTTP integration; do not replay Authorization to another origin.
- Provider evidence acquisition remains a separate operation with explicit support/error state and a server-supplied challenge hash. It never returns `verified` or a server authorization decision.

Fixed errors must not contain authorization/body/private-key/native exception text. A JS/Dart/C# caller cannot export/import private keys, select arbitrary signing algorithms, or ask the protected key API to sign arbitrary unvalidated request bytes. Runtime key storage and transport constraints remain platform-specific and must be documented rather than emulated with a shared JS secret.
