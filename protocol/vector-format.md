# Request conformance fixtures v0

`conformance/v0/requests.json` is a JSON array of scenario objects. All tokens, identifiers, timestamps and public keys are synthetic test data. There are no production credentials or private keys. Duplicate JSON keys, IDs, unknown or missing fields, invalid types, noncanonical base64 and invalid scenario modes MUST reject as fixture-format errors, never as passing verification results.

Each record contains exactly:

- `id`: unique nonempty string.
- `request`: `method`, `target`, `headers` (array of two-string pairs preserving duplicates), `body_b64` (canonical standard padded base64).
- `parameters`: `created`, `expires`, `nonce`, `key_id`, `algorithm`, `tag`, matching the reference signature-parameter names. Malformed parameter values can be represented to test runtime validation.
- `signature_b64`: canonical standard padded base64 of the supplied signature bytes (which may be an invalid-length signature in an attack case).
- `key`: `app_id`, `key_id`, `subject`, `public_key_pem` (ASCII string), `algorithm`, `revoked`.
- `context`: `origin`, `app_id`, `subject`, `now`.
- `replay_store`: `memory`, `unavailable`, or `full`; the latter two are deterministic fault injection for reference tests, not provider events.
- `expected_signature_base`: exact ASCII string without a trailing newline, or JSON null when syntax/profile validation prevents building a base. This field may contain a fake token; never put real token captures in fixtures.
- `expected_codes`: nonempty array of verification result/error codes. Repeated calls use the same scenario-local store. `['VERIFIED', 'REPLAY_DETECTED']` demonstrates replay rejection. State MUST reset between records.

The runner checks canonical bytes independently from the full verification result. An expired request can still have a canonical-byte expectation; time is checked by the full verifier. Mutations of request content normally retain the original signature so the verifier must detect substitution. A valid separate signer is used for cases that specifically test trust bindings or limits.

These fixtures define a **draft typed-input** contract. Passing them does not establish correct raw HTTP parsing, production framework integration, Apple/Google attestation, durable replay prevention or a security audit.
