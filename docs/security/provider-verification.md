# Provider implementation verification

Historical initial provider-adapter evidence,2026-10-20.
For the subsequent assertion/receipt/OAuth/atomic enrollment implementation, see
[non-device qualification](../development/nondevice-readiness.md). Counts, gaps and
review findings below describe that original stage, not the current support matrix.

Experimental local provider adapters,2026-10-20. These are optional Python
EnrollmentService backends; other server languages still need their own trusted
provider integration. They do not replace user authentication or authorization.

| Component | Executed evidence | External boundary |
| --- | --- | --- |
| [Google Standard](google-provider.md) |97 Python tests, strict authenticated fixed-host HTTPS request shape through injected transport; actual EnrollmentService binding/one-use tests | no genuine token, authenticated Google decode, credentials/refresh, Play distribution or quota proof |
| [Android Play Integrity acquisition](../../sdk/android-play-integrity/README.md) | official Integrity1.6.0;8 debug+8 release host tests; release AAR built | opaque token acquisition only, injected manager/Task tests; no device/account run |
| [Apple initial attestation](apple-provider.md) |126 Python tests after review fix, real generated PKI/P-256 and strict CBOR/DER; official pinned root; actual enrollment concurrency/expiry/binding | no current-device full attestation or assertion/receipt/counter lifecycle; iOS-only conservative ACL compatibility pin |

Full Python suite after integration:474 passed with live owned disposable Redis,
0 skips. The223 provider tests also passed from a separately installed noneditable wheel with isolated imports; the bundled PEM matched source byte-for-byte. Provider tests use generated synthetic PKI and trusted transport seams;
they do not claim provider approval. A separate offline Apple sample check proves
its historical certificate chain/ACL only. Its `0x40` flags plus trailing
extensions reject at the full-object ED/trailing-data guard. Preserve that
limitation; the public sample was not accepted end to end.

## One fresh review

The read-only whole-provider review found0 Critical,1 Important,0 Minor issues.
No trust or challenge-binding bypass was established. Important: Apple fixed
errors raised inside `except ... from None` retained raw evidence in
`__context__.doc` and original callback exceptions. Three regressions failed
before the change; fixed errors now raise outside the handler with no cause or
context. Full474 tests passed after the fix, including every rejection helper's
context-absence assertions. There was no second review.

## Rulings and remaining costs

- Apple ACL bytes are a conservative exact compatibility pin, not a documented
  OS/hardware/SIP interpretation. Unknown profiles and macOS reject. Explicit
  legacy ACL absence is a deployment choice, never an automatic fallback.
- Strict signed extension and challenge/key/app/environment checks remain enabled.
  Apple request-signing and App Attest keys are distinct; no hardware backing of
  the request key follows from an attestation verdict.
- Google licensing/device-label relaxations require explicit operator policy.
  Client-decoded JSON is never an authenticated provider response. Injected test
  transports are trusted seams, not proof of Google access.
- Credential acquisition/refresh, Apple lifecycle/receipt/assertion persistence,
  genuine device tests and production identity configuration remain required
  deployment work. Offline verification cannot establish them.
- Fixed SDK errors do not prevent an application from independently logging raw
  inputs. The previously documented Minor EnrollmentService exception-context
  diagnostic limitation remains separate; serialize only its fixed code.

See per-provider documents for exact evidence encodings, bounds, trust-anchor
provenance and configuration examples. Logs, review rulings and regression
receipts remain in the checksummed local provider-stage archive. No accounts,
secrets, provider projects, entitlements or releases were configured.

Final Python wheel SHA-256: `90915ee14a235d6f86e76ca86a1e4a659258202eef84bc3d6c2cf2ee11089e52`. Locally built and unpublished.


Follow-up: the previously deferred enrollment exception-context, Go PEM-envelope and Expo error-classification defects are resolved in [boundary hardening](hardening-verification.md). Original stage counts and review findings above remain historical evidence.
