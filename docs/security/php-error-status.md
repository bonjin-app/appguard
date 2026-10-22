# PHP verification failure HTTP status normalization

2026-10-22; experimental Apache-2.0 PHP SDK. The fixed HTTP failure mapping
already exists in `protocol/http-v0.md`; this change enforces it for explicitly
constructed verification errors without changing the wire protocol.

## Defect and correction

The trusted evidence-capture callback can throw an SDK `VerificationError`.
`HttpAdapter` preserves that error, then returns its status and allowlisted reason
in an `HttpFailure`. Previously the error constructor accepted any integer status,
so `new VerificationError('INVALID_REQUEST', 200)` produced an HTTP-200 failure.
Redirect, informational and invalid HTTP status integers could also reach the
application's response mapping.

The constructor now derives the status from the normalized reason. It permits
only the documented 413 override for normalized `INVALID_REQUEST`, preserving
the SDK's three existing body/header-overflow paths. All other supplied integer
statuses fall back to the fixed 400/401/403/503 reason mapping. The signature,
readonly property types, fixed reason normalization and exception redaction
remain unchanged; arbitrary status overrides are intentionally no longer an
extension point. Application response policy and manually constructed response
objects remain outside this exception contract.

This corrects a trusted-callback integration failure, not an authentication or
authorization bypass. Failed capture already prevents trusted identity/key/clock,
replay and downstream execution. The change preserves that ordering and does not
trust client error codes or relax signature/transport requirements.

## Local verification scope

The regression suite exercises real `HttpAdapter` calls, all 12 allowed reasons,
default/success/413 overrides, extreme integer statuses, unknown-reason redaction,
generic exceptions, and actual header/body/stream overflow. Each failed capture
must return the exact fixed status/body without mutating the native request or
calling identity/key/clock/replay/downstream dependencies. A genuine signed
corpus request succeeds with the same store after these failures, and its next
duplicate is rejected by the real in-memory replay store.

Standalone execution can load an installed Composer autoloader with copied
public conformance fixtures, so the same scenarios can check a standalone package
without a source-tree class reference. Existing OpenSSL signature/scalar tests,
request/wire/policy corpora and five raw loopback requests remain in the full SDK
suite. Counts of assertions, adapter scenarios and HTTP requests are distinct
and overlapping, not a count of independent attack classes.

This is local PHP CLI/native adapter evidence. It does not establish tested
Laravel/Symfony, FPM/Apache, hosted ingress, multi-worker replay, Linux/Windows,
external security audit, remote CI or production deployment. No provider or
physical-device action is part of this stage; the separate device candidate and
its pending hardware verification remain unchanged.
