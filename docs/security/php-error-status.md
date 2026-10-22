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

The adapter also reconstructs a normalized base error at failure publication.
On PHP 8.4+ an ordinary subclass can initialize inherited readonly fields without
calling the parent constructor, so constructor checks alone cannot enforce this
boundary. Caught subclass reasons/statuses are revalidated; absent fields default
to `INVALID_REQUEST` and its 400 status instead of escaping as an uninitialized
property error. Unknown subclass reason text is never copied into the response.
Downstream application exceptions still propagate outside this failure mapping.

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

Four more scenarios cover ordinary subclass status/reason initialization and a
subclass with no initialized fields. The inherited-field fixtures use parent
construction on PHP 8.2/8.3, where the tested subclass initialization capability
is unavailable. Execution here covers PHP 8.5.11 only, including the actual
inherited-field bypass; it is not a fresh compatibility run on older PHP.

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

## Local verification and review correction (2026-10-22)

The final reviewed runtime is `18461e10c444465ae75c00fc7946ea401738e2f8` on local-main
base `514d0558c2fc3dbe24eb784626e7fa1878a979ba`. PHP 8.5.11 CLI ran with `-n`; no newly installed
toolchain or PHP 8.2/8.3 execution is claimed. Composer used task-private
home/cache directories, disabled network access, plugins and install scripts,
and the unchanged zero-external-package dependency lock.

The baseline passed 539 assertions and five raw loopback requests. Corrected
constructor regressions first produced 35 expected status failures and 22
passing controls. The initial constructor fix passed 57 scenarios, 596 total
assertions and five HTTP requests. Independent review then reproduced a real
ordinary-subclass gap on PHP 8.5.11, without Reflection or deserialization.
Four added scenarios reproduced three inherited-field bypasses and an escaped
uninitialized-property error against that intermediate runtime. All four
failed as expected, with the existing 57 controls passing.

The final response-boundary normalization fixed all four. Final source
verification passed 61 response scenarios, 600 total assertions and five raw
loopback requests. The assertion/scenario/request counts overlap and must not
be added as independent attack classes. The final Composer-installed consumer
passed the same 61 scenarios and seven raw HTTP requests with its own autoloader.
Earlier baseline consumer evidence retains35 status failures and four wrong
HTTP responses, with controls passing, before the original fix.

The final local archive SHA-256 is
`dc8e743814630cafa334b7d536a2838620b1cd2a601b5883eb67b95f221e4b2f`. All nine entries match final Git, actual
installed bytes and retained package snapshots. Reflection confirms actual
error/adapter/verifier classes load from the consumer's vendor directory.
Composer lock distribution reference and SHA-1 integrity values match the
local archive; SHA-256 is checked separately. The final archive/install uses
a separate directory/reference from the intermediate package to prevent stale
cache identity. The local `0.0.0-dev` version is test repository metadata, not
a published SDK release or tracked manifest change.

All intermediate packages and three setup/fixture errors are retained: an
unsupported task-only Composer version spelling, two initial positive controls
missing the HTTP signature envelope, and a consumer description missing for
strict manifest validation. Only environment or fixtures were corrected; product
code changed after the corrected RED. The independent subclass finding is a
product issue fixed before integration, and is distinct from these fixture errors.

Raw logs,final and intermediate archives, frozen consumer inputs, conformance
fixtures, package/lock hashes and independent review evidence are retained under
`.superpowers/evidence/2026-10-22-php-error-status/` in the main checkout.
The final record commit changes only this document, leaving reviewed SDK and
archive bytes unchanged.

The inherited-readonly version gate is also supported by the [official PHP property manual](https://www.php.net/manual/en/language.oop5.properties.php#language.oop5.properties.readonly-properties); this documentation check does not add an executed older-runtime claim.

Independent security review confirmed the P2 subclass publication finding is
resolved, with no unresolved findings in this bounded scope. Fresh final review
runs passed 600 source assertions plus five HTTP requests, strict Composer
validation, 61 installed response scenarios and seven installed HTTP requests.
The original independent subclass reproduction now returns 400 with fixed
`INVALID_REQUEST` and no dependency calls.

The reviewer also passed 31 independently written assertions: 24 phase-failure,
signed-retry and replay checks; four downstream exception identity/replay checks;
and three real signature-tamper, genuine retry and replay checks. Downstream
application exceptions still propagate by exact object identity; tampered input
does not consume a nonce. These are assertions with controls, not 31 distinct
attack classes. All nine final package entries, lock distribution integrity and
vendor autoload origins were checked independently. Intermediate findings, RED
and fixture failures remain retained rather than counted as final successes.

Independent review receipt SHA-256:
`d00bf5cd993aa8573ae2f1c354fad314d17fa4cb2da5482f20cdfdff54b8d8a2`.
No remote CI, deployment, framework/container, distributed replay, external audit
or physical-device verification is claimed by these local results.
