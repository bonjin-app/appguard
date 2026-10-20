# Enrollment, key parsing and bridge hardening

Local experimental follow-up on2026-10-20, base5cca8d8. No account, device,
Keychain, remote CI, publication, deployment or global Codex configuration changes.
The three deferred defects from the previous milestone are now addressed.

| Boundary | Reproduction | Final executed verification |
| --- | --- | --- |
| Python enrollment |13 new failures proved clock/provider/validation/SQLite context retention and raw cleanup errors. One additional post-commit close regression failed against original source. |488 tests passed with owned disposable Redis,0 skips; installed noneditable wheel271 enrollment/provider tests passed; source equality checked |
| Go public-key envelope | malformed and unclosed first blocks returned VERIFIED and claimed a nonce using a later valid key |26 top-level+207 subtest pass records in each normal/race run; vet/build; external module verified9 archived Android/Apple public fixtures with replay/body/target/token rejection |
| Expo native-unavailable |22/23 tests passed; native envelope became generic OPERATION_FAILED |23/23 tests, TypeScript and relocated39-file pack passed; separately installed tarball matches built client bytes and preserves fixed unavailable for all3 public operations |

Python changes: `a28d9c6`; Go: `59d36c9`; Expo: `5f2baa5`. Native bridge source
and cryptography were not changed; this follow-up does not repeat or expand
previous native build/device evidence. Existing library/runtime locks are unchanged.

## Python error and transaction boundary

Fixed enrollment errors are raised after callback/validation exception handlers.
The store sanitizes at each public method boundary after transaction unwinding:
`contextlib` can reattach the exception injected into a generator's `yield`, so
moving a raise inside that generator alone was insufficient. Rollback failures do
not skip close, and expected SQLite cleanup errors become STORE_UNAVAILABLE.
Original fixed validation/semantic codes remain unchanged. The handled SDK dependency exception is absent from cause/context in these
tests. An application exception already active in a caller's `except` block can
still become ambient `__context__`; the SDK does not sanitize caller-owned
exception state. Serialize the fixed code, not arbitrary exception chains.
Caller logs, captured traceback locals and hostile code in the same process
remain outside this boundary.

Pre-commit proof/provider/clock rejection preserves the challenge and creates no
credential. Storage failures can have uncertain outcomes: the new real SQLite
fault-injection test commits a credential, closes the connection, then raises a
simulated close error. STORE_UNAVAILABLE is returned while the credential is
already persisted and its challenge consumed. Authenticate and read back the same
app/subject/key state before recovery; never overwrite a key or infer authorization
from either success or an error. This preserves atomic database state without
claiming a failed response proves rollback.

## Key and framework behavior

Go permits a single PUBLIC KEY envelope only. Its bounded guard prevents the
standard decoder from skipping a malformed first block in favor of another.
Existing SPKI/curve checks and trailing whitespace behavior remain unchanged.
Invalid envelopes claim zero nonces; the original valid request can then succeed
with the same store. LF/CRLF and trailing ASCII whitespace remain covered.

Expo recognizes the already documented APPGUARD_NATIVE_UNAVAILABLE code from a
native failure envelope. Additional native messages/details are discarded. Unknown,
malformed and thrown native responses still become fixed OPERATION_FAILED errors.
This is a JavaScript boundary test with a controlled native seam, not a newly
executed Expo engine, missing-React-context lifecycle or physical-device test.

## Package and evidence provenance

Final local wheel SHA-256: `7f2e3b4a941c2b5d9ce8f66f1b57ec8556c2b87efda8d63b8b747fe98728f288`.
Final local npm tarball SHA-256: `49fad74cfdfb2291652cb19ddc3c8985dd3feffc2be026d5373a4f5b72a16dc5`.
The wheel consumer uses isolated imports and separately installed dependencies;
its271 cases are a subset of488, not additional independent security assurances.
Go consumes local source through an external module; no Go publication is claimed.
The9 fixtures were generated in the previous stage with ephemeral software keys,
not newly acquired device/provider evidence.

Raw logs, source hashes, package consumers and RED/GREEN receipts are preserved in
the checksummed owned stage archive under `.superpowers/evidence/2026-10-20-hardening`.
They are local ignored evidence; a fresh checkout supplies its own toolchain.

## Whole-change review

One fresh read-only whole-change review found **0 Critical,0 Important,1 Minor**.
Independent checks passed48 enrollment tests, the Go PEM regression and16 Expo
client tests. Eight SQLite fault probes checked independent cleanup and post-commit
uncertainty;15 additional Go probes accepted2 valid inputs and rejected13 invalid
inputs before replay;18 additional Expo probes retained rejection/redaction.
No second review or production-code fix pass was required.

Minor (deferred): ambient caller-owned Python exception context can attach when
an SDK call is made inside an application `except` block. Dependency exceptions
handled by the SDK are removed in the normal call paths tested here. The
limitation is explicit in the integration guide; serialize fixed codes. Extending
this to arbitrary caller exception-state isolation is outside this change.

## Review rulings and residual costs

- Keep the public store wrapper after transaction unwinding: normal probes show
  contextlib cannot carry the original SQLite exception through that boundary.
  If wrong, structured reporters could expose dependency details.
- Keep independent rollback/close attempts. An underlying close that cannot
  complete can still leave resources unavailable; this is not a resource-recovery
  guarantee under arbitrary storage failure.
- Never interpret STORE_UNAVAILABLE as rollback. Post-commit outcomes require
  authenticated readback; ignoring this can cause ambiguous recovery.
- Keep proof/provider/clock checks before persistence. Rejection probes preserve
  pending challenges and create no credentials; actual provider authentication
  remains outside these synthetic checks. A regression could consume a challenge
  on failed validation.
- Keep the single decoded PUBLIC KEY marker gate plus existing parser/curve
  checks. Independent alternate-label/whitespace/BOM/ending probes reject before
  replay; a missed case could allow ambiguous trusted registry input.
- Preserve valid LF/CRLF/trailing-whitespace/no-final-newline input. No canonical
  PEM promise is added; a missed format case could break operator compatibility.
- Keep fresh fixed-code Expo errors and rejection for every failure envelope;
  additional native fields are discarded. A regression could leak native details
  or incorrectly grant a success result.
- Host callbacks, typed verdicts, paths and direct persistence methods remain
  trusted application primitives. Exposing them to untrusted objects can still
  cause raw host errors or incorrect bindings; this is not process isolation.
- Protected directories, local storage, clock and revocation freshness remain
  deployment responsibilities. Misconfiguration can undermine filesystem and
  multi-process guarantees.
- Treat this as local source/package evidence only. It establishes no real
  provider/device state, hosted CI, deployment or publication; assuming broader
  readiness would bypass those required validations.

No remote run/publication or production security certification follows from
these local checks.
