# Node policy own-field validation

2026-10-21, independent repair from local main
`cacfeae3302dcbee391ed8524a7e0e730e3da333`; experimental SDK, Apache-2.0.

## Reproduction and repair

The policy option validator accepted plain objects with only known own fields,
but constructors used ordinary property reads. If application code or another
dependency had put a writable `require_signature=false` on `Object.prototype`,
`new Policy()` inherited that value instead of requiring a signature by default.
With an authenticated context, missing request verification and fresh trusted
attestation, the resulting Basic policy returned `ALLOWED`. This was reproduced
using the actual exported policy API in a disposable Node process.

The shared option validator now rejects a recognized inherited field when that
field is absent from the input's own properties. Policy configuration, context
verdicts, evaluation time and audit metadata therefore cannot be supplied through
`Object.prototype`. Failures retain their existing fixed policy/context/audit
error codes. Unknown own fields and custom prototypes remain rejected.

Explicit own values take precedence, including the existing explicit Basic-only
signature optout. Own `undefined` values retain their documented default behavior;
null-prototype options remain supported. Unrelated inherited names do not change
valid defaults. Caller objects and global prototypes are not modified or frozen.
The protocol, public API, package exports and dependencies are unchanged.

This repair does not claim the SDK itself introduced prototype pollution, nor
establish a remote attack path in a consuming app. It prevents inherited option
values from weakening this SDK boundary. Arbitrary hostile runtime modification,
replacement of built-ins, hostile getters/proxies and application-owned callback
replacement require broader application controls and are outside this repair.

## Regression verification

- Focused original policy baseline: **75/75**.
- New isolated-process regressions before the repair: **16 tests, 14 failed,
  2 passed**. Each failure was an accepted inherited recognized field: three
  policy fields, six context fields, evaluation time and four audit fields.
- After the repair: combined original and new policy cases **91/91**. Test
  processes isolate prototype modifications from the runner and other suites.
  Positive controls preserve explicit own values, own undefined defaults,
  null-prototype inputs, caller mutability and unrelated inherited properties.
- Complete common server runner: reference Python **209/209**, Python SDK
  **512/512**, Node SDK **355/355**, Spring Boot **188/188**, zero skipped tests.
  Wheel/sdist/JAR builds, TypeScript and isolated npm package smoke passed.
  Redis first-claimer rotations across all three SDKs and the simultaneous
  process race retained exactly one successful claim.
- Offline installed npm package: all **13 packaged files** matched final source
  bytes and **16/16** inherited-field regressions passed through its ESM export.
  An initial comparison caught a README edit made after packaging; that first
  artifact was retained and not counted as success. Final repacking and checks
  above used the completed README. No production source changed for that retry.

The complete server runner, installed npm consumer, security review and merged
tree receipts are retained under
`.superpowers/evidence/2026-10-21-policy-own-fields/` in the primary checkout.
These are local checks; remote CI, publication and deployment are separate.
Unity iPhone/Android physical validation remains pending in its preserved worktree.
