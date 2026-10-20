# AppGuard boundary hardening implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Parent implements three bounded fixes inline, then one fresh whole-change reviewer; no recursive agents.

**Goal:** Resolve the three previously deferred defects with behavioral regressions and packaged consumer checks.

**Architecture:** Preserve existing protocols, trust boundaries and public error codes. Remove retained exception chains at enrollment boundaries, reject ambiguous Go PEM envelopes before crypto/replay, and preserve the existing native-unavailable code in Expo.

**Tech Stack:** Python3.11/SQLite/cryptography, dependency-free Go, TypeScript/Node22; existing frozen runtimes/locks in the attached worktree.

**Spec:** `docs/security/mobile-foundation-verification.md`, `docs/security/client-bridges-build-verification.md`, `docs/security/extended-server-verification.md`; normative `protocol/enrollment-v0.md` and `protocol/client-bridge-v0.md`.

## Global constraints

- No provider-account/device, user Keychain, release, publication or remote push operations.
- Preserve main until a clean verified fast-forward; use the already attached worktree.
- Errors keep existing fixed codes and discard the handled SDK dependency failure from cause/context in normal calls; ambient caller-owned active exceptions and captured traceback locals are outside this boundary. Proof/provider/clock rejection before storage preserves the pending challenge and creates no credential. Storage failures after commit can have an uncertain client-visible outcome; authenticated state readback is required.
- Go remains named P256 SPKI, public-only, single envelope, max4096bytes; malformed input must not consume nonce.
- Expo unknown/native-thrown errors remain redacted OPERATION_FAILED; known native-unavailable envelopes retain NATIVE_UNAVAILABLE.
- One fresh review; parent fixes Critical/Important in one RED/GREEN pass; new unrelated Minor findings explicitly deferred.

## Review focus

- Nested provider exceptions and clock failure before/after provider verification must not retain exception cause/context.
- SQLite failure must roll back, close connections and expose only fixed errors; raw exceptions must not replace public codes.
- Go decoder must not skip leading malformed/nested/repeated PEM blocks; preserve previously valid LF/CRLF and named P256 public keys.
- Every Expo operation must preserve the documented fixed unavailable result without leaking extra native fields/messages.
- Packaged wheel/tarball imports must exercise the changed sources, not stale monorepo outputs.

### Task1: Enrollment error boundaries

**Files:** `sdk/python/src/appguard/enrollment.py`, `enrollment_store.py`, `enrollment_types.py`; `sdk/python/tests/test_enrollment.py`.
**Interfaces:** Existing EnrollmentService.issue/complete and SqliteEnrollmentStore methods, unchanged signatures/codes.

- [x] Add clock/provider/malformed-key/proof/store-error regressions requiring fixed code, absent cause/context and unconsumed challenge/no credential; run targeted pytest and observe failures.
- [x] Move fixed public error raises outside caught exception contexts; preserve transaction rollback/finally closure and existing successful enrollment/revocation behavior.
- [x] Run whole Python suite with an owned disposable Redis; build/install wheel in a separate environment and rerun enrollment/provider suites; commit explicit paths.

### Task2: Go PEM envelope

**Files:** `sdk/go/appguard.go`, `sdk/go/security_test.go` or a new focused test file; `sdk/go/VERIFICATION.md`.
**Interfaces:** VerifyRequest and publicKey internal importer, unchanged public API and KEY_REJECTED result.

- [x] Add real signed-request cases for malformed/unclosed first block, duplicate/nested blocks, junk prefix/suffix, headers, LF/CRLF valid input; assert KEY_REJECTED and0 claims on invalid input, then original request accepts; observe RED.
- [x] Require the first complete single PUBLIC KEY envelope without decoder-skipped material; retain max4096bytes, public-only namedP256 and current supported trailing ASCII whitespace.
- [x] Run full Go normal/race/vet/build plus public fixture probe and separate consumer; commit explicit paths.

### Task3: Expo fixed error propagation

**Files:** `sdk/expo/src/client.ts`, `sdk/expo/test/client.test.cjs` and package verification record.
**Interfaces:** Existing AppGuardErrorCode includes APPGUARD_NATIVE_UNAVAILABLE; allthree public methods retain it for native failure envelopes.

- [x] Add unavailable-envelope coverage across publicKey/prepare/enrollmentProof and assert redacted errors/no native message; observe RED.
- [x] Add only the missing fixed code to nativeCodes; keep unknown/malformed/thrown response paths rejecting.
- [x] Run full Expo test/typecheck/relocated pack verification, installed-tarball runtime regression; commit explicit paths.

### Task4: Integration

- [x] One fresh whole-change security review and any targeted RED/GREEN fix pass; record rulings/costs and deferred findings.
- [x] Update current support/evidence, mark prior deferrals resolved without rewriting historical results; archive checksummed owned scratch.
- [x] Clean local main fast-forward and fresh readback; no remote push/publication.
