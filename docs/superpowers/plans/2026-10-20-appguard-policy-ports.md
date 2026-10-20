# AppGuard policy and audit ports implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. One bounded worker owns Node/Java policy ports; do not recursively delegate.

**Goal:** Make Basic/Balanced/Strict deterministic policy and redacted audit behavior available in all three current server SDKs.

**Architecture:** Port the pure Python policy semantics using the shared42-case corpus. Callers explicitly supply trusted verdicts; existing HTTP middleware remains independently configured. Audit output is an allowlist rather than arbitrary context serialization.

**Tech Stack:** Node22 ESM/TypeScript declarations; Java17 immutable records/classes; existing Node/JUnit runners.

**Spec:** `protocol/policy-v0.md`, `conformance/v0/policy.json`, Python `policy.py` and `audit.py`.

## Global constraints

- Default authentication is missing; no trusted verdict may be read from a client status field.
- Basic alone may explicitly disable request signatures; step_up does not permit execution.
- Fixed codes, precedence and integer domain match the Python source and corpus.
- Signals are bounded untrusted hints; there is no new provider verifier/rate counter/automatic HTTP policy enforcement.
- Audit fields exclude tokens, bodies, subjects, keys, nonces, IPs and raw risk text.

## Review focus

- Empty/default contexts cannot accidentally allow processing.
- Type coercion, unknown fields or mutable caller arrays must not change validated state.
- Freshness at equality denies/observes/steps up according to profile.
- Callback failures must use fixed redacted errors without attaching the original cause.
- Forged decisions cannot introduce arbitrary audit action/reason codes.

### Task 1: Node policy/audit

**Files:** `sdk/node/src/policy.js`, `audit.js`, exports/declarations; policy/audit tests and README.
**Interfaces:** Explicit immutable policy/context/decision values, evaluatePolicy, auditEvent and audit sink; document supported sync/async callback contract.

- [x] Add failing tests consuming all42 portable cases plus default auth, type bounds, mutation, precedence, audit allowlist/redaction; observe RED.
- [x] Implement behavior without dependencies or automatic middleware changes; extend exact public TypeScript types.
- [x] Run full npm tests/type/install checks; commit only on parent authorization to avoid shared-index races.

### Task 2: Java policy/audit

**Files:** `sdk/spring-boot/src/main/java/io/appguard/{Policy,PolicyContext,PolicyDecision,PolicyEngine,AuditEvent,JsonAuditSink,...}.java`; JUnit tests and README.
**Interfaces:** Immutable records/classes with explicit constructors/default factories, evaluate and allowlisted audit JSON through existing Jackson dependency.

- [x] Add failing42-case tests plus equivalent negative boundaries/immutable state/sink failures; observe RED.
- [x] Implement validated pure behavior; no implicit Spring filter enablement or authentication replacement.
- [x] Run full Maven test/package; distinguish unavailable live Redis from successful tests; do not skip failures in report.

### Task 3: Cross-language verification

- [x] Re-run Python/Node/Java corpus and integrated server suites with an owned disposable Redis.
- [x] Fresh whole-port security review, targeted fixes, update policy support matrix/evidence and archive owned scratch.
