# AppGuard client bridges implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Independent platform owners may work in parallel; one fresh whole-stage security review follows integration. Do not recursively delegate.

**Goal:** Expose the validated native request and enrollment operations to Expo/React Native, Unity and Flutter, with relocatable experimental packages and honest local verification.

**Architecture:** The existing Android/Apple SDKs own parsing, keys and cryptography through a bounded JSON facade. Framework bindings only carry typed input and fixed responses. Packages stage their native source dependencies reproducibly for local builds; no published package or provider success is assumed.

**Tech Stack:** Java 17/Android 26+, Swift/iOS 15+, Expo Modules API, Unity 6000 C#, Flutter platform channels.

**Spec:** `protocol/client-bridge-v0.md`, `protocol/request-v0.md`, `protocol/enrollment-v0.md`.

## Global constraints

- Preserve exact target, body and ordered header bytes; no HTTP transport is supplied.
- No private-key export/import, arbitrary signing, silent hardware downgrade or provider verdict.
- Fixed redacted errors, 1500000-byte JSON input, 1048576-byte decoded body, strict native validation.
- Keep current main and prior branches intact while extending the attached worktree.
- No account linking, production release, changes to existing simulators/emulators or user Keychain tests.

## Review focus

- Malformed JSON/types/base64 must reject before persistent-key access where input permits.
- Disabled/missing native platforms must fail explicitly, without JS/Dart/C# cryptographic fallbacks.
- Framework conversions must preserve binary bodies and explicit empty queries.
- Packaged source dependencies must resolve without repository-relative escapes after staging.
- Native exceptions and tokens must not leak through managed error messages.

### Task 1: Shared native JSON facade

**Files:** Android `NativeBridge.java` and tests; Apple `NativeBridge.swift` and tests, package readmes.
**Interfaces:** `NativeBridge.invoke(operation: String, payload: String) -> String`; Android constructor accepts Context, Apple default init uses installation keys. Schema and operation result names are fixed in the spec.

- [x] Write behavioral tests for binary/empty-query preservation, independent signature verification, enrollment binding, malformed input/type/base64, unsupported operations/hardware and redacted key failures; observe RED.
- [x] Implement facade over existing typed SDKs, with internal key-store/clock seams only for tests.
- [x] Run full Android host tests/AAR/lint and SwiftPM tests/unsigned iOS Simulator build; record GREEN and commit owned files.

### Task 2: Expo / React Native package

**Files:** `sdk/expo/**` only.
**Interfaces:** Expo module `AppGuard` with asynchronous `invoke(operation, payload)` calling Task 1. Public TypeScript `publicKey`, `prepare`, `enrollmentProof` APIs and typed results; config plugin and staged native dependencies.

- [x] Scaffold using create-expo-module, remove generated UI/web examples; write failing tests for delegation, exact payload/result bytes, missing module and error redaction.
- [x] Implement Android/Apple module bindings, typed client and minimal config plugin, reproducible native source staging.
- [x] Verify package typecheck/tests/pack contents and available actual native compile paths; document absent runtime evidence and commit.

### Task 3: Unity UPM package

**Files:** `sdk/unity/**` only.
**Interfaces:** C# typed API over Android JNI `invoke` / iOS C ABI; fixed failures on unsupported editor/platform, no crypto fallback.

- [x] Write failing managed tests for binary/empty-query mapping, errors, invalid/missing platform and native return ownership.
- [x] Implement UPM package, Java and Swift/C ABI entry points with bounded string allocation/free, source/artifact staging and install instructions.
- [x] Run tests in an isolated Unity project or supported installed C# runtime; compile available native adapters and clearly label unexecuted platform runtime; commit.

### Task 4: Flutter plugin

**Files:** `sdk/flutter/**` only.
**Interfaces:** MethodChannel `io.appguard/client` method `invoke`, arguments `{operation,payload}`; native Task 1 facade. Typed Dart methods preserve JSON/header/body semantics.

- [x] Write failing Dart tests for exact round-trip, error redaction and missing plugin, and native adapter tests where practical.
- [x] Implement Android/iOS channels, plugin metadata and relocatable source staging.
- [x] Use a task-local official Flutter runtime if available to run analyze/tests/package validation and available native builds; record actual evidence and commit.

### Task 5: Integration and review

**Files:** root README, bridge docs, verification record, stage ledger.

- [x] Re-run integrated native suites and consumer interoperability probes; exercise staged package installation paths, not only monorepo imports.
- [x] One fresh whole-change security review; fix Critical/Important issues using targeted RED/GREEN, explicitly defer any Minor issues with impact.
- [x] Update support matrix and plan from observed evidence, archive checksummed owned scratch, commit clean result and continue Build/CLI roadmap.
