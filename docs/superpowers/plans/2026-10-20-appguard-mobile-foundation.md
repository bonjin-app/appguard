# AppGuard Mobile Foundation Implementation Plan

> Continue the approved platform roadmap without reopening completed server work. Use TDD, bounded platform owners, one whole-change security review, and explicit evidence tiers. The user requested continued work toward the platform goal on 2026-10-20.

**Goal:** Produce real Android/iOS request signers and installation-key adapters interoperable with the existing server protocol, plus explicit enrollment/evidence boundaries and an independently usable local policy/audit foundation.

**Architecture:** Native SDKs sign immutable, caller-supplied raw bytes using installation-specific P-256 keys; no embedded global secret and no private-key export API. Public-key export is explicit. Provider attestation acquisition is separate from request signatures and never implies server trust by itself. Existing server SDKs remain unchanged. Cross-platform wrappers consume a small native bridge contract after these primitives are verified.

**Tech Stack:** Java17/JCA and Android Keystore, Gradle Android library; SwiftPM/CryptoKit/Security/DeviceCheck; Python3.11 for local interoperability and enrollment/policy tests.

**Spec:** `docs/superpowers/specs/2026-10-20-appguard-foundation-design.md`, `protocol/request-v0.md`, `protocol/http-v0.md`.

## Global constraints

- Apache-2.0, locally built packages only, preserve `main` and prior server branch.
- Sign exact raw body and origin-form target; fixed HTTPS origin, pinned P-256/SHA256, raw 64-byte r||s signatures. Preserve query order/duplicates/empty query.
- Use the existing six covered components and exact parameter order; 1MiB body, 8192-byte target, same identifier/header/time limits. Reject invalid inputs before invoking a key.
- Client preparation API consumes method/target/body/contentType/authorization/appId/keyId/created/expires/nonce/origin. It produces method/target/body and ordered headers including Content-Type, Content-Digest, Authorization, AppGuard-App-Id, Signature-Input and Signature. Never silently regenerate input after signing.
- Default nonce comes from OS CSPRNG (16 bytes); default trusted time is integer Unix seconds with at most120s lifetime. Tests can supply fixed time/nonce.
- Store installation private keys only in platform key APIs. Software-backed storage must never be reported as hardware backed. Secure Enclave/StrongBox failure must not silently downgrade an explicit hardware requirement.
- Provider acquisition requires explicit configured Apple/Google identifiers. Opaque client evidence is untrusted until a server verifies it; unavailable/unsupported/error differ from verified.
- Test private keys are ephemeral; tests never read/delete user keys or change provider accounts, existing simulators, signing or published apps.

## Review focus

1. Mutable request buffers, header injection, URL normalization or key-alias reuse must not sign a different request or export private material.
2. DER/raw signature conversion and leading-zero scalars must interoperate with independent server verifiers.
3. Key lookup/generation errors, unsupported hardware and unavailable provider services must fail explicitly without replacing existing keys.
4. Enrollment challenges and evidence bind app, authenticated subject, public key and expiration; unverified evidence never becomes an attestation verdict.
5. Tests must distinguish host cryptographic execution, Android/iOS builds, simulator behavior and actual provider/device proof.

## Ownership

- Android owner: `sdk/android/**` only, including Gradle files, Java core/keystore APIs, test-only export probe and README/license.
- Apple owner: `sdk/apple/**` only, including SwiftPM, native APIs, tests/test-only probe and README/license.
- Parent: protocol/bridge/enrollment documents, Python enrollment/policy foundation, portable interop scripts, root docs and integration evidence.
- No nested agents, no worker commits/index changes. Parent commits tested outputs. No edits across owners.

## Task1: Android signer and keys

- [x] RED: fixed-vector signature-base/digest/wire tests and negative target/header/time/body inputs before implementation.
- [x] Implement Java request preparation, strict DER-to-raw conversion and injectable native signer boundary; generated signatures verify with independent JCA/OpenSSL/server logic.
- [x] Android Keystore get-or-create installation key with explicit alias, fail-closed existing-key checks, public SPKI export and hardware-status reporting; no private export.
- [x] Provider acquisition API only if official dependencies/build are available; otherwise document exact capability boundary rather than a successful mock.
- [x] JVM tests plus actual Android library build; instrumented tests on a new isolated test emulator if feasible, without touching existing AVDs.

## Task2: Apple signer and keys

- [x] RED: fixed vectors and request/DER/buffer limits before implementation.
- [x] Implement Swift value-type preparation and P-256 signers; public SPKI export and strict DER/raw behavior.
- [x] Security/Keychain installation-key API with explicit Secure Enclave requirement and explicit unsupported behavior; preserve pre-existing keys.
- [x] DeviceCheck App Attest acquisition wrapper with support/error states and caller-supplied challenge hash, no server-verification claim.
- [x] Run host Swift tests and build iOS Simulator package targets. Test-only export probe emits only public fixture material, never private keys.

## Task3: Enrollment, policy and client bridge contracts

- [x] Define domain-separated server challenge, proof-of-possession and provider trust states, plus common native bridge method/result schema.
- [x] RED then implement an explicit local SQLite enrollment store and challenge service with atomic one-use/expiry, app+subject+key binding, public-key proof, revocation and no automatic attestation trust.
- [x] RED then implement Basic/Balanced/Strict deterministic policy and redacted audit events; missing/unknown/provider failure never implies verified attestation. No AI dependency.

## Task4: Integration and review

- [x] Native signer output verifies through existing server implementation; independent generated-key signatures, mutations and replay checks.
- [x] Repeat affected suites and package builds. Record versions and host/build/simulator/provider evidence separately.
- [x] One fresh whole-change security review; important fixes require observed RED/GREEN regressions.
- [x] Commit evidence and preserve feature branch; continue remaining approved roadmap without claiming device/provider/release proof that was not obtained.

## Later roadmap

After native primitives: Unity/Expo/React Native/Flutter bridge packages, Build/CLI, .NET/Go/PHP and optional console/analytics. Each gets concrete code and behavioral tests; scaffolding or simulated provider success is not support evidence.
