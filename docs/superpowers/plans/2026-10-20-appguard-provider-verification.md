# AppGuard provider verification implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Separate Google and Apple owners may work independently; parent owns shared Python dependency metadata. No child agents or shared-index commits.

**Goal:** Supply real provider acquisition/verification adapters for the existing authenticated enrollment callback, while separating offline verifier tests from genuine account/device evidence.

**Architecture:** Optional provider modules produce the existing bound AttestationVerdict only after provider-authenticated validation. Google uses authenticated official server decoding and strict verdict/context checks. Apple verifies the attestation certificate chain against pinned official roots and the exact App Attest authenticator/challenge/key context. The enrollment service still atomically consumes challenges and binds the request-signing SPKI.

**Tech Stack:** Android optional Play Integrity dependency, Python cryptography and bounded CBOR parsing, explicit Google authentication/HTTPS transport. Exact dependencies are pinned after official documentation/runtime inspection.

**Spec:** `protocol/enrollment-v0.md`, `docs/security/enrollment-policy.md`; official [Apple verification guide](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server), [Google standard requests](https://developer.android.com/google/play/integrity/standard), [Google verdicts](https://developer.android.com/google/play/integrity/verdicts).

## Global constraints

- No accounts, credentials, entitlements, signing profiles, production network calls or device actions during implementation tests.
- Never trust decoded provider JSON supplied by a client or a certificate root carried inside evidence.
- Configured application identities, environment, certificate digests/device labels and actual challenge hash are mandatory bindings.
- Fixed redacted errors, bounded input/parsing/HTTPS timeouts, explicit credentials and trust anchors; no permissive fallback on unsupported/unavailable providers.
- Synthetic PKI/transport fixtures validate implementation paths, not successful Apple/Google attestation or secure hardware.
- Request signing key and Apple App Attest key remain distinct; app attestation does not prove request-key hardware backing.

## Review focus

- Fresh signed challenge/proof must not be accepted with another app/subject/SPKI or stale/replayed provider context.
- Certificate chain, signature/curve, nonce-extension encoding, authenticator data and app/environment checks all fail closed.
- CBOR/JSON duplicate keys, excessive depth/length, trailing bytes and malformed encodings cannot weaken binding.
- Transport/credential/callback errors cannot leak provider tokens, private material or raw exceptions.
- Acquisition success remains opaque evidence; only authenticated server verification may produce a verdict.

### Task 1: Google acquisition and backend

**Files:** `sdk/android-play-integrity/**`; `sdk/python/src/appguard/providers/google.py`, provider-specific tests/docs. Shared `pyproject.toml`/lock changes coordinated with parent.
**Interfaces:** Optional Android acquisition returns opaque token+requestHash metadata/errors using official standard requests; Python callable `(Challenge, evidence: bytes) -> AttestationVerdict` integrates with EnrollmentService.

- [x] Confirm official API/dependency/credential requirements; add tests first for acquisition support/errors/hash syntax and strict decoded request/app/device/licensing/time/context decisions.
- [x] Implement actual official API transport with explicit credential injection, bounded responses/timeouts and no client-decoded-payload shortcut; test with an isolated injected transport.
- [x] Run optional Android compile/tests and full Python provider/enrollment suites, frozen package install; document external genuine-token verification gap.

### Task 2: Apple backend

**Files:** `sdk/python/src/appguard/providers/apple.py` and strictly necessary provider support files; provider-specific tests/docs and pinned public trust-anchor provenance. Shared dependency metadata coordinated with parent.
**Interfaces:** Enrollment verifier callable over the existing challenge and a precisely documented bounded evidence envelope, returning a context-bound AttestationVerdict after chain/authenticator checks.

- [x] Read official verification steps and inspect current native AppAttestEvidence; define evidence encoding and explicit app/environment configuration.
- [x] Write RED tests using real generated synthetic certificate chains and P-256 keys for each required check, including official-root rejection of synthetic evidence. Distinguish these fixtures from genuine Apple evidence.
- [x] Implement bounded strict CBOR/DER handling, pinned trust chain, challenge nonce/RP ID/AAGUID/counter/credential key bindings and validity checks. Never replace cryptographic validation with client labels.
- [x] Run provider/enrollment/package suites; document initial-attestation scope and any assertion/counter persistence lifecycle not implemented. Successful genuine Apple tokens require separate account/device evidence.

### Task 3: Integration and review

- [x] Exercise actual EnrollmentService with synthetic trusted-backend fixtures: correct binding, cross-context rejection, expiry after backend work and one-use concurrency.
- [x] One fresh whole-provider security review, targeted RED/GREEN fixes and exact support documentation.
- [x] Keep physical-device/provider-account proof explicitly pending; do not simulate successful provider access or silently relax Balanced/Strict.
