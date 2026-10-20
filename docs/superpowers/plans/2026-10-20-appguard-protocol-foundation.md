# AppGuard Protocol Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking. Keep routine work on the main agent; delegate only a bounded question when useful.

**Goal:** Establish a documented, executable draft request-verification contract and shared attack fixtures before implementing framework SDKs.

**Architecture:** Keep a language-neutral protocol and JSON fixtures at the repository root. A Python reference implementation verifies the draft without a web framework or central AppGuard service. Future Java, Python, and Node.js SDKs consume the same fixtures; this milestone does not claim those SDKs exist.

**Tech Stack:** Python 3.11+, pytest, cryptography, standard-library hashing and concurrency, uv with a committed lockfile. Use maintained stable dependency releases, resolve exact versions at implementation time, and exclude prereleases.

**Spec:** [AppGuard 기반 설계](../specs/2026-10-20-appguard-foundation-design.md)

## Global Constraints

- 핵심 보안 기능은 AI 모델이나 유료 AI API 없이 동작한다.
- 각 서버 SDK는 중앙 서비스 없이 기본 검증을 수행할 수 있어야 한다.
- 앱에 모든 설치가 공유하는 장기 비밀키를 내장하지 않는다.
- 요청 서명과 앱 증명은 사용자 인증 및 권한 검사를 대체하지 않는다.
- 지원하지 않는 버전과 알고리즘은 명시적으로 거절한다.
- 감사 로그에 토큰, 비밀키, 요청 본문을 기본 기록하지 않는다.
- 모의 증명 테스트와 실제 공급자·기기 검증 결과를 구분한다.
- 지원 상태는 계획, 구현, 통합 검증, 출시로 구분해 공개한다.

## Scope and Approved Decisions

This plan covers the first foundation milestone, not the entire platform roadmap. Status is draft throughout. No package publishing, deployment, mobile attestation integration, AI, obfuscation tooling, or framework middleware is included.

Use Apache-2.0 for project-authored code and documentation, as approved on 2026-10-20. Add the unmodified license text during implementation and preserve third-party notices. This plan does not relicense imported assets or code.

Use an intentionally restricted RFC 9421 profile named `appguard-request-v0`. Support `ecdsa-p256-sha256` only, using the RFC's 64-byte `r || s` wire signature. Do not invent cryptographic primitives or assume DER is the wire format. The reference API accepts parsed structured input and constructs the signature base; a production HTTP Structured Fields parser and framework adapters are later work.

The covered component order is `@method`, `@target-uri`, `content-type`, `content-digest`, `authorization`, `appguard-app-id`. Signature parameters, in order, are `created`, `expires`, `nonce`, `keyid`, `alg`, `tag`; tag is `appguard-request-v0`. Reject extra or missing components and parameters in this draft. Bind all required parameters through the RFC signature-parameters line.

Compute SHA-256 Content-Digest using RFC 9530 over the supplied body bytes, including an empty body. Require `content-type` explicitly; adapters must supply the actual received value rather than manufacture one. Reject content encodings other than identity in this initial profile. Do not parse and reserialize JSON before hashing.

The verifier receives a trusted externally visible HTTPS origin and an unmodified ASCII request target. Never derive origin from untrusted forwarding headers. Reject fragments, CR/LF/control characters, malformed percent escapes, duplicate protected headers, and ambiguous target syntax. Preserve percent encoding and query ordering. Framework adapters must reject inputs whose original target or body bytes are unavailable.

Require an application-issued Bearer token in the signed authorization field. The reference verifier binds the bytes but does not authenticate the token. A trusted caller supplies the authenticated subject, and a trusted key record binds app ID, key ID, subject, algorithm, and active/revoked state. Fixtures use fake tokens and explicitly provisioned test keys, not simulated provider approval.

Use integer Unix seconds, a maximum signature lifetime of 120 seconds, at most 30 seconds of future clock skew, and reject at `now >= expires`. Require `created < expires`, `expires - created <= 120`, and `created <= now + 30`. Nonce is 16 random bytes encoded as canonical unpadded base64url. Scope replay claims by `(app_id, key_id, nonce)` until `expires`.

Successful cryptographic verification is only one input to an application's security decision. Key enrollment and its attestation requirements are outside this milestone; the reference API only consumes trusted preprovisioned key records. Local replay state is test/reference-only and cannot protect multiple processes or servers.

## Review Focus

- Forwarded origin and normalized query/path changes must never silently validate a different request.
- Body reserialization, missing body bytes, and content encoding must not produce a false integrity result.
- Duplicate covered fields, invalid signature lengths, and unsupported algorithms must reject deterministically.
- Parallel replays must have exactly one success; invalid signatures must not reserve a nonce.
- A valid signature from another app, another authenticated subject, or a revoked key must reject.

## File Structure

- `README.md`: actual implementation status, installation for the reference tool, explicit limits, roadmap.
- `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `.gitignore`: license, private vulnerability-reporting guidance without invented contact channels, contribution and local setup rules.
- `docs/security/threat-model.md`: assets, trust boundaries, attackers, failures and non-goals.
- `protocol/request-v0.md`: normative draft profile and stable rejection reasons.
- `protocol/vector-format.md`: language-neutral fixture fields and sequencing semantics.
- `conformance/v0/requests.json`: committed valid and adversarial request fixtures; no real credentials.
- `conformance/v0/test-public-key.pem`: public test material only; no production key enrollment.
- `reference/python/pyproject.toml`, `reference/python/uv.lock`: reference-tool metadata and reproducible dependencies; no publishing configuration.
- `reference/python/src/appguard_reference/{__init__,types,canonical,crypto,replay,verify}.py`: isolated reference modules.
- `reference/python/tests/{test_canonical,test_crypto,test_replay,test_verify,test_vectors}.py`: protocol and attack tests.

## Task 1: Define the Draft Contract and Open-Source Boundaries

**Files:** Create the root documentation/governance files, threat model, protocol documents, Python project metadata, and `.gitignore` listed above.

**Interfaces:** Define frozen `RequestInput(method: str, target: str, headers: tuple[tuple[str, str], ...], body: bytes)`, `SignatureParameters(created: int, expires: int, nonce: str, key_id: str, algorithm: str, tag: str)`, and `KeyRecord(app_id: str, key_id: str, subject: str, public_key_pem: bytes, algorithm: str, revoked: bool)` in `types.py`. Protected field names compare case-insensitively; retain duplicates until validation. Define `VerificationError` with a stable `code: str`.

- [x] Write the protocol with exact serialization examples, the decisions above, and explicit separation of parsed reference inputs from future HTTP parsing.
- [x] Specify fixture records containing `id`, `request` (body encoded as base64), `parameters`, `signature_b64`, `key`, `context` (`origin`, `app_id`, `subject`, `now`), `replay_store` (`memory`, `unavailable`, or `full`), `expected_signature_base`, and `expected_codes` (a nonempty array). Each expected code describes one repeated verification of that record against the same scenario-local store; a replay scenario expects `["VERIFIED", "REPLAY_DETECTED"]`. State resets between records.
- [x] Define rejection codes: `INVALID_REQUEST`, `UNSUPPORTED_PROFILE`, `INVALID_TIME`, `KEY_REJECTED`, `DIGEST_MISMATCH`, `INVALID_SIGNATURE`, `REPLAY_DETECTED`, `REPLAY_STORE_UNAVAILABLE`; success code is `VERIFIED` and does not mean authorized or attested.
- [x] Document failure precedence: syntax/profile, time, trusted key binding, body digest, signature, atomic replay claim. Tests with multiple errors must follow this order.
- [x] Write the threat model, actual support matrix, contributor setup, and license. SECURITY.md directs reporters to repository private vulnerability reporting only when that feature is actually enabled; otherwise ask them to request a private channel without posting exploit details or secrets publicly. Do not claim a reporting channel has been enabled.
- [x] Create project metadata with src layout, Python >=3.11, stable dependencies, and `uv.lock`; set `tool.uv.package = true` with an explicit build backend. Run `uv sync --locked --project reference/python` and verify `uv run --project reference/python python -c 'import appguard_reference'` succeeds.
- [x] Commit only Task 1 files after `git diff --check` succeeds.

## Task 2: Canonical Bytes and Cryptographic Verification

**Files:** Create `canonical.py`, `crypto.py`, `test_canonical.py`, `test_crypto.py`, and the public test key; extend `types.py` only for types required by these interfaces.

**Interfaces:** `build_signature_base(request: RequestInput, parameters: SignatureParameters, *, origin: str) -> bytes`; `validate_content_digest(request: RequestInput) -> None`; `verify_p256(public_key_pem: bytes, signature_base: bytes, signature: bytes) -> None`. Raise `VerificationError` on invalid input. None of these functions writes replay state, authenticates users, or enrolls keys.

- [x] Write failing tests that compare a fixed signature-base byte string to an independently constructed literal, and pin empty/binary body digests, Unicode rejection in the target, encoded slash, duplicate query keys, query order, invalid percent escapes, CR/LF injection, duplicate protected headers, wrong signature lengths, P-384 keys, and altered signatures.
- [x] Run `uv run --project reference/python pytest reference/python/tests/test_canonical.py reference/python/tests/test_crypto.py -q` and confirm failures are missing behavior rather than setup errors.
- [x] Implement strict validation and RFC serialization without decoding/reordering query strings. Convert the 64-byte signature to DER using cryptography's supported integer conversion helpers before its verification call. Never evaluate client-supplied algorithm names dynamically.
- [x] Verify a fixed P-256 signature independently using OpenSSL, converting its encoding where necessary, before committing the fixture. Keep expected bytes checked in; tests must not generate their expected results through the function under test. Do not regenerate a nondeterministic ECDSA signature as a byte-for-byte test expectation.
- [x] Rerun the targeted tests and confirm every case passes; commit Task 2 files.

## Task 3: Atomic Replay Contract and Complete Reference Verification

**Files:** Create `replay.py`, `verify.py`, `test_replay.py`, `test_verify.py`; document the storage contract in `protocol/request-v0.md`.

**Interfaces:** `ReplayStore.claim(scope: tuple[str, str, str], *, expires: int, now: int) -> bool` atomically returns true only for a new live claim; failures raise `ReplayStoreUnavailable`. Provide `InMemoryReplayStore(capacity: int = 10000)` for reference/tests with locking and expired-entry cleanup; invalid capacity is rejected at construction and capacity exhaustion fails closed. `verify_request(request: RequestInput, parameters: SignatureParameters, signature: bytes, *, origin: str, app_id: str, subject: str, key: KeyRecord, now: int, replay: ReplayStore) -> VerificationResult`; result contains app ID, key ID and expiry only, with no token, request body, or serialized signature base.

- [x] Write failing tests for exact time boundaries (120/121-second lifetimes, 30/31-second future creation, `now == expires`), booleans in integer fields, invalid/canonical nonce encodings, wrong app/subject/key ID, revoked keys, replay-store exceptions, and exhausted capacity.
- [x] Add a barrier-synchronized 32-thread replay test asserting exactly one success, a test that an invalid signature does not reserve its nonce, and a test that distinct app/key scopes remain independent. Verify duplicate request rejection is distinct from application-level idempotency.
- [x] Run `uv run --project reference/python pytest reference/python/tests/test_replay.py reference/python/tests/test_verify.py -q` and confirm the intended failures.
- [x] Implement the declared verification order and local store. Carry the same caller-supplied `now` through all checks. Bound input sizes before cryptographic work; record limits in the protocol: 1 MiB body, 8 KiB target, 64 input header pairs, 16 KiB total header text, 128 ASCII characters per app/key/subject identifier. Reject controls in identifiers and apply limits before canonicalization. Add exact-limit and limit-plus-one tests.
- [x] Verify caller-controlled exceptions do not leak request contents into returned errors. Test a failing store and malformed key with fake token/body markers and assert those markers are absent from error text and result representations.
- [x] Rerun Task 2 and Task 3 tests, then commit Task 3 files. State explicitly that a distributed store and middleware integration are still absent.

## Task 4: Portable Conformance Corpus and Reproducible Handoff

**Files:** Create `conformance/v0/requests.json`, `test_vectors.py`; update the protocol examples, README, and vector-format document.

**Interfaces:** Each language adapter will consume the fixture format from Task 1 and return the same ordered `expected_codes`. The Python fixture loader uses strict base64 validation, detects duplicate JSON keys and fixture IDs, and rejects unknown fields. Its fixture path is derived from the test file location, not the current working directory.

- [x] Write failing corpus tests for missing required scenarios, duplicate IDs/JSON keys, malformed base64, changed expected bytes, and rejection-reason mismatches. Assert that all five Review Focus classes have fixture coverage.
- [x] Check in an independently verified valid signed request plus mutations for body, method, URI/query, token, app, subject, key, time, algorithm, duplicate field, signature bytes, replay, and store failure. Mutations reuse an original signature unless a case specifically needs a different valid signer. Include a separately signed empty-body request.
- [x] Implement a parameterized loader/runner that builds the typed inputs, resets state per scenario, and compares both canonical bytes and final rejection/success codes. A malformed request need not have a signature-base expectation; the format must represent this explicitly.
- [x] Run `uv sync --locked --project reference/python` and `uv run --project reference/python pytest reference/python/tests -q`; all tests must pass. Run the same suite from another working directory using absolute paths to verify fixture discovery.
- [x] Run `git diff --check`; manually inspect all committed fixtures for real credentials and all documentation for unsupported production, attestation, framework-support, or security-audit claims.
- [x] Update README with the exact verified local commands, reference-only limitations, and separate planned Spring Boot/Python/Node.js SDKs. Commit Task 4 files and report the tested commit.

## Exit Criteria and Next Milestone

The deliverable is an executable draft contract, not a production security SDK. The protocol, corpus, and reference implementation must agree, and independent cryptographic verification must be recorded. No Apple/Google verification, physical-device evidence, distributed replay protection, vulnerability assessment, or package publication is implied by passing local tests.

The next plan implements Spring Boot, Python middleware, and Node.js adapters against this corpus, including HTTP Structured Fields parsing, trusted proxy/body capture, existing authentication integration, distributed replay storage, and key-enrollment boundaries. Basic/Balanced/Strict enforcement, provider attestation, build protection, console and AI remain explicit later milestones.

## Sources Consulted for This Plan

- [RFC 9421: HTTP Message Signatures, including section 3.3.4](https://www.rfc-editor.org/rfc/rfc9421.html)
- [RFC 9530: Digest Fields](https://www.rfc-editor.org/rfc/rfc9530.html)
- [cryptography: Elliptic curve signature APIs](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/)

## Plan Review and Execution

The foundation design text was presented in chat and approved before it was saved. This implementation plan introduced concrete draft limits, interfaces, algorithm choices, and licensing; the user explicitly approved the plan and Apache-2.0 on 2026-10-20. Implementation and tests for all four tasks have run; see `docs/security/foundation-verification.md` for evidence and limitations. Recommend main-agent execution with targeted delegation only if a difficult security question needs independent investigation; this avoids a fresh worker context for each tightly coupled task.
