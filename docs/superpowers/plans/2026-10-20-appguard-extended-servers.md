# AppGuard extended server SDK implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Independent .NET, Go and PHP owners may work in parallel; no child agents and no shared-index staging. Parent performs one fresh whole-stage security review.

**Goal:** Extend the exact existing request, wire and policy protocols to ASP.NET Core, Go net/http and PHP without weakening authentication or replay boundaries.

**Architecture:** Each SDK has a pure strict verifier, explicit trusted identity/key/replay dependencies, a bounded local replay implementation and native HTTP integration where raw evidence is available. All consume the existing40 request,43 wire and42 policy vectors. Deployment adapters document evidence gaps rather than reconstructing unavailable raw input.

**Tech Stack:** Task-local official supported .NET/Go/PHP runtimes, native P-256/SHA-256 crypto, pinned package manifests/locks; no SDK runtime downloads or mandatory AppGuard service.

**Spec:** `protocol/request-v0.md`, `http-v0.md`, `policy-v0.md`, `conformance/v0/{requests,http,policy}.json`; existing Python/Node/Java implementations are reference evidence.

## Global constraints

- Verify exact body bytes, target ordering/empty query, fixed six covered fields and strict raw64 P-256 signature.
- Trusted authenticated subject and key record bind app/key/subject, expiry/revocation; signature success is not authorization.
- Syntax/time/key/digest/signature checks precede atomic nonce claim; store failures reject without a permissive fallback.
- Replay tuple/relativeTTL/limits match existing shared contract; in-memory state is explicit process-local only.
- Fixed codes and canonical encodings; reject duplicate singleton headers, malformed types, extra parameters and framing ambiguity.
- No publishing, production endpoints/accounts, unrelated runtime replacement, shared Redis database or user credentials.

## Review focus

- Framework-normalized headers/URI/body must not be presented as raw proof when the required evidence is absent.
- Cancellation/concurrency/store failures must not allow a second nonce claim or consume invalid requests.
- Platform ECDSA DER/raw conversion and PEM imports must enforce P-256 and exact signature lengths.
- Middleware must preserve authenticated identity, downstream body and existing authorization, with explicit dependency setup.
- Policy default missing authentication and audit redaction must match every portable case.

### Task 1: .NET and ASP.NET Core

**Files:** `sdk/dotnet/**` only, SDK project, tests, package metadata, README and evidence record.
**Interfaces:** Public immutable request/parameters/context/key models, strict wire parser, verifier, explicit replay store and ASP.NET Core middleware. Trusted identity/key callbacks are required; use IHttpRequestFeature.RawTarget, configured HTTPS origin and bounded exact body/header evidence.

- [x] Establish official supported runtime locally without global setup changes; pin target and dependencies.
- [x] Add RED corpus tests plus malformed crypto/numeric/header/URI inputs, replay concurrency/capacity/error tests, actual middleware HTTP tests and42 policy cases.
- [x] Implement minimal strict behavior, allowlisted audit API and explicit middleware integration; do not infer authentication from signature or client fields.
- [x] Run full tests and local package/isolated-consumer build; record exact support, skips, artifacts and limitations; notify parent for serialized commit.

### Task 2: Go and net/http

**Files:** `sdk/go/**` only, go.mod/go.sum, verifier/parser/models/replay/policy/audit, HTTP middleware, tests/docs.
**Interfaces:** Context-aware explicit authenticator/key/replay interfaces, request verifier and net/http wrapper using RequestURI. Frameworks supporting net/http may compose it; do not claim untested Gin/Echo-specific integration.

- [x] Establish official checksum-verified task-local Go runtime if not installed; avoid global shell/profile changes.
- [x] Add RED40/43/42 corpus tests and independent P-256 signatures, concurrency/race, raw HTTP and auth/body-preservation tests.
- [x] Implement strict APIs with native crypto and bounded I/O. Shared replay adapter optional only if real backend semantics/tests exist; otherwise require caller store and document local scope.
- [x] Run full tests including race detector, package consumer and HTTP tests; record precise support and notify parent for commit.

### Task 3: PHP

**Files:** `sdk/php/**` only, Composer metadata/lock, core strict verifier/parser/policy/audit/replay and request adapters/tests/docs.
**Interfaces:** Typed explicit immutable inputs and callback boundaries. Use OpenSSL P-256 checks and strict DER/raw conversion. PSR-7/15 or actual framework adapter must retain exact request target/body/header arrays; unsupported normalized front controllers must reject or require trusted evidence.

- [x] Establish a supported task-local official runtime; do not alter global PHP/Composer/server configuration.
- [x] Add RED40/43/42 vectors, signature edge cases, replay/error/identity boundaries and real adapter tests.
- [x] Implement strict core and explicit adapter; do not call framework examples tested Laravel/Symfony support without actual execution.
- [x] Run whole suite and Composer validate/install/isolated consumer; record runtime extensions and limitations, notify parent for commit.

### Task 4: Compatibility review and integration

- [x] Parent executes independent native-client signature verification through all implemented server runtimes and confirms the same replay/policy decisions.
- [x] Run actual shared backend tests only with an owned isolated service; publish no unverified distributed-store claim.
- [x] One fresh whole-stage security review and targeted RED/GREEN fixes; update support matrix, docs and evidence; merge locally only after clean verified state.
