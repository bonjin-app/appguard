# AppGuard Server SDK Implementation Plan

> **For agentic workers:** Use test-driven implementation and bounded parallel language owners, then one whole-branch security review. The user explicitly authorized local foundation merge and continued SDK implementation/testing on 2026-10-20; continue without intermediate approval gates.

**Goal:** Implement locally installable Spring Boot, Python and Node.js server SDKs with one draft protocol, real framework integration tests and shared conformance evidence.

**Architecture:** Each language verifies the existing v0 protocol locally. All consume `conformance/v0/requests.json` and a new strict HTTP-envelope corpus. A fixed wire subset prevents metadata loss and canonicalization ambiguity; configured identity/key resolvers and a caller-provided replay store remain explicit dependencies. Redis adapters share a deterministic nonce namespace and atomic SET NX with relative expiry.

**Tech Stack:** Java 17 / Spring Boot 3.5.x with Maven; Python 3.11 / cryptography / ASGI plus FastAPI, Django ASGI and Flask through WsgiToAsgi integration; Node 22 / native crypto / Express, Fastify and NestJS adapters; Redis clients as optional SDK dependencies.

**Spec:** `docs/superpowers/specs/2026-10-20-appguard-foundation-design.md`, `protocol/request-v0.md`, and `protocol/http-v0.md`.

## Global Constraints

- Apache-2.0; local packages and builds only; no registry publication or deployment.
- Preserve all existing core vectors and reason codes; no shared client secret, AI dependency or required AppGuard service.
- Authentication, resource authorization, key enrollment, provider attestation and transport topology remain application/deployment responsibilities.
- Default protection covers every HTTP request reaching an installed adapter; no automatic prefix exclusions. Install only on intended routes/applications.
- Identity and key resolution, trusted external HTTPS origin, app ID and replay store are mandatory. No implicit trust of forwarding headers or client subject IDs.
- HTTPS is required by default; explicit insecure transport opt-in is only for controlled local testing or separately enforced TLS termination.
- Read and replay exact bytes, with 1 MiB content limit before unbounded reads; no decompression or JSON reserialization before verification.
- Error responses contain fixed codes only; expected authentication rejection is 401, verification rejection 403, malformed input 400, dependency failure 503. Unsupported profile/time/signature/key/replay are 403. Oversized body is 413 with INVALID_REQUEST.
- Local replay stores are explicit test/development choices, not automatic production defaults; Redis needs dedicated capacity/no live-key eviction and suitable persistence.

## Review Focus

- Duplicate/extra wire fields, changed covered lists and noncanonical base64 must not disappear during parsing.
- Missing raw path/header/body capture or exhausted streams must fail closed; downstream code must receive the unchanged body after success.
- Authentication callbacks, public key lookup and backend faults must not leak tokens or convert failures to success.
- Origin spoofing, insecure transport and asynchronous dispatch must not bypass enforcement.
- Redis claims must be atomic across SDK instances, use identical scope keys and preserve claims for the signature's full remaining validity.

## File Ownership and Interfaces

- Main: `protocol/http-v0.md`, `conformance/v0/http.json`, `sdk/python/**`, reference compatibility imports/dependency metadata, root documentation, root scripts and evidence.
- Node owner: `sdk/node/**` only; standalone native verifier and wire parser; Express/Fastify/NestJS installation APIs, Redis/local store implementations and tests.
- Java owner: `sdk/spring-boot/**` only; Java verifier and wire parser, servlet filter/body wrapper, opt-in Boot auto-configuration, Redis/local stores and tests.
- Shared inputs are read-only for language owners. Do not modify another owner's files, root metadata or shared fixtures. No nested delegation. Parent owns commits after owners finish to avoid index conflicts.

The core contracts remain the reference's RequestInput, SignatureParameters, KeyRecord and VerificationResult semantics, using idiomatic language names. Parsers take duplicate-preserving header pairs and return typed parameters plus a 64-byte signature. Authenticated subject and trusted key record are supplied by application callbacks/beans. Body, target, header and identifier limits remain unchanged.

## Task 1: Merge Foundation and Define the HTTP/Redis Contract

- [x] Verify clean main and feature checkouts; fast-forward local main to 1725f89 without remote operations.
- [x] Install frozen reference dependencies in main and rerun all 209 tests.
- [x] Record the common HTTP-envelope grammar, framing checks, error mapping, TLS behavior and Redis key/TTL contract in `protocol/http-v0.md`.
- [x] Generate a portable HTTP parser corpus from the fixed signed request, including missing/duplicate metadata, extra components/parameters, algorithm/tag changes, malformed signatures, leading-zero integers and header-count limits.
- [x] Preserve the foundation worktree and create branch `codex/appguard-server-sdks` for this stage.

## Task 2: Python SDK and Framework Integration

**Files:** `sdk/python/pyproject.toml`, `uv.lock`, `src/appguard/{types,canonical,crypto,verify,replay,wire,asgi}.py`, `src/appguard/{fastapi,django,flask}.py`, `tests/**`; compatibility shims and local source dependency in `reference/python`.

**Interfaces:** Promote the proven core into `appguard` without duplicating it; `appguard_reference` re-exports it for compatibility. `parse_signatures(headers) -> ParsedSignature`. `AppGuardMiddleware(app, *, app_id, origin, identity_resolver, replay, clock, allow_insecure_transport=False)` is pure ASGI and resolves `Identity(subject, key)` from trusted application logic. Adapters must not invent a raw target from decoded path. Flask support deploys WsgiToAsgi behind the ASGI verifier, retaining the original ASGI evidence before WSGI normalization.

- [x] Write failing shared-wire corpus tests and actual FastAPI/Django/Flask request tests: valid request, body echo, tampered body, token callback rejection, missing raw_path, duplicate metadata, insecure request, oversize/chunked body, store and identity failure.
- [x] Run tests RED before implementing parser/middleware. Preserve all existing 209 reference tests through promotion.
- [x] Implement bounded capture and body replay, fixed error responses and a thread-safe synchronous verifier offloaded from the ASGI event loop. Fetch the trusted clock at verification, after authentication completes.
- [x] Add a Redis store using the common key/expiry contract; test live atomic claims with an isolated Redis test process and failures without real credentials.
- [x] Build a standalone wheel, install it in an isolated environment and import the package without a reference checkout dependency; run both Python suites frozen and commit only owned files.

## Task 3: Native Node SDK and Framework Integration

**Files:** `sdk/node/package.json`, lockfile, `src/**`, `test/**`, package README and declarations.

- [x] Write and observe failing tests against all core/HTTP vectors before implementing the verifier/wire parser.
- [x] Use native crypto with pinned P-256 and IEEE P1363 signatures; retain raw target/query and duplicate header pairs.
- [x] Implement Express middleware, a Fastify hook/plugin and NestJS-compatible middleware, installed before parsing/rewriting. Capture bounded raw bytes, restore/replay correctly, and require existing authentication/key-resolution callbacks plus a replay store.
- [x] Exercise each installed framework using real framework request handling: valid body access, mutation rejection, duplicate/missing metadata, async identity errors, insecure transport, body/stream limits and replay.
- [x] Implement common Redis claims and explicit local development store. Run live Redis tests when supplied the test URL; provide type declarations and npm pack/install smoke evidence. No publication.

## Task 4: Spring Boot Starter and Servlet Integration

**Files:** `sdk/spring-boot/pom.xml`, `src/main/java/io/appguard/**`, auto-configuration metadata, `src/test/**`, package README.

- [x] Write and observe failing tests for the shared core/HTTP corpora and framework behavior before implementation.
- [x] Use Java's supported P-256 verification with the fixed wire encoding; validate time, origin, app/subject/key, duplicate metadata and input limits consistently.
- [x] Implement a bounded request-body wrapper that replays bytes to MVC; require transport security, a trusted principal/identity resolver, trusted key resolver and replay store.
- [x] Provide explicit `appguard.enabled=true` auto-configuration; enabled-but-missing security dependencies must fail startup. Respect Spring Security ordering and never install a permissive key resolver or local store silently.
- [x] Test real Spring MVC handling and Boot auto-configuration, including unchanged body/parameters, duplicate fields, bad auth/store, limits, insecure transport, replay and missing dependencies. Test a real servlet container where feasible to expose transport normalization.
- [x] Implement common Redis store semantics, run live test-instance claims, and build the starter JAR locally. Record supported Boot/Java versions actually tested.

## Task 5: Cross-Language Verification and Review

- [x] Run every suite, including the 209-test reference baseline; verify core/HTTP vectors agree across languages.
- [x] Exercise same-scope Redis claims across independent SDK instances/processes against a disposable localhost service; never touch an existing Redis database.
- [x] Run standalone package/JAR builds and alternate-working-directory tests where relevant; add one reproducible root test command and record exact versions/results.
- [x] Update support matrix, installation/authentication integration examples, limitations and security guidance to match verified behavior.
- [ ] Obtain one fresh whole-change security review. Fix significant findings with failing regression tests first and rerun all affected suites.
- [ ] Commit tested results. Preserve the server-SDK branch for review; only the foundation merge has been explicitly requested so far.

## Scope Decisions

This executes the already-approved platform architecture and the user's explicit next-stage implementation request; it does not reopen that design. Strict wire parsing deliberately accepts a documented RFC 9421 subset, not arbitrary Structured Fields formatting. FastAPI and Django use ASGI; Flask is verified before WSGI conversion because ordinary WSGI loses duplicate header evidence. Redis is an optional external dependency and the SDK does not configure its eviction/durability/TLS. No enrollment, mobile SDK, remote publication, production certification or provider-service changes are included.
