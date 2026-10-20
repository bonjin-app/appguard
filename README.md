# AppGuard

Framework-independent, self-hostable app security. Apache-2.0 licensed.

**Status: experimental server SDKs implemented locally.** There are no published SDKs or production security claims. Spring Boot, Python and Node.js share one draft verification protocol, portable attack fixtures and Redis replay namespace. See the [approved design](docs/superpowers/specs/2026-10-20-appguard-foundation-design.md), [server SDK plan](docs/superpowers/plans/2026-10-20-appguard-server-sdks.md) and [verification scope](docs/security/server-sdk-verification.md).

## Architecture

- Client SDKs: platform evidence, installation keys, request binding and risk signals.
- Server SDKs: request verification, integration with existing authentication and authorization.
- Security Engine: common policy, reason codes and audit events; optional threat analytics.
- Build/CLI: future platform-specific protection, setup and diagnostics.

The core will run without an AI model, paid AI API, or mandatory AppGuard cloud service. Obfuscation and local risk signals are supporting defenses. The server remains responsible for authentication, authorization and data access.

## Support roadmap

| Component | Status |
| --- | --- |
| Draft protocol and Python reference | Implemented; locally tested, not production-ready |
| [Spring Boot 3.5 / Java 17](sdk/spring-boot/README.md) | Experimental starter, MVC filter and Redis adapter |
| [Python 3.11+](sdk/python/README.md) | Experimental ASGI verifier; FastAPI, Django ASGI, Flask through WsgiToAsgi |
| [Node.js 22+](sdk/node/README.md) | Experimental native verifier; Express, Fastify, NestJS and Redis adapter |
| Android, iOS, Unity, Expo/React Native, Flutter | Planned, not implemented |
| .NET, Go, PHP | Planned, not implemented |
| Shared Redis replay claims | Implemented; deployment durability/eviction guarantees are operator-owned |
| Key enrollment, Apple/Google attestation | Planned, not implemented |
| Build obfuscation, policy profiles, console, AI | Planned, not implemented |

## Local reference development

Install Python 3.11+ and [uv](https://docs.astral.sh/uv/). From the repository root:

```sh
uv sync --locked --project reference/python
uv run --project reference/python pytest reference/python/tests -q
```

The reference consumes parsed typed inputs and delegates to the Python SDK core. HTTP adapters additionally parse the strict [wire subset](protocol/http-v0.md). Existing token authentication and enrolled-key lookup must be supplied by the application; authorization still runs in the application. No token authenticator or platform-attestation provider is bundled. A verified signature does not grant permission.

## Server SDK verification

Install Python 3.11+, uv, Node.js 22+, Java 17 and Maven. Start a **new disposable Redis** instance bound to `127.0.0.1` on an unused port, with persistence disabled for testing. From any directory:

```sh
APPGUARD_TEST_REDIS_URL=redis://127.0.0.1:DISPOSABLE_PORT/0 \
  /absolute/path/to/appguard/scripts/test-server-sdks.sh
```

`APPGUARD_UV_CMD` and `APPGUARD_MAVEN_CMD` optionally select executable paths. The command uses frozen Python/npm lockfiles, runs all four suites including live Redis, builds the wheel/JAR and tests an isolated npm package install, then rotates the first nonce claim through Python/Node/Java and races independent SDK processes. It never flushes Redis and deletes only probe-owned keys. Never supply an existing shared Redis database. Individual SDK commands and tested versions are documented in their READMEs.

Adapters require unmodified raw target/header/body evidence and explicit identity/replay dependencies. Python needs a trusted exact-target extension when the query string is empty. Spring's servlet adapter rejects form/multipart content and nonblocking input access. Express/Nest must be installed first at application root; Fastify requires native HTTP request capture. TLS/proxy boundaries must preserve trusted evidence. These restrictions are described in each SDK's integration guide; the package alone does not configure a deployment.

## Common verification behavior

- Fixed-order RFC 9421 signature-base bytes with a restricted P-256/SHA-256 profile.
- Exact raw-body SHA-256 Content-Digest, including empty and binary bodies.
- Timestamp/lifetime/skew limits, app/key/authenticated-subject binding and key revocation.
- Atomic nonce claims after verification, bounded explicit local stores, Redis concurrency and fail-closed backend errors.
- [40 portable request scenarios](conformance/v0/requests.json) and [43 HTTP-envelope scenarios](conformance/v0/http.json) covering substitutions, profile/encoding ambiguity, expiry, duplicate metadata and replay.

Tests use synthetic data and fixed clocks, not the current wall-clock time. Four distinct committed signature/base pairs are also checked with the system OpenSSL CLI when available. This check is explicitly skipped when that executable is absent; the normal cryptography-based verifier tests still run.

The Python core entry point is `appguard.verify.verify_request`; `appguard_reference` retains compatibility imports. The [reference tests](reference/python/tests/test_verify.py) show caller-supplied trusted context and test-only signing. No production signing/enrollment API is included. Reuse replay stores across requests. In-memory stores lose state on restart; shared Redis requires an explicit capacity, retention and recovery policy.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), the [threat model](docs/security/threat-model.md), and the [draft protocol](protocol/request-v0.md). Publish no real secrets or production key material in issues, fixtures or logs.

Project-authored code and documentation are licensed under [Apache-2.0](LICENSE). Dependency and third-party licenses remain their own.
