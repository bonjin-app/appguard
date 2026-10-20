# AppGuard

Framework-independent, self-hostable app security. Apache-2.0 licensed.

**Status: experimental foundation implemented.** There are no published SDKs or production security claims. This milestone supplies a draft request-verification contract, a Python reference verifier, and portable attack fixtures. See the [approved design](docs/superpowers/specs/2026-10-20-appguard-foundation-design.md) and [implementation plan](docs/superpowers/plans/2026-10-20-appguard-protocol-foundation.md).

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
| Spring Boot, Python middleware, Node.js | Planned, not implemented |
| Android, iOS, Unity, Expo/React Native, Flutter | Planned, not implemented |
| .NET, Go, PHP | Planned, not implemented |
| Distributed replay store, key enrollment, Apple/Google attestation | Planned, not implemented |
| Build obfuscation, policy profiles, console, AI | Planned, not implemented |

## Local reference development

Install Python 3.11+ and [uv](https://docs.astral.sh/uv/). From the repository root:

```sh
uv sync --locked --project reference/python
uv run --project reference/python pytest reference/python/tests -q
```

The reference consumes parsed typed inputs, not raw HTTP signature headers. It is not middleware, a token authenticator, an attestation verifier, or a production multi-server security layer. Its local replay store protects only one process. A verified signature does not grant permission.

## What this milestone verifies

- Fixed-order RFC 9421 signature-base bytes with a restricted P-256/SHA-256 profile.
- Exact raw-body SHA-256 Content-Digest, including empty and binary bodies.
- Timestamp/lifetime/skew limits, app/key/authenticated-subject binding and key revocation.
- Atomic single-process nonce claims after verification, including 32-thread races and fail-closed store failures/capacity.
- Strict fixture transport and [40 portable scenarios](conformance/v0/requests.json) covering substitutions, profile/encoding ambiguity, expiry and replay.

Tests use synthetic data and fixed clocks, not the current wall-clock time. Four distinct committed signature/base pairs are also checked with the system OpenSSL CLI when available. This check is explicitly skipped when that executable is absent; the normal cryptography-based verifier tests still run.

The callable entry point is `appguard_reference.verify.verify_request`; its typed inputs are in `appguard_reference.types`. The [tests](reference/python/tests/test_verify.py) show caller-supplied trusted context and test-only signing. No production signing/enrollment API is included. Never create a new replay store per request: reuse it for the process lifetime, and remember that restart loses its state.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), the [threat model](docs/security/threat-model.md), and the [draft protocol](protocol/request-v0.md). Publish no real secrets or production key material in issues, fixtures or logs.

Project-authored code and documentation are licensed under [Apache-2.0](LICENSE). Dependency and third-party licenses remain their own.
