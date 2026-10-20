# AppGuard

Framework-independent, self-hostable app security. Apache-2.0 licensed.

**Status: draft foundation under development.** There are no published SDKs or production security claims. The first milestone is a common request-verification contract, a Python reference verifier, and portable attack fixtures. See the [approved design](docs/superpowers/specs/2026-10-20-appguard-foundation-design.md) and [implementation plan](docs/superpowers/plans/2026-10-20-appguard-protocol-foundation.md).

## Architecture

- Client SDKs: platform evidence, installation keys, request binding and risk signals.
- Server SDKs: request verification, integration with existing authentication and authorization.
- Security Engine: common policy, reason codes and audit events; optional threat analytics.
- Build/CLI: future platform-specific protection, setup and diagnostics.

The core will run without an AI model, paid AI API, or mandatory AppGuard cloud service. Obfuscation and local risk signals are supporting defenses. The server remains responsible for authentication, authorization and data access.

## Support roadmap

| Component | Status |
| --- | --- |
| Draft protocol and Python reference | In development |
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

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), the [threat model](docs/security/threat-model.md), and the [draft protocol](protocol/request-v0.md). Publish no real secrets or production key material in issues, fixtures or logs.

Project-authored code and documentation are licensed under [Apache-2.0](LICENSE). Dependency and third-party licenses remain their own.
