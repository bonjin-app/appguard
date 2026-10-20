# AppGuard

Framework-independent, self-hostable app security. Apache-2.0 licensed.

**Status: experimental client/server SDKs and Build/CLI implemented locally.** There are no published SDKs or production security claims. Android/iOS signing interoperates with Spring Boot, Python, Node.js, ASP.NET Core, Go and PHP using one draft protocol. Framework bridges package the native signing boundary; Python additionally provides explicit local enrollment and optional experimental Apple/Google verification backends. See the [approved design](docs/superpowers/specs/2026-10-20-appguard-foundation-design.md) and the [server](docs/security/server-sdk-verification.md), [native](docs/security/mobile-foundation-verification.md), [bridge/Build](docs/security/client-bridges-build-verification.md), [extended server](docs/security/extended-server-verification.md) and [provider](docs/security/provider-verification.md) evidence boundaries.

See the [completed local milestone and remaining roadmap](docs/security/local-milestone-verification.md) and [subsequent boundary hardening](docs/security/hardening-verification.md) for verification, fixes and explicit deferred scope.

The [native local risk stage](docs/security/local-risk-verification.md) adds optional
Android/iOS tamper, root and hook hints with explicit unavailable states. These
observations supplement server checks; they do not establish device integrity.
The [framework risk bridge stage](docs/security/risk-bridges-verification.md) exposes
the same reports through Unity, Expo/React Native and Flutter async APIs.

## Architecture

- Client SDKs: native installation keys and request binding; Apple evidence wrapper and optional Android Play Integrity acquisition; provider configuration remains explicit.
- Server SDKs: request verification, integration with existing authentication and authorization.
- Security Engine: common policy, reason codes and audit events; optional threat analytics.
- Build/CLI: project setup/diagnostics, platform build commands and encrypted mapping retention.

The core will run without an AI model, paid AI API, or mandatory AppGuard cloud service. Obfuscation and local risk signals are supporting defenses. The server remains responsible for authentication, authorization and data access.

## Support roadmap

| Component | Status |
| --- | --- |
| Draft protocol and Python reference | Implemented; locally tested, not production-ready |
| [Spring Boot 3.5 / Java 17](sdk/spring-boot/README.md) | Experimental starter, MVC filter and Redis adapter |
| [Python 3.11+](sdk/python/README.md) | Experimental ASGI verifier; FastAPI, Django ASGI, Flask through WsgiToAsgi |
| [Node.js 22+](sdk/node/README.md) | Experimental native verifier; Express, Fastify, NestJS and Redis adapter |
| [Android Java/Kotlin](sdk/android/README.md) | Native signer, Keystore and enrollment proofs; AAR/JVM tests/API35 emulator checks |
| [Apple Swift/iOS](sdk/apple/README.md) | Native signer, Security key adapter, enrollment proofs and App Attest acquisition wrapper; host tests/unsigned Simulator build |
| [Unity UPM](sdk/unity/README.md) | Typed JNI/C ABI package and async local risk API; [138 EditMode tests](sdk/unity/STRICT_JSON_VERIFICATION.md), [Android Release and iOS Simulator IL2CPP runtime checks](sdk/unity/PLAYER_RUNTIME_VERIFICATION.md), unsigned iOS device Release build; physical-device runtime pending |
| [Expo / React Native](sdk/expo/README.md) | Expo58 async native module;61 tests,44-file relocation, packed Android and unsigned arm64 Simulator CocoaPods compile; engine/device runtime pending |
| [Flutter](sdk/flutter/README.md) | Async platform-channel local risk API;64 tests, background queue/native adapter checks and Simulator library compile; engine/device runtime pending |
| [ASP.NET Core](sdk/dotnet/README.md) | Experimental strict verifier/middleware; mandatory original-header feature;175 tests and isolated NuGet consumer |
| [Go net/http](sdk/go/README.md) | Experimental verifier/middleware; race/vet and isolated consumer; trusted pre-parser evidence required |
| [PHP](sdk/php/README.md) | Experimental verifier/explicit ingress adapter;514 assertions and5 raw loopback requests; no Laravel/Symfony integration claim |
| Shared Redis replay claims | Implemented; deployment durability/eviction guarantees are operator-owned |
| [Enrollment / policy / audit](docs/security/enrollment-policy.md) | Python SQLite challenge/proof/revocation; all six server languages pass deterministic42-case presets and allowlisted audit output |
| [Apple/Google provider verification](docs/security/provider-verification.md) | Experimental Python backends;223 offline provider tests and Android acquisition module. Genuine current-device/account verification pending; Apple lifecycle incomplete |
| [Build / CLI](tools/cli/README.md) | Android R8 setup/build; Flutter obfuscation/Expo minification commands; encrypted mapping archive/restore.19 tests and actual isolated Android release build |
| [Local root/hook/jailbreak hints](protocol/local-risk-v0.md) | Experimental Android/iOS typed scanners; host tests and platform builds; physical rooted/hooked-device efficacy unverified |
| Optional console / AI | Planned, not implemented; core works without either |

## Local reference development

Install Python 3.11+ and [uv](https://docs.astral.sh/uv/). From the repository root:

```sh
uv sync --locked --project reference/python
uv run --project reference/python pytest reference/python/tests -q
```

The reference consumes parsed typed inputs and delegates to the Python SDK core. HTTP adapters additionally parse the strict [wire subset](protocol/http-v0.md). Existing token authentication and enrolled-key lookup must be supplied by the application; authorization still runs in the application. No user-token authenticator is bundled; optional provider backends require explicit trusted configuration. A verified signature does not grant permission.

## Server SDK verification

Install Python 3.11+, uv, Node.js 22+, Java 17 and Maven. Start a **new disposable Redis** instance bound to `127.0.0.1` on an unused port, with persistence disabled for testing. From any directory:

```sh
APPGUARD_TEST_REDIS_URL=redis://127.0.0.1:DISPOSABLE_PORT/0 \
  /absolute/path/to/appguard/scripts/test-server-sdks.sh
```

`APPGUARD_UV_CMD` and `APPGUARD_MAVEN_CMD` optionally select executable paths. The command uses frozen Python/npm lockfiles, runs all four suites including live Redis, builds the wheel/JAR and tests an isolated npm package install, then rotates the first nonce claim through Python/Node/Java and races independent SDK processes. It never flushes Redis and deletes only probe-owned keys. Never supply an existing shared Redis database. Individual SDK commands and tested versions are documented in their READMEs.

Adapters require unmodified raw target/header/body evidence and explicit identity/replay dependencies. Python needs a trusted exact-target extension when the query string is empty. Spring's servlet adapter rejects form/multipart content and nonblocking input access. Express/Nest must be installed first at application root; Fastify requires native HTTP request capture. TLS/proxy boundaries must preserve trusted evidence. These restrictions are described in each SDK's integration guide; the package alone does not configure a deployment.

For the Go/.NET/PHP runner and the locally validated, unexecuted remote CI configuration, see [continuous integration](docs/development/continuous-integration.md). Extended SDK in-memory replay stores are process-local; multi-worker deployments require a real tested shared store.

## Native client and enrollment development

The [Android](sdk/android/README.md) and [Apple](sdk/apple/README.md) packages prepare exact request bytes and fixed wire headers using per-installation P-256 signing capabilities. They expose public SPKI material, not a private-key export API. No HTTP transport adapter is bundled: application transports must preserve the signed target/body/headers and prevent unintended redirects. Local hardware-status metadata is not remotely verified attestation.

The [enrollment protocol](protocol/enrollment-v0.md) binds app, authenticated subject, enrolled key ID, public-key fingerprint, origin and one-use expiry. [Python integration](docs/security/enrollment-policy.md) requires existing authentication and an explicit provider verifier for Balanced/Strict. Proof-only Basic enrollment remains explicitly unattested. Python, Node, Java, .NET, Go and PHP execute the [policy contract's42 portable cases](protocol/policy-v0.md). These explicit APIs consume trusted application verdicts; no profile installs authentication, provider verification or rate counters automatically.

Native tests distinguish JVM/macOS crypto, platform builds and an isolated Android software-keystore emulator. Actual Apple persistent Keychain/Secure Enclave, physical devices and successful provider evidence remain unverified. No Apple/Google project, entitlement, account, release or user key is configured by these tests.

The [bridge contract](protocol/client-bridge-v0.md) exposes only public-key lookup, validated request preparation and enrollment possession proof. Stage each framework package's native sources before local installation as documented; installing a JS/Dart/C# wrapper alone cannot add native code to Expo Go or an existing binary. No transport, provider verdict or arbitrary signing/private-key export is exposed. Packages preserve exact body/target/header values; the application must verify actual HTTP behavior.

For a supported local app project, `node tools/cli/bin/appguard.js init --project /path/to/app --app-id your-app` creates explicit configuration. `doctor`, `policy validate`, `build --dry-run`, `archive` and `restore` are documented in the [CLI guide](tools/cli/README.md). Setup does not install or publish SDK dependencies or configure provider accounts. Keep original build mappings private as well as their encrypted archives.

## Common verification behavior

- Fixed-order RFC 9421 signature-base bytes with a restricted P-256/SHA-256 profile.
- Exact raw-body SHA-256 Content-Digest, including empty and binary bodies.
- Timestamp/lifetime/skew limits, app/key/authenticated-subject binding and key revocation.
- Atomic nonce claims after verification, bounded explicit local stores, Redis concurrency and fail-closed backend errors.
- [40 portable request scenarios](conformance/v0/requests.json) and [43 HTTP-envelope scenarios](conformance/v0/http.json) covering substitutions, profile/encoding ambiguity, expiry, duplicate metadata and replay.

Tests use synthetic data and fixed clocks, not the current wall-clock time. Four distinct committed signature/base pairs are also checked with the system OpenSSL CLI when available. This check is explicitly skipped when that executable is absent; the normal cryptography-based verifier tests still run.

The Python core entry point is `appguard.verify.verify_request`; `appguard_reference` retains compatibility imports. The [reference tests](reference/python/tests/test_verify.py) show caller-supplied trusted context and test-only signing. No production signing API is included; enrollment remains the explicit experimental Python service. Reuse replay stores across requests. In-memory stores lose state on restart; shared Redis requires an explicit capacity, retention and recovery policy.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), the [threat model](docs/security/threat-model.md), and the [draft protocol](protocol/request-v0.md). Publish no real secrets or production key material in issues, fixtures or logs.

Project-authored code and documentation are licensed under [Apache-2.0](LICENSE). Dependency and third-party licenses remain their own.
