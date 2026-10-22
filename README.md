# AppGuard

[English](README.md) | [한국어](README.ko.md) | [日本語](README.ja.md) | [简体中文](README.zh-CN.md)

Framework-independent, self-hostable app security. Apache-2.0 licensed.

**Status: experimental client/server SDKs and Build/CLI implemented locally.** No SDK packages have been published to package registries, and no production security claims are made. Android/iOS signing interoperates with Spring Boot, Python, Node.js, ASP.NET Core, Go and PHP using one draft protocol. Framework bridges package the native signing boundary; Python additionally provides explicit local enrollment and optional experimental Apple/Google verification backends. See the [approved design](docs/superpowers/specs/2026-10-20-appguard-foundation-design.md) and the [server](docs/security/server-sdk-verification.md), [native](docs/security/mobile-foundation-verification.md), [bridge/Build](docs/security/client-bridges-build-verification.md), [extended server](docs/security/extended-server-verification.md) and [provider](docs/security/provider-verification.md) evidence boundaries.

See the [completed local milestone and remaining roadmap](docs/security/local-milestone-verification.md) and [subsequent boundary hardening](docs/security/hardening-verification.md) for verification, fixes and explicit deferred scope.

The [native local risk stage](docs/security/local-risk-verification.md) adds optional
Android/iOS tamper, root and hook hints with explicit unavailable states. These
observations supplement server checks; they do not establish device integrity.
The [framework risk bridge stage](docs/security/risk-bridges-verification.md) exposes
the same reports through Unity, Expo/React Native and Flutter async APIs.

<a id="installation"></a>
## Installation

Packages are **experimental and not published to npm, PyPI, Maven Central,
NuGet, Packagist or pub.dev**. Build/install from this checkout; the versions
below are local artifact identities, not registry releases. Choose the SDKs you
need. Installing a client SDK does not install a server integration automatically.

The shell examples use macOS/Linux syntax. Install each selected platform's
normal toolchain first, activate your Python virtual environment when using pip,
and replace `/path/to/...` and `/absolute/path/to/...` with your own paths.
Android/iOS builds require their SDKs; iOS builds require macOS and Xcode.

```sh
git clone https://github.com/bonjin-app/appguard.git
cd appguard
export APPGUARD_REPO="$PWD"
umask 077
export APPGUARD_PACKAGES="$(mktemp -d)"
```

| Component | Requirements | Install guide |
| --- | --- | --- |
| Spring Boot | Java 17, Maven; Boot 4.1.1 Servlet/MVC | [Starter](#install-spring) |
| Python | Python 3.11+; FastAPI, Django ASGI or Flask through ASGI | [Python SDK](#install-python) |
| Node.js | Node 22+; ESM; Express, Fastify or NestJS/Express | [Node SDK](#install-node) |
| ASP.NET Core | .NET SDK 10.0.402 / ASP.NET Core 10 | [.NET SDK](#install-dotnet) |
| Go | Go 1.26+; `net/http` | [Go module](#install-go) |
| PHP | 64-bit PHP 8.2+, OpenSSL/hash/JSON, Composer | [PHP SDK](#install-php) |
| Android | Java 17, Android SDK 36/build-tools 35.0.0; app API 26+ | [Android AAR](#install-android) |
| Apple | SwiftPM; iOS 15+ / macOS 13+ | [Apple package](#install-apple) |
| Unity | Unity 6000; Android 26+ / iOS 15+ | [Staged UPM package](#install-unity) |
| Expo / React Native | Expo SDK 58 + Expo Modules; Node 22.13+; Android 26+ / iOS 16.4+ | [Native npm package](#install-expo) |
| Flutter | Flutter 3.27+, Dart >=3.6 and <4.0; Android 26+ / iOS 15+ | [Staged Flutter plugin](#install-flutter) |
| Build / CLI | Node 22+ and the selected app's build tools | [CLI](#install-cli) |

<a id="install-spring"></a>
### Spring Boot

Build and install the starter into your local Maven repository:

```sh
mvn -f "$APPGUARD_REPO/sdk/spring-boot/pom.xml" install
```

Add this dependency to your application's `pom.xml`:

```xml
<dependency>
  <groupId>io.appguard</groupId>
  <artifactId>appguard-spring-boot-starter</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

For Gradle Kotlin DSL, use the local Maven repository:

```kotlin
repositories { mavenLocal(); mavenCentral() }
dependencies { implementation("io.appguard:appguard-spring-boot-starter:0.1.0-SNAPSHOT") }
```

Enable AppGuard and supply your application's `IdentityResolver` and `ReplayStore`
beans. Authentication and authorization remain application responsibilities.
See [Spring Boot configuration](sdk/spring-boot/README.md). The live Redis test
is skipped unless a dedicated disposable `APPGUARD_REDIS_URL` is supplied.

<a id="install-python"></a>
### Python — FastAPI, Django and Flask

In your application's virtual environment, choose the matching extras:

```sh
python3 -m pip install "$APPGUARD_REPO/sdk/python[fastapi,redis]"
python3 -m pip install "$APPGUARD_REPO/sdk/python[django,redis]"
python3 -m pip install "$APPGUARD_REPO/sdk/python[flask,redis]"
```

Use `appguard.fastapi.AppGuardMiddleware`,
`appguard.django.protect_django`, or `appguard.flask.protect_flask` as appropriate.
Django uses its ASGI app; Flask must run through the supplied ASGI bridge rather
than plain WSGI. Supply trusted authentication/key lookup, replay storage and raw
request evidence. See [Python integration](sdk/python/README.md).

<a id="install-node"></a>
### Node.js — Express, Fastify and NestJS

```sh
npm pack "$APPGUARD_REPO/sdk/node" --ignore-scripts --pack-destination "$APPGUARD_PACKAGES"
cd /path/to/node-app
npm install "$APPGUARD_PACKAGES/appguard-server-0.0.0-experimental.0.tgz"
```

Import `expressMiddleware`, `installFastify`, or `nestMiddleware` from
`@appguard/server`. Supply your own framework, authenticator, enrolled-key lookup
and replay store. ESM is supported; CommonJS `require` is not. NestJS uses its
Express platform. See [Node integration and install order](sdk/node/README.md).

<a id="install-dotnet"></a>
### .NET / ASP.NET Core

```sh
(cd "$APPGUARD_REPO/sdk/dotnet" && ./scripts/verify.sh)
cd /path/to/dotnet-app
dotnet add package AppGuard.Experimental --version 0.0.0-experimental.1 \
  --source "$APPGUARD_REPO/sdk/dotnet/artifacts"
```

The package targets .NET 10. Provide trusted original-header capture through
`IAppGuardRawHeadersFeature`, authentication, key lookup and a replay store.
Parsed Kestrel headers alone are insufficient. See [ASP.NET Core integration](sdk/dotnet/README.md).

<a id="install-go"></a>
### Go

In an existing Go module, use a local replacement:

```sh
cd /path/to/go-app
go mod edit -require=github.com/bonjin-app/appguard/sdk/go@v0.0.0
go mod edit -replace=github.com/bonjin-app/appguard/sdk/go="$APPGUARD_REPO/sdk/go"
```

`v0.0.0` here is a local replacement placeholder, not a published version. Import
`github.com/bonjin-app/appguard/sdk/go` in your code, then run `go mod tidy`.
The middleware needs a trusted pre-parser `EvidenceSource`; parsed `http.Header`
cannot reconstruct that evidence. See [Go integration](sdk/go/README.md).

<a id="install-php"></a>
### PHP

```sh
cd /path/to/php-app
composer config repositories.appguard path "$APPGUARD_REPO/sdk/php"
composer require "appguard/server:*@dev"
```

Load `vendor/autoload.php` and configure `AppGuard\HttpAdapter` with trusted
raw ingress evidence, authentication/key callbacks and an atomic replay backend.
This is a native callback adapter; Laravel/Symfony/FPM integration is not claimed.
See [PHP integration](sdk/php/README.md).

<a id="install-android"></a>
### Android — Kotlin / Java

```sh
(cd "$APPGUARD_REPO/sdk/android" && ./gradlew --no-daemon assembleRelease)
```

Add the generated local AAR to the app's Gradle dependencies; adapt the absolute
path to your checkout:

```kotlin
dependencies {
    implementation(files("/absolute/path/to/appguard/sdk/android/build/outputs/aar/appguard-android-release.aar"))
}
```

Set the app's minimum SDK to 26+. The SDK supplies Keystore-backed signing and
optional local risk hints; it does not send HTTP requests or enroll keys for you.
See [Android setup and key policy](sdk/android/README.md).

Google Play Integrity acquisition is a separate optional module:

```sh
(cd "$APPGUARD_REPO/sdk/android-play-integrity" && ./gradlew --no-daemon assembleRelease)
```

Its AAR is `sdk/android-play-integrity/build/outputs/aar/appguard-android-play-integrity-release.aar`.
When consuming that AAR directly, also add the official
`com.google.android.play:integrity:1.6.0` dependency. Google project/distribution
configuration and authenticated server verification are separate requirements.
See [Play Integrity module](sdk/android-play-integrity/README.md).

<a id="install-apple"></a>
### iOS / macOS — Swift

In Xcode, choose **File → Add Package Dependencies → Add Local**, select
`$APPGUARD_REPO/sdk/apple`, and add the `AppGuardApple` product to your app target.
For a Swift package, the local dependency is:

```swift
.package(path: "/absolute/path/to/appguard/sdk/apple")
```

Import `AppGuardApple`. Configure the app's signing/entitlements and authenticated
key enrollment separately; App Attest needs matching app/environment setup.
See [Apple SDK integration](sdk/apple/README.md).

<a id="install-unity"></a>
### Unity

Stage a standalone source package, then build its native dependencies:

```sh
python3 "$APPGUARD_REPO/sdk/unity/Tools~/stage.py" --destination "$APPGUARD_PACKAGES/unity"
(cd "$APPGUARD_PACKAGES/unity" && python3 Tools~/build-native.py --platform all)
```

Choose `--platform android` or `--platform ios` instead of `all` when appropriate.
For Android, configure `JAVA_HOME` for Java 17 and `ANDROID_HOME` for Android
SDK 36 with build-tools 35.0.0. For iOS, install Xcode on macOS.
In Unity Package Manager, select **Add package from disk** and choose the staged
`$APPGUARD_PACKAGES/unity/package.json`. Native builds are required; adding this
repository's C# source alone is insufficient. See [Unity installation](sdk/unity/README.md).

<a id="install-expo"></a>
### Expo / React Native

```sh
npm --prefix "$APPGUARD_REPO/sdk/expo" ci --ignore-scripts
(cd "$APPGUARD_REPO/sdk/expo" && npm pack --pack-destination "$APPGUARD_PACKAGES")
cd /path/to/expo-app
npx expo install "$APPGUARD_PACKAGES/appguard-expo-0.0.0-experimental.1.tgz"
```

Merge `"@appguard/expo"` into your existing `expo.plugins` list, then rebuild your
development/native app and install iOS pods as appropriate. Packing stages native
sources and compiles TypeScript; do not bypass its `prepack` step. React Native
apps require Expo Modules integration. Expo Go and web are unsupported, and an
OTA update cannot add this native module. See [Expo / React Native installation](sdk/expo/README.md).

<a id="install-flutter"></a>
### Flutter

```sh
python3 "$APPGUARD_REPO/sdk/flutter/tool/pack.py" --output "$APPGUARD_PACKAGES/appguard_flutter.tar.gz"
mkdir "$APPGUARD_PACKAGES/flutter"
tar -xzf "$APPGUARD_PACKAGES/appguard_flutter.tar.gz" -C "$APPGUARD_PACKAGES/flutter"
```

Merge a path dependency into the consuming app's `pubspec.yaml`, replacing the
example path with the expanded value of `$APPGUARD_PACKAGES/flutter`:

```yaml
dependencies:
  appguard_flutter:
    path: /absolute/path/to/staged/flutter
flutter:
  config:
    enable-swift-package-manager: false
```

Run `flutter pub get` in the app, install iOS pods where needed, and rebuild it.
The plugin currently uses CocoaPods; the setting above selects it per project
rather than changing global Flutter settings. Set Android minSdk 26 and iOS
15.0+. See [Flutter installation](sdk/flutter/README.md).

<a id="install-cli"></a>
### Build / CLI

Run directly from the checkout with Node 22+:

```sh
node "$APPGUARD_REPO/tools/cli/bin/appguard.js" init --project /path/to/app --app-id your-app
node "$APPGUARD_REPO/tools/cli/bin/appguard.js" doctor --project /path/to/app --check
node "$APPGUARD_REPO/tools/cli/bin/appguard.js" build --project /path/to/app --dry-run
```

Or install a local tarball in your project's development dependencies:

```sh
npm pack "$APPGUARD_REPO/tools/cli" --ignore-scripts --pack-destination "$APPGUARD_PACKAGES"
cd /path/to/app
npm install --save-dev "$APPGUARD_PACKAGES/appguard-cli-0.0.0-experimental.0.tgz"
npx --no-install appguard --help
```

The CLI covers Android R8, Expo export, Flutter Android APK obfuscation and
explicit encrypted mapping retention. It does not install SDKs, configure
Apple/Google accounts or select signing credentials. iOS/Unity build adapters,
a console and AI analytics remain outside this CLI's implemented scope.
See [CLI commands and limits](tools/cli/README.md).

### After installation

Connect your existing authentication and resource authorization, enroll trusted
public keys, preserve exact request bytes and configure a long-lived shared
atomic replay store. Configure provider services only if you adopt those optional
backends. Local root/hook/tamper hints and obfuscation are supporting defenses,
not proof of device integrity. Follow each SDK's integration guide before
protecting production traffic.

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
| [Spring Boot 4.1.1 / Java 17](sdk/spring-boot/README.md) | Experimental starter, MVC filter and Redis adapter |
| [Python 3.11+](sdk/python/README.md) | Experimental ASGI verifier; FastAPI, Django ASGI, Flask through WsgiToAsgi |
| [Node.js 22+](sdk/node/README.md) | Experimental native verifier; Express, Fastify, NestJS and Redis adapter |
| [Android Java/Kotlin](sdk/android/README.md) | Native signer, Keystore and enrollment proofs; AAR/JVM tests/API35 emulator checks |
| [Apple Swift/iOS](sdk/apple/README.md) | Native signer, Security key adapter, enrollment proofs and App Attest acquisition wrapper; host tests/unsigned Simulator build |
| [Unity UPM](sdk/unity/README.md) | Typed JNI/C ABI package and async local risk API; [138 EditMode tests](sdk/unity/STRICT_JSON_VERIFICATION.md), [Android Release and iOS Simulator IL2CPP runtime checks](sdk/unity/PLAYER_RUNTIME_VERIFICATION.md), unsigned iOS device Release build; physical-device runtime pending |
| [Expo / React Native](sdk/expo/README.md) | Expo58 async native module;61 tests,40-file relocation, packed Android and unsigned arm64 Simulator CocoaPods compile; engine/device runtime pending |
| [Flutter](sdk/flutter/README.md) | Async platform-channel local risk API;64 tests, background queue/native adapter checks and Simulator library compile; engine/device runtime pending |
| [ASP.NET Core](sdk/dotnet/README.md) | Experimental strict verifier/middleware; mandatory original-header feature;238 tests and isolated NuGet consumer |
| [Go net/http](sdk/go/README.md) | Experimental verifier/middleware; race/vet and isolated consumer; trusted pre-parser evidence required |
| [PHP](sdk/php/README.md) | Experimental verifier/explicit ingress adapter;649 assertions and5 raw loopback requests; no Laravel/Symfony integration claim |
| Shared Redis replay claims | Implemented; deployment durability/eviction guarantees are operator-owned |
| [Enrollment / policy / audit](docs/security/enrollment-policy.md) | Python SQLite challenge/proof/key and subject-wide revocation; all six server languages pass deterministic42-case presets and allowlisted audit output |
| [Apple/Google provider verification](docs/security/provider-verification.md) | Experimental Python verification, explicit OAuth refresh, Apple assertions and atomic verified-receipt enrollment; [lifecycle details](docs/security/apple-enrollment.md). Genuine device/account verification pending |
| [Build / CLI](tools/cli/README.md) | Android R8 setup/build; Flutter obfuscation/Expo minification commands; encrypted mapping archive/verify/restore; local prerequisite/CI checks, strict UTF-8 preservation and actual isolated Android release build |
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

For the Go/.NET/PHP runner, GitHub Actions workflow and verification boundaries, see [continuous integration](docs/development/continuous-integration.md). Extended SDK in-memory replay stores are process-local; multi-worker deployments require a real tested shared store.

## Native client and enrollment development

The [Android](sdk/android/README.md) and [Apple](sdk/apple/README.md) packages prepare exact request bytes and fixed wire headers using per-installation P-256 signing capabilities. They expose public SPKI material, not a private-key export API. No HTTP transport adapter is bundled: application transports must preserve the signed target/body/headers and prevent unintended redirects. Local hardware-status metadata is not remotely verified attestation.

The [enrollment protocol](protocol/enrollment-v0.md) binds app, authenticated subject, enrolled key ID, public-key fingerprint, origin and one-use expiry. [Python integration](docs/security/enrollment-policy.md) requires existing authentication and an explicit provider verifier for Balanced/Strict. Proof-only Basic enrollment remains explicitly unattested. Python, Node, Java, .NET, Go and PHP execute the [policy contract's42 portable cases](protocol/policy-v0.md). These explicit APIs consume trusted application verdicts; no profile installs authentication, provider verification or rate counters automatically.

Native tests distinguish JVM/macOS crypto, platform builds and an isolated Android software-keystore emulator. Actual Apple persistent Keychain/Secure Enclave, physical devices and successful provider evidence remain unverified. No Apple/Google project, entitlement, account, release or user key is configured by these tests.

The [bridge contract](protocol/client-bridge-v0.md) exposes only public-key lookup, validated request preparation and enrollment possession proof. Stage each framework package's native sources before local installation as documented; installing a JS/Dart/C# wrapper alone cannot add native code to Expo Go or an existing binary. No transport, provider verdict or arbitrary signing/private-key export is exposed. Packages preserve exact body/target/header values; the application must verify actual HTTP behavior.

For a supported local app project, `node tools/cli/bin/appguard.js init --project /path/to/app --app-id your-app` creates explicit configuration. `doctor` (read-only local prerequisites), `doctor --check` (CI exit status), `policy validate`, `build --dry-run`, `archive`, `verify-archive` and `restore` are documented in the [CLI guide](tools/cli/README.md). Setup does not install or publish SDK dependencies or configure provider accounts. Keep original build mappings private as well as their encrypted archives.

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

## Non-device production qualification

All six server SDKs now offer an explicitly configured shared Redis replay adapter.
Spring Boot defaults to **4.1.1 / Java 17**; the explicit `legacy-boot3.5` source
profile is a compatibility check, not the maintained production baseline.

Python adds [atomic Apple enrollment and receipt state](docs/security/apple-enrollment.md),
[assertions and counters](docs/security/apple-lifecycle.md),
[CMS receipt verification/refresh](docs/security/apple-receipts.md), and an explicit
[Google service-account token provider](docs/security/google-provider.md).
For the optional direct-TLS server and receipt parser, install in your application environment:

```sh
python3 -m pip install "$APPGUARD_REPO/sdk/python[server,apple,redis]"
```

Use the [TLS ingress guide and executable example](docs/deployment/python-ingress.md).
After building both server runners against the same **new disposable loopback Redis**,
`uv run --frozen --project sdk/python python scripts/check_cross_sdk_replay.py --extended`
checks all six SDKs against one replay namespace. The qualification runner creates
its own Redis before crash, outage, capacity and load tests; it accepts no external
Redis URL. [Commands, evidence and operating limits](docs/development/nondevice-readiness.md).

[Candidate/SBOM/checksum/vulnerability/secret/license automation](docs/development/release-readiness.md)
prepares unpublished source candidates. Passing automated checks still leaves
license review, independent audit, actual provider/account integration, deployment
qualification and maintainer release approval outstanding. Physical devices remain
pending and outside this qualification. This is not an audited production release.
