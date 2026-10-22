# AppGuard

[English](README.md) | [한국어](README.ko.md) | [日本語](README.ja.md) | [简体中文](README.zh-CN.md)

프레임워크에 종속되지 않고 자체 호스팅할 수 있는 앱 보안 도구입니다. Apache-2.0 라이선스를 따릅니다.

**상태: 실험적 클라이언트/서버 SDK와 Build/CLI를 로컬에서 구현했습니다.** 패키지 레지스트리에 출시한 SDK 패키지는 없으며 프로덕션 보안 수준을 보장하지 않습니다. Android/iOS 서명은 하나의 초안 프로토콜로 Spring Boot, Python, Node.js, ASP.NET Core, Go, PHP와 상호 운용됩니다. 프레임워크 브리지는 네이티브 서명 경계를 패키지로 제공하며, Python은 명시적인 로컬 키 등록과 선택적인 실험적 Apple/Google 검증 백엔드도 제공합니다. [승인된 설계](docs/superpowers/specs/2026-10-20-appguard-foundation-design.md)와 [서버](docs/security/server-sdk-verification.md), [네이티브](docs/security/mobile-foundation-verification.md), [브리지/Build](docs/security/client-bridges-build-verification.md), [확장 서버](docs/security/extended-server-verification.md), [제공자](docs/security/provider-verification.md)의 검증 증거 범위를 참조하세요.

검증 결과, 수정 사항, 명시적으로 미룬 범위는 [완료된 로컬 마일스톤과 남은 로드맵](docs/security/local-milestone-verification.md), [후속 경계 강화](docs/security/hardening-verification.md)를 참조하세요.

[네이티브 로컬 위험 신호 단계](docs/security/local-risk-verification.md)는 사용 불가 상태를 명시하는 선택적
Android/iOS 변조, 루팅, 후킹 징후를 추가합니다. 이러한
관측 정보는 서버 검사를 보완하며 기기 무결성을 입증하지는 않습니다.
[프레임워크 위험 신호 브리지 단계](docs/security/risk-bridges-verification.md)는
Unity, Expo/React Native, Flutter의 비동기 API를 통해 동일한 보고서를 제공합니다.

<a id="installation"></a>
## 설치

패키지는 **실험적이며 npm, PyPI, Maven Central,
NuGet, Packagist, pub.dev에 공개 배포되지 않았습니다**. 이 체크아웃에서 빌드·설치하세요. 아래 버전은
레지스트리 릴리스가 아닌 로컬 산출물의 식별자입니다. 필요한 SDK를
선택하세요. 클라이언트 SDK를 설치해도 서버 연동이 자동으로 설치되지는 않습니다.

셸 예제는 macOS/Linux 문법을 사용합니다. 선택한 플랫폼의
일반적인 도구 모음을 먼저 설치하고, pip 사용 시 Python 가상 환경을 활성화한 뒤,
`/path/to/...`와 `/absolute/path/to/...`를 자신의 경로로 바꾸세요.
Android/iOS 빌드에는 해당 SDK가 필요하며, iOS 빌드에는 macOS와 Xcode가 필요합니다.

```sh
git clone https://github.com/bonjin-app/appguard.git
cd appguard
export APPGUARD_REPO="$PWD"
umask 077
export APPGUARD_PACKAGES="$(mktemp -d)"
```

| 구성 요소 | 요구 사항 | 설치 안내 |
| --- | --- | --- |
| Spring Boot | Java 17, Maven; Boot 4.1.1 Servlet/MVC | [스타터](#install-spring) |
| Python | Python 3.11+; FastAPI, Django ASGI 또는 ASGI를 통한 Flask | [Python SDK](#install-python) |
| Node.js | Node 22+; ESM; Express, Fastify 또는 NestJS/Express | [Node SDK](#install-node) |
| ASP.NET Core | .NET SDK 10.0.402 / ASP.NET Core 10 | [.NET SDK](#install-dotnet) |
| Go | Go 1.26+; `net/http` | [Go 모듈](#install-go) |
| PHP | 64비트 PHP 8.2+, OpenSSL/hash/JSON, Composer | [PHP SDK](#install-php) |
| Android | Java 17, Android SDK 36/build-tools 35.0.0; 앱 API 26+ | [Android AAR](#install-android) |
| Apple | SwiftPM; iOS 15+ / macOS 13+ | [Apple 패키지](#install-apple) |
| Unity | Unity 6000; Android 26+ / iOS 15+ | [네이티브 소스를 포함한 UPM 패키지](#install-unity) |
| Expo / React Native | Expo SDK 58 + Expo Modules; Node 22.13+; Android 26+ / iOS 16.4+ | [네이티브 npm 패키지](#install-expo) |
| Flutter | Flutter 3.27+, Dart >=3.6 및 <4.0; Android 26+ / iOS 15+ | [네이티브 소스를 포함한 Flutter 플러그인](#install-flutter) |
| Build / CLI | Node 22+ 및 선택한 앱의 빌드 도구 | [CLI](#install-cli) |

<a id="install-spring"></a>
### Spring Boot

스타터를 빌드하여 로컬 Maven 저장소에 설치하세요.

```sh
mvn -f "$APPGUARD_REPO/sdk/spring-boot/pom.xml" install
```

애플리케이션의 `pom.xml`에 다음 의존성을 추가하세요.

```xml
<dependency>
  <groupId>io.appguard</groupId>
  <artifactId>appguard-spring-boot-starter</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Gradle Kotlin DSL에서는 로컬 Maven 저장소를 사용하세요.

```kotlin
repositories { mavenLocal(); mavenCentral() }
dependencies { implementation("io.appguard:appguard-spring-boot-starter:0.1.0-SNAPSHOT") }
```

AppGuard를 활성화하고 애플리케이션의 `IdentityResolver`와 `ReplayStore`
빈을 제공하세요. 인증과 인가의 책임은 애플리케이션에 있습니다.
[Spring Boot 구성](sdk/spring-boot/README.md)을 참조하세요. 실제 Redis 테스트는
전용 일회용 `APPGUARD_REDIS_URL`을 제공하지 않으면 건너뜁니다.

<a id="install-python"></a>
### Python — FastAPI, Django, Flask

애플리케이션의 가상 환경에서 해당하는 extras를 선택하세요.

```sh
python3 -m pip install "$APPGUARD_REPO/sdk/python[fastapi,redis]"
python3 -m pip install "$APPGUARD_REPO/sdk/python[django,redis]"
python3 -m pip install "$APPGUARD_REPO/sdk/python[flask,redis]"
```

환경에 맞게 `appguard.fastapi.AppGuardMiddleware`,
`appguard.django.protect_django`, `appguard.flask.protect_flask`를 사용하세요.
Django는 ASGI 앱을 사용하며, Flask는 일반 WSGI가 아닌 제공된 ASGI 브리지를 통해
실행해야 합니다. 신뢰할 수 있는 인증/키 조회, 재전송 방지 저장소, 원시
요청 증거를 제공하세요. [Python 연동](sdk/python/README.md)을 참조하세요.

<a id="install-node"></a>
### Node.js — Express, Fastify, NestJS

```sh
npm pack "$APPGUARD_REPO/sdk/node" --ignore-scripts --pack-destination "$APPGUARD_PACKAGES"
cd /path/to/node-app
npm install "$APPGUARD_PACKAGES/appguard-server-0.0.0-experimental.0.tgz"
```

`@appguard/server`에서 `expressMiddleware`, `installFastify`, `nestMiddleware`를
가져오세요. 프레임워크, 인증 처리기, 등록된 키 조회,
재전송 방지 저장소는 직접 제공해야 합니다. ESM을 지원하며 CommonJS `require`는 지원하지 않습니다. NestJS는
Express 플랫폼을 사용합니다. [Node 연동 및 설치 순서](sdk/node/README.md)를 참조하세요.

<a id="install-dotnet"></a>
### .NET / ASP.NET Core

```sh
(cd "$APPGUARD_REPO/sdk/dotnet" && ./scripts/verify.sh)
cd /path/to/dotnet-app
dotnet add package AppGuard.Experimental --version 0.0.0-experimental.1 \
  --source "$APPGUARD_REPO/sdk/dotnet/artifacts"
```

패키지는 .NET 10을 대상으로 합니다. `IAppGuardRawHeadersFeature`를 통해 신뢰할 수 있는
원본 헤더 캡처를 제공하고, 인증, 키 조회, 재전송 방지 저장소를 구성하세요.
파싱된 Kestrel 헤더만으로는 충분하지 않습니다. [ASP.NET Core 연동](sdk/dotnet/README.md)을 참조하세요.

<a id="install-go"></a>
### Go

기존 Go 모듈에서 로컬 대체 경로를 사용하세요.

```sh
cd /path/to/go-app
go mod edit -require=github.com/bonjin-app/appguard/sdk/go@v0.0.0
go mod edit -replace=github.com/bonjin-app/appguard/sdk/go="$APPGUARD_REPO/sdk/go"
```

여기서 `v0.0.0`은 공개 배포 버전이 아닌 로컬 대체용 자리표시자입니다. 코드에서
`github.com/bonjin-app/appguard/sdk/go`를 가져온 뒤 `go mod tidy`를 실행하세요.
미들웨어에는 파싱 전에 증거를 확보하는 신뢰할 수 있는 `EvidenceSource`가 필요합니다. 파싱된 `http.Header`로는
해당 증거를 복원할 수 없습니다. [Go 연동](sdk/go/README.md)을 참조하세요.

<a id="install-php"></a>
### PHP

```sh
cd /path/to/php-app
composer config repositories.appguard path "$APPGUARD_REPO/sdk/php"
composer require "appguard/server:*@dev"
```

`vendor/autoload.php`를 로드하고 `AppGuard\HttpAdapter`에 신뢰할 수 있는
원시 수신 증거, 인증/키 콜백, 원자적 재전송 방지 백엔드를 구성하세요.
이는 네이티브 콜백 어댑터이며 Laravel/Symfony/FPM 연동을 지원한다고 주장하지 않습니다.
[PHP 연동](sdk/php/README.md)을 참조하세요.

<a id="install-android"></a>
### Android — Kotlin / Java

```sh
(cd "$APPGUARD_REPO/sdk/android" && ./gradlew --no-daemon assembleRelease)
```

생성된 로컬 AAR을 앱의 Gradle 의존성에 추가하세요. 절대 경로를
자신의 체크아웃 경로로 바꾸세요.

```kotlin
dependencies {
    implementation(files("/absolute/path/to/appguard/sdk/android/build/outputs/aar/appguard-android-release.aar"))
}
```

앱의 최소 SDK를 26 이상으로 설정하세요. SDK는 Keystore 기반 서명과
선택적 로컬 위험 징후를 제공합니다. HTTP 요청 전송이나 키 등록을 대신 수행하지는 않습니다.
[Android 설정 및 키 정책](sdk/android/README.md)을 참조하세요.

Google Play Integrity 획득 기능은 별도의 선택적 모듈입니다.

```sh
(cd "$APPGUARD_REPO/sdk/android-play-integrity" && ./gradlew --no-daemon assembleRelease)
```

AAR 경로는 `sdk/android-play-integrity/build/outputs/aar/appguard-android-play-integrity-release.aar`입니다.
이 AAR을 직접 사용하는 경우 공식
`com.google.android.play:integrity:1.6.0` 의존성도 추가하세요. Google 프로젝트/배포
구성과 인증된 서버 검증은 별도로 필요합니다.
[Play Integrity 모듈](sdk/android-play-integrity/README.md)을 참조하세요.

<a id="install-apple"></a>
### iOS / macOS — Swift

Xcode에서 **File → Add Package Dependencies → Add Local**을 선택하고
`$APPGUARD_REPO/sdk/apple`을 지정한 뒤 앱 타깃에 `AppGuardApple` 제품을 추가하세요.
Swift 패키지의 로컬 의존성은 다음과 같습니다.

```swift
.package(path: "/absolute/path/to/appguard/sdk/apple")
```

`AppGuardApple`을 가져오세요. 앱의 서명/권한과 인증된
키 등록은 별도로 구성하세요. App Attest에는 일치하는 앱/환경 설정이 필요합니다.
[Apple SDK 연동](sdk/apple/README.md)을 참조하세요.

<a id="install-unity"></a>
### Unity

독립적인 소스 패키지를 준비한 뒤 네이티브 의존성을 빌드하세요.

```sh
python3 "$APPGUARD_REPO/sdk/unity/Tools~/stage.py" --destination "$APPGUARD_PACKAGES/unity"
(cd "$APPGUARD_PACKAGES/unity" && python3 Tools~/build-native.py --platform all)
```

필요에 따라 `all` 대신 `--platform android` 또는 `--platform ios`를 선택하세요.
Android는 Java 17을 가리키는 `JAVA_HOME`과 Android SDK 36 및
build-tools 35.0.0을 사용하는 `ANDROID_HOME`을 설정하세요. iOS는 macOS에 Xcode를 설치하세요.
Unity Package Manager에서 **Add package from disk**를 선택하고 준비된
`$APPGUARD_PACKAGES/unity/package.json`을 지정하세요. 네이티브 빌드가 필요하며,
이 저장소의 C# 소스만 추가해서는 충분하지 않습니다. [Unity 설치](sdk/unity/README.md)를 참조하세요.

<a id="install-expo"></a>
### Expo / React Native

```sh
npm --prefix "$APPGUARD_REPO/sdk/expo" ci --ignore-scripts
(cd "$APPGUARD_REPO/sdk/expo" && npm pack --pack-destination "$APPGUARD_PACKAGES")
cd /path/to/expo-app
npx expo install "$APPGUARD_PACKAGES/appguard-expo-0.0.0-experimental.1.tgz"
```

기존 `expo.plugins` 목록에 `"@appguard/expo"`를 추가한 뒤 개발용/네이티브
앱을 다시 빌드하고 필요에 따라 iOS pods를 설치하세요. 패키징은 네이티브
소스를 준비하고 TypeScript를 컴파일합니다. `prepack` 단계를 건너뛰지 마세요. React Native
앱에는 Expo Modules 연동이 필요합니다. Expo Go와 웹은 지원하지 않으며,
OTA 업데이트로 이 네이티브 모듈을 추가할 수 없습니다. [Expo / React Native 설치](sdk/expo/README.md)를 참조하세요.

<a id="install-flutter"></a>
### Flutter

```sh
python3 "$APPGUARD_REPO/sdk/flutter/tool/pack.py" --output "$APPGUARD_PACKAGES/appguard_flutter.tar.gz"
mkdir "$APPGUARD_PACKAGES/flutter"
tar -xzf "$APPGUARD_PACKAGES/appguard_flutter.tar.gz" -C "$APPGUARD_PACKAGES/flutter"
```

사용하는 앱의 `pubspec.yaml`에 경로 의존성을 추가하고,
예제 경로를 `$APPGUARD_PACKAGES/flutter`의 실제 확장 경로로 바꾸세요.

```yaml
dependencies:
  appguard_flutter:
    path: /absolute/path/to/staged/flutter
flutter:
  config:
    enable-swift-package-manager: false
```

앱에서 `flutter pub get`을 실행하고, 필요한 경우 iOS pods를 설치한 뒤 다시 빌드하세요.
플러그인은 현재 CocoaPods를 사용합니다. 위 설정은 Flutter 전역 설정을 바꾸지 않고
프로젝트별로 CocoaPods를 선택합니다. Android minSdk는 26, iOS는
15.0 이상으로 설정하세요. [Flutter 설치](sdk/flutter/README.md)를 참조하세요.

<a id="install-cli"></a>
### Build / CLI

Node 22 이상을 사용하여 체크아웃에서 직접 실행하세요.

```sh
node "$APPGUARD_REPO/tools/cli/bin/appguard.js" init --project /path/to/app --app-id your-app
node "$APPGUARD_REPO/tools/cli/bin/appguard.js" doctor --project /path/to/app --check
node "$APPGUARD_REPO/tools/cli/bin/appguard.js" build --project /path/to/app --dry-run
```

또는 로컬 tarball을 프로젝트의 개발 의존성으로 설치하세요.

```sh
npm pack "$APPGUARD_REPO/tools/cli" --ignore-scripts --pack-destination "$APPGUARD_PACKAGES"
cd /path/to/app
npm install --save-dev "$APPGUARD_PACKAGES/appguard-cli-0.0.0-experimental.0.tgz"
npx --no-install appguard --help
```

CLI는 Android R8, Expo export, Flutter Android APK 난독화,
명시적인 암호화 매핑 보관을 다룹니다. SDK 설치, Apple/Google 계정 구성,
서명 자격 증명 선택은 수행하지 않습니다. iOS/Unity 빌드 어댑터,
콘솔, AI 분석은 아직 이 CLI의 구현 범위에 포함되지 않습니다.
[CLI 명령 및 제한](tools/cli/README.md)을 참조하세요.

### 설치 후

기존 인증과 리소스 인가를 연결하고, 신뢰할 수 있는 공개 키를
등록하며, 요청의 정확한 바이트를 보존하고, 장기간 유지되는 공유
원자적 재전송 방지 저장소를 구성하세요. 선택적 백엔드를 도입하는 경우에만
제공자 서비스를 구성하세요. 로컬 루팅/후킹/변조 징후와 난독화는 보조 방어 수단이며,
기기 무결성의 증거가 아닙니다. 프로덕션 트래픽을 보호하기 전에
각 SDK의 연동 안내를 따르세요.

## 아키텍처

- 클라이언트 SDK: 설치별 네이티브 키와 요청 바인딩, Apple 증거 래퍼, 선택적인 Android Play Integrity 획득 기능을 제공합니다. 제공자 구성은 명시적으로 수행해야 합니다.
- 서버 SDK: 요청을 검증하고 기존 인증 및 인가와 연동합니다.
- 보안 엔진: 공통 정책, 사유 코드, 감사 이벤트와 선택적 위협 분석을 제공합니다.
- Build/CLI: 프로젝트 설정/진단, 플랫폼 빌드 명령, 암호화 매핑 보관을 제공합니다.

핵심 기능은 AI 모델, 유료 AI API, 필수 AppGuard 클라우드 서비스 없이 실행됩니다. 난독화와 로컬 위험 신호는 보조 방어 수단입니다. 인증, 인가, 데이터 접근의 책임은 서버에 있습니다.

## 지원 로드맵

| 구성 요소 | 상태 |
| --- | --- |
| 초안 프로토콜 및 Python 참조 구현 | 구현 및 로컬 테스트 완료, 프로덕션 사용 준비는 미완료 |
| [Spring Boot 4.1.1 / Java 17](sdk/spring-boot/README.md) | 실험적 스타터, MVC 필터, Redis 어댑터 |
| [Python 3.11+](sdk/python/README.md) | 실험적 ASGI 검증기; FastAPI, Django ASGI, WsgiToAsgi를 통한 Flask |
| [Node.js 22+](sdk/node/README.md) | 실험적 네이티브 검증기; Express, Fastify, NestJS, Redis 어댑터 |
| [Android Java/Kotlin](sdk/android/README.md) | 네이티브 서명기, Keystore, 등록 증명; AAR/JVM 테스트/API35 에뮬레이터 검사 |
| [Apple Swift/iOS](sdk/apple/README.md) | 네이티브 서명기, Security 키 어댑터, 등록 증명, App Attest 획득 래퍼; 호스트 테스트/서명되지 않은 Simulator 빌드 |
| [Unity UPM](sdk/unity/README.md) | 타입이 지정된 JNI/C ABI 패키지와 비동기 로컬 위험 신호 API; [EditMode 테스트 138개](sdk/unity/STRICT_JSON_VERIFICATION.md), [Android Release 및 iOS Simulator IL2CPP 런타임 검사](sdk/unity/PLAYER_RUNTIME_VERIFICATION.md), 서명되지 않은 iOS 기기용 Release 빌드; 실제 기기 런타임 검증 대기 |
| [Expo / React Native](sdk/expo/README.md) | Expo58 비동기 네이티브 모듈; 테스트 61개, 파일 40개 재배치, 패키징된 Android 및 서명되지 않은 arm64 Simulator CocoaPods 컴파일; 엔진/기기 런타임 검증 대기 |
| [Flutter](sdk/flutter/README.md) | 비동기 플랫폼 채널 로컬 위험 신호 API; 테스트 64개, 백그라운드 큐/네이티브 어댑터 검사, Simulator 라이브러리 컴파일; 엔진/기기 런타임 검증 대기 |
| [ASP.NET Core](sdk/dotnet/README.md) | 실험적 엄격 검증기/미들웨어; 원본 헤더 기능 필수; 테스트 238개 및 격리된 NuGet 소비 앱 |
| [Go net/http](sdk/go/README.md) | 실험적 검증기/미들웨어; race/vet 및 격리된 소비 앱; 신뢰할 수 있는 파싱 전 증거 필요 |
| [PHP](sdk/php/README.md) | 실험적 검증기/명시적 수신 어댑터; assertion 649개 및 원시 루프백 요청 5개; Laravel/Symfony 연동은 지원한다고 주장하지 않음 |
| 공유 Redis 재전송 방지 클레임 | 구현 완료; 배포 내구성/축출 보장은 운영자 책임 |
| [등록 / 정책 / 감사](docs/security/enrollment-policy.md) | Python SQLite 챌린지/증명/키 및 주체 전체 키 폐기; 서버 언어 6개 모두 결정적 42개 사례 프리셋과 허용 목록 기반 감사 출력 통과 |
| [Apple/Google 제공자 검증](docs/security/provider-verification.md) | 실험적 Python 검증, 명시적 OAuth 갱신, Apple assertion 및 검증된 영수증의 원자적 등록; [수명 주기 상세](docs/security/apple-enrollment.md). 실제 기기·계정 검증 대기 |
| [Build / CLI](tools/cli/README.md) | Android R8 설정/빌드; Flutter 난독화/Expo 축소 명령; 암호화 매핑 보관/검증/복원; 로컬 사전 요구 사항/CI 검사, 엄격한 UTF-8 보존, 실제 격리된 Android release 빌드 |
| [로컬 루팅/후킹/탈옥 징후](protocol/local-risk-v0.md) | 실험적 Android/iOS 타입 기반 스캐너; 호스트 테스트 및 플랫폼 빌드; 실제 루팅/후킹 기기에서의 효과는 미검증 |
| 선택적 콘솔 / AI | 계획 단계이며 미구현; 둘 다 없어도 핵심 기능 동작 |

## 로컬 참조 구현 개발

Python 3.11 이상과 [uv](https://docs.astral.sh/uv/)를 설치하세요. 저장소 루트에서 다음을 실행하세요.

```sh
uv sync --locked --project reference/python
uv run --project reference/python pytest reference/python/tests -q
```

참조 구현은 파싱된 타입 지정 입력을 받아 Python SDK 핵심 로직에 위임합니다. HTTP 어댑터는 엄격한 [전송 형식 하위 집합](protocol/http-v0.md)도 파싱합니다. 기존 토큰 인증과 등록된 키 조회는 애플리케이션이 제공해야 하며, 인가도 애플리케이션에서 수행합니다. 사용자 토큰 인증 처리기는 포함되어 있지 않습니다. 선택적 제공자 백엔드에는 신뢰할 수 있는 명시적 구성이 필요합니다. 서명이 검증되어도 권한이 부여되지는 않습니다.

## 서버 SDK 검증

Python 3.11 이상, uv, Node.js 22 이상, Java 17, Maven을 설치하세요. 사용하지 않는 포트의 `127.0.0.1`에 바인딩하고 테스트를 위해 영속성을 비활성화한 **새 일회용 Redis** 인스턴스를 시작하세요. 어느 디렉터리에서든 다음을 실행할 수 있습니다.

```sh
APPGUARD_TEST_REDIS_URL=redis://127.0.0.1:DISPOSABLE_PORT/0 \
  /absolute/path/to/appguard/scripts/test-server-sdks.sh
```

`APPGUARD_UV_CMD`와 `APPGUARD_MAVEN_CMD`로 실행 파일 경로를 선택할 수 있습니다. 이 명령은 고정된 Python/npm 잠금 파일을 사용하여 실제 Redis를 포함한 테스트 모음 4개를 모두 실행하고, wheel/JAR을 빌드하며, 격리된 npm 패키지 설치를 테스트합니다. 이어서 첫 nonce 클레임을 Python/Node/Java 순으로 순환 검증하고 독립 SDK 프로세스를 경합시킵니다. Redis를 전체 초기화하지 않으며, 프로브가 소유한 키만 삭제합니다. 기존 공유 Redis 데이터베이스를 지정하지 마세요. 개별 SDK 명령과 테스트한 버전은 각 README에 문서화되어 있습니다.

어댑터에는 수정되지 않은 원시 target/header/body 증거와 명시적인 식별/재전송 방지 의존성이 필요합니다. Python은 쿼리 문자열이 비어 있을 때 신뢰할 수 있는 exact-target 확장이 필요합니다. Spring의 servlet 어댑터는 form/multipart 콘텐츠와 비차단 입력 접근을 거부합니다. Express/Nest는 애플리케이션 루트에서 가장 먼저 설치해야 하며, Fastify에는 네이티브 HTTP 요청 캡처가 필요합니다. TLS/프록시 경계에서는 신뢰할 수 있는 증거를 보존해야 합니다. 이러한 제한은 각 SDK의 연동 안내에 설명되어 있습니다. 패키지만으로 배포 환경이 구성되지는 않습니다.

Go/.NET/PHP 실행기, GitHub Actions 워크플로와 검증 범위는 [지속적 통합](docs/development/continuous-integration.md)을 참조하세요. 확장 SDK의 메모리 내 재전송 방지 저장소는 프로세스별로 동작하므로, 여러 워커를 사용하는 배포에는 실제로 테스트한 공유 저장소가 필요합니다.

## 네이티브 클라이언트 및 등록 개발

[Android](sdk/android/README.md)와 [Apple](sdk/apple/README.md) 패키지는 설치별 P-256 서명 기능으로 정확한 요청 바이트와 고정된 전송 헤더를 준비합니다. 공개 SPKI 자료를 노출하며 개인 키 내보내기 API는 제공하지 않습니다. HTTP 전송 어댑터는 포함되어 있지 않습니다. 애플리케이션 전송 계층은 서명된 target/body/headers를 보존하고 의도하지 않은 리디렉션을 방지해야 합니다. 로컬 하드웨어 상태 메타데이터는 원격 검증된 증명이 아닙니다.

[등록 프로토콜](protocol/enrollment-v0.md)은 앱, 인증된 주체, 등록된 키 ID, 공개 키 지문, origin, 일회용 만료 조건을 바인딩합니다. [Python 연동](docs/security/enrollment-policy.md)에는 기존 인증이 필요하며 Balanced/Strict에는 명시적 제공자 검증기가 필요합니다. 증명만 사용하는 Basic 등록은 명시적으로 기기 증명이 없는 상태입니다. Python, Node, Java, .NET, Go, PHP는 [정책 계약의 이식 가능한 42개 사례](protocol/policy-v0.md)를 실행합니다. 이러한 명시적 API는 신뢰할 수 있는 애플리케이션 판정을 입력으로 받습니다. 어떤 프로필도 인증, 제공자 검증, 요청 빈도 카운터를 자동으로 설치하지 않습니다.

네이티브 테스트는 JVM/macOS 암호화, 플랫폼 빌드, 격리된 Android 소프트웨어 키 저장소 에뮬레이터를 구분합니다. 실제 Apple 영구 Keychain/Secure Enclave, 실제 기기, 성공한 제공자 증거는 아직 검증되지 않았습니다. 이 테스트는 Apple/Google 프로젝트, 권한, 계정, 릴리스, 사용자 키를 구성하지 않습니다.

[브리지 계약](protocol/client-bridge-v0.md)은 공개 키 조회, 검증된 요청 준비, 등록을 위한 키 소유 증명만 노출합니다. 문서에 따라 로컬 설치 전에 각 프레임워크 패키지의 네이티브 소스를 준비하세요. JS/Dart/C# 래퍼만 설치해서는 Expo Go나 기존 바이너리에 네이티브 코드를 추가할 수 없습니다. 전송, 제공자 판정, 임의 서명/개인 키 내보내기는 노출하지 않습니다. 패키지는 정확한 body/target/header 값을 보존하며, 실제 HTTP 동작은 애플리케이션에서 검증해야 합니다.

지원되는 로컬 앱 프로젝트에서 `node tools/cli/bin/appguard.js init --project /path/to/app --app-id your-app`은 명시적 구성을 생성합니다. `doctor`(읽기 전용 로컬 사전 요구 사항), `doctor --check`(CI 종료 상태), `policy validate`, `build --dry-run`, `archive`, `verify-archive`, `restore`는 [CLI 안내](tools/cli/README.md)에 문서화되어 있습니다. 설정 과정에서 SDK 의존성을 설치·공개 배포하거나 제공자 계정을 구성하지는 않습니다. 원본 빌드 매핑과 암호화된 보관 파일을 모두 비공개로 유지하세요.

## 공통 검증 동작

- 제한된 P-256/SHA-256 프로필과 고정 순서의 RFC 9421 서명 기준 바이트.
- 빈 본문과 바이너리 본문을 포함한 정확한 원시 본문의 SHA-256 Content-Digest.
- 타임스탬프/유효 기간/시계 오차 제한, 앱/키/인증된 주체 바인딩, 키 폐기.
- 검증 후 원자적 nonce 클레임, 크기가 제한된 명시적 로컬 저장소, Redis 동시성, 백엔드 오류 시 차단.
- 치환, 프로필/인코딩 모호성, 만료, 중복 메타데이터, 재전송을 다루는 [이식 가능한 요청 시나리오 40개](conformance/v0/requests.json)와 [HTTP 봉투 시나리오 43개](conformance/v0/http.json).

테스트는 현재 실제 시각 대신 합성 데이터와 고정된 시계를 사용합니다. 커밋된 서로 다른 서명/기준 바이트 쌍 4개는 시스템 OpenSSL CLI가 있으면 해당 CLI로도 검사합니다. 실행 파일이 없으면 이 검사는 명시적으로 건너뛰며, 일반 암호화 기반 검증기 테스트는 계속 실행됩니다.

Python 핵심 진입점은 `appguard.verify.verify_request`이며, `appguard_reference`는 호환성 가져오기를 유지합니다. [참조 테스트](reference/python/tests/test_verify.py)는 호출자가 제공하는 신뢰할 수 있는 컨텍스트와 테스트 전용 서명을 보여 줍니다. 프로덕션 서명 API는 포함되어 있지 않으며, 등록은 명시적인 실험적 Python 서비스로 남아 있습니다. 요청 간에 재전송 방지 저장소를 재사용하세요. 메모리 내 저장소는 재시작 시 상태를 잃으므로, 공유 Redis에는 명시적인 용량, 보관, 복구 정책이 필요합니다.

## 기여 및 보안

[CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [위협 모델](docs/security/threat-model.md), [초안 프로토콜](protocol/request-v0.md)을 읽어 주세요. 이슈, fixture, 로그에 실제 비밀 정보나 프로덕션 키 자료를 공개하지 마세요.

프로젝트에서 작성한 코드와 문서는 [Apache-2.0](LICENSE) 라이선스를 따릅니다. 의존성 및 서드파티 라이선스는 각각의 라이선스를 유지합니다.

## 실기기를 제외한 운영 검증

서버 SDK 6종 모두 명시적으로 구성하는 공유 Redis 재전송 방지 어댑터를 제공합니다.
Spring Boot 기본값은 **4.1.1 / Java 17**입니다. 명시적 `legacy-boot3.5` 소스
프로필은 호환성 검사 용도이며, 유지보수되는 프로덕션 기본 환경은 아닙니다.

Python에는 [Apple 등록·영수증의 원자적 저장](docs/security/apple-enrollment.md),
[assertion·카운터](docs/security/apple-lifecycle.md),
[CMS 영수증 검증·갱신](docs/security/apple-receipts.md), 명시적
[Google 서비스 계정 토큰 공급자](docs/security/google-provider.md)가 추가되었습니다.
선택형 직접 TLS 서버와 영수증 파서는 애플리케이션 환경에서 설치합니다.

```sh
python3 -m pip install "$APPGUARD_REPO/sdk/python[server,apple,redis]"
```

[TLS 연동 가이드와 실행 예제](docs/deployment/python-ingress.md)를 참조하세요.
서버 검증 명령 2종을 같은 **새 일회용 로컬 Redis**로 실행한 뒤,
`uv run --frozen --project sdk/python python scripts/check_cross_sdk_replay.py --extended`로
6종 SDK의 동일한 재전송 방지 공간을 검사합니다. 장애·강제 종료·용량·부하 검증기는
자신의 Redis를 생성하며 외부 Redis URL을 받지 않습니다.
[명령·검증 증거·운영 한계](docs/development/nondevice-readiness.md)를 확인하세요.

[후보 소스·SBOM·체크섬·취약점·비밀정보·라이선스 자동화](docs/development/release-readiness.md)는
미공개 소스 후보를 준비합니다. 자동 검사를 통과해도 라이선스 검토, 독립 보안 감사,
실제 제공자·계정 연동, 배포 환경 검증, 유지관리자의 릴리스 승인은 별도로 필요합니다.
실기기 검증은 대기 상태이며 이번 범위에 포함하지 않습니다. 외부 감사를 마친 프로덕션 릴리스는 아닙니다.

확대한 개발 의존성 검사에서는 Expo 빌드 도구의 상위 프로젝트 HIGH 취약점 2건(`braces`, `node-forge`)으로 출시가 차단됩니다. AppGuard 패키지에 포함되는 의존성은 아니며, 검사 결과를 숨김 처리하지 않습니다. [권고문과 영향 경로](docs/security/dependency-advisories-2026-10-22.md)를 확인하세요.

릴리스 게이트는 npm·Python·NuGet·Go·Composer의 기록된 의존성을 소스 SBOM과 대조하고, 실제 Maven JAR의 좌표·해시와 8개 검사 전체를 재검증합니다. 누락되거나 불일치하는 증거로는 산출물을 공개할 수 없습니다. 네이티브·배포 환경의 전체 의존성 검증은 별도로 필요합니다.
