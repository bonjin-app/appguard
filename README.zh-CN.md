# AppGuard

[English](README.md) | [한국어](README.ko.md) | [日本語](README.ja.md) | [简体中文](README.zh-CN.md)

不依赖特定框架、支持自行托管的应用安全方案。采用 Apache-2.0 许可证。

**状态：实验性客户端/服务端 SDK 及 Build/CLI 已在本地实现。** 尚未向软件包注册表发布 SDK 软件包，也不作生产环境安全保证。Android/iOS 签名使用同一份协议草案，可与 Spring Boot、Python、Node.js、ASP.NET Core、Go 和 PHP 互操作。框架桥接层封装原生签名边界；Python 还提供显式的本地密钥注册，以及可选的实验性 Apple/Google 验证后端。请参阅[已批准的设计](docs/superpowers/specs/2026-10-20-appguard-foundation-design.md)，以及[服务端](docs/security/server-sdk-verification.md)、[原生端](docs/security/mobile-foundation-verification.md)、[桥接层/Build](docs/security/client-bridges-build-verification.md)、[扩展服务端](docs/security/extended-server-verification.md)和[服务提供方](docs/security/provider-verification.md)的验证证据边界。

有关验证、修复和明确暂缓的范围，请参阅[已完成的本地里程碑及后续路线图](docs/security/local-milestone-verification.md)和[后续边界加固](docs/security/hardening-verification.md)。

[原生本地风险阶段](docs/security/local-risk-verification.md)增加了可选的 Android/iOS 篡改、root 和 hook 风险提示，并明确表示无法获取结果的状态。这些观测结果用于补充服务端检查，不能证明设备完整性。
[框架风险桥接阶段](docs/security/risk-bridges-verification.md)通过 Unity、Expo/React Native 和 Flutter 异步 API 暴露相同的报告。

<a id="installation"></a>
## 安装

这些软件包**处于实验阶段，尚未发布到 npm、PyPI、Maven Central、NuGet、Packagist 或 pub.dev**。请从此仓库检出目录构建或安装；以下版本号是本地构建产物的标识，并非软件包注册表中的已发布版本。按需选择 SDK。安装客户端 SDK 不会自动安装服务端集成。

Shell 示例使用 macOS/Linux 语法。请先安装所选平台的常规工具链，使用 pip 时激活 Python 虚拟环境，并将 `/path/to/...` 和 `/absolute/path/to/...` 替换为自己的路径。Android/iOS 构建需要相应 SDK；iOS 构建需要 macOS 和 Xcode。

```sh
git clone https://github.com/bonjin-app/appguard.git
cd appguard
export APPGUARD_REPO="$PWD"
umask 077
export APPGUARD_PACKAGES="$(mktemp -d)"
```

| 组件 | 要求 | 安装指南 |
| --- | --- | --- |
| Spring Boot | Java 17、Maven；Boot 4.1.1 Servlet/MVC | [Starter](#install-spring) |
| Python | Python 3.11+；FastAPI、Django ASGI 或通过 ASGI 运行的 Flask | [Python SDK](#install-python) |
| Node.js | Node 22+；ESM；Express、Fastify 或 NestJS/Express | [Node SDK](#install-node) |
| ASP.NET Core | .NET SDK 10.0.402 / ASP.NET Core 10 | [.NET SDK](#install-dotnet) |
| Go | Go 1.26+；`net/http` | [Go 模块](#install-go) |
| PHP | 64 位 PHP 8.2+、OpenSSL/hash/JSON、Composer | [PHP SDK](#install-php) |
| Android | Java 17、Android SDK 36/build-tools 35.0.0；应用 API 26+ | [Android AAR](#install-android) |
| Apple | SwiftPM；iOS 15+ / macOS 13+ | [Apple 软件包](#install-apple) |
| Unity | Unity 6000；Android 26+ / iOS 15+ | [暂存的 UPM 软件包](#install-unity) |
| Expo / React Native | Expo SDK 58 + Expo Modules；Node 22.13+；Android 26+ / iOS 16.4+ | [原生 npm 软件包](#install-expo) |
| Flutter | Flutter 3.27+、Dart >=3.6 且 <4.0；Android 26+ / iOS 15+ | [暂存的 Flutter 插件](#install-flutter) |
| Build / CLI | Node 22+ 及所选应用的构建工具 | [CLI](#install-cli) |

<a id="install-spring"></a>
### Spring Boot

构建 starter 并将其安装到本地 Maven 仓库：

```sh
mvn -f "$APPGUARD_REPO/sdk/spring-boot/pom.xml" install
```

在应用的 `pom.xml` 中添加以下依赖：

```xml
<dependency>
  <groupId>io.appguard</groupId>
  <artifactId>appguard-spring-boot-starter</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

对于 Gradle Kotlin DSL，请使用本地 Maven 仓库：

```kotlin
repositories { mavenLocal(); mavenCentral() }
dependencies { implementation("io.appguard:appguard-spring-boot-starter:0.1.0-SNAPSHOT") }
```

启用 AppGuard，并提供应用自己的 `IdentityResolver` 和 `ReplayStore` bean。身份认证和授权仍由应用负责。请参阅 [Spring Boot 配置](sdk/spring-boot/README.md)。除非提供专用且可丢弃的 `APPGUARD_REDIS_URL`，否则将跳过真实 Redis 测试。

<a id="install-python"></a>
### Python — FastAPI、Django 和 Flask

在应用的虚拟环境中，选择对应的可选依赖组：

```sh
python3 -m pip install "$APPGUARD_REPO/sdk/python[fastapi,redis]"
python3 -m pip install "$APPGUARD_REPO/sdk/python[django,redis]"
python3 -m pip install "$APPGUARD_REPO/sdk/python[flask,redis]"
```

根据需要使用 `appguard.fastapi.AppGuardMiddleware`、`appguard.django.protect_django` 或 `appguard.flask.protect_flask`。Django 使用其 ASGI 应用；Flask 必须通过提供的 ASGI 桥接层运行，不能直接使用 WSGI。请提供可信的身份认证/密钥查询、重放存储和原始请求证据。请参阅 [Python 集成](sdk/python/README.md)。

<a id="install-node"></a>
### Node.js — Express、Fastify 和 NestJS

```sh
npm pack "$APPGUARD_REPO/sdk/node" --ignore-scripts --pack-destination "$APPGUARD_PACKAGES"
cd /path/to/node-app
npm install "$APPGUARD_PACKAGES/appguard-server-0.0.0-experimental.0.tgz"
```

从 `@appguard/server` 导入 `expressMiddleware`、`installFastify` 或 `nestMiddleware`。请自行提供框架、认证器、已注册密钥查询和重放存储。支持 ESM，不支持 CommonJS `require`。NestJS 使用其 Express 平台。请参阅 [Node 集成及安装顺序](sdk/node/README.md)。

<a id="install-dotnet"></a>
### .NET / ASP.NET Core

```sh
(cd "$APPGUARD_REPO/sdk/dotnet" && ./scripts/verify.sh)
cd /path/to/dotnet-app
dotnet add package AppGuard.Experimental --version 0.0.0-experimental.1 \
  --source "$APPGUARD_REPO/sdk/dotnet/artifacts"
```

该软件包面向 .NET 10。请通过 `IAppGuardRawHeadersFeature` 提供可信的原始请求头捕获，并提供身份认证、密钥查询和重放存储。仅有 Kestrel 解析后的请求头并不足够。请参阅 [ASP.NET Core 集成](sdk/dotnet/README.md)。

<a id="install-go"></a>
### Go

在现有 Go 模块中使用本地替换：

```sh
cd /path/to/go-app
go mod edit -require=github.com/bonjin-app/appguard/sdk/go@v0.0.0
go mod edit -replace=github.com/bonjin-app/appguard/sdk/go="$APPGUARD_REPO/sdk/go"
```

此处的 `v0.0.0` 是本地替换占位版本，并非已发布版本。在代码中导入 `github.com/bonjin-app/appguard/sdk/go`，然后运行 `go mod tidy`。中间件需要可信的解析前 `EvidenceSource`；解析后的 `http.Header` 无法重建这些证据。请参阅 [Go 集成](sdk/go/README.md)。

<a id="install-php"></a>
### PHP

```sh
cd /path/to/php-app
composer config repositories.appguard path "$APPGUARD_REPO/sdk/php"
composer require "appguard/server:*@dev"
```

加载 `vendor/autoload.php`，并为 `AppGuard\HttpAdapter` 配置可信的原始入口证据、身份认证/密钥回调及原子重放后端。这是原生回调适配器；不宣称已实现 Laravel/Symfony/FPM 集成。请参阅 [PHP 集成](sdk/php/README.md)。

<a id="install-android"></a>
### Android — Kotlin / Java

```sh
(cd "$APPGUARD_REPO/sdk/android" && ./gradlew --no-daemon assembleRelease)
```

将生成的本地 AAR 添加到应用的 Gradle 依赖中；请根据仓库检出目录调整绝对路径：

```kotlin
dependencies {
    implementation(files("/absolute/path/to/appguard/sdk/android/build/outputs/aar/appguard-android-release.aar"))
}
```

将应用的最低 SDK 设为 26+。SDK 提供基于 Keystore 的签名和可选的本地风险提示；不会代你发送 HTTP 请求或注册密钥。请参阅 [Android 设置与密钥策略](sdk/android/README.md)。

Google Play Integrity 证据获取由单独的可选模块提供：

```sh
(cd "$APPGUARD_REPO/sdk/android-play-integrity" && ./gradlew --no-daemon assembleRelease)
```

其 AAR 位于 `sdk/android-play-integrity/build/outputs/aar/appguard-android-play-integrity-release.aar`。直接使用该 AAR 时，还需添加官方 `com.google.android.play:integrity:1.6.0` 依赖。Google 项目/分发配置及经过身份认证的服务端验证是另外的必要条件。请参阅 [Play Integrity 模块](sdk/android-play-integrity/README.md)。

<a id="install-apple"></a>
### iOS / macOS — Swift

在 Xcode 中选择 **File → Add Package Dependencies → Add Local**，选中 `$APPGUARD_REPO/sdk/apple`，并将 `AppGuardApple` 产品添加到应用 target。对于 Swift 软件包，本地依赖如下：

```swift
.package(path: "/absolute/path/to/appguard/sdk/apple")
```

导入 `AppGuardApple`。请单独配置应用签名/entitlement 及经过身份认证的密钥注册；App Attest 需要匹配的应用/环境设置。请参阅 [Apple SDK 集成](sdk/apple/README.md)。

<a id="install-unity"></a>
### Unity

暂存一个独立的源码包，然后构建其原生依赖：

```sh
python3 "$APPGUARD_REPO/sdk/unity/Tools~/stage.py" --destination "$APPGUARD_PACKAGES/unity"
(cd "$APPGUARD_PACKAGES/unity" && python3 Tools~/build-native.py --platform all)
```

按需将 `all` 替换为 `--platform android` 或 `--platform ios`。Android 需要将 `JAVA_HOME` 配置为 Java 17，并将 `ANDROID_HOME` 配置为包含 build-tools 35.0.0 的 Android SDK 36。iOS 需要在 macOS 上安装 Xcode。在 Unity Package Manager 中，选择 **Add package from disk**，然后选中暂存的 `$APPGUARD_PACKAGES/unity/package.json`。必须执行原生构建；仅添加本仓库的 C# 源码并不足够。请参阅 [Unity 安装](sdk/unity/README.md)。

<a id="install-expo"></a>
### Expo / React Native

```sh
npm --prefix "$APPGUARD_REPO/sdk/expo" ci --ignore-scripts
(cd "$APPGUARD_REPO/sdk/expo" && npm pack --pack-destination "$APPGUARD_PACKAGES")
cd /path/to/expo-app
npx expo install "$APPGUARD_PACKAGES/appguard-expo-0.0.0-experimental.1.tgz"
```

将 `"@appguard/expo"` 合并到现有的 `expo.plugins` 列表中，然后重新构建开发/原生应用，并按需安装 iOS pods。打包过程会暂存原生源码并编译 TypeScript；不要绕过 `prepack` 步骤。React Native 应用需要集成 Expo Modules。不支持 Expo Go 和 web，OTA 更新也无法添加此原生模块。请参阅 [Expo / React Native 安装](sdk/expo/README.md)。

<a id="install-flutter"></a>
### Flutter

```sh
python3 "$APPGUARD_REPO/sdk/flutter/tool/pack.py" --output "$APPGUARD_PACKAGES/appguard_flutter.tar.gz"
mkdir "$APPGUARD_PACKAGES/flutter"
tar -xzf "$APPGUARD_PACKAGES/appguard_flutter.tar.gz" -C "$APPGUARD_PACKAGES/flutter"
```

在使用该插件的应用的 `pubspec.yaml` 中合并路径依赖，将示例路径替换为 `$APPGUARD_PACKAGES/flutter` 展开后的值：

```yaml
dependencies:
  appguard_flutter:
    path: /absolute/path/to/staged/flutter
flutter:
  config:
    enable-swift-package-manager: false
```

在应用中运行 `flutter pub get`，按需安装 iOS pods，然后重新构建。插件当前使用 CocoaPods；以上设置为单个项目选择 CocoaPods，不会更改全局 Flutter 设置。将 Android minSdk 设为 26，iOS 设为 15.0+。请参阅 [Flutter 安装](sdk/flutter/README.md)。

<a id="install-cli"></a>
### Build / CLI

使用 Node 22+ 直接从仓库检出目录运行：

```sh
node "$APPGUARD_REPO/tools/cli/bin/appguard.js" init --project /path/to/app --app-id your-app
node "$APPGUARD_REPO/tools/cli/bin/appguard.js" doctor --project /path/to/app --check
node "$APPGUARD_REPO/tools/cli/bin/appguard.js" build --project /path/to/app --dry-run
```

或者将本地 tarball 安装为项目的开发依赖：

```sh
npm pack "$APPGUARD_REPO/tools/cli" --ignore-scripts --pack-destination "$APPGUARD_PACKAGES"
cd /path/to/app
npm install --save-dev "$APPGUARD_PACKAGES/appguard-cli-0.0.0-experimental.0.tgz"
npx --no-install appguard --help
```

CLI 涵盖 Android R8、Expo export、Flutter Android APK 混淆，以及显式保留加密映射文件。它不会安装 SDK、配置 Apple/Google 账号或选择签名凭据。iOS/Unity 构建适配器、控制台和 AI 分析仍不在此 CLI 已实现的范围内。请参阅 [CLI 命令与限制](tools/cli/README.md)。

### 安装后

接入现有的身份认证和资源授权，注册可信公钥，保留精确的请求字节，并配置长期运行、共享且支持原子操作的重放存储。仅在采用可选后端时配置相应服务提供方。本地 root/hook/篡改提示和混淆属于辅助防御措施，不能证明设备完整性。在保护生产流量前，请遵循各 SDK 的集成指南。

## 架构

- 客户端 SDK：原生安装实例密钥和请求绑定；Apple 证据封装与可选的 Android Play Integrity 证据获取；服务提供方配置仍需显式完成。
- 服务端 SDK：请求验证，与现有身份认证和授权集成。
- 安全引擎：通用策略、原因码和审计事件；可选的威胁分析。
- Build/CLI：项目设置/诊断、平台构建命令和加密映射文件保留。

核心功能无需 AI 模型、付费 AI API 或强制使用 AppGuard 云服务即可运行。混淆和本地风险信号属于辅助防御措施。身份认证、授权和数据访问仍由服务端负责。

## 支持路线图

| 组件 | 状态 |
| --- | --- |
| 协议草案和 Python 参考实现 | 已实现并在本地测试，尚未达到生产可用状态 |
| [Spring Boot 4.1.1 / Java 17](sdk/spring-boot/README.md) | 实验性 starter、MVC 过滤器和 Redis 适配器 |
| [Python 3.11+](sdk/python/README.md) | 实验性 ASGI 验证器；支持 FastAPI、Django ASGI、通过 WsgiToAsgi 运行的 Flask |
| [Node.js 22+](sdk/node/README.md) | 实验性原生验证器；Express、Fastify、NestJS 和 Redis 适配器 |
| [Android Java/Kotlin](sdk/android/README.md) | 原生签名器、Keystore 和注册证明；AAR/JVM 测试/API35 模拟器检查 |
| [Apple Swift/iOS](sdk/apple/README.md) | 原生签名器、Security 密钥适配器、注册证明和 App Attest 证据获取封装；宿主机测试/未签名 Simulator 构建 |
| [Unity UPM](sdk/unity/README.md) | 类型化 JNI/C ABI 软件包和异步本地风险 API；[138 项 EditMode 测试](sdk/unity/STRICT_JSON_VERIFICATION.md)、[Android Release 和 iOS Simulator IL2CPP 运行时检查](sdk/unity/PLAYER_RUNTIME_VERIFICATION.md)、未签名的 iOS 真机 Release 构建；真机运行时验证待完成 |
| [Expo / React Native](sdk/expo/README.md) | Expo58 异步原生模块；61 项测试、40 个文件的重定位、打包后的 Android 及未签名 arm64 Simulator CocoaPods 编译；引擎/真机运行时验证待完成 |
| [Flutter](sdk/flutter/README.md) | 异步 platform-channel 本地风险 API；64 项测试、后台队列/原生适配器检查和 Simulator 库编译；引擎/真机运行时验证待完成 |
| [ASP.NET Core](sdk/dotnet/README.md) | 实验性严格验证器/中间件；强制要求原始请求头 feature；238 项测试及隔离的 NuGet 使用方验证 |
| [Go net/http](sdk/go/README.md) | 实验性验证器/中间件；race/vet 检查及隔离的使用方验证；需要可信的解析前证据 |
| [PHP](sdk/php/README.md) | 实验性验证器/显式入口适配器；649 项断言和 5 次原始回环请求；不宣称支持 Laravel/Symfony 集成 |
| 共享 Redis 防重放占用记录 | 已实现；部署持久性/淘汰保证由运维方负责 |
| [注册 / 策略 / 审计](docs/security/enrollment-policy.md) | Python SQLite 质询/证明/密钥及主体范围撤销；全部六种服务端语言通过确定性的 42 个预设用例，并输出符合允许列表的审计内容 |
| [Apple/Google 服务提供方验证](docs/security/provider-verification.md) | 实验性 Python 验证、显式 OAuth 刷新、Apple assertion 及已验证回执的原子注册；[生命周期详情](docs/security/apple-enrollment.md)。真实设备/账号验证待完成 |
| [Build / CLI](tools/cli/README.md) | Android R8 设置/构建；Flutter 混淆/Expo 压缩命令；加密映射文件归档/验证/恢复；本地前置条件/CI 检查、严格保留 UTF-8 及实际隔离的 Android release 构建 |
| [本地 root/hook/越狱提示](protocol/local-risk-v0.md) | 实验性 Android/iOS 类型化扫描器；宿主机测试和平台构建；在已 root/被 hook 的真机上的有效性尚未验证 |
| 可选控制台 / AI | 已规划，尚未实现；核心功能不依赖二者 |

## 本地参考实现开发

安装 Python 3.11+ 和 [uv](https://docs.astral.sh/uv/)。在仓库根目录运行：

```sh
uv sync --locked --project reference/python
uv run --project reference/python pytest reference/python/tests -q
```

参考实现接收已解析的类型化输入，并将验证委托给 Python SDK 核心。HTTP 适配器还会解析严格的[线上协议子集](protocol/http-v0.md)。应用必须提供现有的 token 身份认证和已注册密钥查询；授权仍在应用内执行。未内置用户 token 认证器；可选的服务提供方后端需要显式的可信配置。签名验证通过不代表获得权限。

## 服务端 SDK 验证

安装 Python 3.11+、uv、Node.js 22+、Java 17 和 Maven。启动一个**全新、可丢弃的 Redis** 实例，绑定到 `127.0.0.1` 的未占用端口，并为测试禁用持久化。在任意目录运行：

```sh
APPGUARD_TEST_REDIS_URL=redis://127.0.0.1:DISPOSABLE_PORT/0 \
  /absolute/path/to/appguard/scripts/test-server-sdks.sh
```

可通过 `APPGUARD_UV_CMD` 和 `APPGUARD_MAVEN_CMD` 选择可执行文件路径。该命令使用冻结的 Python/npm 锁文件，运行包含真实 Redis 的全部四组测试，构建 wheel/JAR 并测试隔离的 npm 软件包安装，然后让 Python/Node/Java 依次尝试同一个 nonce 的首次占用，并使独立 SDK 进程并发竞争。它不会清空 Redis，仅删除探针自身的键。切勿使用现有的共享 Redis 数据库。各 SDK 的命令及已测试版本记录在各自的 README 中。

适配器要求未经修改的原始目标/请求头/请求体证据，以及显式的身份和重放依赖。查询字符串为空时，Python 需要可信的精确目标扩展。Spring servlet 适配器拒绝 form/multipart 内容及非阻塞输入访问。Express/Nest 必须优先安装在应用根级；Fastify 需要捕获原生 HTTP 请求。TLS/代理边界必须保留可信证据。这些限制在各 SDK 的集成指南中有详细说明；软件包本身不会配置部署环境。

有关 Go/.NET/PHP 测试运行器、GitHub Actions 工作流及验证范围，请参阅[持续集成](docs/development/continuous-integration.md)。扩展 SDK 的内存重放存储仅限当前进程；多 worker 部署需要经过实际测试的共享存储。

## 原生客户端和注册开发

[Android](sdk/android/README.md) 和 [Apple](sdk/apple/README.md) 软件包使用每个安装实例的 P-256 签名能力，准备精确的请求字节和固定的线上请求头。它们暴露公钥 SPKI 数据，不提供私钥导出 API。未内置 HTTP 传输适配器：应用的传输层必须保留已签名的目标/请求体/请求头，并防止非预期重定向。本地硬件状态元数据不属于经过远程验证的证明。

[注册协议](protocol/enrollment-v0.md)绑定应用、已认证主体、已注册密钥 ID、公钥指纹、来源及带有效期的一次性使用约束。[Python 集成](docs/security/enrollment-policy.md)的 Balanced/Strict 要求现有身份认证及显式的服务提供方验证器。仅验证持钥证明的 Basic 注册明确不包含可信证明。Python、Node、Java、.NET、Go 和 PHP 执行[策略契约中的 42 个可移植用例](protocol/policy-v0.md)。这些显式 API 接收可信的应用判定结果；任何配置档都不会自动安装身份认证、服务提供方验证或速率计数器。

原生测试区分 JVM/macOS 加密测试、平台构建，以及隔离的 Android 软件 Keystore 模拟器。实际的 Apple 持久化 Keychain/Secure Enclave、真机及成功的服务提供方证据仍未验证。这些测试不会配置任何 Apple/Google 项目、entitlement、账号、发行版本或用户密钥。

[桥接契约](protocol/client-bridge-v0.md)仅暴露公钥查询、经过验证的请求准备及注册持钥证明。请按文档说明，在本地安装前暂存各框架软件包的原生源码；仅安装 JS/Dart/C# 封装无法向 Expo Go 或现有二进制添加原生代码。不会暴露传输、服务提供方判定、任意签名或私钥导出能力。软件包保留精确的请求体/目标/请求头值；应用必须验证实际的 HTTP 行为。

对于受支持的本地应用项目，`node tools/cli/bin/appguard.js init --project /path/to/app --app-id your-app` 会创建显式配置。`doctor`（只读的本地前置条件检查）、`doctor --check`（CI 退出状态）、`policy validate`、`build --dry-run`、`archive`、`verify-archive` 和 `restore` 均记录在 [CLI 指南](tools/cli/README.md)中。设置过程不会安装或发布 SDK 依赖，也不会配置服务提供方账号。原始构建映射文件及其加密归档均应保持私密。

## 通用验证行为

- 采用受限的 P-256/SHA-256 配置，按固定顺序生成 RFC 9421 签名基字符串字节。
- 对原始请求体计算精确的 SHA-256 Content-Digest，包括空请求体和二进制请求体。
- 时间戳/生命周期/时钟偏差限制、应用/密钥/已认证主体绑定，以及密钥撤销。
- 验证后的原子 nonce 占用、容量受限的显式本地存储、Redis 并发，以及后端出错时默认拒绝。
- [40 个可移植请求场景](conformance/v0/requests.json)和 [43 个 HTTP 封装场景](conformance/v0/http.json)，涵盖替换、配置/编码歧义、过期、重复元数据及重放。

测试使用合成数据和固定时钟，不使用当前实际时间。系统 OpenSSL CLI 可用时，还会检查四组不同的已提交签名/签名基字符串对。缺少该可执行文件时，会明确跳过此检查；基于密码学库的常规验证器测试仍会运行。

Python 核心入口为 `appguard.verify.verify_request`；`appguard_reference` 保留兼容性导入。[参考测试](reference/python/tests/test_verify.py)展示了调用方提供的可信上下文，以及仅供测试使用的签名。未包含生产签名 API；注册仍是显式的实验性 Python 服务。请跨请求复用重放存储。内存存储会在重启后丢失状态；共享 Redis 需要明确的容量、保留和恢复策略。

## 贡献与安全

请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)、[SECURITY.md](SECURITY.md)、[威胁模型](docs/security/threat-model.md)及[协议草案](protocol/request-v0.md)。请勿在 issue、测试夹具或日志中发布真实机密或生产密钥材料。

项目自行编写的代码和文档采用 [Apache-2.0](LICENSE) 许可证。依赖项及第三方内容仍遵循各自的许可证。

## 不含真机的运行验证

全部 6 种服务端 SDK 均提供显式配置的共享 Redis 防重放适配器。
Spring Boot 默认采用 **4.1.1 / Java 17**。显式 `legacy-boot3.5` 源码配置仅用于
兼容性检查，不属于持续维护的生产基线。

Python 新增 [Apple 注册及回执的原子存储](docs/security/apple-enrollment.md)、
[assertion 与计数器](docs/security/apple-lifecycle.md)、
[CMS 回执验证/刷新](docs/security/apple-receipts.md)，以及显式的
[Google 服务账号令牌提供器](docs/security/google-provider.md)。
可选的直接 TLS 服务及回执解析器在应用环境中安装：

```sh
python3 -m pip install "$APPGUARD_REPO/sdk/python[server,apple,redis]"
```

参阅 [TLS 接入指南及可执行示例](docs/deployment/python-ingress.md)。
用同一个**全新、可丢弃的本地 Redis**运行两组服务端验证命令后，执行
`uv run --frozen --project sdk/python python scripts/check_cross_sdk_replay.py --extended`，
检查 6 种 SDK 的共享防重放命名空间。故障、强制退出、容量及负载验证器自行创建 Redis，
不接收外部 Redis URL。[命令、证据及运行限制](docs/development/nondevice-readiness.md)。

[候选源码/SBOM/校验和/漏洞/秘密信息/许可证自动化](docs/development/release-readiness.md)
准备未发布的源码候选。通过自动检查后，仍需许可证审查、独立安全审计、实际提供方/账号联调、
部署环境验证及维护者发布批准。真机验证保持待办，不属于本次范围。
这不是已完成外部审计的生产版本。

扩展至开发依赖后的检查因 Expo 构建工具中的两项上游 HIGH 漏洞（`braces`、`node-forge`）阻止发布。这些依赖不随 AppGuard 软件包分发，检测结果未被抑制。参阅[安全公告及影响路径](docs/security/dependency-advisories-2026-10-22.md)。

发布门禁将 npm、Python、NuGet、Go、Composer 的已记录依赖与源码 SBOM 比对，并重新验证实际 Maven JAR 的坐标、哈希及全部 8 项检查。证据缺失或不一致时禁止公开产物；原生及部署环境的完整依赖验证仍需单独完成。

ASP.NET Core 对整个请求体读取实施绝对时间限制（默认 30 秒）。当前 Spring Servlet 阻塞过滤器仍需主机侧经过验证的上传期限，仅空闲超时并不足够。[时间边界及验证范围](docs/security/body-capture-deadlines.md)。
