# AppGuard

[English](README.md) | [한국어](README.ko.md) | [日本語](README.ja.md) | [简体中文](README.zh-CN.md)

フレームワークに依存せず、セルフホストできるアプリセキュリティ。Apache-2.0 ライセンスで提供しています。

**開発状況：実験段階のクライアント／サーバー SDK と Build/CLI をローカルで実装済みです。** SDK パッケージはまだパッケージレジストリに公開されておらず、本番環境でのセキュリティを保証するものではありません。Android/iOS の署名は、共通のドラフトプロトコルを使って Spring Boot、Python、Node.js、ASP.NET Core、Go、PHP と相互運用します。フレームワークブリッジはネイティブ署名の境界をパッケージ化しています。Python には、明示的なローカル登録と、任意で利用できる実験段階の Apple/Google 検証バックエンドもあります。[承認済みの設計](docs/superpowers/specs/2026-10-20-appguard-foundation-design.md)と、[サーバー](docs/security/server-sdk-verification.md)、[ネイティブ](docs/security/mobile-foundation-verification.md)、[ブリッジ／Build](docs/security/client-bridges-build-verification.md)、[追加のサーバー SDK](docs/security/extended-server-verification.md)、[プロバイダー](docs/security/provider-verification.md)それぞれの検証で確認できた範囲を参照してください。

検証結果、修正内容、明示的に先送りした範囲については、[完了したローカルマイルストーンと今後のロードマップ](docs/security/local-milestone-verification.md)、および[その後の境界の強化](docs/security/hardening-verification.md)を参照してください。

[ネイティブのローカルリスク対応段階](docs/security/local-risk-verification.md)では、Android/iOS の改ざん、root 化、フックに関する任意の兆候検出を追加しています。検出できない場合の状態も明示します。これらの観測結果はサーバー側の検証を補助するものであり、デバイスの完全性を証明するものではありません。[フレームワークのリスクブリッジ対応段階](docs/security/risk-bridges-verification.md)では、同じレポートを Unity、Expo/React Native、Flutter の非同期 API から利用できます。

<a id="installation"></a>
## インストール

パッケージは**実験段階であり、npm、PyPI、Maven Central、NuGet、Packagist、pub.dev には公開されていません**。このチェックアウトからビルド／インストールしてください。以下のバージョンはローカル成果物の識別子であり、レジストリで公開されたリリースではありません。必要な SDK を選んでください。クライアント SDK をインストールしても、サーバー連携は自動では導入されません。

シェルの例は macOS/Linux の構文を使用しています。選択したプラットフォームで通常必要となるツールチェーンを先にインストールしてください。pip を使う場合は Python の仮想環境を有効にし、`/path/to/...` と `/absolute/path/to/...` は自分のパスに置き換えてください。Android/iOS のビルドには各 SDK が必要です。iOS のビルドには macOS と Xcode が必要です。

```sh
git clone https://github.com/bonjin-app/appguard.git
cd appguard
export APPGUARD_REPO="$PWD"
umask 077
export APPGUARD_PACKAGES="$(mktemp -d)"
```

| コンポーネント | 要件 | インストールガイド |
| --- | --- | --- |
| Spring Boot | Java 17、Maven、Boot 3.5 Servlet/MVC | [Starter](#install-spring) |
| Python | Python 3.11+、FastAPI、Django ASGI、または ASGI 経由の Flask | [Python SDK](#install-python) |
| Node.js | Node 22+、ESM、Express、Fastify、または NestJS/Express | [Node SDK](#install-node) |
| ASP.NET Core | .NET SDK 10.0.402 / ASP.NET Core 10 | [.NET SDK](#install-dotnet) |
| Go | Go 1.26+、`net/http` | [Go モジュール](#install-go) |
| PHP | 64 ビット PHP 8.2+、OpenSSL/hash/JSON、Composer | [PHP SDK](#install-php) |
| Android | Java 17、Android SDK 36/build-tools 35.0.0、アプリ API 26+ | [Android AAR](#install-android) |
| Apple | SwiftPM、iOS 15+ / macOS 13+ | [Apple パッケージ](#install-apple) |
| Unity | Unity 6000、Android 26+ / iOS 15+ | [ステージング済み UPM パッケージ](#install-unity) |
| Expo / React Native | Expo SDK 58 + Expo Modules、Node 22.13+、Android 26+ / iOS 16.4+ | [ネイティブ npm パッケージ](#install-expo) |
| Flutter | Flutter 3.27+、Dart >=3.6 かつ <4.0、Android 26+ / iOS 15+ | [ステージング済み Flutter プラグイン](#install-flutter) |
| Build / CLI | Node 22+ と、対象アプリのビルドツール | [CLI](#install-cli) |

<a id="install-spring"></a>
### Spring Boot

Starter をビルドし、ローカル Maven リポジトリにインストールします。

```sh
mvn -f "$APPGUARD_REPO/sdk/spring-boot/pom.xml" install
```

アプリケーションの `pom.xml` に次の依存関係を追加します。

```xml
<dependency>
  <groupId>io.appguard</groupId>
  <artifactId>appguard-spring-boot-starter</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Gradle Kotlin DSL の場合は、ローカル Maven リポジトリを使います。

```kotlin
repositories { mavenLocal(); mavenCentral() }
dependencies { implementation("io.appguard:appguard-spring-boot-starter:0.1.0-SNAPSHOT") }
```

AppGuard を有効にし、アプリケーションの `IdentityResolver` と `ReplayStore` の Bean を提供してください。認証と認可は引き続きアプリケーションが担当します。[Spring Boot の設定](sdk/spring-boot/README.md)を参照してください。実際の Redis を使うテストは、専用の使い捨て `APPGUARD_REDIS_URL` を指定しない限りスキップされます。

<a id="install-python"></a>
### Python — FastAPI、Django、Flask

アプリケーションの仮想環境で、該当する extras を選択します。

```sh
python3 -m pip install "$APPGUARD_REPO/sdk/python[fastapi,redis]"
python3 -m pip install "$APPGUARD_REPO/sdk/python[django,redis]"
python3 -m pip install "$APPGUARD_REPO/sdk/python[flask,redis]"
```

必要に応じて `appguard.fastapi.AppGuardMiddleware`、`appguard.django.protect_django`、または `appguard.flask.protect_flask` を使用してください。Django は ASGI アプリを使います。Flask は通常の WSGI ではなく、付属の ASGI ブリッジ経由で実行する必要があります。信頼できる認証／鍵検索、リプレイ防止用ストレージ、生のリクエスト情報を提供してください。[Python 連携](sdk/python/README.md)を参照してください。

<a id="install-node"></a>
### Node.js — Express、Fastify、NestJS

```sh
npm pack "$APPGUARD_REPO/sdk/node" --ignore-scripts --pack-destination "$APPGUARD_PACKAGES"
cd /path/to/node-app
npm install "$APPGUARD_PACKAGES/appguard-server-0.0.0-experimental.0.tgz"
```

`@appguard/server` から `expressMiddleware`、`installFastify`、または `nestMiddleware` をインポートします。フレームワーク、認証処理、登録済み鍵の検索、リプレイ防止用ストアは各自で提供してください。ESM に対応しており、CommonJS の `require` には対応していません。NestJS は Express プラットフォームを使います。[Node 連携とインストール順序](sdk/node/README.md)を参照してください。

<a id="install-dotnet"></a>
### .NET / ASP.NET Core

```sh
(cd "$APPGUARD_REPO/sdk/dotnet" && ./scripts/verify.sh)
cd /path/to/dotnet-app
dotnet add package AppGuard.Experimental --version 0.0.0-experimental.1 \
  --source "$APPGUARD_REPO/sdk/dotnet/artifacts"
```

このパッケージは .NET 10 を対象としています。`IAppGuardRawHeadersFeature` による信頼できる元のヘッダーの取得、認証、鍵検索、リプレイ防止用ストアを提供してください。Kestrel が解析したヘッダーだけでは不十分です。[ASP.NET Core 連携](sdk/dotnet/README.md)を参照してください。

<a id="install-go"></a>
### Go

既存の Go モジュールで、ローカルの置き換えを設定します。

```sh
cd /path/to/go-app
go mod edit -require=github.com/bonjin-app/appguard/sdk/go@v0.0.0
go mod edit -replace=github.com/bonjin-app/appguard/sdk/go="$APPGUARD_REPO/sdk/go"
```

ここでの `v0.0.0` はローカル置き換え用のプレースホルダーであり、公開バージョンではありません。コード内で `github.com/bonjin-app/appguard/sdk/go` をインポートし、`go mod tidy` を実行してください。ミドルウェアには、解析前の情報を提供する信頼できる `EvidenceSource` が必要です。解析済みの `http.Header` からその情報を復元することはできません。[Go 連携](sdk/go/README.md)を参照してください。

<a id="install-php"></a>
### PHP

```sh
cd /path/to/php-app
composer config repositories.appguard path "$APPGUARD_REPO/sdk/php"
composer require "appguard/server:*@dev"
```

`vendor/autoload.php` を読み込み、信頼できる受信時の生の情報、認証／鍵検索コールバック、アトミックなリプレイ防止バックエンドを使って `AppGuard\HttpAdapter` を設定してください。これはネイティブのコールバックアダプターであり、Laravel/Symfony/FPM との連携は確認していません。[PHP 連携](sdk/php/README.md)を参照してください。

<a id="install-android"></a>
### Android — Kotlin / Java

```sh
(cd "$APPGUARD_REPO/sdk/android" && ./gradlew --no-daemon assembleRelease)
```

生成されたローカル AAR をアプリの Gradle 依存関係に追加します。絶対パスは自分のチェックアウトに合わせて変更してください。

```kotlin
dependencies {
    implementation(files("/absolute/path/to/appguard/sdk/android/build/outputs/aar/appguard-android-release.aar"))
}
```

アプリの最小 SDK を 26 以上に設定してください。SDK は Keystore を使った署名と任意のローカルリスクの兆候を提供します。HTTP リクエストの送信や鍵の登録は行いません。[Android のセットアップと鍵ポリシー](sdk/android/README.md)を参照してください。

Google Play Integrity の取得には、別の任意モジュールを使います。

```sh
(cd "$APPGUARD_REPO/sdk/android-play-integrity" && ./gradlew --no-daemon assembleRelease)
```

AAR は `sdk/android-play-integrity/build/outputs/aar/appguard-android-play-integrity-release.aar` に生成されます。この AAR を直接使う場合は、公式の `com.google.android.play:integrity:1.6.0` 依存関係も追加してください。Google のプロジェクト／配信設定と、認証を伴うサーバー側の検証は別途必要です。[Play Integrity モジュール](sdk/android-play-integrity/README.md)を参照してください。

<a id="install-apple"></a>
### iOS / macOS — Swift

Xcode で **File → Add Package Dependencies → Add Local** を選択し、`$APPGUARD_REPO/sdk/apple` を指定して、`AppGuardApple` プロダクトをアプリのターゲットに追加します。Swift パッケージの場合、ローカル依存関係は次のとおりです。

```swift
.package(path: "/absolute/path/to/appguard/sdk/apple")
```

`AppGuardApple` をインポートしてください。アプリの署名／エンタイトルメントと、認証を伴う鍵の登録は別途設定してください。App Attest には、対応するアプリ／環境の設定が必要です。[Apple SDK 連携](sdk/apple/README.md)を参照してください。

<a id="install-unity"></a>
### Unity

独立したソースパッケージをステージングし、そのネイティブ依存関係をビルドします。

```sh
python3 "$APPGUARD_REPO/sdk/unity/Tools~/stage.py" --destination "$APPGUARD_PACKAGES/unity"
(cd "$APPGUARD_PACKAGES/unity" && python3 Tools~/build-native.py --platform all)
```

必要に応じて `all` の代わりに `--platform android` または `--platform ios` を選択してください。Android では Java 17 を指す `JAVA_HOME` と、build-tools 35.0.0 を備えた Android SDK 36 を指す `ANDROID_HOME` を設定してください。iOS では macOS に Xcode をインストールしてください。Unity Package Manager で **Add package from disk** を選択し、ステージング済みの `$APPGUARD_PACKAGES/unity/package.json` を指定します。ネイティブビルドが必要です。このリポジトリの C# ソースを追加するだけでは不十分です。[Unity のインストール](sdk/unity/README.md)を参照してください。

<a id="install-expo"></a>
### Expo / React Native

```sh
npm --prefix "$APPGUARD_REPO/sdk/expo" ci --ignore-scripts
(cd "$APPGUARD_REPO/sdk/expo" && npm pack --pack-destination "$APPGUARD_PACKAGES")
cd /path/to/expo-app
npx expo install "$APPGUARD_PACKAGES/appguard-expo-0.0.0-experimental.1.tgz"
```

既存の `expo.plugins` リストに `"@appguard/expo"` を追加してから、開発用／ネイティブアプリを再ビルドし、必要に応じて iOS の Pod をインストールしてください。パッケージ化の際には、ネイティブソースのステージングと TypeScript のコンパイルが行われます。`prepack` の手順を省略しないでください。React Native アプリには Expo Modules の導入が必要です。Expo Go と Web には対応していません。また、OTA アップデートではこのネイティブモジュールを追加できません。[Expo / React Native のインストール](sdk/expo/README.md)を参照してください。

<a id="install-flutter"></a>
### Flutter

```sh
python3 "$APPGUARD_REPO/sdk/flutter/tool/pack.py" --output "$APPGUARD_PACKAGES/appguard_flutter.tar.gz"
mkdir "$APPGUARD_PACKAGES/flutter"
tar -xzf "$APPGUARD_PACKAGES/appguard_flutter.tar.gz" -C "$APPGUARD_PACKAGES/flutter"
```

利用するアプリの `pubspec.yaml` にパス依存関係を追加します。例のパスは、`$APPGUARD_PACKAGES/flutter` を展開した実際の値に置き換えてください。

```yaml
dependencies:
  appguard_flutter:
    path: /absolute/path/to/staged/flutter
flutter:
  config:
    enable-swift-package-manager: false
```

アプリで `flutter pub get` を実行し、必要に応じて iOS の Pod をインストールして、再ビルドしてください。このプラグインは現在 CocoaPods を使用します。上の設定は Flutter のグローバル設定を変更せず、プロジェクト単位で CocoaPods を選択するものです。Android の minSdk を 26、iOS を 15.0 以上に設定してください。[Flutter のインストール](sdk/flutter/README.md)を参照してください。

<a id="install-cli"></a>
### Build / CLI

Node 22+ を使って、チェックアウトから直接実行できます。

```sh
node "$APPGUARD_REPO/tools/cli/bin/appguard.js" init --project /path/to/app --app-id your-app
node "$APPGUARD_REPO/tools/cli/bin/appguard.js" doctor --project /path/to/app --check
node "$APPGUARD_REPO/tools/cli/bin/appguard.js" build --project /path/to/app --dry-run
```

または、ローカルの tarball をプロジェクトの開発依存関係にインストールできます。

```sh
npm pack "$APPGUARD_REPO/tools/cli" --ignore-scripts --pack-destination "$APPGUARD_PACKAGES"
cd /path/to/app
npm install --save-dev "$APPGUARD_PACKAGES/appguard-cli-0.0.0-experimental.0.tgz"
npx --no-install appguard --help
```

CLI は Android R8、Expo export、Flutter Android APK の難読化、明示的な暗号化済みマッピングの保管に対応しています。SDK のインストール、Apple/Google アカウントの設定、署名用の認証情報の選択は行いません。iOS/Unity ビルドアダプター、コンソール、AI 分析は、この CLI の実装範囲外です。[CLI のコマンドと制限](tools/cli/README.md)を参照してください。

### インストール後

既存の認証とリソース認可を接続し、信頼できる公開鍵を登録し、リクエストの正確なバイト列を保持し、長期間稼働する共有のアトミックなリプレイ防止ストアを設定してください。プロバイダーサービスは、任意のバックエンドを採用する場合にのみ設定してください。ローカルで検出した root 化／フック／改ざんの兆候と難読化は補助的な防御であり、デバイスの完全性を証明するものではありません。本番トラフィックを保護する前に、各 SDK の連携ガイドに従ってください。

## アーキテクチャ

- クライアント SDK：インストール単位のネイティブ鍵とリクエストの紐付け、Apple の検証情報ラッパー、任意の Android Play Integrity 取得機能。プロバイダーは明示的な設定が必要です。
- サーバー SDK：リクエストの検証と、既存の認証・認可との連携。
- セキュリティエンジン：共通のポリシー、理由コード、監査イベント、任意の脅威分析。
- Build/CLI：プロジェクトのセットアップ／診断、プラットフォームのビルドコマンド、暗号化済みマッピングの保管。

コアは AI モデル、有料の AI API、必須の AppGuard クラウドサービスなしで動作する設計です。難読化とローカルリスクシグナルは補助的な防御です。認証、認可、データアクセスは引き続きサーバーが担当します。

## 対応ロードマップ

| コンポーネント | 状況 |
| --- | --- |
| ドラフトプロトコルと Python リファレンス | 実装済み、ローカルでテスト済み、本番利用の準備は未完了 |
| [Spring Boot 3.5 / Java 17](sdk/spring-boot/README.md) | 実験段階の Starter、MVC フィルター、Redis アダプター |
| [Python 3.11+](sdk/python/README.md) | 実験段階の ASGI 検証器。FastAPI、Django ASGI、WsgiToAsgi 経由の Flask に対応 |
| [Node.js 22+](sdk/node/README.md) | 実験段階のネイティブ検証器。Express、Fastify、NestJS、Redis アダプターに対応 |
| [Android Java/Kotlin](sdk/android/README.md) | ネイティブ署名器、Keystore、登録時の証明。AAR／JVM テスト／API35 エミュレーターで確認済み |
| [Apple Swift/iOS](sdk/apple/README.md) | ネイティブ署名器、Security 鍵アダプター、登録時の証明、App Attest 取得ラッパー。ホスト上のテスト／未署名の Simulator ビルドを実施済み |
| [Unity UPM](sdk/unity/README.md) | 型付き JNI/C ABI パッケージと非同期ローカルリスク API。[138 件の EditMode テスト](sdk/unity/STRICT_JSON_VERIFICATION.md)、[Android Release と iOS Simulator の IL2CPP ランタイム確認](sdk/unity/PLAYER_RUNTIME_VERIFICATION.md)、未署名の iOS 実機用 Release ビルドを実施済み。実機での動作確認は未完了 |
| [Expo / React Native](sdk/expo/README.md) | Expo58 非同期ネイティブモジュール。61 件のテスト、44 ファイルの再配置、パッケージ化した Android と未署名 arm64 Simulator の CocoaPods コンパイルを確認済み。エンジン／実機での動作確認は未完了 |
| [Flutter](sdk/flutter/README.md) | 非同期プラットフォームチャネルのローカルリスク API。64 件のテスト、バックグラウンドキュー／ネイティブアダプターの確認、Simulator ライブラリのコンパイルを実施済み。エンジン／実機での動作確認は未完了 |
| [ASP.NET Core](sdk/dotnet/README.md) | 実験段階の厳密な検証器／ミドルウェア。元のヘッダーを提供する機能が必須。175 件のテストと分離した NuGet 利用側プロジェクトで確認済み |
| [Go net/http](sdk/go/README.md) | 実験段階の検証器／ミドルウェア。race/vet と分離した利用側プロジェクトで確認済み。信頼できる解析前の情報が必須 |
| [PHP](sdk/php/README.md) | 実験段階の検証器／明示的な受信アダプター。514 件のアサーションと 5 件の生のループバックリクエストで確認済み。Laravel/Symfony との連携は未確認 |
| Redis を共有したリプレイ防止の記録 | 実装済み。デプロイ環境の永続性／エビクション保証は運用者の責任 |
| [登録／ポリシー／監査](docs/security/enrollment-policy.md) | Python SQLite のチャレンジ／証明／鍵と、主体全体の失効。サーバー側の全 6 言語で決定的な 42 ケースのプリセットと、許可リストに基づく監査出力を検証済み |
| [Apple/Google プロバイダー検証](docs/security/provider-verification.md) | 実験段階の Python バックエンド。223 件のオフラインプロバイダーテストと Android 取得モジュール。現在の実機／アカウントを使った真正な検証は未完了。Apple のライフサイクル対応は未完了 |
| [Build / CLI](tools/cli/README.md) | Android R8 のセットアップ／ビルド、Flutter 難読化／Expo 圧縮コマンド、暗号化済みマッピングのアーカイブ／検証／復元。ローカル前提条件／CI チェック、厳密な UTF-8 保持、分離環境での実際の Android リリースビルドを確認済み |
| [ローカルの root 化／フック／脱獄の兆候](protocol/local-risk-v0.md) | 実験段階の Android/iOS 型付きスキャナー。ホスト上のテストとプラットフォームビルドを実施済み。root 化／フック済み実機での有効性は未検証 |
| 任意のコンソール／AI | 計画段階、未実装。コアはどちらもなしで動作 |

## ローカルでのリファレンス開発

Python 3.11+ と [uv](https://docs.astral.sh/uv/) をインストールしてください。リポジトリのルートから実行します。

```sh
uv sync --locked --project reference/python
uv run --project reference/python pytest reference/python/tests -q
```

リファレンスは解析済みの型付き入力を受け取り、処理を Python SDK コアに委譲します。HTTP アダプターは加えて、厳密な[通信形式のサブセット](protocol/http-v0.md)を解析します。既存のトークン認証と登録済み鍵の検索はアプリケーションが提供する必要があり、認可も引き続きアプリケーション側で行います。ユーザートークン認証器は同梱していません。任意のプロバイダーバックエンドには、信頼できる明示的な設定が必要です。署名の検証に成功しても、権限は付与されません。

## サーバー SDK の検証

Python 3.11+、uv、Node.js 22+、Java 17、Maven をインストールしてください。未使用のポートで `127.0.0.1` にバインドした**新しい使い捨て Redis** インスタンスを起動し、テスト用に永続化を無効にしてください。任意のディレクトリから実行できます。

```sh
APPGUARD_TEST_REDIS_URL=redis://127.0.0.1:DISPOSABLE_PORT/0 \
  /absolute/path/to/appguard/scripts/test-server-sdks.sh
```

`APPGUARD_UV_CMD` と `APPGUARD_MAVEN_CMD` で実行ファイルのパスを任意に指定できます。このコマンドは固定された Python/npm のロックファイルを使い、実際の Redis を含む 4 つのテストスイートをすべて実行します。wheel/JAR をビルドして分離環境での npm パッケージインストールをテストした後、Python/Node/Java の順で最初の nonce 記録を処理させ、独立した SDK プロセスを競合させます。Redis 全体のフラッシュは行わず、検証用に所有する鍵だけを削除します。既存の共有 Redis データベースを指定しないでください。各 SDK のコマンドとテスト済みバージョンは、それぞれの README に記載しています。

アダプターには、変更されていない生のターゲット／ヘッダー／ボディの情報と、明示的な ID／リプレイ防止の依存関係が必要です。Python ではクエリ文字列が空の場合、正確なターゲットを伝える信頼できる拡張が必要です。Spring の Servlet アダプターはフォーム／multipart コンテンツとノンブロッキング入力アクセスを拒否します。Express/Nest はアプリケーションルートの最初に導入する必要があります。Fastify にはネイティブ HTTP リクエストの取得が必要です。TLS／プロキシの境界では、信頼できる情報を保持しなければなりません。これらの制約は各 SDK の連携ガイドで説明しています。パッケージを導入するだけでは、デプロイ環境は設定されません。

Go/.NET/PHP のランナー、GitHub Actions ワークフロー、検証範囲については、[継続的インテグレーション](docs/development/continuous-integration.md)を参照してください。追加のサーバー SDK にあるインメモリのリプレイ防止ストアはプロセス内でのみ有効です。複数ワーカーでのデプロイには、実際にテストした共有ストアが必要です。

## ネイティブクライアントと登録の開発

[Android](sdk/android/README.md) と [Apple](sdk/apple/README.md) のパッケージは、インストール単位の P-256 署名機能を使って、正確なリクエストのバイト列と固定の通信ヘッダーを準備します。公開 SPKI データを提供しますが、秘密鍵のエクスポート API は提供しません。HTTP トランスポートアダプターは同梱していません。アプリケーションのトランスポートは、署名したターゲット／ボディ／ヘッダーを保持し、意図しないリダイレクトを防ぐ必要があります。ローカルのハードウェア状態メタデータは、リモート検証済みのアテステーションではありません。

[登録プロトコル](protocol/enrollment-v0.md)は、アプリ、認証済みの主体、登録済み鍵 ID、公開鍵フィンガープリント、オリジン、1 回限りの有効期限を紐付けます。[Python 連携](docs/security/enrollment-policy.md)では、Balanced/Strict に既存の認証と明示的なプロバイダー検証器が必要です。所有証明のみの Basic 登録は、アテステーションを伴わないことを明示しています。Python、Node、Java、.NET、Go、PHP は、[ポリシー契約の 42 件のポータブルケース](protocol/policy-v0.md)を実行します。これらの明示的な API は、信頼できるアプリケーションの判定結果を受け取ります。認証、プロバイダー検証、レートカウンターがプロファイルによって自動導入されることはありません。

ネイティブのテストは、JVM/macOS の暗号処理、プラットフォームビルド、分離した Android ソフトウェア Keystore エミュレーターを区別しています。実際の Apple 永続 Keychain/Secure Enclave、実機、成功したプロバイダー検証情報は、まだ確認していません。これらのテストによって、Apple/Google のプロジェクト、エンタイトルメント、アカウント、リリース、ユーザー鍵が設定されることはありません。

[ブリッジ契約](protocol/client-bridge-v0.md)は、公開鍵の検索、検証済みリクエストの準備、登録時の鍵所有証明だけを公開します。文書に従い、ローカルインストールの前に各フレームワークパッケージのネイティブソースをステージングしてください。JS/Dart/C# ラッパーをインストールするだけでは、Expo Go や既存のバイナリにネイティブコードを追加できません。トランスポート、プロバイダーの判定結果、任意の署名／秘密鍵エクスポートは公開しません。パッケージは正確なボディ／ターゲット／ヘッダーの値を保持します。実際の HTTP 動作はアプリケーション側で検証する必要があります。

対応するローカルアプリプロジェクトでは、`node tools/cli/bin/appguard.js init --project /path/to/app --app-id your-app` が明示的な設定を作成します。`doctor`（読み取り専用のローカル前提条件の確認）、`doctor --check`（CI 用の終了ステータス）、`policy validate`、`build --dry-run`、`archive`、`verify-archive`、`restore` は、[CLI ガイド](tools/cli/README.md)に記載しています。セットアップでは、SDK 依存関係のインストールや公開、プロバイダーアカウントの設定は行いません。暗号化済みアーカイブと同様に、元のビルドマッピングも非公開で保管してください。

## 共通の検証動作

- 制限された P-256/SHA-256 プロファイルによる、固定順序の RFC 9421 署名ベースのバイト列。
- 空のボディやバイナリボディも含む、正確な生のボディの SHA-256 Content-Digest。
- タイムスタンプ／有効期間／時刻ずれの制限、アプリ／鍵／認証済み主体の紐付け、鍵の失効。
- 検証後のアトミックな nonce 記録、明示的でサイズ上限のあるローカルストア、Redis の並行処理、バックエンドエラー時の fail-closed 動作。
- 置換、プロファイル／エンコーディングの曖昧さ、有効期限切れ、メタデータの重複、リプレイを網羅する [40 件のポータブルなリクエストシナリオ](conformance/v0/requests.json)と [43 件の HTTP エンベロープシナリオ](conformance/v0/http.json)。

テストは合成データと固定時計を使い、現在の実時刻は使いません。コミット済みの 4 組の異なる署名／ベースの組み合わせについても、利用可能な場合はシステムの OpenSSL CLI で検証します。この実行ファイルがない場合、この確認は明示的にスキップされます。通常の暗号ライブラリベースの検証器テストは引き続き実行されます。

Python コアのエントリーポイントは `appguard.verify.verify_request` です。`appguard_reference` は互換性のためのインポートを維持しています。[リファレンステスト](reference/python/tests/test_verify.py)では、呼び出し側が提供する信頼できるコンテキストと、テスト専用の署名処理を示しています。本番用の署名 API は含まれていません。登録は引き続き、明示的に利用する実験段階の Python サービスです。リクエスト間でリプレイ防止ストアを再利用してください。インメモリストアの状態は再起動時に失われます。共有 Redis には、明示的な容量、保持、復旧ポリシーが必要です。

## コントリビューションとセキュリティ

[CONTRIBUTING.md](CONTRIBUTING.md)、[SECURITY.md](SECURITY.md)、[脅威モデル](docs/security/threat-model.md)、[ドラフトプロトコル](protocol/request-v0.md)をお読みください。Issue、フィクスチャ、ログに本物のシークレットや本番の鍵データを公開しないでください。

プロジェクトで作成したコードとドキュメントには [Apache-2.0](LICENSE) ライセンスが適用されます。依存関係とサードパーティのライセンスは、それぞれのものが適用されます。
