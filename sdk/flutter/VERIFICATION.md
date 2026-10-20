# Flutter bridge verification

Observed locally on 2026-10-20; experimental, unpublished package.

- Flutter 3.47.0 stable (`4cf2416426`), Dart 3.13.0, engine `5f77625673`. The installed mise SDK was copied into ignored `.tools/flutter` for task-local use. The official SDK metadata/download attempts returned HTTP 404; no downloaded runtime provenance is asserted.
- `flutter test`: 17 tests passed after 17 expected RED stub failures. Covers exact binary body/base64 and explicit empty query, operation/schema mapping, ordered header round-trip, enrollment challenge/expected bindings, four fixed native codes, missing plugin, unexpected platform exception redaction, malformed/incorrectly typed responses, oversized body before native access.
- `flutter analyze`: no issues found.
- Java 17.0.20 and Android SDK 36: compiled plugin and staged native sources against the actual Flutter engine `flutter.jar` and `android.jar`. Host `AdapterProbe` observed RED then GREEN, 11 assertions; verifies argument types/shape, exact payload and operation forwarding, unknown channel method, fixed redacted exception response and detached/missing native state. It does not access Android keys.
- Gradle 8.11.1 / Android Gradle Plugin 8.10.1: standalone `assembleDebug` passed (22 tasks), producing a plugin AAR containing the native facade. The verification-only init script supplies Flutter's engine jar as `compileOnly`; a consuming Flutter app supplies this dependency through Flutter tooling.
- Xcode 27.1 (`27A9275`): Swift typecheck and dynamic-library link passed for all staged Apple source and the plugin against the actual simulator `Flutter.xcframework`. Target `arm64-apple-ios15.0-simulator`; `vtool` confirms IOSSIMULATOR platform and minimum iOS 15.0. Linker emits a sysroot compatibility warning mentioning macOS 27.0; artifact platform is explicitly verified. No simulator was booted.
- CocoaPods 1.17.0 / Ruby 3.3.4: an isolated Flutter iOS app installed the relocated archive as a path dependency. `flutter build ios --simulator --debug --no-codesign --config-only` succeeded, then explicit `pod install --deployment` succeeded: 2 dependencies and 2 pods (`Flutter`, `appguard_flutter`). CocoaPods home/cache and Xcode derived data remain task-local under `.evidence/`. Flutter warns that the plugin lacks Swift Package Manager support and currently accepts CocoaPods; CocoaPods warns about the generated consumer's Profile base configuration.  Debug includes the generated Pods xcconfig. `xcodebuild -workspace Runner.xcworkspace -scheme Runner -configuration Debug -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' -derivedDataPath <task-local> -clonedSourcePackagesDirPath <task-local> CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build` then completed with `BUILD SUCCEEDED`. The installed plugin framework contains arm64 and x86_64 slices, both IOSSIMULATOR/minimum iOS 15/SDK 27.1. The complete Runner app also contains both architectures; `codesign -dv` reports only a linker-generated ad hoc signature and no TeamIdentifier, not certificate/provisioning signing. No simulator was booted and no runtime key operation was executed.
- Local archive extraction verifies every staged source/license hash, rejects path escapes/symlinks, and includes both actual native facades. A relocated Flutter path-dependency consumer resolves and analyzes separately from the repository package. Native source hashes in `native-provenance.json` identify the exact staged bytes; no published artifact or source commit immutability is implied.

Run `python3 tool/pack.py` before using/redistributing the package. Packaging creates a local tarball only. Staging scripts require this source repository; they are excluded from the packed plugin. `tool/verify.sh` records repeatable package/native checks using caller-provided SDK locations.

Limitations: no engine/device channel execution, persistent Android Keystore or Apple Keychain/Secure Enclave operation through Flutter, hardware backing, provider attestation, end-to-end HTTP signing/send, store, release, or physical-device evidence. Dart channel mocks and host adapter probes are not those runtime checks. Native SDK verification is documented independently in the native packages.

Local-risk follow-up: all 17 tests, analyzer, 11 Java adapter assertions and the
final staged native Simulator library compile pass. The relocated archive verifies
18 source/license hashes. Actual CocoaPods resolution and an unsigned resource
target build carry `AppGuardFlutterPrivacy.bundle` with the native manifest bytes;
omitting that resource declaration first failed the accessor check. The resource
fixture uses a placeholder Flutter dependency and does not establish a new complete
Flutter app build or scanner channel API. See the repository's
[stage receipt](../../docs/security/local-risk-verification.md).
