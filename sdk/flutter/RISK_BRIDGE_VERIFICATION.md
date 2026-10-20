# Flutter local risk bridge verification

Observed locally on 2026-10-20. This experimental package remains unpublished.

Run `tool/verify_risk_bridge.sh` after the sibling Android and Apple sources are
ready. It stages their current bytes, uses package-owned `.evidence/risk-bridge`
outputs, and preserves earlier `.evidence` receipts. `FLUTTER_ROOT` defaults to
`.tools/flutter`; `ANDROID_HOME` identifies the Android SDK; `RUBY` can identify
a Ruby runtime containing CocoaPods. No global SDK/account configuration is changed.

Command executed:

```sh
ANDROID_HOME=/Users/uulab/Library/Android/sdk \
RUBY=/Users/uulab/.local/share/mise/installs/ruby/3.3.4/bin/ruby \
tool/verify_risk_bridge.sh
```

- Flutter 3.47.0 / Dart 3.13.0: all 64 tests pass (17 existing + 47 new).
  New tests exercise all 32 shared report cases, exact empty/configured payloads,
  options snapshot and immutable collections, malformed/null/wrong-type input,
  IDs/paths/pin/count boundaries, fixed errors, missing native plugin, redaction,
  and exact 4096-byte scan response acceptance / 4097-byte rejection. Scan's
  bounded configuration cannot reach 8192 bytes with valid field bounds; native
  adapter probes separately exercise exact input-limit acceptance and UTF-8
  overflow rejection. A 9000-byte existing-operation response remains accepted.
- `flutter analyze`: no issues found.
- Missing API/queue/lifecycle definitions first produced expected RED compilation
  failures, retained in `dart-red.log`, `java-red.log`, and `swift-red.log`.
- Java 17.0.20 compiler with `javac --release 11`, actual Flutter engine
  `flutter.jar`, and Android SDK 36 `android.jar`: all staged native sources and
  the plugin compile; host `AdapterProbe` passes 28 assertions. It checks exact
  forwarding, malformed input, fixed failures, scan UTF-8 input/output bounds,
  preserved existing-operation limits, background task-queue registration,
  execution on the messenger's worker thread, unsupported queues and detach.
- Swift host `AdapterProbe` passes eight result assertions plus queue registration,
  non-main-thread invocation, publication/detach and no-probe unavailable checks.
  It compiles the actual adapter against a host protocol double and a spy native
  bridge. The shim and probe are excluded from the packed plugin.
- Xcode 27.1: all eight staged Apple Swift sources plus the actual plugin compile
  and dynamically link against the installed simulator `Flutter.xcframework`.
  `vtool` confirms `IOSSIMULATOR`, minimum iOS 15.0. The linker reports the same
  incompatible-sysroot warning seen in earlier verification, mentioning macOS
  27.0; the artifact's platform is explicitly checked. No simulator was booted.
- Final archive extraction verifies 18 source/license SHA-256 hashes against both
  packed files and current sibling SDK sources. Both facade implementations and
  the native privacy manifest are present, without repository-relative native
  dependencies or host test shims. Ruby 3.3.4 / CocoaPods resolves all nine actual
  plugin/native Swift sources and `AppGuardFlutterPrivacy.bundle`, including the
  exact `FileTimestamp` / `C617.1` required-reason declaration.

Receipts live in `.evidence/risk-bridge/`: `dart-green.log`, `analyze.log`,
`java-green.log`, `swift-host.log`, `swift-actual-framework.log`, `package.log`,
`privacy-resource.log`, `verification.log`, and `artifact-sha256.txt`. The latter
records archive, native library, and staged-source provenance manifest hashes.
`native-provenance.json` binds all 18 native source/license files to staged bytes.
The archive includes this receipt; repackage after modifying it.

Registration follows the official [Flutter background task queue examples](https://docs.flutter.dev/platform-integration/platform-channels#execute-channel-handlers-on-a-background-thread-android).
The installed `FlutterChannels.h` explicitly permits result callbacks from any
thread; this adapter returns one result on the handler's queue. Android's result
callbacks likewise support arbitrary threads. Detach rejects later calls while
an already captured invocation can finish once. Engines without queue support
return a fixed native-unavailable envelope without scanning on a UI handler.

Limitations: Dart mocks and host protocol/adapter probes are not execution inside
a mobile Flutter engine. This stage does not establish physical-device scanning,
root/hook detection efficacy, persistent key operations, provider verification,
networking, signing, release, or store approval. No new full Flutter app build or
emulator/device run was required. Privacy resource resolution is not proof of a
signed distribution archive. The installed Flutter runtime was reused; no new
SDK download provenance is asserted.
