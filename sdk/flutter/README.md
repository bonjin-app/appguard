# AppGuard Flutter (experimental)

Android 26+ and iOS 15+ plugin for native installation public keys, request preparation, and enrollment possession proof. The native SDK owns validation, keys, and cryptography. There is no Dart secret, signing fallback, automatic enrollment, HTTP transport, or provider verdict.

## Local package

From this repository, run `python3 sdk/flutter/tool/pack.py`. It stages the sibling Android and Apple SDK source files with licenses and SHA-256 provenance, then creates `sdk/flutter/.evidence/appguard_flutter.tar.gz`. Extract that archive into an independent directory and use a Flutter path dependency to it. The archive has no repository-relative native dependencies and excludes tooling, test outputs, caches and SDK runtimes. Local development directly against this checkout first requires `python3 sdk/flutter/tool/stage_native.py`.

The CocoaPods pod compiles the staged Apple SDK into the plugin module; it does not require a remote AppGuard pod or Swift package. Android compiles the staged Java sources. Set the consumer Android minimum SDK to 26 and iOS deployment target to 15.0. Keep the included native licenses and provenance with redistributed sources. This plugin currently supplies CocoaPods integration only. On Flutter versions that default to Swift Package Manager, select CocoaPods per consumer project without changing global Flutter settings:

```yaml
flutter:
  config:
    enable-swift-package-manager: false
```

The Apple SDK privacy manifest ships in `AppGuardFlutterPrivacy.bundle`; verify it
in your final archive. Staged SDK sources include optional native local risk
scanners. Dart channel scanner operations remain outside this plugin's API.


## API

```dart
import 'dart:typed_data';
import 'package:appguard_flutter/appguard_flutter.dart';

final guard = AppGuard();
final key = await guard.publicKey(
  alias: 'installation', hardwareRequirement: HardwareRequirement.any);
final request = await guard.prepare(
  alias: 'installation', hardwareRequirement: HardwareRequirement.any,
  origin: 'https://api.example.com', method: 'POST', target: '/v1/items?',
  body: Uint8List.fromList([0, 255, 128]),
  contentType: 'application/octet-stream', authorization: 'Bearer token',
  appId: 'my-app', keyId: 'server-enrolled-key',
  created: created, expires: expires, nonce: nonce);
// Send request.body and request.headers to request.origin + request.target.
```

Use the returned method, exact ASCII target (including a trailing empty query), binary body and ordered header pairs unchanged. Configure your HTTP integration to prevent redirects, target rewriting and Authorization replay to another origin. The plugin does not supply transport. Request timestamps and canonical nonce remain explicit; the native wall clock validates them. Native input is limited to 1,500,000 UTF-8 JSON bytes and 1,048,576 decoded body bytes.

`enrollmentProof` accepts a typed `EnrollmentChallenge` plus separate `expectedAppId`, `expectedOrigin`, `expectedSubject`, and `expectedKeyId` fields. It returns `proofBase64`, `clientDataHashBase64`, and `googleRequestHash`, which are possession proof/hash outputs only. Acquire provider evidence and validate enrollment on your server separately.

`HardwareRequirement.hardware` requires native hardware storage; `.strongbox` is Android-only and Apple rejects it. Storage labels report local backing, not attestation. Unsupported requirements never silently downgrade. Handle `AppGuardException.code`: `APPGUARD_INVALID_INPUT`, `APPGUARD_KEY_UNAVAILABLE`, `APPGUARD_UNSUPPORTED`, `APPGUARD_OPERATION_FAILED`, or `APPGUARD_NATIVE_UNAVAILABLE`. Error strings omit native messages, details, tokens and bodies. Missing/unsupported native plugins fail explicitly.

## Verification

See [VERIFICATION.md](VERIFICATION.md) for observed checks and limitations. Dart tests use Flutter's mock binary messenger; they prove serialization/error behavior, not running platform keys or a Flutter engine on a device. No physical-device, live provider, publication, or store result is asserted.

The channel is `io.appguard/client`, method `invoke`, with exactly `{operation, payload}` where payload is the native v0 JSON string. Operation names are `publicKey`, `prepare`, `enrollmentProof`.

Official references: [Flutter plugin development](https://docs.flutter.dev/packages-and-plugins/developing-packages), [platform channels](https://docs.flutter.dev/platform-integration/platform-channels).
