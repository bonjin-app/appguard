# Unity mobile player and IL2CPP verification

Observed 2026-10-20 from base `3a27545140eb0ef6a52e6f7254bb15c643d2952b`,
using the existing Unity 6000.3.24f1, Xcode 27.1, Android SDK 36 and JDK 17.
The scope is the public asynchronous **local-risk bridge**, not key enrollment,
request signing, live attestation, physical-device detection efficacy or release.
No SDK runtime/native production source needed a correction in this stage.

## Actual evidence tiers

| Target | Build | Runtime |
| --- | --- | --- |
| Android arm64 | Actual APK, IL2CPP, High managed stripping, R8 enabled, task-owned fixture signing key | AOSP API 35 emulator; 11/11 cases, `development=false`, matching build GUID and PASS log, process alive, no fatal JNI/Java markers |
| iOS arm64 Simulator | Actual app linked by Xcode Release, IL2CPP, High managed stripping | iOS 26.5 private Simulator; 11/11 cases, matching GUID/PASS log and live process; Unity **Development engine** (`development=true`) |
| iOS arm64 device | Actual unsigned Release app, IL2CPP, High managed stripping; Mach-O device platform and both AppGuard exports verified | No device installation or execution |

Unity's installed simulator variants contain `Development_simarm64_managed` and
`Development_simx64_managed`, with no Release simulator variant. `BuildOptions.None`
and Xcode Release do not turn that engine into a Release player. The first receipt
was correctly rejected by the original release-only gate; target-specific tests now
require true for the pinned Simulator tier and false for Android. This establishes
Simulator IL2CPP interoperation, not iOS Release runtime behavior.

The 11 cases are defaults, identity match/mismatch, exact deployed resource
match/mismatch/missing, Android signer mismatch/iOS unsupported signer pins,
invalid configuration with fixed errors, 16 concurrent scans, eight sequential
scans afterward, and a frame heartbeat. Reports continue through the real
`PlatformTransport`, JNI/C ABI and native probes. No fake transport or software
substitute is installed. Native scan results remain untrusted heuristic hints.
In the verified runs both engines advanced frames while concurrent scans were
pending; this is a bounded observation, not a mobile latency guarantee.

## Verification and fixes

- Existing actual Unity EditMode suite: **138/138**, zero failures/skips. Actual
  Android/iOS runtime branches and iOS postprocessor compile again.
- Host receipt/launcher/log-gate regressions: **15/15**. RED/GREEN covers empty
  matching GUIDs, boolean frame counts, missing/duplicate/failed cases, incorrect
  platform/backend/development tier, fatal logs, and malformed launcher resolution.
- Relocated native SDK sources rebuilt into the AAR and device/Simulator XCFramework.
  All 84 original staged manifest files and current runtime source correspondence
  were read back. AAR consumer rules retain the JNI facade. The final APK contains
  arm64 IL2CPP and exact fixture bytes; the actual generated release Gradle section
  has `minifyEnabled true`.
- Actual iOS Simulator/device apps contain `AppGuardUnityInvoke` and
  `AppGuardUnityFree`; Mach-O platform receipts distinguish the two. Both carry the
  byte-identical staged Apple privacy manifest in `AppGuardPrivacy.bundle`.
- Initial Android `monkey` launch failed with exit 251 on the AOSP image's physical
  key check. The runner now resolves exactly one launcher in the fixed smoke package
  and uses `am start -W`, retaining failed-command diagnostics before raising.
- A first immersive-mode confirmation and System UI ANR blocked focus/startup on
  the new owned emulator. Screenshots/logs distinguish this environment issue from
  SDK execution. Only that disposable emulator's confirmation was set and System UI
  restarted. A fresh automated uninstall/install/run then verifies the final artifact.
- Xcode 27.1 emits libc++ deployment warnings for the iOS 15 target, Unity run-script
  output warnings and skipped AppIntents metadata. Android emits the engine's clang
  command-line warnings. These builds succeeded; no iOS 15 physical compatibility,
  warning-free build, or store acceptance is inferred.

## Reproduce

First stage a new local package and build its native plugins as described in
[README.md](README.md). Use explicit new output directories and task-owned projects:

```sh
python3 Tools~/test-player-runner.py
python3 Tools~/test-player.py --unity /path/to/Unity \
  --staged-package /absolute/staged-package \
  --work-directory /absolute/task-project --output-directory /absolute/android-build \
  --target android
# Targets ios-simulator and ios-device export separate actual Xcode projects.
# Build the exported Unity-iPhone scheme with Xcode, arm64, CODE_SIGNING_ALLOWED=NO.
python3 Tools~/run-player.py --target android \
  --artifact /absolute/android-build/player.apk \
  --build-receipt /absolute/android-build/build-receipt.json \
  --evidence-directory /absolute/new-runtime-evidence \
  --android-adb /path/to/adb --android-serial emulator-XXXX
# iOS runtime: --target ios-simulator --artifact /absolute/AppGuardPlayerSmoke.app
# --build-receipt /absolute/ios-build/build-receipt.json
# --evidence-directory /absolute/new-runtime-evidence
# --ios-set /absolute/task-owned-simulator-set --ios-udid <explicit-UDID>
```

The runner refuses an already-installed smoke app and requires an explicit virtual
device selector. It does not create/delete devices, restart system services, unlock
personal devices, or infer runtime success from launch. The fixture uses only
`io.appguard.unity.playersmoke` and no SDK installation keys, network, account or
provider operations. Android build signing uses its own disposable local keystore;
no production signing settings are used.

Raw Unity/Xcode/runtime evidence remains in `.evidence/player-runtime/` and owned
`.tools/player-*` artifacts. Parent coordination, source/artifact hashes, first
failures, review and clean-main readback are archived under
`.superpowers/evidence/2026-10-20-unity-player-runtime/` in the managed worktree.

## Review and integration

One fresh whole-change security review is pending before local main integration.
The author retains the bounded custom receipt/component gates with focused tests;
Simulator development, iOS 15 compatibility and physical runtime limits remain
explicit. Another platform/engine/version requires its own evidence.
