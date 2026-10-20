# Framework local risk bridge verification

Base aabe60116895dad9dbb33aa11939a2645070d8bd; implementation branch
codex/appguard-risk-bridges. This stage exposes the existing optional native
scanner through all three framework packages, preserving independent authentication,
request signatures and provider attestation. Local reports are forgeable hints,
not app/device integrity or authorization verdicts. No publication, account setup,
production deployment, hosted CI or store review is claimed.

## Public APIs and common contract

- Unity: `await new AppGuard.Client().ScanLocalRiskAsync(options)`.
- Expo/React Native: `await scanLocalRisk(options)` from `@appguard/expo`.
- Flutter: `await AppGuard().scanLocalRisk(options: options)`.

All use the new [scanLocalRisk JSON operation](../../protocol/client-bridge-v0.md).
Optional expectedAppId/androidSignerSha256/protectedResources match native bounds.
No alias, hardware requirement, key, clock or injected observation input is accepted.
The entire config validates before a probe. iOS rejects nonempty valid Android
signer expectations explicitly; it does not silently discard protection settings.
Native input/envelope bounds are 8192/4096 UTF-8 bytes. Existing signing operations
retain their 1.5 MB limit and native key/time behavior. Wrapper options snapshot caller
collections; report parsers enforce exact schema/fields/check order/states and
recomputed signal order, returning immutable or defensive values.

The 32 shared report cases (8 valid / 24 invalid) cover both platforms and rejection of
extra/missing fields, wrong types, reordered/duplicate checks/signals, unsupported
states and inconsistent derived hints. Missing/old native modules reject explicitly;
no clean fallback, JS/Dart/C# secret, network transport or background monitor exists.

## Fresh observed checks

| Boundary | Result |
| --- | --- |
| Android native facade | 7 new real-scanner facade tests;54 per debug/release variant = 108 executions, zero failures/errors/skips; AAR/lint/test APK pass |
| Android native runtime | 3 tests on task-owned API 35 AOSP arm64 emulator,including actual app ID/current independently pinned APK signer/AssetManager bytes through JSON scan; no key calls |
| Apple native facade | 14 new tests;79 total Swift tests pass;generic Simulator Debug arm64/x86_64 and device Release arm64 unsigned builds pass;privacy resources match |
| Expo/React Native | 61 tests/typecheck; 44-file relocated npm pack ; actual final consumer Kotlin/Java and unsigned arm64 CocoaPods AppGuardExpo builds pass |
| Flutter | 64 Dart tests/analyzer; 28 Java assertions against actual engine/API 36;Swift host eight-result/thread/queue/lifecycle checks ; actual Simulator framework compile/link and 18 native/license hash readbacks pass |
| Unity | 71 EditMode tests ; actual Android/iOS/runtime/postprocessor compilation ; owned worker/JNI lifetime tests ; ASan 10,000 invoke/free cycles and zero leaks |
| Unity native interop | 6 actual host C ABI scans and two managed async/PInvoke scans with two matching frees;arm64 device/Simulator objects;real PBX privacy export fixture and final source relocation pass |
| Policy consequence |Actual captured native Android JSON is decoded by the compiled Expo parser and passed as untrusted signals to real Node policies;Basic observe/Balanced step_up/Strict deny,with separately synthetic trusted server flags |

Platform/package commands, RED/GREEN details, hashes and limitations:
[Android](../../sdk/android/RISK_BRIDGE_VERIFICATION.md),
[Apple](../../sdk/apple/RISK_BRIDGE_VERIFICATION.md),
[Expo](../../sdk/expo/RISK_BRIDGE_VERIFICATION.md),
[Flutter](../../sdk/flutter/RISK_BRIDGE_VERIFICATION.md),
[Unity](../../sdk/unity/RISK_BRIDGE_VERIFICATION.md).
The Expo consumer was refreshed from the final packed native sources and CocoaPods
regenerated using task-local configuration. Previous installed package/SDK libraries
were preserved; preexisting Gradle caches were reused. Third-party Gradle deprecated
feature and Flutter sysroot warnings remain documented; Flutter artifact platform
is independently checked as iOS Simulator. No dependency upgrades were made.

## Scheduling and evidence boundaries

Expo retains its existing background AsyncFunction. Flutter registers official
background task queues, returns explicit unavailable if queue support is absent,
and handles detach without silently moving scan I/O to the UI thread. Unity owns
a fresh worker thread and its JNI attach/detach lifetime; no caller or pooled
thread is detached. Host doubles and actual API compilation establish different
facts from a real framework engine/player; those runtime tiers remain unverified.

Official scheduling references:
[Expo AsyncFunction](https://docs.expo.dev/modules/module-api/),
[Flutter task queues](https://docs.flutter.dev/platform-integration/platform-channels),
[Unity JNI attachment](https://docs.unity3d.com/6000.0/Documentation/ScriptReference/AndroidJNI.AttachCurrentThread.html).

The prior native stage's disk blocker was rechecked: 31 GiB free allowed this stage's
owned emulator to boot. Three native instrumentation tests passed. It was then
identified by PID/AVD/serial, stopped, and its disposable disks removed; all 61 global
AVD metadata hashes/inventory remained unchanged. Shared ADB was left running.
This establishes native facade runtime, not an Expo/Flutter engine or Unity mobile
player, physical rooted/jailbroken/hooked efficacy, live provider verification, Apple
persistent Keychain/Secure Enclave, or signed-archive privacy/store acceptance.
Reports remain bypassable and can be omitted/forged by a compromised app. Default
health-hint policy remains explicit; iOS release debugger unavailable is unchanged.
Native binary rebuilds are necessary: wrapper/OTA installation cannot add this
native operation to an older binary. React Native requires Expo Modules integration.

## Review and local integration

The original fresh read-only whole-stage security review found **0 Critical, 0 Important,
1 Minor**. Its independent checks reran all seven Android facade tests, 24 actual
Apple host C ABI calls, 32 Unity and 32 Expo shared vectors, Flutter in-flight
detach/success/throw probes, and all staged native/privacy/corpus hashes.
No Critical/Important fix pass or second review was needed.

The original Minor concerned Unity's acceptance of single-quoted/unquoted keys,
trailing commas and comments around an otherwise valid response. It is now
resolved by the [strict JSON follow-up](../../sdk/unity/STRICT_JSON_VERIFICATION.md):
a bounded syntax pass precedes the unchanged duplicate-key and semantic checks,
and 138 Unity EditMode tests pass. Original stage counts and evidence above remain
historical; the follow-up records its own review and current native interop checks.

Rulings retained: reject unsupported signer expectations explicitly (shared configs
need platform-specific pins); dispatch explicit snapshots off UI threads (callers
own frequency/freshness, with no continuous monitor); retry an owned emulator only
after fresh capacity verification (native runtime does not prove framework engine
runtime). Host/compile evidence remains bounded: real Unity/IL2CPP/JNI and Flutter/
Expo mobile-engine timing or integration issues can remain until separate player/
app builds are installed and exercised.

Exact source/package/artifact hashes, raw logs, independent review probes, ownership
and shutdown receipts are retained in the attached worktree's ignored archive
`.superpowers/evidence/2026-10-20-risk-bridges/`, with package-owned evidence/caches
preserved. Only this stage's scratch is removed after checksummed archive/readback.
Integration uses the authorized clean local main fast-forward and exact source
comparison. No push, publication or existing user data cleanup is included.
