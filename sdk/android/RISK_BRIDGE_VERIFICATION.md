# Android local risk JSON bridge verification

Base aabe601; experimental optional scanLocalRisk operation. Config and reports
follow protocol/client-bridge-v0.md and local-risk-v0.md. No alias/key/hardware/
clock input is accepted for a scan. Native configuration validation completes
before any probe; scans perform no key load/create/sign, clock or network action.

## Fresh results

- Seven new real-scanner facade tests observed RED (all7 failed with unsupported
  after the internal seam scaffold), then GREEN. An earlier missing-seam compile
  failure and a test-only JSONArray Android stub API mismatch are retained but
  are not behavioral RED evidence.
- Full debug/release unit suites:54 tests per variant,108 executions,zero failures,
  errors or skips. Existing request/enrollment cryptographic and strict JSON tests
  remain green. Release AAR,lint(no issues) and instrumentation APK build pass.
- New cases cover default/optional lookup suppression, actual pinned temporary
  binary resource bytes, current signer/app ID mapping, exact seven-check redacted
  report, states/category precedence, invalid IDs/paths/hash/counts/types/nulls,
  duplicate decoded config/resource keys, flat string-array limits/nesting,
  distinct signer pins, exact8192UTF8 input bound and fixed operation failures.
  Key/clock sentinels throw if touched; invalid config keeps scan/probe counters0.
- A task-owned API35 AOSP arm64 emulator ran3 instrumentation tests. Independent
  apksigner certificate input verifies actual current APK signer,app ID and asset
  digest through both typed scanner and public JSON facade. Output excludes all
  configured values. Actual proc/debug checks produce finite states; no clean
  emulator/root/hook verdict is asserted. No persistent key operation is invoked.
- This is native SDK runtime evidence, not Unity/Expo/Flutter engine/player runtime
  or physical rooted/hooked-device detection efficacy.

Commands: JAVA_HOME=<Java17> ANDROID_HOME=<SDK>
GRADLE_USER_HOME=$PWD/.tools/gradle-home ./gradlew --offline --no-daemon
 test assembleRelease lint assembleDebugAndroidTest. Instrumentation:
 adb -s <ownedserial> shell am instrument -w -r -e class
 io.appguard.android.LocalRiskScannerInstrumentedTest -e expectedSignerSha256
 <apksigner-current-test-APK-SHA256> io.appguard.android.test/androidx.test.runner.AndroidJUnitRunner.

Exact logs/XML/source/artifact hashes and runtime readback are retained in owned
.evidence/risk-bridge/ and the parent stage archive. No device/account/global AVD
configuration was changed; no publication or remote CI operation is included.
