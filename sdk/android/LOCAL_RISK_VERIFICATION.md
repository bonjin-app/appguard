# Android local risk verification

Scope: optional read-only local hints under `LocalRiskScanner`, Android API 26+.
These checks do not attest device integrity or authorize a request. Root/hook
heuristics have no physical rooted/hooked-device efficacy evidence in this stage.

## Reproduction

From `sdk/android`:

```sh
export JAVA_HOME=/Users/uulab/Library/Java/JavaVirtualMachines/jdk-17.0.20+8.jdk/Contents/Home
export ANDROID_HOME=/Users/uulab/Library/Android/sdk
export GRADLE_USER_HOME="$PWD/.tools/gradle-home"
./gradlew --offline --no-daemon test assembleRelease lint
./gradlew --offline --no-daemon assembleDebugAndroidTest
```

The local `.tools` Gradle cache and test-only signing key are package-owned;
commands do not use or modify the user debug key. Evidence logs, source SHA-256
manifest and built AAR receipt are retained in ignored `.evidence/local-risk/`.
No dependency, manifest permission, existing signing/enrollment API or global
configuration change is part of this implementation.

## Behavioral evidence

The initial minimal API scaffold compiled and all 14 scanner tests failed on
missing scanner behavior (`red.log`). The first full suite reported 41 tests,
40 passing and one failing because an empty certificate fixture was treated as
malformed rather than as an unknown current signer. That fixture now uses
nonempty unknown signer bytes; a separate malformed-certificate case requires
unavailable. Follow-up boundary RED logs cover positive signer precedence and
file-not-found raised during an already-open resource read.

Tests exercise real parsing, byte hashing over temporary files, size limits,
configuration validation, fixed JSON fields and category ordering, defensive
copies, optional checks, and denied/missing/malformed observations through
package-private OS seams. Such fixtures establish contract behavior, not actual
root/hook efficacy or complete coverage of device/vendor restrictions.

## Adapter runtime

`LocalRiskScannerInstrumentedTest` uses the actual scanner constructor and test
APK context. Pass `-e expectedSignerSha256 <lowercase digest>` from an independent
`apksigner verify --print-certs` observation of the test APK. It checks actual
PackageManager current signer, identity mismatch, pinned AssetManager bytes,
missing assets, redacted output, and finite own-process/debug observations.
Root/hook checks are allowed to be unavailable under the OS sandbox. It does
not create root artifacts, alter system state or assert emulator cleanliness.

Instrumentation source/build and an emulator run are separate evidence tiers.
The Android worker does not start/stop or alter existing emulators/AVDs; runtime
execution and the whole-stage security review are coordinated by the parent.

## Final local result

`test assembleRelease lint assembleDebugAndroidTest` passed with 19 scanner tests
and 27 existing native SDK tests in each of debug and release: 92 executions,
zero failures. Android lint reported no issues. The release AAR and instrumentation
APK compiled. Final source/artifact SHA-256 receipts and XML test results are in
`.evidence/local-risk/`.

Additional parser boundary: an out-of-range numeric `TracerPid` field first
failed a direct JUnit regression (`red-tracer-overflow.log`) by reporting detected;
it now reports unavailable. The full Gradle test/build/lint pass includes the fix.
This direct regression compiled the scanner and test with the cached JUnit 4.13.2,
org.json 20250517, Hamcrest 1.3 and Android API 36 jar under the same Java 17 runtime.

No genuine rooted/hooked-device, physical-device, store, network/provider or
hardware-attestation result is established. Runtime receipts, when collected,
are owned by the parent stage report and must be distinguished from these host
and compilation checks. The scanner does not extend `NativeBridge` or alter any
existing request or enrollment verification behavior.
