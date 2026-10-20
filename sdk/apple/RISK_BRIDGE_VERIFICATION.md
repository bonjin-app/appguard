# Apple local-risk JSON bridge verification

The native JSON facade now accepts `scanLocalRisk` and returns the existing
`appguard-local-risk-v0` typed scanner report inside `{ok:true,result:...}`.
This report contains optional, untrusted hints; it does not prove a clean device,
a valid executable signature, or request authorization.

## Scope and API

Worktree: `/Users/uulab/.codex/worktrees/appguard-protocol-foundation/appguard`.
Branch: `codex/appguard-risk-bridges`; starting commit:
`aabe60116895dad9dbb33aa11939a2645070d8bd`. This worker changed only
`sdk/apple/Sources/AppGuardApple/NativeBridge.swift`,
`sdk/apple/Tests/AppGuardAppleTests/LocalRiskBridgeTests.swift` and this receipt.
The parent owns shared contract review, staging, commits and integration.

```swift
let responseJSON = NativeBridge().invoke(
    operation: "scanLocalRisk",
    payload: "{}"
)
```

The payload must be an object with only optional `expectedAppId` string,
`androidSignerSha256` string array and `protectedResources` object fields.
Omitted options and empty arrays/maps are valid. `LocalRiskConfiguration` performs
existing app identifier, resource path, pin and eight-resource validation.
Android signer pins must be distinct lowercase 64-hex strings, with at most eight
entries. All configuration is validated before probing. Nonempty valid Android
signer pins produce `APPGUARD_UNSUPPORTED` on iOS after remaining configuration
validation; malformed configuration produces `APPGUARD_INVALID_INPUT`.

The scan has an 8,192-byte UTF-8 input limit and a 4,096-byte response envelope
limit. A scanner result exceeding that output bound produces the fixed
`APPGUARD_OPERATION_FAILED` envelope. The parser preserves duplicate decoded key
rejection and permits only bounded, flat string arrays for this operation.
The existing three operations retain their fields, grammar and 1,500,000-byte
input limit. Scan dispatch precedes every key/clock path and takes no alias,
hardware requirement, caller observations, time, credentials or network input.

The report keeps exactly `schema`, `platform`, `checks`, `riskSignals`, with the
existing five ordered iOS checks, four states and derived ordered categories.
Encoding uses the typed `LocalRiskReport`; configuration/native error details do
not enter the JSON response. The internal scanner closure seam leaves existing
key-provider/clock initializer calls source-compatible and is inaccessible to
SDK consumers. It permits host tests to use the real typed scanner above a
controlled probe without persistent Keychain state. The public scanner and facade
remain synchronous; framework adapters must schedule scans off their UI thread.

## Test-first evidence

Captured on 2026-10-20, macOS 27.0.1 (26A434), arm64, Xcode 27.1 (27A9275),
Apple Swift 6.4 (`swiftlang-6.4.0.34.1`, clang 2100.3.34.1).
Raw logs and SHA-256 manifests are locally ignored under `.evidence/risk-bridge/`.

| Step | Result | Evidence file |
| --- | --- | --- |
| Missing internal scanner seam | Compile RED: extra `localRiskScanner` initializer argument | `red-api.log` |
| Seam present; operation still absent | Behavioral RED: 13 tests, 109 assertion failures | `red-behavior.log` |
| Scan implementation | Focused GREEN: 13 tests, zero failures | `green-focused.log` |
| Remove output-budget guard temporarily | Regression RED: one test, two failures; 5,227-byte response escaped | `red-output-bound.log` |
| Restore guard; final full suite | GREEN: 79 tests, zero failures, including all 14 new bridge tests | `green-full.log` |

Commands from repository root:

```sh
swift test --package-path sdk/apple --filter LocalRiskBridgeTests
swift test --package-path sdk/apple --filter LocalRiskBridgeTests.testOversizedTypedScannerOutputReturnsBoundedFixedFailure
swift test --package-path sdk/apple
```

The 14 new tests cover default real-host scanning; configured option mapping;
exact report keys, check/state/category serialization and redaction; omitted/empty
configuration; native probe exceptions becoming unavailable; no key/clock calls;
malformed configuration rejected before scanner invocation; unknown fields,
nulls, wrong types and nested/nonstring arrays; trailing/invalid JSON and malformed
Unicode escapes; literal/escaped duplicate keys and signer values; exact signer,
identifier, resource path, hash and collection bounds; escaped ASCII decoding;
8,192/8,193-byte input; output-budget enforcement; validation before iOS signer
unsupported; and preservation of old-operation rejection behavior.
Existing tests use ephemeral cryptographic keys or in-memory storage boundaries.
No persistent key creation/loading/signing was requested by this verification.

## Current-source unsigned iOS builds

SDK versions: iPhoneSimulator 27.1 and iPhoneOS 27.1. Commands from `sdk/apple`:

```sh
xcodebuild -scheme AppGuardApple -destination 'generic/platform=iOS Simulator' \
  -configuration Debug -derivedDataPath .evidence/risk-bridge/deriveddata-simulator \
  CODE_SIGNING_ALLOWED=NO IPHONEOS_DEPLOYMENT_TARGET=15.0 \
  ARCHS='arm64 x86_64' ONLY_ACTIVE_ARCH=NO build
xcodebuild -scheme AppGuardApple -destination 'generic/platform=iOS' \
  -configuration Release -derivedDataPath .evidence/risk-bridge/deriveddata-device \
  CODE_SIGNING_ALLOWED=NO IPHONEOS_DEPLOYMENT_TARGET=15.0 \
  ARCHS=arm64 ONLY_ACTIVE_ARCH=NO build
```

Both succeeded with zero warning/error diagnostic lines. Raw logs are
`build-ios-simulator-debug.log` and `build-ios-device-release.log`.
`lipo -info` confirms Simulator `x86_64 arm64` and device Release `arm64` products.
`plutil -lint` accepts both copied `PrivacyInfo.xcprivacy` files; both match the
unchanged source manifest bytes. The deployment minimum remains iOS 15.

`source-sha256.json` records all 17 package/source/resource/test files before
builds; a final readback confirms unchanged bytes. `artifact-sha256.json` records
17 product files, including object products, module artifacts and copied privacy
resources. `artifact-verification.log` records architecture, privacy, source
readback and diagnostic checks. `environment.log` records exact local tools,
SDKs, branch and starting commit. `evidence-sha256.json` records retained evidence
logs/manifests and this receipt, excluding itself and derived build scratch.
No successful expensive suite/build was repeated without relevant source changes.

## Limits

This is host unit-test and unsigned compilation/package evidence. No Simulator
was booted, no physical device was used, no persistent Keychain or account state
was changed, and no release, signed archive, store submission or publication was
performed. No runtime jailbreak/hook efficacy, mobile threading, attestation,
provider verification or App Store privacy-review result is inferred. Existing
scanner heuristic limitations and Release debugger `unavailable` behavior remain
as described in `LOCAL_RISK_VERIFICATION.md`. Framework runtime/packaging and the
one whole-stage security review are owned by the parent task.
