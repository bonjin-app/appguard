# Unity local risk bridge verification

Observed 2026-10-20 on macOS with Unity 6000.3.24f1, installed Xcode and its iOS/Simulator SDKs. Evidence is retained under `.evidence/risk-bridge/`; older evidence and native artifacts remain separate. No publication, signing, account/configuration changes or persistent key operations were performed.

## Results

- RED: existing 20 tests passed and the missing `ScanLocalRiskAsync` API test failed. Receipt: `red-managed.xml` and `red-managed.log`.
- GREEN: **71/71 actual Unity EditMode tests** passed: the original 20, API existence, 32 individual shared report vectors (8 valid / 24 invalid), and 18 other async/config/error/thread/ownership cases. The package corpus is byte-identical to `conformance/v0/local-risk-bridge.json`. Receipt: `managed-final/managed.xml`, `managed-final/managed.log` and `managed-final.log`.
- Installed Unity Roslyn compiled the actual Android JNI and iOS P/Invoke runtime branches and iOS postprocessor branch. Outputs/response files are in `managed-final/`.
- Options copy caller collections before scheduling, reject invalid identifiers/paths/pins/counts, and expose read-only collections. Managed tests exercise post-call source mutation, immutable reports, exact 4,096-byte UTF8 envelope acceptance and oversize rejection, fixed errors, and explicit Editor rejection.
- Worker tests exercise attach/invoke/detach on the same owned background thread, invocation failure cleanup, and failed attachment without invocation or detach. Android JNI compilation uses the installed `AndroidJNI.AttachCurrentThread` / `DetachCurrentThread` APIs; no caller or shared thread-pool thread is detached.
- RED native C ownership test failed at the new scan input bound. GREEN: **10,000 invoke/free cycles** plus null/invalid UTF8, legacy limits and new 8,192-byte scan input / 4,096-byte output limits passed AddressSanitizer; native `leaks` reported **0 leaks / 0 leaked bytes**. Receipt: `red-native.log`, `green-native.log`, `native-asan.log`, `native-leaks.log`. This ownership harness substitutes the facade and never calls Keychain.
- Final staged real Swift SDK + Unity wrapper built as a host dynamic library. A C host dynamically resolved and invoked the actual exported C ABI for **6 scan cases**: defaults, configured identity/resource pins, unsupported Android signers, unknown field, null field and oversize input. Each owned response was bounded, copied, read back and freed through the matching C export. Receipt: `actual-native.log` and `actual-native/`.
- Actual staged managed source compiled with Unity's compiler/references and called that host C ABI from `ScanLocalRiskAsync`: **2 calls / 2 owned buffers freed** on the worker, with strict success report and unsupported-signer error decoding. This proves host managed/native interoperation and ownership, not mobile runtime behavior.
- Final staged Swift SDK + wrapper compiled into actual Mach-O arm64 objects for `arm64-apple-ios15.0` and `arm64-apple-ios15.0-simulator`. Receipt: `apple-targets.log`, `actual-native/iphoneos.o`, `actual-native/iphonesimulator.o`.
- Actual installed Unity PBX API export probe passed manifest byte propagation, app Resources folder reference, repeated callback idempotence, host/UnityFramework manifest preservation, and missing-input rejection before PBX mutation. Receipt: `export.log`, `export/`; scratch export: `.tools/risk-bridge-export/`.
- Source-only staging/relocation passes without sibling repository references. Final stage `.tools/risk-bridge-stage-final/` contains `SOURCE-MANIFEST.json`; `source-readback.json` verifies all manifest bytes, final Android/Apple native source correspondence, Unity managed/wrapper correspondence, and corpus parity. Compiled stage-1 inputs match final staged managed/native inputs exactly.

## Reproduce

Run from the repository root, with fresh destination names when retaining earlier receipts:

```sh
python3 sdk/unity/Tools~/test-managed.py \
  --unity /Applications/Unity/Hub/Editor/6000.3.24f1/Unity.app/Contents/MacOS/Unity \
  --evidence-directory sdk/unity/.evidence/risk-bridge/managed-final
sh sdk/unity/Tools~/test-native.sh
python3 sdk/unity/Tools~/stage.py \
  --destination sdk/unity/.tools/risk-bridge-stage-final
python3 sdk/unity/Tools~/test-risk-native.py \
  --unity /Applications/Unity/Hub/Editor/6000.3.24f1/Unity.app/Contents/MacOS/Unity \
  --staged-package sdk/unity/.tools/risk-bridge-stage-final \
  --evidence-directory sdk/unity/.evidence/risk-bridge/actual-native
python3 sdk/unity/Tools~/test-ios-export.py \
  --unity /Applications/Unity/Hub/Editor/6000.3.24f1/Unity.app/Contents/MacOS/Unity \
  --staged-package sdk/unity/.tools/risk-bridge-stage-final \
  --evidence-directory sdk/unity/.evidence/risk-bridge/export \
  --export-directory sdk/unity/.tools/risk-bridge-export
```

## Limits

No full XCFramework rebuild, Unity player/IL2CPP build, Android emulator/JVM scanner execution, iOS Simulator launch, physical-device root/hook efficacy, signed archive privacy validation, store submission or provider verification is claimed. Android thread attachment is compiled and its ownership/lifetime seam is tested on the host; an actual Android JVM/player run remains necessary to establish device execution. Host scan reports intentionally contain unsupported/unavailable checks and are not mobile measurements. All local risk results remain untrusted heuristic hints.
