# Unity bridge verification — 2026-10-20

Task 3, `docs/superpowers/plans/2026-10-20-appguard-client-bridges.md`. Ownership: `sdk/unity/**` only. Installed engine retained: Unity **6000.3.24f1**. Tests used only package-owned scratch projects; no existing games, licensing configuration, global profiles, device Keychain or booted Simulators were modified.

Parent review follow-up (`53b9ea8`): an ISO-looking valid key ID/header value exposed Newtonsoft date coercion. The added real EditMode regression failed (19/20), then passed with date coercion disabled (20/20). A separate duplicate-property test still rejects ambiguous JSON. Final Android/iOS managed branches and iOS postprocessor compilation also passed. The original relocated-package18-case evidence below predates this managed parser fix; native source/artifacts were unaffected. New packages must be staged from current source.

## Observed checks

- Initial managed behavioral RED: 17/17 failures against deliberate not-implemented stubs; initial C ABI ownership RED: `owned response required` against a nil-returning stub.
- Missing native library regression: 17 pass / 1 fail (expected native-unavailable, observed operation-failed), followed by fixed exception mapping.
- Unity EditMode: **18/18 passed**, including exact JSON schema mapping, binary body/explicit empty query/ordered headers, enrollment binding, all four native errors, exception/response redaction, unsupported Editor, missing platform, body bound and native return ownership.
- Unity's own Roslyn compiler/reference assemblies compiled both `UNITY_ANDROID` and `UNITY_IOS` managed runtime branches plus the iOS Xcode postprocessor. This is compile evidence, not IL2CPP player execution.
- `sh Tools~/test-native.sh`: **10,000 invoke/free cycles** plus null, oversized and invalid UTF8 input checks passed under macOS AddressSanitizer. A separate `leaks --atExit` run reported **0 leaks / 0 leaked bytes**. `detect_leaks=1` is unsupported by this macOS ASAN, so the native `leaks` tool supplied that distinct check.
- Real Swift SDK + C ABI host integration: **4/4 fixed rejection cases** passed (unsupported operation, malformed JSON, invalid alias, unsupported StrongBox), with no persistent key operations.
- Relocated copied-source Android package: Gradle `assembleRelease` **BUILD SUCCESSFUL**, 25 tasks. Built AAR contains `proguard.txt` preserving `io.appguard.android.NativeBridge(Context)` and `invoke(String,String)` for JNI/R8.
- Relocated copied-source iOS package: `Tools~/build-native.py --platform ios` built `AppGuardUnityNative.xcframework` containing arm64 iOS and arm64/x86_64 Simulator static libraries with the real facade and C adapter.
- Unity project audit: valid scratch project; no OTA/runtime-loader evidence. Its credential-ignore warning applies to a generated empty test project, not a release application.

## Commands and local evidence

Commands were executed from the bridge worktree. `python3 sdk/unity/Tools~/test-managed.py --unity /Applications/Unity/Hub/Editor/6000.3.24f1/Unity.app/Contents/MacOS/Unity` supplies the managed checks; the same runner was run from a staged relocated package. `Tools~/stage.py --destination <package-owned ignored scratch>` copied SDK inputs. `JAVA_HOME=<installed JDK17> ANDROID_HOME=<installed SDK> python3 <staged>/Tools~/build-native.py --platform android` supplied the AAR. `python3 <staged>/Tools~/build-native.py --platform ios` supplied the XCFramework.

The real-facade host probe compiles `sdk/apple/Sources/AppGuardApple/*.swift`, `sdk/unity/Native~/iOS/AppGuardUnity.swift` and `sdk/unity/Tools~/test-real-facade.swift` with `xcrun swiftc`, then executes the probe. It does not create keys.

Raw logs/XML, source input manifests and checksums remain in ignored `sdk/unity/.evidence` and package-owned `.tools` scratch. Artifacts are locally built, unsigned and unpublished. No binary is committed as a distribution claim.

## Remaining evidence

No Unity Android/iOS player export/build, IL2CPP runtime, Android JNI device invocation, iOS player C ABI invocation, device secure hardware, attestation, store or provider runtime result was executed. Export postprocessor compilation does not prove final Xcode linkage/runtime embedding. Native SDK host tests and local static libraries do not establish those runtime tiers. Applications must validate transport byte preservation, redirect handling and alias lifecycle on their actual mobile integration.

## Rulings

Native dependency sources and test tools live under Unity-ignored `Native~` / `Tools~` folders; only built plugins are imported. Native output allocations reserve the documented maximum plus terminator, so the bounded managed decoder can safely inspect a missing terminator before freeing. This costs up to 1.5 MB transient native allocation per call. All native source staging and artifacts stay local; publishing was outside scope.
