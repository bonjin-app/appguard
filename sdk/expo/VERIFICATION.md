# Expo bridge local verification

Date: 2026-10-20. Experimental package; no npm publication or account/project linking.

- Official `create-expo-module@58.0.3` scaffold ran before implementation. The scaffold dependency install was stopped after npm cache errors; package dependencies were then installed with an isolated package-local cache and pinned lockfile.
- Client/parser/public binding tests observed RED for absent implementation/binding, then GREEN. Config plugin observed RED, including duplicate-minimum regression, then GREEN. Final suite: 22 passing tests. Tests execute the real compiled TypeScript client with an injected native boundary; they do not emulate native signing.
- Tests cover binary bytes/empty bodies/all 256 byte values/the full 1 MiB body limit, exact encoded target including empty query, ordered headers, enrollment mapping, malformed/oversized/native-error responses, missing native module, redaction and plugin minimum preservation/idempotence. Native validation and independent signature verification belong to the shared native SDK suites.
- `npm run typecheck`: passed with TypeScript 6.0.3.
- `npm run verify:pack`: builds/stages a tarball, checks contents and native-source hashes, extracts it to a separate directory, and executes the built client from that relocated package. Passed. Staging twice produces identical provenance for the same source/commit.
- Packed consumer: Expo SDK 58.0.16, RN 0.88.0, React 19.3.0. Android and Apple autolinking detect AppGuard; Apple reports both AppGuardApple and AppGuardExpo pods. `expo prebuild --no-install` completed for Android and iOS with minimum OS settings.
- Staged Apple native SDK: `swiftc -emit-module -module-name AppGuardApple vendor/apple/Sources/AppGuardApple/*.swift -o .tools/AppGuardApple.swiftmodule` passed with Xcode 27.1. This is a host SDK compilation, not Expo runtime execution.

Android packed consumer native build: `ANDROID_HOME=/Users/uulab/Library/Android/sdk JAVA_HOME=/Users/uulab/Library/Java/JavaVirtualMachines/jdk-17.0.20+8.jdk/Contents/Home ./gradlew :appguard-expo:compileDebugKotlin :appguard-expo:compileDebugJavaWithJavac --no-daemon` passed (47 tasks; 7 executed, 40 up-to-date). This compiled the actual Kotlin Expo module and the staged Java SDK against Expo Modules Core 58.0.23. An earlier attempt lost generated inputs during a consumer package refresh; rerunning against an unchanged consumer passed.

iOS consumer dependency installation is still in progress; full Expo Apple adapter compilation is not yet claimed. CocoaPods initially rejected the local `0.0.0-experimental.1` version because it is below the implicit `>= 0` requirement. A direct CocoaPods Ruby probe confirmed this; local pod metadata now uses `0.0.0`, and both AppGuard pods resolve. The npm package remains `0.0.0-experimental.1`. Separate podspec directories avoid ambiguous local pod paths. Ruby 3.3.4/CocoaPods 1.17.0 are used for the final consumer installation. No emulator/simulator boot, physical-device execution, installation-key exercise, HTTP integration, store submission, provider verdict, EAS operation or remote release is implied by these local checks.

Detailed logs/tarballs remain in ignored package-owned `.evidence/` and `.tools/`. Source and test files are tracked; generated vendors and build products are refreshed at pack time.
