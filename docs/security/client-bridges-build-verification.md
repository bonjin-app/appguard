# Client bridges and Build/CLI verification

Experimental local evidence observed on 2026-10-20. No SDK has been published. Base native stage: `6f6ce6c`; new native facade `9a47393`, initial CLI/Unity foundation `590b248`, Flutter `f2ef1be`, Expo `884e4a8`, targeted fixes `53b9ea8`. A concurrent shared-index commit grouped authorized CLI/Unity files; all changes were preserved and subsequent commits were serialized by explicit paths.

| Component | Executed evidence | Remaining boundary |
| --- | --- | --- |
| Android native facade |27 host tests; actual ephemeral P-256 request/enrollment verification; release AAR/lint; duplicate-key negative control | No new facade emulator/device run; prior native stage separately exercised Android Keystore on an isolated emulator |
| Apple native facade |34 Swift tests; actual ephemeral crypto; duplicate-key negative control; unsigned generic Simulator arm64/x86_64 build | Persistent Keychain, Secure Enclave and provider/device runtime remain separate |
| Unity UPM |20 EditMode cases after review fix; compiled Android/iOS managed branches/postprocessor; relocated release AAR/JNI keep rules; device-arm64 + Simulator-arm64/x86_64 native libraries; C ABI4 rejection cases, ASAN10000 invoke/free cycles, leaks0 bytes | No Unity mobile player export, IL2CPP linkage/runtime, JNI or iOS player invocation |
| Expo / React Native |22 TypeScript/binding/plugin/pack tests, typecheck, relocated native-source hashes, packed SDK58/RN0.88 Android Kotlin/Java compilation | See package verification record for final CocoaPods build state; no framework engine/device invocation |
| Flutter |17 Dart tests/analyze;11 Java adapter assertions; AAR; relocated consumer CocoaPods installation and generic Simulator app build arm64/x86_64 | No device/engine channel or key-storage execution; no end-to-end HTTP send |
| CLI / Build |19 Node tests; packed installed CLI subprocesses; actual isolated Kotlin-DSL Android release build41 tasks with R8/resource shrinking and mapping `Feature -> a.a`;5 mapping files encrypted/restored byte-identically | Flutter obfuscation command is tested as arguments; no Flutter release/Expo export/Unity CLI adapter execution claim |
| Vault maximum |64 MiB raw symbol file round-trips through119304856-byte authenticated archive; temporary source/destination removed | Archive format experimental; no third-party compatibility, KMS, rotation or long-term recovery claim |

Commands are documented per package: [Android](../../sdk/android/README.md), [Apple](../../sdk/apple/README.md), [Unity](../../sdk/unity/VERIFICATION.md), [Expo](../../sdk/expo/VERIFICATION.md), [Flutter](../../sdk/flutter/VERIFICATION.md), [CLI](../../tools/cli/README.md). Raw logs, artifacts, source hashes and RED/GREEN XML remain locally ignored under package `.evidence/` and the checksummed stage evidence directories. Build output and unit assertions are distinct from deployed/device security.

## Fresh review and targeted fixes

One fresh read-only whole-stage reviewer assessed native JSON boundaries, all framework bindings and packaging, and CLI/archive security. No Critical finding was established. Two Important findings were fixed without a second review:

- Unity's default Newtonsoft date parsing rejected permitted ISO-looking key IDs/header strings. A real compiled-source probe and EditMode regression reproduced rejection; suite19/20 RED became20/20 GREEN with `DateParseHandling.None`. Duplicate-property rejection remains tested. Android/iOS C# branches and iOS postprocessor also compiled after the fix.
- Archive creation lacked the portable whole-manifest collision gate already required by restoration. It could report successful retention that later refused to restore on case-sensitive source filesystems. One shared path validator now runs before encryption and before plaintext restoration. Case/NFC/exact-duplicate/file-prefix/unsafe paths are tested independently of host filesystem behavior; CLI suite19/19 GREEN. The original case-sensitive source scenario was established from the code path, rather than falsely claimed as an execution on this Mac volume.

Deferred Minor: Expo's native error allowlist maps Android's absent-React-context `APPGUARD_NATIVE_UNAVAILABLE` envelope to `APPGUARD_OPERATION_FAILED`. Both remain fixed/redacted failures; missing-module detection at the JS loader has its separate unavailable code. Diagnostic classification is narrower than the bridge contract in that path.

## Review rulings and costs

- Keep only validated request/enrollment signing operations, with no generic signing/private-key import/export. A compromised application can still invoke permitted operations; application-process isolation is outside this API.
- Preserve explicit hardware requirements with fail-closed native key adapters. Local backing labels are not remotely verified hardware or attestation; actual device proof remains required.
- Native parsing rejects malformed/duplicate/type/size/time input before key access where possible. Trusted in-process key/clock adapters and provider callbacks remain trust boundaries; hostile replacement code is outside the guarantee.
- Bindings carry target/body/header evidence unchanged and supply no HTTP transport. Applications must verify their selected transport and redirect/retry behavior; compilation alone cannot protect rewritten wire bytes.
- Unity owns maximum-sized C response allocations and releases them once. Foreign pointers are outside the ABI contract; misuse can still violate memory safety and each call costs up to1.5 MB transient native storage.
- CLI build arguments use `shell:false`, while the selected application wrapper/toolchain and inherited logs execute application-owned code. This tool cannot make hostile build scripts or their output safe.
- Filesystem operations assume exclusive local control and private OS permissions. They do not isolate a compromised account or malicious concurrent filesystem writer; original mappings remain present until the application manages them.
- Software-key nonextractability is not claimed. SDK-level lack of private export differs from hardware/platform enforcement; stronger protection requires actual hardware verification.
- Node/Java policy parity is a separate implementation stage; signatures alone do not install policy, authentication, rate counters or provider verification. Applications remain responsible for these dependencies.

All artifacts remain local. Generic Simulator builds use disabled signing, with any linker-generated ad hoc signature distinguished from an identity/provisioning profile. No provider verdict, store submission, physical-device protection, publication, production deployment or end-to-end HTTP preservation was established by this stage.
