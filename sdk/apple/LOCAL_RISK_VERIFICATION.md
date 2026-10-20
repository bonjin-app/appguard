# Apple local-risk verification

This stage adds optional, untrusted local risk hints. It does not establish a clean
device, validate a code signature or attestation, or authorize a request.

## Provenance and public API

Worktree: `/Users/uulab/.codex/worktrees/appguard-protocol-foundation/appguard`.
Branch: `codex/appguard-local-risk`; starting commit:
`fdd977d6587c51350e50f6bcad3fd06f4942b2f6`. The parent serializes staging, commits,
whole-stage review and local integration. This worker changed only `sdk/apple/**`.

Public entry points:

```swift
let configuration = try LocalRiskConfiguration(
    expectedAppID: "com.example.app", protectedResources: [:]
)
let report: LocalRiskReport = LocalRiskScanner().scan(configuration: configuration)
```

The synchronous scan belongs off the UI thread. Configuration is immutable and
validated before probing. All scan seams, temporary bundle selection and read
injection are internal; there is no public API for presenting injected results
as genuine native evidence. Report/check structs and their enums are immutable
Codable/Sendable values. Only fixed enum values and the fixed schema/platform
cross the reporting boundary. Malformed decoding produces a fixed redacted error,
including when decoding a nested public enum/check directly.

The output keys are exactly `schema`, `platform`, `checks`, `riskSignals`; each
check has exactly `code` and `state`. Five checks and five possible categories
follow the shared spec order. Positive evidence wins over unavailable subprobes;
otherwise unavailable wins over all negative subprobes. Unconfigured identity and
resources perform no corresponding lookup. `local_checks_unavailable` is emitted
for any unavailable check; its server policy behavior requires explicit choice.

## Observed RED and GREEN

Environment: macOS 27.0.1 (26A434), arm64; Xcode 27.1 (27A9275), Apple Swift 6.4
(`swiftlang-6.4.0.34.1`, clang 2100.3.34.1). Package minimums remain iOS 15 and macOS 13.
SDKs used: iPhoneOS 27.1 and iPhoneSimulator 27.1. Evidence was captured on
2026-10-20, without booting a Simulator or accessing any physical device.

From the repository root:

```sh
swift test --package-path sdk/apple --filter LocalRiskTests
swift test --package-path sdk/apple --filter LocalRiskTests.testMalformedNestedWireValuesAlsoHaveFixedRedactedErrors
swift test --package-path sdk/apple --filter LocalRiskTests.testInterruptedResourceReadIsUnavailableWithoutRetry
swift test --package-path sdk/apple --filter LocalRiskTests.testIdentityComparisonRequiresExactASCIIBytes
swift test --package-path sdk/apple
```

| Step | Observed result | Raw log under `.evidence/local-risk/` |
| --- | --- | --- |
| Test-first missing API | Compile failure for the absent scanner/types, recorded separately from behavioral RED | `red-api.log` |
| Minimal API behavioral RED | 25 tests, 74 assertion failures; missing validation, aggregation, hashing, resource results and wire/error behavior | `red-behavior.log` |
| Initial focused GREEN | 25 tests, zero failures | `green-focused.log` |
| Nested error redaction RED | One test, eight assertion failures; synthesized enum/check decoding leaked hostile raw strings | `red-nested-redaction.log` |
| Interrupted read RED | One test, two assertion failures; retries erased an unavailable read and could continue without a bound | `red-interrupted-read.log` |
| Exact identity bytes RED | One test, two assertion failures; Unicode canonical equivalence incorrectly matched a non-ASCII observed identifier to an ASCII expectation | `red-identity-bytes.log` |
| Final full GREEN | 65 tests, zero failures: 34 existing plus 31 local-risk tests; all regressions pass | `green-full-final.log` |

The 31 new tests exercise state/category precedence and ordering; unavailable and
throwing probes; no configured I/O for optional checks; identity matching/missing
and bounds with exact UTF-8 byte comparison; invalid identifiers, paths, traversal, pins and counts; value semantics;
report keys, deterministic roundtrip, invalid decoding and redaction; host/Simulator
unsupported behavior; fixed existence-error classification; bounded environment
values; real temporary bundle identity; exact empty/text/binary resource hashes;
missing resources; exactly 1 MiB and one byte over; eight 1 MiB resources; unreadable
mode-zero files with successful read after restoring permissions; nonregular
directories and FIFOs without blocking; inside/outside/directory/sibling-prefix
symlinks and loops; native read-error handling; and actual streaming read bytes.
The fixture digests were independently computed with Python's SHA-256 rather than
the production hashing helper. Test writes and permission changes were confined
to unique temporary directories, removed by test helpers. Existing key tests use
an in-memory Keychain boundary and real nonpersistent cryptographic keys.

## Unsigned iOS compilation and packaging

Commands from `sdk/apple`, with separate owned DerivedData (no broad clean):

```sh
xcodebuild -scheme AppGuardApple -destination 'generic/platform=iOS Simulator' \
  -configuration Debug -derivedDataPath .evidence/local-risk/deriveddata-simulator \
  CODE_SIGNING_ALLOWED=NO IPHONEOS_DEPLOYMENT_TARGET=15.0 \
  ARCHS='arm64 x86_64' ONLY_ACTIVE_ARCH=NO build
xcodebuild -scheme AppGuardApple -destination 'generic/platform=iOS' \
  -configuration Release -derivedDataPath .evidence/local-risk/deriveddata-device \
  CODE_SIGNING_ALLOWED=NO IPHONEOS_DEPLOYMENT_TARGET=15.0 \
  ARCHS=arm64 ONLY_ACTIVE_ARCH=NO build
xcodebuild -scheme AppGuardApple -destination 'generic/platform=iOS' \
  -configuration Debug -derivedDataPath .evidence/local-risk/deriveddata-device \
  CODE_SIGNING_ALLOWED=NO IPHONEOS_DEPLOYMENT_TARGET=15.0 \
  ARCHS=arm64 ONLY_ACTIVE_ARCH=NO build
```

All three final builds succeeded without warnings or errors. Final logs are
`build-ios-simulator-debug-final.log`, `build-ios-device-release.log`, and
`build-ios-device-debug.log`. The earlier successful Simulator compile is retained
as `build-ios-simulator-debug.log`, before the redaction/read/privacy changes; final
evidence uses the final build log and current source manifest.

`lipo -info` confirms Simulator product architectures x86_64 and arm64, and device
Release product architecture arm64. The Debug Simulator imports `sysctl`; device
Release imports `access`, `dlsym`, `fstat`, and `getenv` and does not import `sysctl`.
This confirms the release debugger exclusion in the compiled product. Compilation
does not demonstrate runtime behavior or genuine jailbroken/hooked-device detection.

`plutil -lint` validates the SDK privacy manifest. SwiftPM copies it into
`AppGuardApple_AppGuardApple.bundle/PrivacyInfo.xcprivacy` in each product directory.
The source, copied manifests, built products and raw evidence are SHA-256 recorded
in the locally ignored source/artifact/log manifests under `.evidence/local-risk/`.

## Public API and privacy rationale

Apple's archived [QA1361](https://developer.apple.com/library/archive/qa/qa1361/_index.html)
uses own-process `sysctl` and `P_TRACED`, but explicitly restricts the `kinfo_proc`
example to debug builds because its structure is unstable. This implementation
therefore compiles the probe only with `DEBUG && os(iOS)`; release and macOS return
`unavailable`. No private or unsupported replacement is used. The selected Xcode
SDK's public `sys/sysctl.h` and `sys/proc.h` declarations were checked, and both
Simulator architectures and device Debug compile this branch. Public availability
and a successful debug build do not establish future ABI stability or release support.

The public [dyld manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dyld.3.html)
and current public `mach-o/dyld.h` warn that image-count iteration races concurrent
image loading/unloading. No such enumeration is used. Four fixed symbols are looked
up through public [dlsym](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dlsym.3.html)
with the SDK-defined default handle; returned pointers are never invoked. Three
selected environment keys are queried with public `getenv`, inspecting at most
4097 bytes to enforce the 4096-byte observation limit. Missing symbols/empty keys
mean no selected artifact observed. Globally hidden/local symbols, stripped keys,
and modified process memory remain outside this heuristic's assurance. Apple
documents default symbol lookup as potentially expensive; the symbol count is
fixed and scans should stay off the UI thread.

Seven fixed artifact paths use `access(F_OK)` for existence only. `ENOENT` and
`ENOTDIR` mean absent; denied and other failures mean unavailable. Root/hook probes
run only on iOS devices, with no host or Simulator jailbreak diagnosis. No new
permission, entitlement, Full Disk Access grant, network, shell, write test,
anti-debug operation, Keychain action or persistent device state is requested.
The sandbox may hide artifacts or deny access; those limitations cannot be
resolved by inferring a clean state.

Resource hashing resolves the bundle root and candidate, enforces a full directory
boundary, opens without following a final symlink or blocking on a FIFO, confirms
the opened descriptor path remains inside that root, checks a regular file and
bounded size with `fstat`, and streams at most 1 MiB per file in 16 KiB chunks.
Read failures (including interruption) are immediately unavailable. A final size
check rejects growth/truncation instead of accepting a partial digest. No file
timestamp or size is reported. Static symlink escape prevention is tested, but
this is not atomic filesystem attestation: concurrent renaming/content changes,
same-size modifications, malicious process memory and hooked APIs can still race
or replace observations. The scanner is an untrusted local hint, not a sandbox
boundary against an already compromised process.

Apple's current [required-reason API list](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacyaccessedapitypes/nsprivacyaccessedapitype)
includes `fstat` in `NSPrivacyAccessedAPICategoryFileTimestamp`, even when only size
and regular-file metadata are used. `C617.1` permits metadata access inside app
containers. The official [file-system guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html)
identifies the bundle container as an app sandbox container. The SDK manifest
declares C617.1 solely for these protected bundle resource checks. Fixed external
existence probes use `access`, not `stat`. Live official DocC JSON and the extracted
FileTimestamp category were saved because the current Markdown export omits the
possible-values table. The SDK must carry its own manifest according to Apple's
[required-reason guidance](https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api);
other packaging systems must copy it into the final archive as well. Actual archive
privacy reporting and App Store review remain separate, unverified evidence tiers.

## Remaining limits

No genuine rooted/jailbroken/hooked-device, physical device, Simulator runtime,
store review or production efficacy result is claimed. There is no full executable
signature, signing identity, certificate-chain or hardware integrity check. Resource
pins and the scanner itself can be replaced by a modified application. App/store
processing may transform bytes. Legitimate development injection, compatible
instrumentation or coincidental symbols/artifacts can produce false positives;
absence, renamed artifacts or suppressed APIs can produce false negatives. Release
debugger checks remain unavailable by design and may affect a policy that explicitly
denies `local_checks_unavailable`.
