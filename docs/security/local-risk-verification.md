# Native local risk stage verification

Scope: optional Android/iOS read-only local tamper, root/jailbreak and hook hints.
Base: `fdd977d6587c51350e50f6bcad3fd06f4942b2f6`; implementation branch:
`codex/appguard-local-risk`. Local tests/builds do not establish physical-device
or provider efficacy, hosted CI success, store approval, publication or production readiness.

## Implemented behavior

The [shared contract](../../protocol/local-risk-v0.md) defines four states,
ordered redacted checks and deduplicated debugger/root/hook/tamper categories.
`local_checks_unavailable` is a separate health hint. Every category is untrusted;
a missing hint never grants authentication, attestation or authorization.

Android exposes `LocalRiskScanner(Context).scan(Config)` with seven checks:
own-process debugger/debuggable state, selected root artifacts, selected loaded
hook-library names, optional exact app ID/current APK signer pins and bounded
asset hashes. All current APK signers must match; rotation history is not trusted
as a current signer. iOS exposes `LocalRiskScanner().scan(configuration:)` with
five checks: own-process debug inspection where supported, fixed jailbreak
artifacts/global hook symbols/injection environment keys, optional exact UTF-8
app ID and bounded bundle resource hashes. Neither scanner writes, starts a shell,
uses a network, requests permissions, terminates the app or prevents debugging.
Run scans off the UI thread.

Configuration/report values are immutable or defensively copied. Resources are
limited to eight, 1 MiB each. iOS validates resolved/opened descriptor containment
and regular-file size; Android reads assets only. Missing configured resources
are mismatches; denied/failed/oversized observations remain unavailable. There is
no full executable-signature or continuous filesystem/process-integrity claim.

See platform-specific reproduction and exact evidence limits:
[Android](../../sdk/android/LOCAL_RISK_VERIFICATION.md),
[Apple](../../sdk/apple/LOCAL_RISK_VERIFICATION.md).
Native typed scanner APIs are implemented; JS/Dart/C# scanner bridge operations
remain deferred. Existing signing/enrollment bridge operations are unchanged.

## Fresh verification

| Layer | Result |
| --- | --- |
| Android host | 20 new scanner + 27 existing tests in each debug/release variant: 94 executions, zero failures/errors/skips; release AAR, instrumentation APK and lint pass |
| Apple host | 31 new + 34 existing Swift tests: 65 pass, zero failures |
| Apple unsigned builds | Simulator Debug arm64/x86_64; device Debug and Release arm64; three final builds pass, privacy resource copies match |
| Core server runner | Reference 209 + Python 512 + Node 333 + Java 188 = 1242 pass, zero skipped; frozen installs, package builds and four live cross-SDK Redis replay probes pass |
| Extended servers | Go normal/race/vet/build pass; .NET 199 pass and Release build/pack with zero warnings/errors; PHP 539 assertions and 5 raw loopback HTTP requests pass |
| Shared policy addition | 24 supplemental local-risk cases per server language; original 42 retained; default unknown-health ignore and explicit health policy, missing auth/attestation tested |
| Expo | 23 tests, typecheck, deterministic staging and 43-file relocated npm pack pass; actual CocoaPods source/resource resolution checked |
| Flutter | 17 tests, analyzer, 11 Java adapter assertions, native Simulator library compile and 18-source/license relocated archive pass; actual CocoaPods source/resource resolution checked |
| Privacy packaging | Both relocated CocoaPods resource-bundle targets build unsigned; copied manifests match native source; Unity actual PBX export/repeat-callback fixture and 20 EditMode tests pass |

The scanner tests include RED-to-GREEN boundary regressions: bounded proc parsing,
signer/observation precedence, real temporary binary resource hashing, exact size
limits, denied/missing/oversized resources, symlink/FIFO handling, nested decoding
redaction, interrupted reads and exact UTF-8 identity comparison. Synthetic native
seams do not establish rooted/jailbroken/hooked-device efficacy.

The final staged Flutter Simulator library also compiles after the final native
identity fix; its pre-existing imported-framework sysroot warning remains. This
is compile evidence only. CocoaPods uses a placeholder Flutter dependency to
build resource targets; it does not establish a new complete Flutter app build.

Two isolated Android emulator startup attempts failed before boot because available
disk space was below the system image's required 7372.80 MB, including a bounded
partition-size retry. No scanner instrumentation test executed this stage. Its two
instrumentation tests and APK are built; actual current-signer/AssetManager runtime
coverage remains pending. No physical device or iOS Simulator runtime was used.
Existing AVDs/apps were not changed. Task-owned resource cleanup is recorded in
the ignored stage evidence; no user cache or historical evidence was removed.

## Platform and packaging rulings

- Apple's [QA1361](https://developer.apple.com/library/archive/qa/qa1361/_index.html)
  limits its unstable debugger example to debug builds. iOS release and macOS
  debugger state therefore remain unavailable. Explicitly treating every health
  hint as risky can step up or deny every iOS release request.
- Use public global dlsym lookups instead of unsafe image-list iteration. Hidden,
  local, renamed or suppressed hook symbols evade this heuristic; development
  injection or coincidental artifacts can produce false positives.
- File existence probes use access(F_OK). Bundle resource fstat metadata access
  carries the SDK C617.1 required-reason manifest; SwiftPM copies it, CocoaPods
  carries separate Expo/Flutter bundles and Unity exports its own bundle. This
  does not confirm archive privacy reporting or App Store acceptance.
- iOS uses pre/post descriptor-size checks while reading within the byte bound,
  rather than a limit+1 read. Concurrent same-size writes or compromised process
  APIs can still replace observations; this is not atomic attestation.
- Scope includes privacy resource propagation in existing framework packages so
  staging the new native source preserves its metadata. No new cross-language
  scanner surface or automatic enforcement policy is introduced.

## Security review and integration

One fresh read-only whole-stage review found **0 Critical, 1 Important, 0 Minor**.
Its independent probes reran the original 19 Android scanner tests, four Swift
descriptor/host/redaction checks and 24 Node supplemental policy cases. It also
reproduced the Important finding: LF-only proc maps suppressed the health hint and
made an explicitly configured Balanced health policy allow instead of step up.

The parent fixed this in one pass. The new Android regression first failed, then
passed after requiring at least one valid map record while preserving positive
precedence. The complete affected suite passed 94 executions, lint and both builds;
a fresh actual Android report passed through the real Node policy now steps up
for both LF-only and empty maps. No independent authentication/signature/attestation
bypass was demonstrated. No Critical/Important finding remains open; no Minor was
deferred. No second review was dispatched.

The stage's ignored checksummed evidence archive is
`.superpowers/evidence/2026-10-20-local-risk/` in the attached worktree. It retains
the review/probes, RED/GREEN/full-run logs, source/artifact hashes, privacy bundles,
owned Redis shutdown and emulator/global-AVD receipts. Package-owned native evidence
and runtime caches remain preserved. Only this stage's scratch directory is removed
after archive/readback. Integration uses the authorized clean local main fast-forward;
no push, publication, account configuration or existing user data cleanup is included.
