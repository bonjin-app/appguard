# Native local risk design

Approved scope: implement Android/iOS local tamper/root/hook risk detection, tests,
one fresh security review, then clean local main fast-forward. Local heuristics
are optional untrusted hints; there is no clean-device, attestation or authorization
verdict. No provider/account/device-keychain configuration is part of this stage.

## API and report

A synchronous explicit scanner uses read-only platform observations. Call it off
the UI thread. No timers, network, shell commands, root execution, ptrace/anti-debug
operations, sandbox-escape writes, application termination or new permissions.

Report JSON fields exactly: schema="appguard-local-risk-v0", platform="android"
or "ios", checks=[{code,state}], riskSignals=[category]. Four states:
`detected`, `not_observed`, `unavailable`, `not_configured`. No overall clean bool.
Report immutable/defensively copied, deterministic checks and deduplicated signals.
No raw paths, loaded-image/symbol/environment values, resource names, app IDs,
signer hashes, exceptions, keys or user identifiers in report/description/errors.

Android checks ordered: debugger_attached,debug_build,root_artifact,hook_artifact,
app_identity_mismatch,app_signer_mismatch,bundle_resource_mismatch.
iOS checks ordered: debugger_attached,root_artifact,hook_artifact,
app_identity_mismatch,bundle_resource_mismatch. Unsupported macOS/simulator
root/hook observations are unavailable, never a jailbreak result about the host.

Signals ordered: debugger,root,hook,tamper,local_checks_unavailable.
Detected debugger_attached/debug_build ->debugger; root_artifact->root;
hook_artifact->hook; any identity/signer/resource mismatch->tamper.
Any unavailable check additionally emits local_checks_unavailable. Not-configured
checks emit no signal. Missing/unavailable observations never become not_observed.
A positive subprobe wins over unavailable siblings; otherwise unavailable wins.
The existing six-language policy defaults recognize debugger/root/hook/tamper;
unknown-health handling requires explicitly configuring local_checks_unavailable.
Empty signals never prove integrity; requests/authentication/authorization remain
independent. These scanners do not extend the JSON signing bridge this stage.

## Configuration and bounds

Expected app ID optional, 1..255 ASCII [A-Za-z0-9][A-Za-z0-9._-]*.
Android signer pins optional max8 lowercase64hex SHA256 values, comparing current
APK signers (all current signers must be allowed), not historical rotation certs.
No pins means not_configured, no certificate lookup needed.
Protected resources optional map max8 relative paths ->lowercase64hex SHA256.
Path max256 ASCII chars, components1..128 [A-Za-z0-9_-][A-Za-z0-9._-]*,
no traversal/absolute/backslash/empty segments. Per-resource streaming limit1MiB,
8MiB aggregate maximum. Missing configured resource means detected mismatch;
read/permission/size/error means unavailable. iOS resolved paths must stay inside
bundle and not escape by symlink. Android reads only AssetManager assets.
Invalid configuration rejects before any probe with fixed invalid-configuration
error; no error can include raw input/probe failure.

## Native observations

Android26+: Debug API plus bounded /proc/self/status TracerPid; own application
FLAG_DEBUGGABLE; fixed known su/Magisk filesystem paths via NIO attributes with
permission failures distinct from absence; bounded /proc/self/maps (512KiB) and
known hook library basenames (Frida/Xposed/Substrate). Never enumerate installed
packages, external storage or network ports. Read status max64KiB. All runtime
and OS read failures become per-check unavailable. PackageManager identity/current
signer certificates only when configured; hash actual signer bytes with SHA256.

Apple iOS15+: DEBUG-only sysctl own-process P_TRACED for debugger per Apple QA1361; Release/macOS debugger observation is unavailable because no supported release debugger API is claimed. Do not ship unstable kinfo_proc layout assumptions in release; fixed known jailbreak
file existence observations with access(F_OK) (no sandbox-write test); known global hook symbols through
public dlsym (no loading/calling suspicious code) and selected injection environment
keys. No unsafe dyld image-list iteration (Apple documents concurrent unload races),
private APIs, certificate-chain/hardware or full code-signature claims. Observation
strings/counts bounded. Host/simulator jailbreak/hook checks unavailable. Bundle
identity and explicitly pinned resources are the tamper signals; a modified app can
also modify its embedded pins/scanner. Build/store processing can change resources,
so pin exact deployed untransformed app-owned bytes, not an assumed executable hash.

iOS resource reads validate the opened descriptor stays inside the resolved bundle,
is a regular file and is within the size bound before reading. A final descriptor
size check rejects growth/truncation. This does not provide atomic filesystem or
process integrity. The fstat metadata access requires the SDK's C617.1 privacy
manifest to be packaged by SwiftPM and each framework's native distribution.

## Evidence

RED/GREEN behavior tests with injected OS boundaries; real temporary resource
hashing/limit/missing/symlink cases; full Android host/AAR/lint and Swift tests;
unsigned generic iOS Simulator and device-target compilation. No genuine rooted/
jailbroken/hooked-device detection efficacy claim from mocks or compilation.
If an isolated emulator can run without changing existing devices/AVDs, add explicit
adapter runtime coverage and record it separately. Preserve existing apps/sessions.
One whole-stage reviewer; fix Critical/Important through targeted RED/GREEN before
local integration. Preserve checksummed logs and exact source/artifact manifests.

API provenance: [Apple QA1361](https://developer.apple.com/library/archive/qa/qa1361/_index.html), [dlsym](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dlsym.3.html), [Android SigningInfo](https://developer.android.com/reference/android/content/pm/SigningInfo), [OWASP root heuristics](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0027/), [OWASP jailbreak heuristics](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0084/).
