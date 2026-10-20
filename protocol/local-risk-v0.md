# Local risk report v0

Experimental native Android/iOS hints. The scanner performs an explicit bounded,
read-only snapshot; call it off the UI thread. It neither authorizes requests nor
verifies app/device integrity. A compromised application can bypass, omit or forge
its own results. Native typed APIs and the optional `scanLocalRisk` operation in
the [framework bridge](client-bridge-v0.md) expose the same report.

Report fields exactly:

```json
{"schema":"appguard-local-risk-v0","platform":"ios","checks":[{"code":"debugger_attached","state":"unavailable"},{"code":"root_artifact","state":"unavailable"},{"code":"hook_artifact","state":"unavailable"},{"code":"app_identity_mismatch","state":"not_configured"},{"code":"bundle_resource_mismatch","state":"not_configured"}],"riskSignals":["local_checks_unavailable"]}
```

The example is a structurally valid unsupported-platform snapshot, not a device
measurement. No timestamp or identity is attached; the application owns freshness,
transport and authenticated server association. Reports contain no raw filenames,
symbol/environment values, pins, app identifiers, process details or errors.

| State | Meaning |
| --- | --- |
| detected | A configured mismatch or suspicious local artifact was observed |
| not_observed | The implemented supported probes completed without a matching hint |
| unavailable | Unsupported, denied, malformed, oversized or failed observation |
| not_configured | An optional identity/signer/resource check has no configured expectation |

A positive subprobe wins over unavailable siblings. Without a positive, any
unavailable subprobe prevents a not_observed result. These are heuristic states,
not proof of root, a hook, tampering or a clean device. No overall clean flag.

Checks are ordered. Android: debugger_attached, debug_build, root_artifact,
hook_artifact, app_identity_mismatch, app_signer_mismatch, bundle_resource_mismatch.
iOS: debugger_attached, root_artifact, hook_artifact, app_identity_mismatch,
bundle_resource_mismatch. iOS release debugger inspection is unavailable: Apple's
[QA1361](https://developer.apple.com/library/archive/qa/qa1361/_index.html) restricts
its unstable kinfo_proc example to debug builds. macOS/Simulator jailbreak/hook
checks are unavailable and do not diagnose the development host.

Deduplicated riskSignals order: debugger, root, hook, tamper,
local_checks_unavailable. Detected debug/debuggable checks map to debugger; root
and hook artifacts map to root/hook; identity, current signer and resource
mismatches map to tamper. Any unavailable check adds local_checks_unavailable.
Not-configured checks add nothing. Categories are compatible with policy-v0.

## Explicit server integration

Pass bounded category strings as **untrusted** risk hints alongside independently
established server authentication, signature verification and attestation state.
Never copy a local state into those trusted fields. Defaults recognize debugger,
root, hook and tamper: Basic observes, Balanced requires step-up, Strict denies,
after all stronger checks. None overrides missing authentication, invalid
signatures or rejected attestation. No hints do not prove the app is genuine.

The default policy does not act on local_checks_unavailable. To require a
particular health policy, explicitly add it while retaining the other categories:

```python
policy = Policy("balanced", suspicious_signals=(
    "debugger", "root", "hook", "tamper", "local_checks_unavailable",
))
```

This can step up every iOS release or unsupported environment because a debugger
probe is unavailable. Decide supported checks and fallback behavior for your app;
never silently relabel unknown as clean. Additional 24 portable policy cases are
in `conformance/v0/local-risk-policy.json`, supplementing the original 42 cases.

## Bounded optional expectations

Configured app IDs and Android current signing certificate pins are application
release data, not secrets or remote evidence. Current signer pins are max8
lowercase SHA256 values; all current APK signers must be allowlisted. Rotation
history is not a substitute for current signers. Apple's module does not verify a
local signing certificate or complete executable code signature.

Resources are explicit app-owned deployment-byte pins: max8 relative ASCII paths,
max256 characters and128 per component; no empty/dot/traversal/absolute/backslash
components. Each file is limited to 1 MiB, at most 8 MiB total. Android streams
through a limit+1 sentinel check; iOS streams within the descriptor's validated
size bound and rejects a changed size after reading. A missing configured resource
is a mismatch; unreadable/oversized
resources are unavailable. iOS symlinks cannot escape the bundle; Android reads
assets only. Build/store processing can transform bytes; pin actual deployed
untransformed resources. An attacker who changes the scanner or pins can bypass
these checks. Process/filesystem isolation and continuous integrity are not implied.

Public API/heuristic references: [Android SigningInfo](https://developer.android.com/reference/android/content/pm/SigningInfo),
[Android Debug](https://developer.android.com/reference/android/os/Debug),
[Apple dlsym](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dlsym.3.html),
[OWASP root detection](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0027/),
[OWASP jailbreak detection](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0084/).
These references define platform behavior/limitations, not certification of this SDK.
