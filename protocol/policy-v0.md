# AppGuard policy and audit v0

Experimental deterministic server policy, independent of AI and provider networks. Portable cases are in `conformance/v0/policy.json`; Python, Node.js and Java implementations all execute the same42 cases. These are explicit server APIs; installing a signature SDK alone does not automatically enable policy middleware.

`PolicyContext` takes trusted server authentication/request-verification/attestation results plus bounded **untrusted** client risk hints. All defaults are missing. Neither a valid signature nor a client-reported status implies authenticated identity or verified platform attestation. Every context built from application state must preserve that distinction.

Policy profiles are `basic`, `balanced`, `strict`; signatures are required by default. Only an explicit `Policy("basic", require_signature=False)` permits server-only operation with existing authentication. Omitting authentication always denies, even in that mode.

Precedence: missing/invalid authentication; rejected/unavailable request verification; rejected attestation; required-but-missing signature; rate limit; missing/unsupported/unavailable/expired attestation; configured risk hints; allow. Fresh `verified` attestation requires integer `now < attestation_expires`.

| Condition after required checks | Basic | Balanced | Strict |
| --- | --- | --- | --- |
| Missing/unsupported/unavailable/expired attestation | observe | step_up | deny |
| Configured suspicious local risk hint | observe | step_up | deny |
| All satisfied | allow | allow | allow |

`observe` explicitly permits processing with an audit observation. `step_up` does **not** permit processing: the application must complete an additional trusted verification flow or reject the operation. Rejected authentication/signatures/attestation and rate limiting deny in every profile; a client hint cannot override them. A boolean `rate_limited` consumes an application's existing rate-limit result; this module does not implement request counters or imply that a limiter is installed.

Suspicious hints default to `debugger`, `root`, `hook`, `tamper`. Hints are at most32 unique codes matching `[a-z][a-z0-9_]{0,63}`; unknown valid codes cannot upgrade trust. Timestamps use request-v0's integer domain. Invalid configurations or input types reject with fixed policy errors.

Audit schema: version `appguard-audit-v0`, opaque `event_id`, configured `app_id`, integer `at`, fixed decision `action`, fixed `code`, profile; optional context contributes only `risk_count` and `attestation_state`. No arbitrary object merge, user identifier, token, nonce, key, fingerprint, IP, body, raw risk payload or provider evidence is recorded. IDs must not themselves contain credentials/user identifiers. The caller manages sink availability, retention and privacy policy. `JsonAuditSink` passes compact JSON to an explicit callback and redacts callback failures as `AUDIT_UNAVAILABLE`.

Node's sink always returns an awaited Promise and supports synchronous or asynchronous delivery callbacks. Java and Python use explicitly synchronous callbacks; the Java sink preserves interruption and normalizes callback `Exception`s without their cause/suppressed exception. None of these APIs promise isolation against hostile application-process code or normalize fatal JVM errors. Valid fixed decision construction is supported and does not itself prove policy evaluation occurred.
