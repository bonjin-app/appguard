# Node replay dependency deadline

2026-10-21; independent main base
`1d3b6f90e14962979448f8be28b2d8fe1e7c2890`; experimental Apache-2.0 SDK.

## Boundary and change

The Node core previously awaited `replay.claim` without an SDK deadline. HTTP
body and authentication budgets ended before that await. The deployment guide
required host-client timeouts; it did not claim the SDK bounded replay. A valid
committed request reached a pending claim and remained unsettled in a local
preflight. This change adds a separate dependency budget to that existing flow.

`replayTimeoutMs` defaults to 10000 in `verifyRequest` and the three Node HTTP
adapters. It accepts integers 1..2147483647; omission/undefined selects the
default. Invalid settings reject with TypeError before a core claim or at
adapter installation. No new protocol field, error code or dependency is added.

The budget starts immediately before the claim after signature verification.
An elapsed-time check rejects synchronous overruns once control returns. A hung
or late claim rejects with the existing `REPLAY_STORE_UNAVAILABLE` (HTTP 503).
Late successes do not authorize downstream handling; late rejections are
consumed. Direct verifier callers keep an active deadline even without other
event-loop work. The verifier clears its timer on settlement.

## Operational limits

The SDK cannot forcibly cancel backend work or preempt JavaScript. A timed-out
command may still claim the nonce. Never delete that claim or fall back to an
unshared store. Retry with a fresh signed request/nonce and use application-level
idempotency/recovery for uncertain operations. Backend connection/command
timeouts, concurrency controls and capacity planning remain required.

Direct `ReplayStore.claim` calls are outside the verifier guard. Separate body,
authentication and replay budgets are not a total request deadline. Request
disconnect cancellation, deployed ingress/load/failover, hosted CI, external
audit, supported production release, provider and physical-device validation
remain separate work. The Unity physical branch is excluded from this change.

See the packaged [deployment guide](../../sdk/node/DEPLOYMENT.md) for rollout and
recovery requirements. The official Node [timer reference](https://github.com/nodejs/node/blob/main/doc/api/timers.md)
describes timer liveness and delay bounds; the [performance reference](https://github.com/nodejs/node/blob/main/doc/api/perf_hooks.md)
describes process-relative elapsed time. Local runtime tests establish the
behaviors of this implementation on the recorded toolchain.
