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

## Local verification and review

- Frozen Node install and original tracked suite: **429/429**, zero skipped.
- RED main run: **94 tests, 28 passed and 66 failed**, zero cancellations/skips.
  Supplemental standalone/default-deadline and nonce-retention probes failed as
  expected; slow-authentication ordering probes passed. TypeScript rejected the
  two missing option declarations. The final file includes **98** tests.
- Focused GREEN: **98/98** with strict unhandled-rejection handling; TypeScript
  passed. Tests cover real P-256 verification, Express/Fastify/Nest localhost
  servers, hung/late outcomes, synchronous overrun, independent requests, invalid
  configuration and standalone process liveness/cleanup. The omitted-default
  probe observes the real 10-second deadline. A late gated backend claim uses
  the real in-memory store; the same request subsequently rejects as replay.
- Common server runner: reference **209**, Python **555**, Node **527**, Java
  **211** (**1502 total**), zero skipped. Wheel/JAR/package builds, Node types,
  package import smoke, shared-Redis first-claim rotations and cross-process
  simultaneous single-winner checks passed on an owned disposable instance.
- Offline installed npm consumer: **98/98** strict regressions, zero skipped or
  cancelled; all **14** source/tarball/actual installed files were byte-identical.
  The installed README's `DEPLOYMENT.md` link target exists. Consumer dependency
  lock, dependency inventory, tests and tarball are retained as evidence.
- Independent security review approved implementation commit
  `5010ae13473182b15037337c613230a68fa98a2a`: **0 Critical, 0 Important, 0 Minor**.
  The reviewer independently passed **135** tests (98 focused, 10 adversarial,
  27 replay/result-binding including live Redis), checked TypeScript and read
  back eight changed source hashes plus all 14 installed package file hashes.
  The common-runner receipts were inspected, not independently rerun wholesale.

Receipts, logs, test probes and build/package hashes are archived under
`.superpowers/evidence/2026-10-21-replay-deadlines/` in the primary checkout at
integration. This verification-record follow-up changes no reviewed runtime,
types, tests or npm package contents. Clean-main integration, merged Node tests
and archive-manifest readback precede temporary worktree cleanup.
