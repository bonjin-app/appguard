# Node HTTP connection lifetime guard

2026-10-21; independent main base
`faf887bb54c20fbc127c75b11e485351ef565b9e`; experimental Apache-2.0 SDK.

## Reproduced behavior and change

Body capture already handled aborted/incomplete request streams. After complete
capture, however, identity/key/replay awaits were independent of HTTP closure.
Real localhost requests could close their response/socket, then late successful
callbacks still started later dependencies or application handlers. With a
hanging replay claim and a long timeout, closing the client and server did not
let a standalone process exit. A later Fastify hook could also delay until
closure and then continue through the guard's `preParsing` handoff.

A private per-request connection observer now stops SDK waits on native response
or socket close, request abort, or an already-ended/destroyed response. Owned
waiters/listeners are disposed in `finally`. Authentication checkpoints prevent
late key/replay work; a replay proxy rejects the SDK-facing wait on close so the
core's deadline timer is cleared. The issued backend command may continue.

Express/Nest recheck native connection state before dispatch. At the SDK-owned
Fastify `onRequest` and `preParsing` checkpoints, observed closure hijacks the
reply and stops subsequent processing. Host hook chains already handed off may
continue until the next SDK-owned checkpoint; arbitrary application hooks are
not continuously wrapped. No public option, protocol field,
error code or runtime dependency is added. Direct core behavior is unchanged.

The guard does not use a completed `IncomingMessage.close` or its post-body
`destroyed` state as proof of lost TCP connection. Healthy async authentication,
complete bodies and keepalive are separate tested paths. See the official Node
[HTTP lifecycle reference](https://nodejs.org/api/http.html#event-close_3) and
Fastify's [reply lifecycle control](https://fastify.dev/docs/latest/Reference/Reply/#hijack).
The recorded local toolchain establishes tested behavior; current upstream
documentation does not expand that support claim.

## Limits

The boundary is an observed runtime closure/ended response. The guard cannot
preempt JavaScript, force prompt OS/network reporting, cancel backend/host work,
undo nonce consumption or stop application work already dispatched. Host event
listeners and framework response/close cleanup may still run. Replays
remain denied; uncertain outcomes require fresh signed requests/nonces plus
business idempotency/recovery. A closed socket may prevent any JSON response.

Direct `verifyRequest` and replay store APIs have no HTTP cancellation context.
Separate phase deadlines are not a total request budget. Backend timeouts and
concurrency/capacity controls remain host-owned. Deployed proxy/ingress/load/
failover, hosted CI, supported release, external audit, provider and physical
device verification remain separate gates. The Unity physical branch and its
historical receipts are excluded from this independent main continuation.

## Local verification and independent review

- Frozen original Node suite: **527/527**, zero skipped/cancelled.
- RED: initial **33 tests, 15 passed and 18 failed**; the relocation-safe
  standalone-process and Fastify handoff follow-up had **4/4 expected failures**.
  There were no skipped/cancelled tests. Final focused file has **34** cases.
- Focused GREEN: **34/34** under strict unhandled-rejection handling. Actual
  Express/Fastify/Nest servers observe native response closure before releasing
  pending identity/key/replay callbacks. Healthy completed bodies, async
  authentication, same-socket keepalive, request isolation and live fixed-code
  failures pass. All three standalone servers exit with a still-pending backend
  promise and a configured long replay deadline after the client disconnects.
- Common server runner: reference **209**, Python **555**, Node **561**, Java
  **211** (**1536 total**), zero skipped. Builds, types/package smoke and shared
  Redis first-claim rotations/simultaneous single-winner checks passed.
- Final offline installed consumer: **34/34** strict tests, zero skips or
  cancellations; all **15** source/tarball/installed files match byte-for-byte,
  including the private connection module and packaged deployment guide.
- Independent review approved scope-correction commit
  `27d3b0e8081e1248e0c328d7367907095b10d417`; **no open findings**. One Low
  documentation ambiguity about continuous Fastify hook cancellation was fixed
  and re-reviewed; there were no Critical/Important runtime findings.
  The reviewer independently passed the full **561**, focused **34**, additional
  **20** lifecycle probes and final installed **34** tests plus TypeScript.
  Probes include 100 sequential async keepalive requests per framework with no
  SDK timer/listener accumulation, partial-body cancellation, thenables/clock
  response-end boundaries and retention of a late backend nonce claim.

The implementation/tests are unchanged from tested commit
`84f3ef0a4694f15f5482a9270ceec8d903520a9b`. Package documentation was repacked
after its scope correction; prior and final packages/consumer locks are retained
separately. Logs, probes, build/package hashes and review receipts are archived
under `.superpowers/evidence/2026-10-21-disconnect-guard/` in the primary checkout
at integration. This record-only follow-up does not change the reviewed runtime,
tests or npm package. Clean-main integration, merged tests and archive-manifest
readback precede temporary worktree cleanup.
