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
