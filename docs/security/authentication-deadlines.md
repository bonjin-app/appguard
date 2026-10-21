# Node authentication deadline hardening

2026-10-21; independent local main base
`e136d066b49e891d3295e2f96cebe830175cd50d`; experimental Apache-2.0 SDK.

## Reproduced behavior and change

The Node adapters bounded body capture but could await identity/key callbacks
forever. Real localhost HTTP requests remained open until the test client's own
watchdog closed them. A slow synchronous callback could also return success after
the intended budget because a timer cannot run while JavaScript is blocked.
Overflow timer values were accepted even though Node cannot represent those
delays as configured. Null body timeout silently selected a default.

`identityTimeoutMs` now defaults to 10 seconds for the complete identity/key lookup
phase after body capture. One monotonic deadline and active-phase checks cover
both callbacks, including synchronous overrun checks. Timeout returns the existing
503 `IDENTITY_UNAVAILABLE` or `KEY_RESOLVER_UNAVAILABLE`. Timers are cleared on
completion; late successes/rejections are consumed without continuing SDK work.
Normal authentication rejection, key rejection, signature/replay semantics and
trusted-clock sampling after authentication retain their existing behavior.

Both timeout options reject values outside integer 1..2147483647, including null;
omission/undefined uses the default. Replace previously accepted null body timeout
with omission. Types and adapter documentation include the optional new setting.
There is no protocol field, new error code or added runtime dependency.

Callbacks are not forcibly cancelled. Event-loop blocking cannot be preempted;
the elapsed-time check acts when control returns. Replay claims, backend client
timeouts/concurrency, request disconnect handling and deployment capacity require
their own controls. The deadline is not a global request/resource bound or a
production-readiness certification. See the [deployment guide](../operations/server-deployment.md).

## Local regression evidence

- Frozen dependency setup and original framework baseline: **112/112**.
- RED: **50 tests, 40 failed and 10 passed**. Hung/late callback requests exceeded
  the client's watchdog, synchronous/shared-budget callbacks incorrectly passed,
  and invalid timeout settings were accepted.
- Focused GREEN: **50/50**, zero skips/cancellations; TypeScript check passed.
  Tests run actual Express/Fastify/Nest HTTP servers and native verification of
  the committed signed request. They assert zero nonce/downstream calls on
  failure, no key lookup after late identity completion, rejection consumption,
  successful defaults and independent concurrent-request progress.
- Test watchdogs were subsequently widened (600 to 3000 ms, independent-request
  budget 100 to 500 ms) for CI scheduling tolerance. The old source still failed
  its hanging-identity probe with the wider watchdog in a separate source copy.
  Final complete Node suite after this test-only adjustment: **429/429**.
- Complete common server runner: reference **209**, Python **555**, Node **429**,
  Java **211**, zero skips; builds, Node types/package smoke and cross-SDK Redis
  first-claimer/concurrent single-winner checks passed. Runtime code did not
  change after that runner; the final Node rerun includes the test adjustment.
- Initial offline installed npm consumer: **50/50** actual HTTP regressions, zero skips.
  All **13** packaged files matched source, tarball and installed copies; the
  consumer retains its actual dependency lock and direct dependency inventory.

## Independent review and package follow-up

The scoped independent security review found **0 Critical, 0 Important and
1 Minor** issue. The reviewer reran **162** source HTTP tests and **50** installed
package regressions with strict unhandled-rejection handling, checked TypeScript,
and passed nine additional public-middleware deadline/cleanup probes. The minor
issue was a README link to a repository-only guide that was absent after package
installation.

The guide is now shipped as `DEPLOYMENT.md` in the npm package and the README
links to that local file. Final repackaging checks compare all **14** files across
source, tarball and installation, verify the installed link target, and rerun
the **50** installed HTTP regressions. This follow-up changes documentation and
the package file allowlist; the reviewed runtime implementation is unchanged.

Common server, offline installed-package and scoped security-review receipts are
collected under `.superpowers/evidence/2026-10-21-auth-deadlines/` in the primary
checkout during clean-main integration. Merged tests and archive readback precede
worktree cleanup. Local checks do not imply hosted CI, deployment, provider or
physical-device verification; the Unity physical branch remains separate.
