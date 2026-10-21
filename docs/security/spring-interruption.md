# Spring callback interruption preservation

2026-10-21; base `4159b523721ba0108f95cbb63c1f24fb5e3e3799`;
experimental Apache-2.0 server SDK.

## Reproduced loss of the host signal

Identity, key lookup and replay callbacks can throw checked exceptions. The SDK
previously translated a directly caught `InterruptedException` into a fixed
dependency failure without restoring the current thread's interruption status.
The request already failed closed, but the caller no longer saw that signal
after an interruptible operation had cleared it.

Worker-thread tests block inside an actual `CountDownLatch.await()`, synchronize
on callback entry and interrupt that worker from another thread. They reproduce
the lost status through the public filter and through direct adapter/verifier
calls. A separate getter fixture uses a deliberately unchecked rethrow because
Java's `Principal.getName()` does not declare checked exceptions; it covers the
adapter's existing broad exception boundary, not normal Principal behavior.

The [Java 17 Thread interruption contract](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/Thread.html#interrupt())
and [InterruptedException documentation](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/InterruptedException.html)
describe the interruption signal and operations that clear it when throwing.

## Behavior and limits

The SDK now restores the current thread's interrupt flag when these existing
boundaries catch `InterruptedException` directly. It then returns the same fixed
failure with no original cause or suppressed exception retained:

| Boundary | Fixed failure |
| --- | --- |
| Principal name getter or custom filter identity resolver | `IDENTITY_UNAVAILABLE` |
| `fromPrincipal` key callback | `KEY_RESOLVER_UNAVAILABLE` |
| Core verifier replay claim callback | `REPLAY_STORE_UNAVAILABLE` |

In the filter these remain HTTP 503 when the response can be written. Identity
and key failures do not sample the verification clock, claim a nonce or dispatch.
A failed replay callback is not retried and does not dispatch. A replay backend
may have committed its claim before reporting failure; no rollback or retry
guarantee is added.

Only the caught exception's type is inspected. Causes and suppressed exceptions
are not traversed to infer interruption. Ordinary failures do not set a new flag
or clear an existing one. Fatal JVM `Error` values remain outside these catches.
The public API, wire protocol, dependencies, time sampling, cryptography and
successful request behavior are unchanged.

This is cooperative signal preservation, not a new cancellation mechanism,
request deadline, forced callback stop, resource cap or shutdown guarantee. The
application/container owns thread lifecycle, interruption policy, dependency
timeouts and response delivery. A callback that swallows interruption or returns
normally is not reclassified by this change. Request-body `IOException` types
are not treated as interruption; for example, a socket timeout does not by itself
prove the thread was interrupted.

Local thread, servlet mock, embedded-container and copied-JAR tests are distinct
from production shutdown, load/failover, deployed transport, hosted CI, provider
or physical-device evidence.

## Local verification and independent review

Runtime/test commit `b2d845aea288f1be1551a4c93049feb69a366501` received an
independent local security/correctness review with no blocking findings. The
subsequent verification record changes only this guide.

- Baseline: 219 Java tests passed. Of ten new regressions/controls, six failed
  before the fix specifically because the interruption status was lost; all ten
  passed after the four catch-boundary changes.
- Full Maven package: 229 tests passed with zero failures, errors or skips. This
  includes shared conformance vectors, embedded Tomcat/Spring Security and an
  isolated local Redis instance.
- Standalone copied JAR: all ten new tests passed with SDK code-source checks and
  project output directories excluded from the consumer classpath. All 37
  class/resource entries and the embedded POM matched the artifact.
- Fresh reviewer execution: 28 selected Maven tests, ten copied-JAR regressions
  and 28 independent copied-JAR scenarios passed. Controls cover all four
  boundaries, nested/suppressed exceptions, existing flags, successful flagged
  callbacks, fixed error privacy/mapping, safe `AssertionError` propagation, and
  no retry/dispatch on failure.
- The reviewer independently compiled all 32 Java source files and matched all
  35 generated class entries to the JAR; all 86 external dependency JAR hashes
  matched the recorded classpath. The saved 229-test suite was inventoried, not
  rerun in full by the reviewer.

Counts overlap and are not unique tests to add together. The Python/Node.js
runtimes and shared protocol were unchanged and their suites were not rerun for
this Java-only fix. No JVM resource exhaustion, deployed shutdown or transport
guarantee was tested.

Commands, reports, source/artifact hashes, review receipt and integration
readback are retained in the primary main checkout under
`.superpowers/evidence/2026-10-21-spring-interruption/`.
