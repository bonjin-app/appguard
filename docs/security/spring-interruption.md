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
