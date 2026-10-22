# Request-body capture time boundaries

A one-megabyte byte cap does not bound upload duration. A client may keep an
incomplete body open, or send small pieces often enough to avoid an idle timeout.
Body capture must finish before trusted identity/key/clock/replay/controller work.
This guide distinguishes the SDK's capture budget from host connection policies.

## ASP.NET Core

`AppGuardOptions` defaults to an absolute **30-second** body capture budget.
The original constructor remains available. To configure the new overload:

```csharp
var options = new AppGuardOptions(
    appId, externalOrigin, replayStore, authenticate, resolveKey,
    bodyReadTimeout: TimeSpan.FromSeconds(15),
    allowInsecureTransport: false);
```

The configured duration must be positive and at most five minutes. Capture uses
one monotonic start time; progress does not restart the budget. Reads, EOF,
framing and the final request snapshot must all complete before it expires.
The middleware bounds its asynchronous wait independently of a stream's
cancellation callbacks. Timeout returns the fixed `400 INVALID_REQUEST` response,
without invoking identity/key resolution, sampling the trusted clock, claiming a
nonce or dispatching the controller. Body-size overflow retains `413` behavior.
The scoped capture cancellation cannot later cancel a successful authentication
or controller. Those phases retain the original `RequestAborted` token.

A late asynchronous read cannot modify a buffer reused for another request:
the read array is private and unpooled. Late faults are observed without exposing
input or exception details. The middleware does not dispose the host-owned body.
Stopping a wait does not forcibly terminate arbitrary host work. A custom stream
that blocks synchronously before returning its asynchronous operation cannot be
preempted; host I/O and cancellation callbacks still need appropriate operating
limits. Header acceptance, TLS setup, response writes and connection draining
remain host responsibilities. This is not a request-wide or connection deadline.

Actual Kestrel loopback tests use the existing test-only HTTP/1 pre-parser header
capture, real signed requests, stalled and progressing incomplete uploads, and a
healthy request alongside a stalled one. They establish that capture rejection
precedes downstream work and that timely body bytes survive unchanged. This
fixture is not a production ingress implementation or TLS/HTTP2 qualification.

## Spring Servlet: unresolved host boundary

The current Spring filter uses blocking `ServletInputStream.read()`. Servlet
6.0/6.1 has no portable API to interrupt that read at an absolute deadline.
An elapsed-time check between reads cannot interrupt the read already waiting.
A background worker reading a request after the filter returns would violate
request ownership, and an asynchronous capture redesign also needs to preserve
Spring Security context, wrapper lifetimes and redispatch verification state.
No such redesign or synthetic deadline is installed by this phase.

`AsyncContext.setTimeout()` applies after the initial dispatch returns; starting
async processing and then continuing the same blocking read does not fix this.
See the [Servlet 6.1 async and nonblocking I/O specification](https://jakarta.ee/specifications/servlet/6.1/jakarta-servlet-spec-6.1.html).
Tomcat's [connection/upload timeout settings](https://tomcat.apache.org/tomcat-11.0-doc/config/http.html)
bound idle reads, not the whole upload when progress continues.

The dedicated limitation test sets a real loopback Tomcat idle timeout of one
second and sends an eight-byte signed body every 250 ms. The valid request
completes after the idle timeout's duration with one nonce claim, demonstrating
that an idle timeout is not an absolute limit. A separate stopped upload receives
`400 INVALID_REQUEST` without a nonce claim. This records a remaining limitation;
it does not certify Spring slow-upload protection.

A Spring deployment must enforce and independently test an absolute upload
boundary in its actual ingress/container and prevent direct access around that
boundary. Configure finite idle/header/TLS/connection admission policies too;
none of them alone substitutes for an absolute upload limit. Qualification of
that deployment remains open until its real slow-drip behavior is measured.

The [Spring mTLS ingress example](../deployment/spring-ingress.md) now supplies
one reproducible local topology to measure this boundary. Its separate bounded
collector completes the upload before opening a backend connection; the Spring
listener requires an ingress client certificate. This does not alter the blocking
Servlet SDK or establish another operator's deployed network boundary.

## Evidence scope

The new unit and localhost integration tests cover software request handling.
They do not establish device/provider behavior, deployment throughput guarantees,
external audit, or registry release readiness. The existing upstream development
dependency advisories remain visible release blockers.

## Local verification on 2026-10-22

The complete ASP.NET Core suite passed **262 tests**, with no failures or skips,
including the actual Kestrel cases and an owned disposable Redis. The default
30-second pending-read reproduction failed before the fix and passed afterward.
Cancellation-delivery and blocked-callback regressions also reproduced the
unsafe intermediate cleanup before the final implementation. The Spring Boot
suite passed **254 tests**, including the two Tomcat limitation probes and live
Redis integration, with no failures or skips. The owned Redis was stopped after
the runs; no existing Redis instance was changed.

A separate consumer was compiled against baseline commit
`4cee15651299e2a893336a345214b6d8e7710c13`. The same compiled consumer ran both
with the baseline library and after replacing only its AppGuard DLL with the
new build, confirming the original constructor's binary compatibility.

Implementation testing and independent internal review exposed linked-cancellation
teardown and queued cancellation-callback delivery issues; both were resolved
and rechecked in the final diff. No unresolved concrete code finding remained in that review. This
is internal evidence, not an external independent audit. Exact-commit hosted
results belong to the associated Actions runs; these local counts do not imply
CI success before those runs complete.
