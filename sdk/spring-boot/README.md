# AppGuard Spring Boot starter

Experimental Apache-2.0 implementation of [request-v0](../../protocol/request-v0.md) and [HTTP v0](../../protocol/http-v0.md). Local artifacts only; nothing has been published to a registry. A successful verification proves the bound request signature and nonce claim. The application still authenticates the Bearer token, enforces resource authorization, and manages trustworthy key enrollment/revocation. Platform attestation is outside this SDK.

## Tested support

- Temurin Java 17.0.20; Spring Boot 4.1.1; Spring Framework 7.0.9; Spring Security 7.1.1; Tomcat 11.0.24; Servlet 6.1.
- Spring Data Redis 4.1.1 with Lettuce 7.5.2.RELEASE; Jackson 2.21.8 / 3.1.8 BOMs and Netty 4.2.19.Final BOM overrides; live tests against disposable Redis 7.2.10.
- Servlet/MVC applications, blocking input-stream/reader body access, JSON and opaque content bytes, duplicate query parameters, chunked request content, Spring MVC asynchronous redispatch.
- Beyond the explicit legacy source/test profile below, other Boot versions, containers, Java providers, HTTP/2, and production TLS topologies have not been runtime-tested. This is an experimental protocol integration, not a production certification.

## Dependency maintenance and legacy source compatibility

The unpublished package now defaults to Boot 4.1.1, the current stable 4.1
release in Maven Central at this receipt. Java 17 and the public AppGuard API
remain unchanged. The POM imports Jackson 2.21.8, Jackson 3.1.8 and Netty
4.2.19.Final BOMs **before** Boot's BOM so Maven aligns each family on its patched
release line. The SDK's explicit Jackson 2 dependency remains; Boot 4 applications
may also use Jackson 3. BOM import alone does not add Jackson 3 runtime JARs.
Jackson annotations intentionally remain at 2.21, as specified by those BOMs.

Vendor sources: [Jackson 2.21.7 security fixes](https://github.com/FasterXML/jackson/wiki/Jackson-Release-2.21.7),
[2.21.8 follow-up patches](https://github.com/FasterXML/jackson/wiki/Jackson-Release-2.21.8),
[Jackson 3.1.8](https://github.com/FasterXML/jackson/wiki/Jackson-Release-3.1.8),
[Netty security releases](https://netty.io/news/),
[SNI advisory](https://github.com/netty/netty/security/advisories/GHSA-c4c3-7fpv-j4q5)
and [compression advisory](https://github.com/netty/netty/security/advisories/GHSA-558v-64gr-wgg4).
The resolved versions exceed the reported fixes for baseline Jackson/Netty
HIGH/CRITICAL and MEDIUM findings. This is a dependency remediation statement;
current scanner results and actual deployment validation are separate evidence.
A consuming application's dependency management takes precedence: import patched
family BOMs before the application's Boot BOM and inspect its own runtime tree,
including optional Redis/container dependencies.

`-Plegacy-boot3.5` is an explicit **local source/test rebuild only** against Boot
3.5.16, Framework 6.2.19, Servlet 6.0, Spring Data Redis 3.5.13, Lettuce 6.6.0.RELEASE
and Netty 4.1.139.Final. Spring identifies 3.5.16 as the
[last OSS 3.5 release](https://spring.io/blog/2026/06/25/spring-boot-3-5-16-available-now/).
Dependency patches do not restore its OSS support. Do not publish, install or
deploy a legacy-profile build under the official Boot 4 artifact coordinates.
Use `mvn -Plegacy-boot3.5 clean test` for this compatibility check; any separately
maintained legacy package would need distinct versioning and explicit consumer
configuration. Re-run default `mvn clean package` afterward to produce the official
Boot 4 package. No one-binary dual-Boot-support guarantee is made.

Spring's [migration guide](https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-4.0-Migration-Guide)
requires Framework 7/Servlet 6.1 and discourages combining Boot 3 and 4 support in
one artifact. The local default and legacy suites each passed all 252 tests on
Java 17 with the owned disposable Redis. No production-source API migration was
needed for this suite; the embedded HTTP test harness now uses
`ConfigurableApplicationContext` and `local.server.port` to avoid a relocated
Boot-specific context class. These observations do not establish compatibility
with every host application's security/filter/container configuration.

The 2026-10-22 final default `clean package` passed 252 tests, and the isolated
installed-Maven consumer passed 32 tests, all with zero failures/errors/skips. Its
resolved application tree confirms Jackson 3.1.8 alongside Jackson 2.21.8. Package
receipts, baseline/patched runtime trees, runtime JARs and legacy test outputs are
ignored under `.evidence/security-dependencies/`. The consumer covers installed-JAR
class origin, wrapper boundaries, real embedded HTTP/Security and owned Redis.
No external Redis, server configuration change, scanner suppression or registry
publication was performed by this dependency-maintenance task.

## Build and install locally

From this directory with Java 17 and Maven:

```sh
mvn test
mvn package
mvn install
```

The artifact is `target/appguard-spring-boot-starter-0.1.0-SNAPSHOT.jar`. The build reads the shared corpora relative to this project's directory, including when invoked with `mvn -f /absolute/path/sdk/spring-boot/pom.xml test` from another directory. For live Redis tests, supply `APPGUARD_REDIS_URL=redis://127.0.0.1:<disposable-port>/0`; otherwise the single live integration test is explicitly skipped. Never point tests at an existing Redis database.

In an existing Boot 3.5.16 servlet application, add the locally installed dependency:

```xml
<dependency>
  <groupId>io.appguard</groupId>
  <artifactId>appguard-spring-boot-starter</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Boot auto-configuration is disabled until explicitly enabled:

```properties
appguard.enabled=true
appguard.app-id=your-app-id
appguard.origin=https://api.example.com
server.forward-headers-strategy=none
```

The configured origin must be the trusted, externally visible lowercase HTTPS DNS origin, with no path or default `:443` port. It is never read from Host or forwarding headers. Configure HTTPS on the actual server connector. Insecure transport rejects by default. Only for controlled local testing or separately enforced TLS termination, explicitly set `appguard.allow-insecure-transport=true`; the operator owns that transport boundary. The SDK unwraps servlet request wrappers before checking connector evidence and capturing original URI/query/headers. Auto-configuration rejects forwarded-header interpretation (`server.forward-headers-strategy` other than `none`) without that explicit opt-in. Programmatically installed container valves and gateways must also preserve the original target and a trustworthy transport indication.

## Authentication, enrolled keys, and replay store

Registry keys must contain one complete ASCII `PUBLIC KEY` PEM envelope and a
P-256 SPKI DER key. The parsed key's encoded DER must match the supplied DER;
ignored trailing/concatenated DER and normalized nonminimal encodings reject as
`KEY_REJECTED` before nonce claims. Existing LF/CRLF, optional final newline and
trailing ASCII whitespace support remains. These checks validate encoding,
not registry trust or enrollment. Java provider support remains as listed above.

Provide both `IdentityResolver` and `ReplayStore` beans. Enabling AppGuard without valid app ID/origin or either security dependency fails startup. There is no automatic key resolver, token acceptance, Redis connection, or volatile replay store.

The application's Bearer authentication must finish before AppGuard runs, and must not consume or change the body. With standard Spring Security servlet registration, AppGuard is registered at order `-90`, after the default security proxy order `-100`; it protects all requests reaching it before MVC controllers. A configured Spring Security chain may reject requests first using its own error responses. AppGuard does not replace those application responses.

For an existing authenticated servlet principal and trusted enrollment repository:

```java
@Bean
IdentityResolver appGuardIdentity(EnrollmentRepository enrolledKeys) {
    return IdentityResolver.fromPrincipal((authenticatedSubject, keyId) ->
        enrolledKeys.findAppGuardKey(authenticatedSubject, keyId));
}
```

`EnrollmentRepository` is application-owned; the SDK does not supply it. Return a trusted `KeyRecord(appId, keyId, subject, publicKeyPemBytes, "ecdsa-p256-sha256", revoked)`. Unknown key may return `null` and rejects with `KEY_REJECTED`. The resolver must never trust a client-supplied subject or key. `fromPrincipal` returns `AUTHENTICATION_REQUIRED` if there is no principal and maps lookup exceptions or malformed non-null key contracts to `KEY_RESOLVER_UNAVAILABLE`. A custom `IdentityResolver` may implement equivalent trusted authentication/key binding, returns `null` for authentication rejection, and must return a validated authenticated subject plus enrolled key. Resolver exceptions produce fixed `IDENTITY_UNAVAILABLE` responses.

`fromPrincipal` reads the principal name once per invocation, validates the existing
AppGuard subject format (1–128 ASCII letters, digits, `.`, `_`, `:`, `-`), then uses
that same immutable string for key lookup and the returned `Identity`. A getter
failure or malformed name produces fixed `IDENTITY_UNAVAILABLE` in the filter
before key lookup. Only key callback/contract failures use `KEY_RESOLVER_UNAVAILABLE`.
Key ownership is still checked by the verifier against the captured subject;
a mutable custom principal cannot replace it after lookup. The host Principal
object is preserved, so the application still owns its authentication context,
immutability and resource authorization. See [principal binding verification](../../docs/security/spring-principal-binding.md).

If authentication or body-processing filters use nonstandard orders, install AppGuard explicitly in the application's Spring Security chain after Bearer authentication and before authorization/body consumers. Set `appguard.register-servlet-filter=false` to disable its automatic servlet registration; keep the supplied `AppGuardFilter` bean and add it exactly once to the security chain. Register it for REQUEST and all redispatch types when registering outside Spring Security. Do not put a JSON/form/decompression filter before it. SDK filtering has no default route exclusions; use an intentional application/filter mapping for the intended protected surface.

For shared replay protection add the application's Redis dependencies (the SDK marks them optional), configure a long-lived secured `StringRedisTemplate`, and supply:

```java
@Bean
ReplayStore appGuardReplay(StringRedisTemplate redis) {
    return new RedisReplayStore(redis);
}
```

The tested dependency versions are `org.springframework.data:spring-data-redis:4.1.1` and `io.lettuce:lettuce-core:7.5.2.RELEASE`; Boot's Redis starter also provides them through its dependency management. Configure connection/command timeouts and lifecycle in the application. Each claim issues a single atomic `SET key 1 NX EX ttl`, with `ttl=expires-now` in `1..150`. Key names are the protocol's SHA-256 of the compact JSON `[appId,keyId,nonce]` array and interoperate across languages. Conflict returns false; exceptions/null fail closed. Redis pipelines/transactions that cannot immediately return a claim result are unsupported and fail closed. Operators must prevent eviction of live security keys, provision capacity, secure connections, and establish their required persistence/replication/restart guarantees.

Only for tests/development, explicitly supply `new LocalReplayStore()` (default 10000 live entries) or `new LocalReplayStore(capacity)`. This synchronized store is volatile and single-process. Never select it implicitly for distributed or production replay guarantees.

An optional application `Clock` bean controls trusted verification time; otherwise `Clock.systemUTC()` is used. Time is sampled once after identity resolution completes. Verified metadata is stored in request attribute `AppGuardFilter.VERIFICATION_ATTRIBUTE` as `VerificationResult`. The authenticated principal is preserved. Internal per-filter proof allows verified async/error/forward/include redispatches without consuming the nonce twice; redispatch without original proof rejects. No-argument `request.startAsync()` retains the verified body wrapper and current response, so a worker can read the original captured bytes through `AsyncContext.getRequest()` before redispatch. The explicit `startAsync(request, response)` overload preserves the supplied objects according to servlet semantics; pass the verified request (or a wrapper around it) to retain its captured body.

## Body and wire boundaries

On the initial `REQUEST`, upstream wrappers must preserve method, URI/query,
context/servlet/path-info routing, content type, character encoding, and all
header views (including direct lookups). Divergence rejects with fixed HTTP 400
before identity lookup or nonce claim. Header names/order may differ; their
ordered values must match. Principal/role wrappers remain supported. Trusted
internal redispatch can change routes using the original proof; applications own
its authorization. Post-capture mutations, custom mapping/parameter APIs and
downstream wrappers remain trusted host code. See the
[wrapper consistency boundary](../../docs/security/spring-wrapper-boundary.md).

The filter retains every enumerated header value, preserves duplicate evidence, verifies the original servlet `requestURI + queryString` (including empty query), and captures no more than 1 MiB plus one byte. Content-Length must match captured bytes; conflicting framing, invalid fields, duplicate singletons, unsupported content encoding, aborted/truncated streams, absent raw target/header/body evidence and oversized bodies fail closed. Downstream code receives the captured bytes only after successful verification.

`application/x-www-form-urlencoded` and every `multipart/*` content type are explicitly rejected with HTTP 400 `INVALID_REQUEST`, before nonce consumption. This avoids changing servlet form/multipart parameter semantics after raw capture. Query parameters remain available, including duplicates. Nonblocking `ServletInputStream.setReadListener` is unsupported; blocking input/reader access and MVC async processing are supported. Use another integration for nonblocking servlet content consumption.

Containers/proxies can reject malformed framing or unsupported targets before the SDK, normalize data, enforce smaller header limits, or discard evidence. The SDK cannot recover evidence lost before its capture point. Keep the container/proxy/request-filter chain within the documented boundary and verify your deployment topology separately. Spring Security's firewall may intentionally reject percent-encoded slash, semicolon, or other targets before AppGuard.

AppGuard failures contain only `{"code":"FIXED_REASON"}`: 400 malformed request/evidence; 413 oversized content; 401 no authenticated identity; 403 core verification/profile/time/key/digest/signature/replay rejection; 503 identity/key/replay dependency failure. Exception details, tokens, bodies, PEM material and signature bases never enter SDK error responses.

When the Principal adapter, custom filter identity resolver or core replay callback
directly throws `InterruptedException`, the SDK restores the current thread's
interrupt flag before returning its existing fixed failure. Causes are not
traversed to infer interruption. Host code still owns thread lifecycle,
interruption policy and dependency timeouts; this adds no cancellation/deadline
mechanism or guarantee that an HTTP error can be delivered after interruption.
See [callback interruption verification](../../docs/security/spring-interruption.md).

## Verification evidence

On 2026-10-20, `APPGUARD_REDIS_URL=redis://127.0.0.1:<disposable-port>/0 mvn -B package` completed with **113 tests, zero failures/errors/skips** and built the starter JAR. A separate `javac`/`java` consumer using only that JAR and the JDK verified the shared signed fixture, then rejected its replay. A second smoke booted Tomcat and Spring Security with SDK classes loaded from the packaged JAR (excluding `target/classes`), then passed signed HTTP byte/query/replay and async redispatch checks. The JAR contains the auto-configuration import and Apache license, and excludes test classes. Initial missing-feature compilation RED evidence and later behavioral RED/GREEN regressions for forwarded transport, malformed resolver contracts, and asynchronous worker body preservation are retained locally.

The suite consumes every shared core case (40) and HTTP parser case (43). Tests also cover fixed time and key/curve boundaries, null/failing replay contracts, atomic local claims/capacity, bounded capture, raw evidence loss, spoofed transport wrappers, nonce preservation after tampering, MVC byte/identity preservation, missing startup dependencies, forwarded-transport configuration, and live Redis concurrency/TTL/backend failure.

Real localhost HTTP tests use Boot/Tomcat plus an actual Spring Security chain with an explicitly test-only Bearer authenticator and insecure transport opt-in. They exercise JSON UTF-8 bytes, duplicate query keys, replay, invalid authentication, actual asynchronous redispatch, worker body access after no-argument async startup, explicit async request/response wrappers, exactly one nonce claim through redispatch, chunked content, explicit empty query, truncated streams, oversized content, duplicate metadata, and explicit form/multipart rejection. They do not claim physical-device, store, production TLS, deployment, or durable Redis evidence.

Test-only cross-process Redis probe (not packaged in the SDK JAR):

```sh
mvn test-compile org.apache.maven.plugins:maven-dependency-plugin:3.8.1:build-classpath \
  -Dmdep.outputFile=target/test-classpath.txt -Dmdep.includeScope=test
java -cp "target/test-classes:target/classes:$(cat target/test-classpath.txt)" \
  io.appguard.RedisClaimCli redis://127.0.0.1:DISPOSABLE_PORT/0 \
  APP_ID KEY_ID CANONICAL_22_CHAR_NONCE EXPIRES NOW
```

The probe prints `CLAIMED` or `REPLAY_DETECTED`, accepts disposable loopback Redis only, and leaves the security key to its short relative expiry. Logs and local RED/GREEN build evidence are ignored under `.evidence/`; build artifacts are ignored under `target/`.

## Explicit policy and audit (experimental v0)

The pure Java 17 policy API matches all 42 shared `conformance/v0/policy.json`
cases. It does not install or change the Servlet filter. The application must
supply trusted server authentication, request-verification and attestation
verdicts; never infer them from client-reported status. Risk codes are bounded
untrusted hints. `rateLimited` consumes your existing limiter's verdict, and this
module installs neither request counters nor a provider verifier.

```java
Policy policy = new Policy("balanced");
// Populate these verdicts only after your trusted server checks.
PolicyContext context = new PolicyContext("authenticated", "verified", "verified",
    101L, List.of(), false);
PolicyDecision decision = PolicyEngine.evaluate(policy, context, 100);
JsonAuditSink sink = new JsonAuditSink(json -> applicationAuditWriter(json));
sink.emit(decision, "opaque-event-1", "my-app", 100, context);
boolean mayContinue = decision.action().equals("allow") || decision.action().equals("observe");
// Application authorization must also succeed. step_up blocks until a separate
// trusted verification flow succeeds; deny blocks execution.
```

`new PolicyContext()` defaults every verdict to missing, and missing authentication
always denies. Signatures default to required. Only explicit
`new Policy("basic", false, List.of("debugger", "root", "hook", "tamper"))` opts out.
Fresh attestation requires `now < attestationExpires`; equality is expired.
Missing/unsupported/unavailable/expired attestation and configured suspicious
hints produce `observe` in Basic, `step_up` in Balanced, and `deny` in Strict.
Authentication failures, rejected/unavailable request verification, rejected
attestation and rate limiting deny in every profile with protocol precedence.

`Policy`, `PolicyContext`, and `PolicyDecision` are validated immutable records;
signal lists are copied and unmodifiable. `toString()` omits raw risk codes.
Signals contain at most 32 unique `[a-z][a-z0-9_]{0,63}` codes. Timestamps are Java
`long` values from 0 through 999999999999999; Java's typed API excludes boolean
and fractional timestamps. Invalid values use fixed `PolicyException.code()`.

`AuditEvent.create(decision, eventId, appId, now[, context]).toMap()` returns an
immutable allowlist. Optional context adds only `risk_count` and
`attestation_state`, with no raw risk codes, subject, token, nonce, key, IP or body.
IDs must be opaque application/event identifiers (1–128 ASCII letters/digits or
`._:-`), never credentials or user IDs. `JsonAuditSink` serializes compact JSON
using Jackson and invokes the explicit synchronous `Callback`, which may throw
checked exceptions. Callback failures become `AuditUnavailableException` with
fixed `AUDIT_UNAVAILABLE`, no original cause or suppressed exception; interruption
restores the thread flag. Invalid metadata uses `AuditException` with
`INVALID_AUDIT_EVENT`. The caller owns storage, availability, privacy and retention.

## Request-body time limit boundary

The one-megabyte capture cap does not bound upload duration. The current blocking
Servlet filter cannot install a portable absolute read deadline. Tomcat idle
connection/upload timeouts do not stop a progressing slow upload. Deploy behind
an independently verified absolute upload boundary and prevent direct access
around it. [Supported .NET deadline and the measured Servlet limitation](../../docs/security/body-capture-deadlines.md).
