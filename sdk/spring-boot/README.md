# AppGuard Spring Boot starter

Experimental Apache-2.0 implementation of [request-v0](../../protocol/request-v0.md) and [HTTP v0](../../protocol/http-v0.md). Local artifacts only; nothing has been published to a registry. A successful verification proves the bound request signature and nonce claim. The application still authenticates the Bearer token, enforces resource authorization, and manages trustworthy key enrollment/revocation. Platform attestation is outside this SDK.

## Tested support

- Temurin Java 17.0.20; Spring Boot 3.5.16; Spring Framework 6.2.19; Spring Security 6.5.11; embedded Tomcat 10.1.55.
- Spring Data Redis 3.5.13 with Lettuce 6.6.0.RELEASE; live tests against disposable Redis 7.2.10.
- Servlet/MVC applications, blocking input-stream/reader body access, JSON and opaque content bytes, duplicate query parameters, chunked request content, Spring MVC asynchronous redispatch.
- Other Boot versions, containers, Java providers, HTTP/2, and production TLS topologies have not been runtime-tested. This is an experimental protocol integration, not a production certification.

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

If authentication or body-processing filters use nonstandard orders, install AppGuard explicitly in the application's Spring Security chain after Bearer authentication and before authorization/body consumers. Set `appguard.register-servlet-filter=false` to disable its automatic servlet registration; keep the supplied `AppGuardFilter` bean and add it exactly once to the security chain. Register it for REQUEST and all redispatch types when registering outside Spring Security. Do not put a JSON/form/decompression filter before it. SDK filtering has no default route exclusions; use an intentional application/filter mapping for the intended protected surface.

For shared replay protection add the application's Redis dependencies (the SDK marks them optional), configure a long-lived secured `StringRedisTemplate`, and supply:

```java
@Bean
ReplayStore appGuardReplay(StringRedisTemplate redis) {
    return new RedisReplayStore(redis);
}
```

The tested dependency versions are `org.springframework.data:spring-data-redis:3.5.13` and `io.lettuce:lettuce-core:6.6.0.RELEASE`; Boot's Redis starter also provides them through its dependency management. Configure connection/command timeouts and lifecycle in the application. Each claim issues a single atomic `SET key 1 NX EX ttl`, with `ttl=expires-now` in `1..150`. Key names are the protocol's SHA-256 of the compact JSON `[appId,keyId,nonce]` array and interoperate across languages. Conflict returns false; exceptions/null fail closed. Redis pipelines/transactions that cannot immediately return a claim result are unsupported and fail closed. Operators must prevent eviction of live security keys, provision capacity, secure connections, and establish their required persistence/replication/restart guarantees.

Only for tests/development, explicitly supply `new LocalReplayStore()` (default 10000 live entries) or `new LocalReplayStore(capacity)`. This synchronized store is volatile and single-process. Never select it implicitly for distributed or production replay guarantees.

An optional application `Clock` bean controls trusted verification time; otherwise `Clock.systemUTC()` is used. Time is sampled once after identity resolution completes. Verified metadata is stored in request attribute `AppGuardFilter.VERIFICATION_ATTRIBUTE` as `VerificationResult`. The authenticated principal is preserved. Internal per-filter proof allows verified async/error/forward/include redispatches without consuming the nonce twice; redispatch without original proof rejects.

## Body and wire boundaries

The filter retains every enumerated header value, preserves duplicate evidence, verifies the original servlet `requestURI + queryString` (including empty query), and captures no more than 1 MiB plus one byte. Content-Length must match captured bytes; conflicting framing, invalid fields, duplicate singletons, unsupported content encoding, aborted/truncated streams, absent raw target/header/body evidence and oversized bodies fail closed. Downstream code receives the captured bytes only after successful verification.

`application/x-www-form-urlencoded` and every `multipart/*` content type are explicitly rejected with HTTP 400 `INVALID_REQUEST`, before nonce consumption. This avoids changing servlet form/multipart parameter semantics after raw capture. Query parameters remain available, including duplicates. Nonblocking `ServletInputStream.setReadListener` is unsupported; blocking input/reader access and MVC async processing are supported. Use another integration for nonblocking servlet content consumption.

Containers/proxies can reject malformed framing or unsupported targets before the SDK, normalize data, enforce smaller header limits, or discard evidence. The SDK cannot recover evidence lost before its capture point. Keep the container/proxy/request-filter chain within the documented boundary and verify your deployment topology separately. Spring Security's firewall may intentionally reject percent-encoded slash, semicolon, or other targets before AppGuard.

AppGuard failures contain only `{"code":"FIXED_REASON"}`: 400 malformed request/evidence; 413 oversized content; 401 no authenticated identity; 403 core verification/profile/time/key/digest/signature/replay rejection; 503 identity/key/replay dependency failure. Exception details, tokens, bodies, PEM material and signature bases never enter SDK error responses.

## Verification evidence

On 2026-10-20, `APPGUARD_REDIS_URL=redis://127.0.0.1:<disposable-port>/0 mvn -B package` completed with **111 tests, zero failures/errors/skips** and built the starter JAR. A separate `javac`/`java` consumer using only that JAR and the JDK verified the shared signed fixture, then rejected its replay. A second smoke booted Tomcat and Spring Security with SDK classes loaded from the packaged JAR (excluding `target/classes`), then passed signed HTTP byte/query/replay and async redispatch checks. The JAR contains the auto-configuration import and Apache license, and excludes test classes. Initial missing-feature compilation RED evidence and later behavioral RED/GREEN regressions for forwarded transport and malformed resolver contracts are retained locally.

The suite consumes every shared core case (40) and HTTP parser case (43). Tests also cover fixed time and key/curve boundaries, null/failing replay contracts, atomic local claims/capacity, bounded capture, raw evidence loss, spoofed transport wrappers, nonce preservation after tampering, MVC byte/identity preservation, missing startup dependencies, forwarded-transport configuration, and live Redis concurrency/TTL/backend failure.

Real localhost HTTP tests use Boot/Tomcat plus an actual Spring Security chain with an explicitly test-only Bearer authenticator and insecure transport opt-in. They exercise JSON UTF-8 bytes, duplicate query keys, replay, invalid authentication, actual asynchronous redispatch, chunked content, explicit empty query, truncated streams, oversized content, duplicate metadata, and explicit form/multipart rejection. They do not claim physical-device, store, production TLS, deployment, or durable Redis evidence.

Test-only cross-process Redis probe (not packaged in the SDK JAR):

```sh
mvn test-compile org.apache.maven.plugins:maven-dependency-plugin:3.8.1:build-classpath \
  -Dmdep.outputFile=target/test-classpath.txt -Dmdep.includeScope=test
java -cp "target/test-classes:target/classes:$(cat target/test-classpath.txt)" \
  io.appguard.RedisClaimCli redis://127.0.0.1:DISPOSABLE_PORT/0 \
  APP_ID KEY_ID CANONICAL_22_CHAR_NONCE EXPIRES NOW
```

The probe prints `CLAIMED` or `REPLAY_DETECTED`, accepts disposable loopback Redis only, and leaves the security key to its short relative expiry. Logs and local RED/GREEN build evidence are ignored under `.evidence/`; build artifacts are ignored under `target/`.
