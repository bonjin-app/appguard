# Server SDK verification record

Date: 2026-10-20. Experimental local implementation; no registry publication, deployment, production security certification or provider-attestation claim.

## Source and reproducible command

The foundation was fast-forwarded into local `main` at `1725f895fd769b6a78a0b37ee19dc7fe0b3064f5`, then its frozen 209-test reference suite passed in that checkout. Server SDK implementation continues on `codex/appguard-server-sdks`, based on that commit. This record concerns that SDK branch.

From any directory, with Python 3.11+, uv, Node 22+, Java 17, Maven and a newly created disposable loopback Redis service:

```sh
APPGUARD_TEST_REDIS_URL=redis://127.0.0.1:DISPOSABLE_PORT/0 \
  /absolute/path/to/appguard/scripts/test-server-sdks.sh
```

The runner requires a loopback URL, uses frozen Python/npm dependency installations, runs all language suites with live Redis, builds wheel/JAR artifacts, tests npm pack/install and checks shared replay claims across processes. It deletes only uniquely scoped probe keys, never flushes a database, and does not start or stop a Redis service. Supply a disposable instance, never an existing application's database. Executable paths can be overridden with `APPGUARD_UV_CMD` / `APPGUARD_MAVEN_CMD`.

## Observed results

The parent agent reran the complete command successfully, with **683 tests passed, zero failed and zero skipped**:

| Suite | Passed | Evidence boundary |
| --- | ---: | --- |
| Python reference | 209 | Promoted SDK core, all 40 request vectors, cryptographic/negative/time/key/local-replay tests; four OpenSSL signature checks ran |
| Python SDK | 105 | All 43 HTTP vectors; real FastAPI/Django/Flask applications through HTTPX ASGITransport; direct bounded-stream checks; live Redis claims |
| Node.js SDK | 258 | All 40 request + 43 HTTP vectors; real Express/Fastify/NestJS servers; transport, callback, runtime-type and live Redis checks |
| Spring Boot SDK | 111 | All 40 request + 43 HTTP vectors; real Tomcat/Spring Security/MVC, async redispatch, bounded servlet capture, configuration and live Redis |

These suite counts overlap in shared scenarios; they are not 683 distinct attack categories. All three implementations consume the same committed corpora, rather than translating a handful of hand-picked examples. Python's original 209 tests now import compatibility shims backed by the standalone SDK core.

Additional integration checks passed:

- Python first, Node first, and Java first each claimed one identical replay scope; both other SDKs rejected it. A concurrent Python/Node/Java process probe accepted exactly one claim. Redis retained the shared key through the remaining signature validity.
- Node TypeScript declarations compiled; npm packed only SDK source/declarations, README and license; a clean temporary consumer installed the tarball and performed native signing, verification, parser and middleware-factory checks without parent `node_modules` fallback.
- Python built both wheel and sdist. A separate virtual environment installed the wheel and imported the core/ASGI/wire/Redis modules with Python `-I`; it verified the committed signature and rejected replay using SDK code loaded from site-packages, without importing the reference checkout.
- Java built the starter JAR. A JDK-only `javac`/`java` consumer verified the committed fixture and rejected replay. A second smoke loaded SDK classes from the JAR, excluded `target/classes`, booted actual Tomcat/Spring Security and passed signed HTTP body/query/replay plus async redispatch checks. The JAR contains auto-configuration imports/license and excludes test classes.
- Java's 83 corpus tests passed from `/tmp` with an absolute Maven project path. Python and Node fixture locations resolve relative to source files, and the root runner changes to its own repository root.

Runtime versions actually exercised: Python 3.11.15, cryptography 50.0.2, FastAPI 0.150.0, Starlette 1.9.0, Django 5.2.18, Flask 3.1.3, asgiref 3.12.1, redis-py 8.1.0; Node 22.23.2, Express 5.3.0, Fastify 5.12.7, NestJS 12.2.0, node-redis 6.3.0; Temurin Java 17.0.20, Maven 3.10.0, Spring Boot 3.5.16, Spring Framework 6.2.19, Spring Security 6.5.11, Tomcat 10.1.55, Spring Data Redis 3.5.13, Lettuce 6.6.0.RELEASE; Redis 7.2.10.

## Implementation and review decisions

Tests were observed failing before parser/verifier/framework implementation in each language. Later regressions were observed RED/GREEN for transport rewriting, original-target preservation and malformed identity/key callback contracts. Local detailed logs and build artifacts are ignored; the portable tests and corpora are committed.

- **ASGI target capture:** ASGI's empty query string cannot distinguish `/path` and `/path?`. Python rejects those requests unless a trusted server integration supplies exact raw-target bytes. Nonempty raw queries can be reconstructed losslessly. This costs a server-specific capture integration for ordinary no-query routes; guessing would violate the signed-target contract.
- **Servlet body semantics:** Spring's first adapter rejects URL-encoded forms, all multipart bodies and nonblocking input-listener access. Blocking JSON/opaque bytes, raw query parameters and MVC async redispatch are supported. This narrows integration scope rather than silently altering parameter semantics after body capture.
- **Node capture placement:** Express/Nest require first-at-root installation before parsers/rewriters. Fastify snapshots native HTTP request evidence before framework hooks; synthetic Fastify injection without that evidence fails closed. These requirements cost explicit integration ordering and exclude injection-only success claims.
- **Dependency contracts:** Unknown enrolled keys are expected 403 failures; thrown/malformed trusted resolver contracts are fixed 503 dependency failures. No adapter accepts identity or a replay store implicitly.

## Limits of this evidence

Python tests exercise framework applications in process, not a deployed ASGI server or production TLS termination. Node/Java localhost servers exercise actual HTTP handling, including explicit test-only insecure transport opt-ins; they do not certify a production proxy/container topology. Original bytes lost before SDK capture cannot be recovered. Operators must secure framework transport metadata and reject untrusted forwarding rewrites.

The disposable Redis instance was built from checksum-verified official source, bound only to localhost and configured without persistence. This proves local atomic claims/interoperability and failure behavior, not production persistence, failover, replication or no-eviction configuration. Configure those guarantees and client timeouts separately.

No mobile SDK, client-key enrollment, Apple/Google attestation, automatic obfuscation, user authorization engine, rate policy engine, AI service or administrator console is implemented in this stage. No real account credentials or production key material are used by the test corpus. The localhost TLS fixture under the Node test directory is explicitly test-only and excluded from the npm package.
