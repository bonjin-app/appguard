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

After review fixes, the parent agent reran all four suites, with **697 tests passed, zero failed and zero skipped**:

| Suite | Passed | Evidence boundary |
| --- | ---: | --- |
| Python reference | 209 | Promoted SDK core, all 40 request vectors, cryptographic/negative/time/key/local-replay tests; four OpenSSL signature checks ran |
| Python SDK | 117 | All 43 HTTP vectors; real FastAPI/Django/Flask applications through HTTPX ASGITransport; direct bounded-stream checks; live Redis claims; Flask framing/header and nonce regressions |
| Node.js SDK | 258 | All 40 request + 43 HTTP vectors; real Express/Fastify/NestJS servers; transport, callback, runtime-type and live Redis checks |
| Spring Boot SDK | 113 | All 40 request + 43 HTTP vectors; real Tomcat/Spring Security/MVC, late async worker reads/redispatch, bounded servlet capture, configuration and live Redis |

These suite counts overlap in shared scenarios; they are not 697 distinct attack categories. All three implementations consume the same committed corpora, rather than translating a handful of hand-picked examples. Python's original 209 tests now import compatibility shims backed by the standalone SDK core.

Additional integration checks passed:

- Python first, Node first, and Java first each claimed one identical replay scope; both other SDKs rejected it. A concurrent Python/Node/Java process probe accepted exactly one claim. Redis retained the shared key through the remaining signature validity.
- Node TypeScript declarations compiled; npm packed only SDK source/declarations, README and license; a clean temporary consumer installed the tarball and performed native signing, verification, parser and middleware-factory checks without parent `node_modules` fallback.
- Python built both wheel and sdist. A separate virtual environment installed the wheel and imported the core/ASGI/wire/Redis modules with Python `-I`; it verified the committed signature and rejected replay using SDK code loaded from site-packages, without importing the reference checkout. The rebuilt wheel additionally passed actual Flask chunked-body/JSON access, header-alias rejection and replay checks in that isolated environment.
- Java built the starter JAR. A JDK-only `javac`/`java` consumer verified the committed fixture and rejected replay. A second smoke loaded SDK classes from the JAR, excluded `target/classes`, booted actual Tomcat/Spring Security and passed signed HTTP body/query/replay plus async redispatch checks. The JAR contains auto-configuration imports/license and excludes test classes.
- Java's 83 corpus tests passed from `/tmp` with an absolute Maven project path. Python and Node fixture locations resolve relative to source files, and the root runner changes to its own repository root.

Runtime versions actually exercised: Python 3.11.15, cryptography 50.0.2, FastAPI 0.150.0, Starlette 1.9.0, Django 5.2.18, Flask 3.1.3, asgiref 3.12.1, redis-py 8.1.0; Node 22.23.2, Express 5.3.0, Fastify 5.12.7, NestJS 12.2.0, node-redis 6.3.0; Temurin Java 17.0.20, Maven 3.10.0, Spring Boot 3.5.16, Spring Framework 6.2.19, Spring Security 6.5.11, Tomcat 10.1.55, Spring Data Redis 3.5.13, Lettuce 6.6.0.RELEASE; Redis 7.2.10.

Final locally tested artifacts (SHA-256; ignored build outputs, not published):

| Artifact | SHA-256 |
| --- | --- |
| `appguard_server-0.1.0.dev0-py3-none-any.whl` | `77ad37a87833a707ff980963880c8ebc193a219d9442e49c26e1e22892ab9e17` |
| `appguard-server-0.0.0-experimental.0.tgz` | `feff5855e1e42fe15557c07d48d1249004cc3e5b4617d976a2a39e16b5ed15a1` |
| `appguard-spring-boot-starter-0.1.0-SNAPSHOT.jar` | `8fc03bb1e3a4cf0ba91986b6d9bc4e2af1dd9de78741a68d80e2e96ef518f2d5` |

Python review fixes are committed in `b3ee191`; the servlet async fix is in `acc9c07`. After both changes the parent reran the complete root command and the isolated wheel/JDK-only/JAR-backed Boot smoke checks. The SDK branch and worktree are preserved for review; only the earlier foundation has been merged into local `main`.

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

## Whole-change review rulings

A fresh read-only security review of `1725f89..208be32` assessed the supported verifier, adapter and replay paths. It found no critical issues, two important body-preservation defects (Flask requests without Content-Length and servlet no-argument asynchronous body access), plus two minor issues: WSGI header-alias ambiguity and inconsistent Python Redis nonce validation. All four were treated as implementation defects and fixed with observed RED/GREEN regressions; the reviewer read back their fixes and found no remaining issue in that bounded readback.

Flask marks only verified, buffered WSGI input as terminated and rejects WSGI header aliases before authentication/nonce consumption. Python Redis validates canonical nonce scopes before contacting Redis. The servlet wrapper retains its response and supplies itself to no-argument async startup, while preserving explicit caller-supplied wrapper semantics. Two actual Tomcat tests read bodies through `AsyncContext.getRequest()` before redispatch and verify unchanged content, retained wrappers and exactly one nonce claim.

The executor accepted the review's eight explicit exclusions with these boundaries and costs:

1. Application authentication, authorization, enrollment, revocation propagation and provider attestation: the SDK binds an already authenticated identity and trusted key. Applications must supply correct services and permission checks; this stage cannot certify them.
2. ASGI scheme/method/raw path/query/exact-target evidence and proxy rewrites: trusted server metadata is a precondition. Python needs server-specific capture for empty query strings; in-process tests provide no live ASGI-server/TLS proof.
3. Upstream parser/container/proxy normalization, stripped optional whitespace, malformed framing rejected before capture and programmable servlet valves: lost wire evidence cannot be recovered. Deployment topology must be tested separately.
4. Parsers/body consumers/rewriters installed before the guard, or arbitrary in-process mutation of captured evidence: those placements violate the integration contract. An exhausted servlet stream with no Content-Length cannot always reveal whether an earlier consumer removed a body; install the guard before consumers rather than infer missing bytes.
5. Production Redis persistence/failover/eviction/capacity/security and client timeouts or hung caller callbacks: tests cover atomic claims and failure responses, not deployment configuration. Operators must configure retention, resource limits and backend/callback deadlines; Python cannot forcibly stop a synchronous callback already running in a worker thread.
6. Untested protocol/framework versions, HTTP/2, Node upgrade/WebSocket/CONNECT handlers outside middleware, servlet form/multipart/nonblocking input and unusual native stream internals: these are outside tested adapter support. Protect those surfaces separately; HTTP middleware does not secure unrelated socket handlers.
7. Trusted internal forward/include/async dispatch and work after initial verification: a successful external request is verified once, with one trusted clock sample, and trusted internal dispatches preserve its proof/body. This does not re-sign internal destinations or continuously re-evaluate freshness while application/store work proceeds; endpoint authorization remains required.
8. Physical-device/client SDK/store/provider/deployment proof or production certification: none is asserted. The completed evidence concerns local server SDKs and test services only.
