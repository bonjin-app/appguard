# Non-device production qualification

This stage implements software and local operating checks that do not require a
physical device or an enrolled provider account. It does not certify AppGuard as
audited, production supported, released, or qualified for a particular deployment.
The [readiness design](../superpowers/specs/2026-10-22-nondevice-production-readiness-design.md)
and [execution checklist](../superpowers/plans/2026-10-22-nondevice-production-readiness.md)
define the bounded stage. Historical verification documents retain their original
counts and exclusions; the links below describe the new optional implementations.

## Implemented integrations

| Integration | Explicit operating boundary |
| --- | --- |
| Python, Node, Java, Go, .NET and PHP Redis replay stores | Caller-configured clients, common hashed namespace, atomic SET NX EX, no local fallback; deployment owns retention, persistence, replication, eviction, credentials and finite transport timeouts |
| [Apple initial metadata and assertion state](../security/apple-lifecycle.md) | Pinned initial trust profile, strict signed request binding, persistent one-use challenges and monotonic counters; host-local dedicated SQLite, no device/account proof |
| [Apple CMS receipts and refresh](../security/apple-receipts.md) | Independent pinned G3 receipt trust, bounded CMS/BER, app/key/environment/client-hash/time binding, explicit JWT callback, fixed provider hosts; no current live Apple exchange |
| [Atomic Apple enrollment](../security/apple-enrollment.md) | One dedicated database transaction activates request key, Apple key, link and verified receipt; persistent refresh CAS and synchronized revocation; no implicit database migration |
| [Google OAuth provider](../security/google-provider.md) | Explicit service-account email/RSA PEM, fixed scope/endpoint/claims, conservative clock cache and bounded waiters; no credential discovery or live Google exchange |
| [Python direct TLS ingress](../deployment/python-ingress.md) | `IngressServer(config).run()`, pinned Uvicorn/h11, raw TCP admission before TLS, original target/header evidence, real validated local TLS; host authentication and resource authorization remain explicit |
| [Release candidate preparation](release-readiness.md) | Clean committed source, checksums, inventory, SBOM, vulnerability/secret scans and pending license review; unpublished source only |

Spring Boot defaults to Boot4.1.1, Java17, Jackson2.21.8/Jackson3.1.8 and
Netty4.2.19.Final. The explicit `legacy-boot3.5` source-test profile is not the
maintained production baseline. A fresh actual37-JAR runtime graph scan reported
zero vulnerabilities after fixing the earlier14 findings. Scanner/database
results are point-in-time evidence, not proof of absence of vulnerabilities.
The consumer's container, optional integrations and resolved application graph
require their own scan and tests.

## Reproducible server verification

First create a **new disposable Redis** bound to127.0.0.1 with an unused explicit
port and database0..15. Do not supply an existing shared instance. These runners
use scoped synthetic keys and delete only their own keys. Redis fault injection
below uses a different process created by the qualification runner itself.

```sh
export APPGUARD_TEST_REDIS_URL=redis://127.0.0.1:DISPOSABLE_PORT/0
bash scripts/test-server-sdks.sh
bash scripts/test-extended-server-sdks.sh
# PHP must have the optional phpredis6.3.0 extension available without php.ini.
# If it is shared, select exactly its readable absolute file:
export APPGUARD_PHP_REDIS_EXTENSION=/absolute/php/extensions/redis.so
uv run --frozen --project sdk/python python scripts/check_cross_sdk_replay.py --extended
python3 sdk/php/tests/redis_integration.py php -n -d "extension=$APPGUARD_PHP_REDIS_EXTENSION"
```

The cross-SDK runner rotates the first claim through every language, verifies
all other SDKs reject it, checks shared retention, and races independent SDK
processes for exactly one winner. Without `--extended` the existing core runner
retains its Python/Node/Java mode; `--extended-only` checks Python/Go/.NET/PHP for
the separate hosted job. Runtime overrides are single executable paths, never
shell expressions: `APPGUARD_UV_CMD`, `APPGUARD_MAVEN_CMD`, `APPGUARD_GO_CMD`,
`APPGUARD_DOTNET`, `APPGUARD_PHP_CMD`, and a readable `APPGUARD_COMPOSER_PHAR`.
Use fixed lockfiles. No tools, registries or accounts are configured automatically.

PHP hosts must explicitly enable `Redis::OPT_REPLY_LITERAL` before constructing
`ExtRedisCommandClient`. The bridge rechecks it on every operation and accepts
only the exact `OK` status; default boolean status coercion cannot distinguish
`OK` from a server-side queued transaction. It never changes client options.

On packaged PHP builds, Redis may require installed `igbinary`/`msgpack` modules
even though raw replay commands do not use serializers. The hosted job loads
those fixed optional module files before Redis, keeps `-n`, verifies Redis6.3.0,
and passes individual validated module paths to the cross-language runner.

The .NET runner disables development-certificate generation and telemetry, uses
an isolated CLI home, and does not alter the user's certificates. PHP SDK tests
run with `-n`; only the selected optional Redis extension is loaded for its live
suite. Go uses the locally selected toolchain and readonly module resolution.

## Owned Redis fault, recovery and load checks

Build or select a trusted local Redis7.2.10 binary. The hosted workflow verifies
the official source archive SHA-256 before compiling it. The following command
accepts a binary path, **not a Redis URL**:

```sh
uv sync --locked --project sdk/python
export APPGUARD_REDIS_SERVER=/absolute/path/to/redis-server
uv run --frozen --project sdk/python python scripts/qualification/replay_resilience.py \
  --iterations 1000 --concurrency 16
uv run --frozen --project sdk/python python -m pytest \
  .github/tests/test_replay_qualification.py .github/tests/test_adversarial_qualification.py -q
uv run --frozen --project sdk/python python scripts/qualification/adversarial_profile.py \
  --iterations 10000 --seed 20261022
```

Before Redis configuration mutation or forced termination, the runner verifies
its own child PID, Redis run ID and exclusive temporary state directory. It
uses `appendonly=yes`, `appendfsync=always`, and `maxmemory-policy=noeviction`.
It checks acknowledged nonce retention after SIGKILL/restart, outage denial,
capacity rejection, one concurrent winner, stalled socket timeout, and removal
of its temporary state. It signals only the process it created. It never scans
for an existing Redis instance, accepts a remote target, flushes a database or
changes a user's server.

The initial local run completed1000 unique claims plus1000 replays with16 workers,
zero failures, and all6 operating scenarios passing. Observed throughput was
3317operations/s; p50/p95/p99 were4.76/8.75/12.23ms, maximum47.68ms. These are a
single local measurement, not a capacity promise or service-level objective.
Process crash plus acknowledged fsync configuration does not certify physical
power loss, disk loss, replica failover, eviction under another configuration,
cloud-service guarantees, or restored stale snapshots.

The seeded adversarial run exercised10000 core and10000 HTTP-wire known-invalid
mutations, with zero unexpected acceptance and zero nonce claims from rejected
inputs. It also verifies a known-valid baseline before negatives. This is a
reproducible regression harness for enumerated invalid classes, not coverage-guided
fuzzing, all-SDK fuzz coverage, or a cryptographic/security audit.

## Deployment and recovery responsibilities

Use the shared replay backend for all replicas accepting the same keys. Reserve
capacity for the entire acceptance window; disallow live-key eviction and define
persistence/replication guarantees before serving traffic. Ambiguous Redis errors
may have consumed a nonce: fail closed, generate a new signed request when policy
permits, and use separate business idempotency. Never undo a claim to retry a
state-changing business operation.

Protect the dedicated Apple database and containing directory. Back up counters,
challenges, key tombstones, links and receipts together. Restoring an older backup
can roll back monotonic counters and revocations; local checks cannot detect all
stale but internally valid snapshots. Revoke/re-enroll affected keys under an
explicit recovery plan rather than claiming continuity or resetting counters.
Read back state after an ambiguous post-commit failure. No automatic migration
or merge of existing enrollment/assertion stores is provided.

Configure real identity/token validation, resource permissions, clock monitoring,
TLS termination/proxy policy, provider credentials/quotas, bounded host callbacks,
rate limiting and operational alerting. An assertion, local risk hint or receipt
risk metric does not authorize a business operation. Authentication providers,
fraud thresholds, customer-data retention and incident response remain deployment
policy, not inferred SDK defaults.

## Known upstream development-tool advisories

Expanded npm development-dependency coverage detects two upstream HIGH findings
in Expo build tooling, `braces` and `node-forge`, for which no fixed upstream
release was available at this check. The UUID finding was removed through the
compatible config-plugins58.0.10/xcode4 update. See [advisories, dependency paths
and limits](../security/dependency-advisories-2026-10-22.md). The vulnerable build
tools are not bundled in AppGuard's npm package. They remain visible in the
complete recorded npm source graph; the release security gate intentionally
fails until remediated. Passing SDK tests does not override this gate.

## Release gates still separate

Automated results do not establish a complete native consumer dependency graph,
license compliance, external independent audit, provider/account interoperability,
operator deployment qualification, support SLA or maintainer release approval.
The generated license/notice inventory deliberately remains pending review and
`release_ready` remains false. No SDK registry release or security certification
is performed by this stage. Physical Android and iPhone checks remain pending;
the separate Unity physical-device candidate is excluded from this integration.

## Internal independent review

Separate reviewers exercised code written by other workers. Reproductions were
converted into regressions and fixes for receipt expiry across credential callbacks,
extra ASN.1 fields, enrollment clock rollback/schema constraints, raw TCP admission
before TLS, mutable TLS/ALPN policy, configuration/error redaction, PHP queued-status
coercion, late .NET cancellation fault redaction, Git replacement-object provenance, source mutation during scanning, and
secret-failure artifact publication. This is internal review evidence; it is not
an external independent security audit. See the per-integration tests and guides
for the precise supported contracts.
