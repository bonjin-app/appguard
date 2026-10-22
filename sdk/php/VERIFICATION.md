# PHP server SDK verification

Point-in-time local evidence: 2026-10-20, macOS arm64. Local and unpublished. No accounts, external deployment, shared replay backend, physical device, store or provider state was exercised.

## Runtime provenance

- PHP **8.5.11**, NTS, 64-bit, Zend Engine/OPcache 8.5.11, built task-locally at `.tools/sapi/cli/php` from [official PHP source](https://www.php.net/downloads.php). Source tar.xz SHA-256: `d9be75c08e8c316f4c8f4194d8fbe1750a15f6a6d9d4e3fe72082abeeb800360`, compared with the official published checksum before extraction.
- Static OpenSSL **3.5.5 27 Jan 2026** uses already-installed headers/libraries in the existing local Ruby runtime. No global installation or config mutation. The first link exposed a missing zlib flag; relinking with existing `-lresolv -lssl -lcrypto -lz` succeeded. The optional `tools/bootstrap-local.sh` includes explicit `ZLIB_LIBS=-lz` for subsequent source builds.
- Composer **2.10.3**, downloaded from [official Composer](https://getcomposer.org/download/). PHAR SHA-256 `7a2d379d5b8ffdaa028580ef26494c36d2feef4b178d3dd1473a4dbc5e17c8d6` matched the official checksum.
- All PHP commands used `-n`. `php --ini` confirmed **no loaded php.ini and no scanned ini files**. Key-generation tests use a committed test-only OpenSSL configuration, because the reused static library's build-time default config path is absent. Verification imports public keys and does not need that generation config.
- Executed extensions: Core, date, openssl, pcre, zlib, ctype, filter, hash, json, lexbor, mbstring, Zend OPcache, uri, SPL, standard, random, Reflection, tokenizer, Phar. Only OpenSSL/hash/JSON are SDK requirements. PHP curl is absent; Composer emitted its expected performance warning and completed installation.

## Executed verification

Commands below run from `sdk/php`. Composer used task-local `COMPOSER_HOME` and `COMPOSER_CACHE_DIR`, `COMPOSER_DISABLE_NETWORK=1`, plugins disabled and no install scripts. No user Composer settings/plugins were loaded.

| Check | Result |
| --- | --- |
| `.tools/sapi/cli/php -n tests/run-all.php` | **PASS**: 40 request, 43 wire and 42 policy vectors; 514 assertions; 5 loopback HTTP requests |
| `.tools/sapi/cli/php -n .tools/composer.phar validate --strict` | **PASS**: manifest and generated lock valid |
| Composer `update --no-interaction --no-plugins --no-scripts --no-audit` | **PASS**: generated lock, zero external package dependencies |
| Composer `install --no-interaction --no-plugins --no-scripts` | **PASS**: frozen lock/platform verification and autoload generation |
| Composer `test` | **PASS**: same full suite through the package script |
| Isolated Composer consumer | **PASS**: copied package source/manifest/license into a separate task-local path package, installed by Composer with `symlink: false` and all remote repositories disabled; consumer verified a signed public fixture through its own generated autoloader |
| Public fixture consumer | **PASS**: core/wire agreement, signature acceptance, replay, body/target/token mutation rejection through public APIs |
| `sh -n tools/bootstrap-local.sh` and PHP source syntax lint | **PASS** |

Security tests include independently generated OpenSSL signatures, binary body/explicit empty-query preservation, strict raw64 and minimal DER scalar/range checks, compressed/uncompressed named P-256 SPKI, wrong curves/revocation/expiry/malformed PEM, strict scalar types and bounds, identity binding, replay result-type errors/capacity/expiry/single winner, missing raw evidence, default secure transport, authentication/key/clock failures, downstream isolation, immutable copied references, policy defaults and Basic opt-out, constructor-bypass semantic revalidation, and audit field allowlisting/failure redaction.

The actual loopback PHP ingress harness reads the request target and duplicate header lines before normalization, keeps a long-lived explicit replay store, and invokes `HttpAdapter`. Five requests prove preserved captured body/application identity, replay rejection, duplicate-Authorization rejection, absent-evidence rejection and body tamper rejection. Transport is loopback with explicit insecure opt-in; this is not TLS termination or framework/container deployment proof.

Tests were authored before implementation and the initial missing SDK API assertion failed. Once the official runtime was available, targeted regression runs also demonstrated valid compressed P-256 SPKI rejection and a constructor-bypassed invalid policy incorrectly returning `ALLOWED`; both were corrected. A separate RED regression confirmed direct callback replay claims needed scope/result validation; that wrapper now rejects malformed calls and backend results with redacted errors. The final full suite passed. Ignored logs are in `.evidence/`.

## Native public fixture command

The parent integration task may independently generate Android/Apple public fixtures and run:

```sh
.tools/sapi/cli/php -n tools/verify-client.php < /absolute/path/public-fixture.json
```

Input is one conformance-shaped JSON object or an array of 1..100 objects, at most 2 MiB, containing public keys and signed requests only. The tool checks wire/core agreement, verifies, rejects replay and body/target/Bearer mutations, and emits only a fixed success marker or `PUBLIC_FIXTURE_FAILED`. It is a test-only command excluded from runtime autoloading. This PHP task's consumer smoke used a public conformance fixture; independent mobile probe results are recorded by the parent task.

## Limits and unverified deployments

API syntax targets PHP 8.2+ on 64-bit runtimes; execution here proves PHP 8.5.11 only. No Laravel, Symfony, PSR-7/15, FPM, Apache, Linux, Windows or distributed replay deployment was run. The native callback adapter requires operator-supplied trusted pre-normalization evidence. Ordinary normalized front controllers cannot supply that proof and must fail closed. Local replay state is bounded, volatile and confined to one interpreter; PHP-FPM request/worker separation, restarts and multiple hosts require an explicit atomic shared implementation. The optional Redis adapter now has separate live evidence below; backend durability and deployment guarantees remain unverified.


Parent integration completed: fresh Android1+Apple8 public fixtures verified with replay/body/target/token mutations rejected; full extended runner passed. One fresh whole-stage review and exact remaining/deferred limits are recorded in [extended verification](../../docs/security/extended-server-verification.md).


## Optional Redis adapter verification (2026-10-22)

Fresh PHP 8.5.11 checks passed: **647 assertions** and the existing **5 raw loopback HTTP requests**. New interface tests exercise exact canonical SET arguments, 1/150-second boundaries, conflict, invalid scope/nonce/time, strict response types and exception redaction. Interface test doubles do not establish phpredis transport behavior.

Actual **phpredis 6.3.0** was downloaded from the [official PECL release](https://pecl.php.net/package/redis/6.3.0), SHA-256 `0d5141f634bd1db6c1ddcda053d25ecf2c4fc1c395430d534fd3f8d51dd7f0b5`. The task-local `.tools/redis-build/redis-6.3.0/redis.so` was built using clang's bundle/dynamic-lookup mode and the existing PHP 8.5.11 generated headers (read only); its source list matches release `config.m4`, with optional serializers/compression/session disabled. No global installation, existing toolchain changes or php.ini were used. Ignored build command/log are beside the module. This is a local test build, not a packaged extension distribution.

With `-n -d extension=/absolute/path/redis.so`, the actual live harness passed against the parent-owned disposable loopback Redis DB3: eight separate PHP processes/connections started behind a barrier and produced exactly one winner; another connection rejected replay and read the canonical key/value/TTL; a one-second claim expired; literal replies and host prefix/serializer bypass were checked; pipeline, Redis error replies and unconnected-client calls failed closed. Only this run's random scoped keys were deleted. No Redis FLUSH or configuration commands were issued. This proves local phpredis/Redis behavior, not TLS/authentication/failover/replication/eviction durability or FPM/framework deployment.

CI must install `ext-redis` and run both the normal no-extension suite and explicit live probe:

```sh
php -n tests/run-all.php
# Set APPGUARD_TEST_REDIS_URL to the CI-owned disposable service.
python3 tests/redis_integration.py php -n -d extension=/absolute/path/redis.so
```

Resolve the installed extension's absolute path in CI before using `-n`; do not depend on loading a global php.ini. Preserve isolated Composer home/cache, disabled plugins/scripts and frozen-lock consumer checks.

The isolated Composer consumer also passed with remote repositories disabled, mirrored package source (`symlink: false`), a frozen-lock install, no Redis extension, and generated-autoloader use of `RedisCommandClient`/`RedisReplayStore`. Composer strict validation passed; the optional extension suggestion changes no runtime dependency or lock content.

### Strict literal status correction (2026-10-22)

Independent review reproduced a queued-claim failure with the actual phpredis
6.3.0 runtime: `rawCommand('MULTI')` left `getMode()` reporting `Redis::ATOMIC`,
and default status coercion mapped the server's `QUEUED` reply to boolean `true`.
The adapter reported success despite the transaction being discarded and no
replay key being stored. Local transaction mode alone was insufficient.

The bridge now requires the host to set `Redis::OPT_REPLY_LITERAL=true`, checks
its exact enabled value before every command, and accepts only literal `'OK'`.
It does not set or restore host options. Default nonliteral mode fails before
sending a claim; a raw-MULTI queued response fails closed. The executable live
and cross-language probes explicitly configure literal mode in their host code.

Fresh checks after correction passed: **649 SDK assertions**, **61 status cases**
within that suite, and **5 raw loopback HTTP requests**. The actual ext-redis live
harness passed against the parent-owned disposable loopback Redis DB5, covering
the eight-process race, canonical key/value/TTL, expiry, prefix/serializer bypass,
nonliteral mode rejection without mutation, raw-MULTI/QUEUED rejection with no
committed claim, normal pipeline rejection, provider error and unavailable
client. Unit tests also reject boolean success and `QUEUED` from custom clients.
Only fresh UUID-scoped test keys were removed, with no Redis configuration or
shared database cleanup. These remain local software/owned-Redis results; no
hosted durability, TLS, production account or deployment guarantee is implied.
