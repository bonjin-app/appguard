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

API syntax targets PHP 8.2+ on 64-bit runtimes; execution here proves PHP 8.5.11 only. No Laravel, Symfony, PSR-7/15, FPM, Apache, Linux, Windows or distributed replay deployment was run. The native callback adapter requires operator-supplied trusted pre-normalization evidence. Ordinary normalized front controllers cannot supply that proof and must fail closed. Local replay state is bounded, volatile and confined to one interpreter; PHP-FPM request/worker separation, restarts and multiple hosts require an explicit atomic shared implementation. No Redis adapter, distributed-lock or backend durability guarantee is claimed.
