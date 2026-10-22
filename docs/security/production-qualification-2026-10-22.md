# Local Spring deployment qualification and readiness evidence

This phase qualifies a constrained local deployment and improves release
evidence handling. It does not certify AppGuard as an externally audited,
published or production-supported security platform. Physical-device work and
the separate Unity device candidate remain excluded.

## Implemented boundary

The [Spring deployment example](../deployment/spring-ingress.md) combines the
existing direct TLS ingress with bounded complete-body capture and a fixed mTLS
backend. Spring retains authentication, signature verification, one Redis replay
claim and resource authorization. It uses the packaged starter and a pinned
Tomcat11.0.27 consumer graph, distinct from the starter's37-JAR runtime scope.

Actual local socket probes passed all8 checks: signed binary/UTF-8/empty/chunked
body and raw query fidelity; replay rejection; missing/wrong client certificate,
plaintext and hostname bypass rejection; progressing/stopped upload deadlines;
malformed framing rejection; bounded backend failure; healthy recovery; and
owned-process cleanup. Direct authorized mTLS slow upload remains a control
showing why the ingress boundary is needed. These probes measure this topology,
not another operator's load balancer or network policy.

The exported graph contained69 runtime JARs and208 files including repository
metadata. The initial actual Syft/Trivy consumer scan covered all69 Maven
identities and reported zero vulnerabilities. This is point-in-time dependency
evidence, not proof that vulnerabilities are absent. The consumer scanner runs
the vulnerability scanner only; its secret-scan field remains unmeasured.
Source secrets and license inventories retain their separate release checks.

## Regression and review

The gateway's54 tests use actual validating TLS clients and a mandatory-mTLS
synthetic backend. The full Python suite passed1151 tests;3 optional live Redis
tests were skipped without their dedicated URL. The actual Spring qualifier
creates and verifies its own Redis child independently. The backend's7 focused
tests run during qualification packaging. Release tooling ran99 tests:96 passed
and3 optional real-Syft cases skipped; scanner/qualifier guard tests run separately.

Independent internal review identified and resolved incomplete export metadata
hashing, skipped backend tests, insufficient failed-qualification/backend-JAR
binding, report replacement during scan validation, mismatched receipt extension
fields, cancellation replaced by a connection-close error, and an incorrect zero
label for an unperformed secrets scan. Assessment
development also reproduced a file-replacement-to-FIFO race and rejected it
using nonblocking no-follow reads. Runtime inputs are pinned before execution
and rechecked after cleanup; dirty exploratory runs explicitly record that they
do not match a clean committed candidate. This is internal review, not external
security audit evidence.

## Explicit remaining gates

The [assessment command](../development/release-readiness.md#separate-readiness-assessment)
revalidates candidate and complete scan evidence. It treats local qualification
receipts as unverified references, never as release approval. Every v1 report
retains `release_ready:false`, with separate hosted/deployed validation, license,
independent audit and maintainer-approval gates. Mobile-attested scope additionally
requires provider-account evidence. A forged `approved:true` cannot pass a gate.

The two previously documented upstream HIGH development-tool advisories remain
visible blockers. No finding is suppressed, no package registry is published,
and no account, production environment or operating-system trust store changes
are performed. Exact-commit CI results and final local receipts must be read
separately; the historical local counts above do not imply hosted CI success.
