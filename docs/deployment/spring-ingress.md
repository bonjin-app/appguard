# Spring behind a bounded TLS ingress

This runnable example qualifies one local HTTP/1.1 deployment topology. It does
not add an absolute timer to the blocking Servlet filter or qualify arbitrary
load balancers, cloud networks, HTTP/2, provider accounts or physical devices.

```text
TLS client → pinned AppGuard Python ingress → complete bounded body
           → fixed loopback mTLS connection → Spring authentication
           → AppGuard signature/replay verification → resource authorization
```

## Install and configure

Use Java17, Maven, Python3.11+ and the SDK's locked Python environment:

```sh
uv sync --locked --project sdk/python
mvn -B -ntp -f sdk/spring-boot/pom.xml install
mvn -B -ntp -f examples/spring-ingress/backend/pom.xml package \
  dependency:build-classpath -Dmdep.outputFile=target/runtime-classpath.txt
```

No package registry release exists. These commands build from this checkout.
The backend consumes the starter JAR, rather than loading its source directories.
Inspect the example POM for pinned Boot/container families; scan your own complete
resolved graph too. This example's graph is distinct from the starter-only graph.

Provision your own certificates outside the source tree. The frontend certificate
must match the external origin. The backend server certificate must match
`APPGUARD_BACKEND_HOSTNAME`. Use a dedicated CA for ingress-client certificates;
the backend truststore must not trust ordinary public web CAs for client access.
Protect private keys and restrict the service account and certificate rotation.
The qualification tool below generates temporary certificates only for its run;
it does not install certificates into the operating system trust store.

Set explicit environment values before starting the backend:

| Variable | Required value |
| --- | --- |
| `APPGUARD_BACKEND_PORT` | Unused loopback backend port |
| `APPGUARD_BACKEND_KEYSTORE`, `APPGUARD_BACKEND_KEYSTORE_PASSWORD` | Server PKCS12 and its password |
| `APPGUARD_BACKEND_TRUSTSTORE`, `APPGUARD_BACKEND_TRUSTSTORE_PASSWORD` | Dedicated ingress-client CA PKCS12 and its password |
| `APPGUARD_APP_ID`, `APPGUARD_ORIGIN` | App identifier and exact external HTTPS origin |
| `APPGUARD_SUBJECT`, `APPGUARD_KEY_ID`, `APPGUARD_PUBLIC_KEY_FILE` | Explicit enrolled identity and P-256 SPKI public key PEM |
| `APPGUARD_BEARER_SHA256` | Lowercase SHA-256 of a high-entropy bearer token |
| `APPGUARD_REDIS_URL` | Explicit dedicated replay Redis connection |

The static token/key enrollment demonstrates the host integration contract;
replace it with your actual identity and key lifecycle for an application.
The resource accepts only authorized `POST /v1/items` requests. A signature is
not a substitute for application permissions. Redis failures deny access and do
not fall back to process-local replay state.

Launch `io.appguard.example.BackendMain` with the built backend JAR and resolved
runtime JAR classpath. The backend fixes loopback binding, required client
certificates, HTTPS, disabled forwarded-header interpretation and HTTP/2.
It exposes no plaintext connector. Optional private counter output is only for
qualification and contains fixed integer counters, never request data.

The gateway requires these additional values:

| Variable | Required value |
| --- | --- |
| `APPGUARD_TLS_CERT`, `APPGUARD_TLS_KEY` | Frontend PEM certificate and private key |
| `APPGUARD_BACKEND_HOSTNAME`, `APPGUARD_BACKEND_CA` | Verified backend hostname and server CA PEM |
| `APPGUARD_BACKEND_CLIENT_CERT`, `APPGUARD_BACKEND_CLIENT_KEY` | Ingress-client PEM certificate and key |

```sh
uv run --frozen --project sdk/python python examples/spring-ingress/ingress.py
```

Optional `APPGUARD_LISTEN_HOST`/`APPGUARD_LISTEN_PORT` configure the frontend
listener. Body and backend budgets default to10s and5s; the ingress total budget
defaults to20s. Configure them with `APPGUARD_BODY_TIMEOUT`,
`APPGUARD_BACKEND_TIMEOUT`, and `APPGUARD_TOTAL_TIMEOUT`. Admission defaults to128
connections and64 in-flight tasks. Match budgets to the actual workload and test
overload recovery. Memory remains bounded by admission and one-megabyte request
and response caps; this example is not a general streaming proxy.

## Reproduce local qualification

Select a trusted Redis7.2.16 executable. The runner starts its own Redis, verifies
its child PID before using it, and stops only its owned processes. Use a new
canonical output directory; on macOS resolve `/private/var/...` rather than its
`/var/...` symlink alias.

```sh
uv run --frozen --project sdk/python python scripts/qualification/spring_ingress.py \
  --redis-server /absolute/path/to/redis-server --output /absolute/new/qualification
python3 scripts/qualification/scan_spring_runtime.py \
  --qualification /absolute/new/qualification --output /absolute/new/runtime-scan
```

The runtime scanner downloads checksum-pinned Syft/Trivy releases using the same
reviewed pins as the release tooling, preserves the raw SBOM, verifies every
exported JAR against its Maven coordinate and hash, and checks that Trivy consumed
every runtime identity. All severities remain enabled, with no ignore rules.
It scans the actual exported graph including the embedded container. It does not
scan the host OS, JVM or Python environment as a container image. Scanner results
depend on the vulnerability database at execution time. Raw logs/SBOMs remain
private; stdout is a fixed status with counts and opaque hashes.

## Trust and failure boundaries

No backend connection opens before the complete body arrives. Upload progress
does not restart the absolute budget. Exact method, raw target (including an
empty `?`, query duplicates and percent-encoding case), signed header values and
entity-body bytes reach Spring. Validated chunk framing is replaced by a single
Content-Length. The gateway does not authenticate or claim a replay nonce.

Backend connections use fixed loopback routing, CA and hostname verification,
and an ingress client certificate. There are no redirects, retries or connection
pooling. Request-controlled upstream URLs are not supported. Backend I/O and
close are bounded; failures return fixed public codes. An ambiguous failure may
follow a completed business operation: use separate business idempotency.

Direct connections without the client certificate must fail before HTTP
dispatch. A local process able to read the ingress key is trusted. Production
operators must separately verify firewall policy, process isolation, key access,
rate limits, Redis retention, identity lifecycle and their deployed ingress.
Successful local probes do not prove those external controls.

See the [local qualification and internal review record](../security/production-qualification-2026-10-22.md)
for test scope, findings resolved during development and remaining release gates.

## Sustained load and container deployment

Add `--soak-seconds 1800 --soak-concurrency 8` to the qualification command
for a 30-minute operating probe. The runner checks unique signed calls, exact
replay rejection, owned Redis outage/recovery, backend restart and bounded
admission pressure. See [production release criteria](../development/production-release.md)
for measured evidence and its limits. The process fixture uses nonpersistent
Redis and cannot prove replay retention across Redis data loss.

The example's Lettuce client reconnects after Redis returns, rejects commands
while disconnected, and caps its queue at 128. Reconnection does not restore
lost replay state. Never admit protected requests during a replay-store outage.

For pinned image builds, constrained runtime settings and a persistent owned
Redis volume, follow the [container installation guide](../../deploy/spring-ingress/README.md).
Its qualifier separately exercises ordinary Redis stop/start retention and
backend mTLS isolation. Actual operator deployment approval remains required.
