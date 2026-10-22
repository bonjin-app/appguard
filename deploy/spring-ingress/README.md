# Constrained Spring mTLS container profile

This Compose profile packages the existing Python TLS ingress, the actual
Maven-built Spring starter/backend and Redis. It targets Linux amd64 and arm64.
Only gateway TCP 8443 is published, on host 127.0.0.1 by default. The backend fixes
its listener to 127.0.0.1:8444; Redis binds 127.0.0.1:6379. Both use
`network_mode: service:gateway`, preserving their loopback transport boundary.
The frontend is HTTP/1.1 TLS and the backend requires the dedicated ingress
client certificate. Docker daemon access remains an operator trust boundary.

## Build inputs

Run Compose from this checkout with its explicit file path. Build contexts are
repository-relative. Dockerfile-specific `.dockerignore` files omit local
builds, caches, environments, keys and certificates without excluding an entire
SDK tree. No secret is supplied as a build argument or copied into an image.

[base-images.json](base-images.json) records the official registry index digests
and their amd64/arm64 child manifests. The backend runtime row was reviewed on
2026-10-23; the unchanged Python, Maven and Redis rows retain their 2026-10-22
review. The exact registry response bytes and `Docker-Content-Digest` header
matched each SHA-256. These
immutable pins identify content; they do not certify vulnerability status.
The current pins use Python 3.11.17 and Redis 7.2.16. The Maven 3.9.16
builder and Temurin 17 JRE both declare `jdk-17.0.20.1+1` on amd64 and arm64
in their hash-bound OCI configuration metadata. Runtime execution and image
vulnerability checks remain separate verification steps.
The gateway uses Alpine 3.24 (musl); the backend uses the official
`17.0.20.1_1-jre-resolute` image based on Ubuntu 26.04 Resolute.
Ubuntu documents [generic amd64 and arm64 architecture baselines](https://ubuntu.com/project/docs/how-ubuntu-is-made/concepts/supported-architectures/#architecture-baselines)
without optional CPU extensions; `amd64v3` is a separate opt-in variant.
The backend keeps the same Java release and vendor JRE archive hashes recorded
in the pinned Adoptium Dockerfiles for
[Resolute](https://raw.githubusercontent.com/adoptium/containers/511f9356dc4d50932a0a5f8cfb0f87ed1aef4f07/17/jre/ubuntu/resolute/Dockerfile)
and [Noble](https://raw.githubusercontent.com/adoptium/containers/511f9356dc4d50932a0a5f8cfb0f87ed1aef4f07/17/jre/ubuntu/noble/Dockerfile).
The recorded arm64 manifest and declared Java version identify build inputs;
they do not establish ARM execution evidence. The changed runtime requires fresh
Docker qualification and exact-image scans. OS/dpkg and JAR metadata remain
intact; no package deletion or scan suppression is used. This baseline change
does not establish zero vulnerabilities, reduced image size, native dependency
closure or production readiness.
Upstream sources are the official [Python](https://hub.docker.com/_/python),
[Maven](https://hub.docker.com/_/maven),
[Temurin](https://hub.docker.com/_/eclipse-temurin) and
[Redis](https://hub.docker.com/_/redis) images.

The gateway installs hash-pinned uv 0.13.4 from official PyPI wheels and runs
`uv sync --locked --no-build --no-dev --extra server --extra redis --no-install-project`.
It copies the SDK source separately into the final image, avoiding an unlocked
isolated build backend. Runtime dependencies come from `sdk/python/uv.lock`;
development dependencies, uv and its build cache are absent from the final stage.
The final gateway also uninstalls unused global pip, setuptools and wheel, and
removes ensurepip including its bundled installer wheels. Build-stage pip is
retained to install pinned uv. The copied production virtual environment keeps
all package code and distribution metadata; a build-time inventory comparison
and runtime readback require its package versions to remain intact.
The gateway keeps the SDK's required h11/uvicorn versions. Maven builds both
JARs from source and copies the actual resolved runtime JARs into a Java 17 JRE
image. Image builds skip Java tests; the regular SDK/qualification suites must
pass separately. Maven POMs use fixed versions; reproducible here means recorded
inputs and build steps, not a claim of byte-identical JAR/image builds.

The explicit `3.11.17-alpine3.24` Python tag is pinned to its reviewed index;
Alpine 3.24 is a [maintained upstream release](https://alpinelinux.org/releases/).
Every locked production dependency has a compatible pure-Python or musl wheel
for amd64 and arm64, including cryptography and cffi. The uv requirements include
the [official PyPI](https://pypi.org/pypi/uv/0.13.4/json) musl x86_64 wheel hash;
the existing aarch64 wheel supports both libc variants. `--no-build` rejects a
source-build fallback. These checks establish available inputs; actual image
execution and an exact-image vulnerability scan are still required.

## Explicit operator inputs

Supply an operator-owned private environment file outside the checkout, then
pass it with `--env-file`. Its values are interpolation inputs; the PKCS12
password itself is read inside the backend from its mounted file. The two
PKCS12 files use that same password. Each file path must be absolute and point
to an existing regular file readable by the configured non-root UID. Keep
private key/password files owner-readable only. This profile installs no
certificates into operating-system trust stores.

| Environment variable | File or value |
| --- | --- |
| `APPGUARD_OWNER` | New opaque owner token for this deployment |
| `APPGUARD_IMAGE_TAG` | New local image tag |
| `APPGUARD_UID`, `APPGUARD_GID` | Gateway/backend file owner, defaults 10001:10001 |
| `APPGUARD_FRONTEND_CERT_FILE`, `APPGUARD_FRONTEND_KEY_FILE` | Frontend server leaf certificate/key PEM |
| `APPGUARD_SERVER_CA_FILE` | CA PEM used to verify the backend server |
| `APPGUARD_INGRESS_CERT_FILE`, `APPGUARD_INGRESS_KEY_FILE` | Dedicated ingress client leaf certificate/key PEM |
| `APPGUARD_BACKEND_KEYSTORE_FILE` | Backend server certificate/key PKCS12 |
| `APPGUARD_BACKEND_TRUSTSTORE_FILE` | Dedicated trusted ingress-client CA PKCS12 |
| `APPGUARD_BACKEND_PASSWORD_FILE` | Password for both PKCS12 files |
| `APPGUARD_ENROLLED_KEY_FILE` | Enrolled P-256 SPKI public key PEM |
| `APPGUARD_BACKEND_HOSTNAME` | Exact backend certificate DNS name |
| `APPGUARD_ORIGIN`, `APPGUARD_APP_ID` | Exact external HTTPS origin and application identifier |
| `APPGUARD_SUBJECT`, `APPGUARD_KEY_ID` | Explicit enrolled subject/key identifier |
| `APPGUARD_BEARER_SHA256` | SHA-256 of the high entropy example bearer token |

The gateway receives only its frontend leaf/key, backend CA and ingress
client leaf/key. The backend receives only its server keystore, client CA
truststore, password file and enrolled public key. All those mounts are
read-only. Redis receives no application certificate or key. Replace the
example's static identity integration with your application's identity lifecycle
before production use; see the [deployment contract](../../docs/deployment/spring-ingress.md).

```sh
# Use a unique project name and the same private environment file for each call.
docker --context default compose --env-file /absolute/private/operator.env \
  --project-name appguard-spring-operator-unique-id \
  --file deploy/spring-ingress/compose.json config --quiet
docker --context default compose --env-file /absolute/private/operator.env \
  --project-name appguard-spring-operator-unique-id \
  --file deploy/spring-ingress/compose.json build --builder default --pull
docker --context default compose --env-file /absolute/private/operator.env \
  --project-name appguard-spring-operator-unique-id \
  --file deploy/spring-ingress/compose.json up --detach --no-build
```

Choose a trusted local Docker context and its built-in `docker` builder. The
qualifier enforces both selections before sending source to a builder; it does
not change the active Docker context or builder. Compose 2 and BuildKit with
Dockerfile-specific ignore support are required. The default publication is
127.0.0.1:8443; `APPGUARD_PUBLISHED_PORT=0` requests an ephemeral host port.
Changing the gateway container recreates the network namespace, so upgrade the
gateway/backend/Redis deployment together. Never publish 8444 or 6379.

## Operating limits and replay persistence

Every service has a read-only root, all capabilities dropped,
`no-new-privileges`, a private IPC namespace, bounded noexec/nosuid/nodev `/tmp`
and bounded memory, swap, PIDs, file descriptors, CPU and log rotation. Defaults
use Docker's `local` log driver with one file capped at 1 MiB per service,
including the qualification probe. Rotated-file compression is explicitly
disabled with the string option `"compress": "false"`, because the local driver
rejects compression when only one file is retained. See the
[local driver options](https://docs.docker.com/engine/logging/drivers/local/#options).
Resource defaults
are 256 MiB / 64 PIDs / 1 CPU for the gateway, 512 MiB / 128 PIDs / 1 CPU for the backend and
128 MiB / 32 PIDs / 0.5 CPU for Redis. Tune and requalify for the actual workload.
These configured limits are separate from measured production resource usage.

Redis always runs as 10001:10001. Its Dockerfile sets `/data` ownership and 0700
permissions at build time; the new named volume inherits that ownership without
a root runtime init container. AOF is enabled with `appendfsync always`, no
snapshot timer, a 64 MiB key-memory limit and `noeviction`. Replay state survives
a routine Redis container stop/start while the named volume is preserved.
Disk capacity, disk failures, power loss, backups, AOF corruption and distributed
failover require separate operator testing. Do not delete or restore an older
replay volume during the live nonce window. A full Redis memory budget denies
new claims instead of evicting existing nonces.

The production profile retains its named volume. The qualifier uses a fresh,
labelled, disposable named volume and deletes only that owned fixture after its
retention probes. Application keys and request data never enter a retained test
receipt.

## Run owned container qualification

Use a new canonical output path outside the checkout, a non-root host user,
a trusted local Unix-socket Docker daemon and Java 17 `keytool` on the host.
No existing service, Redis URL or operator certificate is used.

```sh
uv run --frozen --project sdk/python python scripts/qualification/spring_containers.py \
  --docker-context default --java-home "$JAVA_HOME" \
  --output /absolute/new/appguard-spring-containers
```

For sustained synthetic traffic under the same configured container limits,
add `--soak-seconds 1800 --soak-concurrency 8`. Duration accepts 0 (disabled,
the CLI default) or 1–3600 seconds; concurrency accepts 1–32. A disabled soak
does not establish sustained operating behavior. Normal push/PR CI enables a
30-second, eight-worker check. Manual `Container deployment readiness` runs
default to 1800 seconds and eight workers and reject disabled or invalid input.
Keep the reviewed ref unchanged during a manual run: a later run on that ref
can cancel an in-progress qualification.

The optional operating evidence uses actual signed requests and exact replay
denials, with strict zero-error checks. Resource observations come from the
owned running containers rather than host JVM RSS. Linux cgroup v2 evidence
is required for this mode, including numeric-zero `memory.swap.max` and
`memory.swap.current` readbacks for the no-swap profile. Missing, unlimited or
nonzero swap evidence fails this qualification. The kernel exposes swap as a
[separate memory interface](https://docs.kernel.org/admin-guide/cgroup-v2.html#memory-interface-files),
and Docker documents that [swap limiting requires kernel support](https://docs.docker.com/engine/containers/resource_constraints/).
Sampled resource peaks are not continuous maxima,
memory-leak analysis or production capacity/SLA evidence. Container identity,
image, configured restrictions, OOM/restart state and source provenance must
remain valid; a failed sampler, traffic worker or cleanup cannot become a pass.
Credentials and raw traffic stay in the temporary private fixture, and only
bounded results are retained. The existing Redis outage/AOF restart checks
remain separate from sustained healthy traffic; this mode does not prove
power-loss durability or service availability during an induced outage.

The runner creates one random Compose project, ephemeral CAs and leaf keys.
It builds three local images, inspects actual runtime resource/UID/capability/
mount/rootfs/port restrictions and verifies shared network namespace identity.
Within the existing effective-restrictions check, it reads back Python 3.11.17,
Java 17.0.20.1 and Redis 7.2.16 from the running binaries, confirms the global
Python installers are absent and compares the production Python environment
against its build inventory. Only validated fixed versions and booleans are
retained in the receipt's `runtime_versions` field.
It exercises signed raw-target/body fidelity, replay rejection, owned Redis
outage denial/recovery and retention of the original nonce after restart. A
separate same-namespace probe has only the server CA and an untrusted client
leaf/key; plaintext, absent-client and wrong-client attempts must leave backend
HTTP dispatch counters unchanged. Malformed and incomplete/slow uploads must
also leave all backend counters unchanged.

Commands, output and request exchanges are bounded. Cleanup reinspects full
container IDs and ownership labels before each stop/removal, checks named
volume ownership and references, and reads back that owned containers, networks
and volumes are gone. SIGTERM unwinds through cleanup. SIGKILL, daemon failure
or host loss can prevent cleanup; those runs cannot supply a verified receipt.
There is no prune, registry upload, active-context switch or trust-store change.

Private certificates, inspect output and command output expire with the private
temporary directory. Only `receipt.json` is retained with mode 0600: fixed
checks, phase, counters, candidate/source hashes, immutable image IDs, limits,
cleanup status and explicit limitations. `technical_verification` requires the
entire probe sequence and cleanup to finish. `source_matches_commit` separately
records whether the checkout stayed clean. `release_ready` and
`external_approval` always remain false.

Owned images remain in the selected daemon for the subsequent image scan.
Use `containers.image_ids` from the receipt for the current image vulnerability
scan of discovered OS and supported language packages. This does not establish
native Redis/JVM binary dependency closure or complete image coverage.
Build-time Maven/uv inputs and external security/license review remain separate
coverage. A Linux amd64 CI
run does not prove arm64 runtime behavior; arm64 support also needs a run on
that architecture. The local macOS host used to author this profile had no
Docker CLI/daemon, so unit/static checks are not container execution evidence.
