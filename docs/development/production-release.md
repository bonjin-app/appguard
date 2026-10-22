# Production release goal

The goal is a production release of the supported AppGuard components, with
physical devices explicitly excluded from this engineering effort. The goal is
not complete while required findings, operating evidence or approvals remain
unresolved. Passing an increment's tests does not complete this product goal.

## Required evidence

| Condition | How it is checked | Remaining authority |
| --- | --- | --- |
| Recorded source and runtime security | Candidate, complete lock/runtime coverage, unsuppressed vulnerability and secret checks | Two upstream Expo development-tool HIGH findings remain blocking |
| Hosted SDK verification | Direct fixed GitHub HTTPS API, exact commit/tree/archive/workflow, latest run attempt and every required job | A saved success JSON is insufficient |
| Actual deployment artifacts | [Pinned container profile](../../deploy/spring-ingress/README.md), runtime inspection and exact image-ID scans | A local/CI container is not an operator's deployed environment |
| Operating behavior | Concurrent signed traffic/replays, owned Redis outage/recovery, backend restart and admission recovery | Timed tests are not long-term production history or an SLA |
| License and notices | Original artifact bytes, locations and hashes in a private review bundle; missing material reported | Maintainer/legal review and final distribution notices remain required |
| Independent security assessment | Candidate/deployment-bound audit scope, findings and remediation | Internal review is not an external audit |
| Mobile-attested claims | Real Apple/Google app/account evidence and supported failure cases | Provider configuration remains deployment-specific; no device proof inferred |
| Publication and support | Approved version, registry identity, signing/provenance, support policy and release approval | No registry publication or security support commitment is implied |

## Native Java runtime inventory

The separate `Java native runtime inventory` workflow measures the complete
vendor JRE on native Linux amd64 and arm64 runners. It compares the pinned
Temurin Noble image with a diagnostic Debian 13.7-slim image containing the same
whole JRE directory. The production backend image is unchanged. No packages,
license records or unresolved libraries are removed to improve scan counts.
The diagnostic image rebuilds its own OS loader cache instead of copying Noble
system libraries or the loader cache.

The inventory CLI requires Python 3.11+ and accepts an exact **local image ID**,
not a tag or pull URL:

```sh
python3 scripts/qualification/inspect_java_runtime.py \
  --docker-context default --image sha256:<local-image-id> \
  --platform linux/amd64 --output /absolute/new/java-native
```

Only the bounded sanitized `java-runtime.json` report is retained. Probes use a
fresh owned container without network, secrets or host mounts, with a numeric
user, read-only filesystem and finite resource/time/output limits. Exit 0 means
the implemented inventory checks passed; exit 1 retains a complete measurement
with unresolved checks; exit 2 means setup or inventory completeness failed.
The diagnostic workflow accepts exit 1 so missing dependencies remain available
as failure evidence. A green collection job is **not** a native compatibility,
vulnerability, complete dependency closure or release approval.

With `--features`, the CLI requires the diagnostic image with the baked-in
`AppGuardRuntimeProbe` classes. Both native CI targets compile those same classes
using the pinned Java17 builder, without downloading Maven dependencies. Their
location is outside the vendor JRE, preserving whole-JRE comparison. Extended
reports use schema2 and retain all existing false release/closure flags.

The ten selected checks exercise P256 signature mutation refusal, AES-GCM tag
refusal, private PKCS12 roundtrip, default JSSE trust roots/TLS1.3, mutual TLS over
the container's own loopback, UTF8 file IO, explicit locale data, timezone data,
literal localhost NSS and headless font rendering. The TLS fixture creates only
short-lived synthetic keys/certificates and never changes system trust or contacts
external services. Native stderr is discarded to keep the strict JSON channel
clean; each measured check failure remains explicit, while missing/malformed
results or contradictory process status make collection incomplete. A result
cannot pass because output was absent. Caller host environment is not injected;
feature execution uses the diagnostic image's configured locale/trust defaults.
These probes do not establish arbitrary DNS, provider accounts, GUI/audio hardware
behavior or every JNI/dlopen path.

A replacement runtime requires inspection of both architectures, explicit native
provider packages with frozen provenance, application compatibility checks and
unsuppressed image scans. Linker resolution does not exercise Java feature
behavior, dynamically loaded plugins, TLS trust, DNS/NSS, timezone handling,
font rendering or a real operator environment. Existing native-coverage and
production-release flags remain false.

## Python build dependency verification

Both Python projects record the same reviewed build-tool versions and wheel
hashes in their uv configuration and lock manifests. Their existing lock
package records are preserved; those records include local projects and
development dependencies, not just installed production dependencies.

Use the reviewed uv 0.13.4 producer with build isolation and no prior cache:

```sh
uv --no-cache --directory sdk/python build --require-build-hashes
uv --no-cache --directory reference/python build --require-build-hashes
```

The explicit packaging check in SDK CI tests fresh locked editable installation
of both projects, isolated wheel builds, missing/incorrect transitive hash
refusals, wheel contents and a fresh all-extras consumer
installation from frozen hashed runtime requirements. Only its fixed-schema
receipt is retained. Pip source builds do not enforce these uv settings;
controlled producer checks do not establish universal build reproducibility.
Editable installation additionally needs the reviewed `editables` build helper;
passing a wheel-only build is insufficient to verify `uv sync --locked`.

Source scanning preserves `sbom-source.raw.cdx.json` and adds a deterministic
declared-build overlay to the existing `sbom.cdx.json` read by Trivy. The
`python-build-catalog-overlay.json` binds the raw SBOM and project configuration
hashes. Coverage validation recomputes the overlay and rejects missing or
mismatched pins and altered evidence. Project-bound build components do not
replace raw components, licenses or runtime locations, including when a package
version appears in both build and runtime inputs. This inventories declared
hash-pinned build constraints; downloaded artifacts, resolved build/runtime
closure, native dependencies and license approval require separate evidence.

## Sustained operating verification

The existing Spring qualifier now accepts `--soak-seconds` from 0 (disabled) to 3600
and `--soak-concurrency` from 1 to 32. A clean committed checkout, Java 17, Maven,
the locked Python environment and a trusted Redis 7.2.16 executable are required:

```sh
uv sync --locked --project sdk/python
uv run --frozen --project sdk/python python scripts/qualification/spring_ingress.py \
  --redis-server /absolute/path/to/redis-server \
  --soak-seconds 1800 --soak-concurrency 8 --output /absolute/new/operations
```

The runner uses fresh owned services and synthetic data. It measures accepted
signed traffic, exact replay denials, fixed latency buckets, CPU/RSS snapshots,
outage denial and recovery. It rechecks source/artifact hashes after cleanup.
Its original eight transport checks and receipt fields remain compatible;
operating evidence appears in the optional `operational` block.

The first 1,800-second, eight-worker run at `1d5b59d` failed its strict zero-error
gate: 79,758 exchanges included 24 signed-response fidelity mismatches and 20
unexpected replay responses, with no transport exceptions. All owned children
settled and source/artifact provenance remained unchanged. This is retained as
failed evidence, not a passing endurance result. Its aggregate counters do not
identify each failed response or establish a security bypass.

The optional process-local backend counter file previously forced disk
durability after every verification stage. Removing that unnecessary operation
preserves synchronous snapshots, exact counts and file protections; these
snapshots do not promise crash durability. A controlled 60-second comparison
improved measured throughput from 40.98 to 170.10 exchanges/second, with zero
errors in both short runs. That comparison does not establish the cause of the
historical failures. A separate attempt also failed before its first core
check and remains unexplained; a subsequent observed attempt passed. Fixed
status/error-code diagnostics now distinguish response outcomes without storing
request bodies, tokens, headers or arbitrary exception text. Equivalent-duration
clean-commit verification is required after the changes. Timed local results
remain distinct from a deployed container's resource limits and operating SLA.

The standalone process fixture deliberately uses nonpersistent Redis. It does
not claim replay retention across losing that Redis process. Its backend restart
check verifies nonce retention in the still-running Redis. The container profile
separately uses an owned AOF volume and tests ordinary Redis stop/start retention;
neither test establishes physical power-loss or cloud failover durability.

Actual outage testing exposed disabled automatic reconnect in the Spring
example. The corrected client reconnects while rejecting disconnected commands,
caps its queue at 128 and preserves one-second connect/command timeouts. Recovery
does not introduce an in-memory replay fallback or business-operation retries.

### Constrained-container sustained verification

The standalone qualifier above uses the host JVM's default heap; it does not
prove operating behavior at the container profile's 512 MiB backend limit.
Run the separate [owned container qualifier](../../deploy/spring-ingress/README.md)
with `--soak-seconds 1800 --soak-concurrency 8` to test that profile. It retains
the gateway 256 MiB, backend 512 MiB and Redis 128 MiB limits, CPU/PID limits,
read-only roots and existing mTLS boundaries. Optional operating evidence must
not replace or weaken any existing core transport, Redis or cleanup check.

The `Container deployment readiness` workflow uses a short 30-second soak on
push/PR and offers bounded numeric inputs for manual runs. Dispatch a reviewed
ref, retain its exact commit and run ID, and compare both with the receipt;
the artifact name alone is insufficient. Keep the ref unchanged until the run
finishes to avoid concurrency cancellation. Only the fixed receipt and image
status are retained, without credentials, raw requests or private logs.

Strict normal/replay outcomes, sampled container resource measurements and
unchanged runtime identities/restrictions are required. Missing resource
evidence, worker failure, unexpected OOM/restart or cleanup failure cannot satisfy this
technical qualification. Linux cgroup v2 is required for the optional operating
mode, with effective zero swap limit/usage required in addition to configured
Docker limits. Sampled peaks are not exact maxima or leak proof, and neither a short nor
a 30-minute synthetic run grants production approval or an SLA. Image findings,
native dependency coverage, actual operator deployment and external approvals
remain independent gates. Historical unexplained failures remain open even if
this separate qualification passes.

## Authoritative hosted verification

For a completed main push run of `Verify SDK foundation`:

```sh
python3 scripts/release/verify_hosted.py --candidate /absolute/path/to/candidate \
  --expected-commit EXACT_COMMIT --repository bonjin-app/appguard \
  --run-id NUMERIC_RUN_ID --output /absolute/new/hosted

python3 scripts/release/assess.py --candidate /absolute/path/to/candidate \
  --scans /absolute/path/to/scans --expected-commit EXACT_COMMIT \
  --hosted-run-id NUMERIC_RUN_ID --output /absolute/new/assessment --check
```

The verifier contacts only the public GitHub API over validating HTTPS. It has
no token, URL/host or offline-report CLI option. The repository/workflow scope
is deliberately fixed. It binds the Git commit/tree, all distributed blob bytes
and modes, deterministic source archive, exact workflow bytes, current attempt
and all required completed jobs. A self-restamped altered candidate is rejected.
An owned subprocess bounds DNS, TLS, headers and body work for every request.
Public API rate limits and availability can deny verification; that is not a pass.

The optional assessor flag runs this verifier directly. Only that technical CI
gate can pass from its result; scans, external approvals and deployment gates
remain independent. Original input identities/hashes are checked again after
networking. External approvals are not inferred from the result.

### Owned container artifact verification

The separate container verifier accepts a local artifact ZIP as **untrusted
bytes**. Live public GitHub metadata must authenticate its exact digest, size,
run, repository and candidate before any receipt can affect readiness. It does
not accept a saved verifier report, a token, an alternate API host or an artifact
download URL. Download the original immutable artifact through GitHub separately;
recompressing or editing it changes its digest and cannot pass verification.

```sh
python3 scripts/release/verify_container.py --candidate /absolute/path/to/candidate \
  --expected-commit EXACT_COMMIT --run-id NUMERIC_CONTAINER_RUN_ID \
  --artifact /absolute/path/to/original-artifact.zip --output /absolute/new/container

python3 scripts/release/assess.py --candidate /absolute/path/to/candidate \
  --scans /absolute/path/to/scans --expected-commit EXACT_COMMIT \
  --hosted-run-id NUMERIC_SDK_RUN_ID \
  --container-run-id NUMERIC_CONTAINER_RUN_ID \
  --container-artifact /absolute/path/to/original-artifact.zip \
  --output /absolute/new/assessment --check
```

Both assessor container arguments are required together. Missing, malformed,
changed, expired or ambiguous evidence remains unverified. The verifier binds
all distributed source bytes and modes, the container workflow, current run and
attempt, required steps, the latest applicable main push or manual run, and a
uniquely named artifact. Version 1 accepts only attempt 1: GitHub artifact
metadata identifies its run but has no run-attempt field. Use a new run rather
than rerunning failed jobs when collecting this evidence.

The artifact contains exactly `binding.json`, `receipt.json` and
`image-status.json` at its root. The name includes the commit, run ID and attempt.
Only bounded fixed-schema JSON is staged; raw logs, configuration, certificates,
request bodies and reports are not uploaded. ZIP entries are validated without
general extraction, and receipt/source/image hashes and operating measurements
are checked independently of self-declared success flags.
The upload runs only after staging validation succeeds; a rejected or preexisting
staging directory cannot be uploaded by a later unconditional cleanup step.
Verifier output is finalized in private staging before exclusive publication;
existing results are preserved. Cooperative cancellation rolls back owned
output, but SIGKILL, host failure or a compromised host cannot guarantee cleanup.
Both staging tools require an existing output parent owned by the current user
with no group or other write permission. Use a private evidence directory;
writing directly into a shared writable directory is rejected. These controls
assume a trusted current-user process and operating system.

The `owned_container_ci` technical gate requires at least 1800 requested and
observed seconds with exactly eight synthetic workers, successful normal/replay
outcomes, matching counters, resource continuity, no OOM or unintended restart,
backend recovery with replay retention, and cleanup. A normal 30-second push
run can provide authentic artifact observations but cannot pass this sustained
gate. Sampled measurements do not establish continuous peaks, absence of leaks,
long-term capacity or an operator SLA.

An image-scan failure is compatible with authentic operating observations only
when it represents validated positive vulnerability counts and all required
functional and evidence steps succeeded. Those vulnerabilities remain blocking
scan findings. Passing the owned operating gate never clears image findings,
native dependency coverage, the consumer graph, actual production deployment,
licenses or external approvals. Every result retains `release_ready: false`.

## Image scan coverage

The container scanner checks exact locally built image IDs. It requires OS
package evidence in all three images and expected installed Python/JAR package
evidence in the gateway/backend. Missing inventory is unverified, rather than
a zero-finding pass. Finding counts remain independent of coverage validation.
This does not establish complete native dependency coverage for source-built
Redis, the JVM or bundled native libraries; those gaps remain explicit.
Image scan completion cannot grant deployment or release approval.

Image status schema 2 retains bounded finding records: advisory ID, package,
installed version, reported fixed versions, severity, package class/type and an
opaque occurrence digest. Duplicate occurrences, unfixed findings and all
severities remain counted. An empty fixed-version array means the scanner did
not report one; it is not proof that no fix exists. Raw targets, package paths,
descriptions, URLs and logs remain private. If projection exceeds lexical,
record or the 2 MiB status envelope limits, detailed records become unverified
while aggregate finding counts remain intact.

The scanner explicitly downloads the vulnerability and Java databases into a
fresh private cache, then scans all images with both update paths disabled.
Schema 2 records the pinned Trivy release archive and installed executable
digests, both database/metadata digests and database timestamps. Stable bytes
are rechecked across scanning and publication. These values identify the
observed scanner and data; they do not prove database completeness or native
coverage. An integrity or setup failure cannot claim complete details or an
automated scan pass.

The evidence producer and verifier validate schema 2 independently. The
verifier requires complete, count-consistent detail provenance for this new
format. It still accepts schema 1 operating evidence, reporting
`image_finding_details_verified: false` for that legacy format. Finding
verification never clears positive image findings or changes release approval.

## Original license materials

```sh
python3 scripts/release/license_materials.py \
  --artifacts /absolute/path/to/operations/maven-runtime \
  --manifest /absolute/path/to/operations/maven-runtime-manifest.json \
  --output /absolute/new/license-review
```

The private output contains `license-materials.json`, `materials.zip` and an
unapproved notices index. It preserves original LICENSE/NOTICE/COPYING bytes
from verified JARs and reports the original archive paths and hashes. Content
is stored under hashed names, never extracted through archive paths. Input ZIP
directory size, entry count, material sizes and aggregate output are bounded;
Zip64/multivolume/SFX archives are unsupported. The initial 69-JAR collection
found 99 material records and 15 artifacts without matching original material.
Those 15 require additional authoritative source materials and review.

`--check` also rejects missing material. Collection never sets review approval,
complete distribution notices or release readiness. OS image licenses, Python,
other SDKs, bundled/shaded dependencies and all distribution obligations require
their own complete review. Raw bundles remain private; CI retains fixed status
only. No support or license determination is made by this command.

## Security reporting

[Private vulnerability reporting](https://github.com/bonjin-app/appguard/security/advisories/new)
was enabled and read back on 2026-10-22. No report was submitted and no message
was sent to a third party. See [the security policy](../../SECURITY.md) for the
actual reporting/support boundaries.

The two existing upstream advisories remain visible. The unmerged node-forge
proposals require further cryptographic review; a suggested patch is not treated
as a released fix. See [the current advisory record](../security/dependency-advisories-2026-10-22.md).
