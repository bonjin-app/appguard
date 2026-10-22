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

The standalone process fixture deliberately uses nonpersistent Redis. It does
not claim replay retention across losing that Redis process. Its backend restart
check verifies nonce retention in the still-running Redis. The container profile
separately uses an owned AOF volume and tests ordinary Redis stop/start retention;
neither test establishes physical power-loss or cloud failover durability.

Actual outage testing exposed disabled automatic reconnect in the Spring
example. The corrected client reconnects while rejecting disconnected commands,
caps its queue at 128 and preserves one-second connect/command timeouts. Recovery
does not introduce an in-memory replay fallback or business-operation retries.

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

## Image scan coverage

The container scanner checks exact locally built image IDs. It requires OS
package evidence in all three images and expected installed Python/JAR package
evidence in the gateway/backend. Missing inventory is unverified, rather than
a zero-finding pass. Finding counts remain independent of coverage validation.
This does not establish complete native dependency coverage for source-built
Redis, the JVM or bundled native libraries; those gaps remain explicit.
Image scan completion cannot grant deployment or release approval.

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
