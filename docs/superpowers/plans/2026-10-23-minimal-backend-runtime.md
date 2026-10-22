# Backend runtime baseline hardening implementation plan

> For agentic workers: use subagent-driven-development with bounded ownership, tests before changes, and no recursive delegation.

**Goal:** Resolve reported backend OS vulnerabilities using a maintained runtime baseline while preserving its Java version, CPU support scope, application behavior, deployment isolation and truthful scan coverage.

**Architecture:** Evaluate the official same-version Temurin Ubuntu 26.04 Resolute JRE using an immutable, independently read registry index, both platform manifests and hash-bound configuration blobs. Change the final runtime base only after verifying those inputs. Keep installed OS package metadata, application JAR metadata, full-severity/unfixed scan behavior, resource limits, non-root execution and read-only deployment controls intact. A fresh real Docker qualification and exact-image scan decide whether this is an improvement. This change makes no image-size reduction claim.

**Tech stack:** Existing Docker Compose profile, Temurin jdk-17.0.20.1+1, Maven 3.9.16, Python stdlib tooling and pinned Trivy 0.76.1.

**Spec:** The active production goal and docs/development/production-release.md; this plan is one increment and cannot approve a release.

## Baseline and constraints

- Previous goal turn is progress: main/origin main 05fd5e5 is clean and contains schema-2 scanner/DB/finding evidence plus tested version-output and confirmed-absent process-group fixes. Main SDK CI39835656891 passed all five jobs. Actual image run39835656990 retained31 backend OS findings (27 MEDIUM,4 LOW),0 gateway/Redis findings, and complete detail provenance. Source scans still have2 HIGH findings. Overall readiness remainsfalse.
- The current backend final base is Temurin17-jre-noble index07fa0356cf354c5252947575f42ed42aa6fd921f36438b7bc77ad81c31c537dd. It carries the reported Ubuntu packages; no OS packages are added in our final Dockerfile. Empty reported fixed-version lists do not prove that no fix exists.
- Evaluation candidate: eclipse-temurin:17.0.20.1_1-jre-resolute indexaa78671e02c465ed264807a33fb2b2edc9fd853d05237de270e468cf84c7b412. Source Dockerfile at Adoptium commit511f9356dc4d50932a0a5f8cfb0f87ed1aef4f07 declares the same Java version and exact same vendor JRE tarball hashes as the Noble image. Refresh actual registry index, child and config bytes before accepting its metadata.
- Require Linux amd64 and arm64 manifest/config identities and matching declared Java versions. Architecture metadata alone is not runtime execution. Alpine is unsuitable for this candidate because its actual current index lacks arm64 despite an upstream listing claiming it.
- Maven's pinned builder, the gateway/Redis bases and all runtime JAR versions stay recorded. This runtime change does not close builder, native or complete dependency coverage; those remain required later work.
- No deleted OS/JAR metadata, ignored/unfixed suppression, severity threshold, manual count override, relaxed qualifier, privilege escalation, new network exposure or success inferred from an image name.
- Physical hardware, actual deployment/provisioning, external approvals, registry publication and global Codex configuration remain excluded. Old evidence snapshots are immutable.

## Review focus

1. Ubuntu package/dpkg metadata must remain present and recognized; missing inventory can never become zero-finding approval.
2. Shell, JVM, mTLS/PKCS12, classpath, numeric user, temporary directories and read-only-root behavior must work in the changed OS.
3. Registry tag text and architecture listings can disagree with actual index contents; hash exact index/children/configs and pin the index.
4. Reduced package count or zero reported findings cannot prove native closure, performance/SLA, complete license obligations or release readiness.
5. Failed starts, recovery, scans or cleanup remain failures. Diagnose and fix actual problems without weakening the measurement or security boundary.

## Tasks

- [x] Fast read-only agent: refresh exact official index/child/config metadata; provide a compatible base-images.json row. Root retained the verified raw bytes separately. No layers or credentials retained.
- [x] Routine implementation worker owns deploy/spring-ingress/Dockerfile.backend, base-images.json and README.md. Preserve the existing real image scan's31finding failure as the meaningful pre-change RED. Root validated exact raw registry/config bytes and unchanged vendor archive hashes. All196 existing tooling tests pass with disposable Redis and zero skips. No new literal configuration test is counted as behavioral coverage. Actual Docker qualification and unsuppressed image scanning remain required: Docker is unavailable locally.
- [ ] Independent deep reviewer checks changed build inputs, metadata provenance, deployment invariants and tests. Root handles integration and evidence.
- [ ] Push isolated branch; obtain exact-commit SDK CI, actual constrained Docker functional/recovery/cleanup proof and full image scan. Assess actual package inventory/counts/details. Reject or fix an unsuitable base rather than hiding findings.
- [ ] Generate a fresh candidate and source/runtime scans; preserve known source HIGH failures and native/approval gaps.
- [ ] Integrate reviewed bounded change to local main/remote only after meaningful implementation checks pass. Read back exact-main CI and original artifact, then dispatch a single1800-second/eight-worker main operating run for this changed runtime. Keep main fixed while that run is live and never restart it on an observation timeout.

## Evidence limits

The previous113167d 1800-second run remains valid only for that older candidate.
Current05fd5e5 has30-second functional evidence and cannot inherit sustained
approval. Public unauthenticated GitHub metadata budget currently has5 requests
remaining until2026-10-22T19:37:44Z; do not add credentials or change the fixed
transport to evade the limit. Live CI observation through existing authorized
GitHub CLI remains available. Independent consumer transport/ZIP dynamic review
was previously rejected by automatic safety review and is not reopened here.

## Preserving the CPU support scope

The first investigated UBI10 candidate has verified platform/config metadata,
but is rejected as the default: RHEL10 requires x86-64-v3, which would silently
narrow the current generic amd64 scope. Its raw registry bytes are retained
separately as rejected-candidate evidence. Ubuntu documents generic amd64 as
the original AMD64/Intel64 baseline and arm64 as ARMv8-A without optional
extensions; amd64v3 is a separate variant. The selected official Resolute
image uses the generic platform, and its vendor JRE archives match Noble's.
These are published input properties, not execution on every baseline CPU or
arm64 runtime proof. Actual host/platform runtime coverage remains explicit.

Primary sources:
- https://ubuntu.com/project/docs/how-ubuntu-is-made/concepts/supported-architectures/#architecture-baselines
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/considerations_in_adopting_rhel_10/architectures
- https://raw.githubusercontent.com/adoptium/containers/511f9356dc4d50932a0a5f8cfb0f87ed1aef4f07/17/jre/ubuntu/resolute/Dockerfile
