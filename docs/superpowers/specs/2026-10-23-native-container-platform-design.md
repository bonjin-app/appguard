# Native architecture binding for the complete container topology

Extend the approved production qualification with real ARM64 execution of the
existing gateway, Spring backend and Redis topology. Keep all 12 functional
checks, seven operating checks, constrained resources, mTLS, exact source/image
identities, cleanup and unsuppressed vulnerability findings. This is operating
evidence for a named architecture, never production or native-CVE closure approval.

The existing workflow gains one required dispatch choice `architecture`, with
`amd64` default and only `amd64`/`arm64` allowed. Push and PR remain AMD64.
Map these choices to the fixed `ubuntu-24.04` and `ubuntu-24.04-arm` labels;
never accept a runner label as input. Keep the existing job, step names, artifact
layout and timeouts. Separate concurrency by architecture. No QEMU setup or
runtime Dockerfile/base-image change is part of this increment.

The qualifier gains optional `--platform linux/amd64|linux/arm64`, absent by
default for existing callers. Explicit mode fixes build/service platform in its
owned override, requires the actual Linux host and local daemon architecture,
and binds exact image IDs/OS/architecture plus the first 20 bytes of actual
`/proc/1/exe` ELF headers in all three owned services. Pre/post observations
must match across the complete functional and optional operating interval.
64-bit little-endian executable/shared-object ELF headers must have machine 62
for AMD64 or 183 for ARM64. Labels alone cannot establish native execution.
The PID1 observation establishes platform only, not complete executable bytes
or all native library identities; existing version/source/image checks remain.

Optional receipt `runtime_platform` has exact fields `schema:1`, `platform`,
`host_machine`, `daemon_architecture`, `images`, `verified`. Canonical machines
are `x86_64`/`aarch64`; canonical architectures are `amd64`/`arm64`. Each image
row is `{image_id,os,architecture,pid1_elf_machine}`. Incomplete initial receipts
may contain null host/daemon and partial image maps with `verified:false`.
Verified blocks require all three roles, exact existing receipt image IDs and
matching platform/ELF machines. Unknown fields and values are rejected.

The existing schema-2 three-role scanner accepts a native Linux AArch64 host
only with a verified explicit ARM64 receipt block. Legacy no-block ARM scanning
remains rejected. In explicit mode independently inspect the same image IDs and
platform before/after scanning, require matching Linux host/daemon, and retain
an optional block of the same prefix shape whose image rows omit PID1 fields.
Its scanner archive/executable and both databases remain hash-bound. Existing
finding/detail limits, all severities, duplicates and unfixed findings remain.

The standalone binder and formal verifier independently validate exact optional
blocks and all cross-artifact relations. Older receipt/schema-1/schema-2 image
proofs remain accepted without a platform claim. Pre-update strict readers may
reject new extended receipts; compatibility means updated readers retain old
proof support, not that unknown fields are silently accepted. ARM scanner pins
are independently allowlisted in both readers from the already reviewed
official Trivy 0.76.1 Linux AArch64 archive. Formal jobs must report the matching
fixed runner label for new architecture claims. No extra GitHub API calls are
needed. The existing strict latest-run union across both architectures remains.

Formal verification additionally accepts optional `--expected-platform`;
requiring ARM64 cannot accept legacy or AMD64 evidence. Its default retains
existing behavior. Public results expose the bound platform and verification
boolean, with all release/external/native-coverage approvals still false.
The assessor's existing generic container gate is unchanged.

Each architecture needs its own real full-topology run and exact-image scan.
The Java diagnostic matrix cannot substitute for this evidence. The current
single latest-run policy means a newer ARM64 run supersedes an older AMD64 run
for formal freshness; this increment does not aggregate both into one approval.

Primary references: [GitHub runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[choice inputs](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onworkflow_dispatchinputs),
[job metadata](https://docs.github.com/en/rest/actions/workflow-jobs), and
[Compose platform semantics](https://docs.docker.com/reference/compose-file/services/#platform).
