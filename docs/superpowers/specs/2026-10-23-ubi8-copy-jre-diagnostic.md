# UBI8 copy-only JRE diagnostic

This separate diagnostic observes the current full Noble JRE copied into a
pinned official UBI8 minimal base on selected native Linux amd64/arm64 CI hosts.
It changes no production runtime, UBI10 default, scanner, feed control or public
release gate. Local fixtures verify code behavior; actual container execution,
feature results, full-tree equality, RPM/native observations and vulnerability
findings remain pending a reviewed branch CI run.

## Fixed recipe

`java-runtime-probe.Dockerfile --target ubi8-copy-jre` uses
`registry.access.redhat.com/ubi8/ubi-minimal@sha256:c851eaf99ddf32811fdf8a216c2609cd0e55317ab8c46ecbaa3ea8298532f055`.
Copy the entire `/opt/java/openjdk/` from the existing Noble source
`eclipse-temurin:17-jre-noble@sha256:07fa0356cf354c5252947575f42ed42aa6fd921f36438b7bc77ad81c31c537dd`.
The unchanged pinned Maven builder supplies the two existing Java17 probe
classes and AppGuard LICENSE outside the JRE. Keep UID/GID10001, an absolute
Java entrypoint and empty CMD, clearing the base's Bash command.

This target has no RUN or ENV instruction. Retain the captured base PATH and
`container=oci`; do not add locales, fonts, system libraries, loader cache or
packages. Do not run the vendor certificate entrypoint. Preserve every JRE
file and symlink, including classes.jsa, legal, release, security and CA bytes,
and all base package metadata/notices/buildinfo. The existing final UBI10
target remains last, preserving the Dockerfile's implicit default.

## Explicit observations

`inspect_java_runtime.py --features --package-profile rpm-ubi8-copy-jre-v1`
selects schema4. It requires features and rejects dependency-closure mixing
before Docker contact. Omission retains dpkg/schema1/2/3; `rpm-ubi10-v1` retains
its existing CPU dictionary and OS-major10 behavior. The UBI8 profile accepts
only os-release ID rhel/ubi with exact VERSION_ID8.10.

Reuse the unchanged standard-Java helper and feature engine. Run direct Java
PID1, check actual PID1/self ELF64 little-endian machine and four UID/GID fields,
native Linux host/daemon architecture and immutable image ID before/after.
Features run first. The seven exact stages remain identity, features, jre_tree,
rpm_database_hashes, rpm_inventory, native_linkage and native_providers. Typed
envelopes, feature attempted/passed/result-code equations, strict NEVRA joins
and canonical provider hashes retain the existing contracts in the
[UBI10 specification](2026-10-23-ubi-runtime-diagnostics.md).

Missing tools, unsupported known primary RPM DB layout, failed Java startup,
bad linkage/providers or later errors keep previously validated observations.
They cannot complete an unavailable stage. A feature result2 remains typed
partial evidence and prevents completion, even if its observed checks are true.
Complete failed native/feature checks return1; incomplete measurement returns2;
complete passing measurement returns0. Cleanup and final identity are required
for measurement_complete. No error or process exit alone proves an ABI cause.

Keep the existing limits: network none, read-only root, cap-drop ALL,
no-new-privileges, no bind mounts/ports/restart/logs,256MiB memory and memory+swap,
one CPU, pids64,16MiB tmpfs,600sec audit plus60sec owned cleanup;8/64MiB idle/exec
heaps,30sec helper child queries and existing stage deadlines;4096 file/link
entries,8192 directories,256 ELFs/library paths,1GiB total JRE,512MiB/file,
64MiB/known DB file,1024 RPM records,8MiB protocol and2MiB native/raw RPM output.
Do not raise caps to force success. Reject unknown/duplicate image environment
keys and JVM/loader injection. The RPM path preserves host HOME/CODEX_HOME
values and forwards neither host Java options nor arbitrary probe arguments.

UBI8 CPU provenance explicitly records `copied_jre_minimum_unverified`, the
declared RHEL8 generic OS floor as context, and observed-CI-host-only scope.
Copied-JRE minimum CPU/GLIBC, host ISA baseline, Noble support-scope preservation
and CPU approval remain false. The RHEL8 OS floor, OCI architecture and a
successful selected host do not prove minimum JRE ISA/GLIBC or kernel portability.

## Binding, workflow and retained failures

The binder requires the explicit UBI8 profile plus exact `--ubi-base-index`
and `--jre-source-index` above. Wrong/cross-profile pins, observed wrong OS,
CPU records, swapped/equal image IDs or platform mismatch deny binding.
Reconstruct the complete file/symlink digest independently from original
records. classes.jsa and all legal/security/link records participate; do not
exclude differences. Bind original JSON hashes, raw private RPM TSV hash/count,
collector/recipe/profile sources, binder and dedicated workflow source hashes.
Pins describe fixed recipe inputs, not independently attested image ancestry.
Valid partial originals can bind with collection_complete=false.

`.github/workflows/java-ubi8-copy-jre.yml` has an exact
`codex/ubi8-copy-jre-evaluation` push bootstrap plus manual dispatch, fixed
ubuntu-24.04/ubuntu-24.04-arm runners, pinned actions, read-only contents,
no persisted credentials, fail-fast=false and cancel-in-progress=false.
Build baseline/ubi8-copy-jre once and use the same two exact IDs throughout.
Both native roles run despite measured failures; native1 and native2 remain
failure outcomes. Later eligible scan/bind steps run with always(), retaining
their actual exits. Always attempt cleanup restricted to this run's exact
label/ID, and record fixed whitelisted step outcomes/role exits, source commit,
run/attempt/arch and image IDs. Missing reports stay absent; fabricate no data.

Use new private owned state and held-parent-FD publication. Reject pre-existing
or unsafe output. Build logs stay bounded and unuploaded. Only nine explicit
artifact paths are eligible: two native JSONs, RPM TSV, diagnostic JSON, two
Trivy image JSONs, unchanged Debian calibration JSON, comparison JSON and fixed
run-status JSON. This is controlled diagnostic evidence, not a general raw-log
upload. Keep the90min budget covering build10min, two bounded native lifecycles,
the unchanged46min scan and bounded binding/cleanup/status/upload margin.

The unchanged scanner freezes its pinned databases and retains unsuppressed
findings. No UBI8 advisory/NEVRA/content-set positive control has been researched
or pinned here. Debian13 calibration proves no UBI8 coverage. Zero UBI8 findings
remain feed-unverified/exit2; positive counts are reported occurrences/exit1,
not complete CVE coverage. This initial diagnostic cannot establish an all-green
or CVE-clean conclusion. Native success and artifact binding remain separate.

All native-coverage/full-graph/CPU/legal/external/release approval flags stay
false. No production traffic, vendor-entrypoint startup, full JNI/dlopen closure,
host-kernel support or legal completeness is established. Actual both-architecture
branch outcomes must be reviewed before integration; never merge an unexecuted
workflow merely to obtain manual dispatch.

Primary context: [official UBI8 repository](https://catalog.redhat.com/en/software/containers/ubi8/ubi-minimal/5c359a62bed8bd75a2c3fba8),
[RHEL limits](https://access.redhat.com/articles/rhel-limits),
[RHEL8 release notes](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/8.0_release_notes/rhel-8_0_0_release),
[pinned Red Hat detector](https://github.com/aquasecurity/trivy/blob/v0.76.1/pkg/detector/ospkg/redhat/redhat.go).
The pinned local registry/source captures reviewed for this recipe are input
evidence, not execution or coverage proof.
