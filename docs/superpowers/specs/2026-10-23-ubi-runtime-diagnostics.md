# UBI10 Java runtime diagnostics

Approved implementation scope: v1 RPM/image comparison design plus the v2
independent Java observation amendment. The frozen private v1/v2 proposals are
historical inputs; this specification describes their combined final contract.
Implementation review and actual native CI evidence remain separate.

## Purpose and exclusions

Evaluate the untouched official Temurin17 UBI10 minimal runtime against the
current Noble runtime on selected owned native Linux amd64/arm64 CI hosts.
Observe all ten existing Java features, the entire vendor JRE, installed RPM
metadata/providers, and unsuppressed exact-image vulnerability findings.
This does not promise to resolve Noble's 31 previously observed findings.

UBI10 amd64 requires x86-64-v3. It cannot replace Noble's current CPU support
scope based on a selected CI host. UBI10 is diagnostic only: production runtime
Dockerfiles, full-topology qualification, public verifiers, scanners/Trivy pins
and release gates are unchanged. No package installation/removal, JRE trimming,
notice/DB/buildinfo removal, root privilege, emulation or new dependency is
allowed. UBI8 with an identical whole vendor JRE remains untested and outside
this scope. Rejected Alpine/Debian/Resolute experiments are not repeated.

Fixed UBI index:
`eclipse-temurin:17.0.20.1_1-jre-ubi10-minimal@sha256:25c83f52d080115d99d80eaeda67a5221b07b7066ae8248fdd37f6e1c6469aef`.
Root's 2026-10-23 registry/source preflight observed both child manifests and
config OS/architecture; it did not pull layers, execute Java or scan CVEs.
The official Noble/UBI recipes declare the same Linux JRE archive per arch;
actual complete-tree equality must still be measured.

## Explicit profile and lifecycle

`inspect_java_runtime.py --package-profile rpm-ubi10-v1 --features` produces
schema4. Omission retains `dpkg-v1` and the exact existing schema1/2/3 behavior.
RPM without features, or combined with `--dependency-closure`, is rejected
before Docker contact. The Debian historical closure schema remains specific
to its existing lock.

The RPM path reuses the owned-container controller and held-parent-FD private
publication/rollback policy. It requires native Linux host/machine, a local
Linux daemon, exact immutable image ID/platform and stable pre/post image and
owned container observations. PID1 is directly the fixed vendor Java binary
running helper `idle`; no shell, sleep, id, uname, env, find, stat or sha256sum
inside the image is needed to start the audit. Actual `/proc/{1,self}/exe`
ELF64/little-endian/ET_EXEC-or-ET_DYN/machine headers and four UID/GID fields
are read through Java before observations and again at final identity checks.
No Java property or image label alone proves native execution or CPU ISA.

Keep UID/GID10001, network none, read-only root, cap-drop ALL, no-new-privileges,
256MiB/no swap, one CPU, pids64, fixed 16MiB tmpfs, no binds/ports/restart/logs,
600-second audit deadline and 60-second owned cleanup budget. Helper idle uses
8MiB heap; other execs use64MiB heap. Idle JVM overhead can make the measurement
incomplete; caps must not be raised to force success. Each query has a fixed
30-second child deadline and bounded child/output settlement, additionally
bounded by its outer stage and the global audit deadline. Cancellation,
identity mutation, unconfirmed process settlement or timeout stops new stages.

Before create, reject unknown/duplicate image environment keys and every JVM
or native loader injection variable, even empty values. Accepted keys are
PATH/JAVA_HOME/JAVA_VERSION/LANG/LANGUAGE/LC_ALL/LC_CTYPE/TZ/container. No host
Java options or arbitrary classpath/property/executable input is forwarded.
The new path preserves existing HOME/CODEX_HOME values without overriding
them in any host or child environment; fixed `-Duser.home=/tmp` and private
temporary directories provide Java scratch state. Legacy dpkg Docker CLI HOME
and legacy keytool-child HOME filtering remain unchanged, as a compatibility
limitation rather than authorization to introduce new overrides.

## Independent observations and schema4

After trustworthy identity, execute features first. Then independently attempt
JRE tree, RPM DB hashes, RPM query and native linkage. Provider collection needs
complete linkage requests and RPM identities. Missing rpm/ldd cannot erase a
validated feature/tree/DB observation or manufacture a complete inventory.

`stages` has exactly identity, features, jre_tree, rpm_database_hashes,
rpm_inventory, native_linkage, native_providers. Every row is
`{attempted:bool, complete:bool, reason:enum, transport_exit_code:int|null}`.
The code is a non-Boolean integer -128..255 or null when unavailable.
Complete requires attempted=true, reason=measured and transport code0.
Fixed reasons: not_attempted, measured, tool_unavailable, read_unavailable,
query_failed, protocol_unverified, prerequisite_incomplete, identity_unverified,
resource_unverified, timeout, cancelled, budget_exhausted, output_limit.
Normal helper transport0 alone never completes an observation.

`features` is null without a valid envelope; otherwise schema2 has the exact
ten existing check keys, each `{attempted:bool, passed:bool|null}`. Unentered
means false/null; entered means a Boolean outcome. `checks_passed` means all
ten entered and passed. `result_code` is the existing engine0/1/2, distinct
from helper transport. Feature stage is complete only for all ten entered and
code0/1. Code0 requires all true; code1 requires a measured false; code2 retains
actual observations but remains incomplete/resource_unverified even with all
true checks. `features.passed = stage.complete && checks_passed`.
The default probe main still emits exactly schema1/checks/passed and its
existing process0/1/2 behavior; no public fault-injection option is added.

The standard-Java17 helper has only fixed idle/identity/features/tree/
database-hashes/rpm/linkage/providers modes. It streams SHA256 using64KiB
buffers, walks without FOLLOW_LINKS, checks file identity/attributes around
reads, and enumerates every regular file and literal symlink. Legal, release,
security and non-ELF files remain part of the canonical whole-tree digest.
Limits remain4096 JRE file/link entries,256 ELFs/OS library paths,1GiB total,
512MiB/file,8MiB protocol and2MiB native JSON. Known fixed RPM DB files have a
64MiB/file cap and fixed public tags; hashing bytes is not package parsing.

RPM queries use direct fixed argv, no shell expansion, with separate name,
epoch, version, release, architecture, source-RPM and uninterpreted declared
license fields. Full NEVRA is identity; distinct versions remain distinct and
duplicates are rejected. Native arch/noarch and only the exact gpg-pubkey
metadata exception are permitted. Owner queries must match an inventoried
non-metadata tuple and the actual canonical library SHA256. `/usr/lib64` is
accepted only by the explicit RPM parser. Raw query records are retained as a
private file600, at most2MiB, with count/byte/SHA binding. Original image RPM DB,
notices and Red Hat content manifests remain untouched in their image layers.

Aggregate equations are strict:

- inventory_complete: identity/tree/DB/RPM/linkage/providers all complete.
- measurement_complete: inventory_complete, complete feature stage, final
  unchanged image/platform/identity and successful cleanup.
- native_checks_passed: measurement_complete, all original native checks and
  features.passed.
- Exit0: complete passing measurement; exit1: complete failed native checks;
  exit2: incomplete/unverified. Measured missing dependencies can fail checks
  with complete inventory; a missing loader tool cannot complete linkage.

Later stage errors never clear prior validated feature data. JSON overflow
retains bounded features/stages/counts, drops supporting large records and
invalidates corresponding stages/digest/aggregate claims. Late unsafe parent
ownership/mode/identity rolls back all owned output.

## Same-image comparison and evidence limits

`java-ubi-runtime.yml` is manual on main, with a push trigger restricted to the
exact owned `codex/ubi-runtime-evaluation` branch for first-version premerge CI.
GitHub requires default-branch presence for manual dispatch, so this bounded
bootstrap avoids merging an unexecuted workflow. It adds no main or PR trigger.
The workflow maps fixed amd64/arm64 runners, builds the
two pinned diagnostic targets once, and reuses those exact IDs for native
inspection and one unchanged pinned-Trivy/frozen-DB scanner session. It retains
original native JSON, RPM query records, full unsuppressed Trivy image/control
JSON and comparison JSON even when later stages fail. No release is deployed.
The job90-minute ceiling includes build10min, two660-second native lifecycles,
the unchanged scanner2760-second ceiling, bounded bind/cleanup/upload margin.

The new UBI binder binds original report hashes, ordered image IDs/platform,
fixed base pins and collector-source hashes. It independently reconstructs
complete original JRE tree digests, validates feature/stage aggregates, and
keeps actual finding counts separate from collection/native/feed outcomes.
Partial evidence may be identity-bound while collection_complete=false.
All release/external/legal/native-closure/CPU-baseline approvals remain false.

Current Debian13 calibration establishes no Red Hat10 feed coverage. Pinned
Trivy's Red Hat fallback content-set map lacks10; original BuildInfo content
sets may matter and remain preserved. UBI zero findings stay unverified and
can yield scanner/binder exit2. Nonzero counts are reported occurrences, not
complete CVE coverage. A reviewed Red Hat advisory/NEVRA/content-set positive
control is a separate future scope. Vendor certificate entrypoint side effects,
AppGuard bootstrap, production traffic/recovery, generic CPU compatibility,
complete dlopen/JNI coverage and license approval are not established here.

Primary references: [official pinned image recipe](https://raw.githubusercontent.com/adoptium/containers/511f9356dc4d50932a0a5f8cfb0f87ed1aef4f07/17/jre/ubi/ubi10-minimal/Dockerfile),
[RHEL10 architectures](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/considerations_in_adopting_rhel_10/architectures),
[RPM tags](https://rpm.org/docs/6.0.x/manual/tags.html),
[Trivy Red Hat detector](https://raw.githubusercontent.com/aquasecurity/trivy/v0.76.1/pkg/detector/ospkg/redhat/redhat.go).
