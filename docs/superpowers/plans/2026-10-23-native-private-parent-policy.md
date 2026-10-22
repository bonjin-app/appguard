# Bind native diagnostic output policy to the held parent descriptor

The native inventory and same-image comparison callers require their new
output parent to belong to the current UID and disallow group/other writes.
Their original `Path.stat()` policy check preceded `Publication.__enter__()`.
Publication binds its adopted descriptor to the current path identity, but
does not apply caller-specific ownership or mode policy. A pre-adoption policy
decision therefore did not establish the policy of the descriptor used for
the private output.

## Bounded change

Add `check_private_parent()` and a small `private_publication()` context manager
to `java_runtime_dependencies.py`, which the native inventory already imports.
The wrapper immediately checks the adopted parent descriptor with `os.fstat()`
and the existing `check_parent()` path/descriptor identity check. In the native
caller this completes before the temporary directory, private session state or
Docker commands are created. In the comparison caller it completes before
writing any report. Retain the initial path check as an early rejection.

Both callers recheck this policy immediately before and after publication.
A late policy failure propagates through the existing descriptor-owned
publication cleanup, removing only the owned staged/published output. The CLI
returns 2 with its existing fixed incomplete/false result. Native container
cleanup still happens before final publication checks and retains exact owned
container identity checks.

There is no change to shared `Publication`, the production container scanner,
the separate diagnostic CVE scanner, schemas 1/2/3, native resource limits,
Docker commands, package/source pins, canonical non-symlink `.pgp` keyring trust,
whole-JRE identity, or report binding rules. The comparison's input/lock hashes
are still checked before and after publishing. The helper does not import the
CVE CLI and does not add a generic policy to unrelated Publication consumers.

## Fail-first verification

Use only owned temporary test files and existing bounded fake Docker fixtures.
Mock `fstat` exclusively for the captured parent descriptor after its actual
adoption, preserving inode/device identity and all other descriptor reads.
Independently vary the UID and group/other writable mode. No actual cross-user
ownership changes, shared processes, Docker daemon or external service is used.

For each caller, cover both bad descriptor handoffs and UID/mode policy changes
at both final boundaries. Native final cases arm failure after owned container
cleanup or just after publication; comparison cases arm it after writing the
private summary or just after publication. Require CLI exit 2, false completion
or artifact-binding status, no output directory, and retained native cleanup.
Initial native failures must issue no Docker command and create no private
temporary session; initial comparison failures must write no report.

The initial run on the unfixed callers failed all 12 policy subcases because
the CLI returned 0 instead of 2. Existing native, feature, closure, canonical
keyring and same-image comparison tests remain the contract regressions.
Run both focused files and the full tooling suite with an explicit owned Redis
binary so the Redis fixture runs instead of skipping. Retain private RED/GREEN
logs and source hashes for independent review. Unit fixtures establish local
policy behavior, not actual APT, image/native execution, vulnerability closure,
external approval, or release readiness.

Observed verification on base `afb8963`: focused native/dependency tests passed
49/49; the full tooling suite passed 272/272 in 16.140 seconds with zero skips
and the explicit disposable-process Redis 7.2.16 binary. The 12 new policy
subcases were RED before the implementation and GREEN afterward. Scoped diff
checks passed. Private logs and a source-hash freeze are retained under
`.superpowers/sdd/native-private-parent-policy-2026-10-23/` for independent
review; no actual Docker/APT/native result is inferred from these fixtures.
