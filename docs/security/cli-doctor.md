# Local build prerequisite diagnostics

2026-10-21; experimental Apache-2.0 CLI, no published package or production
readiness claim.

## Functional change

`doctor` now reports read-only local build prerequisites in addition to the
existing configuration checks. `doctor --check` makes those results usable as a
CI preflight. A valid configuration still produces a JSON report on stdout:

- Default `doctor` exits 0 even when local prerequisites fail.
- `doctor --check` exits 0 only when every required check passes, otherwise 2.
- Invalid arguments or configuration reads retain fixed errors on stderr and
  exit 1. Tool path failures become fixed diagnostic codes without path contents.

Reports retain `sdkInstalled: "not_checked"`,
`providerConfigured: "not_checked"` and `buildVerified: false`. Additive fields
are `checks: [{id, status, code}]` and `localChecksPassed`. Each listed check is
required; statuses are `pass`, `fail` or `not_checked`. Unchecked required checks
cannot pass the optional gate. A passing individual check uses `READY`.

| Platform | Check ID | Local observation |
| --- | --- | --- |
| Android | `android_protection` | Exact generated sidecar and apply line |
| Android | `android_gradle_wrapper` | Local regular executable wrapper |
| Expo | `expo_cli` | Local regular readable CLI entrypoint, no executable bit required |
| Flutter | `flutter_cli` | Regular executable selected from the target build PATH |

Android/Expo tool paths follow the existing project no-symlink policy. Flutter
PATH entries permit normal symlinked installations. Lookup continues past
unusable candidates to find an executable; if none is found, it reports the
first non-missing failure in PATH order, or `MISSING`. Empty and relative entries
resolve against the target project, not the CLI's working directory. An unset
PATH is `not_checked` / `PATH_NOT_SET`. Android/Flutter checks on Windows are
`not_checked` / `PLATFORM_UNSUPPORTED`; no Windows launch/PATHEXT inference is
made.

Other reason codes are `PROTECTION_NOT_CONFIGURED`, `NOT_REGULAR_FILE`,
`NOT_EXECUTABLE`, `UNSAFE_PATH` and `UNREADABLE`. Diagnostics use fixed IDs,
statuses and codes, without raw PATH values, tool contents or filesystem errors.

## Boundaries

Diagnosis uses filesystem metadata/access checks and existing bounded project
configuration reads. It does not execute a wrapper, CLI, Flutter binary, version
probe or shell; write project files; install dependencies; contact providers; or
configure accounts. Project files and the caller's PATH remain trusted local
inputs. This is a point-in-time diagnostic, not an atomic guarantee against a
concurrent local writer or a compromised account.

A readable/executable file does not establish a valid entrypoint, compatible tool
version, working interpreter, Android SDK, signing setup, final Gradle model,
actual source protection or successful build. The application still owns SDK
installation, provider setup and inspection of produced release artifacts.
`build --dry-run` remains a plan; build execution semantics are unchanged. The
existing Android protection check still gates build plans, while the newly
reported tool checks do not add a build gate.

Source tests and isolated local-package probes cover actual CLI subprocess exit
behavior, metadata checks, PATH handling, privacy and unchanged project snapshots.
They do not run real platform builds or establish production ingress, device,
provider, hosted CI or public registry behavior. Verification receipts and exact
source/package hashes are kept in
`.superpowers/evidence/2026-10-21-cli-doctor/` on local main.

## Local verification and review

The reviewed runtime/package source is commit
`a675ce804f4ff43ad1b0b4cc2eb57d1270407fc0`, tested with Node 22.23.2 on
macOS arm64 as the unprivileged local user.

- Baseline: all 23 CLI tests passed. Final regression tests against the unchanged
  base reproduced nine failures, with the existing 23 passing and one new
  Windows-only case skipped. An additional unreadable-Expo-entrypoint RED was
  observed before adding the access check.
- Final whole CLI suite: 33 total, 32 passed, zero failed, one Windows-only skip.
  Parent and reviewer each freshly reran the full suite. `git diff --check`
  passed.
- An offline, lifecycle-scripts-disabled local npm pack/install produced a copied
  package with all 10 file bytes and modes matching the committed source and
  tarball. Eight installed-command probes passed. The archive SHA-256 is
  `168c6d02c012ae940853edc69da3c1e3989bb19213733449281ef77ba9ab7947`.
- Independent security review found no blockers. The reviewer freshly reran the
  eight installed probes and ran eight independently written targeted cases
  against both source and installed entrypoints. All passed. Checks included
  unreadable/executable files, PATH error precedence, redaction, project snapshots
  and preservation of all-platform dry-run plans despite missing tool checks.

These tiers overlap; counts are not summed as independent scenarios. Review
inspected baseline/RED inventories without rerunning them and rehashed the
existing local package rather than packing/installing a second copy. One
intermediate test-cleanup permission failure was corrected by restoring the
fixture's permissions before removal. Its overwritten raw log is unavailable;
the observed summary and final passing results are retained explicitly.

Windows runtime, different users/ACLs and real platform builds were not tested.
This stage changes only CLI diagnosis/help, tests and documentation: build/vault
implementation, dependencies, SDKs and protocols are unchanged. The final
verification-record commit only changes this root security document, leaving the
reviewed CLI package unchanged. No remote publication, deployment, provider,
physical-device or global Codex configuration operation was performed.
