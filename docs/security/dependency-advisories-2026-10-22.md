# Dependency advisories checked 2026-10-22

The production-goal recheck on the same date still found no published fixed
version for either remaining HIGH finding. Expo58.0.17/CLI58.1.14 retain the
affected dependency ranges, so that parent update is not presented as a fix.
For node-forge, [upstream PR1159](https://github.com/digitalbazaar/forge/pull/1159)
reports additional DER/NULL validation cases beyond the earlier proposal;
[PR1161](https://github.com/digitalbazaar/forge/pull/1161) remains an unmerged
proposal. No unreviewed cryptographic patch or scanner exclusion was adopted.

The source dependency gate remains **blocked by two unfixed HIGH findings** in
the Expo development/tooling dependency graph. A compatible upstream patch
removed the third finding, CVE-2026-41907 (`uuid`). No suppression, ignored
vulnerability, dev-dependency omission, unreviewed fork, or scanner success claim
was introduced. Registry publication/release approval remains blocked by the
unresolved source gate and the other release-readiness requirements.

## Current results

| Advisory | Recorded package | Status |
| --- | --- | --- |
| CVE-2026-93687 | `braces@3.0.3` | HIGH; current official registry release remains affected; no patched release listed |
| CVE-2026-85393 | `node-forge@1.4.0` | HIGH; current official registry release remains affected; no patched release listed |
| CVE-2026-41907 | former `uuid@7.0.3` | Removed from the Expo lock and installed graph through an upstream config-plugin patch |

All three findings originated in `sdk/expo/package-lock.json`. The current
`sdk/node/package-lock.json` contains none of these three packages. That statement
is specific to these advisories and recorded inputs; it does not certify the
Node SDK or exclude future vulnerabilities.

## Applied compatible patch

Only `sdk/expo/package.json` and its lockfile changed:

```text
@expo/config-plugins 58.0.9 -> 58.0.10
  xcode 3.0.1 -> 4.0.0
    uuid 7.0.3 -> removed
```

The exact direct development pin is now `58.0.10`. Expo remains `58.0.16`,
`expo-modules-core` remains `58.0.23`, and React, React Native, TypeScript and all
other direct development requirements remain unchanged. No major Expo SDK
migration or dependency override was used.

The official [config-plugins 58.0.10 manifest](https://registry.npmjs.org/@expo%2fconfig-plugins/58.0.10)
requires `xcode ^4.0.0`. The official [xcode 4.0.0 manifest](https://registry.npmjs.org/xcode/4.0.0)
no longer depends on `uuid`; its installed implementation uses Node's
`crypto.randomUUID()`. The upstream [xcode advisory issue #177](https://github.com/apache/cordova-node-xcode/issues/177)
is closed and points to the UUID replacement work. The
[uuid maintainer advisory](https://github.com/uuidjs/uuid/security/advisories/GHSA-w5hq-g745-h8pq)
lists patched releases `11.1.1`, `12.0.1` and `13.0.1`; the chosen fix removes the
old dependency through the supported parent upgrade instead of forcing a
cross-major UUID override.

The previous xcode implementation used `uuid.v4()`, while the reported buffer
bounds defect affects the `v3()`/`v5()`/`v6()` methods. This use-path observation
was not used as an exclusion: the vulnerable package was actually removed.

## Unfixed HIGH: braces

Recorded dependency path:

```text
@appguard/expo development dependency expo@58.0.16
  @expo/metro@58.0.0
    metro-file-map@0.87.1
      micromatch@4.0.8
        braces@3.0.3
```

The [reviewed advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm)
reports stack exhaustion in deeply nested brace patterns and lists no patched
version. The [upstream issue #73](https://github.com/micromatch/braces/issues/73)
was **open** when checked. The
[official registry latest manifest](https://registry.npmjs.org/braces/latest)
still reports `3.0.3`; current `micromatch@4.0.8` still requires `braces ^3.0.3`.
Current `metro-file-map@0.87.1` still requires micromatch, so a supported parent
upgrade did not offer a fixed dependency chain at this checkpoint.

The installed `metro-file-map/src/watchers/common.js` imports micromatch and
uses `micromatch.some()` on watcher glob patterns. This is development/build
file-watching machinery. Hostile or untrusted build configuration/input remains
relevant to its availability risk. AppGuard's request verifier and native client
bridge do not directly import this package; that does not remove the finding or
establish that every Expo consumer's build inputs are trusted.

## Unfixed HIGH: node-forge

Recorded dependency paths:

```text
@appguard/expo development dependency expo@58.0.16
  @expo/cli@58.1.13
    node-forge@1.4.0
    @expo/code-signing-certificates@0.0.7
      node-forge@1.4.0 (deduplicated)
```

The [reviewed advisory](https://github.com/advisories/GHSA-86w9-cpqp-85rv)
lists versions through `1.4.0` as affected with no patched release. It describes
an RSA PKCS#1 v1.5 verification bypass involving extra nested DigestAlgorithm
elements and low-exponent keys. The maintainer-repository
[issue #1149](https://github.com/digitalbazaar/forge/issues/1149) and proposed
[fix PR #1152](https://github.com/digitalbazaar/forge/pull/1152) were both **open**
when checked. The [official registry latest manifest](https://registry.npmjs.org/node-forge/latest)
still reports `1.4.0`.

The latest available `@expo/cli@58.1.14` still requires `node-forge ^1.4.0`,
and `@expo/code-signing-certificates@0.0.7` still requires the same version
range. Upgrading the CLI alone therefore does not fix the advisory.

Installed use is real: Expo CLI's iOS code-signing support parses certificates
with node-forge. The code-signing-certificates package calls
`certificate.verify()`, `certificate.publicKey.verify()` and `csr.verify()` in
its certificate/signing workflows. Those workflows are separate from AppGuard's
own native P-256 bridge and server verification code. Operators must still
assess and protect their Expo development/signing workflow; no blanket
unreachability or non-exploitability claim is made here.

## Validation and exact limits

Fresh local checks after the patch, using Node **22.23.2** and npm **10.9.8**:

- `npm ci --no-audit --no-fund`: passed from the updated lock.
- `npm test`: **61 passed, 0 failed, 0 skipped**, including config-plugin target
  preservation/idempotency and native-source staging checks.
- `npm run typecheck`: passed.
- `npm run verify:pack`: passed; the **40-file** package was extracted elsewhere,
  its native-source hashes were checked, and its built client ran from the
  relocated package. Dependencies/node_modules were not bundled.
- The actual installed xcode 4 API generated **1000 unique 24-character uppercase
  hexadecimal project IDs** in a local probe.
- Fresh `npm ls` and whole-lock inspection confirmed that no UUID package remains
  in the installed graph or lock, and all Expo users of config-plugins resolve to
  `58.0.10`.
- A fresh snapshot of both npm package manifests/locks was cataloged with
  Syft **1.54.1**, explicitly including development dependencies. The source-lock
  coverage check matched **479/479 Expo** and **152/152 Node** recorded versioned
  entries. Optional/peer records are included; this is not proof that every
  platform artifact was installed or that native/system dependency closure was
  scanned.
- Trivy **0.76.1**, with the unsuppressed database updated
  `2026-10-22T01:15:55Z`, returned **exit 1** and exactly the two HIGH findings
  above. CVE-2026-41907 was absent. This is a deliberately failing vulnerability
  gate, not an automated security pass.

Local scan evidence was retained in the task's temporary evidence directory
`appguard-dependency-advisory-gofzc7z7`: `summary.json`, `findings.json`,
`sbom.cdx.json`, `source-lock-coverage.json` and scanner logs. The scanned Expo
lock SHA-256 is
`3c66a884a4153486c5eea1e810675ec622c0dea3c3fe127c8e84a605c4745d70`;
the Node lock SHA-256 is
`5692c8d5e0966a5184c968d531b4001d2ea0149e5570814e35028063dc503956`.
These bind this local npm snapshot. A final release candidate must run its own
source/artifact gates against its exact commit.

This patch changes build-tool dependency metadata, with unchanged tested plugin
outputs and unchanged native SDK sources. It does not establish a new Android,
CocoaPods, physical-device, provider, signing, store, or production result.
Expo consumers still receive/use Expo's own dependency graph and must maintain
it even though AppGuard's package does not bundle these development tools.

## Resolution boundary

Keep the legitimate Expo development and validation dependencies. Do not omit
them from source cataloging, suppress the advisories, or substitute unreviewed
forks merely to obtain a clean report. Recheck the upstream issues and registry
releases, adopt a compatible supported fix when available, then repeat frozen
installation, functional/package checks and the complete source/artifact scan.
A maintained security fork or independently reviewed patch would be a separate
maintenance/security commitment, not evidence that these upstream releases are
fixed. Until a reviewed resolution exists, these HIGH findings remain open and
the source vulnerability gate remains failed.

## Newly observed uv build-tool finding

The expanded candidate at `fb91e90` exposed
[GHSA-hq85-5cpj-mr62](https://github.com/astral-sh/uv/security/advisories/GHSA-hq85-5cpj-mr62)
in uv 0.13.3. The scan database classified it CRITICAL; the maintainer advisory
classifies it High. Versions before 0.13.4 trust an affected emSign root in the
bundled CA store. The official fix removes that root. CI and the container's
private build stage now pin 0.13.4, with official PyPI wheel hashes. uv is not
copied into the final gateway image. Historical verification records retain
the version actually used; they are not evidence for the corrected build.
A fresh source/image scan is required to verify remediation, and the two
unfixed Expo tool findings remain separate. No finding is suppressed.

## Native runtime and build baseline

The first real container probe passed all 12 operating checks, but the image
scan observed 319 gateway and 42 backend vulnerability records before the Redis
scan became unverified. These are partial counts, not a complete image result.
Native executable coverage remains incomplete.

Official security releases additionally showed that the initial Python 3.11.16
and Redis 7.2.10 baselines preceded available fixes. The updated profile pins
[Python 3.11.17](https://www.python.org/downloads/release/python-31117/) and
[Redis 7.2.16](https://github.com/redis/redis/releases/tag/7.2.16). The maintained
Maven 3.9.16 build image and existing Temurin 17 JRE declare 17.0.20.1+1. Official
registry index, child-manifest and config digests are recorded in
[base-images.json](../../deploy/spring-ingress/base-images.json).

CI also pins that exact Java build and the Redis service image digest, and
verifies the Redis 7.2.16 source archive SHA256
`960a8ec15e34ff40e57ff16837b26b33bd81f2da6d24497bb63de532a323a18e`
against the [official Redis hash registry](https://github.com/redis/redis-hashes).
Rebuilds, actual operating tests and fresh image scans are required; updated
versions alone do not establish zero findings or complete native coverage.
