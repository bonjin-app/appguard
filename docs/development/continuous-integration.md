# Local verification and CI

The workflow runs on GitHub Actions. Check the [hosted run history](https://github.com/bonjin-app/appguard/actions/workflows/verify.yml)
for the result and commit of each run. Local validation, hosted jobs and native
app/device verification establish different evidence; workflow source alone is
not a successful job receipt. Packages remain unpublished to package registries.

## Hosted Composer runtime compatibility

The [first hosted run](https://github.com/bonjin-app/appguard/actions/runs/39722189426)
on 2026-10-22 passed the core server, JavaScript client and Apple jobs, but stopped
the extended job before its SDK suites because Phar was unavailable under
Ubuntu's `php -n`. The local static PHP already included it. The workflow requested
PHP 8.5.11; the action selected PHP 8.5.12 in that run. The workflow's PHP version
below is an action input, not an assertion of the exact installed patch version.

The extended runner now keeps `-n` and probes Composer's Phar and encoding
requirements. When absent from the no-ini runtime, only Composer invocations load
Phar and, if neither iconv nor mbstring is built in, the first available shared
iconv or mbstring module. Each shared module must be a readable file at an
absolute path derived from the selected PHP runtime's
compiled extension directory; missing/relative paths fail before Composer runs.
The workflow provisions these modules with the PHP toolchain. SDK tests and their
loopback subprocess still use plain `php -n`. No user php.ini, Composer plugins or
Composer scripts are enabled. The runtime/module installation remains an explicit
operator prerequisite outside CI; the runner downloads no extensions. See the
[PHP CLI options](https://www.php.net/manual/en/features.commandline.options.php)
and [Composer 2.10.3 entry point](https://github.com/composer/composer/blob/2.10.3/bin/composer)
for the no-ini flags and Composer's encoding requirements.

## Checks and boundaries

[`.github/workflows/verify.yml`](../../.github/workflows/verify.yml) runs on push,
pull request and manual dispatch only. It has four jobs without a version matrix:

| Job | Intended checks | Toolchain |
| --- | --- | --- |
| Core server | Frozen Python/Node installs, Python/reference/Node/Java suites, package consumers, live cross-process Redis replay | Ubuntu 24.04; Python 3.11, uv 0.13.3, Node 22.23.2, Temurin Java 17; runner Maven |
| Extended server | Runner lifecycle tests; Go tests/race/vet/build; .NET locked restore/tests/build/package; PHP strict Composer lock validation/install and tests | Ubuntu 24.04; Go 1.27.3, .NET SDK 10.0.402, PHP 8.5.11 requested (8.5.12 observed in the first run), Composer 2.10.3 |
| JavaScript clients | CLI tests/local tarball; frozen Expo install, tests, TypeScript and relocated tarball verification | Ubuntu 24.04; Node 22.23.2; Expo dependencies from package-lock.json |
| Apple | Host Swift package tests, reporting Xcode and Swift versions | macOS 15 hosted image and its installed Xcode/Swift |

Jobs have 15 or 20 minute timeouts, read-only repository permissions and checkout
credential persistence disabled. Concurrency cancels superseded work on the same
branch/PR. No schedule, release/publish command, artifact upload, provider secrets,
credential provisioning or production environment is configured. Private repository
runner usage can consume account minutes; this change does not establish account
billing state. The macOS image/toolchain and Python/Java/PHP patch versions evolve;
the workflow logs their selected versions and does not promise an exact local clone.

The core job creates a new Redis **7.2.10** service container, bound to host loopback
only, disables snapshot/AOF persistence before the suites and relies on job teardown
to discard it. Never point the core runner at a shared or existing database.

Python uses `uv sync --locked`/`uv run --frozen`; npm uses `npm ci --ignore-scripts`;
.NET uses `restore --locked-mode` and subsequent `--no-restore`; Go uses
`GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly` and `GOWORK=off`; PHP installs its
committed lock with plugins/scripts and network disabled. Go and PHP currently
have no third-party runtime package dependencies. Maven uses the existing POM
pins and may fetch its declared dependencies; it has no dependency lockfile.
The dependency-free CLI has no npm lockfile/install step.

## Local commands

For Python/Node/Java, first start a **new disposable** loopback Redis with
persistence disabled, then run:

```sh
APPGUARD_TEST_REDIS_URL=redis://127.0.0.1:YOUR_UNUSED_PORT/0 \
  bash scripts/test-server-sdks.sh
```

See the root README for core runtime prerequisites and `APPGUARD_UV_CMD` /
`APPGUARD_MAVEN_CMD`. The runner does not provision or stop Redis.

For Go/.NET/PHP, install the prerequisite runtimes yourself and run:

```sh
bash scripts/test-extended-server-sdks.sh --check
bash scripts/test-extended-server-sdks.sh
```

`--check` only checks runtime execution/versions and PHP's required extensions.
It does not run SDK suites or establish package/build/CI success. The script never
installs runtimes, evaluates shell text, starts services or publishes packages.
Every override below is a single path, not a shell command with arguments. Use
absolute paths for state directories. Runtime/Composer paths containing spaces
are supported.

| Variable | Default / purpose |
| --- | --- |
| `APPGUARD_GO_CMD` | `go` from PATH |
| `APPGUARD_DOTNET` | `dotnet` from PATH; uses `sdk/dotnet/global.json` exact SDK pin |
| `APPGUARD_PHP_CMD` | `php` from PATH |
| `APPGUARD_COMPOSER_PHAR` | `composer` file from PATH; must be a readable PHP PHAR/script, not a shell wrapper |
| `APPGUARD_GO_PATH` | `sdk/go/.tools/gopath` |
| `APPGUARD_GO_CACHE` | `sdk/go/.tools/cache` |
| `APPGUARD_DOTNET_CLI_HOME` | A new temporary isolated CLI home, removed on exit; an explicitly supplied path is retained |
| `APPGUARD_NUGET_PACKAGES` | `sdk/dotnet/.tools/packages` |

Before **every .NET command**, including version checks, the runner disables
ASP.NET development-certificate generation, telemetry and first-use experience,
and selects the isolated CLI home. The workflow sets those guards before the
setup action too. PHP always runs with `-n`, loading no user php.ini or scanned ini
files. Composer alone may use the explicit modules described above.
OpenSSL/hash/JSON and a 64-bit runtime must be available without ini files.
Composer gets new temporary home/cache directories and cannot use user plugins
or network dependencies. PHP test signing uses its committed test-only OpenSSL
configuration. Go caches, .NET outputs/packages and PHP vendor output remain in
package-local ignored directories. Suite failures stop the runner and propagate
the command's exit code; temporary runner state is removed on exit.

The existing task-local runtime layout can be selected explicitly from the root:

```sh
APPGUARD_GO_CMD="$PWD/sdk/go/.tools/go/bin/go" \
APPGUARD_DOTNET="$PWD/sdk/dotnet/.tools/dotnet/dotnet" \
APPGUARD_PHP_CMD="$PWD/sdk/php/.tools/sapi/cli/php" \
APPGUARD_COMPOSER_PHAR="$PWD/sdk/php/.tools/composer.phar" \
  bash scripts/test-extended-server-sdks.sh
```

These ignored runtimes are not committed or downloaded by the runner. CI setup
actions obtain their explicitly selected runtimes in disposable hosted machines.

## Native checks kept local

The Apple job proves host Swift package behavior only. It does not run an iOS
application, Simulator or device, test hardware storage, or contact App Attest.
The Expo job checks JavaScript/TypeScript and package relocation; it does not
compile native Android/iOS bridges or boot Expo/React Native.

Android, Flutter and Unity native checks remain local-only in this workflow.
Their SDK packages have real local verification instructions and separate receipts,
but no reproducible licensed hosted toolchain was configured or exercised here:

- [Android](../../sdk/android/README.md): JDK 17, Android SDK and the pinned Gradle wrapper; host unit tests, release AAR and lint are distinct from instrumented device tests.
- [Flutter](../../sdk/flutter/VERIFICATION.md): `sdk/flutter/tool/verify.sh` with explicit Java/Android/Flutter paths; native compile and mock-messenger tests are distinct from an app runtime.
- [Unity](../../sdk/unity/VERIFICATION.md): explicit licensed Unity editor path and package-owned scratch projects; managed/native probes are distinct from an IL2CPP player.
- [Expo](../../sdk/expo/VERIFICATION.md): local CocoaPods/Android native receipts remain separate from this CI job.

No hosted job result, physical-device proof, secure hardware attestation, provider
approval, OTA, store submission or production replay guarantee follows from these
local commands or from workflow source validation.

## Workflow provenance and foundation validation

Runner labels and syntax were checked against the official
[GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
and [workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).
Every external `uses:` is pinned to the full commit resolved from its official
release tag on 2026-10-20; the readable version appears alongside the pin:
[checkout](https://github.com/actions/checkout/releases),
[setup-node](https://github.com/actions/setup-node/releases),
[setup-python](https://github.com/actions/setup-python/releases),
[setup-java](https://github.com/actions/setup-java/releases),
[setup-go](https://github.com/actions/setup-go/releases),
[setup-dotnet](https://github.com/actions/setup-dotnet/releases),
[setup-uv](https://github.com/astral-sh/setup-uv/releases) and
[setup-php](https://github.com/shivammathur/setup-php/releases).
Pins freeze action code, while runner images, image tags and upstream downloads
remain external inputs. Update pins deliberately after reviewing official releases.

Historical foundation checks (2026-10-20, before the first hosted run):

- `bash -n scripts/test-extended-server-sdks.sh`: passed.
- `python3 .github/tests/test_extended_runner.py -v`: **4/4 passed**. Stub executables check fixed arguments, paths containing spaces, guard environment, check-only behavior, fail-fast exit propagation, temporary-home cleanup, invalid arguments and missing runtimes.
- Official [actionlint v1.7.12](https://github.com/rhysd/actionlint/releases/tag/v1.7.12), downloaded into a temporary directory and checked against its release SHA-256 manifest: workflow YAML/schema/expression checks passed. SHA-256 of the Darwin arm64 archive: `aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f`. ShellCheck was not installed; Bash syntax and executable stub tests supply the local shell checks.
- Actual task-local `--check`: passed with Go 1.27.3, .NET SDK 10.0.402, PHP 8.5.11 and Composer 2.10.3.
- Full actual extended runner: passed locally with the above task-local runtimes. Go normal/race/vet/build passed; .NET 175 tests passed with 0 failures/skips, Release build 0 warnings/errors and pack succeeded; PHP strict frozen Composer validation/install, 125 corpus cases/514 assertions and 5 raw loopback HTTP requests passed. Log: ignored checksummed extended-stage evidence. These are historical local results, not hosted receipts; use the run history above for current remote results.
