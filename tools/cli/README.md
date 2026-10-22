# AppGuard CLI / Build (experimental)

Local Node 22+ tool, Apache-2.0, no runtime dependencies. No package has been published. From the repository root:

```sh
node tools/cli/bin/appguard.js init --project /path/to/app --app-id your-app
node tools/cli/bin/appguard.js doctor --project /path/to/app
node tools/cli/bin/appguard.js doctor --project /path/to/app --check
node tools/cli/bin/appguard.js build --project /path/to/app --dry-run
node tools/cli/bin/appguard.js build --project /path/to/app
```

`init` recognizes an Expo dependency, Flutter pubspec or Android `app/build.gradle[.kts]`. Select `--platform android|expo|flutter` if multiple candidates exist. IDs are explicit; `balanced` is the default profile (`--profile basic|balanced|strict`). Existing appguard config or release-sidecar collisions reject. A concurrent CLI init uses an exclusive project lock; a stale lock needs inspection before manual removal. Backups of files changed by init live in private `.appguard/init-UUID/` directories. Changed files are restored on a detected write failure when their current bytes still match this invocation's write. Keep the project under exclusive local control during initialization; this is not a transaction against hostile concurrent filesystem writers.

Project text must be valid UTF-8. Malformed byte sequences return `INVALID_FILE`
before initialization changes application files or creates backups; the owned init
lock is removed. The CLI does not guess or convert legacy encodings. Valid Unicode,
including literal replacement characters, BOM bytes and existing line endings,
is retained in original content and byte-identical backups when files are updated.
JSON files still follow their existing parser rules; this does not add BOM support
to JSON. See [input preservation verification](../../docs/security/cli-input-preservation.md).

Android init appends an apply statement and creates an app-specific release sidecar enabling R8 minification and resource shrinking with the optimized default rules. Existing ProGuard rules remain intact; an empty application rules file is created only if absent. Review reflection/JNI/framework keep rules for the actual application. Build runs the existing wrapper with `:app:assembleRelease` and never downloads a replacement wrapper, accepts licenses, selects signing credentials or publishes an artifact itself. Gradle may download dependencies according to the application's existing repository configuration. Mapping output normally remains in `app/build/outputs/mapping/release/` until explicitly archived; protect/ignore that original directory too.

Flutter build invokes `flutter build apk --release --obfuscate --split-debug-info=<project>/.appguard/symbols`. Supply the locally installed Flutter tool on PATH. This first CLI profile builds Android APKs; iOS release targets and Unity builds are not CLI adapters yet. Expo build uses the project's installed `node_modules/expo/bin/cli export --platform all --output-dir <project>/dist`. Production minification is the Expo default; no source-map flag is passed. Minification and Hermes bytecode do not guarantee source concealment. Existing Metro/Expo configuration can still change export behavior or emit sensitive files: inspect final output before distributing it. Expo prebuild, native release builds and EAS are separate steps.

`doctor` validates configuration and reports read-only local build prerequisites.
For Android it checks the exact generated sidecar/apply line and the local Gradle
wrapper. For Expo it checks the installed local CLI entrypoint, which Node runs
without requiring an executable bit. For Flutter it looks for an executable
`flutter` on the build's PATH without running it. Required checks and their fixed
reason codes appear in `checks`; `localChecksPassed` is true only when every
required check passes. No project files or build tools are changed by diagnosis. Android project paths follow the existing no-symlink policy. For Expo, the
`node_modules` root must be an ordinary directory; the `expo` package entry may
link to a directory strictly inside its canonical dependency tree, supporting
local pnpm installations. The package's `bin` and CLI file may not be symlinks.
Doctor does not execute the resolved file; actual build passes that checked path
to Node. External/hoisted packages, linked dependency roots and external virtual
stores remain unsupported. See the [Expo link boundary](../../docs/security/cli-expo-links.md). Flutter PATH lookup permits normal
symlinked installations; empty or relative PATH entries are resolved against the
target project, as with a build. An unset PATH is explicitly `not_checked` with
`PATH_NOT_SET`. POSIX executability uses access checks, not a tool invocation.
Android/Flutter Windows tool checks are `not_checked` with
`PLATFORM_UNSUPPORTED`; required unchecked results also fail `--check`.

Default `doctor` remains report-only: a valid config produces a JSON report and
exit 0 even when local checks fail. `doctor --check` prints the report on stdout
and exits 2 when required local checks do not pass, so a CI job can reject missing
prerequisites. Invalid arguments or configuration reads retain fixed redacted errors on stderr
and exit 1; missing, unreadable or unsafe tool paths are reported as failed
checks with fixed codes. Diagnostics do not include raw PATH
entries or build-tool error text. Neither mode executes a build or tool version
command, installs dependencies, or contacts provider services.

A passing check establishes local prerequisite presence at that instant. It does
not evaluate the final Gradle model, tool version, Android SDK, signing readiness,
SDK installation, provider accounts, attestation, user authentication or a
successful build. The existing `sdkInstalled`/`providerConfigured` fields remain
`not_checked`; `buildVerified` remains false. A dry-run only returns the argument array. Actual builds inherit application build output, propagate nonzero exit codes, and use no shell. Windows Android wrapper execution is currently unsupported. Build logs belong to the application's toolchain and may contain its own sensitive output.

## Policy file validation

```sh
node tools/cli/bin/appguard.js policy validate --file /path/to/policy.json
```

The exact schema is `{"profile":"balanced","requireSignature":true}`. Only Basic may explicitly disable request signatures. This command validates configuration, without installing authentication, rate counters, provider verification or a policy middleware. Server decisions follow the separate [policy protocol](../../protocol/policy-v0.md).

## Encrypted mapping and symbol retention

Create a random 32-byte key in an application-owned private location. Keep it separate from archives and source control, with an independent backup/recovery policy. POSIX key files must be owned by the current user and inaccessible to group/others. No default/shared key is generated or embedded.

```sh
node tools/cli/bin/appguard.js archive \
  --source /path/to/mapping-directory --vault /private/archive-directory \
  --key-file /private/appguard-vault.key --build-id android-release-001
node tools/cli/bin/appguard.js verify-archive \
  --archive /private/archive-directory/android-release-001.agvault \
  --key-file /private/appguard-vault.key
node tools/cli/bin/appguard.js restore \
  --archive /private/archive-directory/android-release-001.agvault \
  --destination /new/private/restored-directory --key-file /private/appguard-vault.key
```

Archives use a fresh random 96-bit nonce, AES-256-GCM and authenticated version/build ID. File names and contents are encrypted. They retain at most1000 regular files/64 MiB raw bytes. Symlinks, path traversal, special files, unsafe portable names, untrusted permissions, an archive directory inside its source, and destination/ID overwrites reject. Existing source files are retained; encryption does not remove or secure the original mappings. Vault directories and restored roots are mode0700, archive/restored files0600. Authenticate and validate the complete manifest before creating any plaintext destination. Wrong keys/tampering fail closed. Relative parent directories must already exist. Keep all involved locations under exclusive local control; OS permissions and this tool are not isolation against a compromised user account. JavaScript memory is not guaranteed to be erased.

`verify-archive` authenticates the archive and validates the complete manifest
using the same rules as restore, without creating a plaintext destination. It
returns only `{"verified":true,"buildId":"android-release-001","fileCount":2,"plaintextBytes":123}`
(the counts above are illustrative). File names, contents, archive/key paths and
key bytes are omitted. Success exits 0; malformed input, wrong keys, tampering,
unsafe entries or rejected filesystem inputs exit 1 with a fixed redacted error
on stderr and no success report. Unknown or duplicate options also reject.

Verification decrypts and examines data in process memory. It does not copy,
restore, replace, delete or repair files, create temporary plaintext directories,
rotate keys or contact a service. Reads can update filesystem access times.
A successful check establishes authentication and format validity for the bytes
read at that moment; it does not establish archive freshness, the producer's
identity, backup durability, future key recovery or a successful application
release. Keep separate key backups and periodically test an actual restore in an
appropriate private location. JavaScript does not guarantee complete memory
erasure, including immutable strings and garbage-collected copies.

Core library APIs are internal to this experimental package; use the CLI to receive fixed redacted tool errors. Format version `appguard-vault-v0` has no external interoperability or long-term compatibility claim. Preserve the exact CLI version with important archives. No automatic key rotation, cloud KMS, retention deletion or public artifact upload is included.

## Local verification

```sh
npm --prefix tools/cli test
npm pack ./tools/cli --pack-destination /private/temporary-output
```

Tests exercise subprocess commands, initialization preservation/preconditions, exact argument arrays, failure propagation, authenticated round-trip/tampering/wrong keys, hostile encrypted manifests, permissions and path/size boundaries. Actual platform-build evidence is recorded separately in repository security documentation. Passing fixtures alone is not application release evidence.

Official build references: [Android R8](https://developer.android.com/topic/performance/app-optimization/enable-app-optimization), [Flutter obfuscation](https://docs.flutter.dev/deployment/obfuscate), [Expo production minification](https://docs.expo.dev/guides/minify/), [Expo CLI](https://docs.expo.dev/more/expo-cli/).
