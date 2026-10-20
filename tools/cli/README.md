# AppGuard CLI / Build (experimental)

Local Node 22+ tool, Apache-2.0, no runtime dependencies. No package has been published. From the repository root:

```sh
node tools/cli/bin/appguard.js init --project /path/to/app --app-id your-app
node tools/cli/bin/appguard.js doctor --project /path/to/app
node tools/cli/bin/appguard.js build --project /path/to/app --dry-run
node tools/cli/bin/appguard.js build --project /path/to/app
```

`init` recognizes an Expo dependency, Flutter pubspec or Android `app/build.gradle[.kts]`. Select `--platform android|expo|flutter` if multiple candidates exist. IDs are explicit; `balanced` is the default profile (`--profile basic|balanced|strict`). Existing appguard config or release-sidecar collisions reject. A concurrent CLI init uses an exclusive project lock; a stale lock needs inspection before manual removal. Backups of files changed by init live in private `.appguard/init-UUID/` directories. Changed files are restored on a detected write failure when their current bytes still match this invocation's write. Keep the project under exclusive local control during initialization; this is not a transaction against hostile concurrent filesystem writers.

Android init appends an apply statement and creates an app-specific release sidecar enabling R8 minification and resource shrinking with the optimized default rules. Existing ProGuard rules remain intact; an empty application rules file is created only if absent. Review reflection/JNI/framework keep rules for the actual application. Build runs the existing wrapper with `:app:assembleRelease` and never downloads a replacement wrapper, accepts licenses, selects signing credentials or publishes an artifact itself. Gradle may download dependencies according to the application's existing repository configuration. Mapping output normally remains in `app/build/outputs/mapping/release/` until explicitly archived; protect/ignore that original directory too.

Flutter build invokes `flutter build apk --release --obfuscate --split-debug-info=<project>/.appguard/symbols`. Supply the locally installed Flutter tool on PATH. This first CLI profile builds Android APKs; iOS release targets and Unity builds are not CLI adapters yet. Expo build uses the project's installed `node_modules/expo/bin/cli export --platform all --output-dir <project>/dist`. Production minification is the Expo default; no source-map flag is passed. Minification and Hermes bytecode do not guarantee source concealment. Existing Metro/Expo configuration can still change export behavior or emit sensitive files: inspect final output before distributing it. Expo prebuild, native release builds and EAS are separate steps.

`doctor` validates the config and, for Android, exact generated sidecar/apply-line content. It does not evaluate the final Gradle model, install SDKs, configure provider accounts, verify attestation, authenticate users or prove a successful build. Its `sdkInstalled`/`providerConfigured` fields are explicitly `not_checked`; `buildVerified` is false. A dry-run only returns the argument array. Actual builds inherit application build output, propagate nonzero exit codes, and use no shell. Windows Android wrapper execution is currently unsupported. Build logs belong to the application's toolchain and may contain its own sensitive output.

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
node tools/cli/bin/appguard.js restore \
  --archive /private/archive-directory/android-release-001.agvault \
  --destination /new/private/restored-directory --key-file /private/appguard-vault.key
```

Archives use a fresh random 96-bit nonce, AES-256-GCM and authenticated version/build ID. File names and contents are encrypted. They retain at most1000 regular files/64 MiB raw bytes. Symlinks, path traversal, special files, unsafe portable names, untrusted permissions, an archive directory inside its source, and destination/ID overwrites reject. Existing source files are retained; encryption does not remove or secure the original mappings. Vault directories and restored roots are mode0700, archive/restored files0600. Authenticate and validate the complete manifest before creating any plaintext destination. Wrong keys/tampering fail closed. Relative parent directories must already exist. Keep all involved locations under exclusive local control; OS permissions and this tool are not isolation against a compromised user account. JavaScript memory is not guaranteed to be erased.

Core library APIs are internal to this experimental package; use the CLI to receive fixed redacted tool errors. Format version `appguard-vault-v0` has no external interoperability or long-term compatibility claim. Preserve the exact CLI version with important archives. No automatic key rotation, cloud KMS, retention deletion or public artifact upload is included.

## Local verification

```sh
npm --prefix tools/cli test
npm --prefix tools/cli pack --pack-destination /private/temporary-output
```

Tests exercise subprocess commands, initialization preservation/preconditions, exact argument arrays, failure propagation, authenticated round-trip/tampering/wrong keys, hostile encrypted manifests, permissions and path/size boundaries. Actual platform-build evidence is recorded separately in repository security documentation. Passing fixtures alone is not application release evidence.

Official build references: [Android R8](https://developer.android.com/topic/performance/app-optimization/enable-app-optimization), [Flutter obfuscation](https://docs.flutter.dev/deployment/obfuscate), [Expo production minification](https://docs.expo.dev/guides/minify/), [Expo CLI](https://docs.expo.dev/more/expo-cli/).
