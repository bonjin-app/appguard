# AppGuard Expo bridge (experimental)

Native-only Expo module for the [client bridge v0 contract](./BRIDGE_CONTRACT.md). It forwards typed request preparation and enrollment possession proof to AppGuard's Android/Apple SDKs. It supplies no HTTP transport, provider evidence acquisition, attestation verdict, automatic enrollment, arbitrary signing, or private-key export.

## Supported development target

Pinned local verification: Expo **58.0.16**, React Native **0.88.0**, React **19.3.0**, Expo Modules Core **58.0.23**, Node **22.23.2**. Android requires API **26+** and Java **17**; iOS requires **16.4+** because Expo SDK 58 raises the underlying Apple SDK's iOS 15 minimum. Other Expo SDKs and platforms are unverified. This package requires a development/native build with `expo` installed. Expo Go and web have no implementation: missing native modules reject with `APPGUARD_NATIVE_UNAVAILABLE`.

The npm package is private to guard accidental registry publication during this experimental local-package stage.

## Build and install the local package

From this repository's `sdk/expo` directory:

```sh
python3 -I -B ../../scripts/dependencies/build-backports.py --check
npm ci --ignore-scripts
node ../../scripts/dependencies/build-resolver.cjs --check
python3 -I -B ../../.github/tests/test_resolver_backport.py
npm run verify:backports
npm test
npm run typecheck
npm run verify:pack
```

The checkout root declares logical `braces`, `node-forge`, and `resolve-workspace-root` as direct
`devDependencies` targeting the reviewed archives under
`tools/dependency-backports/archives/`, with exact `$braces`, `$node-forge`, and `$resolve-workspace-root`
override references to those direct specs. Keep both parts together: the root
direct archive edge avoids the importer-relative archive lookup observed with
raw relative overrides on the pinned npm toolchain. The owned metadata fixture
verified that mechanism; actual Expo lock/install/relocation verification remains
separate. These are local
**development/tooling** dependencies of this Expo verification checkout; they are
not the bridge's declared runtime dependencies. Every independent
application or other consumer root needs its own reviewed override and lock
policy. Overrides inside a transitive dependency do not protect an unrelated
application root.

`verify:backports` requires both direct-dev archive targets and exact `$` override
references, then binds the reviewed manifest, archive SHA-256/SHA-512 SRI, exact
lock locations and identities, every installed payload file (including Forge
CommonJS, browser, worker, maps and original LICENSE; resolver's four JS modules,
original declarations, LICENSE.md and identical LICENSE), and resolution from
Expo CLI, code-signing, micromatch, all three actual Expo resolver import files,
and resolver's external js-yaml/micromatch import file. The public producer script,
selected dependency lock versions/SRI and legal bytes are also bound. It resolves entrypoints without
executing the derivative exports. It fails if a dependency is absent. The separate
Python `--check` command reconstructs the complete archives from retained inputs;
JavaScript installed-file checks do not reproduce compilation or archive assembly.

Run the explicit verifier after `npm ci --ignore-scripts`; no postinstall hook is
required. Supported `build`, `typecheck`, `test` and `prepack` commands check payloads
before tooling use. `verify:pack` and direct `node scripts/verify-pack.mjs` run the
guarded prepack staging/build once, then pack with `--ignore-scripts` to avoid
repeating lifecycle work. A bare `npm pack --ignore-scripts` skips preparation and
is not a supported verification route.

The resolver is an unbundled, controlled TypeScript 6.0.3/CommonJS/ES2020 derivative
with exact js-yaml 4.3.2/micromatch 4.0.8 runtime edges. Its normal filesystem and
type fixtures copy a pinned installed dependency closure and reviewed tracked braces
archive into new roots with explicit override/payload/origin checks. Copied fixtures
prove source semantics and declaration compatibility, not npm installation or adoption.
The source-alpha change intentionally stages package metadata before the separately
reviewed lock/install update; a frozen install is not qualified at that intermediate stage.

These checks do not clear original upstream ancestry findings, original bundled
resolver lineage, or the source scan gate. They do not establish Forge
compiler reproduction, fresh/relocated actual consumer adoption, registry
publication or release approval; those require separate reviewed evidence.

`npm pack` runs a repository-only staging step that copies the sibling native SDK Java/Swift sources and their licenses into `vendor/`. `PROVENANCE.json` records the source commit and exact per-file SHA-256 values, including uncommitted native changes. The tarball contains the built JS/declarations, native adapters, both Apple podspecs, vendored sources/licenses, contract snapshot, and config plugin. Native pod metadata uses version `0.0.0`: CocoaPods' default `>= 0` requirement excludes the npm baseline prerelease `0.0.0-experimental.1`. The package remains experimental. Consumer installation does not run staging and resolves no SDK paths outside the package.

In an Expo SDK 58 app, install the resulting `appguard-expo-0.0.0-experimental.1.tgz` with `npx expo install /path/to/the/tarball`. Add `"@appguard/expo"` to `expo.plugins`, then generate/rebuild the native app and install pods as usual. Autolinking discovers the Android module and the separate `AppGuardApple` and `AppGuardExpo` pods. The config plugin raises Android's application minimum to at least 26 and iOS's deployment target to at least 16.4, preserving higher values and unrelated properties. Existing bare native projects need those same minimums applied and a native rebuild.

The staged Apple SDK privacy manifest ships in `AppGuardApplePrivacy.bundle`.
Verify its presence in your final archive. The typed `scanLocalRisk` API exposes optional local risk hints. See
[RISK_BRIDGE_VERIFICATION.md](./RISK_BRIDGE_VERIFICATION.md) for its evidence limits.

## API

```ts
import { publicKey, prepare, enrollmentProof, AppGuardError } from '@appguard/expo';

const keyOptions = { alias: 'installation', hardwareRequirement: 'any' } as const;
const key = await publicKey(keyOptions); // { publicKeyPem, backing }
```

`prepare(input)` accepts `KeyOptions` plus explicit `origin`, `method`, `target`, `body: Uint8Array`, `contentType`, complete `authorization` Bearer value, `appId`, enrolled `keyId`, integer `created`/`expires`, and canonical 16-byte base64url `nonce`. Caller supplies valid timestamps and nonce; no JavaScript key/nonce/clock fallback exists. Native SDKs validate all fields before signing. Body bytes are converted directly to canonical standard padded base64; no text conversion, URL parser, query normalizer, or header object conversion occurs.

The result is `{ origin, method, target, bodyBase64, keyId, headers: [string, string][] }`. Preserve the exact target (including an explicit empty `?`), decoded body bytes, and ordered header pairs in your HTTP integration. Prevent redirect following and automatic target rewriting; never forward Authorization to another origin. Raw body limit is 1,048,576 bytes; JSON request/response limit is 1,500,000 UTF-8 bytes.

`enrollmentProof(input)` accepts `KeyOptions`, `challenge: { appId, origin, subject, keyId, publicKeySha256, nonce, expires }`, and separate `expectedAppId`, `expectedOrigin`, `expectedSubject`, `expectedKeyId`. It returns `{ proofBase64, clientDataHashBase64, googleRequestHash }`, which are possession-proof/hash outputs, not server authorization or provider verification.

Hardware modes are `any`, `hardware`, `strongbox`. Android/Apple SDKs enforce the requirement without silent downgrade; Apple rejects `strongbox`. Returned `backing` labels describe local storage and do not prove remote attestation.

Failures throw `AppGuardError` with only a fixed `code`/message: `APPGUARD_INVALID_INPUT`, `APPGUARD_KEY_UNAVAILABLE`, `APPGUARD_UNSUPPORTED`, `APPGUARD_OPERATION_FAILED`, or `APPGUARD_NATIVE_UNAVAILABLE`. Native exception text, tokens, request body content and key material are not attached to errors.

See [VERIFICATION.md](./VERIFICATION.md) for observed build evidence and remaining runtime limitations.

## Official API references

Scaffolded with [`create-expo-module` 58.0.3](https://docs.expo.dev/more/create-expo-module/), then removed generated example/UI/web code. API choices follow the [Expo Modules API](https://docs.expo.dev/modules/module-api/), [module configuration](https://docs.expo.dev/modules/module-config/), [config plugins](https://docs.expo.dev/modules/config-plugin-and-native-module-tutorial/), and [SDK 58 support matrix](https://docs.expo.dev/versions/v58.0.0/).

## Local risk snapshot

```ts
import { scanLocalRisk, type LocalRiskReport } from '@appguard/expo';
const report: LocalRiskReport = await scanLocalRisk(); // optional checks unconfigured
const configured = await scanLocalRisk({
  expectedAppId: 'com.example.app',
  androidSignerSha256: ['a'.repeat(64)], // actual lowercase current certificate pins
  protectedResources: { 'assets/release.json': 'b'.repeat(64) }, // actual deployed bytes
});
```

Call the async API explicitly; the existing native AsyncFunction runs the scan off
its caller thread. React Native consumers need Expo Modules integration and a
native rebuild containing the updated SDK. Expo Go/web have no implementation;
missing modules reject with `APPGUARD_NATIVE_UNAVAILABLE`, and old native SDKs
reject the operation with `APPGUARD_UNSUPPORTED`. No JavaScript fallback probes,
keys, clock or network calls are used. A JavaScript/OTA update alone cannot add
the native operation.

Only `expectedAppId`, `androidSignerSha256` and `protectedResources` are accepted.
An app ID is 1..255 ASCII characters beginning with an alphanumeric character,
then alphanumeric, dot, underscore or hyphen. At most eight distinct lowercase
64-hex signer pins and eight resource paths are allowed. Paths are relative ASCII,
at most 256 characters with slash-separated components of 1..128 characters;
components start with alphanumeric, underscore or hyphen and continue with those
characters or dot. Nulls and unknown fields reject before native dispatch. Empty
arrays/maps are valid. iOS rejects nonempty Android signer pins as unsupported
after validating all options. Input is snapshotted before native work; scan JSON
input is limited to 8192 UTF-8 bytes and its response envelope to 4096 bytes.
Signing/enrollment retain their existing limits.

Reports are deeply frozen, freshly decoded values with schema
`appguard-local-risk-v0`, platform `android`/`ios`, ordered checks and deduplicated
ordered risk categories. States are `detected`, `not_observed`, `unavailable` and
`not_configured`; required checks cannot be unconfigured. Invalid/inconsistent
native reports reject with `APPGUARD_OPERATION_FAILED`, without raw response text.
These are local heuristic hints that a compromised app can forge, bypass or omit.
They do not prove a clean device or authorize a request. Treat categories as
untrusted server hints alongside independent authentication/signature/attestation
checks. The API returns no overall clean verdict, identity, pins, paths or raw
observations. Local scanner behavior is documented in the repository's
[local-risk protocol](../../protocol/local-risk-v0.md).
