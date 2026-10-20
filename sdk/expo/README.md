# AppGuard Expo bridge (experimental)

Native-only Expo module for the [client bridge v0 contract](./BRIDGE_CONTRACT.md). It forwards typed request preparation and enrollment possession proof to AppGuard's Android/Apple SDKs. It supplies no HTTP transport, provider evidence acquisition, attestation verdict, automatic enrollment, arbitrary signing, or private-key export.

## Supported development target

Pinned local verification: Expo **58.0.16**, React Native **0.88.0**, React **19.3.0**, Expo Modules Core **58.0.23**, Node **22.23.2**. Android requires API **26+** and Java **17**; iOS requires **16.4+** because Expo SDK 58 raises the underlying Apple SDK's iOS 15 minimum. Other Expo SDKs and platforms are unverified. This package requires a development/native build with `expo` installed. Expo Go and web have no implementation: missing native modules reject with `APPGUARD_NATIVE_UNAVAILABLE`.

The npm package is private to guard accidental registry publication during this experimental local-package stage.

## Build and install the local package

From this repository's `sdk/expo` directory:

```sh
npm ci --ignore-scripts
npm test
npm run typecheck
npm run verify:pack
```

`npm pack` runs a repository-only staging step that copies the sibling native SDK Java/Swift sources and their licenses into `vendor/`. `PROVENANCE.json` records the source commit and exact per-file SHA-256 values, including uncommitted native changes. The tarball contains the built JS/declarations, native adapters, both Apple podspecs, vendored sources/licenses, contract snapshot, and config plugin. Native pod metadata uses version `0.0.0`: CocoaPods' default `>= 0` requirement excludes the npm baseline prerelease `0.0.0-experimental.1`. The package remains experimental. Consumer installation does not run staging and resolves no SDK paths outside the package.

In an Expo SDK 58 app, install the resulting `appguard-expo-0.0.0-experimental.1.tgz` with `npx expo install /path/to/the/tarball`. Add `"@appguard/expo"` to `expo.plugins`, then generate/rebuild the native app and install pods as usual. Autolinking discovers the Android module and the separate `AppGuardApple` and `AppGuardExpo` pods. The config plugin raises Android's application minimum to at least 26 and iOS's deployment target to at least 16.4, preserving higher values and unrelated properties. Existing bare native projects need those same minimums applied and a native rebuild.

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
