# AppGuard Android (experimental)

A locally buildable Android library for the [request-v0](../../protocol/request-v0.md) and
[HTTP envelope](../../protocol/http-v0.md) draft. Apache-2.0. No package has been published.

The platform-neutral Java core signs exact caller-supplied bytes with P-256/SHA-256.
`AndroidInstallationKey` keeps installation private keys in Android Keystore; `JcaSigningKey`
accepts a caller-owned JCA key pair for host integrations/tests and makes no hardware claim.
Neither adapter offers a private-key export API. Public export is an explicit SPKI PEM.

## Prepare and send

```java
AndroidInstallationKey key = AndroidInstallationKey.getOrCreate(
    context, "appguard-installation-v1", AndroidInstallationKey.Requirement.ANY_KEYSTORE);
String publicPem = key.publicKeyPem(); // enroll through your authenticated server flow
String enrolledKeyId = "server-issued-key-id"; // not the local alias
RequestSigner.Input input = RequestSigner.Input.fresh(
    "POST", "/v1/items?b=2&a=1", rawBodyBytes,
    "application/json", "Bearer " + accessToken,
    "your-app-id", enrolledKeyId, "https://api.example.test");
RequestSigner.Prepared prepared = new RequestSigner().prepare(input, key);
```

Send `prepared.method()`, `prepared.target()`, `prepared.body()` and **all ordered**
`prepared.headers()` to the configured HTTPS origin. The six headers are Content-Type,
Content-Digest, Authorization, AppGuard-App-Id, Signature-Input and Signature. The algorithm,
coverage, label, tag, and parameter order are fixed. Returned body bytes are defensive copies;
headers are immutable. Inputs are validated before hashing or invoking the signing key.
Wire ECDSA is strict 64-byte unsigned `r || s`; provider DER is validated and converted.

The SDK does not send requests. Select a transport that preserves the exact origin-form target,
query order, duplicate parameters, percent-escape case and an explicit empty query. Do not
reconstruct, normalize or re-encode targets; do not serialize, compress or change a signed body.
Transport-added framing must be unambiguous and must describe the same raw body. Never
forward the prepared Authorization or signatures to a redirected origin. Request signatures
prove possession of an enrolled key; the server still authenticates the Bearer token, binds app,
subject and public key, checks trusted time, and atomically rejects nonce replays.

`Input.fresh` uses the OS CSPRNG for a 16-byte nonce, the device integer Unix-second clock,
and a 120-second expiry. The explicit `Input` constructor accepts a canonical nonce and
created/expires for deterministic callers/tests; it validates range and a 1..120-second lifetime.
The server independently decides expiry and allowed clock skew. Device time is not an
attested or trusted server clock.

Limits match the draft: 1 MiB raw body, 8192 ASCII target bytes, 1..128-character app/key
identifiers, lowercase configured HTTPS DNS origin, printable header values and 16 KiB total
header-name/value bytes including the generated signature envelope. This preparation API
emits exactly six fields and does not accept arbitrary unsigned headers.

## Installation-key policy

Use a stable app-owned alias and an authenticated enrollment flow. The alias and server-enrolled
key ID are separate inputs. Access is serialized using a process lock and an app-private no-backup
file lock shared by SDK callers in the same application; lock contention fails explicitly. Code
outside this SDK that manipulates the same alias must honor that lifecycle and lock.

An existing alias is inspected and reused only if it is a generated, usable P-256 EC private key
with SHA-256 signing authorization and a matching public key. Finite-use keys reject before
the self-check can consume a use or trigger platform deletion. Restricted/unusable/wrong-type
keys reject. The SDK never deletes or replaces an existing alias, including after a lookup,
validation, generation, hardware-policy, or signing failure. A newly generated key can remain
under its alias when a subsequent requirement check fails; rotation/deletion and server
revocation are explicit application responsibilities.

`backing()` reports SOFTWARE, TRUSTED_ENVIRONMENT, STRONGBOX, HARDWARE_UNSPECIFIED,
or UNKNOWN from Android KeyInfo. ANY_KEYSTORE allows software; HARDWARE_REQUIRED accepts
only a confirmed hardware result. On API 26–30 the older hardware boolean cannot identify
StrongBox, so STRONGBOX_REQUIRED is unavailable. On API 31+ it requires the StrongBox feature,
requests StrongBox explicitly for generation, and confirms the resulting security level.
Failures never retry using weaker storage. These are local platform reports, not remote
attestation verdicts. Calling applications must not present emulator/software keys as hardware.

No Play Integrity acquisition or server verification is included. A real integration requires a
configured Google Cloud project, the official Play Integrity dependency and provider-capable
distribution/device flow. An opaque acquired token would remain untrusted until the server
verifies it and its request binding. This library does not simulate successful provider evidence,
enroll keys automatically, or establish authorization, device integrity, hardware attestation,
physical-device support, or store approval.

## Enrollment proof

`EnrollmentProof.create(challenge, expectedAppId, expectedOrigin, expectedSubject,
expectedKeyId, now, key)` implements the dedicated
[enrollment-v0](../../protocol/enrollment-v0.md) operation. `Challenge` holds app ID, origin,
subject, key ID, lowercase public-SPKI SHA-256 fingerprint, canonical 32-byte nonce, and expiry.
All configured identity/origin bindings, syntax, key fingerprint, and the server challenge
freshness window (`now < expires <= now + 300`) are checked before signing. The supplied
`now` is the caller's integer Unix-second observation; servers independently recheck their clock.

The key must implement `RequestSigner.PublicSigningKey`; both concrete adapters export only
public SPKI DER copies through `publicKeySpki()`. Noncanonical DER, wrong curves and mismatched
fingerprints reject. `Result.proof()` is raw 64-byte P-256/SHA-256 proof, `clientDataHash()` is
SHA-256 of the exact domain-separated message, and `googleRequestHash()` is canonical
unpadded base64url of that hash. Results return byte copies. These hashes can bind a real
provider acquisition; they do not acquire evidence or establish a provider verdict. A bridge
should expose this validated operation, not an unrestricted arbitrary-message signing endpoint.

## Native JSON bridge

`new NativeBridge(context).invoke(operation, payloadJSON)` returns one JSON string under the
[client-bridge-v0 contract](../../protocol/client-bridge-v0.md). Operations are exactly `publicKey`,
`prepare`, `enrollmentProof`, and `scanLocalRisk`. The framework binding must carry signing results without rebuilding
signed targets, binary bodies, or ordered headers. There is no HTTP transport or unrestricted sign,
private-key import/export, provider acquisition, or authorization verdict operation.

The three signing/enrollment payloads require `alias` and `hardwareRequirement`: `any`, `hardware`, or `strongbox` map to
`ANY_KEYSTORE`, `HARDWARE_REQUIRED`, and `STRONGBOX_REQUIRED`. The installation-key adapter owns
storage checks and fails closed; returned `backing` is its explicit native enum label. The bridge
uses native wall-clock time to reject expired requests and creation more than 30 seconds ahead.
Callers supply explicit integer timestamps and canonical nonces, rather than a JavaScript clock.

The boundary accepts at most 1500000 UTF-8 bytes and 1048576 decoded body bytes. It rejects unknown
fields, duplicate decoded JSON keys (including escaped aliases), coercible/wrong types, non-integer
number spelling, malformed strings, and noncanonical padded standard base64. A lazy key handle lets
the typed SDK reject request syntax, final header limits, and enrollment bindings before persistent
key access where possible. Responses contain either `ok: true` with the documented result, or
`ok: false` with only a fixed error code; native exception messages never cross the bridge.

Observed bridge verification: 9 host tests plus the existing 18 host tests pass; release AAR and
lint pass, with the existing AGP/AndroidX version-update warnings. Real ephemeral JCA request and
enrollment signatures are independently verified. Exact body/JSON boundaries, binary bodies, empty
queries, invalid input before key lookup, hardware mapping, native-clock rejection, and redacted
key/signing failures are covered. Disabling duplicate-key rejection makes its regression fail.
These host bridge tests do not exercise actual Android Keystore or framework/device runtime.

`scanLocalRisk` accepts optional `expectedAppId`, `androidSignerSha256` and
`protectedResources`, default `{}`. It validates all configuration before probing
and performs no key or clock access. Scan JSON input/envelope limits are 8192/4096
UTF-8 bytes. See [risk bridge verification](RISK_BRIDGE_VERIFICATION.md) for the
current 108 unit executions and three isolated native runtime tests. These tests
do not establish framework engine runtime or physical-device root/hook efficacy.

## Build and verification

Requires Java 17, Android SDK platform 36, and build-tools 35.0.0 already installed/licensed.
The package pins minSdk 26, AGP 8.10.1 and Gradle 8.11.1. Gradle's official distribution SHA-256
is pinned in `gradle/wrapper/gradle-wrapper.properties`. No license acceptance or global Android
configuration changes are part of this build. Keep local dependencies/caches in ignored `.tools/`:

```sh
cd sdk/android
ANDROID_HOME=/path/to/Android/sdk GRADLE_USER_HOME="$PWD/.tools/gradle-home" \
  ./gradlew --no-daemon testDebugUnitTest assembleRelease lintRelease
```

The local AAR is `build/outputs/aar/appguard-android-release.aar`; it contains no test probe or
conformance private keys. Host tests exercise literal corpus bases/wire headers, invalid input
rejection before signing, body/header immutability, strict DER scalar handling and independently
verified ephemeral JCA signatures. They do not execute Android Keystore.

Instrumentation APKs use an isolated debug signing key under `.tools/`, created by
`scripts/prepare-test-keystore.sh`; the build does not use the global Android debug keystore.

Instrumented `InstallationKeyTest` runs real Android Keystore operations under fresh UUID aliases
inside the test APK's UID and deletes only those test aliases. It checks generation/reuse,
non-exportability, actual local backing, signatures, wrong existing aliases and fail-closed
StrongBox requirements. Build the test APK and install/run it only on an explicitly owned test
emulator/device; never use broad connected-device commands against unrelated devices:

```sh
ANDROID_HOME=/path/to/Android/sdk GRADLE_USER_HOME="$PWD/.tools/gradle-home" \
  ./gradlew --no-daemon assembleDebugAndroidTest
adb -s YOUR_ISOLATED_TEST_SERIAL install -r build/outputs/apk/androidTest/debug/appguard-android-debug-androidTest.apk
adb -s YOUR_ISOLATED_TEST_SERIAL shell am instrument -w \
  io.appguard.android.test/androidx.test.runner.AndroidJUnitRunner
```

The tests run without Google provider services. Emulator results establish virtual Android
Keystore behavior only; hardware and real-device/provider behavior require separate evidence.

### Public interoperability probe (test only)

```sh
./scripts/signer-probe.sh > /tmp/appguard-android-public-fixture.json
```

This command needs only Java 17. It generates an ephemeral P-256 JCA key in memory and emits
one JSON object shaped like `conformance/v0/requests.json`: request, parameters, signature_b64,
public key record, context and expected result. It uses the fixed corpus method, target, body,
timestamps, nonce and test-only Bearer token, plus the newly generated public key and signature.
It prints no private key. It is outside shipped AAR sources and must not be used as enrollment
or production evidence.

Official sources checked for this package:
[AGP 8.10 compatibility](https://developer.android.com/build/releases/agp-8-10-0-release-notes),
[Android Keystore](https://developer.android.com/privacy-and-security/keystore),
[KeyInfo security levels](https://developer.android.com/reference/android/security/keystore/KeyInfo#getSecurityLevel()),
[StrongBox generation](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setIsStrongBoxBacked(boolean)).

## Optional local risk hints

```java
LocalRiskScanner.Config config = new LocalRiskScanner.Config(
    "io.example.app",                        // optional expected application ID
    Collections.singleton(currentSignerSha256), // optional lowercase SHA-256 pins
    Collections.singletonMap("rules.bin", resourceSha256)); // optional assets
LocalRiskScanner.Report hints = new LocalRiskScanner(context).scan(config);
String json = hints.toJson();
```

Call synchronously off the UI thread. `new LocalRiskScanner.Config()` leaves
identity, signer and asset checks `not_configured`. `Report.checks()` is an
immutable ordered map from fixed check codes to `LocalRiskScanner.State`;
`riskSignals()` is an immutable ordered list compatible with existing policy
categories. `toJson()` emits only `schema`, `platform`, `checks` and `riskSignals`.
There is no clean-device flag. Empty signals do not establish integrity.

Configuration is validated before observations. Expected app IDs use 1–255 ASCII
characters; signer pins are at most eight lowercase 64-character SHA-256 hashes.
Every current APK signer must be pinned (API 28+ current APK signers, never signing
history; API 26/27 legacy current signatures). Assets are at most eight relative
paths, each at most 256 ASCII characters with safe components of at most 128;
no absolute paths, traversal, empty segments or backslashes. Each asset read is
limited to 1 MiB. Pin exact deployed untransformed app-owned bytes.

The scanner reads only public debug/application/signature APIs, fixed root
artifact metadata, bounded own-process proc files and configured AssetManager
assets. It performs no network, shell, write, package inventory or permission
request. A positive subprobe wins over sibling failures; otherwise a failed,
denied, malformed or truncated observation is `unavailable` and also emits
`local_checks_unavailable`. Missing configured assets are mismatches. Configure
that health signal explicitly if server policy needs to react to unavailable
checks. No authentication, signing or authorization behavior changes implicitly.

Root and hook checks are incomplete heuristics that can be bypassed or modified
along with the application and its pins. See `LOCAL_RISK_VERIFICATION.md` for
host, build and runtime evidence; tests do not prove rooted/hooked device efficacy.
