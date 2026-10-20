# AppGuard Unity client (experimental)

Typed UPM bindings for Unity 6000, Android API 26+ and iOS 15+. The native SDK owns input validation, installation keys and cryptography. The public managed API offers only `PublicKey`, `Prepare`, and `EnrollmentProof`. No network transport, private-key export, arbitrary signing, automatic enrollment or attestation verdict is provided.

## Local installation

No AAR, XCFramework, or published package is distributed by this source directory. Stage a standalone package and build its native dependencies first:

```sh
python3 sdk/unity/Tools~/stage.py --destination /absolute/task-scratch/appguard-unity
cd /absolute/task-scratch/appguard-unity
# iOS requires installed Xcode. Android requires JDK 17 and Android SDK 36.
JAVA_HOME=/path/to/jdk17 ANDROID_HOME=/path/to/android-sdk \
  python3 Tools~/build-native.py --platform all
```

`--platform ios` and `--platform android` are available separately. Gradle may download its checksummed wrapper and pinned build plugin. Builds use the copied `Native~/Dependencies` sources and package-local caches. `SOURCE-MANIFEST.json` records staged input hashes. Paths to the original repository are unnecessary after staging. `Native~` and `Tools~` are excluded from Unity asset import so test Swift sources cannot enter a player.

Add the resulting local folder through Unity Package Manager **Add package from disk**, selecting `package.json`. Unity resolves the declared Newtonsoft JSON and Android JNI module dependencies. Configure Android minimum API 26 and iOS target 15 or later in Player Settings. The Android AAR carries consumer R8 rules preserving the JNI facade. The iOS XCFramework carries static Swift libraries for arm64 devices and arm64/x86_64 Simulators. The export postprocessor enables Swift runtime embedding and adds a small Swift source to UnityFramework. Do not add the raw native Swift sources to Xcode alongside this XCFramework.

The iOS export postprocessor resolves the installed UPM package and copies its staged Apple privacy manifest into `Libraries/AppGuardPrivacy.bundle`. It adds this folder reference to the main app Resources phase; host and UnityFramework manifests remain separate. Keep `Native~/Dependencies` in the installed package and restage older packages that lack the manifest. Export and iOS native build fail early if that staged input is missing.

The native bridge executes synchronously. Call from Unity's main thread for Android JNI/activity access. Keep your application's alias stable and use the returned backing label explicitly. `HardwareRequirement.Hardware` never silently downgrades, and Apple rejects `StrongBox`.

```csharp
using AppGuard;
var client = new Client();
var publicKey = client.PublicKey("my.installation", HardwareRequirement.Any);
var signed = client.Prepare(new PrepareRequest {
    Alias = "my.installation", HardwareRequirement = HardwareRequirement.Any,
    Origin = "https://api.example", Method = "POST", Target = "/resource?",
    Body = new byte[] { 0, 255, 128 }, ContentType = "application/octet-stream",
    Authorization = "Bearer " + accessToken, AppId = appId, KeyId = enrolledKeyId,
    Created = createdUnixSeconds, Expires = expiresUnixSeconds, Nonce = nonceBase64Url
});
// Send signed.Body and ordered signed.Headers unchanged to signed.Origin + signed.Target.
// Disable redirects and target rewriting; never replay Authorization to another origin.
```

`EnrollmentProof(new EnrollmentRequest { Alias = ..., Challenge = new EnrollmentChallenge { AppId = ..., Origin = ..., Subject = ..., KeyId = ..., PublicKeySha256 = ..., Nonce = ..., Expires = ... }, ExpectedAppId = ..., ExpectedOrigin = ..., ExpectedSubject = ..., ExpectedKeyId = ... })` returns the possession proof and hashes. Obtain the challenge and enrollment identity from your server. This does not acquire provider attestation or decide server authorization.

`PrepareRequest.Body` is required, including `Array.Empty<byte>()`. Exact target strings, explicit empty queries, binary body bytes and ordered header pairs survive the bridge. Input JSON is bounded to 1,500,000 UTF8 bytes and decoded bodies to 1,048,576 bytes. Native SDK validation remains authoritative for origin, methods, timestamps, encodings and challenge bindings.

Failures throw `AppGuardException` containing only a fixed `Code` and message. Unexpected exception text is discarded. Editor and other unsupported platforms return `APPGUARD_UNSUPPORTED`; missing iOS entry points/libraries return `APPGUARD_NATIVE_UNAVAILABLE`. There is no Editor/software-crypto substitute. A native response pointer is copied with a strict UTF8 bound and freed exactly once, including decode failures; managed code never exposes that pointer.

## Verification

```sh
python3 Tools~/test-managed.py --unity /Applications/Unity/Hub/Editor/6000.3.24f1/Unity.app/Contents/MacOS/Unity
sh Tools~/test-native.sh
# After staging a package, exercise the actual Unity PBX export API:
python3 Tools~/test-ios-export.py --unity /Applications/Unity/Hub/Editor/6000.3.24f1/Unity.app/Contents/MacOS/Unity --staged-package /absolute/task-scratch/appguard-unity
```

These create only this package's ignored `.tools` and `.evidence` folders. The managed runner uses a separate scratch project and compiles the Android JNI, iOS P/Invoke and iOS export postprocessor branches. The native ownership harness substitutes the facade to avoid persistent key operations. See [VERIFICATION.md](VERIFICATION.md) for observed evidence and missing runtime coverage. No signing, store publication, physical-device behavior or provider decision is established by these checks.
