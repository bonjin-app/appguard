# AppGuard Apple SDK (experimental)

A native SwiftPM library for iOS 15+ and macOS 13+. It prepares the restricted [request-v0](../../protocol/request-v0.md) HTTP envelope, signs exact bytes with an installation-specific P-256 key, and acquires opaque Apple App Attest evidence. Apache-2.0; no package or binary is published.

## Request preparation

Add the local `sdk/apple` Swift package and select its sole library product, `AppGuardApple`. No external package dependencies are required.

```swift
import AppGuardApple
import Foundation

// The application owns this tag and the corresponding enrolled key ID.
// Requiring Secure Enclave fails explicitly on unsupported hardware.
let key = try InstallationKey.getOrCreate(
    applicationTag: "com.example.app.appguard.request.v1",
    secureEnclaveRequired: true
)
let parameters = try SignatureParameters.fresh(keyID: "previously-enrolled-key-id")
let preparer = try RequestPreparer(origin: "https://api.example.test")
let input = UnsignedRequest(
    method: "POST", target: "/v1/items?b=2&a=1", body: Data("{}".utf8),
    contentType: "application/json", authorization: "Bearer YOUR_AUTH_TOKEN", appID: "your-app"
)
let signed = try preparer.prepare(input, parameters: parameters, key: key)
// Send signed.request.method/target/body and every ordered header unchanged.
let publicSPKI = try key.publicKeyPEM()
```

`SignatureParameters.fresh` reads integer Unix seconds and obtains 16 nonce bytes from `SecRandomCopyBytes`; default lifetime is 120 seconds. Explicit parameters and a fixed `now` enable reproducible tests. The preparer validates syntax, final header limits and time before hashing the body or calling the key. Input and output body values own their byte storage, including inputs originating from `Data(bytesNoCopy:)`.

The six covered components, parameter order and wire fields match [http-v0](../../protocol/http-v0.md). P-256/SHA-256 signatures are exactly 64 raw `r || s` bytes; strict DER conversion rejects malformed/nonminimal integers, invalid scalars and trailing bytes. Query ordering, duplicate query keys, percent-escape case and an explicit empty `?` are preserved. The origin is fixed trusted configuration, never derived from forwarding headers. No URL parser is used to canonicalize the target.

Limits: 1 MiB raw body, 8192 ASCII target bytes, 64 total header pairs and 16384 header name/value bytes including both signature fields, 1..128-character identifiers, 512-character origin, canonical 16-byte nonce, and at most 120-second request lifetime. Required and HTTP framing singleton duplicates reject; `Content-Length`, if provided, must equal body length. Time, target, identifier, authorization, digest, control-character and encoding checks follow the profile. `RequestProfile.signatureBase` is a low-level canonicalizer for conformance, not a verifier or time-validity result.

This package has no transport adapter. The application must ensure its HTTP stack sends the prepared target/body/header evidence unchanged; URL normalization, body encoding and retries with a reused nonce can invalidate it. Verify the actual wire behavior of the chosen URLSession/HTTP integration. Extra headers added after preparation are outside its final-size checks. A signature does not validate the Bearer token, authorize a user, enroll a key or verify attestation.

## Installation keys

`InstallationKey.getOrCreate` queries the caller's application tag across both synchronization classes. A valid existing nonsynchronized P-256 private key is reused; synchronized entries, missing synchronization metadata, ambiguous tags, wrong curve/class, unreadable keys, lookup failures, hardware mismatch, generation failures and inconsistent persistence readback fail explicitly. The API never deletes, replaces or silently rotates an existing key. Tags are UTF-8, 1..256 bytes, without controls. Concurrent callers in this process are serialized, and a reported duplicate item is reread rather than replaced. Keychain tags are not unique across processes: an app and extensions sharing a tag must coordinate initial provisioning themselves. Concurrent cross-process creation can leave an ambiguous, unusable tag; this SDK does not choose or automatically delete an entry to recover it.

Keys are generated with Security, marked permanent and accessible when unlocked on this device only. macOS uses the data-protection Keychain and requests `kSecAttrIsExtractable=false`; requesting that attribute does not establish software-key nonextractability. This SDK does not guarantee that software Keychain keys cannot be extracted through platform APIs. `.backing` distinguishes `.keychain` from `.secureEnclave`; ordinary Keychain storage is not hardware-backed signing. An explicit Secure Enclave requirement never falls back to software; actual hardware protection still requires device validation. Only public SPKI PEM export is exposed by this SDK; there is no SDK private-export API. The application's Keychain entitlements, signing and tag/rotation/enrollment lifecycle remain its responsibility.

## Enrollment and App Attest

Create an `EnrollmentChallenge` from the authenticated server's [enrollment-v0](../../protocol/enrollment-v0.md) fields, then use:

```swift
let possession = try EnrollmentProof.create(
    challenge: challenge, expectedAppID: configuredAppID, expectedSubject: authenticatedSubject,
    expectedKeyID: enrolledKeyID, expectedOrigin: "https://api.example.test", key: key
)
// Send possession.proof (raw64) and the challenge back to the authenticated server.
// possession.clientDataHash is SHA256 of the exact enrollment message.
```

The helper checks every identity/origin binding, canonical 32-byte server nonce, `now < expires <= now + 300`, and SHA-256 of the key's canonical SPKI DER before signing. It verifies the resulting proof against that public key. The exact LF-separated, domain-prefixed message has no trailing LF. `canonicalMessage()` only constructs validated bytes; it does not establish server trust. A bridge should expose these typed operations, not arbitrary-message signing.

`AppAttestClient` is `@MainActor`. Its configuration requires the explicit Apple App ID (`TeamID.BundleID`) and `.development` or `.production`, matching the application's actual entitlement. It exposes `.supported`, `.unsupported` and `.unavailable` distinctly. `generateKey()` returns the Apple key identifier, which the application must persist. `attest(keyID:challengeHash:)` and `assertion(keyID:challengeHash:)` require an exact 32-byte SHA-256 hash of server-defined challenge/request bytes. Use `possession.clientDataHash` for enrollment acquisition.

`AppAttestEvidence` contains only the opaque object and its app/environment/key/hash/operation context. Apple manages the nonexportable App Attest key separately from the installation request-signing key; it cannot export the request key's SPKI. Provider failures, unsupported service, unavailable service, invalid keys, server unavailability and malformed responses fail explicitly. The wrapper performs no automatic retry, key-ID discard or rotation. Configuration labels are not entitlement validation. The server must authenticate/decode the provider object and verify Apple identity, environment, challenge, key binding and replay/counter policy; this package makes no server-attestation-verification claim.

## Native JSON bridge

`NativeBridge().invoke(operation:payload:)` returns the fixed JSON envelope in
[client-bridge-v0](../../protocol/client-bridge-v0.md). Supported operations are `publicKey`,
`prepare`, and `enrollmentProof`. Bindings carry the exact target, canonical base64 body, and ordered
header pairs from the result; this API does not send HTTP requests, expose unrestricted signing or
private-key import/export, acquire provider evidence, or return an authorization verdict.

Every payload requires `alias` and `hardwareRequirement`. `any` uses the installation-key default;
`hardware` requires Secure Enclave without fallback; `strongbox` returns `APPGUARD_UNSUPPORTED`.
`publicKey` reports `keychain` or `secureEnclave` without claiming remote attestation. Request and
enrollment timestamps are validated against native wall-clock time. Internal ephemeral-key/clock
seams are inaccessible through the public JSON API.

The parser bounds input to 1500000 UTF-8 bytes, rejects duplicate decoded keys, unknown fields,
wrong types, non-integer numeric spellings, invalid string encodings, and noncanonical standard
padded base64. Decoded bodies are limited to 1048576 bytes. Keys load lazily, after the existing
typed SDK validates request syntax, final header limits, and enrollment identity/time bindings.
Only the fixed error code crosses the failure boundary; underlying native errors are redacted.

Eight bridge tests independently verify real ephemeral CryptoKit request/enrollment signatures and
hashes, binary/empty-query preservation, exact size boundaries, native-clock rejection, hardware
mapping, malformed input before key lookup, and redacted load/signing failures. A negative control
removing duplicate-key detection fails its regression. The bridge-stage baseline was 34 XCTest methods;
the unsigned generic iOS Simulator build passes arm64 and x86_64. No bridge test writes persistent
Keychain items or boots a Simulator. Persistent storage, physical Secure Enclave, framework runtime,
provider and store evidence remain separate requirements.

## Optional local risk hints

`LocalRiskScanner` performs a synchronous, read-only scan using public APIs. Run it off the UI thread:

```swift
let configuration = try LocalRiskConfiguration(expectedAppID: "com.example.app")
DispatchQueue.global().async {
    let report = LocalRiskScanner().scan(configuration: configuration)
    let signals = report.riskSignals.map(\.rawValue)
    // Use only as untrusted hints in an independently configured server policy.
}
```

`LocalRiskConfiguration` also accepts `protectedResources: [String: String]`, mapping relative bundle-root paths to lowercase SHA-256 hex pins. The default empty map performs no resource lookup. Pin exact deployed, untransformed app-owned bytes; build or store transformations can invalidate assumed pins. Configuration rejects invalid identifiers, pins, paths and bounds with a fixed redacted error before scanning. At most eight resources are streamed, at most 1 MiB each and 8 MiB total. Missing configured resources mean a detected mismatch; unreadable, nonregular, oversized or escaping resources are unavailable. Resolved symlinks and the opened descriptor must remain inside the app bundle.

The immutable Codable report contains exactly `schema`, `platform`, ordered `checks` (`code`, `state`), and ordered, deduplicated `riskSignals`. States are `detected`, `not_observed`, `unavailable`, and `not_configured`. Signals are `debugger`, `root`, `hook`, `tamper`, and `local_checks_unavailable`. A positive subprobe wins over unknown siblings; unknown wins over all negative observations. There is no overall clean-device verdict. Reports and descriptions contain no raw artifact paths, symbols, environment values, bundle identifiers, resource names, hashes or probe errors.

The own-process debugger probe uses the public `sysctl` example only in iOS debug builds, following Apple's [QA1361 debug-only restriction](https://developer.apple.com/library/archive/qa/qa1361/_index.html). Release builds and macOS return `unavailable` for debugger observations. Root and hook checks run only on iOS devices; macOS and Simulator return `unavailable` rather than diagnosing their host. Device heuristics examine a fixed small set of artifact existence probes, global symbols via `dlsym`, and bounded selected environment values. They never enumerate the unsafe dyld image list, load or invoke suspicious code, write files, deny debugger attachment, make network calls or touch Keychain.

These heuristics can produce false positives and be bypassed by a modified process, hidden artifacts, renamed/local symbols, stripped environment variables or replacement embedded pins. Empty signals never establish integrity, attestation, authentication or authorization. Release scans normally include `local_checks_unavailable`; server policies must explicitly decide how to handle that category. This API does not extend the JSON signing bridge.

SwiftPM copies `Sources/AppGuardApple/Resources/PrivacyInfo.xcprivacy` into its resource bundle. It declares `NSPrivacyAccessedAPICategoryFileTimestamp` reason `C617.1` for regular-file/size validation of resources inside the app bundle. Fixed external artifact probes use `access(F_OK)` and do not read external metadata. Consumers using other packaging systems must include the SDK manifest in the resulting application; verify the final archive. This declaration is not App Store approval. See [local-risk verification](LOCAL_RISK_VERIFICATION.md) for exact commands, hashes, API references and remaining evidence limits.

## Verification and public-only probes

From the repository root on macOS with Xcode selected:

```sh
swift test --package-path sdk/apple
(cd sdk/apple && xcodebuild -scheme AppGuardApple \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath .evidence/ios-deriveddata -configuration Debug \
  CODE_SIGNING_ALLOWED=NO IPHONEOS_DEPLOYMENT_TARGET=15.0 build)
swift run --package-path sdk/apple/Tools/InteropProbe InteropProbe > /tmp/apple-signed-vectors.json
swift run --package-path sdk/apple/Tools/InteropProbe InteropProbe --enrollment > /tmp/apple-enrollment-proof.json
```

The probe is a separate local executable package under `Tools/InteropProbe`; it is not an SDK product. Each invocation generates a fresh in-memory private key. Default output is eight complete conformance-shaped scenarios (six successful core corpus inputs, explicit empty query, raw binary body), with ordered wire headers, raw64 signatures, context and public SPKI. `--enrollment` emits a typed fixed synthetic challenge, proof, public SPKI and fixed trusted time. No private material is written or printed. An optional positional argument selects another corpus JSON file. Host corpus tests require this repository's `conformance/v0/requests.json`.

Observed with Xcode 27.1 (27A9275), Swift 6.4 and macOS 27.0.1:

| Evidence tier | Result |
| --- | --- |
| Host SwiftPM | 65 XCTest methods pass (34 existing and 31 local-risk tests), covering all 40 corpus canonical-base scenarios and six fixed successful CryptoKit signature checks, new signatures, limits, raw buffer ownership, DER/raw edge cases, enrollment bindings and App Attest error boundaries. |
| Native key operations | Real nonpersistent Security `SecKey` creation/signing and CryptoKit public-SPKI verification execute on the host; persistent I/O is replaced by an in-memory store in tests. |
| iOS build | Unsigned generic iOS Simulator Debug build passes for arm64 and x86_64; generic iOS device Release build passes for arm64, all with an iOS 15.0 deployment target. No Simulator is booted and no device is exercised. |
| Persistence / device / provider | Actual persistent Keychain creation/reload, Secure Enclave hardware, device runtime, entitlements, Apple provider acquisition and server verification are untested here. No accounts/profiles/user keys are changed. |

Observed RED/GREEN logs and build outputs remain locally ignored under `.evidence/`. A deliberate negative-control mutation confirms that removing raw-body copies or enrollment identity binding makes the targeted regression tests fail; the protections are restored before the final green suite. This is experimental local foundation code, without physical-device, provider, store or release evidence.

Apple API references: [Key generation](https://developer.apple.com/documentation/security/generating-new-cryptographic-keys), [Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave), [DCAppAttestService](https://developer.apple.com/documentation/devicecheck/dcappattestservice), [App Attest client/server boundary](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity).
