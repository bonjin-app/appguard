# Optional Android Play Integrity acquisition

Experimental, separate Android library. Minimum Android API 26, Java 17, official `com.google.android.play:integrity:1.6.0`. This dependency is not added to `sdk/android` or any existing bridge/package. Include this module explicitly in the application build when adopting Play Integrity.

```java
import io.appguard.playintegrity.PlayIntegrityAcquirer;
import io.appguard.playintegrity.PlayIntegrityResult;

// Configured Google Cloud project NUMBER linked to the app in Play Console.
PlayIntegrityAcquirer acquisition = PlayIntegrityAcquirer.create(context, cloudProjectNumber);
// Existing sdk/android EnrollmentProof.Result.googleRequestHash() supplies this value.
// canonical unpadded base64url(SHA256(exact enrollment_message bytes)); 32 bytes.
acquisition.acquire(challengeHash).addOnSuccessListener(result -> {
    if (result.state() == PlayIntegrityResult.State.EVIDENCE_AVAILABLE) {
        // Send bytes as opaque enrollment evidence alongside the signing proof.
        sendEnrollmentEvidence(result.opaqueEvidence());
    } else {
        showFixedError(result.errorCode());
    }
});
```

`EVIDENCE_AVAILABLE` means token acquisition completed. It does not mean an app, device, request signing key, or secure hardware was verified. The backend authenticates the token through Google's decode API and checks its exact request hash and policy. Never accept client `verified` labels. Keep the installation signing proof as a separate step.

Input must be the server enrollment message's SHA256, not the random challenge alone, request-signing hash, or caller-chosen text. The message binds the app, authenticated subject, origin, signing SPKI, key ID, nonce and expiry. A canonical 43-character base64url encoding of 32 bytes is required; padded or noncanonical aliases are rejected before any provider call.

Acquisition prepares a fresh Standard token provider per call, then requests one token with the configured project number. Use only for occasional enrollment, and avoid retry loops or parallel warmups: Google limits preparation calls. This module does not persist token providers, automatically retry, show Play remediation dialogs, or impose a UI deadline. The host app owns cancellation/UI timeout and may create a new acquisition attempt after a provider outage; no outage becomes successful evidence.

Results expose `state`, fixed `errorCode`, the original `requestHash`, and a defensive copy of UTF8 `opaqueEvidence` only on acquisition success. Token size is capped at 64 KiB. Failed/canceled/throwing provider tasks produce `UNAVAILABLE`; missing/unsupported/outdated Play services can produce `UNSUPPORTED`. Raw provider exception messages and causes are not returned. Never log the token or send evidence to analytics.

Local verification (Java 17 and installed Android SDK):

```sh
ANDROID_HOME=/path/to/Android/sdk ./gradlew test assembleDebug --no-daemon
```

Tests inject the official Google Task/manager boundary. Android service/Looper behavior is stubbed in JVM tests. Compilation and these offline tests do not prove Play Console linking, credentials, service quotas, Play-installed app recognition, device integrity, or genuine-token verification. No emulator or physical-device tests have been run for this module.

Official references: [setup and version](https://developer.android.com/google/play/integrity/setup), [Standard token acquisition](https://developer.android.com/google/play/integrity/standard), [errors](https://developer.android.com/google/play/integrity/reference/com/google/android/play/core/integrity/model/StandardIntegrityErrorCode), and [published 1.6.0 POM](https://dl.google.com/dl/android/maven2/com/google/android/play/integrity/1.6.0/integrity-1.6.0.pom).
