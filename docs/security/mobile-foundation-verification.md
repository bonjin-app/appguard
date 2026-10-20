# Native client, enrollment and policy verification

Date: 2026-10-20. Branch `codex/appguard-mobile-foundation`, based on the locally tested server SDK commit `2e26241`. Apache-2.0, experimental local packages; no registry publication, deployment, physical-device or provider-verification claim.

## Executed evidence

| Layer | Observed result | What it proves |
| --- | --- | --- |
| Full server compatibility command | 831 passed, zero failures/skips: reference209 + Python251 + Node258 + Spring113 | Existing request/HTTP corpora, frameworks, live disposable Redis and new Python enrollment/policy/audit remain green |
| Android host | 18 passed; release AAR and lint succeeded | Java/JCA request/enrollment primitives, strict encodings, before-sign validation and body ownership; two dependency-update lint warnings remain |
| Android isolated emulator | 7 passed, including a separate parent rerun | Real API35 **software** Android Keystore creation/reuse, public-only interface, existing-key preservation, StrongBox rejection and enrollment proof behavior |
| Apple host | 26 XCTest methods passed after review fixes | All40 canonical corpus rows, six fixed signature checks, generated signatures, buffer ownership, DER/raw, enrollment, provider boundary and synchronized-alias query regression |
| Apple build | Unsigned generic iOS Simulator build, arm64 + x86_64, iOS15 deployment target | Compilation/linking of the native SDK for those targets, without booting or using a Simulator |
| Python wheel | Isolated virtual environment, Python `-I`, actual site-packages imports | Enrollment store imports independently; default Balanced service and default missing-auth policy deny unsafe operation; audit output remains allowlisted |

These total882 tests across suites; counts overlap in shared scenarios and do not represent882 distinct attack classes. Swift corpus loops are counted as XCTest methods, not multiplied by their input rows. Native probes below are additional integration checks.

The parent ran `scripts/test-server-sdks.sh` with a newly owned, protected localhost Redis7.2.10 service, persistence disabled. All three rotating first-claim cases and the concurrent Python/Node/Java process race passed. Only unique probe keys were deleted; no existing database was used. An initial background-service lifecycle mistake caused three connection setup errors, was diagnosed, and was corrected with an owned daemonized service before the successful complete rerun.

## Native interoperability

Eight fresh Apple request cases (six successful core inputs, explicit empty query and raw binary body) and one fresh Android/JCA case were consumed by **all three** existing server implementations. Each consumer parsed the actual wire envelope, checked typed agreement, verified the signature, rejected nonce replay and rejected independent body/target/Authorization mutations. The probes use newly generated ephemeral keys and export only public fixture material.

```sh
uv run --frozen --project sdk/python python scripts/verify_client_vector.py \
  /path/to/apple-signed-vectors.json /path/to/android-public-fixture.json
uv run --frozen --project sdk/python python scripts/verify_enrollment_probe.py \
  /path/to/apple-enrollment-proof.json /path/to/android-enrollment-proof.json
```

The Java consumer requires the built starter JAR and `target/test-classpath.txt` from the server verification command. Native request/proof producers and platform builds are documented in the [Apple](../../sdk/apple/README.md) and [Android](../../sdk/android/README.md) guides. The root `scripts/AndroidEnrollmentProbe.java` is a test-only JCA producer compiled with the Android core sources and Jackson test dependencies; it never enters the AAR.

Apple and Android native enrollment proofs were verified against the server's independently constructed enrollment message, inserted into real temporary SQLite stores, rejected on reuse and persistently revoked. These probes intentionally fix a synthetic challenge's entropy source to match the native fixture; they are **not** live HTTP/provider challenge roundtrips. Both use explicit Basic mode and leave attestation `missing`.

## Storage and provider boundaries

Android instrumented tests use fresh UUID aliases in the dedicated test APK UID. The owner created only `AppGuard_Isolated_API35_20261020` under package-local scratch, serial5598, and the parent independently reran all seven tests. Identity-checked shutdown removed only that emulator/AVD; all31 pre-existing global AVD definitions remained byte-identical. Final APK signing uses an ignored package-local debug key; the initial RED APK used AGP's default debug-signing fallback before isolation was added. No existing key was replaced or deleted.

Apple host tests perform real **nonpersistent** Security/CryptoKit operations, replacing only persistent I/O. No actual persistent Keychain entry, Secure Enclave, entitlement or Apple provider acquisition was exercised. A Keychain storage label/requested extractability attribute is not proof of software nonextractability; the SDK exposes no private-export API, and explicit Secure Enclave requirements fail instead of falling back. Actual device enforcement remains unverified.

The App Attest wrapper acquires opaque evidence when correctly configured on a supported device; neither it nor the enrollment service implements Apple certificate-chain/assertion verification or Google's authenticated token decode. The enrollment service requires an explicit trusted server verifier for attestation-required profiles and validates its app/subject/key/challenge/expiry binding. Synthetic callback tests confer no provider trust. Client-reported risk hints confer no identity or attestation trust.

## Whole-change security review

A fresh read-only review of `2e26241..5ce35b1` found no critical issues, two important issues and one minor issue. No additional request-integrity, enrollment-binding, single-use or revocation bypass was found. The reviewer separately ran134 enrollment/policy/audit tests,18 independent-process completion attempts (one success,17 challenge rejections), persistent revocation readback and an independent JCA request-signature check.

Important findings addressed in `43cb2de`:

- Apple omitted synchronization classes in alias lookup, potentially hiding a pre-existing synchronized key. A query-capture test observed the wrong creation attempt (two assertions failed) before the fix. Lookup now enumerates both classes, obtains metadata and rejects synchronized or incomplete records before creation. The normal nonsynchronized reference remains usable. All26 host tests passed afterward; no user Keychain I/O was invoked by this regression.
- The README asserted software-key nonextractability without evidence. It now distinguishes the macOS attribute request, absent SDK private-export API and unverified platform enforcement. Unsupported attribute use is excluded from the iOS creation branch. This human-facing claim correction earns no source-text assertion.

One **deferred minor** remains: provider/clock/backend exception wrappers can retain an original exception in Python `__context__` even when standard formatted tracebacks are suppressed with `from None`. Public errors expose fixed codes and failed enrollment preserves challenge state, but structured error reporters must not traverse/serialize raw callback exception context. The audit sink already avoids retaining its callback exception. This deferral is explicit, not a claim that callback exception objects are sanitized.

## Executor rulings on every review exclusion

1. Actual Apple/Google trust verification: outside this foundation, explicitly required from a trusted backend. Cost: no attested production enrollment until that backend and real provider/device evidence exist.
2. Application authentication, resource authorization, counters/rate limiting, account-wide revocation, pending-challenge cancellation and cache propagation: application-owned. Local per-key revocation is implemented/tested. Cost: integrations must not confuse proof enrollment with permissions or fresh account state.
3. Native transport normalization/redirects/framing/wire capture: no HTTP transport adapter is bundled. Cost: each real app transport must preserve prepared evidence and prevent unsafe redirects before claiming an integrated app flow.
4. Physical hardware, persistent Apple Keychain, entitlements and successful provider acquisition: unverified rather than inferred from host tests/builds. Cost: later device/provider validation is mandatory for those guarantees.
5. Apple shared-tag creation across processes: the SDK serializes one process only; applications/extensions must coordinate initial provisioning. Cost: concurrent cross-process creation can leave an ambiguous unusable tag; the SDK refuses to select/delete an entry automatically.
6. SQLite directory replacement, backup/restore, network filesystems, distributed replication and clock administration: trusted deployment responsibilities. Cost: use a protected local directory/accurate clock and a backend suited to the actual topology; do not infer multi-host consistency.
7. Malicious trusted callbacks, manually forged policy contexts, secret-bearing audit IDs, hostile custom signers and future bridge exposure: trusted application inputs/future integration boundaries. Cost: only actual server results may populate trust states, and future bridges must expose validated operations rather than generic private-key signing.
8. Falsified local risk hints and later wrapper/build/CLI features: hints never confer trust; those later implementations are not claimed here. Cost: native primitives alone do not deliver Unity/Expo/Flutter installation, obfuscation or a release-ready platform.
