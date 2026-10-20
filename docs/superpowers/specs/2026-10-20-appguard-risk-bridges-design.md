# Local risk bridge design

Authorized scope: expose existing Android/iOS local risk scanners through Unity,
Expo/React Native and Flutter; tests, one fresh whole-stage security review, then
clean local main fast-forward. Base aabe60116895dad9dbb33aa11939a2645070d8bd.
No global config, accounts, device keys, releases or publication are authorized.

## Shared operation

Add scanLocalRisk to the existing invoke(operation,payloadJSON) facade. Existing
three operations retain their exact fields and behavior. Scan takes an object with
only these OPTIONAL fields (default {}): expectedAppId string,
androidSignerSha256 array of distinct lowercase64hex SHA256 strings (max8),
protectedResources object of path->lowercase64hex pins (max8). No nulls, alias,
hardwareRequirement, clock, injected observations or arbitrary paths. Validate
all configuration before native probing. An omitted field means the existing
native optional check is not configured. Empty arrays/maps are valid; empty IDs
are invalid. App IDs:1..255 ASCII [A-Za-z0-9][A-Za-z0-9._-]*. Resource paths:1..256
ASCII, each slash-separated component1..128 [A-Za-z0-9_-][A-Za-z0-9._-]*; no empty,
dot/traversal/absolute/backslash. All bounds match local-risk-v0.

New scan input UTF8 JSON limit8192 bytes; success/failure envelope limit4096.
Existing invoke input/output limits1500000 stay intact for other operations.
Native JSON parsing rejects duplicate decoded keys and wrong/nested array values;
new arrays contain strings only and at most8 elements. Native scan never creates,
loads or signs a key, calls a clock, or performs networking. iOS validates the
whole config then returns APPGUARD_UNSUPPORTED for nonempty Android signer pins;
it must not silently ignore a configured check. Other malformed config is
APPGUARD_INVALID_INPUT. Native probe failures are per-check unavailable as before;
an unavailable module/old native operation rejects, never a clean fallback.

Success result is the exact local-risk-v0 report, wrapped in existing {ok,result}.
Report exactly schema/platform/checks/riskSignals. Schema appguard-local-risk-v0;
platform android/ios; Android ordered7 checks and iOS ordered5 from local-risk-v0.
Each check exactly code/state; states detected/not_observed/unavailable/not_configured.
Required checks (Android first4, iOS first3) cannot be not_configured. Signals must
exactly match recomputed ordered deduplicated debugger/root/hook/tamper/
local_checks_unavailable categories. No raw config/native errors or extra fields.
Wrappers reject wrong shapes, counts, duplicate/reordered checks/signals,
inconsistent categories, unknown values/platform/schema before returning a fresh
immutable or defensive typed report. Valid report cases are shared in
conformance/v0/local-risk-bridge.json; raw response text is never returned.

## Public APIs and scheduling

Expo: exported scanLocalRisk(options?: LocalRiskOptions):Promise<LocalRiskReport>,
using existing background AsyncFunction invoke. React Native requires Expo Modules
integration/native rebuild; Expo Go/web remain unavailable. No dependency upgrade.
Flutter: AppGuard.scanLocalRisk({LocalRiskOptions? options}):Future<LocalRiskReport>.
Register native method handlers with official background task queues (with explicit
unsupported/unavailable fallback if needed), preserving fixed errors and detach
behavior. Native result callbacks obey engine threading rules; no Dart fallback.
Unity: Client.ScanLocalRiskAsync(LocalRiskOptions options=null):Task<LocalRiskReport>.
Snapshot/validate config before native work. Use an owned worker thread/explicit
JNI attach-detach (or proven installed API equivalent) so file I/O stays off the
Unity/UI thread and existing synchronous key APIs remain unchanged. Editor and
unsupported platforms return explicit unsupported errors. Immutable config/report
collections; no arbitrary caller observations or mutable shared native state.

## Evidence and limits

TDD for native facade validation/no-key/no-clock/state preservation and all wrapper
serialization/decoding/errors/thread dispatch; full affected native/framework
suites; staged/relocated package provenance; current actual adapter compilation
and Unity actual C ABI buffer + compiled JNI path where available. Keep privacy
manifest propagation. No claim of mobile runtime, physical rooted/hooked efficacy,
provider verification, signed archive privacy or store approval from host/mocks/builds.
If current disk capacity permits, run only a task-owned isolated Android native
bridge instrumentation fixture; never change existing devices/AVDs. Distinguish
native facade runtime from Unity/Expo/Flutter engine runtime.
One fresh whole-stage review, one Critical/Important RED/GREEN fix pass, no re-review.

References: protocol/local-risk-v0.md and protocol/client-bridge-v0.md.
Official queues: https://docs.flutter.dev/platform-integration/platform-channels
and https://docs.expo.dev/modules/module-api/ .
