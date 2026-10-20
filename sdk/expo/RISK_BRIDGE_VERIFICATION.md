# Expo local risk bridge verification

Date: 2026-10-20. Experimental local package. No publication.

- RED: `npm test` ran the 32 shared report cases plus initial configuration,
  snapshot, immutable result, error and boundary tests. The existing 23 tests
  passed; all 36 new tests failed because `scanLocalRisk` was absent. Evidence:
  ignored `.evidence/risk-bridge/red.log`.
- GREEN: 61 total tests pass: 23 existing and 38 new, including all 32 shared
  reports. Public package binding exercises `scanLocalRisk`; existing signing
  tests still pass, including the 1 MiB body and 1500000-byte JSON limit.
- `npm run typecheck` passes with the cached pinned TypeScript/dependencies.
- Input tests reject wrong/null/unknown values, bad IDs, duplicate/uppercase/
  sparse signer pins, excessive counts, invalid paths and throwing getters before
  loading native code. Valid boundary IDs/paths/counts pass. The accepted ASCII
  configuration shape is itself below 8192 bytes; serialization additionally
  enforces the 8192 UTF-8 limit. Caller iterators cannot alter the copied pin array.
- Report tests reject unknown schemas/platforms/fields/states, missing/reordered/
  duplicate checks, required `not_configured`, and inconsistent/duplicate/reordered
  signals. Every result/check/array is freshly constructed and frozen.
- The valid success envelope padded to exactly 4096 bytes passes and 4097 fails.
  A valid multibyte failure envelope at exactly 4096 bytes preserves its fixed
  error; adding one byte changes it to `APPGUARD_OPERATION_FAILED`. Native error
  text, response content and caller configuration are never attached to errors.
- Snapshot tests mutate caller options while the native Promise is pending; the
  dispatched JSON retains the original app ID, pin array and resource map.
- `npm run verify:pack` packs/stages native sources, checks every provenance hash,
  preserves the Apple privacy manifest and executes the compiled risk decoder
  from an extracted relocated tarball. It also checks the exported declarations.
  This exercises a mocked native boundary, not native scanner execution.

The existing Android/Apple `AsyncFunction("invoke")` adapters are retained. No new
network, clock, key, dependency, native-adapter or plugin behavior was added.
React Native requires Expo Modules integration and a rebuilt native app carrying
the new shared SDK operation; Expo Go/web remain unavailable. Unsupported old
SDKs reject explicitly. JS/OTA changes alone cannot add the native operation.

Final native sources were restaged after the parent confirmed the Android and
Apple implementation sources were complete. The refreshed 44-file tarball passes
relocated verification; its vendored hashes match current sibling SDK sources.
BRIDGE_CONTRACT.md now reflects the updated shared client bridge protocol.
Current-native consumer Android/iOS adapter builds are coordinated by the parent. Earlier build evidence in VERIFICATION.md
is historical and does not establish compilation of the new scan sources. This
receipt does not claim a new consumer native build, application/mobile runtime,
physical-device root/hook detection, provider state, signing/archive privacy or
store evidence. Ignored `.evidence/risk-bridge/` retains RED/GREEN/typecheck/pack
logs and SHA-256 receipts; the parent retains responsibility for final consumer build evidence.
