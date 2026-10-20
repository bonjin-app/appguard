# Local risk bridge implementation plan

> Workers use TDD with disjoint file ownership; no recursive agents, staging or
> commits by workers. Parent serializes commits and dispatches one whole-stage review.

**Goal:** Typed async local risk APIs in all existing framework packages.
**Architecture:** One new bounded native JSON operation feeds strict report parsers.
**Tech Stack:** Java17,Swift5.9+,Expo58/TypeScript,Flutter3.47/Dart,Unity6000.3/C#.
**Spec:** docs/superpowers/specs/2026-10-20-appguard-risk-bridges-design.md.

## Global constraints

Exact optional scan config keys expectedAppId/androidSignerSha256/protectedResources.
Input8192UTF8bytes; envelope4096. No keys/clocks/network for scan. Four existing
report states; no clean verdict; iOS nonempty signer pins unsupported after validation.
Existing operations/protection and privacy resources remain unchanged.

## Review focus

- Malformed config, wrong collection types, duplicate decoded keys and escaped
  strings must fail before keys or probes (native facade tests).
- Plausible but inconsistent native reports must reject rather than be trusted
  (shared report vectors in each wrapper).
- Config/report mutation across an async boundary must not change observations
  or returned report (wrapper snapshot/immutability tests).
- Background dispatch, JNI thread ownership and Flutter detach/task queue behavior
  must preserve one fixed result and avoid UI file I/O (adapter probes/compilation).
- Old/missing native module, native throws and oversized results must fail with
  fixed codes without exposing config or native text (each wrapper error tests).

### Task1 Native JSON facades — parent Android, Apple worker sdk/apple/**

- [x] RED tests for default/configured scan, exact state serialization,
  bounds/null/unknown/duplicates/arrays and no-key/no-clock/no-probe invalid config.
- [x] Implement scanLocalRisk; keep existing strict parsers, add bounded string
  arrays; iOS signer unsupported distinction; fixed error mapping.
- [x] Full native tests/lint/builds and source/artifact receipts.

### Task2 Expo — worker sdk/expo/** only

- [x] RED tests for exported async API, optional config mapping/shared corpus,
  malformed/native-unavailable/errors, mutation and exact byte limits.
- [x] Implement typed defensive options/report and strict decoder using existing
  AsyncFunction native boundary; document React Native/Expo Go limits.
- [x] Full23+newtests/typecheck, final packed relocation/native adapter compile.

### Task3 Flutter — worker sdk/flutter/** only

- [x] RED shared corpus/config/error/immutability tests and adapter lifecycle tests.
- [x] Add typed Future API and actual background native task queue registration.
- [x] Full17+newtests/analyzer/Java probes/Swift compile, staged archive/resource checks.

### Task4 Unity — worker sdk/unity/** only

- [x] RED shared corpus/config/error/async snapshot/thread/memory ownership tests.
- [x] Add immutable report/options and async API with owned JNI-safe worker execution.
- [x] Full20+newEditMode, platform compile/C ABI/relocation/privacy export checks.

### Task5 Review and integration — parent

- [x] Verify latest staged source bytes; targeted policy integration preserves
  untrusted hints; one fresh security review and required fix pass.
- [x] Update docs/support evidence, collect rulings/costs, archive checksummed owned
  scratch; clean local main fast-forward and exact source readback. No push.

Observed results and the deferred Minor JSON-syntax hardening item are recorded in docs/security/risk-bridges-verification.md. Final source/hash and clean main integration receipts are retained in the owned stage archive.
