# Unity player runtime implementation plan

> **For agentic workers:** Use superpowers:executing-plans for native execution with one final fresh security reviewer.

**Goal:** Build and execute the Unity local-risk bridge in real Android/iOS IL2CPP players, repair observed defects, verify and merge locally.
**Architecture:** Relocated source UPM package with rebuilt AAR/XCFramework; disposable consumer project containing a public-API smoke scene. Explicit build and device selectors; machine-readable app receipt binds cases to player build GUID.
**Tech Stack:** Existing Unity 6000.3.24f1, IL2CPP, Xcode, installed Android SDK/JDK; Python standard library runner.
**Spec:** User's requested next verification tier plus sdk/unity/README.md and protocol/client-bridge-v0.md. No provider/store/release claims.

## Global constraints
- Preserve existing managed worktree, other device sessions, package evidence and caches.
- Only task-owned scratch project/apps/emulator/simulator; no real app IDs, accounts or production signing.
- IL2CPP with High managed stripping; Android arm64 Release/R8; iOS arm64 Simulator Development engine and unsigned generic device Release build.
- Scan-only fixture; no installation key, Keychain, enrollment, network or provider operation.
- Runtime reports are untrusted hints; do not assert clean/root/hook absence on virtual devices.

## Review focus
- Actual exported native entry points survive stripping/static linking and consumer R8.
- Worker JNI attach/detach and concurrent scans complete without UI blocking or engine errors.
- Default/configured/mismatching identity/resource observations remain distinct; signals match semantic decoder.
- Failures remain fixed/redacted; unsupported signer options on iOS fail explicitly.
- Receipts require every named case, matching app/build/backend and no stale-file acceptance.

### Task 1: Consumer harness and actual builds
Files: create sdk/unity/Tools~/PlayerSmoke.cs, PlayerBuild.cs, test-player.py; update package docs as needed.
- [x] Create public-API fixture: default checks, identity match/mismatch, resource match/mismatch/missing, signer mismatch/unsupported, validation, 16 concurrent/repeated scans, fixed errors, frame heartbeat.
- [x] Stage and build native plugins from current sources, create task-owned project and runtime receipt protocol.
- [x] Build Android arm64 release IL2CPP/R8 APK; iOS arm64 Simulator IL2CPP app; unsigned generic device app. Record first failures before fixes.
Expected: real artifacts with source hashes, IL2CPP output, native library symbols/privacy resources.

### Task 2: Runtime and repairs
Files: same harness; only production files where demonstrated defects require correction; associated Editor regressions.
- [x] Own isolated virtual devices, install/launch exact artifacts, require all smoke cases and frame progress, capture receipts and errors.
- [x] Diagnose each failure at boundary, add regression before minimal correction, rerun affected player and Editor suite.
Expected: no invented physical-device evidence; concrete blockers and exact completed tiers if external environment prevents a target.

### Task 3: Security review, evidence and local main
Files: sdk/unity/PLAYER_RUNTIME_VERIFICATION.md, README/roadmap references; plan and stage ledger.
- [x] Fresh whole-change read-only security reviewer; regrade by effect, one Critical/Important fix pass with regressions/full affected checks, record Minor/rulings; no re-review.
- [x] Hash sources/artifacts/receipts, preserve archived evidence, stop/remove only owned virtual device resources.
- [x] Fresh clean main check, local fast-forward merge and exact source hash readback.
