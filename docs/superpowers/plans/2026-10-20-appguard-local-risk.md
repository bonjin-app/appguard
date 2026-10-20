# Native local risk implementation plan

> **For agentic workers:** Use the approved scope and TDD. Android/iOS are independent
> platform-owned implementations; no recursive subagents, staging or commits by workers.
> Parent serializes commits and dispatches one fresh whole-change security reviewer.

**Goal:** Read-only local risk hints with explicit unavailable states and safe typed APIs.
**Architecture:** Each native SDK owns a scanner/config/immutable report and internal
OS seams. Shared report/category contract feeds existing explicit server policies.
**Tech Stack:** Android26+/Java17/NIO/PackageManager; iOS15+/Swift/Foundation/Darwin/CryptoKit.
**Spec:** docs/superpowers/specs/2026-10-20-appguard-local-risk-design.md.

## Global constraints / review focus

All bounds, fixed states, ordering and privacy constraints in the spec are normative.
Probe failure is unavailable, not clean. No side effects beyond read-only observations.
Hash actual current signing certificates; resource paths must not escape the bundle.
Only public APIs, no persistent keys, provider/device changes or global config edits.

### Task1 Android — sdk/android/** only

- [x] Add failing tests for state/category precedence, per-check errors, bounds,
  malformed configuration before I/O, signer all-members/rotation, exact binary
  resource hash/missing/oversize, defensive copies and fixed errors/report redaction.
- [x] Implement LocalRiskScanner typed API, real Android probe adapter and bounded I/O.
- [x] Full host tests, release AAR/lint and available isolated instrumentation;
  record exact commands, RED/GREEN and untested physical-device efficacy.

### Task2 Apple — sdk/apple/** only

- [x] Add failing tests for state/category precedence, throw/unsupported handling,
  config/resource traversal and symlink boundaries, exact binary hashes/limits,
  immutability/redaction and host/simulator unsupported behavior.
- [x] Implement LocalRiskScanner/LocalRiskConfiguration/LocalRiskReport using
  read-only public native APIs, bounded scans and no keychain/network operations.
- [x] Full Swift tests and unsigned generic Simulator/device builds; record
  actual host execution separately from iOS compilation/device efficacy.

### Task3 Integration — parent

- [x] Review native evidence; exercise same hint categories through all six
  existing policy implementations; verify staging/consumer native source paths.
- [x] One fresh whole-stage security review; targeted RED/GREEN fix pass for
  Critical/Important, document new Minor limitations and all rulings/costs.
- [x] Support matrix, public examples, exact provenance and explicit efficacy
  limits; archive checksummed owned scratch; clean local main fast-forward.

Final integration uses a checksummed owned evidence archive, clean original main precondition and fast-forward readback. Runtime disk blocker and no physical-device efficacy are recorded in docs/security/local-risk-verification.md.
