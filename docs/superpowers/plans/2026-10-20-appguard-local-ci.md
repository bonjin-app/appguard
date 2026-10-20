# AppGuard local CI foundation

Approved bounded implementation; no deployment, publication, workflow dispatch or account changes.

1. Inspect existing server/SDK commands and official runner/action documentation.
2. Add a fixed-argument extended server runner with explicit runtime overrides, isolated state, frozen dependencies, Go race/vet and PHP without user ini.
3. Add PR/push/manual workflow jobs for core Redis/server SDKs, extended SDKs, CLI/Expo and Apple Swift; pin external actions to full verified commit SHAs.
4. Validate shell and workflow semantics locally; exercise runner lifecycle/error propagation and coordinate real SDK execution with the parent.
5. Record commands, evidence boundaries and local-only native toolchains in development documentation.

Ownership: `.github/**`, `scripts/test-extended-server-sdks.sh`, this plan and `docs/development/continuous-integration.md`. Preserve other work. No staging or commits.

## Evidence ledger

- Inspected core runner, .NET locked verification script/global SDK pin, Go module, PHP lock/manifest and SDK verification receipts, CLI/Expo scripts and Apple package.
- Official runner documentation confirms `ubuntu-24.04` and `macos-15` hosted labels. External action release tags are resolved through the official GitHub repositories before pinning.
- Implementation and verification results are recorded in the development document when complete. GitHub execution remains unverified.

Complete: all five steps executed. Actual full extended runner passed locally (Go/race/vet/build, .NET175/build/pack, PHP514 assertions+5 raw HTTP requests); remote Actions remains unverified. See docs/development/continuous-integration.md for fixed pins, guards and evidence.
