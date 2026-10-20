# AppGuard Build/CLI implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Parent owns `tools/cli/**`; framework workers own `sdk/**`. No nested delegation.

**Goal:** Provide a locally installable, dependency-free CLI for safe setup, policy validation, platform build commands and encrypted mapping-file retention.

**Architecture:** Node 22 ESM modules separate project configuration, platform build plans, command dispatch and encrypted artifacts. Init creates a small explicit config and Android release protection sidecar; all writes have preconditions and existing content is preserved. Builds use argument arrays without a shell; encrypted archives use caller-provided 256-bit keys and authenticated encryption.

**Tech Stack:** Node 22 built-ins, Node test runner; Android R8/Gradle, Flutter release obfuscation and Expo production minification.

**Spec:** Approved root design and roadmap; Android [official optimization settings](https://developer.android.com/topic/performance/app-optimization/enable-app-optimization), Flutter [obfuscation](https://docs.flutter.dev/deployment/obfuscate), Expo [minification](https://docs.expo.dev/guides/minify/).

## Global constraints

- No downloads, account setup, SDK publication or arbitrary shell commands during CLI execution.
- No claims of complete source concealment or provider configuration.
- `balanced` default; configured app ID explicit; native SDK packages remain separately installed local artifacts.
- Preserve existing files and reject symlink/path traversal or overwrite ambiguity.
- Archive input mappings at most 64 MiB total; caller key file exactly32 bytes and private on POSIX; AES-256-GCM with version/build-ID authenticated context.

## Review focus

- Re-running init and colliding files must not clobber existing application configuration.
- Build invocation must retain argument boundaries and propagate process failure.
- Private mapping/source-map material must not be written into a public output directory by archive/restore.
- Tampering/wrong keys/path traversal must fail without partial plaintext restores.
- A dry-run or configuration check must not imply a successful platform build.

### Task 1: Project setup and build plans

**Files:** `tools/cli/src/project.js`, `build.js`, `test/project.test.js`, `test/build.test.js`.
**Interfaces:** `initialize(project, {appId, platform?, profile?})`, `inspect(project)`, `buildPlan(project)`; schemaVersion appguard-project-v0, platforms android/flutter/expo.

- [x] Observe failing tests for detection, multi-platform ambiguity, existing files, symlinks, invalid profile/app ID and idempotence.
- [x] Implement bounded config parsing, exclusive writes, Android Groovy/Kotlin R8 sidecar integration and `.appguard/` ignore entry.
- [x] Observe failing tests for build plans; implement Android wrapper release, Flutter `build apk --release --obfuscate --split-debug-info=...` and Expo local CLI production export without source maps.
- [x] Run fixture tests and one actual isolated Android release R8 build, inspect mapping output; commit.

### Task 2: Encrypted artifact retention

**Files:** `tools/cli/src/vault.js`, `test/vault.test.js`.
**Interfaces:** `archive({source, vault, keyFile, buildId})`, `restore({archiveFile, destination, keyFile})`.

- [x] Observe RED for round-trip bytes, tampering/wrong key, symlink inputs, overwrite, unsafe names/permissions, size limits and atomic failure.
- [x] Implement versioned authenticated archive, private modes, no overwrite, authenticate and validate complete payload before destination creation; original source is retained.
- [x] Run full CLI suite; commit.

### Task 3: CLI package and verification

**Files:** `tools/cli/bin/appguard.js`, package.json, README, LICENSE; root verification docs later.

- [x] Test subprocess `init`, `doctor`, `policy validate`, `build --dry-run`, archive/restore and invalid arguments through the actual packaged bin.
- [x] Implement fixed errors (no secret/file contents), successful JSON output, explicit build execution and exit-code propagation.
- [x] npm pack/install to isolated directory, run installed commands and whole suite; review with native bridge stage, document actual scope and limits.
