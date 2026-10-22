# Java Native Runtime Inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Measure complete JRE native linkage on native amd64 and arm64 before selecting a replacement backend OS.

**Architecture:** Run a bounded fixed probe in owned isolated containers and retain a strict sanitized report. Compare the pinned production Temurin Noble JRE with the complete same JRE directory copied into digest-pinned Debian 13.7-slim. The experimental image does not replace the production backend; missing libraries are failure evidence, never exclusions.

**Tech Stack:** Python standard library, Docker, GitHub native Linux runners, pinned official OCI images.

**Spec:** `docs/development/production-release.md` required runtime and dependency evidence; rejected Resolute candidate `1487b8708f6c0c09e3db28c87815ee5a12aef248` private evidence retains 71 findings including four HIGH findings.

## Global Constraints

- Preserve Java vendor/version, all JRE bytes/legal/CA material, existing production backend and package metadata.
- No physical devices, registry publication, production deployment or global Codex edits.
- Inspect trusted digest-pinned images only on an explicitly selected local daemon; no secret mounts or network inside probes.
- Do not infer complete dependency closure, vulnerability approval or production readiness from linker success.
- Keep existing three-file container-readiness evidence contract unchanged.

## Review Focus

- Truncated or missing terminator must fail inventory completeness rather than publish partial success.
- Missing loader libraries must remain explicit unresolved findings, including optional Java native libraries.
- Untrusted image metadata, duplicate paths and oversized output must fail closed without echoing raw output.
- Probe cleanup must target only exact freshly owned containers, even after timeout or command failure.
- Cross-architecture execution must agree with native daemon and runtime identity; no QEMU execution inferred as native proof.

### Task 1: Bounded native inventory

**Files:** Create `scripts/qualification/inspect_java_runtime.py`; create `.github/tests/test_java_runtime_inventory.py`.

**Interface:** Command receives explicit local Docker context, immutable image reference and expected native architecture, writes a bounded new-directory report. Records exact runtime image ID, Java identity, JRE native files/hashes/linkage, OS providers and required legal/CA presence. Incomplete input, missing libraries and command failures cannot produce a passing inventory. Exact CLI flags and schema are documented with implementation.

- [x] Write behavior tests for real protocol parsing, missing dependencies, malformed/truncated/duplicate/oversized data, immutable identity and owned cleanup.
- [x] Run tests before implementation to confirm meaningful failures.
- [x] Implement fixed container probe and strict bounded parsing using existing command/local-daemon helpers where appropriate.
- [x] Run focused tests and review resource ownership, publication and native-identity checks.

### Task 2: Native CI comparison and documented limits

**Files:** Create `.github/workflows/java-native-runtime.yml`; create `deploy/spring-ingress/Dockerfile.java-runtime-probe`; modify `docs/development/production-release.md`.

**Interface:** Native `ubuntu-24.04` and `ubuntu-24.04-arm` jobs build/inspect immutable official baseline and experimental image. Experimental Debian digest is `sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad`; JRE remains original Noble digest `sha256:07fa0356cf354c5252947575f42ed42aa6fd921f36438b7bc77ad81c31c537dd`. Recreate loader configuration against final OS; preserve original JRE legal/CA bytes. No apt package selection is approved by metadata alone.

- [x] Integrate inventory CLI, finite timeouts, read-only workflow permissions, digest-pinned actions and report-only artifact upload.
- [x] Run actionlint and all appropriate tooling tests; independently review new scripts and workflow.
- [ ] Commit/push branch and inspect exact-commit SDK plus actual native workflow results and retained artifact hashes.
- [ ] Fix diagnosed implementation failures, retain unresolved dependency results and update documentation with observed findings.
- [ ] Integrate only reviewed working inventory tooling; production runtime replacement requires separate actual OS inventory, vulnerability scans and compatibility tests.

## Completion boundary

This increment provides trustworthy diagnostic measurements. It does not resolve known backend/source findings, prove a complete build graph or complete the production goal. Candidate security failures and external approvals remain blocking.
