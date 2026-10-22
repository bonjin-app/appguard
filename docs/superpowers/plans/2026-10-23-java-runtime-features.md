# Java Runtime Feature Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task by task. Track steps with checkboxes.

**Goal:** Measure Java behavior omitted by direct ELF linkage before replacing the backend runtime OS.

**Architecture:** Compile a dependency-free Java 17 probe with the existing pinned Maven/Temurin builder. Bake identical classes outside the JRE into both diagnostic image targets. The inventory CLI optionally runs this fixed probe in its existing owned isolated container and strictly validates its bounded JSON. Keep production images and all release/native-closure flags unchanged.

**Tech Stack:** Java 17 standard libraries, Python standard library, pinned Docker images and native GitHub amd64/arm64 runners.

**Spec:** `docs/development/production-release.md`; native inventory at `2c8ad421901aa8e98d3e8e787433c61bc9c1302f` found identical JRE content and six missing SONAMEs in both images, while Debian lacks baseline fontconfig, fonts, locales and OS CA packages. Loader resolution cannot establish their behavioral effects.

## Global Constraints

- Do not replace production runtime, install packages, remove metadata/licenses, suppress findings, publish or touch global Codex configuration.
- Probe only fresh owned container loopback; no external DNS, real credentials, accounts or services.
- Generated keys/passwords/certificates are ephemeral, private and never printed or retained.
- Native matrix remains amd64/arm64; compile with pinned Java17 builder, no Maven downloads required for this standalone class.
- Existing inventory without the optional feature flag retains schema1 behavior. Extended diagnostic reports use schema2 and remain release_ready=false, native_binary_coverage=false and coverage_complete=false.

## Review Focus

- Strict feature JSON must reject omitted/duplicate/extra checks, non-booleans, contradictory exit status and truncated/oversized data.
- TLS must verify the generated certificate endpoint SAN, require client authentication, constrain timeout and close every owned socket/thread/process/temp file.
- Failed graphics/native initialization must become an explicit failed check, not vanish behind successful crypto results.
- Both diagnostic targets preserve whole vendor JRE bytes and existing final-OS loader cache behavior.
- Default image locale/trust behavior must be exercised without injecting host environment or weakening inherited inventory isolation.

### Task 1: Fixed Java behavioral probe

**File:** Create `scripts/qualification/java/AppGuardRuntimeProbe.java`.

**Interface:** No command arguments. Emit exactly one JSON object: `{"schema":1,"checks":{...},"passed":boolean}`. Exact ten check keys: `crypto_p256`, `aes_gcm`, `pkcs12_roundtrip`, `jsse_default_trust`, `mtls_loopback`, `utf8_io`, `locale_data`, `timezone_data`, `localhost_nss`, `headless_font`. Every key is boolean and every check is attempted. Exit0 iff all true, exit1 for measured failures, exit2 for invalid invocation/unverified fatal setup. No arbitrary exception messages/paths/addresses/keys enter JSON.

- [x] Implement P256 sign/verify plus mutation refusal, AES-GCM roundtrip plus tag refusal, private PKCS12 secret-key roundtrip, loaded default X509 trust roots and enabled TLS1.3.
- [x] Generate a short-lived EC PKCS12 using the JRE keytool in a fresh private directory, random password passed via child-only environment, output discarded, bounded subprocess lifetime. Perform TLS1.3 mutual authentication only over127.0.0.1 with HTTPS endpoint checking and matching IP SAN. Close/join/remove all owned resources even on failure.
- [x] Test UTF8 bytes and private-file roundtrip, explicit Japanese locale data, fixed historical timezone offsets, literal localhost NSS, and headless BufferedImage font rendering.
- [x] Compile/run with pinned local Java17, retain only fixed result/exit/provenance and private logs. Local macOS proof is not Linux runtime proof.

### Task 2: Strict optional integration and native matrix

**Files:** Modify `scripts/qualification/inspect_java_runtime.py`, `.github/tests/test_java_runtime_inventory.py`, `scripts/qualification/java-runtime-probe.Dockerfile`, `.github/workflows/java-native-runtime.yml`, `docs/development/production-release.md`.

**Interface:** Add `--features` and `inspect_runtime(..., features=False)`. Fixed classpath `/opt/appguard/java-runtime-probe`, class `AppGuardRuntimeProbe`, heap64MiB, one active processor and private/tmp. Do not clear image locale for feature execution; do not inject host environment. Schema2 report contains validated feature object and includes `runtime_features_passed` in checks. Invalid feature evidence cannot pass or remain complete. Full inventory and feature failures remain diagnostic, never approval.

- [x] Write RED parser/lifecycle tests for valid failing check preservation, contradiction, malformed/extra/duplicate checks and command failure; implement minimal strict integration; run GREEN.
- [x] Build both `baseline` and `debian-probe` targets from fixed image digests with identical compiled probe classes; pass feature flag in all four native jobs.
- [x] Run appropriate full suites/actionlint and independent security review before commit.
- [ ] Review actual exact-commit native CI; preserve measured and incomplete failures.
- [ ] Inspect actual native artifacts and preserve failing feature evidence. Fix diagnosed tool failures; do not install guessed dependencies or downgrade acceptance criteria to conceal runtime differences.

## Completion boundary

These bounded probes exercise selected functionality. They do not establish every JNI/dlopen path, GUI/audio hardware behavior, complete dependency or license closure, external approval, real provider accounts, sustained operation or production readiness. The broader production goal remains active.

## Native CI follow-up

The initial exact-commit run2222c32 measured all ten baseline checks passing on
both native architectures, but both Debian collections were incomplete. Original
artifacts retained `features:null`, so the Linux cause was not distinguishable.
A strict exit2 partial-result regression was first RED, then fixed to retain only
validated ten-boolean diagnostic objects while preserving incomplete/exit2 and
all false approval flags. Do not weaken VirtualMachineError or cleanup handling.
The subsequent native run must establish the actual retained result; the suspected
font initialization failure is not established by the first run alone.
