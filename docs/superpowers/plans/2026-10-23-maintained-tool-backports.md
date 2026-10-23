# Maintained tool backports implementation plan

> For a later authorized implementer: use superpowers:executing-plans task by task. No execution, install or adoption is authorized by this plan.

**Goal:** Install reviewed maintained tool derivatives while preserving affected upstream ancestry and an honest failing source gate.
**Architecture:** Tracked deterministic local archives, consumer-root overrides and a dedicated hash-bound backport SBOM; resolver follows as a separate review.
**Stack:** Existing Python3.11 stdlib, pinned Node22.23.2/npm and TypeScript6.0.3; no new bundler or test framework.
**Spec:** [Maintained tool backports design](../specs/2026-10-23-maintained-tool-backports-design.md).

## Constraints and review focus

Preserve frozen private evidence, HOME/CODEX_HOME and other workers. No postinstall workaround, scanner exclusion, VEX autoapproval or upstream-fixed claim.
Raw HIGH findings, unresolved bundled resolver and false full-graph/native/legal/external/release flags remain explicit through every stage.
Review archive/manifest/lock drift; missing ancestry or skipped scans; logical-name resolution; stale Forge distributions; resolver precedence/API differences.
Reuse only approved normal fixtures after separate runtime authorization; no new attack, RSA-forgery, DoS, depth/cycle or Bash-oracle execution.
New builder tests use ordinary owned files/manifests/SRI/expected-payload mutations only: no new adversarial TAR/ZIP/path/symlink/transport payload research.
Static archive parsing, safe paths and strict type/size/member limits remain required; that does not authorize attack experiments.

### Task 1: Smallest first deliverable: two deterministic packages and verifier only

- [ ] Add meaningful RED tests in `.github/tests/test_tool_backports.py` using ordinary owned input fixtures:
  edited source/manifest/SRI, missing retained file, stale distribution/map, wrong expected payload/name/version and repeat-assembly drift must fail.
- [ ] Create `tools/dependency-backports/manifest.json`, README, per-package retained inputs/patch/provenance and two `archives/*.tgz` per spec.
  Retain each original `upstream.tgz` plus readable changed source and9 Forge distribution/map replacements; no expanded duplicate59-file original tree.
  Preserve every original payload/license/Flash member except exact declared replacements, and import no private key/test-generated material.
  First-unit Forge README/provenance explicitly keeps `compilation_reproduction_verified=false` and `producer_closure_verified=false`.
- [ ] Implement `scripts/dependencies/build-backports.py`: `load_manifest`, `assemble_package`, `check_archives`, `write_archives` with exact spec schema.
  `--check` reconstructs/verifies tracked archives; explicit `--output DIR` writes two archives to new private owned output, never overwriting existing output.
- [ ] GREEN ordinary tests verify deterministic stored-gzip/USTAR, exact full member bytes, upstream/result SRI and fixed summary/errors.
  Confirm all physical inputs use `replacements/distribution/` and later `resolver/compiled/`; logical dist/build paths exist only inside archives.
  Existing candidate allowlist must include every intended input without exceptions. Freeze this unit separately for review.
- [ ] First-unit boundary: no npm resolution/install, consumer lock/override, scanner/catalog/gate change or candidate/lifecycle execution.

### Task 2: Separate ancestry catalog and required scans, before consumer adoption

- [ ] Add RED tests in `scripts/release/tests/test_tool_backport_catalog.py` for input/SRI/provenance drift and missing or misclassified ancestry.
- [ ] Add `tool_backport_catalog.py` prepare/validate interfaces and separate SBOM/provenance, preserving all original source/Python components.
  Extend `source_catalog.py`, `scan.py` and their existing tests for archive-derived coverage, both new Trivy command bindings and required execution.
- [ ] RED→GREEN rename-only/missing-ancestry/removed-command/changed-overlay tests: upstream affected purls and advisory IDs survive;
  mocked positive ancestry findings force gate failure even if the scoped derivative reports zero. Fresh actual scanner evidence must later confirm it.
- [ ] Freeze/review catalog and required-command bindings independently. Packaging/candidate checks never imply a clean source gate.

### Task 3: Real consumer install and maintenance routing

- [ ] Modify `sdk/expo/{package.json,package-lock.json,README.md}` for exact logical braces/Forge root direct file devDependencies
  and matching `$braces`/`$node-forge` overrides; inspect every lock diff. Raw relative transitive overrides alone failed existing-importer migration.
  Begin only after task2 review; preserve unrelated graph identities/dependency flags. Add resolver override only after task4 review.
- [ ] Implement `scripts/dependencies/verify-backports.cjs` to compare lock/SRI/archive metadata, logical resolution origins and every installed payload hash;
  wire supported install/test/build/typecheck/pack commands and `.github/workflows/verify.yml` without weakening `--ignore-scripts`.
- [ ] With later authorization, fresh ordinary and relocated same-lock `npm ci --ignore-scripts` must preserve locks and resolve actual Expo/CLI consumers
  to the reviewed forks. Compare Forge public CJS/browser/worker entrypoint payloads and reuse approved normal candidate/consumer fixtures only.
- [ ] Preserve actual exits/cleanup and bounded fixed receipts; run targeted catalog/workflow/consumer tests, then relevant existing checks.
  No proof from the synthetic3-package graph alone and no new global config, lifecycle execution or hidden online fallback.

### Task 4: Proposed source-based resolver derivative, separately accepted

- [ ] Retain official2.0.1 archive/SRI/license/declarations and four publisher TS files under `tools/dependency-backports/resolver/` with exact hashes.
  Add `build-resolver.cjs` compile flags/producer pins and exact existing js-yaml4.3.2/micromatch4.0.8 dependency/integrity review; do not revive ncc/Bun.
- [ ] RED→GREEN ordinary temp-workspace fixtures in `.github/tests/test_resolver_backport.py`: all four exports, sync/async agreement, npm/Yarn/pnpm
  forms, nested/absent workspace, option defaults/precedence and normal read/parse failures. Match controlled published API behavior and exact declarations.
- [ ] Verify TypeScript consumer compatibility and deterministic four-output builds; package the unbundled derivative with explicit external dependencies.
  Keep physical outputs in `resolver/compiled/`, with manifest mappings to logical `package/build/*`; add no candidate allowlist exception.
  Check every real/test consumer root routes micromatch's braces to the reviewed archive; embedded old bundle must be absent from installed payload.
- [ ] Extend manifest/catalog ancestry and Expo lock/consumer tests; until this stage is complete, report the separate bundled braces path unresolved.

### Task 5: Review and evidence boundary

- [ ] Before production adoption, retain the readable reviewed modern Webpack recipe, complete producer lock/config, exact Node/npm/tool pins
  and source/output joins under `tools/dependency-backports/node-forge/producer/`. Independently rebuild all six JS/three maps and match expected hashes;
  otherwise stop with compilation reproduction/producer closure unverified. Archive/install equality or private receipts alone cannot satisfy this requirement.
  Static producer retention does not prove a fresh rebuild; this requirement supplies no legal or upstream-build-reproduction approval.
- [ ] Freeze product/source/archive/lock/tool/fixture hashes, actual counters and unresolved limitations; obtain independent review before adoption/CI.
  Maintainers own future upstream monitoring, rebuilds and replacement/removal when a supported fixed release is independently verified.
- [ ] Review actual consumer and unsuppressed source/ancestry scan results separately from source-byte checks; keep failure reports and all other gates false.
  Root controls commits, pushes, CI and integration. This design-only task creates just this plan and its linked spec.
