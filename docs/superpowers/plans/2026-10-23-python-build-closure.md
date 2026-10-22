# Python build dependency closure

## Objective

Close the verified gap where `uv.lock` fixes Python runtime dependencies but an
ordinary SDK wheel build resolves an unconstrained Hatchling backend closure.
The supported producer command must use isolated builds, exact reviewed build
versions and artifact hashes. Consumer wheel requirements must remain unchanged.
This increment does not complete AppGuard's production release objective.

## Baseline and evidence

- Main and the reusable worktree start at `89a9907`.
- Actual wheel and fresh consumer probes passed, but only with private build
  constraints; those constraints are not part of the baseline candidate.
- A separate prototype verified project-level hashed build constraints with
  uv 0.13.4, isolated builds, three missing/incorrect hash refusals, and a lock
  refresh preserving all 40 existing package records.
- The preceding main SDK CI passed five jobs. Source HIGH findings, image
  findings, native dependency coverage, license approval and external approvals
  remain independent unresolved release gates.

## Implementation and verification

1. Add meaningful regressions and observe failure on the baseline configuration.
2. Review the exact six universal build wheels (including the editable-install
   helper) and their dependency metadata,
   known vulnerability observations and original license material.
3. Add versioned hashed build constraints and hash enforcement to both Python
   projects: the SDK and the protocol reference. Refresh their locks without
   changing existing package records (40 SDK records and 11 reference records;
   these include development dependencies and local project records).
4. Use the no-cache, project-directory isolated build command in the server SDK runner;
   document the supported uv version and the fact that pip does not enforce
   `[tool.uv]` settings.
5. Make explicit CI packaging verification exercise ordinary project settings,
   missing and incorrect transitive hashes, wheel payload/LICENSE/metadata, and
   a fresh consumer installation from hash-locked runtime requirements. Exercise
   `uv sync --locked` in fresh SDK and reference environments with the actual
   relative project topology and verify editable metadata, imports and lock bytes.
6. Add source scan inventory visibility for both projects' declared build pins,
   with independently bound raw-Syft/overlay evidence. Scan those components
   while preserving the distinction between declared pins and resolved runtime
   proof, including shared package versions that also appear in runtime locks.
7. Run appropriate local tests and obtain an independent security review of the
   build/download boundaries, failure handling, isolation and scope claims.
8. Freeze a candidate, run fresh exact-commit CI and scans, and integrate the
   verified bounded change into main. Retain failing security findings and all
   unverified production gates instead of treating SDK CI as release approval.

## Boundaries

No package publication, provider provisioning, production deployment, physical
device work or global Codex configuration changes. Build and consumer probes own
their temporary environments and caches. Tests must not depend on private prior
evidence directories or preinstalled build backends. Negative hash tests must
fail without a wheel; network failures must not become successful verification.
Fixed-input byte equality is narrower than universal reproducible builds.

## Local verification before candidate freeze

The initial implementation passed 147 tooling/operating regressions, 177 release tests
with actual reviewed Syft checks, and nine real packaging tests. Independent
review closed downloader deadline and cancellation findings, direct-validator
FIFO handling, finite JSON parsing, and provenance-file pinning/staging gaps.
Both original lock package lists remain unchanged. Candidate-bound Trivy and
hosted CI observations remain required; these local results do not complete the
production goal or clear existing findings and external approvals.

The first candidate (`1dbf53f`) failed fresh Linux SDK and container setup because
wheel-only verification had missed Hatchling's `editables` build dependency.
It was not integrated into main. The corrective regression reproduces the SDK
and reference failures, adds the reviewed `editables==0.6` wheel hash to both
projects, and passes ten real packaging tests, including fresh locked editable
installs. Existing 40 SDK and 11 reference package records remain unchanged.
Fresh final-candidate Linux CI and source scanning remain required.
