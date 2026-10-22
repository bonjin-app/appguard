# CLI local Expo package links

2026-10-22; base `8fbe3a002db8d161363e887ba45f67abfa5e1159`;
experimental Apache-2.0 CLI. No dependency, protocol or archive-format change.

## Bounded compatibility

The previous all-component no-symlink rule rejected normal pnpm installations,
where `node_modules/expo` links into a package directory under the project's
`node_modules/.pnpm/`. This was a documented limitation, not an undisclosed
security vulnerability. See [pnpm's dependency layout](https://pnpm.io/symlinked-node-modules-structure).

Expo doctor and build now share one resolver. The project's `node_modules` must
be an ordinary directory under the existing no-symlink policy. Its canonical
path is the boundary: the Expo package entry may resolve through links only to
a directory strictly inside that canonical dependency tree. Exact-root targets,
sibling-prefix paths and final external targets reject. This does not depend on
pnpm's versioned directory spelling. The final package's `bin` and `bin/cli` must
still pass the existing no-symlink checks; the CLI must be a regular file.

Doctor checks readability without running the tool and returns only existing
fixed readiness codes. Build uses the resolved, checked entrypoint as Node's
script argument, without a shell. The original link is not rewritten. Dry-run
retains the logical `node_modules/expo/bin/cli` argument and permits a missing
local tool, as before. Child exit codes continue to propagate.

## Limits

This is final canonical containment, not a prohibition on every link traversed
while resolving the package target. It does not relax generic `safePath`,
Android wrapper, init, archive/key or restore rules. Linked `node_modules` roots,
workspace-hoisted/external Expo packages, external virtual stores, Yarn PnP and
linked package `bin`/CLI files remain unsupported. A missing/dangling package or
missing CLI reports unavailable; loops and rejected targets report unsafe.

Dependency contents and their own imports are trusted executable application
code. A contained entrypoint does not authenticate packages, sandbox their code,
confine their subsequent imports or prove that build output is safe. Keep the
project and dependency tree under exclusive local filesystem control while
checking/building; paths can change after a check and this is not protection
against hostile concurrent filesystem mutation. Reads may update access times.
Doctor success remains prerequisite evidence, not SDK/provider/signing/build
approval. Fixture child execution is not a genuine Expo export or device proof.

## Verification

Runtime `b7e2128e6b491f1f712c5e2a984ee3810b572f5d` was verified locally on
macOS with Node 22.23.2 and npm 10.9.8.

- Baseline: 79 cases, 78 passed and one Windows-only case skipped.
- RED: 16 focused cases, six expected failures and ten passing controls before
  the resolver was added.
- Final full CLI suite: **96 cases, 95 passed**, one Windows-only case skipped,
  no failures or cancellations. The new 17 cases exercise actual CLI processes,
  readable non-executable entrypoints, relative/absolute pnpm-style links, child
  exit status and exact execution receipts, unsafe target rejection, read-only
  diagnosis snapshots/redaction, readability and missing-tool dry-run behavior.
- A real npm tarball was installed offline into a fresh local consumer with
  lifecycle scripts disabled. All **17 copied cases passed** through its installed
  CLI. All 11 archive files matched committed source and installed bytes.
- Actual pnpm **11.10.0** installed a synthetic local Expo-named tarball offline
  with scripts disabled and a task-owned store/cache. The resulting real pnpm
  package link passed installed-CLI diagnosis without running its tool, then
  executed the resolved synthetic script with exact expected arguments/cwd and
  exit zero. This establishes package-manager layout compatibility, not a real
  Expo/Metro dependency installation, release export or mobile build.

Reviewed AppGuard tarball SHA-256:
`88312e2485e0fd8cbbb2bd3074fbb7adc33d318dd91ca16fc5116f138b87cfb2`.

Independent security/correctness review found no scoped blockers. **20 additional
probes passed using 65 installed public CLI subprocesses**, and a fresh run of all
17 new tests against the installed package passed. The reviewer compared all 11
package files against Git, source, tarball and installation, and checked read-only
snapshots, redacted failures, canonical execution and exit propagation. Probes
covered multi-hop links, contained dot-prefixed paths, external/sibling/equal-root
and file targets, missing/dangling/looping links, linked bin/CLI paths, project
aliases and literal shell characters. An external bridge ending back inside the
dependency tree passes the documented final canonical containment rule.

Review receipt SHA-256:
`694f0282781315248d3e5a4751fca14c7a0f050710ef5c56ba6348798b9cb0f1`.
Review probes used synthetic tools; the parent's actual pnpm installer probe is
separate evidence. Neither establishes a genuine Expo release export. Windows
and hostile concurrent filesystem mutation were not verified. The final commit
changes only this guide; runtime/package bytes are unchanged.

Commands, reports, package/source hashes and final integration readback are kept
in the main checkout at `.superpowers/evidence/2026-10-22-cli-expo-links/` after
local integration. Counts overlap and must not be summed as unique cases. No
package installation into user applications or external release is part of this
local change.
