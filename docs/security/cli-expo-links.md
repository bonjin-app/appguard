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

Source, package-consumer and independent review results will be recorded after
execution. No package installation into user applications or external release
is part of this local change.
