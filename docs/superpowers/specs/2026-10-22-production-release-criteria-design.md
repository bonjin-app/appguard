# Production release criteria

The user requested a production-grade goal, excluding physical devices. This
goal remains open until the required conditions are actually satisfied; a
completed engineering increment is not completion of the product goal.

## Release definition

All distributed components and their supported build inputs need recorded
dependency closure, vulnerability handling, license/NOTICE materials, tested
installation, operating limits, deployment qualification and release provenance.
Production approval additionally needs the project's external security review,
license review, supported provider-account validation where claimed, and
maintainer approval. No boolean in an imported JSON file can provide approval.

Source and runtime scan findings remain blocking. On 2026-10-22 official package
and upstream evidence still offered no published fix for the two Expo build-tool
HIGH findings. An unmerged cryptographic patch is not adopted to obtain a clean
scanner result. Build dependencies remain in recorded coverage.

## First engineering increment

1. Exercise the actual packaged Spring deployment under sustained concurrent
   signed requests, replay, Redis outage/recovery, backend restart and ingress
   admission pressure. Record bounded latency/failure/counter/resource data and
   owned-process cleanup. Test-time shutdowns must never target existing services.
   A timed local soak is not long-term cloud operating evidence.
2. Supply reproducible container deployment sources for the same HTTP/1.1 mTLS
   topology. Only the frontend port may be published. Backend and Redis stay on
   a shared private loopback network namespace, preserving the current backend's
   fixed loopback-only transport boundary. Services run without root, with
   dropped capabilities, read-only roots, bounded memory/PIDs and explicit keys.
   Base images require reviewed immutable digests; no registry upload is done.
3. Verify hosted CI from GitHub's authenticated HTTPS API rather than imported
   success flags. Bind repository, workflow bytes/path, commit, run attempt,
   completed status and all required jobs. Keep technical verification and
   production/external approval separate. Do not change v1 compatibility.
4. Collect original license/NOTICE files from the actual exported Maven JARs
   with their exact hashes and original locations into a bounded review bundle.
   Missing materials are visible; collection does not approve legal obligations.

## Evidence and trust

Every tool binds candidate/source and artifact hashes, rejects ambiguous or
changed inputs, bounds input sizes and I/O, and emits privacy-bounded status.
Private certificates/logs remain temporary; no operating-system trust changes,
external account configuration, production traffic or customer data are used.
Docker daemon access is used only on an available owned test runner; global
Docker configuration, existing containers, caches and credentials are preserved.

Independent internal review and same-commit CI are required before main
integration. External audit, live provider/account checks and operator release
signoff remain required and explicitly pending. This increment cannot turn
`release_ready` true while those or vulnerability conditions are unresolved.
