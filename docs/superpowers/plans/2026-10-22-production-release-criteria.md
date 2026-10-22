# Production release criteria implementation plan

**Goal:** Implement reproducible operational and supply-chain verification while
retaining truthful unresolved production gates.

**Architecture:** Extend the owned-process Spring qualifier; provide a bounded
container profile; independently verify hosted jobs via GitHub API; collect
artifact-bound license evidence without approving it.

**Spec:** ../specs/2026-10-22-production-release-criteria-design.md

**Global constraints:** Apache-2.0; exact candidate/artifact binding; no physical
devices, provider account provisioning, registry publication, vulnerability suppression,
global tool configuration changes, or recursive agents.

## Tasks

- [x] Extend `scripts/qualification/spring_ingress.py` and its focused tests with
  bounded soak/concurrency and owned outage/restart/admission scenarios. Observe
  failing tests first, then verify actual signed requests and cleanup.
- [ ] Add `deploy/spring-ingress/` container build/runtime sources and an owned
  container qualification runner plus tests. Check official base-image digests;
  test actual running containers in hosted CI when no local daemon exists.
- [x] Add `scripts/release/verify_hosted.py` and focused tests. Verify live GitHub
  run/attempt/job/workflow data; forged/offline reports cannot satisfy this gate.
  Existing `assess.py` remains backward compatible and production approval stays
  pending when required external evidence is absent.
- [x] Add bounded `scripts/release/license_materials.py` and focused tests for
  exact original JAR license/NOTICE extraction, malformed ZIPs, missing material,
  changed inputs, path/symlink boundaries and redacted status.
- [ ] Run appropriate tests, actual timed operating probes and container CI;
  perform independent internal security review and fix reproduced defects.
- [ ] Update deployment/readiness documentation and four-language README links;
  integrate tested changes into main and inspect hosted runs at the exact head.
- [ ] Keep the overarching production goal active while mandatory findings or
  external approvals are unresolved; report actual engineering progress.

Workers own disjoint operational, container and hosted-verifier modules. The
main agent owns license collection, documentation, integration and final review.

The repository-level private vulnerability reporting setting was enabled and
read back separately; no provider account was provisioned. Container execution,
the final sustained run and exact-main hosted verification remain pending until
the corresponding evidence is collected. An internal scanner review identified
output races, process cleanup and empty-inventory acceptance. Regression tests
and independent review now cover the fixes; actual Linux execution remains
pending. Native Redis/JVM dependency coverage is explicitly incomplete.
