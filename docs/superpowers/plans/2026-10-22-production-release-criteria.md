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
- [x] Add `deploy/spring-ingress/` container build/runtime sources and an owned
  container qualification runner plus tests. Check official base-image digests;
  test actual running containers in hosted CI when no local daemon exists.
- [x] Add `scripts/release/verify_hosted.py` and focused tests. Verify live GitHub
  run/attempt/job/workflow data; forged/offline reports cannot satisfy this gate.
  Existing `assess.py` remains backward compatible and production approval stays
  pending when required external evidence is absent.
- [x] Add bounded `scripts/release/license_materials.py` and focused tests for
  exact original JAR license/NOTICE extraction, malformed ZIPs, missing material,
  changed inputs, path/symlink boundaries and redacted status.
- [x] Run appropriate tests, actual timed operating probes and container CI;
  perform independent internal security review and fix reproduced defects.
- [x] Update deployment/readiness documentation and four-language README links;
  integrate tested changes into main and inspect hosted runs at the exact head.
- [ ] Keep the overarching production goal active while mandatory findings or
  external approvals are unresolved; report actual engineering progress.

Workers own disjoint operational, container and hosted-verifier modules. The
main agent owns license collection, documentation, integration and final review.

The first increment reached main at `55d728b48b346768a5d27f8bd9d49cd4604d4e49`.
Its [exact-main SDK run](https://github.com/bonjin-app/appguard/actions/runs/39794251481)
completed all five required jobs successfully and was checked by the live
commit/tree/archive/workflow verifier. The final host-process 30-minute soak
passed, while source and image findings still blocked their separate release
workflows. These completed tasks do not close the overall production goal.

## Constrained-container continuation

- [x] Extend the existing container runner with optional bounded sustained
  signed/replay traffic, actual cgroup/resource observations, failure cleanup,
  runtime identity/restriction checks and regression tests.
- [ ] Run strict short qualification on push and a separately dispatched
  1800-second/eight-worker qualification at the same frozen candidate. Bind
  receipts to that commit and retain failures instead of weakening the gate.
- [ ] Review the increment, integrate only the verified change into main,
  and recheck required hosted jobs at the integrated commit. Image findings,
  native closure and external approvals remain unresolved independently.

The repository-level private vulnerability reporting setting was enabled and
read back separately; no provider account was provisioned. Actual Linux container
execution passed all 12 operating checks at `ecab22c`, including exact runtime
versions, effective isolation, outage recovery, ordinary Redis AOF restart
retention and owned-resource cleanup. Image scanning remains failed on reported
findings. Internal review identified and fixed output races, process cleanup
and empty-inventory acceptance; actual CI additionally exposed a Docker logging
configuration failure and the process probes exposed disabled Redis reconnect.
Each continuation needs fresh sustained and exact-main hosted verification
after its source commit is frozen; separate hash-bound receipts, rather than
this implementation plan, attest those outcomes. Native Redis/JVM
dependency coverage is explicitly incomplete. Temporary encrypted diagnostic
code and its owned private key were removed before final integration; raw
scanner reports are not published.
