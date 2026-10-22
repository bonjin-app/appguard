# Container artifact verification implementation plan

> For agentic workers: use subagent-driven-development; no recursive delegation.

**Goal:** Verify exact-candidate owned Docker operating evidence through live public GitHub metadata and a locally supplied, untrusted artifact ZIP, preserving all independent release gates.

**Architecture:** Keep verify_hosted.py's no-offline-report CLI unchanged. A separate fixed-scope verifier reuses its safe HTTPS/source-tree checks, binds main push or workflow_dispatch runs and an attempt-specific immutable artifact, hashes a bounded local ZIP before parsing three fixed entries, and validates receipt/source/image/check relationships. Only first-attempt runs are accepted in v1 because artifact API metadata has no run_attempt. A readiness technical gate requires at least 1800 seconds, eight workers, complete functional/recovery/cleanup evidence; short runs remain verified observations but cannot pass this sustained operating gate. Image findings and native coverage remain separate and cannot be cleared by an operating pass.

**Tech stack:** Python 3.11 stdlib, existing fixed public GitHub HTTPS transport, GitHub Actions upload-artifact v4. No new packages or credentials.

## Contract

- Repository bonjin-app/appguard; branch main; workflow .github/workflows/container-readiness.yml; event push or workflow_dispatch; current completed first attempt, latest applicable run for that commit across these events; expected job owned-container-deployment. Overall run may fail only because image scan found vulnerabilities, while build/exercise and evidence staging/upload succeeded. Other failed/skipped steps deny operating verification.
- Artifact name owned-container-readiness-SHA-RUN_ID-ATTEMPT; exactly one matching unexpired artifact with matching run/repository/head identities, timestamps, size and sha256 digest, rechecked after validation. No arbitrary URL download or credentials in verifier.
- ZIP exactly binding.json, receipt.json and image-status.json at root. Reject duplicate/path/symlink/directory/encrypted/oversized/unsupported entries, excessive expansion, unsafe files and changing inputs. No extraction.
- Binding schema 1: evidence_class owned_container_ci_binding, repository, candidate_commit, run_id, run_attempt, event, head_branch, workflow_path, receipt_sha256, image_status_sha256. All fields exact and typed; no unknown fields.
- Candidate/source bytes and executable modes bound to Git commit/tree and exact workflow bytes. Receipt source_sha256 must equal qualification's defined source set at this candidate; all hashes match candidate. Receipt and image-status bind exact image IDs and qualification_sha256; fixed schema/checks, counters, resource continuity/limits, cleanup and restart replay checks validated independently. Never execute candidate code when validating untrusted data.
- Output privacy-bounded fixed summary only: hashes, fixed identities, bounded counts/booleans/reasons; never copy arbitrary strings or raw receipt/API/ZIP data into public summary. Network availability and malformed evidence fail closed. Original identities rechecked after networking.
- Staging/output parents must already exist, be owned by the current user, and have no group/other write bits; created staging directories must remain owner-only. Shared writable parents are rejected. A compromised same-user process or operating system is outside this filesystem trust boundary.
- Existing scan/consumer graph/operator/external/legal/publication gates remain unresolved unless their own evidence proves them. release_ready remains false. Physical hardware, actual deployment, providers, publication and global Codex configuration excluded.

## Tasks

- [x] Routine worker: tests first for owned binding/staging script and workflow artifact identity/layout; stage only fixed-schema receipts with validated CI identity, preserve failure propagation and fixed privacy surface.
- [x] Deep worker: failing tests then separate verifier for live run/workflow/source/job/artifact provenance, bounded safe ZIP/JSON and operating semantics; reuse fixed transport with narrowly enumerated new endpoints and no broad URL exposure. Do not weaken existing hosted verifier.
- [x] Parent: integrate paired assessor arguments, new sustained-owned-container technical gate and docs/tests; no local offline report may self-approve.
- [x] Internal review completed within the scope below; confirmed findings corrected with regressions. Independent dynamic transport/ZIP probing remains unverified.
- [ ] Full local relevant tests, fresh candidate/source scans and exact commit SDK/container CI. Merge passing bounded implementation to local main and remote; obtain exact-main SDK and live verifier evidence. A current short/finding-positive container run must remain denied for sustained readiness.

## Review focus

1. Metadata identifies a run but not its attempt: reject attempts other than 1, duplicates, changed/deleted/expired artifacts, and latest-attempt/run races.
2. Valid GitHub digest does not imply truthful operating claims: strict cross-file source/hash/check/counter/resource validation, workflow trust explicit.
3. A short run, failed cleanup/restart, incomplete counters or any malformed field cannot satisfy 1800-second sustained evidence.
4. FIFO/symlink/race/oversized ZIP/JSON/NaN and compression attacks must reject within bounded time and without unsafe extraction.
5. Download authentication is outside verifier: only live public metadata may authenticate the local ZIP; no token/host/redirect flags, no raw-data logging.
6. Accepted timestamps must sort as UTC times regardless of fractional precision. Final output must be published from an already owned private stage, with cancellation cleanup, rather than adopting a newly substituted output directory.
7. Histogram counts, global latency extrema and mean must describe a possible measurement set; no individual latency may exceed the total observed traffic window.

## Baseline

Main/origin main and reused managed worktree start clean at e4497b0. Prior goal turn changed authoritative state and supplied new Linux packaging/main CI/source scan/Docker proof; classify it as progress. That candidate's actual 30-second Docker run has 31 backend-image findings and cannot satisfy this sustained gate. Existing source HIGH findings, native dependency closure, licenses and external approvals remain independent unresolved conditions.

## Local verification and review scope

Final local verification: 169 tooling/operating tests and 214 release tests,
including actual reviewed Syft checks, pass with zero skips. The verifier has
32 focused tests. Real-verifier assessor fixtures accept sustained evidence and
deny short evidence without passing consumer, operator or external gates.

Internal reviews closed persisted-report mismatch/error handling, extra-file
upload, UTC ordering, output ownership/cancellation and latency-consistency
findings. Producer/operating reviews include bounded local tests. The independent
transport/ZIP/output review used static source and existing test-assertion
inspection only; dynamic independent probing was not completed. This is not an
external audit or a release approval. Fresh exact-commit CI and live original
artifact verification remain required.
