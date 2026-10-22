# Native container platform qualification plan

Apply the [approved bounded design](../specs/2026-10-23-native-container-platform-design.md)
on branch `codex/arm64-container-qualification` from `90ade9f`. Do not change
runtime Dockerfiles, global configuration, main's active run, frozen evidence,
production security timeouts or approvals. No delegation, commit, push or live
dispatch precedes root review.

1. Add meaningful RED tests for qualifier native host/daemon/image/PID1 binding,
   pre/post mutation, bad ELF class/machine, exact role IDs, and unchanged legacy
   behavior. Add scanner RED tests for verified native ARM mode, no-block ARM
   refusal, image/platform changes, legacy schema compatibility and findings.
2. Implement bounded qualifier observations and owned Compose platform override.
   Add optional schema-1 receipt block without changing existing core/operating
   check names or positional caller defaults. Require post observation before
   technical completion, retaining false/partial data on failure and cleanup.
3. Extend only the existing three-role scanner explicit mode and reviewed ARM
   pin eligibility. Independently inspect native host/daemon and immutable image
   platforms before/after scanning and at publication guards. Keep reports,
   counters, unsuppressed findings and existing role/inventory policy intact.
4. Extend standalone binder and formal verifier with independent exact optional
   schemas, complete cross-artifact relations, reviewed native scanner pin and
   fixed job-label checks. Add fail-first malformed/missing/mismatched/forged
   block tests, and preserve both old image schemas and the strict latest union,
   source/run/attempt/time/hash guards and API request budget.
5. Add the fixed workflow choice/runner mapping, architecture concurrency and
   quoted `--platform` handoff inside the existing step. Execute actual workflow
   shell preflight with owned fixtures and static workflow checks. Add optional
   expected-platform formal CLI coverage; no assessor contract changes.
6. Run focused suites, full tooling with the explicit owned Redis binary and full
   release tests with pinned Syft. Preserve RED/GREEN logs, source hashes and
   limitations privately; freeze for independent review. Root then coordinates
   CI and real short/full ARM runs after the active main run has settled.

Local fixtures prove parser/control behavior only. Actual native execution,
three-service functional and 1,800-second operating evidence, exact ARM image
findings, hosted metadata authentication and cleanup remain separate observed
CI results. No GUI/audio package additions or clean/native-closure claim follows.

## Observed local verification

The initial tests were RED on base production source `90ade9f`: the new native
snapshots/override were unavailable, forged optional receipt blocks were ignored,
native ARM scanning was refused, workflow handoff omitted the platform and the
formal verifier did not support the new claim. A subsequent fail-first test
showed that the initial scanner implementation did not recheck the daemon after
scanning; the final implementation rechecks native host/daemon at post-scan and
publication guards as well as image platforms. Private logs retain these failures.

Final focused checks passed: 12 platform tests, 41 existing qualifier tests,
48 existing scanner tests, six real workflow-shell tests and 48 formal container
tests. The full tooling suite passed 285/285 with the explicit owned Redis
7.2.16 binary (zero skips); the full release suite passed 234/234 with pinned
Syft (zero skips). Pinned actionlint 1.7.12 passed with shellcheck/pyflakes
disabled; the workflow shell tests independently execute the preflight.
Scoped diff checks passed. No Docker/APT/native runtime was executed locally.

The exact bounded platform protocol is specified in the companion spec. The
unchanged latest-run union, both legacy image schemas without a platform claim,
false/partial diagnostics, mismatched expected platform and late publication
mutation are covered. Root coordinates independent source review and actual CI;
these local results are not the remaining real ARM topology qualification.
