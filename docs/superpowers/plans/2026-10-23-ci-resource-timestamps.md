# CI resource timestamp validation

The official run and attempt responses for SDK run `39848616343`, candidate
`2c8ad421901aa8e98d3e8e787433c61bc9c1302f`, agree on identity, attempt 1,
completed status and success. Their `updated_at` values differ by one second:
`2026-10-22T20:27:37Z` and `2026-10-22T20:27:38Z`. Both independently pass
the verifier's timestamp checks. Exact cross-resource fingerprint equality
caused `run_unverified` after two requests.

GitHub documents separate [run and attempt REST resources](https://docs.github.com/en/rest/actions/workflow-runs#get-a-workflow-run-attempt).
The [context reference](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#github-context)
states that run IDs remain stable across reruns while attempt numbers increase.
No cross-resource timestamp equality guarantee was found. A different attempt-2
creation time is a policy regression case, not an observed live response.

## Bounded design

- Preserve `_run` validation and its complete fingerprint for same-resource
  rereads and latest-run comparison.
- Compare explicitly named identity and status fields between separately
  validated run and attempt documents; exclude only their creation/update times.
- Keep independent strict UTC syntax, seven-day freshness, no future times and
  creation-before-update checks for both resources.
- Preserve the container verifier's numeric repository identity, attempt-1
  restriction and final attempt comparison against its own initial fingerprint.
- Keep the original run's window for jobs, receipts, scanner and artifact times.
- Add no requests, retries, tolerance windows or transport changes. Keep API
  budgets, candidate/source/workflow hashes and latest-attempt guards unchanged.

## Implementation and verification

- [x] Add meaningful failing regressions for the observed timestamp difference
  and independently valid attempt creation times through full verification.
- [x] Add denials for invalid endpoint times, identity substitution and drift of
  each same-resource fingerprint; retain existing latest-run/attempt tests.
- [x] Implement only cross-resource identity comparison and container attempt
  fingerprint retention.
- [x] Run focused hosted/container tests, then the full release suite with the
  reviewed pinned Syft binary; check the scoped diff and freeze hashes for an
  independent review.

Eight added tests cover both verifiers. Before the implementation, the focused
suite ran 80 tests with eight failing subcases: timestamp differences prevented
successful completion or reaching the final same-resource check. After the
implementation, all 80 focused tests passed in 9.003 seconds. All 228 release
tests passed without skips in 23.404 seconds, with reviewed Syft 1.54.1 enabled.
The Darwin archive matched its pinned SHA256
`b4319c3abaa87a0170ab76ee83ea2260ca34b53aecfa3ab0dd5428d2319d744f`, and the
executable matched the archive's binary. Scoped `git diff --check` passed.

The ordinary test exchanges still use eight hosted API responses and thirteen
container API responses. The existing API caps remain nine and twenty-four.
The full candidate/source/workflow/artifact checks run in successful regression
cases; changed workflow/repository identity, endpoint timestamp invalidity and
same-resource timestamp drift remain denials. Existing pagination, latest-run,
attempt-change, source/hash and transport tests also remain passing.

## Limits

Unit transports exercise deterministic test responses only. They are not live
provider approval or a replacement for a fresh default-transport verification.
The failed official responses and assessments remain retained. Resource-specific
timestamps may differ, but same-resource metadata drift remains fail-closed.
No broader claim about GitHub timestamp propagation, artifact timing or rerun
creation semantics is inferred from the one-second observation. Production and
external approval flags remain false.
