# Node policy own-field validation implementation plan

> **For agentic workers:** Use superpowers:executing-plans for this bounded repair.

**Goal:** Reject recognized policy/context/evaluation/audit fields inherited from
Object.prototype. Only explicitly owned fields can configure security behavior.
**Base:** clean main `cacfeae3302dcbee391ed8524a7e0e730e3da333`.

- [x] Establish the focused policy baseline. Add isolated child-process regression
  cases in `sdk/node/test/policy-inheritance.test.js` for inherited policy defaults,
  context verdicts, evaluation time and audit metadata. Observe the failures.
  Cover explicit own fields, null-prototype inputs and unchanged valid defaults.
- [x] Harden the shared `options` predicate in `sdk/node/src/policy.js` to reject
  recognized inherited fields. Preserve unknown-own-field rejection, errors,
  explicit Basic signature optout, legitimate own undefined defaults and exports.
  Do not mutate/freeze globals or caller inputs. Run focused GREEN, the complete
  shared server runner with an owned disposable Redis, types and package smoke.
- [x] Run the regression against the offline installed npm tarball and compare
  its source bytes. Document exact guarantees and limits in the Node README and
  `docs/security/policy-own-fields.md`. One fresh scoped read-only security review,
  resolve material findings, fast-forward clean local main, rerun merged Node
  tests. Stop only the owned Redis and archive evidence before worktree cleanup.

No new protocol, provider, dependency, global prototype lockdown, hostile runtime
isolation, push or publication. Dynamic application-owned replay callbacks are
outside this repair; adapter setup has never promised to freeze store internals.
Unity physical-device branch and its pending validation remain separate.
