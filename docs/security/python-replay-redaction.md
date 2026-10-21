# Python replay exception-chain redaction

2026-10-21; independent repair from clean local main
`60330e9e6731c5e30f5e81635cf9cea8ec3afe4e`; experimental Apache-2.0 SDK.

## Reproduced behavior and repair

The Redis adapter and core verifier raised fixed replay failures inside their
dependency exception handlers using `raise ... from None`. Ordinary traceback
formatting hid the original error, but Python retained it in `__context__`.
An exception-chain reporter could therefore recover backend details, including
nested causes, notes and exception-group contents. A real refused loopback Redis
connection reproduced the retained dependency chain too. HTTP response redaction
already returned fixed codes; this repair strengthens the Python exception object.

Both boundaries now record failure and raise a fresh fixed error after leaving
the handler. In ordinary calls the public error has neither backend context nor
cause. Error types/messages, single-attempt behavior, signature-before-replay
ordering and strict success/duplicate/unavailable meanings are unchanged.
`KeyboardInterrupt` and `SystemExit` still propagate instead of being converted.
There are no protocol, dependency, retry or provider changes.

The guarantee concerns SDK-handled dependency exceptions in these two paths.
Calling from an application's active `except` block can still attach the caller's
ambient exception. This does not sanitize captured traceback frame locals or
caller-owned objects, erase backend logs, or cover all other SDK errors. Reporting
fixed codes remains the application's responsibility; arbitrary exception graphs
and local-variable capture should not be treated as sanitized SDK audit events.

## Regression evidence

- Existing non-live Redis baseline: **14/14**, three live tests deselected.
- RED new regression suite: **19 tests, 11 failed and 8 passed**. All nine
  plain/nested/grouped failures across direct core, direct Redis and combined
  Redis/core paths retained dependency context; both real refused-socket paths
  retained context as well.
- Focused GREEN after the repair: **33/33**, three unrelated live tests deselected.
  Signed requests use the committed valid vector and actual P-256 verification;
  no cryptographic verification function is replaced. Controls preserve strict
  claim results, zero claims for invalid signatures and process-control signals.
- Complete common runner: reference Python **209/209**, Python SDK **531/531**,
  Node SDK **355/355**, Spring Boot **188/188**, zero skipped tests. Python
  sdist/wheel, Java JAR, Node types and isolated npm smoke checks passed.
- Shared Redis interoperability retained all three first-claimer rotations and
  exactly one winner across concurrent Python/Node/Java processes.
- The wheel installed offline in a separate environment passed **19/19** new
  regressions using isolated Python imports, without source-checkout imports.
  All **21 SDK source files** matched source, wheel and installed copies.

Local integration requires a complete common server run with an owned disposable
Redis, an offline installed-wheel regression and source comparison, one scoped
read-only security review, clean-main fast-forward checks and merged Python tests.

One independent read-only review approved `1df7b25` with **0 Critical, 0 Important
and 0 Minor** findings. It reran the focused source suite (33 passed, three live
tests deselected), isolated installed-wheel suite (19/19) and 26 additional control,
result and ambient-context probes. It verified all source/artifact hashes and the
21 source/wheel/installed/snapshot files, and inspected without rerunning the
complete common runner. Caller exception state, local-variable capture, unrelated
SDK errors and client-configured internal Redis retries were explicitly assessed
as outside this bounded guarantee. No SDK retry was introduced.

Logs, artifacts, review and integration receipts are collected under
`.superpowers/evidence/2026-10-21-python-replay-redaction/` in the primary checkout
and hash-checked before managed-worktree cleanup. These are local checks, not
remote CI, publication, production deployment or device/provider validation.
The Unity physical-device branch and iPhone/Android waiting states remain separate.
