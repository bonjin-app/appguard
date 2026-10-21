# Node verification result binding repair

**Goal:** A successful asynchronous verifier must report the key ID/expiry used
for signature/replay verification, even if caller-owned records change while the
replay backend is pending. No new protocol fields, callback deadlines or providers.
**Base:** local main7faa507, independent managed `codex/node-result-binding`.
Preserve the unmerged Unity physical branch and its hardware gates.

1. Establish a frozen Node baseline with owned disposable loopback Redis. Add
   tests using a real valid signed vector and deferred replay promise. Mutate the
   caller key record/parameters only after the replay call starts; assert returned
   key/expiry match the original signed/replay inputs. Reproduce synchronous
   backend mutation too. Watch regressions fail before production changes.
2. Capture the successful result before invoking/awaiting replay; use the same
   captured key/expiry for replay and the eventual return. Return it only after
   strict true replay success. Preserve validation order and errors. Complete
   Node tests, types, packaged consumer and shared Python/Node/Java runner with
   isolated Redis; preserve first failures and never use a shared database.
3. One fresh scoped read-only security review, any material fixes RED/GREEN,
   source/artifact readback, CLI-independent local main integration and tests on
   merged source. No push/publication. Stop only the owned Redis after identity
   readback; archive evidence before managed-worktree cleanup.

Review focus: signed metadata/replay/result correspondence across await; false,
nonboolean or rejected replay still fails closed; no returned object escapes
before claim; public ESM/types remain compatible; mutable inputs are not rewritten;
do not imply a fresh-clock guarantee or hostile getter/proxy isolation.
