# Node verification result binding

Observed 2026-10-21 from local main base
`7faa507b2b7e6c6aeebfc4a3287391f5c616f9fa` in an independent managed worktree.
This server repair does not include the pending Unity physical-device branch.

## Reproduced behavior and repair

After validating a real signature, `verifyRequest` awaited the replay store and
then reread the caller-owned key ID and request expiry to construct its result.
Changing those records while the claim was pending could make a successful result
report a different key ID or a later expiry than the signature and replay claim.
A synchronous replay callback could trigger the same discrepancy.

The verifier now constructs its frozen result before invoking the replay store.
It uses that same captured key ID and expiry for the claim, and returns the result
only after strict `true` success. `false` still rejects with `REPLAY_DETECTED`;
exceptions and other responses reject with `REPLAY_STORE_UNAVAILABLE`, without
leaking backend error messages. Caller inputs are neither frozen nor rewritten.
The protocol, validation order, types, package exports and dependencies are unchanged.

This repair handles ordinary mutable records crossing the asynchronous boundary.
It does not isolate hostile JavaScript getters/proxies, recheck time or key
revocation after the replay wait, or add backend deadlines. Trusted application
callbacks and replay availability remain deployment responsibilities.

## Regression evidence

Six regression cases use the committed valid signed request vector and real
P-256 verification. Only the replay backend is controlled to pause or mutate
caller metadata. Assertions compare literal original metadata and replay inputs,
check that results remain frozen, and verify unchanged failure behavior.

- Targeted RED: 6 tests, 3 failed and 3 passed. The pending key ID, pending expiry
  and synchronous mutation cases exposed the original discrepancy.
- Full RED with live disposable Redis: 339 tests, 336 passed and 3 failed. All
  333 original tests passed; the failures were the new mutation regressions.
- Targeted GREEN after the repair: 6/6, zero skipped or cancelled.
- Complete common runner: reference Python **209/209**, Python SDK **512/512**,
  Node SDK **339/339**, Spring Boot **188/188**, with no skipped tests. Python
  sdist/wheel and Java packaging, Node TypeScript declarations and isolated ESM
  package smoke checks passed.
- Shared Redis interoperability: each SDK claimed first in turn and both others
  rejected replay. A simultaneous Python/Node/Java process race produced exactly
  one successful claim.
- Offline installed npm tarball: all **13 packaged files** matched source bytes;
  the same **6/6** regression cases passed against its installed ESM export.

The first attempted baseline started before dependency installation completed and
failed a framework import. That setup failure is retained separately and is not
counted as a valid baseline. The subsequent full RED included the newly added
test file and is reported as such.

## Validation boundary

Common server verification, packaged consumer evidence and security review are
recorded with the local integration receipt under
`.superpowers/evidence/2026-10-21-node-result-binding/` in the primary checkout.
The runner is `scripts/test-server-sdks.sh`, with an explicitly owned disposable
loopback Redis and the existing locked dependencies. No shared Redis database is
flushed. This is local verification, not remote CI, package publication, production
deployment, platform attestation or physical-device validation.

Unity iPhone installation/runtime and Android physical validation remain pending
in their preserved worktree. No device or provider state is changed by this repair.
