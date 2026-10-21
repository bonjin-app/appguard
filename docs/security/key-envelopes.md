# Public-key envelope hardening

2026-10-21, experimental Apache-2.0 server SDKs; independent base
`1c18bb05a2cb850f36e62b61877404a5e2674342`.

## Reproduction and repair

The Python loader accepted concatenated valid PEM keys, junk prefixes/suffixes,
legacy headers, a leading blank/BOM and non-ASCII suffix data. Node accepted
concatenated PEM keys and trailing data. Node and Java also accepted a valid SPKI
followed by extra DER bytes or a second key; some BER/nonminimal encodings were
silently normalized. Real signed requests verified and consumed a replay claim
using those ambiguous registry records. Trusted registry input remains the
application's responsibility; no remote registry-write attack is established.

Python now requires one complete ASCII PUBLIC KEY envelope before the existing
cryptography parser. Node applies a byte-preserving envelope gate and canonical
Base64 check, imports the decoded SPKI, and requires its exported DER to match
the entire input. Java likewise compares the JCA parsed key's encoded SPKI with
the supplied DER. Existing crypto libraries remain responsible for key parsing,
curve checks and signatures; no custom ASN.1 parser or dependency is introduced.

Rejected keys return `KEY_REJECTED` before digest/signature/replay processing.
The original valid key can then verify the same signed request and nonce using
the same store. Existing LF/CRLF, no-final-newline and trailing ASCII whitespace
forms remain supported. Python/Node compressed-point support is explicitly tested
and retained; no new Java-provider encoding support is claimed. Public APIs,
wire fields, authentication and key lifecycle are unchanged.

Go's existing dedicated envelope regressions already reject ambiguous PEMs.
.NET/PHP/Java envelope guards were inspected as well; .NET/PHP were not rerun in
this stage and their runtime behavior is not inferred from static inspection.
Platform-specific PEM whitespace/encoding capabilities are not promoted into a
new universal key-serialization protocol by this repair.

## Regression evidence

- Focused baseline: Python reference verifier **55/55**, Node validation **42/42**,
  Java security-boundary suite **4/4**.
- Committed shared matrix: **23** synthetic registry encodings, using the original
  signed request and public key. Each SDK asserts zero claims for rejection and
  successful recovery with the original key in the same store.
- RED: Python **7 failed, 17 passed**; Node **7 failed, 17 passed**; Java **3 failed,
  20 passed**. The two 24-case suites additionally test compressed-point keys.
- Focused GREEN: Python **24/24**, Node **24/24**, Java **23/23**.
- Complete common runner: reference Python **209/209**, Python SDK **555/555**,
  Node **379/379**, Java **211/211**, zero skipped tests. Wheel/sdist/JAR builds,
  Node type checking and isolated npm smoke passed. Redis first-claimer rotations
  and the simultaneous process race retained exactly one successful claim.
- Offline installed wheel and npm consumers repeated **24/24 each**. All 21
  Python SDK source files and all 13 npm package files matched their source
  counterparts. A separate Java consumer, compiled and executed with only the
  SDK JAR and its own classes, repeated **23/23** without checkout classpaths.

Integration requires the complete common server runner with owned disposable
Redis, isolated wheel/npm/JAR consumers, source/artifact checks, one read-only
security review, clean-main fast-forward checks and merged-tree verification.
Receipts are collected under `.superpowers/evidence/2026-10-21-key-envelopes/`
in the primary checkout and checked before managed-worktree cleanup.
These are local results, not remote CI, publication, deployment, provider proof
or device validation. The Unity physical branch and iPhone/Android waiting
states remain unchanged.
