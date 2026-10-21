# Public-key envelope hardening implementation plan

> **For agentic workers:** Use superpowers:executing-plans for this bounded repair.

**Base:** clean main `1c18bb05a2cb850f36e62b61877404a5e2674342`.
**Goal:** Reject ambiguous registry key material before digest/signature/replay:
one PUBLIC KEY PEM envelope containing one complete DER SPKI key.

1. Establish focused Python/Node/Java key-validation baselines in the managed
   worktree. Add committed synthetic `conformance/v0/public-key-pem.json` and
   corresponding verifier tests in all three SDKs. Verify actual fixed signatures,
   zero replay claims for rejected keys and successful retry with the original
   key/nonce. Observe RED before changing loaders.
2. Python: bound and match one complete ASCII PUBLIC KEY envelope before the
   existing cryptography parser. Node: match the same envelope, validate complete
   Base64 input, and compare imported/exported SPKI DER to reject ignored bytes.
   Java: compare supplied DER with the parsed key's encoded SPKI. Leave curve and
   signature verification to existing crypto libraries; add no ASN.1 parser or
   dependency. Preserve supported LF/CRLF/no-final-newline and trailing ASCII
   whitespace forms, and existing Python/Node compressed-point support.
3. Finalize SDK documentation, then run the complete common server runner using
   a new owned disposable Redis. Test isolated offline wheel/npm consumers with
   the same matrix and compare package/source bytes. One fresh read-only security
   review of the whole repair, resolve material findings, then clean-main
   fast-forward integration and merged-tree verification.
4. Stop only owned services after identity readback; archive artifacts, logs and
   hashes before native worktree cleanup. Preserve the unmerged Unity physical
   branch and pending iPhone/Android validation. No push or publication.

Scope: registry parser ambiguity, not key enrollment or attacker access to a key
registry. Other SDK envelope guards are inspected separately; do not infer their
runtime verification from source inspection. No new wire fields or authentication
behavior. Client builds, providers and physical devices remain outside this stage.
