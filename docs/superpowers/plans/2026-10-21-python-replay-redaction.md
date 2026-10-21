# Python replay exception redaction implementation plan

> **For agentic workers:** Use superpowers:executing-plans for this bounded repair.

**Goal:** SDK-handled replay backend exceptions must not remain attached through
`__context__` or `__cause__` on the fixed public replay failures.
**Base:** clean local main `60330e9e6731c5e30f5e81635cf9cea8ec3afe4e`.

1. Install locked Python dependencies in the managed worktree and establish the
   existing non-live Redis baseline. Add `sdk/python/tests/test_replay_redaction.py`
   with real signed-vector verification, controlled backend failures with nested
   causes/groups, and a real refused loopback Redis connection. Observe RED.
2. Update only the backend catch boundaries in `sdk/python/src/appguard/verify.py`
   and `redis.py`: raise fresh fixed errors after their handlers have unwound.
   Preserve strict claim results, crypto-before-claim order, process-control
   BaseException propagation, no retries and the existing protocol/public API.
3. Run focused GREEN and the complete common server runner with a new owned
   disposable loopback Redis. Build/install the wheel in a separate environment,
   rerun the regressions there and compare installed source hashes. Finalize the
   Python README and `docs/security/python-replay-redaction.md` before packaging.
4. One fresh scoped read-only security review; fix material findings. Clean-main
   fast-forward integration and merged-tree Python verification, stop only the
   owned Redis after identity readback, archive/hash-check evidence before native
   worktree cleanup. Keep the Unity physical branch and hardware gates unchanged.

Limit: this removes SDK-handled dependency exception chains in ordinary calls. It
does not sanitize arbitrary caller `except` state, traceback-local capture, hostile
objects or all other SDK errors. No provider/device actions, push or publication.
