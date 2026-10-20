# Foundation threat model

Status: draft, reference-only; no external security audit has been performed.

## Assets and trust

Protect the exact request meaning and body bytes, app/key/subject binding, and replay state. The caller supplies a trusted configured HTTPS origin, authenticated subject, trusted pre-enrolled public key record, clock and replay store. The reference is not responsible for obtaining or authenticating those inputs.

The network, headers, method, request target, body, signature parameters, mobile app, local risk signals and client signing environment are untrusted. A stolen active private key can sign fresh requests; this milestone does not solve key theft or malicious authorized users.

## Attack cases and controls

| Threat | Draft control | Remaining boundary |
| --- | --- | --- |
| Body, method, URI or Bearer substitution | Signed components and SHA-256 content digest | TLS and correct raw input capture are still required |
| Origin spoofing through Forwarded headers | Origin is trusted configuration; forwarding fields are ignored | A future adapter must enforce trusted proxy configuration |
| Parsing confusion | Restricted typed profile, no control characters, duplicates or ambiguous target forms | No raw HTTP or Structured Fields parser is shipped |
| Cross-app or cross-user key reuse | Trusted key/app/subject binding and revocation flag | Enrollment, token authentication, key rotation delivery are external |
| Replay and concurrent double use | Expiry and atomic per-key nonce claim after signature verification | Local store cannot coordinate multiple processes or hosts |
| Replay-store failure/exhaustion | Fail closed with a stable reason code | Availability, durable storage and distributed consistency are external |
| Resource exhaustion | Bounded body, target, header and identifier sizes | Edge rate limits and bounded HTTP reading remain necessary |
| Sensitive diagnostics | Fixed error codes and redacted object representations | Callers must not log raw inputs or exception frames with locals |

## Failure behavior and non-goals

Syntax/profile errors precede time, trusted key binding, body digest, cryptographic verification and replay claims. Unverified requests cannot consume a nonce. Expired entries can be discarded because their corresponding signatures are no longer accepted under the same trusted clock.

The application must keep clock correctness and a long-lived replay store; constructing a fresh store per request defeats replay prevention. Process restart loses all local claims, so previously valid requests can replay within their lifetime. Persisted/distributed storage and restart protection are not provided.

Verification does not authorize an action, supply idempotency, attest an app/device, detect all automation, prevent hooking or hide code. Apple/Google integration, production HTTP adapters, authentication systems, policy presets, obfuscation, AI and performance guarantees are later milestones. No production install, provider approval or device evidence follows from passing these tests.


## Subsequent experimental integrations

The milestone exclusions above describe the initial protocol foundation.
Later client, provider, policy, build and server integrations have local evidence
in the [current support matrix](../../README.md) and its linked verification
receipts. Their narrower tests do not establish deployment, device, provider
approval or broad production security/performance guarantees. Optional native
root/hook/jailbreak hints now have [scoped local evidence](local-risk-verification.md);
they remain bypassable and never establish integrity. Optional AI/console and
unsupported deployment adapters remain future work.
