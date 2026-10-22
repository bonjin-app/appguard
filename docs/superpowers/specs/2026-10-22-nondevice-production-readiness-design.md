# Non-device production-readiness engineering

Status: implementation authorized by the user's request to add all technically feasible work excluding physical devices. This extends the existing approved AppGuard platform design. It is not production certification.

## Outcome and boundaries

Close the identified source-level and reproducible-test gaps without changing existing request protocol semantics or removing fail-closed behavior. Preserve existing callers and the pending physical-runtime branch. No real credentials, account enrollment, certificate/private-key issuance, registry publication, deployment, external audit claim or global Codex configuration change is included.

## Work packages

1. Shared replay: optional configured Redis adapters for Go, .NET and PHP using maintained client libraries/interfaces, the existing canonical hashed key and atomic SET NX EX contract. Reject invalid time/scope/backend outcomes, do not auto-connect/discover credentials, preserve host ownership. Test actual independent Redis claims and cross-language replay.
2. Apple lifecycle: retain verified initial public key/receipt metadata through an additive API, verify strict bounded assertions and authenticated request/challenge bindings, persist monotonic counters and one-use challenges atomically, separate app/subject/environment, support revocation/restart/concurrency. Add independently validated receipt/assessment helpers only to the extent supported by current official Apple formats; opaque or synthetic data must never be called genuine provider validation.
3. Google credential lifecycle: explicit service-account OAuth token source with fixed audience/scope/endpoint, bounded HTTPS, expiry/refresh and redacted failures; no credential discovery or network on import/construction. Real server/provider calls remain operator-configured.
4. Real ingress: a concrete version-bounded Python server integration preserving exact raw targets/headers/body under TLS, including trailing question marks, with actual socket tests. Preserve application authentication/authorization and fail closed on missing transport evidence. Configure bounded admission/timeouts and graceful shutdown in the example rather than claiming arbitrary deployments are covered.
5. Operations qualification: owned disposable Redis persistence/crash/restart/outage scenarios, deterministic malformed-input/fuzz corpus, concurrency/load benchmark with machine-readable measurements and explicit resource/deadline checks. Never connect fault injection to a supplied shared database or mutate its configuration.
6. Release readiness: reproducible source/package preparation, checksums, dependency/SBOM and license evidence, offline/package consumer validation and vulnerability scanning in CI. Output release candidates and evidence; do not silently publish packages or manufacture support commitments/audit approval.
7. Integration: update protocol/deployment guidance and all four root README summaries consistently. Run scoped red/green regressions, full affected SDK suites, fresh hosted CI and independent read-only code/security review; integrate only verified changes.

## Common invariants

- A verified signature or attestation does not authorize resource access.
- No private key export, token/body/evidence logging, permissive fallback or silent async callback delivery.
- Cryptographic parsers are bounded, whole-input and ambiguity rejecting.
- Replay and monotonic counter updates are atomic across independent clients/processes. State must survive the documented restart scenario; Redis durability remains conditional on the tested operator configuration.
- Test data, generated certificates and local fixtures establish software behavior only, not Apple/Google/device approval or secure-hardware efficacy.
- Existing experimental APIs remain compatible; new integrations are explicit opt-in.

## Completion evidence

Each work package records implementation, executable tests and reviewed limits. A consolidated readiness report lists completed software evidence and unresolved external gates. Anything not supported by observed evidence remains pending rather than being labeled production-ready.
