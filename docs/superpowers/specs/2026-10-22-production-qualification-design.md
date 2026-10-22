# Production qualification design

The approved goal is to improve production readiness without physical devices,
while retaining explicit blockers for findings and external approvals.

## Constrained Spring deployment

Reuse the pinned Python HTTP/1.1 TLS ingress. Its ASGI application collects the
complete entity body (at most 1 MiB) under an absolute upload budget before
opening a backend connection. A fixed loopback mTLS connection carries exact
method, raw target, covered headers and entity bytes to Spring. Spring alone
authenticates, verifies AppGuard signatures and claims Redis replay keys.

The backend requires an ingress-client CA, verifies end-user bearer identity,
uses the packaged starter JAR, disables forwarded-header interpretation and
HTTP/2, and authorizes only the example resource. Local processes able to read
the ingress private key remain trusted. No claim covers cloud network policy,
HTTP/2 or arbitrary proxy topologies.

The forwarder uses h11 rather than URL reconstruction, has no retries,
redirects or pooling, and bounds upload, backend work, response sizes and close.
It reports fixed public error codes without request or credential data.

## Qualification

A locally runnable tool creates ephemeral CAs and owned service processes,
then tests signed binary/UTF-8/empty/chunked bodies and exact query targets,
replay, malformed framing, absolute slow-upload limits, mTLS bypass rejection,
failure recovery and cleanup. It records actual artifact hashes and narrow
local-deployment evidence; it never records credentials. Container dependencies
must be inventoried separately from the starter-only runtime scope.

## Readiness assessment

A separate release assessment reuses the existing fail-closed publication
evidence validator. A fixed gate ledger keeps known findings blocking and
external audit, license approval, deployed environment and maintainer approval
pending. JSON booleans and an untrusted local receipt cannot certify production
readiness. The existing doctor command keeps its local-prerequisite meaning.

## Completion criteria

Implementation, adversarial regression tests, actual local Spring/mTLS probes,
artifact/runtime provenance, independent security review, documentation and CI
are required before main integration. External requirements remain explicit.
The qualification outcome cannot establish audited production release status.
