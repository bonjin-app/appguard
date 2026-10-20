# Policy and audit ports verification

Observed locally on 2026-10-20; implementation `d3adedd`. Python, Node.js and Java execute the same42 portable policy cases. No middleware enables these explicit APIs automatically.

The root server verification ran209 reference tests,251 Python SDK tests,309 Node tests and164 Java tests: **933 passed, zero failures/skips**. Wheel/source distribution, JAR, TypeScript declarations and isolated npm package installation also passed. The script's final separate cross-SDK replay probe initially exceeded its30-second Java process limit under host load; the complete command therefore did not initially exit successfully. A diagnostic Java invocation succeeded in27.306 seconds, with its thread dump showing runnable Lettuce proxy initialization rather than a blocked Redis request. An unchanged retry then passed all four probe scenarios: Python, Node and Java first-writer rotations, and exactly one winner across concurrent SDK processes. No timeout or production behavior was relaxed. The Redis service was newly created on loopback and owned by this task; no existing database was flushed or reused.

One fresh read-only whole-port reviewer reported **no Critical, Important or Minor findings**. Independently executed Node policy tests passed51/51, and25,920 authentication/verification/attestation/expiry/rate/hint/profile combinations matched Python exactly. Additional Node shape, maximum timestamp, step-up and asynchronous sink probes passed. Java source review and the parent full Maven suite are distinct evidence; an unsupported macOS stdin probe did not establish an extra Java runtime result.

Owner RED/GREEN tests cover caller-array iterator mutation and Java copied-list bounds. Validated values retain immutable copies, missing authentication denies by default, Basic alone may explicitly opt out of request signatures, and step-up does not permit processing. Audit output uses fixed validated actions/reasons and explicit fields. Node awaits sync/async delivery; Java's documented synchronous callback preserves interruption and drops the original exception cause.

Review rulings and limits:

- Constructing a valid fixed decision is a supported API, not proof evaluation ran. Applications own their authorization control flow; misuse can bypass their own intended policy.
- ID grammar cannot prove semantic opacity. Callers must keep credentials/user identifiers out of event/app IDs, or those values can still reach their audit sink.
- Reflection, hostile prototypes and malicious application-process replacements are outside an isolation guarantee. Compromised application code can bypass its own checks.
- Java normalizes callback Exceptions; fatal JVM Errors are outside the contract and can still terminate processing.
- No new provider verifier, authentication system, rate counter, distributed enrollment store or HTTP policy enablement is implied. These remain explicit dependencies.

Raw RED/GREEN and full-server/probe logs, source records and the review ledger are archived locally with SHA-256 manifests under ignored `.superpowers/evidence/2026-10-20-policy-ports/`. This is local runtime evidence, without remote CI, deployment, account/provider or production security proof.
