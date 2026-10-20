# Local implementation milestone

2026-10-20; Apache-2.0; experimental source, no published release.

Implemented locally: one strict request/wire/enrollment/policy contract; Spring
Boot, Python, Node.js, .NET, Go and PHP verification SDKs; Android/Apple native
installation keys and request protection; Unity/Expo/Flutter native bindings;
Android build protection and bounded Flutter/Expo build commands; CLI with
AES-GCM mapping retention; deterministic policy/allowlisted audit; optional Python
Apple initial-attestation and Google Standard backends and Android acquisition.
All shared server protocols retain explicit authentication/key/replay dependencies.

Final core runner passed1156 tests (reference209, Python474, Node309, Java164),
zero failures/skips. Wheels/JAR/npm types and isolated package checks passed.
Live disposable Redis replay passed with Python-first, Node-first, Java-first
and concurrent independent SDK processes: exactly one claim in every case.
The full extended runner passed Go/race/vet/build, .NET175 tests/build/pack and
PHP514 assertions/5 raw HTTP requests. Test counts of different kinds are not
summed as independent security assurances. Isolated wheel provider223 tests are
a subset of Python474. Native/bridge/build results are separately recorded:
[bridge/Build](client-bridges-build-verification.md),
[native](mobile-foundation-verification.md),
[extended](extended-server-verification.md),
[provider](provider-verification.md), [CI](../development/continuous-integration.md).

One whole-stage review per implemented stage, followed by targeted fixes without
re-review, is recorded in those receipts. Minor issues deferred at this milestone were:
Python EnrollmentService callback exception context, Expo unavailable/error
classification, Go malformed-leading-PEM tolerance for trusted registry records.
Those three defects were subsequently resolved in the [boundary hardening follow-up](hardening-verification.md). No Critical or Important finding remained open in the original stage reviews. This is
scoped local review evidence, not independent security certification.

The roadmap's local experimental implementation goal is bounded by these
receipts. Local root/hook/jailbreak heuristics, complete Apple assertion/receipt/
counter lifecycle, additional production ingress/build adapters, optional console
and AI remain future work. Genuine provider/device integration, persistent Apple
Keychain/Secure Enclave, framework mobile-player execution, hosted CI, performance
qualification, package publication and deployment have not been established.
No test result means a production app is protected merely by installing a package.

Original main is integrated only by an authorized clean fast-forward; no history
rewrite, remote push, release or account configuration is part of this milestone.
Local artifact/log/checksum evidence and task-local runtimes remain preserved in
the attached worktree, outside Git. Source packages, locked dependencies and
reproduction instructions are committed; a fresh checkout supplies its own tools.
