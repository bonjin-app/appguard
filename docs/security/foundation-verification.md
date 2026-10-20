# Foundation verification record

Date: 2026-10-20. Scope: experimental `appguard-request-v0` typed-input reference.

## Local evidence

Environment: Python 3.11.15, uv 0.13.3, cryptography 50.0.2, pytest 9.1.1, system LibreSSL/OpenSSL CLI 3.3.6. Exact Python dependencies are recorded in `reference/python/uv.lock`.

```sh
uv sync --locked --project reference/python
uv run --project reference/python pytest reference/python/tests -q
uv run --project reference/python pytest reference/python/tests/test_vectors.py -k openssl -v
git diff --check
```

Before independent review: **207 tests passed**, including all 40 portable scenarios and the external OpenSSL check. The full suite also passed from `/tmp` with absolute project/test paths, showing that fixture discovery does not depend on the caller's working directory. No tests were skipped in this environment.

TDD evidence was observed during implementation: initial canonical/crypto tests failed against unimplemented behavior, then 72 passed; replay/verification tests then brought the suite to 141; corpus transport/scenario tests and independent CLI verification brought it to 207. The binary NUL-body digest literal had a transcription error corrected against the independent CLI's SHA-256 output before the canonical/crypto commit.

Fixed expected signature-base bytes were constructed independently of the canonicalizer. Four distinct valid signed bases (JSON, empty body, encoded slash, lowercase escape) were signed and independently verified by the system CLI; the committed suite rechecks them. Public keys and fixed signatures are synthetic public material. Private signing material is not part of the source tree.

Concurrency tests synchronize 32 threads and require exactly one live nonce claim and one successful complete verification. They also check that invalid signatures do not reserve a nonce and that capacity exhaustion never evicts an unexpired claim. This demonstrates only single-process behavior.

## Evidence limits

These are local functional and reference interoperability checks, not production benchmarks, a formal cryptographic proof or an external audit. Raw HTTP parsing, framework SDKs, authenticated enrollment, distributed/durable replay storage, Apple/Google service verification, physical devices, build obfuscation and deployment have not been implemented or verified in this milestone.

See Git history for the tested source changes and the approved plan for the boundary of this work. No SDK package has been published.
