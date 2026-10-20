# Contributing

AppGuard is an early draft. Protocol changes must update the normative profile, public test fixtures and reference tests together. Do not describe planned SDKs as released or simulated evidence as provider/device verification.

Use Python 3.11+ and uv. Run the README's locked install and test commands. Commit `reference/python/uv.lock` when changing dependencies. Use stable releases. Keep modules focused, retain input limits, and add a failing attack/regression test before changing security behavior.

No live credentials are required. Test keys and fake Bearer strings are public test material, never enrollment or production secrets. Keep logging free of token values, request bodies, private keys and signature-base bytes.

Contributions are accepted under Apache-2.0; retain required upstream licenses and attribution when introducing third-party material. Do not add a dependency or copy code without checking its license and maintained status.

Before proposing a change, run `git diff --check` and the complete test suite. Include the commands and results, and distinguish reference/unit evidence from framework, provider, device, deployment and external-audit evidence.
