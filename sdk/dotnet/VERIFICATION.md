# .NET / ASP.NET Core verification record

Task 1 of `docs/superpowers/plans/2026-10-20-appguard-extended-servers.md`, completed locally on 2026-10-20. Scope is `sdk/dotnet/**`; no index staging, commit, publication, provider account, shared backend or production operation was performed by this owner. Parent owns the fresh whole-stage security review and integration.

## Runtime and provenance

- Task-local Microsoft .NET SDK **10.0.402**, host/runtime **10.0.13**, ASP.NET Core **10.0.13**, `osx-arm64`, executing on reported macOS **27.0**. This records the tested host; it does not assert additional Microsoft OS support certification or tests on Windows/Linux.
- Official current release metadata: `https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json`; .NET 10 is active LTS in the [official support policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core).
- Download: `https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.402/dotnet-sdk-10.0.402-osx-arm64.tar.gz`.
- The complete archive SHA-512 matched official metadata before extraction:
  `ee0d379c144ebddef6efe851e1514883d1b695430d13b3fb13e8153f8476e1e5ac7abc42c08668471aaf4d738ff367cf53009845f94d224ba126febe74d00b75`.
- Runtime/archive, CLI/package caches and raw evidence remain ignored under `.tools/` / `.evidence/`. SDK pin: `global.json`; exact test package versions plus checked-in NuGet locks. Runtime SDK project has no third party package dependencies.
- Apache-2.0 `LICENSE` is byte-identical to root `LICENSE`: SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`.

## Verification outcomes

1. Test-first API scaffold: **163 cases, 119 failed / 44 passed**. Positive request/wire/policy cases and missing implementation behavior failed as expected (`.evidence/red.log`).
2. Implemented core/middleware/policy/audit: **163 / 163 passed** (`green-1.log`).
3. Additional transport regression: `SchemeAndForwardedHeadersCannotFakeTlsTransport` failed because a rewritten HTTPS scheme reached downstream without a TLS feature; **1 failed / 165 passed** (`tls-red.log`).
4. Required actual TLS connection feature, added independent crypto/nonce and middleware coverage: **168 / 168 passed** (`green-2.log`).
5. Fresh `APPGUARD_DOTNET="$PWD/.tools/dotnet/dotnet" ./scripts/verify.sh`: **locked restore passed; full Release suite 168 passed / 0 failed / 0 skipped; solution build passed with 0 warnings / 0 errors; pack passed** (`final-verify.log`).
6. An isolated console consumer under `.tools/consumer` used only the exact local `.nupkg` through a local-only NuGet source and its own package cache; no source `ProjectReference`. Restore/build/run passed. It exercised core/wire/replay from the public fixture plus policy defaults, audit and middleware API construction (`consumer.log`).
7. The public test-only interoperability probe passed the baseline fixture: wire metadata/signature equality, core verification, replay rejection, body/target/token mutation rejection and no nonce consumption by rejected mutations (`probe.log`). Fresh Android/Apple fixture runs are a parent integration step and are not claimed by this owner's baseline run.
8. Package inventory was read back: DLL, NuGet metadata, README and LICENSE only; no fixture, `.tools`, `.evidence`, runtime or private key files. Source whitespace scan passed; generated artifacts, logs and tool/runtime caches are ignored.

The 168 cases include **all 40 request, 43 HTTP envelope and 42 policy corpus cases**, plus 43 security/middleware cases. Extra coverage includes independent native .NET P-256 signatures, exact 64-byte raw versus DER format, wrong curves/private keys/trailing PEM/key expiry, invalid timestamp/null inputs, digest/signature validation before replay, equivalent ECDSA signatures sharing one nonce, a 100-way atomic claim race, capacity/expiry/cancellation/store errors, defensive copies, default missing authentication, policy/audit validation and callback redaction.

Four actual Kestrel HTTP/1.1 tests send raw TCP requests over owned ephemeral loopback listeners. They cover encoded target case/order and configured-origin behavior despite hostile Host/forwarding values; an explicit empty query; singleton duplicates; altered target/framing; chunked framing with exact downstream body; and replay rejection. Direct middleware tests cover missing raw feature/target, scheme spoofing, trusted clock after authentication, identity preservation, dependency failure/status redaction, overflow/incomplete body/cancellation, and downstream exception/body-restoration behavior. These are local virtual server tests, not deployment or physical-device proof.

## Artifact

Local unpublished package:
`artifacts/AppGuard.Experimental.0.0.0-experimental.1.nupkg`

SHA-256:
`4adef65632e55487b808f46410fc33f8a6d53212a614e20c1c01011ee70cedb4`

It was built from this owner's uncommitted worktree snapshot. Automatic NuGet repository commit metadata identifies the underlying base commit and is **not** a claim that this new SDK already exists in that commit. `.evidence/source-files.sha256` binds the current source/test/config/documentation snapshot; parent must commit/rebuild/reverify before any future publishing claim. No NuGet publication took place.

## Reproduce native-client interoperability

After the solution Release build, from `sdk/dotnet/`:

```sh
DOTNET_GENERATE_ASPNET_CERTIFICATE=false \
DOTNET_CLI_HOME="$PWD/.tools/cli-home" \
DOTNET_CLI_TELEMETRY_OPTOUT=1 \
.tools/dotnet/dotnet \
  tools/InteropProbe/bin/Release/net10.0/InteropProbe.dll \
  /absolute/path/to/native-fixture.json
```

The test-only probe accepts one object or an array (1..100 fixtures, file at most 2 MiB) in `scripts/verify_client_vector.py`'s native fixture format. It consumes public keys only, prints fixed results, and never exports or requests private keys. It is not included in the runtime package.

## Deliberate boundaries and remaining verification

- No distributed store is included or simulated as production-ready. `InMemoryReplayStore` is explicit, bounded, atomic, volatile and **process-local**. A real deployment must supply and test its shared `IReplayStore`; no Redis/backend durability, eviction, replication or restart claim was tested.
- Default secure transport uses trusted `ITlsConnectionFeature` plus HTTPS scheme, since forwarding middleware can rewrite scheme. Hosts without that trusted feature reject unless the operator explicitly enables the documented insecure/TLS-termination boundary. Actual TLS handshake, HTTP/2/3, IIS/HTTP.sys, reverse proxies, decompression and production deployment were not integration-tested.
- Headers reflect the server feature collection with each value enumerated. No API can recover evidence previously normalized/discarded by a proxy/server or body-consuming middleware. Installation order and trusted feature capture remain host obligations; unavailable target/body evidence fails closed when observable.
- Authentication, key enrollment/revocation distribution, platform attestation, application rate limiting, resource authorization, audit availability/retention/privacy and production provider state remain caller-owned. Signature success cannot grant any of those properties.
- Parent's fresh whole-stage review and independently generated fresh Android/Apple signature runs remain separate evidence tiers.

## Automatic SDK certificate side effect and cleanup

The first task-local `dotnet test` invocation unexpectedly generated an untrusted ASP.NET localhost development certificate in the user's login Keychain. No trust action occurred. Creation time **2026-10-20 08:07:21 UTC**, the task first-use sentinel/time and ASP.NET OID `1.3.6.1.4.1.311.84.1.1` identified it; `security find-identity` proved its exact private-key association and `CSSMERR_TP_NOT_TRUSTED` status.

Only that exact certificate/private-key identity was removed using `security delete-identity -Z <exact SHA-256> <login keychain>`, with no broad cleanup or trust settings change:

- SHA-256 `4B10EDFF36396C1ACF3CF9ADADAC6E8691CC18E324AE59B3C4C9350FBC518C12`
- SHA-1 `662AAA3687F657D60FFB3E3E7F76074CB318A66C`

Fresh post-verification readback found no localhost certificate and zero matching SSL server identities. No pre-existing identity was removed. All later SDK commands and the checked-in verification script set `DOTNET_GENERATE_ASPNET_CERTIFICATE=false`; no global SDK installation or shell/profile changes were made. Detailed cleanup evidence is in `.evidence/certificate-cleanup.txt`.
