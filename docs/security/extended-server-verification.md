# Extended server SDK verification

Experimental, local, unpublished evidence on2026-10-20. All three SDKs consume
all40 request,43 HTTP envelope and42 policy vectors without changing the draft
protocols. Signatures never establish authenticated identity or authorization.

| SDK | Executed evidence | Deployment boundary |
| --- | --- | --- |
| [Go](../../sdk/go/VERIFICATION.md) | Official checksum-verified Go1.27.3;25 top-level tests plus197 subtest pass records, normal and race runs; vet/build; separate package consumer; actual raw loopback HTTP | net/http needs trusted pre-parser headers; Gin/Echo, TLS/H2 and distributed stores were not tested |
| [.NET](../../sdk/dotnet/VERIFICATION.md) | Official checksum-verified .NET10.0.402;175 tests,0 failures/skips; locked restore, Release build0 warnings/errors, pack; fresh isolated NuGet consumer; actual raw TCP Kestrel requests | mandatory original-header feature, no production collector; TLS/H2/IIS/HTTP.sys and distributed stores were not tested |
| [PHP](../../sdk/php/VERIFICATION.md) | Official checksum-verified PHP8.5.11 source build and Composer2.10.3;125 corpus cases/514 assertions;5 raw loopback requests; strict frozen Composer install and isolated copied-package consumer | trusted explicit ingress evidence required; Laravel/Symfony/PSR/FPM and shared replay were not tested |

The actual shared extended runner passed all three suites. Its lifecycle/error/
guard tests passed4/4; see [local CI instructions](../development/continuous-integration.md).
Remote CI has not run. PHP used `-n`; .NET certificate generation was disabled
before every later command. The one initial SDK-created localhost identity and
its precise cleanup are recorded in the .NET receipt.

## Independent native interoperability

The parent generated new ephemeral Android1 and Apple8 signed public fixtures.
All9 verified through each public Go/.NET/PHP SDK; each probe also rejected
replay, body, target and Bearer substitution, then proved rejected mutations had
not consumed the original nonce. After the .NET fix a new isolated NuGet package
consumer with an empty cache repeated all9 and checked the new public feature.
No fixture contains a private key. The producing tests use ephemeral software
keys, not persistent hardware or provider attestation.

Fixture SHA-256:

- Android: `a79a058d7e65512cda72d0582dd5551ba5ccf6f9fb0ef672f37c220d93ad06ca`.
- Apple: `eb7e353f3d599e3ba5980b08e698eba44b0c83b167b5fa400b7099cb67217dc1`.

Logs, fixture manifest and RED/GREEN evidence are locally ignored in the
checksummed `.superpowers/evidence/2026-10-20-extended-servers` archive. Package
receipts retain their own source/artifact manifests under `.evidence/`.

## Fresh review and targeted fix

One fresh whole-stage read-only review found0 Critical,1 Important and1 Minor.
No second review was performed.

Important: Kestrel can normalize trailing header whitespace, `Content-Length:02`
and CL+TE framing before middleware sees `IHttpRequestFeature.Headers`. A real
TCP probe reproduced acceptance. Seven new regressions failed (17/24 passed),
then all24 middleware tests and the full175-test suite passed after requiring
`IAppGuardRawHeadersFeature`. It must preserve original names/values/duplicates
and be attached by trusted pre-parser capture to the same request. Missing
capture rejects before authentication or nonce use. The tests capture one HTTP/1
request per connection only; this is not a reusable production collector.

Deferred Minor: Go's PEM decoder can skip a malformed/unclosed first PUBLIC KEY
block and accept a later valid block in a trusted registry record. No wrong-key,
client-input authentication or signature bypass was established; canonical
single-block key records remain the deployment contract. Strict malformed-prefix
rejection is future hardening. It does not relax P-256 or exact signature checks.

## Review rulings and costs

- Trusted raw-evidence/authentication/key callbacks are explicit integration
  boundaries. Reconstructing original headers from normalized framework state or
  accepting client-supplied capture metadata is outside the guarantee.
- Local stores are bounded/volatile and explicitly process-local; PHP state is
  interpreter-local. No cross-worker or durable-store claim is inferred. Operators
  must supply and exercise atomic shared stores before multi-process deployment.
- Explicit insecure-loopback test mode does not validate TLS termination. Forwarded
  scheme alone is insufficient transport proof; secure defaults reject it.
- ECDSA equivalent signatures still share the app/key/nonce replay tuple, so
  malleability does not bypass replay. Crypto/parsing failures precede nonce claims.
- Hostile in-process reflection, dishonest trusted callbacks and caller mutation
  races are outside the trusted host model. This choice keeps integration APIs
  small and does not isolate a compromised application process.
- Policy constructors and explicit decisions are not authorization. Applications
  retain resource permissions, rate counters, provider state and audit retention.
- Callback errors return fixed codes without raw exception causes; audit fields
  are allowlisted. Host application logging remains its own privacy boundary.

No package publication, physical device, provider account, hosted CI or production
security assurance is established by these local checks.


Follow-up: the previously deferred enrollment exception-context, Go PEM-envelope and Expo error-classification defects are resolved in [boundary hardening](hardening-verification.md). Original stage counts and review findings above remain historical evidence.
