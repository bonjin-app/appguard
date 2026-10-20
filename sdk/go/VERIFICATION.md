# Go SDK verification receipt

Point-in-time evidence: 2026-10-20 08:25 UTC. Experimental local source; unpublished.
All implementation changes are under `sdk/go/`; no staging or commits were made by
this task owner. The package [LICENSE](LICENSE) is byte-identical to the repository's
Apache License 2.0. Parent whole-stage security review and fresh native-client
integration remain separate evidence gates.

## Runtime and source inputs

No Go executable was present on PATH or the inspected mise install paths. The task
used an official task-local archive, never a global installation/profile change:

- Runtime: `go version go1.27.3 darwin/arm64`.
- Archive: <https://go.dev/dl/go1.27.3.darwin-arm64.tar.gz>.
- SHA-256: `dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2`.
- Expected checksum/version came from the live official
  <https://go.dev/dl/?mode=json> response, preserved in `.tools/downloads.json` and
  `.tools/runtime.json`; the archive checksum was verified before extraction/use.
- Go executable, GOPATH and build cache are under ignored `.tools/`.
  `GOTOOLCHAIN=local` prevented automatic runtime downloads.
- `go.mod` declares Go 1.26.0, module `github.com/bonjin-app/appguard/sdk/go`.
  Only Go 1.27.3/macOS ARM64 was actually exercised. The declared minimum/other
  platforms have not been independently run. The SDK has no third-party modules;
  `go mod tidy` generated no `go.sum`.

The normative protocols and Python/Node implementations were inspected. Shared
corpus inputs were consumed directly from the repository, without modifying them:

| Corpus | Cases | SHA-256 |
| --- | ---: | --- |
| `conformance/v0/requests.json` | 40 | `9ef1fe5db7f1b608d5e844eaa8eb21ea95c31540dd2cfc3cd36c539824ea3177` |
| `conformance/v0/http.json` | 43 | `1bf594a6c8925f4e1c6e4a18ba0308358d293388d7b148975bcf99ed1f52cf90` |
| `conformance/v0/policy.json` | 42 | `235e6eeb63e3d9fe50531c8fb1b31b9f1cb73611e13a1fa8ad8010355ad59dc1` |

## Fresh checks

All commands used task-local GOPATH/GOCACHE and `GOTOOLCHAIN=local`.

| Command | Result |
| --- | --- |
| `go test -count=1 -json ./...` | Exit 0: both packages; 25 top-level tests + 197 subtest pass records; 0 failures |
| `go test -race -count=1 -json ./...` | Exit 0: same 25 + 197 pass records; no race reports |
| `go vet ./...` | Exit 0, no diagnostics |
| `go build ./...` | Exit 0, no diagnostics |
| Separate temporary consumer: `go mod tidy`, `go build`, executable | All exit 0; public request verification, replay rejection, blocked step_up and allowlisted audit JSON |
| `go run ./tools/verify-fixture .evidence/public-request.json` | Exit 0; wire/typed/core verification, replay and body/target/token mutations rejected |
| `gofmt`, Apache license comparison | No formatting differences; identical license bytes |

The pass-record counts include 125 portable corpus subcases, 72 additional named
boundary/concurrency/HTTP subcases, plus top-level tests with further looped
assertions. They are test event counts, not counts of independent production
systems or security assurances.

Raw logs and the final source SHA-256 manifest are under ignored `.evidence/`:
`test.jsonl`, `race.jsonl`, `vet.log`, `build.log`, `consumer.log`, `fixture.log`,
`verification.json`. The manifest binds executed checks to Go source bytes.

## Coverage and RED/GREEN evidence

- Initial corpus tests failed on absent public APIs (`corpus-red.log`), then all
  request/wire/policy vectors passed after the implementation (`core-green.log`).
- HTTP tests failed on absent middleware APIs (`http-red.log`), then real local
  HTTP/1.1 tests passed (`http-green.log`). They use a test-only, trusted pre-parser
  connection capture with `Connection: close`, not a fabricated `Header` snapshot.
- Additional RED tests demonstrated Go fixed-array JSON evidence loss and a
  cancelled store call returning success (`hardening-red-confirmed.log`). Strict
  two-string header unmarshalling and a post-store cancellation check closed those
  paths (`hardening-green.log`). A failing mutation-isolation assertion was traced
  to the test assuming Content-Type was the first raw field; Host actually preceded
  it. The assertion was corrected to locate Content-Type, and passed before any
  mutation-isolation implementation change.
- The public fixture command's tests failed while its API was absent
  (`fixture-red.log`), then passed (`fixture-green.log`). A separate RED test exposed
  a Content-Length/content mismatch in that test-only command
  (`fixture-framing-red.log`); adding public `ValidateFraming` made it pass
  (`fixture-framing-green.log`).

Core checks include independently generated native Go P-256 signatures, wrong
curve/private PEM/DER signature rejection, malformed PEM, raw64 scalar bounds,
header and URI syntax/size limits, timestamp skew/lifetime/expiry, strict wire
integer/pad-bit/order/coverage rules, first-failure codes and no nonce claims on
pre-verification failures. An equivalent `r || (n-s)` ECDSA signature cannot bypass
the tuple nonce claim.

Replay tests cover 100 concurrent direct claims, 32 concurrent verifications,
capacity exhaustion, expiry cleanup, cancellation, errors/panics and tuple scope
separation. Local storage is mutex-protected; no Redis service was installed or
contacted for this SDK and no distributed-store adapter is claimed.

Actual net/http tests cover preserved encoded paths/escape case/query order/empty
query, binary and chunked body replay, retained authenticated context and separate
verification metadata, authentication/key errors and contracts, unknown keys,
clock-after-auth, secure-default/forwarding rejection, missing or conflicting raw
evidence, duplicate/oversized/whitespace headers, framing ambiguity, body overflow,
read timeout/incomplete streams, callback copy isolation, and fixed redacted
errors/panics. Failed verification never invokes the downstream handler.

Policy/audit checks include all 42 portable cases, deny-by-default authentication,
Basic-only explicit signature opt-out, blocked step_up, bounded/unique risk hints,
precise precedence, allowlisted audit fields, opaque identifier validation and
redacted audit callback errors/panics.

## Limits and review boundaries

- Native middleware was exercised on local HTTP/1.1 with **explicit insecure local
  opt-in** and trusted raw capture. This is not TLS deployment, HTTP/2/3, Gin/Echo,
  proxy, cloud, physical-device, provider or production evidence.
- Standard `net/http.Header` cannot supply original evidence. A trusted ingress
  collector is required and is not provided as production code. The test collector
  handles one request per connection and is unsuitable for general keep-alive,
  pipelining, TLS or HTTP/2. Without a trusted source the middleware fails closed.
- Install before body parsing/URI/header rewrites. A stream consumed/replaced by
  another component cannot be reconstructed. Declared trailers reject.
  ResponseWriter wrappers must expose native read-deadline support or Unwrap.
- The explicit local replay store is volatile and process-local. No multi-process,
  distributed, Redis durability/eviction/restart or production replay guarantee was
  established. An ambiguous cancelled backend may have committed a nonce; the SDK
  rejects and never unclaims/retries with a fallback.
- Caller-owned core inputs/keys must not be mutated concurrently. Trusted callbacks
  must actually authenticate tokens and resolve pre-enrolled keys. Policy states
  must come from trusted server verdicts. Success proves neither authorization nor
  attestation; audit identifiers must not themselves encode secrets or users.
- The fixture consumer is test-only and reads public fixtures, including explicit
  synthetic subject/time inputs. Fresh native Android/Apple fixture runs are
  performed by the parent stage and are not asserted by this receipt.
- No publication, provider account change, authorization decision, enrollment,
  physical-device/hardware attestation or production deployment occurred.


Parent integration completed: fresh Android1+Apple8 public fixtures verified with replay/body/target/token mutations rejected; full extended runner passed. One fresh whole-stage review and exact remaining/deferred limits are recorded in [extended verification](../../docs/security/extended-server-verification.md).
