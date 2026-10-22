# Direct TLS Python ingress

`appguard.uvicorn.IngressConfig` is an **opt-in, HTTP/1.1, direct TLS** integration
for the existing `AppGuardMiddleware`. The optional `server` extra pins
**Uvicorn 0.54.0 and h11 0.16.0**. The core SDK and `appguard.asgi` do not import
either server package. Installation from this repository:

```sh
python -m pip install './sdk/python[server,redis]'
```

```python
from appguard.uvicorn import IngressConfig, IngressServer

# application is your configured AppGuardMiddleware, including application-owned
# authentication, enrolled-key lookup, replay storage and resource authorization.
config = IngressConfig(
    application,
    authority="api.example.com",
    ssl_certfile="/operator/tls/fullchain.pem",
    ssl_keyfile="/operator/tls/private-key.pem",
    host="127.0.0.1", port=8443,
    max_connections=128, max_inflight=64,
    handshake_timeout=5.0, tls_shutdown_timeout=1.0,
    header_timeout=5.0, total_timeout=20.0,
    timeout_keep_alive=3, timeout_graceful_shutdown=10,
)
IngressServer(config).run()
```

The authority is the configured HTTPS origin's host and optional nondefault port,
and must match the incoming Host field exactly. Configure the middleware origin
to that same origin. An external origin may use port 443 while a port-forwarded
listener uses 8443, provided the forwarding preserves the original TLS stream,
Host and request bytes. This adapter does not establish trust in a TLS-terminating
proxy or determine whether a network intermediary rewrote a request before it
arrived. Use direct TLS or a transparent TCP forwarder for this integration.

## Exact transport evidence

ASGI `raw_path` and `query_string` cannot distinguish `/v1/items` from
`/v1/items?`. `AppGuardH11Protocol` observes each actual `h11.Request.target` and
places that immutable byte string in `scope["appguard.raw_target"]`. The existing
middleware validates it against ASGI path/query fields before signature
verification. A per-connection FIFO transfers a separate frozen `RequestEvidence`
to each ASGI invocation, including keepalive and pipelined requests.

`scope["appguard.ingress"]` is a frozen `RequestEvidence` with:

- `target`: the exact origin-form target, including an explicit empty query.
- `method`: the request method bytes.
- `header_fields`: original field casing and field multiplicity before h11
  normalization. One optional separating SP after `:` is removed; remaining
  leading/trailing whitespace, tabs and folded fields are rejected.
- `header_block`: original request line and header bytes, including CRLFs.
- `accepted_at`: monotonic header-completion time used for the total budget.

All fields are excluded from `repr`. **Never log or serialize these fields**:
they include authentication and signature material. Neither ASGI headers nor
`h11.Request.headers.raw_items()` constitute the original wire header block.
The request body passed to the verifier and downstream application is the exact
entity body after HTTP chunk framing, before parsing or decompression. Chunk size
lines/extensions are framing, outside the signed body; request trailers are
unsupported and rejected.

The integration uses h11's existing `ReceiveBuffer.maybe_extract_lines`/
`_extract` and `Connection.next_event` hooks; it does not copy the HTTP parser.
The extraction observer validates the original bounded header block before h11
can collapse identical Content-Length duplicates, collapse comma-list lengths,
trim whitespace, unfold obs-fold or lowercase transfer-coding values. Duplicate
security/framing singleton fields, CL+TE, noncanonical lengths/transfer coding,
LF-only headers, non-origin targets, unsupported target encodings and trailers
fail closed. Non-singleton field duplicates remain separate in the evidence and
ASGI header sequence.

The module refuses a Uvicorn/h11 version mismatch. `IngressConfig` fixes the
protocol, ASGI3, one process, direct TLS, HTTP/1.1 ALPN, TLS 1.2 minimum, no root
path, no proxy-header rewriting, no WebSocket upgrade and no access/trace logging.
Forwarding/rewrite header fields are rejected. Changing these supported transport
settings fails before serving. A conventional `uvicorn app:application` command
does not activate this integration. Do not put a path-rewriting ASGI middleware
between this adapter and `AppGuardMiddleware` or supply a fabricated raw-target
resolver. Trusted host code can alter a scope; the adapter is not a sandbox for
malicious application code.

`IngressServer` revalidates owned finite limits before listener startup, even
after a loaded config was modified. Limits are also checked during load and
protocol construction. Raw TCP sockets are admitted before any TLS work begins;
an asyncio protocol owns each admitted connection through handshake, HTTP and
teardown. It upgrades the existing transport with public `loop.start_tls`, with
explicit handshake/shutdown deadlines, then delegates HTTP processing to the
unchanged Uvicorn h11 cycle. Uvicorn's listener-level `config.ssl` is intentionally
`None`: the admission protocol owns the configured TLS context, so
`create_server(ssl=...)` cannot bypass admission. No plaintext HTTP fallback
exists. Use the supplied `IngressServer` entry point for startup validation.
The owned TLS 1.2 floor and HTTP/1.1 ALPN list are reapplied to a loaded context
at startup and before every handshake; a lower minimum or changed ALPN list
cannot weaken that policy. Actual negotiated TLS version and ALPN are checked
again before HTTP handling. A stronger configured TLS 1.3 minimum is preserved.

## Runnable host and explicit dependencies

[The executable example](../../examples/python-ingress/server.py) uses an
operator-supplied enrolled P-256 public key, a high-entropy Bearer token's SHA-256
digest, one explicitly configured subject, and a configured Redis client. It
does no credential discovery or network access at import. It authenticates the
token before looking up the supplied key ID. After AppGuard verification, its
separate authorization rule permits only POST `/v1/items` for the authenticated
subject; other resources receive `RESOURCE_FORBIDDEN`.

Supply these environment variables through your secret manager or local shell:

| Variable | Meaning |
| --- | --- |
| `APPGUARD_ORIGIN` | Fixed HTTPS origin, for example `https://api.example.com` |
| `APPGUARD_APP_ID` | Expected enrolled app ID |
| `APPGUARD_HOST_SUBJECT` | Server-trusted authenticated subject |
| `APPGUARD_HOST_BEARER_SHA256` | Lowercase SHA-256 hex of a high-entropy host token |
| `APPGUARD_ENROLLED_KEY_ID` | Trusted enrolled key ID |
| `APPGUARD_ENROLLED_PUBLIC_KEY` | Path to its public PEM; never a request-supplied key |
| `APPGUARD_REDIS_URL` | Explicit Redis endpoint; use TLS/authentication as appropriate |
| `APPGUARD_TLS_CERT` / `APPGUARD_TLS_KEY` | Existing operator-controlled TLS certificate and private-key paths |
| `APPGUARD_LISTEN_HOST` / `APPGUARD_LISTEN_PORT` | Optional listener; defaults `127.0.0.1:8443` |

```sh
python examples/python-ingress/server.py
```

The example does not enroll keys, issue certificates, contact provider accounts
or accept a client identity merely because a signature verifies. Replace its
single-subject authentication/key table and fixed permission rule with your host
services. Configure revocation, shared Redis durability and client trust for your
deployment. Request signatures must use the fixed configured origin and the
exact transmitted target. Do not disable certificate verification in clients.

## Budgets and their limits

| Boundary | Configuration / behavior |
| --- | --- |
| Request header | 32 KiB complete/incomplete head ceiling, 64 fields, 16 KiB combined field names/values; target at most 8192 bytes |
| TLS handshake / teardown | Explicit 5 second / 1 second budgets in the example; an omitted handshake budget inherits `header_timeout` |
| Header wait | 5 seconds in the example, starting after TLS and each completed response; partial progress does not reset it |
| Body | Existing middleware's 1 MiB entity-body limit and 10 second total body budget in the example |
| Identity | Existing middleware's 2 second identity budget in the example |
| Replay backend | Configured Redis connect/command timeouts, 1 second each in the example |
| Total request | 20 seconds after header completion in the example, including body, identity, verification and response work |
| Inflight application work | At most 64 ASGI application tasks; excess requests receive 503 `INGRESS_OVERLOADED` and close |
| Connections | At most 128 admitted raw TCP connections, including pending TLS handshakes; excess peers are aborted before handshake work |
| Keepalive / backlog | 3 seconds / 128 queued accepts in the example |
| Shutdown | Uvicorn stops accepting, disables keepalive and waits up to 10 seconds before requesting task cancellation |

A total timeout fences late response sends and returns 504 `INGRESS_TIMEOUT`
before response start; after response start it closes the connection. Unfinished
ASGI application tasks retain admission slots until they finish, even when they
suppress cancellation. Client disconnect requests cancellation. Host failures are
reduced to fixed codes before Uvicorn's exception logger sees their details.
Any response sent while the request body is still incomplete closes the
connection, including a body-timeout response; a slow sender cannot keep the
abandoned upload alive by resetting Uvicorn's idle keepalive timer.

These limits bound cooperative event-loop waiting and admitted ASGI tasks, not
all process resources. They cannot preempt event-loop-blocking work, terminate
Python threads, force cancellation-resistant resolvers/receives to finish, or
undo external side effects. Middleware-internal abandoned resolver/receive tasks
and synchronous worker threads have their own lifetimes. Bound the host's
downstream I/O, connection pools and executor, and supervise the process with an
external termination deadline. The listener backlog, kernel accepts, file
descriptors and rejected transports still require network/OS resource limits;
application admission is not a global memory guarantee. At most one entity body
plus a 32 KiB head is buffered if decrypted data arrives before TLS promotion
finishes. Pending handshakes are explicitly aborted during server shutdown.
Lifespan is off in this constrained host; explicitly own and
close clients/resources outside the server, as the example does. No hard
shutdown guarantee is made for arbitrary Python application code.

## Verification evidence

Run the real-socket suite and the full SDK suite from `sdk/python`:

```sh
uv sync --locked --all-extras
uv run --frozen pytest tests/test_uvicorn_ingress.py -q
uv run --frozen pytest -q
```

The tests create an ephemeral local CA and a signed leaf certificate. Every
normal client validates that CA and the DNS hostname; separate negative cases
prove untrusted CA/wrong-host failures. They cover exact targets, binary/empty/
chunked bodies, fragmentation, keepalive/pipelining isolation, duplicate/framing/
whitespace ambiguity, target substitution, replay, failed authentication,
resource denial, upload limits/disconnects, deadlines, overload, late-response
fencing and redacted failures. These are local software/transport observations,
not a deployment, provider validation, external audit or physical-device proof.

Primary implementation references:
[Uvicorn 0.54.0 h11 protocol](https://github.com/Kludex/uvicorn/blob/0.54.0/uvicorn/protocols/http/h11_impl.py),
[h11 0.16.0 receive buffer](https://github.com/python-hyper/h11/blob/v0.16.0/h11/_receivebuffer.py),
[h11 header normalization](https://github.com/python-hyper/h11/blob/v0.16.0/h11/_headers.py),
[h11 API](https://h11.readthedocs.io/en/stable/api.html),
[asyncio TLS upgrades](https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.start_tls).
