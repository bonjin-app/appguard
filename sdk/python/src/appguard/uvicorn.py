"""Opt-in direct TLS HTTP/1.1 ingress. Install ``appguard-server[server]``.

The two private buffer hooks are deliberately version-pinned. They observe h11's
existing header extraction; they do not implement an alternate HTTP parser.
"""

import asyncio
import math
import ssl
from collections import deque
from dataclasses import dataclass, field

import h11
import uvicorn
from h11._receivebuffer import ReceiveBuffer
from uvicorn.protocols.http.h11_impl import H11Protocol

from .canonical import _validate_origin, _validate_target
from .types import VerificationError
from .wire import validate_headers

_VERSIONS = ("0.54.0", "0.16.0")
_MAX_HEAD = 32768
_FORWARDED = frozenset(("forwarded", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host",
                        "x-forwarded-port", "x-original-url", "x-rewrite-url", "upgrade"))


def _versions():
    if (uvicorn.__version__, h11.__version__) != _VERSIONS:
        raise ValueError("AppGuard ingress requires uvicorn==0.54.0 and h11==0.16.0")


def _positive(value):
    try:
        return type(value) in (int, float) and math.isfinite(value) and value > 0
    except OverflowError:
        return False


@dataclass(frozen=True)
class RequestEvidence:
    """Per-request immutable evidence. Never log this object's individual fields.

    ``header_fields`` preserves original casing and duplicates before h11's
    normalization, with one optional separating SP after ':' removed.
    ``header_block`` contains the original request line, headers and CRLFs.
    Neither h11 event.headers nor ASGI scope.headers are original wire bytes.
    """

    target: bytes = field(repr=False)
    header_fields: tuple[tuple[bytes, bytes], ...] = field(repr=False)
    header_block: bytes = field(repr=False)
    method: bytes = field(repr=False)
    accepted_at: float = field(repr=False)


class _HeadBuffer(ReceiveBuffer):
    def __init__(self, connection):
        super().__init__()
        self.connection = connection
        self._extracting_head = False

    def maybe_extract_lines(self):
        self._extracting_head = True
        try:
            return super().maybe_extract_lines()
        finally:
            self._extracting_head = False

    def _extract(self, count):
        # h11's _extract is also used for body bytes and chunk delimiters.
        # Only observe the existing maybe_extract_lines operation.
        if self._extracting_head and count > _MAX_HEAD:
            raise h11.LocalProtocolError("invalid request")
        value = super()._extract(count)
        if self._extracting_head:
            if self.connection.their_state is h11.IDLE:
                self.connection.capture_head(bytes(value))
            elif value != b"\r\n":
                # ASGI does not expose request trailers. Never silently discard
                # security metadata supplied there, or normalize LF delimiters.
                raise h11.LocalProtocolError("request trailers unsupported")
        return value


class _Connection(h11.Connection):
    def __init__(self, protocol):
        super().__init__(h11.SERVER, max_incomplete_event_size=_MAX_HEAD)
        self.protocol = protocol
        self._receive_buffer = _HeadBuffer(self)
        self._head = None

    def capture_head(self, raw):
        try:
            if self._head is not None or not raw.endswith(b"\r\n\r\n"):
                raise ValueError
            lines = raw[:-4].split(b"\r\n")
            method, target, version = lines[0].split(b" ")
            if version != b"HTTP/1.1" or not 1 <= len(method) <= 32 or method != method.upper():
                raise ValueError
            _validate_target(target.decode("ascii"))
            fields = []
            for line in lines[1:]:
                name, separator, value = line.partition(b":")
                if not separator:
                    raise ValueError
                if value.startswith(b" "):
                    value = value[1:]
                fields.append((name, value))
            text_fields = tuple((name.decode("ascii"), value.decode("ascii")) for name, value in fields)
            values = validate_headers(text_fields)
            if (values.get("host") != self.protocol.config.authority or _FORWARDED.intersection(values)
                    or any(name.startswith("x-forwarded-") for name in values)):
                raise ValueError
            self._head = (method, target, tuple(fields), raw)
        except (ValueError, UnicodeError, VerificationError):
            raise h11.LocalProtocolError("invalid request") from None

    def next_event(self):
        event = super().next_event()
        if isinstance(event, h11.Request):
            captured, self._head = self._head, None
            if captured is None:
                raise h11.RemoteProtocolError("missing transport evidence")
            method, target, fields, raw = captured
            if (event.method != method or event.target != target
                    or tuple(event.headers) != tuple((name.lower(), value) for name, value in fields)):
                raise h11.RemoteProtocolError("transport evidence mismatch")
            evidence = RequestEvidence(event.target, fields, raw, event.method, self.protocol.loop.time())
            self.protocol.capture_request(evidence)
        return event


class IngressConfig(uvicorn.Config):
    """Bounded single-process direct TLS configuration for AppGuardMiddleware.

    Authentication, key lookup, resource authorization, replay storage and
    body/identity deadlines remain the host's explicit middleware dependencies.
    Admission counts unfinished application tasks even after a request times out.
    The host must supervise/restart a process containing uncooperative work.
    """

    def __init__(self, app, *, authority, ssl_certfile, ssl_keyfile, host="127.0.0.1", port=8443,
                 max_connections=128, max_inflight=64, header_timeout=5.0, total_timeout=45.0,
                 timeout_keep_alive=5, timeout_graceful_shutdown=10, backlog=128,
                 handshake_timeout=None, tls_shutdown_timeout=1.0):
        _versions()
        try:
            _validate_origin("https://" + authority)
        except (TypeError, VerificationError):
            raise ValueError("invalid ingress authority") from None
        if (not callable(app) or not ssl_certfile or not ssl_keyfile
                or any(type(v) is not int or v < 1 for v in (max_connections, max_inflight, backlog))
                or any(not _positive(v) for v in (header_timeout, total_timeout, timeout_keep_alive,
                                                   timeout_graceful_shutdown, tls_shutdown_timeout))
                or (handshake_timeout is not None and not _positive(handshake_timeout))):
            raise ValueError("invalid ingress configuration")
        self.authority = authority
        self.max_connections, self.max_inflight = max_connections, max_inflight
        self.header_timeout, self.total_timeout = header_timeout, total_timeout
        self.handshake_timeout = header_timeout if handshake_timeout is None else handshake_timeout
        self.tls_shutdown_timeout = tls_shutdown_timeout
        self._active = set()
        super().__init__(app, host=host, port=port, http=AppGuardH11Protocol, ws="none", http2=False,
                         interface="asgi3", loop="asyncio", lifespan="off", workers=1,
                         proxy_headers=False, root_path="", access_log=False, log_config=None,
                         log_level="warning", server_header=False, backlog=backlog,
                         limit_concurrency=None, h11_max_incomplete_event_size=_MAX_HEAD,
                         timeout_keep_alive=timeout_keep_alive,
                         timeout_graceful_shutdown=timeout_graceful_shutdown,
                         ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile)

    def load(self):
        self._validate(require_tls=False)
        super().load()
        self.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ssl.set_alpn_protocols(["http/1.1"])
        self._tls_context, self.ssl = self.ssl, None
        # Accept raw TCP first. Delegating TLS to create_server(ssl=...) would
        # bypass protocol admission until after its handshake had completed.
        self.http_protocol_class = _TLSAdmission
        self._validate()

    def _validate(self, *, require_tls=True):
        _versions()
        if (not callable(self.app)
                or any(type(v) is not int or v < 1 for v in (self.max_connections, self.max_inflight, self.backlog))
                or any(not _positive(v) for v in (self.header_timeout, self.total_timeout,
                                                   self.timeout_keep_alive, self.timeout_graceful_shutdown,
                                                   self.handshake_timeout, self.tls_shutdown_timeout))):
            raise ValueError("invalid ingress configuration")
        if (self.root_path != "" or self.proxy_headers or self.http2 or self.ws != "none"
                or self.interface != "asgi3" or self.loop != "asyncio" or self.limit_concurrency is not None
                or self.access_log or self.log_level != "warning" or self.lifespan != "off"
                or self.http is not AppGuardH11Protocol or self.workers != 1
                or not self.ssl_certfile or not self.ssl_keyfile
                or (require_tls and (self.ssl is not None or self.http_protocol_class is not _TLSAdmission
                                     or not isinstance(self._tls_context, ssl.SSLContext)))):
            raise ValueError("unsupported ingress transport configuration")
        if require_tls:
            # SSLContext remains mutable after Config.load. Reapply the owned
            # floor and ALPN policy at startup and immediately before upgrade.
            if self._tls_context.minimum_version < ssl.TLSVersion.TLSv1_2:
                self._tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._tls_context.set_alpn_protocols(["http/1.1"])


class IngressServer(uvicorn.Server):
    """Uvicorn lifecycle with validation before every listener startup."""

    async def startup(self, sockets=None):
        if not isinstance(self.config, IngressConfig):
            raise ValueError("IngressServer requires IngressConfig")
        if not self.config.loaded:
            self.config.load()
        self.config._validate()
        await super().startup(sockets=sockets)


class _TLSAdmission(asyncio.Protocol):
    """Own an admitted raw socket through TLS, HTTP and connection teardown."""

    def __init__(self, config, server_state, app_state, _loop=None):
        config._validate()
        self.config, self.server_state, self.app_state = config, server_state, app_state
        self.loop = _loop or asyncio.get_running_loop()
        self.transport = self.inner = self._handshake = self._timer = None
        self._early = bytearray()
        self._lost = False

    def _release(self):
        self.server_state.connections.discard(self)
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _abort(self):
        self._lost = True
        self._release()
        self._early.clear()
        if self.transport is not None:
            self.transport.abort()
        if (self._handshake is not None and not self._handshake.done()
                and self._handshake is not asyncio.current_task()):
            self._handshake.cancel()

    def connection_made(self, transport):
        self.transport = transport
        if transport.get_extra_info("ssl_object") is not None:
            self._abort()  # Native create_server TLS would bypass raw admission.
            return
        if len(self.server_state.connections) >= self.config.max_connections:
            self._abort()
            return
        self.server_state.connections.add(self)
        transport.pause_reading()
        self._timer = self.loop.call_later(self.config.handshake_timeout, self._abort)
        self._handshake = self.loop.create_task(self._upgrade())

    async def _upgrade(self):
        established = False
        try:
            self.config._validate()
            upgraded = await self.loop.start_tls(
                self.transport, self, self.config._tls_context, server_side=True,
                ssl_handshake_timeout=self.config.handshake_timeout,
                ssl_shutdown_timeout=self.config.tls_shutdown_timeout,
            )
            if upgraded is None or self._lost:
                return
            self.transport = upgraded
            secured = upgraded.get_extra_info("ssl_object")
            if (secured is None or secured.version() not in {"TLSv1.2", "TLSv1.3"}
                    or secured.selected_alpn_protocol() not in {None, "http/1.1"}):
                return  # Recheck actual negotiation before constructing HTTP.
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            self.inner = AppGuardH11Protocol(self.config, self.server_state, self.app_state,
                                           self.loop, _admission=self)
            self.inner.connection_made(upgraded)
            established = True
            if self._early:
                data = bytes(self._early)
                self._early.clear()
                self.inner.data_received(data)
        except (Exception, asyncio.CancelledError):
            pass  # TLS/configuration failures never expose request/config data.
        finally:
            if not established:
                self._abort()

    def data_received(self, data):
        if self._lost:
            return
        if self.inner is not None:
            self.inner.data_received(data)
        elif len(data) + len(self._early) <= 1048576 + _MAX_HEAD:
            # TLS may deliver application bytes before start_tls' waiter resumes.
            self._early.extend(data)
        else:
            self._abort()

    def connection_lost(self, exc):
        self._lost = True
        self._release()
        self._early.clear()
        if self._handshake is not None and not self._handshake.done():
            self._handshake.cancel()
        if self.inner is not None:
            self.inner.connection_lost(exc)

    def eof_received(self):
        if self.inner is not None:
            return self.inner.eof_received()

    def pause_writing(self):
        if self.inner is not None:
            self.inner.pause_writing()

    def resume_writing(self):
        if self.inner is not None:
            self.inner.resume_writing()

    def shutdown(self):
        if self.inner is None:
            self._abort()
        else:
            self.inner.shutdown()


class AppGuardH11Protocol(H11Protocol):
    """Only supported through IngressConfig; no proxy or root-path rewriting."""

    def __init__(self, config, server_state, app_state, _loop=None, *, _admission=None):
        if not isinstance(config, IngressConfig):
            raise ValueError("AppGuardH11Protocol requires IngressConfig")
        if not config.loaded:
            config.load()
        config._validate()
        super().__init__(config, server_state, app_state, _loop)
        self.conn = _Connection(self)
        self._application, self.app = self.app, self._dispatch
        self._pending = deque()
        self._running = set()
        self._header_timer = None
        self._rejected = False
        self._admission = _admission
        # Uvicorn's global access logger can have handlers from another server.
        self.access_log = False

    def _cancel_header_timer(self):
        if self._header_timer is not None:
            self._header_timer.cancel()
            self._header_timer = None

    def _arm_header_timer(self):
        self._cancel_header_timer()
        self._header_timer = self.loop.call_later(self.config.header_timeout, self.transport.close)

    def connection_made(self, transport):
        super().connection_made(transport)
        self.connections.discard(self)  # Raw admission owns this connection.
        if (transport.get_extra_info("ssl_object") is None or self._admission not in self.connections
                or self._admission.inner is not self):
            self._rejected = True
            # No request has been admitted. Abort instead of retaining a TLS
            # shutdown handshake for each rejected idle peer.
            transport.abort()
        else:
            self._arm_header_timer()

    def data_received(self, data):
        if not self._rejected:
            super().data_received(data)

    def connection_lost(self, exc):
        self._cancel_header_timer()
        self._pending.clear()
        for task in tuple(self._running):
            task.cancel()
        super().connection_lost(exc)

    def capture_request(self, evidence):
        self._cancel_header_timer()
        if self._pending:
            raise h11.RemoteProtocolError("transport evidence queue overflow")
        self._pending.append(evidence)

    def on_response_complete(self):
        super().on_response_complete()
        if not self.transport.is_closing() and self.conn.their_state is h11.IDLE:
            self._arm_header_timer()

    async def _failure(self, send, status, code):
        body = ('{"code":"' + code + '"}').encode("ascii")
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"cache-control", b"no-store"), (b"connection", b"close"),
        ]})
        await send({"type": "http.response.body", "body": body})

    async def _dispatch(self, scope, receive, send):
        evidence = self._pending.popleft() if self._pending else None
        if evidence is None:
            await self._failure(send, 400, "INVALID_REQUEST")
            return
        path, _, query = evidence.target.partition(b"?")
        fields = tuple((name.lower(), value) for name, value in evidence.header_fields)
        if (scope.get("scheme") != "https" or scope.get("root_path") != ""
                or scope.get("method", "").encode("ascii") != evidence.method
                or scope.get("raw_path") != path or scope.get("query_string") != query
                or tuple(scope.get("headers", ())) != fields):
            await self._failure(send, 400, "INVALID_REQUEST")
            return
        if len(self.config._active) >= self.config.max_inflight:
            await self._failure(send, 503, "INGRESS_OVERLOADED")
            return
        deadline = evidence.accepted_at + self.config.total_timeout
        if self.loop.time() >= deadline:
            await self._failure(send, 504, "INGRESS_TIMEOUT")
            return
        captured_scope = {**scope, "appguard.raw_target": evidence.target, "appguard.ingress": evidence}
        enabled, started = True, False

        async def guarded_send(message):
            nonlocal started
            if not enabled or self.transport.is_closing():
                raise ConnectionError("ingress response closed")
            if self.loop.time() >= deadline:
                raise TimeoutError("ingress deadline expired")
            if message.get("type") == "http.response.start":
                started = True
                if self.conn.their_state not in (h11.DONE, h11.MUST_CLOSE):
                    # A body deadline/early refusal must not leave an incomplete
                    # request drainable forever through keepalive data arrivals.
                    headers = [(name, value) for name, value in message.get("headers", ())
                               if name.lower() != b"connection"]
                    message = {**message, "headers": [*headers, (b"connection", b"close")]}
            await send(message)

        async def invoke():
            # Call inside the task: a broken callable can fail before returning
            # an awaitable. Its exception must cross the same redaction boundary.
            await self._application(captured_scope, receive, guarded_send)

        task = self.loop.create_task(invoke())
        self.config._active.add(task)
        self._running.add(task)

        def finished(completed):
            self.config._active.discard(completed)
            self._running.discard(completed)
            if not completed.cancelled():
                completed.exception()  # Consume late failures, never log exception data.

        task.add_done_callback(finished)
        try:
            remaining = deadline - self.loop.time()
            done, _ = await asyncio.wait({task}, timeout=max(0, remaining))
            if not done or self.loop.time() >= deadline:
                enabled = False
                task.cancel()
                if not started and not self.transport.is_closing():
                    await self._failure(send, 504, "INGRESS_TIMEOUT")
                else:
                    self.transport.close()
                return
            failed = False
            try:
                task.result()
            except asyncio.CancelledError:
                self.transport.close()
            except Exception:
                failed = True
            # Emit a host failure only after leaving the exception handler.
            # A failed response transport must not acquire the private host
            # exception as its __context__ and expose it to server error logs.
            if failed:
                if not started and not self.transport.is_closing():
                    await self._failure(send, 503, "APPLICATION_UNAVAILABLE")
                else:
                    self.transport.close()
        except asyncio.CancelledError:
            task.cancel()
            self.transport.close()
        finally:
            enabled = False
