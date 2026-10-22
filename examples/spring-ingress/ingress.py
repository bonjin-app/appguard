"""Constrained direct-TLS → loopback-mTLS Spring deployment example.

Spring owns authentication, signature verification, replay and authorization.
Only a complete bounded entity body may open a backend connection. This example
supports HTTP/1.1, one fixed backend, identity encoding and bounded responses;
it has no redirects, retries, pooling, arbitrary proxy destinations or logging.
"""

import asyncio
import math
import os
import re
import ssl
from pathlib import Path
from urllib.parse import urlsplit

import h11

from appguard.canonical import _validate_origin, _validate_target
from appguard.uvicorn import IngressConfig, IngressServer, RequestEvidence
from appguard.wire import validate_headers

_LIMIT = 1024 * 1024
_HEAD = 32768
_HOPS = frozenset(("upgrade", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "expect"))
_FORWARDING = frozenset(("forwarded", "x-original-url", "x-rewrite-url"))
_DNS = re.compile(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", re.ASCII)


class _Failure(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


def _finite_timeout(value, maximum):
    try:
        return type(value) in (int, float) and math.isfinite(value) and 0 < value <= maximum
    except OverflowError:
        return False


def _fields(pairs, *, request):
    text = tuple((name.decode("ascii"), value.decode("ascii")) for name, value in pairs)
    values = validate_headers(text)
    connections = [value.lower() for name, value in text if name.lower() == "connection"]
    if (len(connections) > 1 or (connections and connections[0] not in {"close", "keep-alive"})
            or _HOPS.intersection(values)
            or (request and (_FORWARDING.intersection(values)
                             or any(name.startswith("x-forwarded-") for name in values)))):
        raise ValueError("invalid fields")
    return values


def _request(scope):
    evidence = scope.get("appguard.ingress")
    if type(evidence) is not RequestEvidence:
        raise ValueError("missing transport evidence")
    path, _, query = evidence.target.partition(b"?")
    if (scope.get("type") != "http" or scope.get("scheme") != "https" or scope.get("root_path") != ""
            or scope.get("appguard.raw_target") != evidence.target
            or scope.get("raw_path") != path or scope.get("query_string") != query
            or scope.get("method", "").encode("ascii") != evidence.method
            or tuple(scope.get("headers", ())) != tuple((name.lower(), value) for name, value in evidence.header_fields)
            or type(evidence.accepted_at) not in (int, float) or not math.isfinite(evidence.accepted_at)
            or evidence.accepted_at > asyncio.get_running_loop().time()):
        raise ValueError("invalid transport evidence")
    _validate_target(evidence.target.decode("ascii"))
    values = _fields(evidence.header_fields, request=True)
    if "content-length" in values and int(values["content-length"]) > _LIMIT:
        raise _Failure(413, "INVALID_REQUEST")
    return evidence, values


async def _body(receive, evidence, values, timeout):
    # Header completion, not the most recent received byte, anchors this budget.
    deadline = evidence.accepted_at + timeout
    body = bytearray()
    try:
        async with asyncio.timeout_at(deadline):
            while True:
                if asyncio.get_running_loop().time() >= deadline:
                    raise TimeoutError
                event = await receive()
                if (type(event) is not dict or event.get("type") != "http.request"
                        or type(event.get("body", b"")) is not bytes
                        or type(event.get("more_body", False)) is not bool):
                    raise _Failure(400, "INVALID_REQUEST")
                part = event.get("body", b"")
                if len(part) > _LIMIT - len(body):
                    raise _Failure(413, "INVALID_REQUEST")
                body.extend(part)
                if not event.get("more_body", False):
                    break
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError
    except TimeoutError:
        raise _Failure(408, "UPLOAD_TIMEOUT") from None
    if "content-length" in values and int(values["content-length"]) != len(body):
        raise _Failure(400, "INVALID_REQUEST")
    return bytes(body)


def _response_fields(head):
    if len(head) > _HEAD or not head.startswith(b"HTTP/1.1 ") or not head.endswith(b"\r\n\r\n"):
        raise ValueError("invalid backend head")
    lines = head[:-4].split(b"\r\n")
    fields = []
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator:
            raise ValueError("invalid backend head")
        if value.startswith(b" "):
            value = value[1:]
        fields.append((name, value))
    values = _fields(tuple(fields), request=False)
    if "content-length" in values and int(values["content-length"]) > _LIMIT:
        raise ValueError("oversized backend response")
    return fields, values


async def _close(writer, deadline):
    writer.close()
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        writer.transport.abort()
        return
    try:
        await asyncio.wait_for(writer.wait_closed(), min(0.25, remaining))
    except (Exception, asyncio.CancelledError):
        writer.transport.abort()
        # Connection cleanup must not suppress cancellation of the application.
        if asyncio.current_task().cancelling():
            raise asyncio.CancelledError from None


async def _backend(evidence, body, *, port, hostname, context, timeout):
    writer = None
    deadline = asyncio.get_running_loop().time() + timeout
    try:
        async with asyncio.timeout_at(deadline):
            connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=_HEAD)
            outgoing = [(name, value) for name, value in evidence.header_fields
                        if name.lower() not in {b"connection", b"content-length", b"transfer-encoding"}]
            outgoing.extend([(b"Content-Length", str(len(body)).encode()), (b"Connection", b"close")])
            head = connection.send(h11.Request(method=evidence.method, target=evidence.target, headers=outgoing))
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", port, ssl=context, server_hostname=hostname, limit=_HEAD,
                ssl_handshake_timeout=timeout, ssl_shutdown_timeout=min(1.0, timeout))
            secured = writer.get_extra_info("ssl_object")
            if (secured is None or secured.version() not in {"TLSv1.2", "TLSv1.3"}
                    or secured.selected_alpn_protocol() not in {None, "http/1.1"}):
                raise ValueError("unsupported backend TLS")
            writer.write(head)
            await writer.drain()
            for index in range(0, len(body), 8192):
                writer.write(connection.send(h11.Data(data=body[index:index + 8192])))
                await writer.drain()
            writer.write(connection.send(h11.EndOfMessage()))
            await writer.drain()
            head = await reader.readuntil(b"\r\n\r\n")
            fields, values = _response_fields(head)
            connection.receive_data(head)
            started = None
            captured = bytearray()
            while True:
                if asyncio.get_running_loop().time() >= deadline:
                    raise TimeoutError
                event = connection.next_event()
                if event is h11.NEED_DATA:
                    data = await reader.read(8192)
                    connection.receive_data(data)
                elif isinstance(event, h11.Response):
                    if started is not None or not 200 <= event.status_code <= 599:
                        raise ValueError("invalid backend response")
                    started = event.status_code
                elif isinstance(event, h11.Data):
                    if len(event.data) > _LIMIT - len(captured):
                        raise ValueError("oversized backend response")
                    captured.extend(event.data)
                elif isinstance(event, h11.EndOfMessage):
                    if started is None or event.headers:
                        raise ValueError("invalid backend response")
                    # h11 owns framing validation. Forward only the entity bytes,
                    # never hop metadata, chunk delimiters or backend trailers.
                    forwarded = [(name, value) for name, value in fields
                                 if name.lower() not in {b"connection", b"content-length", b"transfer-encoding"}]
                    if started != 204:
                        if evidence.method == b"HEAD" or started == 304:
                            if "content-length" in values:
                                forwarded.append((b"content-length", values["content-length"].encode()))
                        else:
                            forwarded.append((b"content-length", str(len(captured)).encode()))
                    return started, forwarded, bytes(captured)
                else:
                    # No informational responses, upgrades or a close-delimited
                    # incomplete message may masquerade as a completed response.
                    raise ValueError("invalid backend response")
    except TimeoutError:
        raise _Failure(504, "BACKEND_TIMEOUT") from None
    finally:
        if writer is not None:
            await _close(writer, deadline)


async def _respond(send, status, code):
    body = ('{"code":"' + code + '"}').encode("ascii")
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
        (b"cache-control", b"no-store"), (b"connection", b"close")]})
    await send({"type": "http.response.body", "body": body})


def build_application(*, backend_port, backend_hostname, backend_ca, client_cert, client_key,
                      body_timeout=10.0, backend_timeout=5.0):
    """Configure one fixed loopback mTLS backend; performs no network requests.

    Upload/response bodies are limited to 1 MiB. Upload timeout must be ≤60 s,
    backend total timeout ≤30 s. Trust and identity PEMs are operator-owned;
    do not let untrusted requests or tenants select them.
    """
    if (type(backend_port) is not int or not 1 <= backend_port <= 65535
            or type(backend_hostname) is not str or not _DNS.fullmatch(backend_hostname)
            or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                   for label in backend_hostname.split("."))
            or not _finite_timeout(body_timeout, 60) or not _finite_timeout(backend_timeout, 30)
            or any(not isinstance(path, (str, Path)) or not str(path) for path in (backend_ca, client_cert, client_key))
            or h11.__version__ != "0.16.0"):
        raise ValueError("invalid Spring ingress configuration")
    failed = False
    try:
        context = ssl.create_default_context(cafile=str(backend_ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["http/1.1"])
        context.load_cert_chain(str(client_cert), str(client_key))
    except Exception:
        failed = True
    if failed:
        raise ValueError("invalid Spring ingress configuration")

    async def application(scope, receive, send):
        failure = None
        try:
            evidence, values = _request(scope)
            body = await _body(receive, evidence, values, body_timeout)
        except _Failure as error:
            failure = error.status, error.code
        except Exception:
            failure = 400, "INVALID_REQUEST"
        if failure is not None:
            await _respond(send, *failure)
            return
        try:
            status, headers, body = await _backend(
                evidence, body, port=backend_port, hostname=backend_hostname, context=context,
                timeout=backend_timeout)
        except _Failure as error:
            failure = error.status, error.code
        except Exception:
            failure = 502, "BACKEND_UNAVAILABLE"
        if failure is not None:
            await _respond(send, *failure)
            return
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    return application


def main():
    """Explicit startup only; never discover credentials or contact accounts."""
    failed = False
    try:
        origin = os.environ["APPGUARD_ORIGIN"]
        _validate_origin(origin)
        app = build_application(
            backend_port=int(os.environ["APPGUARD_BACKEND_PORT"]),
            backend_hostname=os.environ["APPGUARD_BACKEND_HOSTNAME"],
            backend_ca=os.environ["APPGUARD_BACKEND_CA"],
            client_cert=os.environ["APPGUARD_BACKEND_CLIENT_CERT"],
            client_key=os.environ["APPGUARD_BACKEND_CLIENT_KEY"],
            body_timeout=float(os.environ.get("APPGUARD_BODY_TIMEOUT", "10")),
            backend_timeout=float(os.environ.get("APPGUARD_BACKEND_TIMEOUT", "5")))
        config = IngressConfig(
            app, authority=urlsplit(origin).netloc,
            ssl_certfile=os.environ["APPGUARD_TLS_CERT"], ssl_keyfile=os.environ["APPGUARD_TLS_KEY"],
            host=os.environ.get("APPGUARD_LISTEN_HOST", "127.0.0.1"),
            port=int(os.environ.get("APPGUARD_LISTEN_PORT", "8443")),
            max_connections=int(os.environ.get("APPGUARD_MAX_CONNECTIONS", "128")),
            max_inflight=int(os.environ.get("APPGUARD_MAX_INFLIGHT", "64")),
            header_timeout=5, handshake_timeout=5, tls_shutdown_timeout=1,
            total_timeout=float(os.environ.get("APPGUARD_TOTAL_TIMEOUT", "20")),
            timeout_keep_alive=3, timeout_graceful_shutdown=10)
        IngressServer(config).run()
    except Exception:
        failed = True
    if failed:
        raise SystemExit("SPRING_INGRESS_HOST_FAILED")


if __name__ == "__main__":
    main()
