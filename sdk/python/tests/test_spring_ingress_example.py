"""Constrained gateway evidence: actual verifying TLS frontend/backend sockets."""

import asyncio
import importlib.util
import ssl
import subprocess
import sys
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from test_uvicorn_ingress import connect, exchange, live, response, signer, tls, wire

ROOT = Path(__file__).resolve().parents[3]


def module():
    path = ROOT / "examples/spring-ingress/ingress.py"
    assert path.is_file(), "The constrained Spring ingress example is not implemented"
    spec = importlib.util.spec_from_file_location("spring_ingress_example", path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


@pytest.fixture
def mtls(tmp_path):
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic backend CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .sign(ca_key, hashes.SHA256()))
    ca_path = tmp_path / "backend-ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def leaf(name, usage):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
            .add_extension(x509.ExtendedKeyUsage([usage]), False).sign(ca_key, hashes.SHA256()))
        cert_path, key_path = tmp_path / (name + ".pem"), tmp_path / (name + ".key")
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        key_path.chmod(0o600)
        return cert_path, key_path

    server_cert, server_key = leaf("backend.example.test", ExtendedKeyUsageOID.SERVER_AUTH)
    client_cert, client_key = leaf("ingress.example.test", ExtendedKeyUsageOID.CLIENT_AUTH)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(server_cert, server_key)
    context.load_verify_locations(cafile=str(ca_path))
    context.verify_mode = ssl.CERT_REQUIRED
    context.set_alpn_protocols(["http/1.1"])
    return {"context": context, "backend_ca": ca_path, "client_cert": client_cert,
            "client_key": client_key, "backend_hostname": "backend.example.test"}


class BackendObservations(list):
    def __init__(self):
        super().__init__()
        self.connections = []


@asynccontextmanager
async def backend(mtls, *, reply=None, stall=False, drip=False):
    seen, closed, tasks = BackendObservations(), [], set()

    async def handle(reader, writer):
        current = asyncio.current_task()
        tasks.add(current)
        seen.connections.append(True)
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            fields = [line.split(b":", 1) for line in head.split(b"\r\n")[1:] if line]
            length = int(next(value.strip() for name, value in fields if name.lower() == b"content-length"))
            body = await reader.readexactly(length)
            seen.append((head, body))
            if stall:
                if reply is not None:
                    writer.write(reply); await writer.drain()
                await reader.read()
            elif drip:
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n")
                for index in range(8):
                    if index: await asyncio.sleep(0.04)
                    writer.write(b"x"); await writer.drain()
            else:
                writer.write(reply if reply is not None else (
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                    + b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body))
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.CancelledError):
            pass
        finally:
            closed.append(True)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 0.5)
            except (ConnectionError, TimeoutError, ssl.SSLError):
                writer.transport.abort()
            tasks.discard(current)

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=mtls["context"],
                                        ssl_handshake_timeout=0.5, ssl_shutdown_timeout=0.2)
    args = {name: value for name, value in mtls.items() if name != "context"}
    args["backend_port"] = server.sockets[0].getsockname()[1]
    try:
        yield args, seen, closed
    finally:
        server.close()
        await server.wait_closed()
        for task in tuple(tasks):
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def test_exact_target_signed_fields_binary_body_and_response_survive_mtls(signer, tls, mtls):
    async def run():
        _, sign = signer
        body = b"\x00\xff\x80\r\n" + "한국어".encode()
        target = "/echo?x=2&x=1&raw=%2f&raw=%2F"
        headers = sign(target, body) + [("X-Extra", "first"), ("X-Extra", "second")]
        async with backend(mtls) as (args, seen, _):
            app = module().build_application(**args)
            async with live(app, tls) as (port, _):
                assert await exchange(port, tls, wire(target, headers, body)) == (200, body)
        assert len(seen) == 1
        head, captured = seen[0]
        assert head.startswith(b"POST /echo?x=2&x=1&raw=%2f&raw=%2F HTTP/1.1\r\n")
        for name, value in headers:
            assert name.encode() + b": " + value.encode() + b"\r\n" in head
        assert head.count(b"Content-Length:") == 1
        assert b"Transfer-Encoding:" not in head
        assert captured == body
    asyncio.run(run())


@pytest.mark.parametrize("chunked,target", [(False, "/echo?"), (True, "/echo?")])
def test_empty_query_and_chunked_entity_body_are_not_rewritten(signer, tls, mtls, chunked, target):
    async def run():
        _, sign = signer
        async with backend(mtls) as (args, seen, _):
            async with live(module().build_application(**args), tls) as (port, _):
                assert await exchange(port, tls, wire(target, sign(target), chunked=chunked)) == (200, b"{}")
        assert seen[0][0].startswith(b"POST /echo? HTTP/1.1\r\n")
        assert b"Content-Length: 2\r\n" in seen[0][0]
        assert b"Transfer-Encoding:" not in seen[0][0]
    asyncio.run(run())


@pytest.mark.parametrize("drip", [False, True])
def test_absolute_upload_budget_never_connects_backend_for_stall_or_drip(signer, tls, mtls, drip):
    async def run():
        _, sign = signer
        body = b"12345678"
        async with backend(mtls) as (args, seen, _):
            async with live(module().build_application(**args, body_timeout=0.15), tls,
                            total_timeout=2) as (port, server):
                reader, writer = await connect(port, tls)
                try:
                    head = wire("/echo", sign("/echo", body), body).split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
                    started = time.monotonic()
                    writer.write(head + body[:1]); await writer.drain()
                    if drip:
                        for index in (1, 2):
                            await asyncio.sleep(0.04)
                            writer.write(body[index:index + 1]); await writer.drain()
                    assert await response(reader) == (408, b'{"code":"UPLOAD_TIMEOUT"}')
                    assert 0.10 <= time.monotonic() - started < 1.5
                    assert await asyncio.wait_for(reader.read(), 1) == b""
                finally:
                    writer.close(); await writer.wait_closed()
                assert not seen and not seen.connections
                await asyncio.sleep(0)
                assert not server.config._active
                assert await exchange(port, tls, wire("/echo", sign("/echo"))) == (200, b"{}")
    asyncio.run(run())


@pytest.mark.parametrize("extra", [[("Connection", "authorization")], [("Connection", "close, signature")],
    [("Connection", "close"), ("Connection", "keep-alive")], [("Expect", "100-continue")],
    [("TE", "trailers")], [("Trailer", "X-Late")], [("Proxy-Authorization", "PRIVATE")]])
def test_hop_ambiguity_is_rejected_before_backend_connection(signer, tls, mtls, extra):
    async def run():
        _, sign = signer
        async with backend(mtls) as (args, seen, _):
            async with live(module().build_application(**args), tls) as (port, _):
                raw = wire("/echo", sign("/echo"))
                raw = raw.replace(b"Connection: close\r\n", b"")
                raw = raw.replace(b"\r\n\r\n", b"\r\n" + b"".join(
                    name.encode() + b": " + value.encode() + b"\r\n" for name, value in extra) + b"\r\n", 1)
                assert await exchange(port, tls, raw) == (400, b'{"code":"INVALID_REQUEST"}')
                assert not seen and not seen.connections
    asyncio.run(run())


def test_backend_stall_expires_absolute_budget_and_closes_socket(signer, tls, mtls):
    async def run():
        _, sign = signer
        async with backend(mtls, stall=True) as (args, seen, closed):
            async with live(module().build_application(**args, backend_timeout=0.15), tls) as (port, _):
                started = time.monotonic()
                assert await exchange(port, tls, wire("/echo", sign("/echo"))) == (
                    504, b'{"code":"BACKEND_TIMEOUT"}')
                assert time.monotonic() - started < 1.5
                for _ in range(10):
                    if closed: break
                    await asyncio.sleep(0.01)
                assert len(seen) == 1 and closed
    asyncio.run(run())


@pytest.mark.parametrize("reply", [
    b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}",
    b"HTTP/1.1 200 OK\r\nConnection: content-type\r\nContent-Length: 2\r\n\r\n{}",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nX-Late: PRIVATE\r\n\r\n",
    b"HTTP/1.1 200 OK\nContent-Length: 2\n\n{}",
    b"HTTP/1.1 200 OK\r\nX-Secret: " + b"a" * 32768 + b"\r\n\r\n",
])
def test_malformed_or_oversized_backend_response_is_fixed_failure(signer, tls, mtls, reply, caplog):
    async def run():
        _, sign = signer
        async with backend(mtls, reply=reply) as (args, seen, _):
            async with live(module().build_application(**args), tls) as (port, _):
                assert await exchange(port, tls, wire("/echo", sign("/echo"))) == (
                    502, b'{"code":"BACKEND_UNAVAILABLE"}')
                assert len(seen) == 1
        assert "PRIVATE" not in caplog.text and "TEST_ONLY_TOKEN" not in caplog.text
    asyncio.run(run())


@pytest.mark.parametrize("change", [{"backend_port": True}, {"backend_port": 0}, {"backend_port": 65536},
    {"backend_hostname": "user@host"}, {"backend_hostname": "host:443"}, {"backend_hostname": ""},
    {"body_timeout": True}, {"body_timeout": 0}, {"body_timeout": float("inf")},
    {"backend_timeout": float("nan")}, {"backend_timeout": -1}])
def test_invalid_host_configuration_fails_before_network(mtls, change):
    args = {name: value for name, value in mtls.items() if name != "context"}
    args["backend_port"] = 8443
    with pytest.raises(ValueError, match="invalid Spring ingress configuration"):
        module().build_application(**{**args, **change})


def test_chunked_response_is_deframed_with_duplicate_headers_preserved(signer, tls, mtls):
    async def run():
        _, sign = signer
        reply = (b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n"
                 b"Set-Cookie: first=a\r\nSet-Cookie: second=b\r\n\r\n2\r\n\x00\xff\r\n1\r\nx\r\n0\r\n\r\n")
        async with backend(mtls, reply=reply) as (args, _, _):
            async with live(module().build_application(**args), tls) as (port, _):
                reader, writer = await connect(port, tls)
                try:
                    writer.write(wire("/echo", sign("/echo"))); await writer.drain()
                    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
                    assert head.startswith(b"HTTP/1.1 201 ")
                    assert head.lower().count(b"set-cookie:") == 2
                    assert b"content-length: 3\r\n" in head.lower()
                    assert b"transfer-encoding:" not in head.lower()
                    assert await reader.readexactly(3) == b"\x00\xffx"
                finally:
                    writer.close(); await writer.wait_closed()
    asyncio.run(run())


@pytest.mark.parametrize("change", ["hostname", "server_ca", "client_identity"])
def test_untrusted_backend_or_client_certificate_cannot_proxy(signer, tls, mtls, change):
    async def run():
        _, sign = signer
        async with backend(mtls) as (args, seen, _):
            if change == "hostname": args["backend_hostname"] = "wrong.example.test"
            elif change == "server_ca": args["backend_ca"] = tls[0]
            else: args["client_cert"], args["client_key"] = tls[0], tls[1]
            async with live(module().build_application(**args), tls) as (port, _):
                assert await exchange(port, tls, wire("/echo", sign("/echo"))) == (
                    502, b'{"code":"BACKEND_UNAVAILABLE"}')
            assert not seen and not seen.connections
    asyncio.run(run())


def test_direct_backend_connection_without_client_certificate_is_rejected(mtls):
    async def run():
        async with backend(mtls) as (args, seen, _):
            context = ssl.create_default_context(cafile=str(args["backend_ca"]))
            reader, writer = await asyncio.open_connection("127.0.0.1", args["backend_port"],
                            ssl=context, server_hostname="backend.example.test", ssl_handshake_timeout=1)
            try:
                writer.write(b"POST /echo HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 0\r\n\r\n")
                try:
                    await writer.drain()
                    assert await asyncio.wait_for(reader.read(), 1) == b""
                except (ConnectionError, ssl.SSLError):
                    pass
            finally:
                writer.close()
                try: await writer.wait_closed()
                except (ConnectionError, ssl.SSLError): pass
            assert not seen and not seen.connections
    asyncio.run(run())


@pytest.mark.parametrize("chunked", [False, True])
def test_oversized_upload_never_opens_backend_connection(signer, tls, mtls, chunked):
    async def run():
        _, sign = signer
        body = b"x" * (1024 * 1024 + 1)
        async with backend(mtls) as (args, seen, _):
            async with live(module().build_application(**args), tls) as (port, _):
                raw = wire("/echo", sign("/echo"), body, chunked=chunked)
                if not chunked:
                    raw = raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
                reader, writer = await connect(port, tls)
                try:
                    writer.write(raw); await writer.drain()
                    assert await response(reader) == (413, b'{"code":"INVALID_REQUEST"}')
                finally:
                    writer.close()
                    try: await writer.wait_closed()
                    except (ConnectionError, ssl.SSLError): pass
            assert not seen and not seen.connections
    asyncio.run(run())


def test_upload_disconnect_before_completion_never_opens_backend(signer, tls, mtls):
    async def run():
        _, sign = signer
        async with backend(mtls) as (args, seen, _):
            async with live(module().build_application(**args), tls) as (port, server):
                _, writer = await connect(port, tls)
                writer.write(wire("/echo", sign("/echo"))[:-1]); await writer.drain()
                writer.close(); await writer.wait_closed()
                for _ in range(20):
                    if not server.config._active: break
                    await asyncio.sleep(0.01)
                assert not server.config._active
                assert not seen and not seen.connections
    asyncio.run(run())


def test_backend_body_drip_cannot_reset_absolute_backend_budget(signer, tls, mtls):
    async def run():
        _, sign = signer
        async with backend(mtls, drip=True) as (args, seen, closed):
            async with live(module().build_application(**args, backend_timeout=0.15), tls) as (port, _):
                assert await exchange(port, tls, wire("/echo", sign("/echo"))) == (
                    504, b'{"code":"BACKEND_TIMEOUT"}')
                assert len(seen) == 1
                await asyncio.sleep(0.2)
                assert closed
    asyncio.run(run())


def test_outer_request_timeout_cancels_and_closes_backend(signer, tls, mtls):
    async def run():
        _, sign = signer
        async with backend(mtls, stall=True) as (args, _, closed):
            async with live(module().build_application(**args, backend_timeout=2), tls,
                            total_timeout=0.15) as (port, server):
                assert await exchange(port, tls, wire("/echo", sign("/echo"))) == (
                    504, b'{"code":"INGRESS_TIMEOUT"}')
                for _ in range(20):
                    if closed and not server.config._active: break
                    await asyncio.sleep(0.01)
                assert closed and not server.config._active
    asyncio.run(run())


def test_ssl_configuration_error_has_no_private_exception_context(mtls):
    args = {name: value for name, value in mtls.items() if name != "context"}
    args.update(backend_port=8443, backend_ca="/PRIVATE_TOKEN_DO_NOT_LOG/missing.pem")
    with pytest.raises(ValueError) as caught:
        module().build_application(**args)
    assert str(caught.value) == "invalid Spring ingress configuration"
    assert caught.value.__context__ is None and caught.value.__cause__ is None


def test_cli_configuration_failure_prints_only_fixed_code(tmp_path):
    env = {name: value for name, value in os.environ.items() if not name.startswith("APPGUARD_")}
    result = subprocess.run([sys.executable, str(ROOT / "examples/spring-ingress/ingress.py")],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode != 0
    assert result.stdout == "" and result.stderr.strip() == "SPRING_INGRESS_HOST_FAILED"


def test_backend_http10_response_is_not_silently_qualified_as_http11(signer, tls, mtls):
    async def run():
        _, sign = signer
        async with backend(mtls, reply=b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}") as (args, _, _):
            async with live(module().build_application(**args), tls) as (port, _):
                assert await exchange(port, tls, wire("/echo", sign("/echo"))) == (
                    502, b'{"code":"BACKEND_UNAVAILABLE"}')
    asyncio.run(run())


def test_maximum_entity_body_survives_while_chunked_response_overflow_rejects(signer, tls, mtls):
    async def run():
        _, sign = signer
        body = b"\x00" * (1024 * 1024)
        async with backend(mtls) as (args, seen, _):
            async with live(module().build_application(**args), tls) as (port, _):
                assert await exchange(port, tls, wire("/echo", sign("/echo", body), body)) == (200, body)
                assert seen[0][1] == body
        oversized = b"x" * (1024 * 1024 + 1)
        reply = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100001\r\n"
                 + oversized + b"\r\n0\r\n\r\n")
        async with backend(mtls, reply=reply) as (args, _, _):
            async with live(module().build_application(**args), tls) as (port, _):
                assert await exchange(port, tls, wire("/echo", sign("/echo"))) == (
                    502, b'{"code":"BACKEND_UNAVAILABLE"}')
    asyncio.run(run())


@pytest.mark.parametrize("change", ["proof", "target", "method", "headers", "root", "scheme"])
def test_rewritten_or_missing_raw_transport_evidence_never_reaches_backend(signer, tls, mtls, change):
    async def run():
        _, sign = signer
        async with backend(mtls) as (args, seen, _):
            app = module().build_application(**args)
            async def rewrite(scope, receive, send):
                changed = dict(scope)
                if change == "proof": changed.pop("appguard.ingress", None)
                elif change == "target": changed["appguard.raw_target"] = b"/elsewhere"
                elif change == "method": changed["method"] = "GET"
                elif change == "headers": changed["headers"] = ()
                elif change == "root": changed["root_path"] = "/prefix"
                else: changed["scheme"] = "http"
                await app(changed, receive, send)
            async with live(rewrite, tls) as (port, _):
                assert await exchange(port, tls, wire("/echo", sign("/echo"))) == (
                    400, b'{"code":"INVALID_REQUEST"}')
            assert not seen and not seen.connections
    asyncio.run(run())


def test_backend_tls_handshake_stall_is_bounded_and_raw_connection_closes(signer, tls, mtls):
    async def run():
        _, sign = signer
        tasks, closed = set(), []
        async def silent_backend(reader, writer):
            task = asyncio.current_task(); tasks.add(task)
            try:
                while await reader.read(8192):
                    pass  # Consume TLS bytes without answering the handshake.
            finally:
                closed.append(True)
                writer.close(); await writer.wait_closed()
                tasks.discard(task)
        server = await asyncio.start_server(silent_backend, "127.0.0.1", 0)
        args = {name: value for name, value in mtls.items() if name != "context"}
        args["backend_port"] = server.sockets[0].getsockname()[1]
        try:
            async with live(module().build_application(**args, backend_timeout=0.15), tls) as (port, _):
                assert await exchange(port, tls, wire("/echo", sign("/echo"))) == (
                    504, b'{"code":"BACKEND_TIMEOUT"}')
                for _ in range(20):
                    if closed: break
                    await asyncio.sleep(0.01)
                assert closed
        finally:
            server.close(); await server.wait_closed()
            for task in tuple(tasks): task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    asyncio.run(run())


def test_backend_close_reset_does_not_replace_pending_request_cancellation():
    async def run():
        gateway = module()
        class ResetWriter:
            # Force the stream boundary's reset at the otherwise racy TLS close.
            def __init__(self):
                self.transport = self
                self.closed = False
                self.aborted = False
            def close(self): self.closed = True
            def abort(self): self.aborted = True
            async def wait_closed(self):
                raise ConnectionResetError("PRIVATE_CLOSE_ERROR")
        writer = ResetWriter()
        async def pending_request():
            try:
                await asyncio.Future()
            finally:
                await gateway._close(writer, asyncio.get_running_loop().time() + 1)
        task = asyncio.create_task(pending_request())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert task.cancelled() and writer.closed and writer.aborted
    asyncio.run(run())
