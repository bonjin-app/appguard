"""Actual validating TLS clients and HTTP/1.1 sockets, never ASGITransport."""

import asyncio
import base64
import hashlib
import json
import ssl
import time
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

from appguard.asgi import AppGuardMiddleware, Identity
from appguard.canonical import build_signature_base
from appguard.replay import InMemoryReplayStore
from appguard.types import KeyRecord, RequestInput, SignatureParameters
from conftest import NOW, ORIGIN, VECTOR


@pytest.fixture
def tls(tmp_path):
    """Ephemeral local CA and server leaf. Clients verify chain and hostname."""
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AppGuard local test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    server_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "api.example.test")]))
        .issuer_name(ca_name).public_key(server_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.example.test")]), critical=False)
        .sign(ca_key, hashes.SHA256()))
    ca_path, cert_path, key_path = (tmp_path / name for name in ("ca.pem", "server.pem", "key.pem"))
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    return cert_path, key_path, ssl.create_default_context(cafile=str(ca_path))


@pytest.fixture
def signer():
    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    key = KeyRecord("test-app", "test-key", "test-user", pem, "ecdsa-p256-sha256", False)
    counter = 0

    def sign(target, body=b"{}", *, authorization="Bearer TEST_ONLY_TOKEN"):
        nonlocal counter
        counter += 1
        nonce = base64.urlsafe_b64encode(counter.to_bytes(16, "big")).decode().rstrip("=")
        params = replace(SignatureParameters(**VECTOR["parameters"]), nonce=nonce)
        pairs = (("Content-Type", "application/octet-stream"),
                 ("Content-Digest", "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"),
                 ("Authorization", authorization), ("AppGuard-App-Id", "test-app"))
        base = build_signature_base(RequestInput("POST", target, pairs, body), params, origin=ORIGIN)
        r, s = utils.decode_dss_signature(private.sign(base, ec.ECDSA(hashes.SHA256())))
        signature = base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()
        return list(pairs) + [
            ("Signature-Input", "appguard=" + base.decode().split('"@signature-params": ', 1)[1]),
            ("Signature", "appguard=:" + signature + ":"),
        ]

    return key, sign


def wire(target, headers, body=b"{}", *, close=True, chunked=False):
    pairs = [("Host", "api.example.test"), *headers]
    if chunked:
        pairs.append(("Transfer-Encoding", "chunked"))
        body = b"".join(f"{len(part):x}\r\n".encode() + part + b"\r\n"
                        for part in (body[:1], body[1:]) if part) + b"0\r\n\r\n"
    elif not any(name.lower() in {"content-length", "transfer-encoding"} for name, _ in pairs):
        pairs.append(("Content-Length", str(len(body))))
    pairs.append(("Connection", "close" if close else "keep-alive"))
    return (b"POST " + target.encode("ascii") + b" HTTP/1.1\r\n"
            + b"".join(name.encode() + b": " + value.encode() + b"\r\n" for name, value in pairs)
            + b"\r\n" + body)


async def response(reader):
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ")[1])
    headers = dict(line.lower().split(b": ", 1) for line in lines[1:] if line)
    if b"content-length" in headers:
        body = await asyncio.wait_for(reader.readexactly(int(headers[b"content-length"])), 2)
    elif headers.get(b"transfer-encoding") == b"chunked":
        body = b""
        while True:
            size = int((await reader.readuntil(b"\r\n")).strip(), 16)
            body += await reader.readexactly(size)
            assert await reader.readexactly(2) == b"\r\n"
            if not size:
                break
    else:
        body = await asyncio.wait_for(reader.read(), 2)
    return status, body


async def connect(port, tls):
    return await asyncio.open_connection("127.0.0.1", port, ssl=tls[2], server_hostname="api.example.test")


@asynccontextmanager
async def live(app, tls, *, before_start=None, **changes):
    from appguard.uvicorn import IngressConfig, IngressServer

    config = IngressConfig(app, authority="api.example.test", ssl_certfile=str(tls[0]),
                           ssl_keyfile=str(tls[1]), port=0, **changes)
    config.load()
    if before_start is not None:
        before_start(config)
    server = IngressServer(config)
    server.lifespan = config.lifespan_class(config)
    await server.startup()
    try:
        yield server.servers[0].sockets[0].getsockname()[1], server
    finally:
        await server.shutdown()


async def exchange(port, tls, data):
    reader, writer = await connect(port, tls)
    try:
        writer.write(data)
        await writer.drain()
        return await response(reader)
    finally:
        writer.close()
        await writer.wait_closed()


def protected(key, *, calls=None, identity=None, endpoint=None, **changes):
    async def default_endpoint(scope, receive, send):
        if calls is not None:
            calls.append(scope)
        assert scope["state"]["appguard"].code == "VERIFIED"
        body = (await receive())["body"]
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    def resolve(scope, kid):
        headers = dict(scope["headers"])
        return Identity("test-user", key) if headers.get(b"authorization") == b"Bearer TEST_ONLY_TOKEN" else None

    return AppGuardMiddleware(endpoint or default_endpoint, app_id="test-app", origin=ORIGIN,
                              identity_resolver=identity or resolve, replay=InMemoryReplayStore(),
                              clock=lambda: NOW, **changes)


@pytest.mark.parametrize("target", ["/v1/items", "/v1/items?", "/a%2Fb?b=2&a=1&a=3", "/a//b?q=%2f"])
@pytest.mark.parametrize("body,chunked", [(b"", False), (b"\x00\xff\r\n{}", False), (b"\x00\xff\r\n{}", True)])
def test_exact_target_and_body_over_validating_tls(target, body, chunked, signer, tls):
    key, sign = signer
    calls = []

    async def run():
        async with live(protected(key, calls=calls), tls) as (port, server):
            assert await exchange(port, tls, wire(target, sign(target, body), body, chunked=chunked)) == (200, body)

    asyncio.run(run())
    assert calls[0]["appguard.raw_target"] == target.encode()
    assert calls[0]["appguard.ingress"].target == target.encode()


@pytest.mark.parametrize("pipelined", [False, True])
def test_keepalive_and_pipelining_keep_capture_per_request(signer, tls, pipelined):
    key, sign = signer
    calls = []
    targets = ["/v1/items", "/v1/items?", "/a%2fb?c=1&c=2"]

    async def run():
        async with live(protected(key, calls=calls), tls) as (port, server):
            reader, writer = await connect(port, tls)
            requests = [wire(target, sign(target, bytes([i])), bytes([i]), close=i == 2)
                        for i, target in enumerate(targets)]
            try:
                if pipelined:
                    writer.write(b"".join(requests))
                for i, data in enumerate(requests):
                    if not pipelined:
                        writer.write(data)
                    await writer.drain()
                    assert await response(reader) == (200, bytes([i]))
            finally:
                writer.close()
                await writer.wait_closed()

    asyncio.run(run())
    assert [scope["appguard.ingress"].target for scope in calls] == [target.encode() for target in targets]


@pytest.mark.parametrize("extra", [[("Content-Length", "2"), ("content-length", "2")],
                                  [("Content-Length", "2, 2")],
                                  [("Content-Length", "02")],
                                  [("Content-Length", "2"), ("Transfer-Encoding", "chunked")],
                                  [("Transfer-Encoding", "CHUNKED")],
                                  [("Authorization", "Bearer TEST_ONLY_TOKEN")],
                                  [("Signature", "appguard=:AAAA:")],
                                  [("AppGuard-App-Id", "test-app")],
                                  [("X-Forwarded-Proto", "https")]])
def test_ambiguous_or_normalized_headers_rejected_before_identity(extra, signer, tls):
    key, sign = signer
    calls = []

    def identity(*args):
        calls.append("identity")
        return Identity("test-user", key)

    async def run():
        async with live(protected(key, calls=calls, identity=identity), tls) as (port, server):
            status, body = await exchange(port, tls, wire("/v1/items?", sign("/v1/items?") + extra))
            assert status == 400
            assert b"TOKEN" not in body

    asyncio.run(run())
    assert calls == []


@pytest.mark.parametrize("replacement", [b"Authorization:  Bearer TEST_ONLY_TOKEN", b"Authorization:\tBearer TEST_ONLY_TOKEN",
                                         b"Authorization: Bearer TEST_ONLY_TOKEN ",
                                         b"Authorization: Bearer\r\n TEST_ONLY_TOKEN"])
def test_header_whitespace_cannot_be_normalized_into_valid_signature(replacement, signer, tls):
    key, sign = signer
    data = wire("/v1/items?", sign("/v1/items?")).replace(b"Authorization: Bearer TEST_ONLY_TOKEN", replacement)

    async def run():
        async with live(protected(key), tls) as (port, server):
            assert (await exchange(port, tls, data))[0] == 400

    asyncio.run(run())


def test_signed_target_cannot_substitute_empty_query(signer, tls):
    key, sign = signer

    async def run():
        async with live(protected(key), tls) as (port, server):
            assert await exchange(port, tls, wire("/v1/items?", sign("/v1/items"))) == (403, b'{"code":"INVALID_SIGNATURE"}')

    asyncio.run(run())


def test_replay_authentication_and_resource_authorization_remain_separate(signer, tls):
    key, sign = signer
    calls = []

    async def resource(scope, receive, send):
        calls.append(scope["state"]["appguard"].code)
        await send({"type": "http.response.start", "status": 403,
                    "headers": [(b"content-length", b"16")]})
        await send({"type": "http.response.body", "body": b"resource denied!"})

    # The sample host's authorization is independent of AppGuard verification.
    async def run():
        app = protected(key, endpoint=resource)
        async with live(app, tls) as (port, server):
            bad = sign("/private?", authorization="Bearer INVALID_TOKEN")
            assert await exchange(port, tls, wire("/private?", bad)) == (401, b'{"code":"AUTHENTICATION_REQUIRED"}')
            data = wire("/private?", sign("/private?"))
            assert await exchange(port, tls, data) == (403, b"resource denied!")
            assert await exchange(port, tls, data) == (403, b'{"code":"REPLAY_DETECTED"}')

    asyncio.run(run())
    assert calls == ["VERIFIED"]


@pytest.mark.parametrize("extra", [[("Host", "api.example.test")], [("Host", "other.example.test")],
                                  [("Content-Encoding", "gzip")], [("Content-Type", "application/json")],
                                  [("Content-Digest", "sha-256=:AAAA:")],
                                  [("Signature-Input", "untrusted")],
                                  [("Transfer-Encoding", "gzip")], [("Upgrade", "websocket")]])
def test_other_transport_ambiguities_fail_closed(extra, signer, tls):
    key, sign = signer
    calls = []

    async def run():
        async with live(protected(key, calls=calls), tls) as (port, server):
            assert (await exchange(port, tls, wire("/v1/items?", sign("/v1/items?") + extra)))[0] == 400

    asyncio.run(run())
    assert calls == []


@pytest.mark.parametrize("target", ["https://api.example.test/v1/items?", "//api.example.test/v1/items?",
                                   "*", "/../private?", "/%2e%2e/private?", "/a%5cb?", "/a%00b?",
                                   "/a%GG?", "/a#fragment?"])
def test_unsupported_request_target_forms_rejected_before_auth(target, signer, tls):
    key, sign = signer
    calls = []

    async def run():
        async with live(protected(key, calls=calls), tls) as (port, server):
            assert (await exchange(port, tls, wire(target, sign("/v1/items?"))))[0] == 400

    asyncio.run(run())
    assert calls == []


@pytest.mark.parametrize("change", ["lf", "http10", "trailer", "header_count", "header_size", "target_size"])
def test_framing_and_capture_limits_are_enforced_on_socket(change, signer, tls):
    key, sign = signer
    headers = sign("/v1/items?")
    data = wire("/v1/items?", headers)
    if change == "lf":
        data = data.replace(b"\r\n", b"\n")
    elif change == "http10":
        data = data.replace(b"HTTP/1.1", b"HTTP/1.0")
    elif change == "trailer":
        data = wire("/v1/items?", headers, chunked=True).replace(b"0\r\n\r\n", b"0\r\nAuthorization: hidden\r\n\r\n")
    elif change == "header_count":
        data = wire("/v1/items?", headers + [("X-Extra", "x")] * 65)
    elif change == "header_size":
        data = wire("/v1/items?", headers + [("X-Extra", "x" * 17000)])
    else:
        data = wire("/" + "x" * 8192, headers)
    calls = []

    async def run():
        async with live(protected(key, calls=calls), tls) as (port, server):
            assert (await exchange(port, tls, data))[0] == 400

    asyncio.run(run())
    assert calls == []


def test_fragmented_headers_and_body_preserve_immutable_evidence(signer, tls):
    key, sign = signer
    calls = []
    data = wire("/v1/items?", sign("/v1/items?"))

    async def run():
        async with live(protected(key, calls=calls), tls) as (port, server):
            reader, writer = await connect(port, tls)
            try:
                for offset in range(0, len(data), 7):
                    writer.write(data[offset:offset + 7])
                    await writer.drain()
                    await asyncio.sleep(0)
                assert await response(reader) == (200, b"{}")
            finally:
                writer.close()
                await writer.wait_closed()

    asyncio.run(run())
    evidence = calls[0]["appguard.ingress"]
    assert evidence.header_block == data[:data.index(b"\r\n\r\n") + 4]
    assert (b"Authorization", b"Bearer TEST_ONLY_TOKEN") in evidence.header_fields
    assert repr(evidence) == "RequestEvidence()"
    with pytest.raises(AttributeError):
        evidence.target = b"/other"


def test_actual_tls_certificate_validation_is_required(signer, tls):
    key, _ = signer

    async def run():
        async with live(protected(key), tls) as (port, server):
            with pytest.raises(ssl.SSLCertVerificationError):
                await asyncio.open_connection("127.0.0.1", port, ssl=ssl.create_default_context(),
                                              server_hostname="api.example.test")
            with pytest.raises(ssl.SSLCertVerificationError):
                await asyncio.open_connection("127.0.0.1", port, ssl=tls[2], server_hostname="wrong.example.test")

    asyncio.run(run())


def test_body_limit_and_truncated_disconnected_upload_never_authenticate(signer, tls):
    key, sign = signer
    calls = []

    def identity(*args):
        calls.append("identity")
        return Identity("test-user", key)

    async def run():
        async with live(protected(key, identity=identity), tls) as (port, server):
            assert await exchange(port, tls, wire("/v1/items?", sign("/v1/items?"),
                                                  b"", close=True).replace(b"Content-Length: 0", b"Content-Length: 1048577")) == (413, b'{"code":"INVALID_REQUEST"}')
            reader, writer = await connect(port, tls)
            data = wire("/v1/items?", sign("/v1/items?"), close=False)
            writer.write(data[:-1])
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.03)

    asyncio.run(run())
    assert calls == []


def test_header_and_body_deadlines_close_or_reject_without_auth(signer, tls):
    key, sign = signer
    calls = []

    def identity(*args):
        calls.append("identity")
        return Identity("test-user", key)

    async def run():
        app = protected(key, identity=identity, body_timeout=0.04)
        async with live(app, tls, header_timeout=0.04) as (port, server):
            reader, writer = await connect(port, tls)
            writer.write(b"POST /v1/items? HTTP/1.1\r\nHost: api.example.test\r\n")
            await writer.drain()
            start = time.monotonic()
            assert await asyncio.wait_for(reader.read(), 0.7) == b""
            assert time.monotonic() - start < 0.5
            writer.close()
            await writer.wait_closed()
            data = wire("/v1/items?", sign("/v1/items?"), close=False)
            reader, writer = await connect(port, tls)
            writer.write(data[:-1])
            await writer.drain()
            assert await response(reader) == (400, b'{"code":"INVALID_REQUEST"}')
            # Returning an error while an upload is incomplete must close the
            # transport rather than leave a drainable keepalive request alive.
            assert await asyncio.wait_for(reader.read(), 0.3) == b""
            writer.close()
            await writer.wait_closed()

    asyncio.run(run())
    assert calls == []


def test_identity_deadline_and_exception_are_redacted(signer, tls, caplog):
    key, sign = signer

    async def identity(scope, kid):
        await asyncio.sleep(10)
        raise RuntimeError("PRIVATE_IDENTITY_SECRET")

    async def run():
        async with live(protected(key, identity=identity, identity_timeout=0.03), tls) as (port, server):
            assert await exchange(port, tls, wire("/secret?", sign("/secret?"))) == (503, b'{"code":"IDENTITY_UNAVAILABLE"}')

    asyncio.run(run())
    assert "TEST_ONLY_TOKEN" not in caplog.text and "/secret?" not in caplog.text
    assert "PRIVATE_IDENTITY_SECRET" not in caplog.text


def test_application_exception_is_redacted_before_uvicorn_error_logging(signer, tls, caplog):
    key, sign = signer

    async def broken(scope, receive, send):
        raise RuntimeError("PRIVATE_APPLICATION_SECRET TEST_ONLY_TOKEN")

    async def run():
        async with live(protected(key, endpoint=broken), tls) as (port, server):
            assert await exchange(port, tls, wire("/secret?", sign("/secret?"))) == (503, b'{"code":"APPLICATION_UNAVAILABLE"}')

    asyncio.run(run())
    assert "PRIVATE_APPLICATION_SECRET" not in caplog.text and "TEST_ONLY_TOKEN" not in caplog.text
    assert "/secret?" not in caplog.text


def test_total_deadline_retains_admission_until_resistant_application_finishes(signer, tls, caplog):
    key, sign = signer

    async def run():
        gate, cancelled = asyncio.Event(), asyncio.Event()
        calls = []

        async def resistant(scope, receive, send):
            calls.append(True)
            while not gate.is_set():
                try:
                    await gate.wait()
                except asyncio.CancelledError:
                    cancelled.set()
            # A late response must be fenced; its error cannot be logged.
            await send({"type": "http.response.start", "status": 200, "headers": []})
            raise RuntimeError("PRIVATE_LATE_APPLICATION_SECRET")

        async with live(protected(key, endpoint=resistant), tls, max_inflight=1,
                        total_timeout=0.04) as (port, server):
            assert await exchange(port, tls, wire("/first?", sign("/first?"))) == (504, b'{"code":"INGRESS_TIMEOUT"}')
            await asyncio.wait_for(cancelled.wait(), 0.5)
            assert len(server.config._active) == 1
            assert await exchange(port, tls, wire("/second?", sign("/second?"))) == (503, b'{"code":"INGRESS_OVERLOADED"}')
            assert calls == [True]
            gate.set()
            await asyncio.sleep(0.02)
            assert len(server.config._active) == 0

    asyncio.run(run())
    assert "PRIVATE_LATE_APPLICATION_SECRET" not in caplog.text


def test_connection_admission_does_not_allow_idle_peers_to_grow_unbounded(signer, tls):
    key, _ = signer

    async def run():
        async with live(protected(key), tls, max_connections=1) as (port, server):
            first_reader, first = await connect(port, tls)
            try:
                # Admission occurs before a TLS handshake can complete.
                with pytest.raises((ConnectionResetError, ssl.SSLError)):
                    await connect(port, tls)
                await asyncio.sleep(0)
                assert len(server.server_state.connections) == 1
            finally:
                first.close()
                await first.wait_closed()

    asyncio.run(run())


@pytest.mark.parametrize("name,value", [("root_path", "/mounted"), ("proxy_headers", True),
                                       ("http2", True), ("access_log", True), ("workers", 2),
                                       ("log_level", "trace"), ("limit_concurrency", 2)])
def test_changed_server_configuration_fails_closed(name, value, tls):
    from appguard.uvicorn import IngressConfig
    config = IngressConfig(lambda *args: None, authority="api.example.test",
                           ssl_certfile=str(tls[0]), ssl_keyfile=str(tls[1]))
    setattr(config, name, value)
    with pytest.raises(ValueError, match="unsupported ingress transport configuration"):
        config.load()


def test_dependency_version_mismatch_is_rejected(monkeypatch, tls):
    from appguard.uvicorn import IngressConfig
    monkeypatch.setattr(uvicorn, "__version__", "0.55.0")
    with pytest.raises(ValueError, match="requires uvicorn==0.54.0"):
        IngressConfig(lambda *args: None, authority="api.example.test",
                      ssl_certfile=str(tls[0]), ssl_keyfile=str(tls[1]))


def test_non_singleton_duplicates_are_preserved_without_normalization(signer, tls):
    key, sign = signer
    calls = []
    headers = sign("/v1/items?") + [("X-Trace", "first"), ("x-trace", "second")]

    async def run():
        async with live(protected(key, calls=calls), tls) as (port, server):
            assert await exchange(port, tls, wire("/v1/items?", headers)) == (200, b"{}")

    asyncio.run(run())
    assert calls[0]["appguard.ingress"].header_fields[-4:-2] == ((b"X-Trace", b"first"), (b"x-trace", b"second"))
    assert [(name, value) for name, value in calls[0]["headers"] if name == b"x-trace"] == [
        (b"x-trace", b"first"), (b"x-trace", b"second")]


def test_example_host_runs_with_independent_authentication_and_resource_rule(signer, tls):
    import importlib.util
    from pathlib import Path

    example = Path(__file__).resolve().parents[3] / "examples/python-ingress/server.py"
    spec = importlib.util.spec_from_file_location("appguard_ingress_example", example)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    key, sign = signer
    app = module.build_application(
        app_id=key.app_id, origin=ORIGIN, subject="test-user", key_id=key.key_id,
        public_key_pem=key.public_key_pem, bearer_sha256=hashlib.sha256(b"TEST_ONLY_TOKEN").hexdigest(),
        replay=InMemoryReplayStore(),
    )
    app.clock = lambda: NOW

    async def run():
        async with live(app, tls) as (port, server):
            assert await exchange(port, tls, wire("/v1/items?", sign("/v1/items?"))) == (200, b"{}")
            assert await exchange(port, tls, wire("/v1/admin?", sign("/v1/admin?"))) == (403, b'{"code":"RESOURCE_FORBIDDEN"}')
            assert await exchange(port, tls, wire("/v1/items?", sign("/v1/items?", authorization="Bearer WRONG"))) == (401, b'{"code":"AUTHENTICATION_REQUIRED"}')

    asyncio.run(run())


def test_core_sdk_import_does_not_load_optional_server_packages():
    import subprocess
    import sys

    script = """
import sys
from importlib.abc import MetaPathFinder
class NoServer(MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split('.')[0] in {'h11', 'uvicorn'}:
            raise ImportError('optional server dependency unavailable')
sys.meta_path.insert(0, NoServer())
import appguard
import appguard.asgi
assert 'h11' not in sys.modules and 'uvicorn' not in sys.modules
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_graceful_shutdown_drains_cooperative_request_and_closes_keepalive(signer, tls):
    key, sign = signer

    async def run():
        started, release = asyncio.Event(), asyncio.Event()

        async def endpoint(scope, receive, send):
            started.set()
            await release.wait()
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]})
            await send({"type": "http.response.body", "body": b"ok"})

        async with live(protected(key, endpoint=endpoint), tls, timeout_graceful_shutdown=0.5) as (port, server):
            reader, writer = await connect(port, tls)
            writer.write(wire("/v1/items?", sign("/v1/items?"), close=False))
            await writer.drain()
            await asyncio.wait_for(started.wait(), 0.5)
            shutdown = asyncio.create_task(server.shutdown())
            await asyncio.sleep(0.01)
            release.set()
            assert await response(reader) == (200, b"ok")
            assert await asyncio.wait_for(reader.read(), 0.5) == b""
            await asyncio.wait_for(shutdown, 1)
            assert not server.config._active and not server.server_state.connections
            writer.close()
            await writer.wait_closed()

    asyncio.run(run())


def test_already_expired_request_never_starts_application(signer, tls, monkeypatch):
    from appguard.uvicorn import AppGuardH11Protocol
    original = AppGuardH11Protocol.capture_request
    calls = []

    def capture(self, evidence):
        original(self, evidence)
        self.loop.call_soon(time.sleep, 0.04)

    monkeypatch.setattr(AppGuardH11Protocol, "capture_request", capture)

    async def app(scope, receive, send):
        calls.append(True)
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"ok"})

    _, sign = signer

    async def run():
        async with live(app, tls, total_timeout=0.01) as (port, server):
            assert await exchange(port, tls, wire("/v1/items?", sign("/v1/items?"))) == (504, b'{"code":"INGRESS_TIMEOUT"}')

    asyncio.run(run())
    assert calls == []


def test_event_loop_blocking_app_cannot_send_success_after_deadline(signer, tls):
    _, sign = signer

    async def app(scope, receive, send):
        time.sleep(0.04)  # Cannot be preempted, but its late response is fenced.
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"ok"})

    async def run():
        async with live(app, tls, total_timeout=0.01) as (port, server):
            assert await exchange(port, tls, wire("/v1/items?", sign("/v1/items?"))) == (504, b'{"code":"INGRESS_TIMEOUT"}')

    asyncio.run(run())


@pytest.mark.parametrize("case", ["digest", "signature", "host", "oversize_chunked", "maximum_body", "maximum_target"])
def test_end_to_end_security_and_size_boundaries(case, signer, tls):
    key, sign = signer
    body, target = b"{}", "/v1/items?"
    if case == "maximum_body":
        body = b"x" * 1048576
    if case == "maximum_target":
        target = "/" + "x" * 8191
    headers = sign(target, body)
    if case == "digest":
        data = wire(target, headers, b"changed")
        expected = (403, b'{"code":"DIGEST_MISMATCH"}')
    elif case == "signature":
        headers[-1] = ("Signature", "appguard=:" + base64.b64encode(b"\x00" * 64).decode() + ":")
        data = wire(target, headers)
        expected = (403, b'{"code":"INVALID_SIGNATURE"}')
    elif case == "host":
        data = wire(target, headers).replace(b"Host: api.example.test", b"Host: other.example.test")
        expected = None
    elif case == "oversize_chunked":
        data = wire(target, headers, b"x" * 1048577, chunked=True)
        expected = (413, b'{"code":"INVALID_REQUEST"}')
    else:
        data, expected = wire(target, headers, body), (200, body)

    async def run():
        async with live(protected(key), tls) as (port, server):
            result = await exchange(port, tls, data)
            if expected is None:
                assert result[0] == 400
            else:
                assert result == expected

    asyncio.run(run())


def test_bad_pipelined_request_cannot_reuse_previous_transport_capture(signer, tls, caplog):
    key, sign = signer
    calls = []
    first = wire("/first?", sign("/first?"), close=False)
    invalid = wire("/second?", sign("/second?"), close=False).replace(
        b"Content-Length: 2", b"Content-Length: 2\r\nContent-Length: 2")
    third = wire("/third?", sign("/third?"))

    async def run():
        async with live(protected(key, calls=calls), tls) as (port, server):
            reader, writer = await connect(port, tls)
            writer.write(first + invalid + third)
            await writer.drain()
            assert await response(reader) == (200, b"{}")
            assert (await response(reader))[0] == 400
            assert await asyncio.wait_for(reader.read(), 0.5) == b""
            writer.close()
            await writer.wait_closed()

    asyncio.run(run())
    assert [scope["appguard.raw_target"] for scope in calls] == [b"/first?"]
    assert "TEST_ONLY_TOKEN" not in caplog.text and "/second?" not in caplog.text


def test_shutdown_requests_cancellation_without_claiming_to_terminate_resistant_work(signer, tls, caplog):
    key, sign = signer

    async def run():
        started, release, cancelled = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def resistant(scope, receive, send):
            started.set()
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    cancelled.set()

        async with live(protected(key, endpoint=resistant), tls, timeout_graceful_shutdown=0.03,
                        total_timeout=2) as (port, server):
            reader, writer = await connect(port, tls)
            writer.write(wire("/v1/items?", sign("/v1/items?"), close=False))
            await writer.drain()
            await asyncio.wait_for(started.wait(), 0.5)
            begin = time.monotonic()
            await asyncio.wait_for(server.shutdown(), 0.7)
            await asyncio.wait_for(cancelled.wait(), 0.5)
            assert time.monotonic() - begin < 0.7
            assert len(server.config._active) == 1  # Shutdown cannot terminate it.
            assert await asyncio.wait_for(reader.read(), 0.5) == b""
            release.set()
            await asyncio.sleep(0.02)
            assert not server.config._active
            writer.close()
            await writer.wait_closed()

    asyncio.run(run())
    assert "TEST_ONLY_TOKEN" not in caplog.text


def test_failed_error_response_does_not_chain_private_application_exception(signer, tls, caplog, monkeypatch):
    from appguard.uvicorn import AppGuardH11Protocol
    key, sign = signer

    async def broken(scope, receive, send):
        raise RuntimeError("PRIVATE_EXCEPTION_CHAIN_SECRET")

    async def failed_response(*args):
        raise ConnectionError("response transport failed")

    monkeypatch.setattr(AppGuardH11Protocol, "_failure", failed_response)

    async def run():
        async with live(protected(key, endpoint=broken), tls) as (port, server):
            assert (await exchange(port, tls, wire("/v1/items?", sign("/v1/items?"))))[0] == 500

    asyncio.run(run())
    assert "PRIVATE_EXCEPTION_CHAIN_SECRET" not in caplog.text


def test_parser_error_after_response_start_cannot_log_private_wire_bytes(signer, tls, caplog):
    _, sign = signer

    async def run():
        gate = asyncio.Event()

        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"100")]})
            await gate.wait()

        data = wire("/v1/items?", sign("/v1/items?"), chunked=True, close=False)
        head = data[:data.index(b"\r\n\r\n") + 4]
        async with live(app, tls) as (port, server):
            reader, writer = await connect(port, tls)
            writer.write(head)
            await writer.drain()
            assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
            writer.write(b"PRIVATE_PARSER_WIRE_SECRET\r\n")
            await writer.drain()
            try:
                assert await asyncio.wait_for(reader.read(), 0.5) == b""
            finally:
                gate.set()
                writer.close()
                await writer.wait_closed()

    asyncio.run(run())
    assert "PRIVATE_PARSER_WIRE_SECRET" not in caplog.text


def test_exception_during_application_call_is_also_redacted(signer, tls, caplog):
    _, sign = signer

    def broken(scope, receive, send):
        raise RuntimeError("PRIVATE_CALL_EXCEPTION_SECRET")

    async def run():
        async with live(broken, tls) as (port, server):
            assert await exchange(port, tls, wire("/v1/items?", sign("/v1/items?"))) == (503, b'{"code":"APPLICATION_UNAVAILABLE"}')

    asyncio.run(run())
    assert "PRIVATE_CALL_EXCEPTION_SECRET" not in caplog.text


def test_pre_tls_raw_tcp_peers_obey_connection_admission_and_handshake_deadline(signer, tls):
    key, _ = signer

    async def run():
        async with live(protected(key), tls, max_connections=1, header_timeout=0.03) as (port, server):
            peers = [await asyncio.open_connection("127.0.0.1", port) for _ in range(4)]
            try:
                await asyncio.sleep(0.12)
                assert len(server.server_state.connections) <= 1
                for reader, _ in peers:
                    assert await asyncio.wait_for(reader.read(1), 0.1) == b""
                assert not server.server_state.connections
            finally:
                for _, writer in peers:
                    writer.close()
                for _, writer in peers:
                    await writer.wait_closed()

    asyncio.run(run())


@pytest.mark.parametrize("name,value", [("total_timeout", float("inf")), ("header_timeout", float("nan")),
                                       ("timeout_keep_alive", 0), ("timeout_graceful_shutdown", False),
                                       ("max_connections", float("inf")), ("max_inflight", float("inf")),
                                       ("max_connections", True), ("max_inflight", 0), ("backlog", -1),
                                       ("handshake_timeout", float("inf")), ("tls_shutdown_timeout", 0)])
def test_owned_limits_are_revalidated_after_mutation(name, value, tls):
    from appguard.uvicorn import IngressConfig
    config = IngressConfig(lambda *args: None, authority="api.example.test",
                           ssl_certfile=str(tls[0]), ssl_keyfile=str(tls[1]))
    setattr(config, name, value)
    with pytest.raises(ValueError, match="invalid ingress configuration"):
        config.load()


def test_example_startup_failure_does_not_retain_private_exception_context(monkeypatch):
    import importlib.util
    from pathlib import Path
    import redis

    path = Path(__file__).resolve().parents[3] / "examples/python-ingress/server.py"
    spec = importlib.util.spec_from_file_location("appguard_failure_example", path)
    example = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(example)
    monkeypatch.setenv("APPGUARD_ORIGIN", "https://api.example.test")
    monkeypatch.setenv("APPGUARD_REDIS_URL", "redis://local.invalid")

    def broken(*args, **kwargs):
        raise RuntimeError("PRIVATE_REDIS_STARTUP_CREDENTIAL")

    monkeypatch.setattr(redis.Redis, "from_url", broken)
    with pytest.raises(SystemExit) as error:
        example.main()
    assert str(error.value) == "INGRESS_HOST_FAILED"
    assert error.value.__cause__ is None and error.value.__context__ is None


@pytest.mark.parametrize("name,value", [("max_inflight", float("inf")), ("total_timeout", float("inf")),
                                       ("max_connections", float("inf")), ("handshake_timeout", 0),
                                       ("tls_shutdown_timeout", False)])
def test_loaded_configuration_is_revalidated_before_listener_startup(name, value, tls):
    from appguard.uvicorn import IngressConfig, IngressServer
    config = IngressConfig(lambda *args: None, authority="api.example.test",
                           ssl_certfile=str(tls[0]), ssl_keyfile=str(tls[1]), port=0)
    config.load()
    setattr(config, name, value)
    server = IngressServer(config)

    async def run():
        with pytest.raises(ValueError, match="invalid ingress configuration"):
            await server.startup()
        assert not getattr(server, "servers", ())

    asyncio.run(run())


def test_pending_tls_handshakes_are_owned_and_aborted_during_shutdown(signer, tls):
    key, sign = signer

    async def run():
        async with live(protected(key), tls, max_connections=2, handshake_timeout=5) as (port, server):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await asyncio.sleep(0.01)
            pending = next(iter(server.server_state.connections))
            assert pending.inner is None and not pending._handshake.done()
            assert await exchange(port, tls, wire("/v1/items?", sign("/v1/items?"))) == (200, b"{}")
            await asyncio.wait_for(server.shutdown(), 0.7)
            assert await asyncio.wait_for(reader.read(), 0.2) == b""
            await asyncio.sleep(0)
            assert not server.server_state.connections and pending._handshake.done()
            writer.close()
            await writer.wait_closed()

    asyncio.run(run())


def test_raw_plaintext_cannot_supply_https_transport_evidence(signer, tls):
    key, sign = signer
    calls = []

    async def run():
        async with live(protected(key, calls=calls), tls) as (port, server):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(wire("/v1/items?", sign("/v1/items?")))
            await writer.drain()
            try:
                assert await asyncio.wait_for(reader.read(), 0.5) == b""
            finally:
                writer.close()
                await writer.wait_closed()
            await asyncio.sleep(0)
            assert not server.server_state.connections

    asyncio.run(run())
    assert calls == []


@pytest.mark.parametrize("stage", ["before_start", "before_accept"])
def test_mutated_loaded_tls_context_cannot_negotiate_tls10(stage, signer, tls):
    import warnings
    key, sign = signer
    calls = []

    def weaken(config):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            config._tls_context.minimum_version = ssl.TLSVersion.TLSv1
        config._tls_context.set_ciphers("DEFAULT:@SECLEVEL=0")

    client = tls[2]  # Still validates the test CA and hostname.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        client.minimum_version = client.maximum_version = ssl.TLSVersion.TLSv1
    client.set_ciphers("DEFAULT:@SECLEVEL=0")

    async def run():
        async with live(protected(key, calls=calls), tls,
                        before_start=weaken if stage == "before_start" else None) as (port, server):
            if stage == "before_accept":
                weaken(server.config)
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=client,
                    server_hostname="api.example.test", ssl_handshake_timeout=0.5)
            except (ssl.SSLError, ConnectionResetError):
                return
            try:
                negotiated = writer.get_extra_info("ssl_object").version()
                writer.write(wire("/v1/items?", sign("/v1/items?")))
                await writer.drain()
                result = await response(reader)
                pytest.fail(f"unsupported TLS negotiated {negotiated}; response status {result[0]}")
            finally:
                writer.close()
                await writer.wait_closed()

    asyncio.run(run())
    assert calls == []


@pytest.mark.parametrize("stage", ["before_start", "before_accept"])
def test_mutated_loaded_alpn_context_is_reset_to_http11(stage, signer, tls):
    key, sign = signer

    def weaken(config):
        config._tls_context.set_alpn_protocols(["h2"])

    tls[2].set_alpn_protocols(["h2", "http/1.1"])

    async def run():
        async with live(protected(key), tls,
                        before_start=weaken if stage == "before_start" else None) as (port, server):
            if stage == "before_accept":
                weaken(server.config)
            reader, writer = await connect(port, tls)
            try:
                assert writer.get_extra_info("ssl_object").selected_alpn_protocol() == "http/1.1"
                writer.write(wire("/v1/items?", sign("/v1/items?")))
                await writer.drain()
                assert await response(reader) == (200, b"{}")
            finally:
                writer.close()
                await writer.wait_closed()

    asyncio.run(run())
