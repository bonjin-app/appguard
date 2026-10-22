"""Explicitly configured direct-TLS host; no credentials or network on import."""

import hashlib
import hmac
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from appguard.asgi import AppGuardMiddleware, Identity
from appguard.canonical import validate_identifier
from appguard.types import KeyRecord


def build_application(*, app_id, origin, subject, key_id, public_key_pem, bearer_sha256, replay):
    """A single enrolled subject with a separate fixed resource authorization rule.

    Replace this example host authentication/key lookup with your own services.
    The token must be high entropy; its digest is operator configuration, never
    a value or identity accepted from the request as trusted enrollment data.
    """
    for identifier in (app_id, subject, key_id):
        validate_identifier(identifier)
    if type(bearer_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", bearer_sha256):
        raise ValueError("invalid host authentication configuration")
    public = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
        raise ValueError("a trusted enrolled P-256 public key is required")
    key = KeyRecord(app_id, key_id, subject, public_key_pem, "ecdsa-p256-sha256", False)

    async def identity(scope, requested_key_id):
        authorization = dict(scope["headers"]).get(b"authorization", b"")
        scheme, separator, token = authorization.partition(b" ")
        if (scheme.lower() != b"bearer" or not separator or not token
                or not hmac.compare_digest(hashlib.sha256(token).hexdigest(), bearer_sha256)):
            return None
        scope.setdefault("state", {})["host_subject"] = subject
        return Identity(subject, key if requested_key_id == key_id else None)

    async def resource(scope, receive, send):
        # AppGuard verification does not grant access. Enforce the application's
        # authenticated identity and resource permissions after verification.
        allowed = (scope["state"].get("host_subject") == subject
                   and scope["method"] == "POST" and scope["raw_path"] == b"/v1/items")
        body = (await receive())["body"] if allowed else b'{"code":"RESOURCE_FORBIDDEN"}'
        await send({"type": "http.response.start", "status": 200 if allowed else 403, "headers": [
            (b"content-type", b"application/octet-stream" if allowed else b"application/json"),
            (b"content-length", str(len(body)).encode()), (b"cache-control", b"no-store"),
        ]})
        await send({"type": "http.response.body", "body": body})

    return AppGuardMiddleware(resource, app_id=app_id, origin=origin, identity_resolver=identity,
                              replay=replay, body_timeout=10.0, identity_timeout=2.0)


def main():
    # Optional packages are loaded only when this explicitly configured host runs.
    import redis
    from appguard.redis import RedisReplayStore
    from appguard.uvicorn import IngressConfig, IngressServer

    client = None
    failed = False
    try:
        origin = os.environ["APPGUARD_ORIGIN"]
        client = redis.Redis.from_url(os.environ["APPGUARD_REDIS_URL"], socket_connect_timeout=1.0,
                                      socket_timeout=1.0, health_check_interval=30,
                                      decode_responses=False)
        app = build_application(
            app_id=os.environ["APPGUARD_APP_ID"], origin=origin,
            subject=os.environ["APPGUARD_HOST_SUBJECT"], key_id=os.environ["APPGUARD_ENROLLED_KEY_ID"],
            public_key_pem=Path(os.environ["APPGUARD_ENROLLED_PUBLIC_KEY"]).read_bytes(),
            bearer_sha256=os.environ["APPGUARD_HOST_BEARER_SHA256"], replay=RedisReplayStore(client),
        )
        config = IngressConfig(
            app, authority=urlsplit(origin).netloc,
            ssl_certfile=os.environ["APPGUARD_TLS_CERT"], ssl_keyfile=os.environ["APPGUARD_TLS_KEY"],
            host=os.environ.get("APPGUARD_LISTEN_HOST", "127.0.0.1"),
            port=int(os.environ.get("APPGUARD_LISTEN_PORT", "8443")),
            max_connections=128, max_inflight=64, backlog=128,
            handshake_timeout=5.0, tls_shutdown_timeout=1.0,
            header_timeout=5.0, total_timeout=20.0,
            timeout_keep_alive=3, timeout_graceful_shutdown=10,
        )
        IngressServer(config).run()
    except Exception:
        # Startup/configuration exceptions can include credential-bearing URLs
        # or paths. Report only a fixed code; operators inspect inputs privately.
        failed = True
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
    if failed:
        # Raising outside both handlers/finally also clears __context__; hiding
        # a traceback with ``from None`` would retain the private exception.
        raise SystemExit("INGRESS_HOST_FAILED")


if __name__ == "__main__":
    main()
