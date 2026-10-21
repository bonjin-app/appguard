"""Bounded ASGI capture before application body parsing or routing."""

import asyncio
import inspect
import json
import math
import time
from dataclasses import dataclass, field

from .canonical import _validate_origin, validate_identifier
from .types import KeyRecord, RequestInput, VerificationError
from .verify import verify_request
from .wire import parse_signatures, validate_headers

_LIMIT = 1024 * 1024
_CORE_CODES = {"INVALID_REQUEST", "UNSUPPORTED_PROFILE", "INVALID_TIME", "KEY_REJECTED",
               "DIGEST_MISMATCH", "INVALID_SIGNATURE", "REPLAY_DETECTED", "REPLAY_STORE_UNAVAILABLE"}
_IDENTITY_TASKS = set()


def _identity_finished(task):
    # Keep unfinished tasks alive; retrieve late failures without logging them.
    _IDENTITY_TASKS.discard(task)
    if not task.cancelled():
        task.exception()


@dataclass(frozen=True)
class Identity:
    subject: str = field(repr=False)
    key: KeyRecord | None = field(repr=False)


class _HttpFailure(Exception):
    def __init__(self, status: int, code: str):
        self.status, self.code = status, code


def _target(scope: dict, resolver) -> str:
    path, query = scope.get("raw_path"), scope.get("query_string")
    if (type(path) is not bytes or type(query) is not bytes or b"?" in path
            or len(path) + len(query) > 8192):
        raise VerificationError("INVALID_REQUEST")
    exact = resolver(scope) if resolver is not None else scope.get("appguard.raw_target")
    if exact is None:
        # ASGI has no flag distinguishing /path from /path?. Do not guess.
        if not query:
            raise VerificationError("INVALID_REQUEST")
        exact = path + b"?" + query
    if type(exact) is not bytes or not 1 <= len(exact) <= 8192:
        raise VerificationError("INVALID_REQUEST")
    expected_path, _, expected_query = exact.partition(b"?")
    if expected_path != path or expected_query != query:
        raise VerificationError("INVALID_REQUEST")
    try:
        return exact.decode("ascii")
    except UnicodeError:
        raise VerificationError("INVALID_REQUEST") from None


def _header_pairs(scope: dict) -> tuple[tuple[str, str], ...]:
    values = scope.get("headers")
    if type(values) not in (list, tuple) or len(values) > 64:
        raise VerificationError("INVALID_REQUEST")
    pairs, size = [], 0
    for pair in values:
        if type(pair) not in (list, tuple) or len(pair) != 2 or any(type(v) is not bytes for v in pair):
            raise VerificationError("INVALID_REQUEST")
        size += len(pair[0]) + len(pair[1])
        if size > 16384:
            raise VerificationError("INVALID_REQUEST")
        try:
            pairs.append((pair[0].decode("ascii"), pair[1].decode("ascii")))
        except UnicodeError:
            raise VerificationError("INVALID_REQUEST") from None
    return tuple(pairs)


async def _respond(send, status: int, code: str) -> None:
    body = json.dumps({"code": code}, separators=(",", ":")).encode("ascii")
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
        (b"cache-control", b"no-store"),
    ]})
    await send({"type": "http.response.body", "body": body})


class AppGuardMiddleware:
    def __init__(self, app, *, app_id, origin, identity_resolver, replay, clock=None,
                 allow_insecure_transport=False, raw_target_resolver=None, body_timeout=30.0, identity_timeout=10.0):
        try:
            validate_identifier(app_id)
            _validate_origin(origin)
        except VerificationError:
            raise ValueError("invalid AppGuard app ID or origin") from None
        if (not callable(app) or not callable(identity_resolver) or not callable(getattr(replay, "claim", None))
                or (clock is not None and not callable(clock)) or type(allow_insecure_transport) is not bool
                or (raw_target_resolver is not None and not callable(raw_target_resolver))
                or any(type(t) not in (int, float) or not math.isfinite(t) or t <= 0 for t in (body_timeout, identity_timeout))):
            raise ValueError("invalid AppGuard security dependencies")
        self.app, self.app_id, self.origin = app, app_id, origin
        self.identity_resolver, self.replay = identity_resolver, replay
        self.clock = clock if clock is not None else lambda: int(time.time())
        self.allow_insecure_transport, self.raw_target_resolver = allow_insecure_transport, raw_target_resolver
        self.body_timeout, self.identity_timeout = body_timeout, identity_timeout

    async def _body(self, receive, headers) -> bytes:
        length = int(headers["content-length"]) if "content-length" in headers else None
        if length is not None and length > _LIMIT:
            raise _HttpFailure(413, "INVALID_REQUEST")
        deadline = asyncio.get_running_loop().time() + self.body_timeout
        body = bytearray()
        while True:
            try:
                remaining = deadline - asyncio.get_running_loop().time()
                event = await asyncio.wait_for(receive(), timeout=max(0, remaining))
            except Exception:
                raise _HttpFailure(400, "INVALID_REQUEST") from None
            if (type(event) is not dict or event.get("type") != "http.request"
                    or type(event.get("body", b"")) is not bytes or type(event.get("more_body", False)) is not bool):
                raise _HttpFailure(400, "INVALID_REQUEST")
            part = event.get("body", b"")
            if len(part) > _LIMIT - len(body):
                raise _HttpFailure(413, "INVALID_REQUEST")
            body.extend(part)
            if not event.get("more_body", False):
                break
        if length is not None and length != len(body):
            raise _HttpFailure(400, "INVALID_REQUEST")
        return bytes(body)

    async def _identity(self, scope, key_id):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.identity_timeout

        async def resolve():
            if loop.time() >= deadline:
                raise TimeoutError
            if inspect.iscoroutinefunction(self.identity_resolver):
                value = self.identity_resolver(scope, key_id)
            else:
                value = await asyncio.to_thread(self.identity_resolver, scope, key_id)
            return await value if inspect.isawaitable(value) else value

        task = loop.create_task(resolve())
        _IDENTITY_TASKS.add(task)
        task.add_done_callback(_identity_finished)
        try:
            done, _ = await asyncio.wait({task}, timeout=max(0, deadline - loop.time()))
            if not done or loop.time() >= deadline:
                raise TimeoutError
            identity = task.result()
        except Exception:
            raise _HttpFailure(503, "IDENTITY_UNAVAILABLE") from None
        finally:
            # Do not await cancellation: a host resolver can suppress it.
            if not task.done():
                task.cancel()
        if identity is None:
            raise _HttpFailure(401, "AUTHENTICATION_REQUIRED")
        if not isinstance(identity, Identity):
            raise _HttpFailure(503, "IDENTITY_UNAVAILABLE")
        try:
            validate_identifier(identity.subject)
            if identity.key is not None:
                key = identity.key
                if (not isinstance(key, KeyRecord) or type(key.public_key_pem) is not bytes
                        or type(key.algorithm) is not str or type(key.revoked) is not bool):
                    raise ValueError("invalid trusted key contract")
                for identifier in (key.app_id, key.key_id, key.subject):
                    validate_identifier(identifier)
        except (VerificationError, ValueError):
            raise _HttpFailure(503, "IDENTITY_UNAVAILABLE") from None
        if loop.time() >= deadline:
            raise _HttpFailure(503, "IDENTITY_UNAVAILABLE")
        return identity

    async def __call__(self, scope, receive, send):
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        try:
            if not self.allow_insecure_transport and scope.get("scheme") != "https":
                raise VerificationError("INVALID_REQUEST")
            headers = _header_pairs(scope)
            parsed = parse_signatures(headers)
            target = _target(scope, self.raw_target_resolver)
            body = await self._body(receive, validate_headers(headers))
            identity = await self._identity(scope, parsed.parameters.key_id)
            request = RequestInput(scope.get("method"), target, headers, body)

            def verify():
                return verify_request(request, parsed.parameters, parsed.signature, origin=self.origin,
                                      app_id=self.app_id, subject=identity.subject, key=identity.key,
                                      now=self.clock(), replay=self.replay)

            result = await asyncio.to_thread(verify)
        except _HttpFailure as failure:
            await _respond(send, failure.status, failure.code)
            return
        except VerificationError as failure:
            code = failure.code if failure.code in _CORE_CODES else "VERIFICATION_UNAVAILABLE"
            status = 400 if code == "INVALID_REQUEST" else 503 if code in {"REPLAY_STORE_UNAVAILABLE", "VERIFICATION_UNAVAILABLE"} else 403
            await _respond(send, status, code)
            return
        except Exception:
            await _respond(send, 503, "VERIFICATION_UNAVAILABLE")
            return

        downstream_scope = {**scope, "state": {**scope.get("state", {}), "appguard": result}}
        delivered = False

        async def replay_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(downstream_scope, replay_receive, send)
