import asyncio
import json
from dataclasses import replace

import httpx
import pytest

from appguard.asgi import AppGuardMiddleware, Identity
from appguard.replay import InMemoryReplayStore
from conftest import NOW, ORIGIN, VECTOR


def options(key, **changes):
    result = dict(app_id="test-app", origin=ORIGIN, identity_resolver=lambda scope, kid: Identity("test-user", key),
                  replay=InMemoryReplayStore(), clock=lambda: NOW)
    result.update(changes)
    return result


async def invoke(headers, app, events=None, scope_changes=None):
    target = VECTOR["request"]["target"].encode()
    path, _, query = target.partition(b"?")
    scope = dict(type="http", asgi={"version": "3.0"}, http_version="1.1", method="POST", scheme="https",
                 path=path.decode(), raw_path=path, query_string=query, headers=[(k.lower().encode(), v.encode()) for k, v in headers])
    scope.update(scope_changes or {})
    queue = list(events if events is not None else [dict(type="http.request", body=b"{}", more_body=False)])
    sent = []

    async def receive():
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    return start["status"], b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


async def echo(scope, receive, send):
    event = await receive()
    assert scope["state"]["appguard"].code == "VERIFIED"
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": event["body"]})


def test_valid_body_replayed_and_repeat_blocked(headers, key):
    app = AppGuardMiddleware(echo, **options(key))
    assert asyncio.run(invoke(headers, app)) == (200, b"{}")
    assert asyncio.run(invoke(headers, app)) == (403, b'{"code":"REPLAY_DETECTED"}')


def test_chunked_body_is_bound_and_replayed(headers, key):
    events = [dict(type="http.request", body=b"{", more_body=True), dict(type="http.request", body=b"}", more_body=False)]
    assert asyncio.run(invoke(headers + [["Transfer-Encoding", "chunked"]], AppGuardMiddleware(echo, **options(key)), events)) == (200, b"{}")


@pytest.mark.parametrize("change,expected", [
    ({"scheme": "http"}, (400, "INVALID_REQUEST")),
    ({"raw_path": None}, (400, "INVALID_REQUEST")),
    ({"query_string": b""}, (400, "INVALID_REQUEST")),
    ({"raw_path": b"/v1/items?a=1"}, (400, "INVALID_REQUEST")),
    ({"query_string": b"a=1&b=2"}, (403, "INVALID_SIGNATURE")),
])
def test_capture_and_transport_fail_closed(headers, key, change, expected):
    status, raw = asyncio.run(invoke(headers, AppGuardMiddleware(echo, **options(key)), scope_changes=change))
    assert (status, json.loads(raw)["code"]) == expected


def test_forwarded_does_not_supply_transport_security(headers, key):
    status, raw = asyncio.run(invoke(headers + [["X-Forwarded-Proto", "https"]],
                                    AppGuardMiddleware(echo, **options(key)), scope_changes={"scheme": "http"}))
    assert (status, json.loads(raw)["code"]) == (400, "INVALID_REQUEST")


def test_explicit_local_insecure_transport(headers, key):
    app = AppGuardMiddleware(echo, **options(key, allow_insecure_transport=True))
    assert asyncio.run(invoke(headers, app, scope_changes={"scheme": "http"})) == (200, b"{}")


@pytest.mark.parametrize("identity,expected", [(None, (401, "AUTHENTICATION_REQUIRED")),
                                               ({"subject": "test-user"}, (503, "IDENTITY_UNAVAILABLE"))])
def test_identity_contract(headers, key, identity, expected):
    app = AppGuardMiddleware(echo, **options(key, identity_resolver=lambda scope, kid: identity))
    status, raw = asyncio.run(invoke(headers, app))
    assert (status, json.loads(raw)["code"]) == expected


def test_async_identity_failure_is_redacted(headers, key):
    async def broken(scope, kid):
        raise RuntimeError("TEST_ONLY_TOKEN BACKEND_SECRET")

    status, raw = asyncio.run(invoke(headers, AppGuardMiddleware(echo, **options(key, identity_resolver=broken))))
    assert status == 503 and json.loads(raw) == {"code": "IDENTITY_UNAVAILABLE"}
    assert b"SECRET" not in raw and b"TOKEN" not in raw


def test_async_identity_is_supported(headers, key):
    async def resolve(scope, kid):
        await asyncio.sleep(0)
        assert kid == "test-key"
        return Identity("test-user", key)

    assert asyncio.run(invoke(headers, AppGuardMiddleware(echo, **options(key, identity_resolver=resolve)))) == (200, b"{}")


@pytest.mark.parametrize("events", [
    [dict(type="http.disconnect")],
    [dict(type="http.request", body="not bytes", more_body=False)],
    [dict(type="http.request", body=b"{", more_body=True), dict(type="http.disconnect")],
    [dict(type="http.request", body=b"{}", more_body="false")],
])
def test_invalid_and_aborted_streams(headers, key, events):
    status, raw = asyncio.run(invoke(headers, AppGuardMiddleware(echo, **options(key)), events))
    assert (status, json.loads(raw)["code"]) == (400, "INVALID_REQUEST")


@pytest.mark.parametrize("extra_header,events,expected", [
    (["Content-Length", "3"], [dict(type="http.request", body=b"{}", more_body=False)], (400, "INVALID_REQUEST")),
    (["Content-Length", "1048577"], [], (413, "INVALID_REQUEST")),
    (["Transfer-Encoding", "chunked"], [dict(type="http.request", body=b"x" * 1048577, more_body=False)], (413, "INVALID_REQUEST")),
])
def test_body_length_limits(headers, key, extra_header, events, expected):
    status, raw = asyncio.run(invoke(headers + [extra_header], AppGuardMiddleware(echo, **options(key)), events))
    assert (status, json.loads(raw)["code"]) == expected


def test_duplicate_metadata_never_reaches_auth(headers, key):
    def must_not_auth(*args):
        raise AssertionError("must not authenticate malformed request")

    app = AppGuardMiddleware(echo, **options(key, identity_resolver=must_not_auth))
    status, raw = asyncio.run(invoke(headers + [headers[-1]], app))
    assert (status, json.loads(raw)["code"]) == (400, "INVALID_REQUEST")


def test_store_failure_is_redacted(headers, key):
    class Broken:
        def claim(self, *args, **kwargs):
            raise RuntimeError("TEST_ONLY_TOKEN")

    app = AppGuardMiddleware(echo, **options(key, replay=Broken()))
    assert asyncio.run(invoke(headers, app)) == (503, b'{"code":"REPLAY_STORE_UNAVAILABLE"}')


def test_trusted_clock_checked_after_authentication(headers, key):
    clock = [NOW]

    async def slow_identity(scope, kid):
        clock[0] = NOW + 120
        return Identity("test-user", key)

    app = AppGuardMiddleware(echo, **options(key, identity_resolver=slow_identity, clock=lambda: clock[0]))
    assert asyncio.run(invoke(headers, app)) == (403, b'{"code":"INVALID_TIME"}')


def test_fastapi_real_request_and_body_echo(headers, key):
    from fastapi import FastAPI, Request, Response

    api = FastAPI()

    @api.post("/v1/items")
    async def endpoint(request: Request):
        assert request.state.appguard.code == "VERIFIED"
        return Response(await request.body(), media_type="application/json")

    app = AppGuardMiddleware(api, **options(key))

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
            good = await client.post(VECTOR["request"]["target"], headers=headers, content=b"{}")
            bad = await client.post(VECTOR["request"]["target"], headers=headers, content=b"changed")
            return good, bad

    good, bad = asyncio.run(run())
    assert (good.status_code, good.content) == (200, b"{}")
    assert (bad.status_code, bad.json()["code"]) == (403, "DIGEST_MISMATCH")


def test_django_asgi_real_request(headers, key):
    import django
    from django.conf import settings
    from django.core.asgi import get_asgi_application
    from django.http import HttpResponse
    from django.urls import path

    if not settings.configured:
        settings.configure(SECRET_KEY="TEST_ONLY_DJANGO_KEY", ROOT_URLCONF=__name__, ALLOWED_HOSTS=["api.example.test"],
                           INSTALLED_APPS=[], MIDDLEWARE=[])
    django.setup()

    def view(request):
        return HttpResponse(request.body, content_type="application/json")

    globals()["urlpatterns"] = [path("v1/items", view)]
    app = AppGuardMiddleware(get_asgi_application(), **options(key))

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
            return await client.post(VECTOR["request"]["target"], headers=headers, content=b"{}")

    result = asyncio.run(run())
    assert (result.status_code, result.content) == (200, b"{}")


def test_flask_asgi_real_request(headers, key):
    from flask import Flask, request, Response
    from appguard.flask import protect_flask

    api = Flask(__name__)

    @api.post("/v1/items")
    def endpoint():
        return Response(request.get_data(), content_type="application/json")

    app = protect_flask(api, **options(key))

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
            return await client.post(VECTOR["request"]["target"], headers=headers, content=b"{}")

    result = asyncio.run(run())
    assert (result.status_code, result.content) == (200, b"{}")


@pytest.mark.parametrize("target", ["/v1/items", "/v1/items?"])
def test_exact_target_extension_preserves_empty_query_distinction(target, signed_case):
    headers, key = signed_case(target)
    changes = {"query_string": b"", "appguard.raw_target": target.encode()}
    assert asyncio.run(invoke(headers, AppGuardMiddleware(echo, **options(key)), scope_changes=changes)) == (200, b"{}")


def test_captured_target_cannot_disagree_with_scope(headers, key):
    app = AppGuardMiddleware(echo, **options(key))
    status, raw = asyncio.run(invoke(headers, app, scope_changes={"appguard.raw_target": b"/other?b=2&a=1"}))
    assert (status, json.loads(raw)["code"]) == (400, "INVALID_REQUEST")


def test_raw_target_callback_is_explicit_capture(headers, key):
    app = AppGuardMiddleware(echo, **options(key, raw_target_resolver=lambda scope: VECTOR["request"]["target"].encode()))
    assert asyncio.run(invoke(headers, app)) == (200, b"{}")


def test_exact_body_size_limit_is_accepted(signed_case):
    body = b"x" * 1048576
    headers, key = signed_case(VECTOR["request"]["target"], body)
    events = [dict(type="http.request", body=body, more_body=False)]
    assert asyncio.run(invoke(headers, AppGuardMiddleware(echo, **options(key)), events)) == (200, body)


def test_body_timeout_never_calls_downstream(headers, key):
    async def run():
        sent = []

        async def receive():
            await asyncio.Event().wait()

        async def send(message):
            sent.append(message)

        path, _, query = VECTOR["request"]["target"].encode().partition(b"?")
        scope = dict(type="http", scheme="https", method="POST", raw_path=path, query_string=query,
                     headers=[(k.encode(), v.encode()) for k, v in headers])
        await AppGuardMiddleware(echo, **options(key, body_timeout=0.01))(scope, receive, send)
        return sent

    messages = asyncio.run(run())
    assert messages[0]["status"] == 400


def test_identity_timeout_fails_closed(headers, key):
    async def hung(scope, kid):
        await asyncio.Event().wait()

    app = AppGuardMiddleware(echo, **options(key, identity_resolver=hung, identity_timeout=0.01))
    assert asyncio.run(invoke(headers, app)) == (503, b'{"code":"IDENTITY_UNAVAILABLE"}')


def test_existing_authentication_state_is_preserved(headers, key):
    async def endpoint(scope, receive, send):
        assert scope["state"]["existing_user"] == "server-authenticated"
        await echo(scope, receive, send)

    app = AppGuardMiddleware(endpoint, **options(key))
    assert asyncio.run(invoke(headers, app, scope_changes={"state": {"existing_user": "server-authenticated"}})) == (200, b"{}")


def test_clock_failure_is_not_returned_to_client(headers, key):
    def clock():
        raise RuntimeError("TEST_ONLY_TOKEN")

    app = AppGuardMiddleware(echo, **options(key, clock=clock))
    assert asyncio.run(invoke(headers, app)) == (503, b'{"code":"VERIFICATION_UNAVAILABLE"}')


@pytest.mark.parametrize("changed", [dict(allow_insecure_transport="false"), dict(replay=None),
                                     dict(identity_resolver=None), dict(origin="http://evil.test"),
                                     dict(body_timeout=0), dict(body_timeout=float("inf"))])
def test_invalid_security_configuration_is_rejected(key, changed):
    with pytest.raises(ValueError):
        AppGuardMiddleware(echo, **options(key, **changed))


def framework_app(name, reached):
    if name == "fastapi":
        from fastapi import FastAPI, Request, Response
        api = FastAPI()

        @api.post("/v1/items")
        async def endpoint(request: Request):
            reached.append(True)
            return Response(await request.body())

        return api
    if name == "django":
        import django
        from django.conf import settings
        from django.core.asgi import get_asgi_application
        from django.http import HttpResponse
        from django.urls import clear_url_caches, path
        if not settings.configured:
            settings.configure(SECRET_KEY="TEST_ONLY_DJANGO_KEY", ROOT_URLCONF=__name__, ALLOWED_HOSTS=["api.example.test"],
                               INSTALLED_APPS=[], MIDDLEWARE=[])
        django.setup()

        def endpoint(request):
            reached.append(True)
            return HttpResponse(request.body)

        globals()["urlpatterns"] = [path("v1/items", endpoint)]
        clear_url_caches()
        return get_asgi_application()
    from flask import Flask, request, Response
    from asgiref.wsgi import WsgiToAsgi
    api = Flask(__name__)

    @api.post("/v1/items")
    def endpoint():
        reached.append(True)
        return Response(request.get_data())

    return WsgiToAsgi(api)


@pytest.mark.parametrize("framework", ["fastapi", "django", "flask"])
def test_each_real_framework_rejects_before_endpoint(framework, headers, key):
    reached = []

    def authenticate(scope, kid):
        token = next((v for k, v in scope["headers"] if k.lower() == b"authorization"), b"")
        return Identity("test-user", key) if token == b"Bearer TEST_ONLY_TOKEN" else None

    app = AppGuardMiddleware(framework_app(framework, reached), **options(key, identity_resolver=authenticate))

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
            target = VECTOR["request"]["target"]
            good = await client.post(target, headers=headers, content=b"{}")
            replay = await client.post(target, headers=headers, content=b"{}")
            tampered = await client.post(target, headers=headers, content=b"changed")
            missing = await client.post(target, headers=headers[:-1], content=b"{}")
            duplicate = await client.post(target, headers=headers + [headers[-1]], content=b"{}")
            bad_token = [(k, "Bearer OTHER" if k.lower() == "authorization" else v) for k, v in headers]
            unauthenticated = await client.post(target, headers=bad_token, content=b"{}")
            oversized = await client.post(target, headers=headers, content=b"x" * 1048577)
            insecure = await client.post("http://api.example.test" + target, headers=headers, content=b"{}")
            return good, replay, tampered, missing, duplicate, unauthenticated, oversized, insecure

    results = asyncio.run(run())
    assert (results[0].status_code, results[0].content) == (200, b"{}")
    assert [(r.status_code, r.json()["code"]) for r in results[1:]] == [
        (403, "REPLAY_DETECTED"), (403, "DIGEST_MISMATCH"), (400, "INVALID_REQUEST"),
        (400, "INVALID_REQUEST"), (401, "AUTHENTICATION_REQUIRED"), (413, "INVALID_REQUEST"), (400, "INVALID_REQUEST"),
    ]
    assert reached == [True]


def test_unknown_key_is_expected_rejection(headers, key):
    app = AppGuardMiddleware(echo, **options(key, identity_resolver=lambda scope, kid: Identity("test-user", None)))
    assert asyncio.run(invoke(headers, app)) == (403, b'{"code":"KEY_REJECTED"}')


@pytest.mark.parametrize("identity_factory", [lambda key: Identity(None, key),
                                             lambda key: Identity("test-user", object()),
                                             lambda key: Identity("test-user", replace(key, public_key_pem=None))])
def test_malformed_identity_contract_is_dependency_failure(headers, key, identity_factory):
    app = AppGuardMiddleware(echo, **options(key, identity_resolver=lambda scope, kid: identity_factory(key)))
    assert asyncio.run(invoke(headers, app)) == (503, b'{"code":"IDENTITY_UNAVAILABLE"}')
