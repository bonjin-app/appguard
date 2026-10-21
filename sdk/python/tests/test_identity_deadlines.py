"""Public ASGI identity deadline regressions, including resistant host cleanup."""

import asyncio
from contextlib import contextmanager
import gc
import threading
import time
from types import ModuleType

import httpx
import pytest

from appguard.asgi import AppGuardMiddleware, Identity
from appguard.replay import InMemoryReplayStore
from conftest import NOW, ORIGIN, VECTOR


def dependencies(key, resolver, counts, timeout=0.01):
    store = InMemoryReplayStore()

    class Replay:
        def claim(self, *args, **kwargs):
            counts["replay"] += 1
            return store.claim(*args, **kwargs)

    def clock():
        counts["clock"] += 1
        return NOW

    return dict(app_id=VECTOR["context"]["app_id"], origin=ORIGIN,
                identity_resolver=resolver, replay=Replay(), clock=clock,
                identity_timeout=timeout)


def counters():
    return dict(clock=0, replay=0, downstream=0)


async def invoke(headers, body, app, sent=None):
    """Self-contained ASGI harness; no dependency on another test module."""
    path, _, query = VECTOR["request"]["target"].encode().partition(b"?")
    scope = dict(type="http", asgi={"version": "3.0"}, http_version="1.1",
                 method=VECTOR["request"]["method"], scheme="https", path=path.decode(),
                 raw_path=path, query_string=query,
                 headers=[(k.lower().encode(), v.encode()) for k, v in headers])
    messages = [] if sent is None else sent
    delivered = False

    async def receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return dict(type="http.request", body=body, more_body=False)
        return dict(type="http.disconnect")

    async def send(message):
        messages.append(message)

    await app(scope, receive, send)
    status = next(message["status"] for message in messages if message["type"] == "http.response.start")
    content = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
    return status, content


def endpoint(counts):
    async def app(scope, receive, send):
        counts["downstream"] += 1
        assert scope["state"]["appguard"].code == "VERIFIED"
        event = await receive()
        await send(dict(type="http.response.start", status=200, headers=[]))
        await send(dict(type="http.response.body", body=event["body"]))
    return app


@contextmanager
def framework_app(name, counts):
    if name == "fastapi":
        from fastapi import FastAPI, Request, Response
        api = FastAPI()

        @api.post("/v1/items")
        async def view(request: Request):
            counts["downstream"] += 1
            return Response(await request.body())

        yield api
    elif name == "django":
        import django
        from django.conf import settings
        from django.core.asgi import get_asgi_application
        from django.http import HttpResponse
        from django.test import override_settings
        from django.urls import path

        if not settings.configured:
            settings.configure(SECRET_KEY="TEST_ONLY_DEADLINE_KEY", ALLOWED_HOSTS=["api.example.test"],
                               INSTALLED_APPS=[], MIDDLEWARE=[])
        django.setup()

        def view(request):
            counts["downstream"] += 1
            return HttpResponse(request.body)

        urls = ModuleType("identity_deadline_test_urls")
        urls.urlpatterns = [path("v1/items", view)]
        with override_settings(ROOT_URLCONF=urls):
            yield get_asgi_application()
    else:
        from flask import Flask, request, Response
        from asgiref.wsgi import WsgiToAsgi
        api = Flask(__name__)

        @api.post("/v1/items")
        def view():
            counts["downstream"] += 1
            return Response(request.get_data())

        yield WsgiToAsgi(api)


async def http_invoke(headers, body, app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
        response = await client.post(VECTOR["request"]["target"], headers=headers, content=body)
        return response.status_code, response.content


async def watchdog(task):
    # wait_for itself waits for cancellation cleanup, exactly the bug under test.
    done, _ = await asyncio.wait({task}, timeout=0.3)
    assert task in done, "identity middleware waited for cancellation-resistant host cleanup"
    return await task


async def drain():
    for _ in range(5):
        await asyncio.sleep(0)
    gc.collect()
    await asyncio.sleep(0)


async def cleanup(gate, request, owned):
    gate.set()
    await asyncio.gather(request, *owned, return_exceptions=True)
    await drain()


def resistant(gate, started, canceled, owned, key, outcome):
    async def resolve(scope, key_id):
        owned.add(asyncio.current_task())
        started.set()
        while not gate.is_set():
            try:
                await gate.wait()
            except asyncio.CancelledError:
                canceled.set()
        if outcome == "reject":
            raise RuntimeError("PRIVATE_IDENTITY_BACKEND_FAILURE")
        return Identity(VECTOR["context"]["subject"], key) if outcome == "identity" else None
    return resolve


def assert_unavailable(response):
    assert response == (503, b'{"code":"IDENTITY_UNAVAILABLE"}')


@pytest.mark.parametrize("framework", ["fastapi", "django", "flask"])
@pytest.mark.parametrize("outcome", ["identity", "none", "reject"])
def test_resistant_cleanup_cannot_hold_framework_response(framework, outcome, headers, body, key):
    async def run():
        gate, started, canceled = asyncio.Event(), asyncio.Event(), asyncio.Event()
        owned, errors, counts = set(), [], counters()
        loop = asyncio.get_running_loop()
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda loop, context: errors.append(context))
        with framework_app(framework, counts) as api:
            resolver = resistant(gate, started, canceled, owned, key, outcome)
            app = AppGuardMiddleware(api, **dependencies(key, resolver, counts))
            request = asyncio.create_task(http_invoke(headers, body, app))
            try:
                response = await watchdog(request)
                assert started.is_set() and not gate.is_set()
                assert_unavailable(response)
                assert counts == counters()
                await drain()
                assert canceled.is_set(), "owned resolver did not receive best-effort cancellation"
                gate.set()
                # Waiting must not retrieve its exception: the SDK owns that duty.
                await asyncio.wait(owned, timeout=0.3)
                assert all(task.done() for task in owned)
                owned.clear()
                await drain()
                assert counts == counters()
                assert errors == [], "late host exception was not consumed"
            finally:
                await cleanup(gate, request, owned)
                loop.set_exception_handler(previous)
    asyncio.run(run())


@pytest.mark.parametrize("outcome", ["identity", "none", "reject"])
def test_late_resistant_outcome_does_not_replace_expired_failure(outcome, headers, body, key):
    async def run():
        gate, started, canceled = asyncio.Event(), asyncio.Event(), asyncio.Event()
        owned, counts = set(), counters()
        resolver = resistant(gate, started, canceled, owned, key, outcome)
        app = AppGuardMiddleware(endpoint(counts), **dependencies(key, resolver, counts))
        request = asyncio.create_task(invoke(headers, body, app))
        release = asyncio.get_running_loop().call_later(0.06, gate.set)
        try:
            assert_unavailable(await watchdog(request))
            await asyncio.gather(*owned, return_exceptions=True)
            assert counts == counters()
        finally:
            release.cancel()
            await cleanup(gate, request, owned)
    asyncio.run(run())


@pytest.mark.parametrize("framework", ["fastapi", "django", "flask"])
def test_async_resolver_loop_overrun_is_rejected_when_control_returns(framework, headers, body, key):
    async def resolve(scope, key_id):
        time.sleep(0.08)
        return Identity(VECTOR["context"]["subject"], key)

    counts = counters()
    with framework_app(framework, counts) as api:
        app = AppGuardMiddleware(api, **dependencies(key, resolve, counts))
        assert_unavailable(asyncio.run(http_invoke(headers, body, app)))
    assert counts == counters()


@pytest.mark.parametrize("outcome", ["identity", "none", "reject"])
def test_caller_cancellation_propagates_before_resistant_cleanup(outcome, headers, body, key):
    async def run():
        gate, started, canceled = asyncio.Event(), asyncio.Event(), asyncio.Event()
        owned, counts, sent, errors = set(), counters(), [], []
        loop = asyncio.get_running_loop()
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda loop, context: errors.append(context))
        resolver = resistant(gate, started, canceled, owned, key, outcome)
        app = AppGuardMiddleware(endpoint(counts), **dependencies(key, resolver, counts, timeout=10))
        request = asyncio.create_task(invoke(headers, body, app, sent))
        try:
            await asyncio.wait_for(started.wait(), 0.3)
            request.cancel()
            done, _ = await asyncio.wait({request}, timeout=0.3)
            assert request in done, "caller cancellation waited for resistant resolver cleanup"
            with pytest.raises(asyncio.CancelledError):
                await request
            assert not gate.is_set()
            assert sent == [] and counts == counters()
            gate.set()
            await asyncio.wait(owned, timeout=0.3)
            assert all(task.done() for task in owned)
            owned.clear()
            await drain()
            assert sent == [] and counts == counters()
            assert errors == [], "late canceled-request host exception was not consumed"
        finally:
            await cleanup(gate, request, owned)
            loop.set_exception_handler(previous)
    asyncio.run(run())


def test_sync_resolver_thread_can_finish_after_timeout_without_verification(headers, body, key):
    async def run():
        gate, started, finished = threading.Event(), threading.Event(), threading.Event()
        counts = counters()

        def resolve(scope, key_id):
            started.set()
            gate.wait(2)
            finished.set()
            return Identity(VECTOR["context"]["subject"], key)

        app = AppGuardMiddleware(endpoint(counts), **dependencies(key, resolve, counts))
        request = asyncio.create_task(invoke(headers, body, app))
        try:
            assert_unavailable(await watchdog(request))
            assert started.is_set() and not finished.is_set()
            assert counts == counters()
            gate.set()
            assert await asyncio.to_thread(finished.wait, 0.3)
            await drain()
            assert counts == counters()
        finally:
            gate.set()
            await asyncio.gather(request, return_exceptions=True)
    asyncio.run(run())


@pytest.mark.parametrize("framework", ["fastapi", "django", "flask"])
def test_timed_out_identity_does_not_block_an_independent_request(framework, headers, body, key):
    async def run():
        gate, started, canceled = asyncio.Event(), asyncio.Event(), asyncio.Event()
        owned, counts, calls = set(), counters(), 0
        first = resistant(gate, started, canceled, owned, key, "identity")

        async def resolve(scope, key_id):
            nonlocal calls
            calls += 1
            if calls == 1:
                return await first(scope, key_id)
            return Identity(VECTOR["context"]["subject"], key)

        with framework_app(framework, counts) as api:
            app = AppGuardMiddleware(api, **dependencies(key, resolve, counts, timeout=0.03))
            request = asyncio.create_task(http_invoke(headers, body, app))
            try:
                await asyncio.wait_for(started.wait(), 0.3)
                second = asyncio.create_task(http_invoke(headers, body, app))
                assert await watchdog(second) == (200, body)
                assert_unavailable(await watchdog(request))
                gate.set()
                await asyncio.gather(*owned, return_exceptions=True)
                await drain()
                assert counts == dict(clock=1, replay=1, downstream=1)
            finally:
                await cleanup(gate, request, owned)
    asyncio.run(run())


@pytest.mark.parametrize("style", ["sync", "async", "returned-awaitable"])
def test_successful_resolver_forms_keep_clock_and_nonce_after_auth(style, headers, body, key):
    authenticated, counts = [], counters()

    async def async_resolve(scope, key_id):
        await asyncio.sleep(0)
        authenticated.append(True)
        return Identity(VECTOR["context"]["subject"], key)

    def sync_resolve(scope, key_id):
        authenticated.append(True)
        return Identity(VECTOR["context"]["subject"], key)

    resolver = sync_resolve if style == "sync" else async_resolve if style == "async" else lambda scope, kid: async_resolve(scope, kid)
    options = dependencies(key, resolver, counts, timeout=1)
    clock = options["clock"]

    def after_auth():
        assert authenticated
        return clock()

    options["clock"] = after_auth
    app = AppGuardMiddleware(endpoint(counts), **options)
    assert asyncio.run(invoke(headers, body, app)) == (200, body)
    assert counts == dict(clock=1, replay=1, downstream=1)


@pytest.mark.parametrize("field", ["subject", "key"])
def test_trusted_identity_normalization_shares_total_deadline(field, headers, body, key):
    class SlowIdentity(Identity):
        def __getattribute__(self, name):
            if name == field:
                time.sleep(0.08)
            return super().__getattribute__(name)

    async def resolve(scope, key_id):
        return SlowIdentity(VECTOR["context"]["subject"], key)

    counts = counters()
    app = AppGuardMiddleware(endpoint(counts), **dependencies(key, resolve, counts))
    assert_unavailable(asyncio.run(invoke(headers, body, app)))
    assert counts == counters()
