"""Public body deadlines bound SDK waiting even if host receive resists cancellation."""

import asyncio
import time

import pytest

from appguard.asgi import AppGuardMiddleware, Identity
from conftest import VECTOR
from test_identity_deadlines import (
    cleanup, counters, dependencies, drain, endpoint, framework_app, http_invoke,
)


def body_counters():
    return dict(identity=0, **counters())


def middleware(api, key, counts, timeout=0.2):
    async def resolve(scope, key_id):
        counts["identity"] += 1
        return Identity(VECTOR["context"]["subject"], key)

    return AppGuardMiddleware(
        api, **dependencies(key, resolve, counts, timeout=1), body_timeout=timeout,
    )


def driver(app, host, sent=None, *, stall_before_read=False):
    """Replace the server receive boundary; preserve the real client's body source."""
    async def wrapped(scope, receive, send):
        async def record(message):
            if sent is not None:
                sent.append(message)
            await send(message)

        if stall_before_read:
            asyncio.get_running_loop().call_soon(time.sleep, 0.08)
        await app(scope, lambda: host(receive), record)
    return wrapped


async def watchdog(request):
    # wait_for would itself wait for cancellation-resistant cleanup.
    done, _ = await asyncio.wait({request}, timeout=1)
    assert request in done, "body middleware waited for cancellation-resistant host cleanup"
    return await request


def assert_invalid(response):
    assert response == (400, b'{"code":"INVALID_REQUEST"}')


def resistant(gate, started, canceled, owned, calls, outcome, *, more_body=False):
    async def receive(original):
        calls.append(True)
        owned.add(asyncio.current_task())
        started.set()
        while not gate.is_set():
            try:
                await gate.wait()
            except asyncio.CancelledError:
                canceled.set()
        if outcome == "exception":
            raise RuntimeError("PRIVATE_BODY_RECEIVE_FAILURE")
        if outcome == "invalid":
            return dict(type="http.request", body="invalid", more_body=False)
        event = await original()
        return {**event, "more_body": more_body}
    return receive


@pytest.mark.parametrize("framework", ["fastapi", "django", "flask"])
@pytest.mark.parametrize("outcome", ["valid", "invalid", "exception"])
def test_resistant_body_cleanup_cannot_hold_framework_response(framework, outcome, headers, body, key):
    async def run():
        gate, started, canceled = asyncio.Event(), asyncio.Event(), asyncio.Event()
        owned, calls, errors, counts = set(), [], [], body_counters()
        loop = asyncio.get_running_loop()
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda loop, context: errors.append(context))
        with framework_app(framework, counts) as api:
            host = resistant(gate, started, canceled, owned, calls, outcome)
            request = asyncio.create_task(http_invoke(headers, body, driver(middleware(api, key, counts), host)))
            try:
                await asyncio.wait_for(started.wait(), 1)
                assert_invalid(await watchdog(request))
                assert not gate.is_set() and counts == body_counters()
                await drain()
                assert canceled.is_set(), "pending body read did not receive best-effort cancellation"
                gate.set()
                # Do not retrieve host exceptions: late exception consumption is SDK-owned.
                await asyncio.wait(owned, timeout=0.3)
                assert all(task.done() for task in owned)
                owned.clear()
                await drain()
                assert calls == [True] and counts == body_counters()
                assert errors == [], "late body exception escaped SDK ownership"
            finally:
                await cleanup(gate, request, owned)
                loop.set_exception_handler(previous)
    asyncio.run(run())


@pytest.mark.parametrize("framework", ["fastapi", "django", "flask"])
def test_caller_cancellation_does_not_wait_for_body_cleanup(framework, headers, body, key):
    async def run():
        gate, started, canceled = asyncio.Event(), asyncio.Event(), asyncio.Event()
        owned, calls, sent, counts = set(), [], [], body_counters()
        with framework_app(framework, counts) as api:
            host = resistant(gate, started, canceled, owned, calls, "valid")
            app = driver(middleware(api, key, counts, timeout=10), host, sent)
            request = asyncio.create_task(http_invoke(headers, body, app))
            try:
                await asyncio.wait_for(started.wait(), 1)
                request.cancel()
                done, _ = await asyncio.wait({request}, timeout=1)
                assert request in done, "caller cancellation waited for resistant body cleanup"
                with pytest.raises(asyncio.CancelledError):
                    await request
                await drain()
                assert canceled.is_set() and not gate.is_set()
                assert sent == [] and counts == body_counters()
                gate.set()
                await asyncio.wait(owned, timeout=0.3)
                assert all(task.done() for task in owned)
                assert calls == [True] and sent == [] and counts == body_counters()
            finally:
                await cleanup(gate, request, owned)
    asyncio.run(run())


@pytest.mark.parametrize("framework", ["fastapi", "django", "flask"])
def test_loop_blocking_body_overrun_is_rejected_before_auth(framework, headers, body, key):
    counts = body_counters()

    async def receive(original):
        time.sleep(0.08)
        # Complete without yielding again: the deadline must be checked even
        # when the host supplies a final event before cancellation can run.
        return dict(type="http.request", body=body, more_body=False)

    with framework_app(framework, counts) as api:
        app = driver(middleware(api, key, counts, timeout=0.01), receive)
        assert_invalid(asyncio.run(http_invoke(headers, body, app)))
    assert counts == body_counters()


def test_expiry_before_read_starts_does_not_invoke_host(headers, body, key):
    calls, counts = [], body_counters()

    async def receive(original):
        calls.append(True)
        return await original()

    app = driver(middleware(endpoint(counts), key, counts, timeout=0.01), receive, stall_before_read=True)
    assert_invalid(asyncio.run(http_invoke(headers, body, app)))
    assert calls == [] and counts == body_counters()


def test_late_second_chunk_cannot_resume_body_capture(headers, body, key):
    async def run():
        gate, started, canceled = asyncio.Event(), asyncio.Event(), asyncio.Event()
        owned, calls, counts = set(), [], body_counters()
        late = resistant(gate, started, canceled, owned, calls, "valid", more_body=True)
        reads = 0

        async def receive(original):
            nonlocal reads
            reads += 1
            if reads == 1:
                return dict(type="http.request", body=b"", more_body=True)
            return await late(original)

        app = driver(middleware(endpoint(counts), key, counts), receive)
        request = asyncio.create_task(http_invoke(headers, body, app))
        try:
            await asyncio.wait_for(started.wait(), 1)
            assert_invalid(await watchdog(request))
            await drain()
            assert canceled.is_set() and not gate.is_set()
            gate.set()
            await asyncio.wait(owned, timeout=0.3)
            assert all(task.done() for task in owned)
            await drain()
            assert reads == 2 and counts == body_counters()
        finally:
            await cleanup(gate, request, owned)
    asyncio.run(run())


@pytest.mark.parametrize("style", ["chunks", "future", "length-mismatch"])
def test_healthy_receive_contracts_and_chunk_framing(style, headers, body, key):
    async def run():
        counts, calls = body_counters(), []
        parts = [body[:1], body[1:]] if style != "future" else [body]

        def receive(original):
            # ASGI permits any awaitable, including a Future returned by a
            # synchronous callable, rather than requiring a coroutine object.
            calls.append(True)
            event = dict(type="http.request", body=parts.pop(0), more_body=bool(parts))
            future = asyncio.get_running_loop().create_future()
            future.set_result(event)
            return future

        request_headers = list(headers)
        if style == "length-mismatch":
            request_headers = [(name, value) for name, value in headers if name.lower() != "content-length"]
            request_headers.append(("Content-Length", str(len(body) + 1)))
        app = driver(middleware(endpoint(counts), key, counts, timeout=1), receive)
        response = await http_invoke(request_headers, body, app)
        if style == "length-mismatch":
            assert_invalid(response)
            assert counts == body_counters()
        else:
            assert response == (200, body)
            assert counts == dict(identity=1, clock=1, replay=1, downstream=1)
        assert len(calls) == (1 if style == "future" else 2)
    asyncio.run(run())
