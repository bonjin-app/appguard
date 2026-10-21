"""Real thread return/cancellation regressions for public identity middleware."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import contextvars
import inspect
import threading
from types import CoroutineType

import pytest

from appguard.asgi import AppGuardMiddleware, Identity
from conftest import VECTOR
from test_identity_deadlines import (
    assert_unavailable, counters, dependencies, endpoint, framework_app,
    http_invoke, invoke, watchdog,
)


async def until(predicate):
    deadline = asyncio.get_running_loop().time() + 1
    while not predicate():
        assert asyncio.get_running_loop().time() < deadline, "bounded condition did not become true"
        await asyncio.sleep(0.001)


class HostAwaitable:
    def __init__(self, identity):
        self.identity, self.awaited, self.closed, self.canceled = identity, False, False, False

    def __await__(self):
        self.awaited = True
        if False:
            yield
        return self.identity

    def close(self):
        self.closed = True

    def cancel(self):
        self.canceled = True


class SpoofedNative(HostAwaitable):
    cr_running, cr_suspended, cr_frame = False, False, object()
    inspected = False

    @property
    def __class__(self):
        self.inspected = True
        return CoroutineType


@pytest.mark.parametrize("framework", ["fastapi", "django", "flask"])
@pytest.mark.parametrize("outcome", ["timeout", "caller-cancel"])
def test_late_native_coroutine_is_closed_without_execution(framework, outcome, headers, body, key):
    async def run():
        gate, started, finished = threading.Event(), threading.Event(), threading.Event()
        counts, values, executed = counters(), [], []

        async def returned():
            executed.append(True)
            return Identity(VECTOR["context"]["subject"], key)

        def resolve(scope, key_id):
            started.set()
            assert gate.wait(2), "test did not release resolver"
            values.append(returned())
            finished.set()
            return values[-1]

        with framework_app(framework, counts) as api:
            app = AppGuardMiddleware(api, **dependencies(
                key, resolve, counts, timeout=0.2 if outcome == "timeout" else 10))
            request = asyncio.create_task(http_invoke(headers, body, app))
            try:
                await until(started.is_set)
                if outcome == "timeout":
                    assert_unavailable(await watchdog(request))
                else:
                    request.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await watchdog(request)
                assert not gate.is_set() and not finished.is_set()
                assert counts == counters()
                gate.set()
                await until(finished.is_set)
                await until(lambda: inspect.getcoroutinestate(values[0]) == inspect.CORO_CLOSED)
                assert executed == [] and counts == counters()
            finally:
                gate.set()
                await asyncio.gather(request, return_exceptions=True)
                await until(finished.is_set)
                for value in values:
                    value.close()  # Silence baseline leak warnings after assertions.
    asyncio.run(run())


@pytest.mark.parametrize("handoff", ["cancel-queued-before-return", "worker-done-before-delivery"])
def test_native_coroutine_cancellation_handoff_is_closed(handoff, headers, body, key):
    class ObservedExecutor(ThreadPoolExecutor):
        def __init__(self):
            super().__init__(max_workers=1)
            self.completed = threading.Event()

        def submit(self, fn, /, *args, **kwargs):
            future = super().submit(fn, *args, **kwargs)
            future.add_done_callback(lambda future: self.completed.set())
            return future

    async def run():
        loop = asyncio.get_running_loop()
        executor = ObservedExecutor()
        loop.set_default_executor(executor)
        counts, values, executed, callback_failures = counters(), [], [], []

        async def returned():
            executed.append(True)
            return Identity(VECTOR["context"]["subject"], key)

        def cancel_before_delivery():
            if handoff == "worker-done-before-delivery" and not executor.completed.wait(1):
                callback_failures.append("worker did not finish before delivery")
            request.cancel()

        def resolve(scope, key_id):
            values.append(returned())
            # Queued before returning: delivery of the thread result must follow
            # this callback. The second ordering additionally proves worker done.
            loop.call_soon_threadsafe(cancel_before_delivery)
            return values[-1]

        app = AppGuardMiddleware(endpoint(counts), **dependencies(key, resolve, counts, timeout=0.2))
        request = asyncio.create_task(invoke(headers, body, app))
        try:
            with pytest.raises(asyncio.CancelledError):
                await watchdog(request)
            assert callback_failures == []
            await until(executor.completed.is_set)
            await until(lambda: inspect.getcoroutinestate(values[0]) == inspect.CORO_CLOSED)
            assert executed == [] and counts == counters()
        finally:
            await asyncio.gather(request, return_exceptions=True)
            executor.shutdown(wait=True)
            for value in values:
                value.close()
    asyncio.run(run())


@pytest.mark.parametrize("kind", ["native-coroutine", "future", "custom-awaitable"])
def test_healthy_thread_return_keeps_awaitable_and_context(kind, headers, body, key):
    marker = contextvars.ContextVar("identity_cleanup_marker")

    async def run():
        marker.set("request-context")
        loop = asyncio.get_running_loop()
        identity = Identity(VECTOR["context"]["subject"], key)
        counts, seen = counters(), []
        future = loop.create_future()
        future.set_result(identity)
        custom = HostAwaitable(identity)

        async def returned():
            seen.append(marker.get())
            await asyncio.sleep(0)
            return identity

        def resolve(scope, key_id):
            seen.append(marker.get())
            return returned() if kind == "native-coroutine" else future if kind == "future" else custom

        app = AppGuardMiddleware(endpoint(counts), **dependencies(key, resolve, counts, timeout=1))
        assert await watchdog(asyncio.create_task(invoke(headers, body, app))) == (200, body)
        assert seen == ["request-context"] * (2 if kind == "native-coroutine" else 1)
        assert counts == dict(clock=1, replay=1, downstream=1)
        assert not future.cancelled() and not custom.closed and not custom.canceled
        assert custom.awaited == (kind == "custom-awaitable")
    asyncio.run(run())


@pytest.mark.parametrize("kind", ["future", "task", "custom-awaitable", "spoofed-native", "started-native-coroutine"])
def test_late_host_owned_values_are_untouched(kind, headers, body, key):
    async def run():
        loop = asyncio.get_running_loop()
        gate, started, finished = threading.Event(), threading.Event(), threading.Event()
        executor = ThreadPoolExecutor(max_workers=1)
        loop.set_default_executor(executor)
        counts, values, executed = counters(), [], []
        identity = Identity(VECTOR["context"]["subject"], key)
        host_gate = asyncio.Event()

        async def host_task():
            await host_gate.wait()
            return identity

        async def started_native():
            executed.append("host-started")
            await asyncio.sleep(0)
            executed.append("unexpected-resume")
            return identity

        future = loop.create_future()
        task = asyncio.create_task(host_task())
        custom = SpoofedNative(identity) if kind == "spoofed-native" else HostAwaitable(identity)
        native = started_native()
        native.send(None)
        value = dict(future=future, task=task, **{"custom-awaitable": custom, "spoofed-native": custom,
                     "started-native-coroutine": native})[kind]

        def resolve(scope, key_id):
            started.set()
            assert gate.wait(2), "test did not release resolver"
            values.append(value)
            finished.set()
            return value

        app = AppGuardMiddleware(endpoint(counts), **dependencies(key, resolve, counts, timeout=0.2))
        request = asyncio.create_task(invoke(headers, body, app))
        try:
            await until(started.is_set)
            assert_unavailable(await watchdog(request))
            gate.set()
            await until(finished.is_set)
            # Join only after releasing the worker: all result-delivery callbacks
            # are then queued before the loop barriers and ownership assertions.
            executor.shutdown(wait=True)
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            assert counts == counters() and executed == ["host-started"]
            assert not future.done() and not task.done()
            assert not custom.awaited and not custom.closed and not custom.canceled
            if kind == "spoofed-native":
                assert not custom.inspected
            assert inspect.getcoroutinestate(native) == inspect.CORO_SUSPENDED
        finally:
            gate.set()
            await asyncio.gather(request, return_exceptions=True)
            await until(finished.is_set)
            executor.shutdown(wait=True)
            native.close()
            future.cancel()
            host_gate.set()
            await task
    asyncio.run(run())


def test_late_native_coroutine_is_closed_after_request_loop_closes(headers, body, key):
    loop = asyncio.new_event_loop()
    executor = ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(executor)
    gate, started = threading.Event(), threading.Event()
    counts, values, executed = counters(), [], []

    async def returned():
        executed.append(True)
        return Identity(VECTOR["context"]["subject"], key)

    def resolve(scope, key_id):
        started.set()
        assert gate.wait(2), "test did not release resolver"
        values.append(returned())
        return values[-1]

    async def request_until_timeout():
        app = AppGuardMiddleware(endpoint(counts), **dependencies(key, resolve, counts, timeout=0.2))
        request = asyncio.create_task(invoke(headers, body, app))
        try:
            await until(started.is_set)
            assert_unavailable(await watchdog(request))
            assert not gate.is_set() and counts == counters()
            # Deliver best-effort resolver cancellation before closing its loop.
            await asyncio.sleep(0)
            await asyncio.sleep(0)
        finally:
            await asyncio.gather(request, return_exceptions=True)

    try:
        loop.run_until_complete(request_until_timeout())
        loop.close()
        gate.set()
        # Observe after the real worker fully returned with no live event loop.
        executor.shutdown(wait=True)
        assert len(values) == 1
        assert inspect.getcoroutinestate(values[0]) == inspect.CORO_CLOSED
        assert executed == [] and counts == counters()
    finally:
        gate.set()
        executor.shutdown(wait=True)
        if not loop.is_closed():
            loop.close()
        for value in values:
            value.close()
