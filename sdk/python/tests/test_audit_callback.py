"""A synchronous audit call must not silently discard asynchronous delivery."""
import asyncio
from functools import partial
import gc
import inspect
import json
import types
import warnings

import pytest

from appguard.audit import AuditUnavailable, JsonAuditSink
from appguard.policy import PolicyDecision

DECISION = PolicyDecision("allow", "ALLOWED", "basic")


def emit(callback):
    JsonAuditSink(callback).emit(DECISION, event_id="event-1", app_id="test-app", now=100)


def unavailable(callback):
    with pytest.raises(AuditUnavailable, match="^AUDIT_UNAVAILABLE$") as caught:
        emit(callback)
    assert caught.value.code == "AUDIT_UNAVAILABLE"
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert caught.value.args == ("AUDIT_UNAVAILABLE",)


@pytest.mark.parametrize("shape", ["function", "partial", "callable_object", "sync_wrapper"])
def test_async_callback_cannot_report_delivery_without_running(shape):
    written, created = [], []

    async def write(line):
        written.append(line)

    class Writer:
        async def __call__(self, line):
            written.append(line)

    def wrapper(line):
        value = write(line)
        created.append(value)
        return value

    callback = {"function": write, "partial": partial(write), "callable_object": Writer(), "sync_wrapper": wrapper}[shape]
    try:
        with warnings.catch_warnings(record=True) as emitted:
            warnings.simplefilter("always", RuntimeWarning)
            unavailable(callback)
            gc.collect()
        assert written == []
        assert not [warning for warning in emitted if issubclass(warning.category, RuntimeWarning)]
        for value in created:
            assert inspect.getcoroutinestate(value) == inspect.CORO_CLOSED
            assert value.cr_frame is None
    finally:
        for value in created:
            value.close()


@pytest.mark.parametrize("state", ["suspended", "closed"])
def test_already_started_or_closed_coroutine_is_not_resumed_or_closed_by_sink(state):
    reached = []

    class Suspend:
        def __await__(self):
            yield "paused"

    async def write():
        try:
            reached.append("start")
            await Suspend()
            reached.append("finish")
        finally:
            reached.append("finally")

    value = write()
    assert value.send(None) == "paused"
    if state == "closed":
        value.close()
    before = list(reached)
    try:
        unavailable(lambda _line: value)
        assert reached == before
        assert inspect.getcoroutinestate(value) == (inspect.CORO_CLOSED if state == "closed" else inspect.CORO_SUSPENDED)
    finally:
        value.close()


@pytest.mark.parametrize("complete", [False, True])
def test_host_future_is_rejected_without_cancellation_or_result_consumption(complete):
    loop = asyncio.new_event_loop()
    try:
        value = loop.create_future()
        if complete:
            value.set_result("host-result")
        unavailable(lambda _line: value)
        assert value.done() is complete
        assert not value.cancelled()
        if complete:
            assert value.result() == "host-result"
    finally:
        loop.close()


def test_host_task_remains_owned_and_runnable_by_host():
    async def run():
        written = []

        async def write():
            await asyncio.sleep(0)
            written.append("host-delivery")

        task = asyncio.create_task(write())
        try:
            unavailable(lambda _line: task)
            assert not task.cancelled() and not task.done()
            await task
            assert written == ["host-delivery"]
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    asyncio.run(run())


def test_custom_awaitable_is_not_awaited_or_given_arbitrary_cleanup_calls():
    touched = []

    class HostAwaitable:
        def __await__(self):
            touched.append("await")
            raise AssertionError("SECRET host operation")

        def close(self):
            touched.append("close")
            raise AssertionError("SECRET host cleanup")

        def cancel(self):
            touched.append("cancel")
            raise AssertionError("SECRET host cancel")

    unavailable(lambda _line: HostAwaitable())
    assert touched == []


def test_generator_coroutine_is_rejected_without_stepping_or_closing_host_generator():
    reached = []

    @types.coroutine
    def write():
        try:
            reached.append("start")
            yield
        finally:
            reached.append("finally")

    value = write()
    try:
        unavailable(lambda _line: value)
        assert inspect.getgeneratorstate(value) == inspect.GEN_CREATED
        assert reached == []
    finally:
        value.close()


@pytest.mark.parametrize("answer", [None, False, 0, "stored", {"status": "stored"}])
def test_synchronous_callback_still_delivers_one_allowlisted_event(answer):
    written = []

    def write(line):
        written.append(json.loads(line))
        return answer

    assert emit(write) is None
    assert written == [{"schema_version": "appguard-audit-v0", "event_id": "event-1", "app_id": "test-app", "at": 100,
                        "action": "allow", "code": "ALLOWED", "profile": "basic"}]


@pytest.mark.parametrize("complete", [False, True])
def test_concurrent_future_cannot_hide_unobserved_background_delivery(complete):
    from concurrent.futures import Future

    value = Future()
    if complete:
        value.set_result("host-result")
    unavailable(lambda _line: value)
    assert value.done() is complete
    assert not value.cancelled()
    if complete:
        assert value.result() == "host-result"
