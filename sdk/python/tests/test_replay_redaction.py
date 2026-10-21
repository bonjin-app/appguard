"""Real verification and replay failures must not retain dependency chains."""
import base64
import socket
import traceback

import pytest
import redis

from appguard.redis import RedisReplayStore
from appguard.replay import ReplayStoreUnavailable
from appguard.types import KeyRecord, RequestInput, SignatureParameters, VerificationError
from appguard.verify import verify_request
from conftest import VECTOR

SECRET = "SYNTHETIC_PRIVATE_BACKEND_DETAIL"
SCOPE = ("test-app", "test-key", VECTOR["parameters"]["nonce"])


def verify(store, signature=None):
    request = VECTOR["request"]
    key = {**VECTOR["key"], "public_key_pem": VECTOR["key"]["public_key_pem"].encode()}
    return verify_request(
        RequestInput(request["method"], request["target"], tuple(map(tuple, request["headers"])),
                     base64.b64decode(request["body_b64"])),
        SignatureParameters(**VECTOR["parameters"]),
        base64.b64decode(VECTOR["signature_b64"]) if signature is None else signature,
        **VECTOR["context"], key=KeyRecord(**key), replay=store,
    )


def backend_failure(kind):
    if kind == "plain":
        raise RuntimeError(SECRET)
    if kind == "group":
        raise ExceptionGroup(SECRET, [ValueError(SECRET), RuntimeError(SECRET)])
    try:
        raise ValueError(SECRET)
    except ValueError as cause:
        error = RuntimeError(SECRET)
        error.add_note(SECRET)
        raise error from cause


def redacted(error, message):
    assert error.args == (message,)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.__suppress_context__ is True
    assert SECRET not in "".join(traceback.format_exception(error))


@pytest.mark.parametrize("kind", ["plain", "nested", "group"])
@pytest.mark.parametrize("path", ["core", "redis", "redis-core"])
def test_backend_exception_chain_is_discarded(kind, path):
    class Backend:
        calls = 0

        def claim(self, *args, **kwargs):
            self.calls += 1
            backend_failure(kind)

        set = claim

    backend = Backend()
    if path == "redis":
        with pytest.raises(ReplayStoreUnavailable) as caught:
            RedisReplayStore(backend).claim(SCOPE, expires=120, now=1)
        redacted(caught.value, "replay backend unavailable")
    else:
        store = backend if path == "core" else RedisReplayStore(backend)
        with pytest.raises(VerificationError) as caught:
            verify(store)
        assert caught.value.code == "REPLAY_STORE_UNAVAILABLE"
        redacted(caught.value, "REPLAY_STORE_UNAVAILABLE")
    assert backend.calls == 1  # No retry or claim after a dependency failure.


@pytest.mark.parametrize("path", ["redis", "redis-core"])
def test_actual_refused_connection_is_redacted(path):
    # Reserve a real local port without listening, so no unrelated service is used.
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        client = redis.Redis(host="127.0.0.1", port=reserved.getsockname()[1],
                             socket_connect_timeout=.1, socket_timeout=.1)
        try:
            store = RedisReplayStore(client)
            if path == "redis":
                with pytest.raises(ReplayStoreUnavailable) as caught:
                    store.claim(SCOPE, expires=120, now=1)
                redacted(caught.value, "replay backend unavailable")
            else:
                with pytest.raises(VerificationError) as caught:
                    verify(store)
                redacted(caught.value, "REPLAY_STORE_UNAVAILABLE")
        finally:
            client.close()


@pytest.mark.parametrize("answer, code", [(True, "VERIFIED"), (False, "REPLAY_DETECTED"),
                                         (None, "REPLAY_STORE_UNAVAILABLE"),
                                         (1, "REPLAY_STORE_UNAVAILABLE"),
                                         ("OK", "REPLAY_STORE_UNAVAILABLE")])
def test_claim_results_keep_strict_meaning(answer, code):
    class Store:
        def claim(self, *args, **kwargs):
            return answer
    if answer is True:
        assert verify(Store()).code == code
    else:
        with pytest.raises(VerificationError) as caught:
            verify(Store())
        assert caught.value.code == code and caught.value.__context__ is None


def test_invalid_signature_does_not_claim():
    class Store:
        calls = 0

        def claim(self, *args, **kwargs):
            self.calls += 1
            raise RuntimeError(SECRET)
    store = Store()
    with pytest.raises(VerificationError, match="^INVALID_SIGNATURE$"):
        verify(store, signature=bytes(64))
    assert store.calls == 0


@pytest.mark.parametrize("control", [KeyboardInterrupt, SystemExit])
def test_process_control_exceptions_are_not_converted(control):
    class Store:
        def claim(self, *args, **kwargs):
            raise control()
    with pytest.raises(control):
        verify(Store())
