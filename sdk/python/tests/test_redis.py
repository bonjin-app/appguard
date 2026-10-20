import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
import redis

from appguard.redis import RedisReplayStore, redis_replay_key
from appguard.replay import ReplayStoreUnavailable


def test_replay_key_is_language_neutral():
    # Independent literal generated with the Redis contract's compact JSON/hash.
    import hashlib
    scope = ("test-app", "test-key", "AAECAwQFBgcICQoLDA0ODw")
    literal = b'["test-app","test-key","AAECAwQFBgcICQoLDA0ODw"]'
    assert redis_replay_key(scope) == "appguard:v0:replay:" + hashlib.sha256(literal).hexdigest()


@pytest.mark.parametrize("answer", [False, 1, "OK", b"OK"])
def test_unexpected_backend_result_fails_closed(answer):
    class Client:
        def set(self, *args, **kwargs):
            return answer

    with pytest.raises(ReplayStoreUnavailable):
        RedisReplayStore(Client()).claim(("app", "key", "nonce"), expires=120, now=1)


def test_backend_exception_is_redacted():
    class Client:
        def set(self, *args, **kwargs):
            raise RuntimeError("TEST_ONLY_TOKEN")

    with pytest.raises(ReplayStoreUnavailable) as caught:
        RedisReplayStore(Client()).claim(("app", "key", "nonce"), expires=120, now=1)
    assert "TEST_ONLY_TOKEN" not in str(caught.value)


@pytest.mark.parametrize("expires,now", [(1, 1), (152, 1), (True, 0), (120, True), (-1, 1)])
def test_invalid_expiry_never_claims(expires, now):
    class Client:
        def set(self, *args, **kwargs):
            raise AssertionError("invalid claim must not reach Redis")

    with pytest.raises(ReplayStoreUnavailable):
        RedisReplayStore(Client()).claim(("app", "key", "nonce"), expires=expires, now=now)


@pytest.fixture
def client():
    url = os.environ.get("APPGUARD_TEST_REDIS_URL")
    if not url:
        pytest.skip("set APPGUARD_TEST_REDIS_URL for isolated live Redis tests")
    result = redis.Redis.from_url(url, socket_connect_timeout=1, socket_timeout=1)
    result.ping()
    yield result
    result.close()


def test_live_two_instances_and_retention(client):
    scope = ("python-test", uuid.uuid4().hex, "nonce")
    key = redis_replay_key(scope)
    now = int(time.time())
    try:
        assert RedisReplayStore(client).claim(scope, expires=now + 120, now=now)
        assert not RedisReplayStore(client).claim(scope, expires=now + 120, now=now)
        assert 118 <= client.ttl(key) <= 120
    finally:
        client.delete(key)


def test_live_32_concurrent_claims(client):
    scope = ("python-test", uuid.uuid4().hex, "nonce")
    key = redis_replay_key(scope)
    barrier = Barrier(32)
    now = int(time.time())

    def claim(_):
        barrier.wait(timeout=10)
        return RedisReplayStore(client).claim(scope, expires=now + 120, now=now)

    try:
        with ThreadPoolExecutor(max_workers=32) as pool:
            assert list(pool.map(claim, range(32))).count(True) == 1
    finally:
        client.delete(key)


def test_live_disconnected_client_fails_closed(client):
    # A real refused socket, not a mocked successful Redis response.
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        broken = redis.Redis(host="127.0.0.1", port=port, socket_connect_timeout=.1, socket_timeout=.1)
        try:
            with pytest.raises(ReplayStoreUnavailable):
                RedisReplayStore(broken).claim(("app", "key", "nonce"), expires=120, now=1)
        finally:
            broken.close()
