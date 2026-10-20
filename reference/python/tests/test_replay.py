"""Catch races, premature eviction and fail-open capacity behavior."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from appguard_reference.replay import InMemoryReplayStore, ReplayStoreUnavailable

SCOPE = ("test-app", "test-key", "nonce")


def test_only_one_concurrent_claim():
    store = InMemoryReplayStore()
    barrier = Barrier(32)

    def attempt(_):
        barrier.wait(timeout=10)
        return store.claim(SCOPE, expires=120, now=1)

    with ThreadPoolExecutor(max_workers=32) as pool:
        assert list(pool.map(attempt, range(32))).count(True) == 1


def test_capacity_does_not_evict_live_claims():
    store = InMemoryReplayStore(capacity=1)
    assert store.claim(SCOPE, expires=120, now=1)
    assert not store.claim(SCOPE, expires=120, now=1)
    with pytest.raises(ReplayStoreUnavailable):
        store.claim(("app", "key", "other"), expires=120, now=1)
    assert not store.claim(SCOPE, expires=120, now=1)


def test_expired_entry_releases_capacity():
    store = InMemoryReplayStore(capacity=1)
    assert store.claim(SCOPE, expires=10, now=1)
    assert store.claim(("app", "key", "new"), expires=20, now=10)


def test_app_and_key_scopes_are_independent():
    store = InMemoryReplayStore()
    assert store.claim(SCOPE, expires=120, now=1)
    assert store.claim(("other-app", "test-key", "nonce"), expires=120, now=1)
    assert store.claim(("test-app", "other-key", "nonce"), expires=120, now=1)


@pytest.mark.parametrize("capacity", [0, -1, True, 1.5, "1"])
def test_invalid_capacity(capacity):
    with pytest.raises(ValueError):
        InMemoryReplayStore(capacity=capacity)


@pytest.mark.parametrize("expires,now", [(1, 1), (0, 1), (True, 0), (2, True), (3, -1)])
def test_invalid_claim_time_fails_closed(expires, now):
    with pytest.raises(ReplayStoreUnavailable):
        InMemoryReplayStore().claim(SCOPE, expires=expires, now=now)
