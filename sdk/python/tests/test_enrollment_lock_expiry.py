"""Enrollment expiry at real SQLite write-lock contention boundaries."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import sqlite3
from threading import Event

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from appguard.enrollment import (AttestationVerdict, Credential, EnrollmentError,
                                EnrollmentService, SqliteEnrollmentStore,
                                enrollment_message)
from appguard.types import KeyRecord


@pytest.fixture
def setup(tmp_path):
    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    store = SqliteEnrollmentStore(tmp_path / "enrollment.sqlite")
    service = EnrollmentService(store, profile="basic", clock=lambda: 1700000000)
    challenge = service.issue(app_id="test-app", subject="test-user", key_id="test-key",
                              origin="https://api.example.test", public_key_pem=pem)
    r, s = utils.decode_dss_signature(private.sign(enrollment_message(challenge),
                                                  ec.ECDSA(hashes.SHA256())))
    proof = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return store, service, challenge, proof


def provider_verdict(challenge, expires):
    return AttestationVerdict("apple", "verified", challenge.app_id, challenge.subject,
        challenge.public_key_sha256, hashlib.sha256(enrollment_message(challenge)).hexdigest(), expires)


def complete(service, challenge, proof, *, evidence=None):
    return service.complete(challenge.nonce, app_id=challenge.app_id, subject=challenge.subject,
                            proof=proof, evidence=evidence)


def complete_after_lock_wait(setup, monkeypatch, time_after_wait, *, evidence=None):
    """Advance the injected clock only after SQLite attempts the final BEGIN.

    The initial pending read finishes before the separate connection takes the
    write lock. Trace observation retains the real SQLite BEGIN/lock behavior;
    neither the transaction nor any database mutation is replaced by a double.
    """
    import appguard.enrollment_store as module

    store, service, challenge, proof = setup
    before_finish, continue_finish, observe_begin, begin_attempted = (Event() for _ in range(4))
    state, samples = [1700000000], [0]
    original_connect = sqlite3.connect

    def clock():
        samples[0] += 1
        # Pause the existing sample after proof/provider verification, allowing
        # the other connection to acquire its lock before the final transaction.
        if samples[0] == 2:
            before_finish.set()
            if not continue_finish.wait(10):
                raise AssertionError("test did not release the final enrollment phase")
        value = state[0]
        return value() if callable(value) else value

    def traced_connect(*args, **kwargs):
        db = original_connect(*args, **kwargs)

        def trace(statement):
            if observe_begin.is_set() and statement == "BEGIN IMMEDIATE":
                begin_attempted.set()

        db.set_trace_callback(trace)
        return db

    service.clock = clock
    with monkeypatch.context() as patch, ThreadPoolExecutor(max_workers=1) as pool:
        patch.setattr(module.sqlite3, "connect", traced_connect)
        holder = original_connect(store.path, timeout=5, isolation_level=None)
        future = pool.submit(complete, service, challenge, proof, evidence=evidence)
        try:
            assert before_finish.wait(10), "completion did not finish proof/provider verification"
            holder.execute("BEGIN IMMEDIATE")
            observe_begin.set()
            continue_finish.set()
            assert begin_attempted.wait(10), "completion did not attempt the final SQLite write lock"
            assert not future.done(), "completion bypassed the separate connection's write lock"
            state[0] = time_after_wait
            holder.execute("COMMIT")
            return future.result(timeout=10)
        finally:
            continue_finish.set()
            if holder.in_transaction:
                holder.rollback()
            holder.close()


def assert_preserved(setup):
    store, _, challenge, _ = setup
    assert store.pending(challenge.nonce) == challenge
    assert store.lookup("test-app", "test-user", "test-key") is None


def assert_redacted(error, code):
    assert error.code == code and str(error) == code
    assert error.__cause__ is None
    assert error.__context__ is None


@pytest.mark.parametrize("profile", ["basic", "balanced"])
@pytest.mark.parametrize("after_wait", [1700000120, 1700000121])
def test_challenge_expiring_while_waiting_for_write_lock_is_rejected(setup, monkeypatch, profile, after_wait):
    _, service, challenge, _ = setup
    service.profile = profile
    if profile == "balanced":
        service.attestation_verifier = lambda c, evidence: provider_verdict(c, 1700000300)

    with pytest.raises(EnrollmentError) as result:
        complete_after_lock_wait(setup, monkeypatch, after_wait,
                                 evidence=b"SYNTHETIC_PROVIDER" if profile == "balanced" else None)

    assert_redacted(result.value, "CHALLENGE_REJECTED")
    assert_preserved(setup)


@pytest.mark.parametrize("after_wait", [1700000060, 1700000061])
def test_attestation_expiring_while_waiting_for_write_lock_is_rejected(setup, monkeypatch, after_wait):
    _, service, _, _ = setup
    service.profile = "balanced"
    service.attestation_verifier = lambda c, evidence: provider_verdict(c, 1700000060)

    with pytest.raises(EnrollmentError) as result:
        complete_after_lock_wait(setup, monkeypatch, after_wait, evidence=b"SYNTHETIC_PROVIDER")

    assert_redacted(result.value, "ATTESTATION_REJECTED")
    assert_preserved(setup)


def test_challenge_rejection_precedes_attestation_rejection_after_lock_wait(setup, monkeypatch):
    _, service, _, _ = setup
    service.profile = "balanced"
    service.attestation_verifier = lambda c, evidence: provider_verdict(c, 1700000060)

    with pytest.raises(EnrollmentError) as result:
        complete_after_lock_wait(setup, monkeypatch, 1700000120, evidence=b"SYNTHETIC_PROVIDER")

    assert_redacted(result.value, "CHALLENGE_REJECTED")
    assert_preserved(setup)


@pytest.mark.parametrize("profile", ["basic", "balanced"])
def test_valid_challenge_and_attestation_can_finish_after_write_lock_wait(setup, monkeypatch, profile):
    store, service, challenge, proof = setup
    service.profile = profile
    if profile == "balanced":
        service.attestation_verifier = lambda c, evidence: provider_verdict(c, 1700000120)

    result = complete_after_lock_wait(setup, monkeypatch, 1700000119,
                                      evidence=b"SYNTHETIC_PROVIDER" if profile == "balanced" else None)

    assert result.attestation == ("verified" if profile == "balanced" else "missing")
    assert store.lookup("test-app", "test-user", "test-key") == result
    assert store.pending(challenge.nonce) is None
    service.clock = lambda: 1700000119
    with pytest.raises(EnrollmentError, match="^CHALLENGE_REJECTED$"):
        complete(service, challenge, proof)


def unavailable_clock():
    try:
        raise ValueError("PRIVATE_SYNTHETIC_CLOCK_INNER")
    except ValueError as original:
        raise RuntimeError("PRIVATE_SYNTHETIC_CLOCK_OUTER") from original


@pytest.mark.parametrize("after_wait", [None, True, 1700000000.0, -1, 1000000000000000,
                                        "PRIVATE_SYNTHETIC_CLOCK", [], unavailable_clock],
                         ids=["none", "bool", "float", "negative", "out-of-range", "string", "list", "exception"])
def test_live_clock_failure_is_redacted_preserves_pending_and_allows_retry(setup, monkeypatch, after_wait):
    store, service, challenge, proof = setup

    with pytest.raises(EnrollmentError) as result:
        complete_after_lock_wait(setup, monkeypatch, after_wait)

    assert_redacted(result.value, "CLOCK_UNAVAILABLE")
    assert_preserved(setup)
    service.clock = lambda: 1700000001
    credential = complete(service, challenge, proof)
    assert store.lookup("test-app", "test-user", "test-key") == credential
    assert store.pending(challenge.nonce) is None


@pytest.mark.parametrize("now,accepted", [(1700000119, True), (1700000120, False)])
def test_direct_store_finish_retains_integer_now_contract(setup, now, accepted):
    store, _, challenge, _ = setup
    credential = Credential(KeyRecord("test-app", "test-key", "test-user", challenge.public_key_pem,
                                       "ecdsa-p256-sha256", False), "missing", None, None)

    if accepted:
        store.finish(challenge, credential, now=now)
        assert store.lookup("test-app", "test-user", "test-key") == credential
        assert store.pending(challenge.nonce) is None
    else:
        with pytest.raises(EnrollmentError) as result:
            store.finish(challenge, credential, now=now)
        assert_redacted(result.value, "CHALLENGE_REJECTED")
        assert_preserved(setup)
