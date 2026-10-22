"""Subject revocation against real SQLite and genuine synthetic P-256 proofs."""

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, fields, is_dataclass
import hashlib
from pathlib import Path
import sqlite3
from threading import Barrier, Event

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from appguard import RequestInput, SignatureParameters, VerificationError, verify_request
from appguard.canonical import build_signature_base
from appguard.enrollment import (AttestationVerdict, EnrollmentError, EnrollmentService,
                                SqliteEnrollmentStore, enrollment_message)
from appguard.replay import InMemoryReplayStore


@pytest.fixture
def setup(tmp_path):
    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    clock = [1700000000]
    store = SqliteEnrollmentStore(tmp_path / "enrollment.sqlite")
    service = EnrollmentService(store, profile="basic", clock=lambda: clock[0])

    def sign(message):
        r, s = utils.decode_dss_signature(private.sign(message, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return store, service, pem, sign, clock


def issue(service, pem, key_id, *, app_id="test-app", subject="test-user", ttl=120):
    return service.issue(app_id=app_id, subject=subject, key_id=key_id,
                         origin="https://api.example.test", public_key_pem=pem, ttl=ttl)


def complete(service, challenge, sign, **kwargs):
    return service.complete(challenge.nonce, app_id=challenge.app_id, subject=challenge.subject,
                            proof=sign(enrollment_message(challenge)), **kwargs)


def revoke_subject(store, app_id="test-app", subject="test-user"):
    operation = getattr(store, "revoke_subject", None)
    assert callable(operation), "SqliteEnrollmentStore.revoke_subject is missing"
    return operation(app_id, subject)


def counts(result):
    return result.revoked_keys, result.cancelled_challenges


def assert_redacted(error, code="STORE_UNAVAILABLE"):
    assert error.code == code and str(error) == code
    assert error.__cause__ is None
    assert error.__context__ is None


def test_revocation_is_exactly_scoped_and_durable_including_expired_pending(setup):
    store, service, pem, sign, clock = setup
    enrolled = [
        issue(service, pem, "active-one"),
        issue(service, pem, "active-two"),
        issue(service, pem, "already-revoked"),
        issue(service, pem, "active-one", app_id="other-app"),
        issue(service, pem, "other-subject", subject="other-user"),
        issue(service, pem, "subject-prefix", subject="test-user.extra"),
        issue(service, pem, "app-prefix", app_id="test-app.extra"),
    ]
    for challenge in enrolled:
        complete(service, challenge, sign)
    assert store.revoke("test-app", "test-user", "already-revoked") is True
    pending = issue(service, pem, "pending")
    expired = issue(service, pem, "expired", ttl=1)
    unrelated = [issue(service, pem, "other-pending", subject="other-user"),
                 issue(service, pem, "other-pending", app_id="other-app")]
    clock[0] += 1
    assert store.pending(expired.nonce) == expired

    assert counts(revoke_subject(store)) == (2, 2)

    reopened = SqliteEnrollmentStore(store.path)
    for challenge in enrolled[:3]:
        assert reopened.lookup(challenge.app_id, challenge.subject, challenge.key_id).key.revoked is True
    for challenge in enrolled[3:]:
        assert reopened.lookup(challenge.app_id, challenge.subject, challenge.key_id).key.revoked is False
    assert reopened.pending(pending.nonce) is None
    assert reopened.pending(expired.nonce) is None
    for challenge in unrelated:
        assert reopened.pending(challenge.nonce) == challenge
        assert complete(service, challenge, sign).key.revoked is False


def test_result_is_the_public_immutable_counts_value(setup):
    store, service, pem, sign, _ = setup
    complete(service, issue(service, pem, "active"), sign)
    issue(service, pem, "pending-one")
    issue(service, pem, "pending-two")

    result = revoke_subject(store)

    from appguard.enrollment import SubjectRevocationResult

    assert type(result) is SubjectRevocationResult
    assert is_dataclass(result)
    assert [field.name for field in fields(result)] == ["revoked_keys", "cancelled_challenges"]
    assert result == SubjectRevocationResult(1, 2)
    assert type(result.revoked_keys) is int
    assert type(result.cancelled_challenges) is int
    with pytest.raises(FrozenInstanceError):
        result.revoked_keys = 0


def test_repeated_revocation_counts_only_new_changes(setup):
    store, service, pem, sign, _ = setup
    complete(service, issue(service, pem, "active"), sign)
    issue(service, pem, "pending")

    assert counts(revoke_subject(store)) == (1, 1)
    assert counts(revoke_subject(store)) == (0, 0)
    assert counts(revoke_subject(SqliteEnrollmentStore(store.path))) == (0, 0)


@pytest.mark.parametrize("app_id,subject", [("test-app", "test-user"),
    ("missing-app", "test-user"), ("test-app", "missing-user")])
def test_absent_scope_returns_zero_counts(setup, app_id, subject):
    store, _, _, _, _ = setup
    assert counts(revoke_subject(store, app_id, subject)) == (0, 0)


@pytest.mark.parametrize("has_key,has_pending,want", [(True, False, (1, 0)),
    (False, True, (0, 1))])
def test_keys_and_pending_challenges_are_independently_counted(setup, has_key, has_pending, want):
    store, service, pem, sign, _ = setup
    if has_key:
        complete(service, issue(service, pem, "active"), sign)
    if has_pending:
        issue(service, pem, "pending")
    assert counts(revoke_subject(store)) == want


def test_cancelled_challenge_cannot_complete_with_valid_proof(setup):
    store, service, pem, sign, clock = setup
    challenge = issue(service, pem, "pending")
    assert counts(revoke_subject(store)) == (0, 1)
    reopened = SqliteEnrollmentStore(store.path)
    service = EnrollmentService(reopened, profile="basic", clock=lambda: clock[0])

    with pytest.raises(EnrollmentError, match="^CHALLENGE_REJECTED$"):
        complete(service, challenge, sign)

    assert reopened.lookup("test-app", "test-user", "pending") is None


@pytest.mark.parametrize("subject", ["test-user", "other-user"])
def test_revoked_key_id_tombstone_prevents_reenrollment_for_any_subject(setup, subject):
    store, service, pem, sign, _ = setup
    complete(service, issue(service, pem, "retained-key"), sign)
    assert counts(revoke_subject(store)) == (1, 0)

    with pytest.raises(EnrollmentError, match="^KEY_ID_IN_USE$"):
        issue(service, pem, "retained-key", subject=subject)

    assert SqliteEnrollmentStore(store.path).lookup("test-app", "test-user", "retained-key").key.revoked is True


def test_revocation_is_point_in_time_and_fresh_authorized_issuance_can_enroll(setup):
    store, service, pem, sign, _ = setup
    complete(service, issue(service, pem, "old-key"), sign)
    issue(service, pem, "cancelled-key")
    assert counts(revoke_subject(store)) == (1, 1)

    fresh = issue(service, pem, "fresh-key")
    credential = complete(service, fresh, sign)

    assert credential.key.revoked is False
    assert store.lookup("test-app", "test-user", "fresh-key") == credential
    assert store.lookup("test-app", "test-user", "old-key").key.revoked is True


def signed_request(challenge, sign, now):
    body = b"{}"
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode()
    request = RequestInput("POST", "/v1/items", (("content-type", "application/json"),
        ("content-digest", f"sha-256=:{digest}:"), ("authorization", "Bearer TEST_ONLY_TOKEN"),
        ("appguard-app-id", challenge.app_id)), body)
    parameters = SignatureParameters(now, now + 120, "AAECAwQFBgcICQoLDA0ODw", challenge.key_id,
                                     "ecdsa-p256-sha256", "appguard-request-v0")
    signature = sign(build_signature_base(request, parameters, origin=challenge.origin))
    return request, parameters, signature


def test_fresh_lookup_rejects_revoked_request_before_nonce_and_other_scopes_verify(setup):
    store, service, pem, sign, clock = setup
    challenges = [issue(service, pem, "target"),
                  issue(service, pem, "other-user-key", subject="other-user"),
                  issue(service, pem, "target", app_id="other-app")]
    for challenge in challenges:
        complete(service, challenge, sign)
    assert counts(revoke_subject(store)) == (1, 0)
    replay = InMemoryReplayStore()

    for challenge in challenges:
        request, parameters, signature = signed_request(challenge, sign, clock[0])

        def verify():
            return verify_request(request, parameters, signature, origin=challenge.origin,
                app_id=challenge.app_id, subject=challenge.subject,
                key=store.lookup(challenge.app_id, challenge.subject, challenge.key_id).key,
                now=clock[0], replay=replay)

        if challenge is challenges[0]:
            with pytest.raises(VerificationError, match="^KEY_REJECTED$"):
                verify()
            assert replay.claim(("test-app", "target", parameters.nonce),
                                expires=clock[0] + 120, now=clock[0]) is True
        else:
            assert verify().code == "VERIFIED"


def test_concurrent_connections_count_each_change_once(setup):
    store, service, pem, sign, _ = setup
    for key_id in ("active-one", "active-two"):
        complete(service, issue(service, pem, key_id), sign)
    pending = [issue(service, pem, key_id) for key_id in ("pending-one", "pending-two")]
    connections = [SqliteEnrollmentStore(store.path), SqliteEnrollmentStore(store.path)]
    gate = Barrier(3, timeout=5)

    def revoke(connection):
        gate.wait()
        return counts(revoke_subject(connection))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(revoke, connection) for connection in connections]
        gate.wait()
        results = [future.result(timeout=10) for future in futures]

    assert sorted(results) == [(0, 0), (2, 2)]
    for key_id in ("active-one", "active-two"):
        assert store.lookup("test-app", "test-user", key_id).key.revoked is True
    for challenge in pending:
        assert store.pending(challenge.nonce) is None


def test_inflight_provider_completion_cannot_finish_after_revocation(setup):
    store, service, pem, sign, clock = setup
    challenge = issue(service, pem, "inflight")
    entered, resume = Event(), Event()

    def synthetic_provider(bound_challenge, evidence):
        entered.set()
        assert resume.wait(timeout=5), "provider release gate timed out"
        return AttestationVerdict("apple", "verified", bound_challenge.app_id, bound_challenge.subject,
            bound_challenge.public_key_sha256, hashlib.sha256(enrollment_message(bound_challenge)).hexdigest(),
            clock[0] + 60)

    service = EnrollmentService(store, clock=lambda: clock[0], attestation_verifier=synthetic_provider)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(complete, service, challenge, sign, evidence=b"TEST_ONLY_PROVIDER_EVIDENCE")
        try:
            assert entered.wait(timeout=5), "provider was not reached"
            assert counts(revoke_subject(SqliteEnrollmentStore(store.path))) == (0, 1)
        finally:
            resume.set()
        with pytest.raises(EnrollmentError, match="^CHALLENGE_REJECTED$"):
            future.result(timeout=5)

    assert store.pending(challenge.nonce) is None
    assert store.lookup("test-app", "test-user", "inflight") is None


@pytest.mark.parametrize("field", ["app_id", "subject"])
@pytest.mark.parametrize("invalid", ["", None, True, [], {}, "with space", "line\nbreak", "é",
    "x" * 129, "test-user' OR 1=1 --"])
def test_invalid_identifiers_reject_before_database_access(setup, field, invalid):
    store, service, pem, sign, _ = setup
    complete(service, issue(service, pem, "active"), sign)
    pending = issue(service, pem, "pending")
    original_path = store.path
    store.path = str(Path(store.path).parent / "missing-parent" / "unavailable.sqlite")
    values = {"app_id": "test-app", "subject": "test-user", field: invalid}

    with pytest.raises(EnrollmentError) as result:
        revoke_subject(store, **values)

    assert_redacted(result.value, "INVALID_ENROLLMENT")
    reopened = SqliteEnrollmentStore(original_path)
    assert reopened.lookup("test-app", "test-user", "active").key.revoked is False
    assert reopened.pending(pending.nonce) == pending


def test_valid_identifier_boundaries_keep_literal_scope(setup):
    store, service, pem, sign, _ = setup
    app_id, subject = "a" * 128, "u" * 128
    challenge = issue(service, pem, "key", app_id=app_id, subject=subject)
    complete(service, challenge, sign)
    unrelated = issue(service, pem, "literal", app_id="app:._-", subject="subject:._-")
    complete(service, unrelated, sign)

    assert counts(revoke_subject(store, app_id, subject)) == (1, 0)

    assert store.lookup(app_id, subject, "key").key.revoked is True
    assert store.lookup("app:._-", "subject:._-", "literal").key.revoked is False


def test_delete_failure_rolls_back_key_update_and_redacts_sqlite_context(setup):
    store, service, pem, sign, _ = setup
    complete(service, issue(service, pem, "active"), sign)
    pending = issue(service, pem, "pending")
    with sqlite3.connect(store.path) as db:
        db.execute("""CREATE TRIGGER fail_challenge_delete BEFORE DELETE ON appguard_challenges
            BEGIN SELECT RAISE(ABORT, 'PRIVATE_SYNTHETIC_DELETE_FAILURE'); END""")

    with pytest.raises(EnrollmentError) as result:
        revoke_subject(store)

    assert_redacted(result.value)
    reopened = SqliteEnrollmentStore(store.path)
    assert reopened.lookup("test-app", "test-user", "active").key.revoked is False
    assert reopened.pending(pending.nonce) == pending


def test_commit_failure_rolls_back_both_mutations(setup, monkeypatch):
    import appguard.enrollment_store as module

    store, service, pem, sign, _ = setup
    complete(service, issue(service, pem, "active"), sign)
    pending = issue(service, pem, "pending")
    original_connect = sqlite3.connect

    class Connection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql == "COMMIT":
                raise sqlite3.OperationalError("PRIVATE_SYNTHETIC_COMMIT_FAILURE")
            return super().execute(sql, parameters)

    with monkeypatch.context() as patch:
        patch.setattr(module.sqlite3, "connect", lambda *args, **kwargs:
                      original_connect(*args, **kwargs, factory=Connection))
        with pytest.raises(EnrollmentError) as result:
            revoke_subject(store)
        assert_redacted(result.value)

    assert store.lookup("test-app", "test-user", "active").key.revoked is False
    assert store.pending(pending.nonce) == pending


def test_post_commit_close_failure_reports_error_and_requires_state_readback(setup, monkeypatch):
    import appguard.enrollment_store as module

    store, service, pem, sign, _ = setup
    complete(service, issue(service, pem, "active"), sign)
    pending = issue(service, pem, "pending")
    original_connect = sqlite3.connect

    class Connection(sqlite3.Connection):
        def close(self):
            super().close()
            raise sqlite3.OperationalError("PRIVATE_SYNTHETIC_POST_COMMIT_CLOSE_FAILURE")

    with monkeypatch.context() as patch:
        patch.setattr(module.sqlite3, "connect", lambda *args, **kwargs:
                      original_connect(*args, **kwargs, factory=Connection))
        with pytest.raises(EnrollmentError) as result:
            revoke_subject(store)
        assert_redacted(result.value)

    reopened = SqliteEnrollmentStore(store.path)
    assert reopened.lookup("test-app", "test-user", "active").key.revoked is True
    assert reopened.pending(pending.nonce) is None
    assert counts(revoke_subject(reopened)) == (0, 0)
