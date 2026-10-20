"""Real local key enrollment; provider verification is an explicit synthetic boundary."""

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import os
import sqlite3
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from appguard.enrollment import (AttestationVerdict, EnrollmentError, EnrollmentService,
                                SqliteEnrollmentStore, enrollment_message)


def test_store_module_can_be_imported_independently():
    result = subprocess.run([sys.executable, "-I", "-c", "from appguard.enrollment_store import SqliteEnrollmentStore"],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.fixture
def setup(tmp_path):
    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    clock = [1700000000]
    store = SqliteEnrollmentStore(tmp_path / "enrollment.sqlite")
    service = EnrollmentService(store, profile="basic", clock=lambda: clock[0])
    challenge = service.issue(app_id="test-app", subject="test-user", key_id="test-key",
                              origin="https://api.example.test", public_key_pem=pem)

    def sign(message):
        r, s = utils.decode_dss_signature(private.sign(message, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return store, service, challenge, sign, clock


def complete(service, challenge, signature, **changes):
    return service.complete(challenge.nonce, app_id=changes.pop("app_id", "test-app"),
                            subject=changes.pop("subject", "test-user"), proof=signature, **changes)


def test_message_is_bound_with_fixed_order_and_no_trailing_newline(setup):
    _, _, challenge, _, _ = setup
    expected = ("appguard-enrollment-v0\napp-id: test-app\norigin: https://api.example.test\nsubject: test-user\n"
                "key-id: test-key\npublic-key-sha256: " + challenge.public_key_sha256
                + "\nchallenge: " + challenge.nonce + "\nexpires: 1700000120").encode()
    assert enrollment_message(challenge) == expected
    assert len(base64.urlsafe_b64decode(challenge.nonce + "=")) == 32


def test_valid_proof_enrolls_public_key_and_rejects_replay(setup):
    store, service, challenge, sign, _ = setup
    record = complete(service, challenge, sign(enrollment_message(challenge)))
    assert record.key.subject == "test-user" and record.key.revoked is False
    assert record.attestation == "missing" and record.provider is None
    assert store.lookup("test-app", "test-user", "test-key") == record
    assert store.lookup("test-app", "other-user", "test-key") is None
    with pytest.raises(EnrollmentError, match="^CHALLENGE_REJECTED$"):
        complete(service, challenge, sign(enrollment_message(challenge)))


@pytest.mark.parametrize("change", [{"app_id": "other-app"}, {"subject": "other-user"}])
def test_subject_app_substitution_does_not_consume_challenge(setup, change):
    _, service, challenge, sign, _ = setup
    proof = sign(enrollment_message(challenge))
    with pytest.raises(EnrollmentError, match="^CHALLENGE_REJECTED$"):
        complete(service, challenge, proof, **change)
    assert complete(service, challenge, proof).key.key_id == "test-key"


@pytest.mark.parametrize("field,value", [("origin", "https://other.test"), ("key_id", "other-key"),
                                         ("public_key_sha256", "0" * 64), ("expires", 1700000121)])
def test_changed_challenge_proof_rejects_without_consuming(setup, field, value):
    _, service, challenge, sign, _ = setup
    with pytest.raises(EnrollmentError, match="^PROOF_REJECTED$"):
        complete(service, challenge, sign(enrollment_message(replace(challenge, **{field: value}))))
    assert complete(service, challenge, sign(enrollment_message(challenge))).attestation == "missing"


@pytest.mark.parametrize("proof", [b"", b"x" * 63, b"\x00" * 64])
def test_invalid_proof_never_creates_credential(setup, proof):
    store, service, challenge, _, _ = setup
    with pytest.raises(EnrollmentError, match="^PROOF_REJECTED$"):
        complete(service, challenge, proof)
    assert store.lookup("test-app", "test-user", "test-key") is None


def test_expiration_boundary_rejects(setup):
    _, service, challenge, sign, clock = setup
    clock[0] = challenge.expires
    with pytest.raises(EnrollmentError, match="^CHALLENGE_REJECTED$"):
        complete(service, challenge, sign(enrollment_message(challenge)))


def test_multiple_connections_accept_exactly_one_proof(setup):
    store, _, challenge, sign, clock = setup
    proof = sign(enrollment_message(challenge))

    def attempt(_):
        service = EnrollmentService(SqliteEnrollmentStore(store.path), profile="basic", clock=lambda: clock[0])
        try:
            complete(service, challenge, proof)
            return "ENROLLED"
        except EnrollmentError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(16)))
    assert results.count("ENROLLED") == 1
    assert set(results) <= {"ENROLLED", "CHALLENGE_REJECTED"}


def test_revocation_persists_and_key_id_cannot_be_replaced(setup):
    store, service, challenge, sign, _ = setup
    complete(service, challenge, sign(enrollment_message(challenge)))
    assert store.revoke("test-app", "test-user", "test-key") is True
    assert store.revoke("test-app", "other-user", "test-key") is False
    assert SqliteEnrollmentStore(store.path).lookup("test-app", "test-user", "test-key").key.revoked is True
    with pytest.raises(EnrollmentError, match="^KEY_ID_IN_USE$"):
        service.issue(app_id="test-app", subject="test-user", key_id="test-key", origin=challenge.origin,
                      public_key_pem=store.lookup("test-app", "test-user", "test-key").key.public_key_pem)


@pytest.mark.parametrize("profile", ["balanced", "strict"])
def test_attestation_required_profile_never_accepts_missing_or_client_verdict(setup, profile):
    store, _, challenge, sign, clock = setup
    service = EnrollmentService(store, profile=profile, clock=lambda: clock[0])
    proof = sign(enrollment_message(challenge))
    with pytest.raises(EnrollmentError, match="^ATTESTATION_REQUIRED$"):
        complete(service, challenge, proof)
    with pytest.raises(EnrollmentError, match="^INVALID_ENROLLMENT$"):
        complete(service, challenge, proof, evidence={"status": "verified"})
    assert store.lookup("test-app", "test-user", "test-key") is None


def verdict(challenge, now):
    return AttestationVerdict("apple", "verified", challenge.app_id, challenge.subject,
                              challenge.public_key_sha256, hashlib.sha256(enrollment_message(challenge)).hexdigest(), now + 60)


def test_trusted_verifier_binding_is_required_and_persisted(setup):
    store, _, challenge, sign, clock = setup
    seen = []

    def trusted_verifier(bound_challenge, opaque_evidence):
        seen.append((bound_challenge, opaque_evidence))
        return verdict(bound_challenge, clock[0])

    service = EnrollmentService(store, profile="balanced", clock=lambda: clock[0], attestation_verifier=trusted_verifier)
    result = complete(service, challenge, sign(enrollment_message(challenge)), evidence=b"TEST_ONLY_PROVIDER_EVIDENCE")
    assert seen == [(challenge, b"TEST_ONLY_PROVIDER_EVIDENCE")]
    assert result.attestation == "verified" and result.provider == "apple" and result.attestation_expires == clock[0] + 60


@pytest.mark.parametrize("field,value", [("app_id", "other-app"), ("subject", "other-user"),
    ("public_key_sha256", "0" * 64), ("challenge_sha256", "0" * 64), ("expires", 1700000000),
    ("status", "missing"), ("provider", "client-json")])
def test_verifier_cannot_authorize_an_unbound_or_expired_verdict(setup, field, value):
    store, _, challenge, sign, clock = setup
    service = EnrollmentService(store, profile="balanced", clock=lambda: clock[0],
                                attestation_verifier=lambda c, e: replace(verdict(c, clock[0]), **{field: value}))
    with pytest.raises(EnrollmentError, match="^ATTESTATION_REJECTED$"):
        complete(service, challenge, sign(enrollment_message(challenge)), evidence=b"TEST_ONLY_PROVIDER_EVIDENCE")
    assert store.lookup("test-app", "test-user", "test-key") is None


def test_expired_during_provider_check_is_not_enrolled(setup):
    store, _, challenge, sign, clock = setup

    def verify(c, e):
        result = verdict(c, clock[0])
        clock[0] = c.expires
        return result

    service = EnrollmentService(store, profile="balanced", clock=lambda: clock[0], attestation_verifier=verify)
    with pytest.raises(EnrollmentError, match="^CHALLENGE_REJECTED$"):
        complete(service, challenge, sign(enrollment_message(challenge)), evidence=b"TEST_ONLY_PROVIDER_EVIDENCE")
    assert store.lookup("test-app", "test-user", "test-key") is None


def test_provider_exception_is_redacted_and_preserves_challenge(setup):
    store, _, challenge, sign, clock = setup

    def unavailable(c, e):
        raise RuntimeError("TEST_ONLY_TOKEN")

    service = EnrollmentService(store, profile="balanced", clock=lambda: clock[0], attestation_verifier=unavailable)
    with pytest.raises(EnrollmentError, match="^ATTESTATION_UNAVAILABLE$"):
        complete(service, challenge, sign(enrollment_message(challenge)), evidence=b"TEST_ONLY_PROVIDER_EVIDENCE")
    assert store.lookup("test-app", "test-user", "test-key") is None


def test_sqlite_file_is_private_and_existing_unrelated_database_is_rejected(tmp_path):
    path = tmp_path / "private.sqlite"
    SqliteEnrollmentStore(path)
    assert os.stat(path).st_mode & 0o077 == 0
    other = tmp_path / "unrelated.sqlite"
    with sqlite3.connect(other) as db:
        db.execute("CREATE TABLE user_data (id INTEGER)")
        db.execute("INSERT INTO user_data VALUES (42)")
    os.chmod(other, 0o600)
    with pytest.raises(EnrollmentError, match="^STORE_UNAVAILABLE$"):
        SqliteEnrollmentStore(other)
    with sqlite3.connect(other) as db:
        assert db.execute("SELECT id FROM user_data").fetchall() == [(42,)]


def test_pending_capacity_fails_closed_and_expired_challenges_are_reclaimed(setup):
    store, _, challenge, _, clock = setup
    service = EnrollmentService(store, profile="basic", clock=lambda: clock[0], max_pending=1)
    pem=store.pending(challenge.nonce).public_key_pem
    with pytest.raises(EnrollmentError, match="^STORE_UNAVAILABLE$"):
        service.issue(app_id="test-app", subject="test-user", key_id="other-key", origin=challenge.origin, public_key_pem=pem)
    clock[0] = challenge.expires
    assert service.issue(app_id="test-app", subject="test-user", key_id="other-key", origin=challenge.origin, public_key_pem=pem).key_id == "other-key"


@pytest.mark.parametrize("bad_value", [[], {"status": "verified"}, True])
def test_malformed_trusted_provider_contract_fails_with_fixed_code(setup, bad_value):
    store, _, challenge, sign, clock = setup
    service = EnrollmentService(store, clock=lambda: clock[0],
                                attestation_verifier=lambda c, e: replace(verdict(c, clock[0]), provider=bad_value))
    with pytest.raises(EnrollmentError, match="^ATTESTATION_REJECTED$"):
        complete(service, challenge, sign(enrollment_message(challenge)), evidence=b"TEST_ONLY_PROVIDER_EVIDENCE")


def test_enrolled_key_verifies_requests_and_revocation_rejects_them(setup):
    from appguard import RequestInput, SignatureParameters, VerificationError, verify_request
    from appguard.canonical import build_signature_base
    from appguard.replay import InMemoryReplayStore

    store, service, challenge, sign, clock = setup
    complete(service, challenge, sign(enrollment_message(challenge)))
    body = b"{}"
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode()
    request = RequestInput("POST", "/v1/items?b=2&a=1", (("content-type", "application/json"),
        ("content-digest", f"sha-256=:{digest}:"), ("authorization", "Bearer TEST_ONLY_TOKEN"), ("appguard-app-id", "test-app")), body)
    parameters = SignatureParameters(clock[0], clock[0]+120, "AAECAwQFBgcICQoLDA0ODw", "test-key", "ecdsa-p256-sha256", "appguard-request-v0")
    signature = sign(build_signature_base(request, parameters, origin=challenge.origin))
    replay = InMemoryReplayStore()

    def verify():
        return verify_request(request, parameters, signature, origin=challenge.origin, app_id="test-app", subject="test-user",
                              key=store.lookup("test-app", "test-user", "test-key").key, now=clock[0], replay=replay)

    assert verify().code == "VERIFIED"
    store.revoke("test-app", "test-user", "test-key")
    with pytest.raises(VerificationError, match="^KEY_REJECTED$"):
        verify()


def test_symlink_or_world_readable_enrollment_database_is_rejected(tmp_path):
    original = tmp_path / "original.sqlite"
    SqliteEnrollmentStore(original)
    link = tmp_path / "linked.sqlite"
    link.symlink_to(original)
    with pytest.raises(EnrollmentError, match="^STORE_UNAVAILABLE$"):
        SqliteEnrollmentStore(link)
    os.chmod(original, 0o644)
    with pytest.raises(EnrollmentError, match="^STORE_UNAVAILABLE$"):
        SqliteEnrollmentStore(original)


def assert_redacted(error, code):
    assert error.code == code and str(error) == code
    assert error.__cause__ is None
    assert error.__context__ is None


@pytest.mark.parametrize("phase", ["issue", "complete", "after_provider"])
def test_clock_errors_have_no_retained_exception_or_enrollment_side_effect(setup, phase):
    store, _, challenge, sign, clock = setup
    def unavailable():
        raise RuntimeError("PRIVATE_SYNTHETIC_CLOCK")
    service = EnrollmentService(store, profile="basic", clock=lambda: clock[0])
    if phase == "after_provider":
        def provider(c, evidence):
            service.clock = unavailable
            return verdict(c, clock[0])
        service.attestation_verifier = provider
    else:
        service.clock = unavailable
    with pytest.raises(EnrollmentError) as result:
        if phase == "issue":
            service.issue(app_id="test-app", subject="test-user", key_id="another-key", origin=challenge.origin,
                          public_key_pem=challenge.public_key_pem)
        else:
            complete(service, challenge, sign(enrollment_message(challenge)),
                     **({"evidence": b"PRIVATE_SYNTHETIC_EVIDENCE"} if phase == "after_provider" else {}))
    assert_redacted(result.value, "CLOCK_UNAVAILABLE")
    assert store.pending(challenge.nonce) == challenge
    assert store.lookup("test-app", "test-user", "test-key") is None


def test_nested_provider_error_does_not_retain_evidence(setup):
    import json
    store, _, challenge, sign, clock = setup
    def provider(c, evidence):
        try:
            json.loads(evidence)
        except ValueError as original:
            raise RuntimeError("PRIVATE_SYNTHETIC_PROVIDER") from original
    service = EnrollmentService(store, clock=lambda: clock[0], attestation_verifier=provider)
    with pytest.raises(EnrollmentError) as result:
        complete(service, challenge, sign(enrollment_message(challenge)), evidence=b"PRIVATE_SYNTHETIC_EVIDENCE")
    assert_redacted(result.value, "ATTESTATION_UNAVAILABLE")
    assert store.pending(challenge.nonce) == challenge
    assert store.lookup("test-app", "test-user", "test-key") is None


@pytest.mark.parametrize("kind", ["public_key", "proof", "identifier", "origin"])
def test_validation_errors_do_not_retain_internal_exception_context(setup, kind):
    store, service, challenge, _, _ = setup
    with pytest.raises(EnrollmentError) as result:
        if kind == "proof":
            complete(service, challenge, b"\0" * 64)
        else:
            service.issue(app_id="invalid app" if kind == "identifier" else "test-app", subject="test-user",
                          key_id="another-key", origin="invalid origin" if kind == "origin" else challenge.origin,
                          public_key_pem=b"PRIVATE_SYNTHETIC_INVALID_PEM" if kind == "public_key" else challenge.public_key_pem)
    assert_redacted(result.value, "PROOF_REJECTED" if kind == "proof" else "INVALID_ENROLLMENT")
    assert store.pending(challenge.nonce) == challenge
    assert store.lookup("test-app", "test-user", "test-key") is None


def test_sqlite_constraint_error_has_no_context_and_transaction_rolls_back(setup):
    store, _, challenge, _, clock = setup
    with pytest.raises(EnrollmentError) as result:
        store.add_challenge(challenge, now=clock[0], max_pending=100)
    assert_redacted(result.value, "STORE_UNAVAILABLE")
    assert store.pending(challenge.nonce) == challenge
    assert store.lookup("test-app", "test-user", "test-key") is None


def test_invalid_database_error_does_not_retain_sqlite_exception(tmp_path):
    path = tmp_path / "invalid.sqlite"
    path.write_bytes(b"PRIVATE_SYNTHETIC_NOT_A_DATABASE")
    path.chmod(0o600)
    with pytest.raises(EnrollmentError) as result:
        SqliteEnrollmentStore(path)
    assert_redacted(result.value, "STORE_UNAVAILABLE")
    assert path.read_bytes() == b"PRIVATE_SYNTHETIC_NOT_A_DATABASE"


def test_os_store_error_does_not_retain_private_path(tmp_path):
    with pytest.raises(EnrollmentError) as result:
        SqliteEnrollmentStore(tmp_path / "PRIVATE_SYNTHETIC_MISSING_PARENT" / "db")
    assert_redacted(result.value, "STORE_UNAVAILABLE")


@pytest.mark.parametrize("failure", ["rollback", "close"])
def test_sqlite_cleanup_failure_is_fixed_and_connection_is_closed(setup, monkeypatch, failure):
    import appguard.enrollment_store as module
    store, _, challenge, _, clock = setup
    original = sqlite3.connect
    closed = []
    class Connection(sqlite3.Connection):
        def rollback(self):
            super().rollback()
            if failure == "rollback":
                raise sqlite3.OperationalError("PRIVATE_SYNTHETIC_ROLLBACK")
        def close(self):
            super().close()
            closed.append(True)
            if failure == "close":
                raise sqlite3.OperationalError("PRIVATE_SYNTHETIC_CLOSE")
    monkeypatch.setattr(module.sqlite3, "connect", lambda *a, **kw: original(*a, **kw, factory=Connection))
    with pytest.raises(EnrollmentError) as result:
        store.add_challenge(challenge, now=clock[0], max_pending=100)
    assert closed == [True]
    assert_redacted(result.value, "STORE_UNAVAILABLE")
    monkeypatch.undo()
    assert store.pending(challenge.nonce) == challenge


def test_close_error_after_commit_requires_authenticated_state_readback(setup, monkeypatch):
    import appguard.enrollment_store as module
    store, service, challenge, sign, _ = setup
    original = sqlite3.connect
    class Connection(sqlite3.Connection):
        def close(self):
            changed = self.total_changes > 0
            super().close()
            if changed:
                raise sqlite3.OperationalError("PRIVATE_SYNTHETIC_POST_COMMIT_CLOSE")
    monkeypatch.setattr(module.sqlite3, "connect", lambda *a, **kw: original(*a, **kw, factory=Connection))
    with pytest.raises(EnrollmentError) as result:
        complete(service, challenge, sign(enrollment_message(challenge)))
    assert_redacted(result.value, "STORE_UNAVAILABLE")
    monkeypatch.undo()
    assert store.pending(challenge.nonce) is None
    assert store.lookup("test-app", "test-user", "test-key").key.key_id == "test-key"
