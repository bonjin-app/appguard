"""Independent synthetic ECDSA/PKI and real persistent-process lifecycle tests."""
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import importlib
import multiprocessing
import sqlite3

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from test_apple_provider import APP_ID, NOW, SyntheticPKI, b64, cbor, context, verifier

REQUEST = b"POST\nhttps://api.example.test/premium?\nsha256:sample-body-digest"


def client_message(challenge):
    # Independently specified wire bytes: do not use the production serializer.
    return ("appguard-apple-assertion-v0\n"
        f"app-id: {challenge.app_id}\napple-app-id: {challenge.apple_app_id}\n"
        f"environment: {challenge.environment}\nsubject: {challenge.subject}\n"
        f"key-id: {challenge.key_id}\nrequest-sha256: {challenge.request_sha256}\n"
        f"challenge: {challenge.nonce}\nissued-at: {challenge.issued_at}\nexpires: {challenge.expires}").encode("ascii")


def signed(pki, challenge, *, counter=1, auth=None, message=None, extensions=None, double_hash=False, key=None):
    if auth is None:
        auth = (hashlib.sha256(APP_ID.encode()).digest() + bytes([0x80 if extensions is not None else 0])
                + counter.to_bytes(4, "big") + (cbor(extensions) if extensions is not None else b""))
    digest = hashlib.sha256(auth + hashlib.sha256(client_message(challenge) if message is None else message).digest()).digest()
    signature = (key or pki.key).sign(digest, ec.ECDSA(hashes.SHA256() if double_hash else utils.Prehashed(hashes.SHA256())))
    return cbor({"signature": signature, "authenticatorData": auth})


def new_lifecycle(context, monkeypatch, tmp_path, *, policy=False, **settings):
    pki, initial, _ = context
    api = importlib.import_module("appguard.providers.apple_lifecycle")
    clock = [NOW]
    opts = {"allowed_validation_categories": {3}, "allowed_bundle_versions": {"42", "43"}} if policy else {}
    backend = verifier(pki, monkeypatch, **opts)
    backend._clock = lambda: clock[0]
    store = api.SqliteAppleAppAttestStore(tmp_path / "apple.sqlite")
    service = api.AppleAppAttestLifecycle(verifier=backend, store=store, clock=lambda: clock[0], **settings)
    ext = {"apple_validation_category_01": b"\x03\0\0\0", "apple_bundle_version_01": "42"} if policy else None
    registration = service.register(initial, pki.evidence(initial, extensions=ext))
    return api, pki, initial, clock, service, registration


def rejected(api, operation, code="APPLE_ASSERTION_REJECTED"):
    with pytest.raises(api.AppleLifecycleError, match=f"^{code}$") as caught:
        operation()
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert caught.value.__suppress_context__ is True


def test_request_bound_assertion_survives_restart_and_preserves_unverified_receipt(context, monkeypatch, tmp_path):
    api, pki, _, clock, service, record = new_lifecycle(context, monkeypatch, tmp_path)
    assert (record.counter, record.revoked, record.subject, record.environment) == (0, False, "test-user", "development")
    assert record.opaque_receipt == b"TEST ONLY opaque unverified receipt"
    assert record.subject not in repr(record) and record.opaque_receipt.decode() not in repr(record)
    challenge = service.issue(subject="test-user", key_id=record.key_id, request=REQUEST)
    assert api.assertion_client_data(challenge) == client_message(challenge)
    assert challenge.request_sha256 == hashlib.sha256(REQUEST).hexdigest()
    assert len(base64.urlsafe_b64decode(challenge.nonce + "=")) == 32
    restarted = api.AppleAppAttestLifecycle(verifier=service.verifier,
        store=api.SqliteAppleAppAttestStore(tmp_path / "apple.sqlite"), clock=lambda: clock[0])
    result = restarted.verify(challenge.nonce, subject="test-user", key_id=record.key_id,
        request=REQUEST, assertion=signed(pki, challenge, counter=7))
    assert (result.counter, result.request_sha256, result.verified_at) == (7, hashlib.sha256(REQUEST).hexdigest(), NOW)
    assert restarted.lookup(subject="test-user", key_id=record.key_id).counter == 7
    rejected(api, lambda: service.verify(challenge.nonce, subject="test-user", key_id=record.key_id,
        request=REQUEST, assertion=signed(pki, challenge, counter=8)))
    second = restarted.issue(subject="test-user", key_id=record.key_id, request=REQUEST)
    rejected(api, lambda: restarted.verify(second.nonce, subject="test-user", key_id=record.key_id,
        request=REQUEST, assertion=signed(pki, second, counter=6)))
    restarted.verify(second.nonce, subject="test-user", key_id=record.key_id, request=REQUEST,
        assertion=signed(pki, second, counter=8))


@pytest.mark.parametrize("change", ["request", "subject", "key", "client_data", "rp", "counter_zero", "double_hash", "wrong_signer", "flags", "trailing", "unknown", "der", "oversize"])
def test_invalid_assertions_preserve_challenge_and_counter(context, monkeypatch, tmp_path, change):
    api, pki, _, _, service, record = new_lifecycle(context, monkeypatch, tmp_path)
    challenge = service.issue(subject="test-user", key_id=record.key_id, request=REQUEST)
    options = dict(subject="test-user", key_id=record.key_id, request=REQUEST, assertion=signed(pki, challenge))
    if change == "request": options["request"] += b"changed"
    if change == "subject": options["subject"] = "another-user"
    if change == "key": options["key_id"] = b64(b"K" * 32)
    if change == "client_data": options["assertion"] = signed(pki, challenge, message=b"unsigned challenge replacement")
    if change == "rp": options["assertion"] = signed(pki, challenge, auth=b"X"*32 + b"\0\0\0\0\x01")
    if change == "counter_zero": options["assertion"] = signed(pki, challenge, counter=0)
    if change == "double_hash": options["assertion"] = signed(pki, challenge, double_hash=True)
    if change == "wrong_signer": options["assertion"] = signed(pki, challenge, key=ec.generate_private_key(ec.SECP256R1()))
    if change == "flags": options["assertion"] = signed(pki, challenge, auth=hashlib.sha256(APP_ID.encode()).digest()+b"\x01\0\0\0\x01")
    if change == "trailing": options["assertion"] += b"\0"
    if change == "unknown": options["assertion"] = cbor({"signature": b"x", "authenticatorData": b"x", "claim": 1})
    if change == "der": options["assertion"] = cbor({"signature": b"0\x06\x02\x01\0\x02\x01\0", "authenticatorData": hashlib.sha256(APP_ID.encode()).digest()+b"\0\0\0\0\x01"})
    if change == "oversize": options["assertion"] = b"X" * 8193
    rejected(api, lambda: service.verify(challenge.nonce, **options))
    assert service.lookup(subject="test-user", key_id=record.key_id).counter == 0
    service.verify(challenge.nonce, subject="test-user", key_id=record.key_id, request=REQUEST, assertion=signed(pki, challenge))


@pytest.mark.parametrize("extensions", [None, {"apple_validation_category_01": b"\x04\0\0\0", "apple_bundle_version_01": "42"},
    {"apple_validation_category_01": b"\x03\0\0\0", "apple_bundle_version_01": "99"},
    {"apple_validation_category_01": 3, "apple_bundle_version_01": "42"},
    {"validationCategory": b"\x03\0\0\0", "bundleVersion": "42"}])
def test_assertions_enforce_signed_category_version_policy(context, monkeypatch, tmp_path, extensions):
    api, pki, _, _, service, record = new_lifecycle(context, monkeypatch, tmp_path, policy=True)
    challenge = service.issue(subject="test-user", key_id=record.key_id, request=REQUEST)
    rejected(api, lambda: service.verify(challenge.nonce, subject="test-user", key_id=record.key_id, request=REQUEST,
        assertion=signed(pki, challenge, extensions=extensions)))
    good = {"apple_validation_category_01": b"\x03\0\0\0", "apple_bundle_version_01": "43"}
    service.verify(challenge.nonce, subject="test-user", key_id=record.key_id, request=REQUEST,
        assertion=signed(pki, challenge, extensions=good))


def test_keys_and_challenges_are_scoped_and_globally_non_reassignable(context, monkeypatch, tmp_path):
    api, pki, initial, clock, service, record = new_lifecycle(context, monkeypatch, tmp_path)
    rejected(api, lambda: service.register(initial, pki.evidence(initial)), "APPLE_STATE_REJECTED")
    other_subject = replace(initial, subject="other-user", nonce="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA")
    rejected(api, lambda: service.register(other_subject, pki.evidence(other_subject)), "APPLE_STATE_REJECTED")
    for changes in [{"app_id":"other-app"}, {"apple_app_id":"ABCDEFGHIJ.co.other.app"}, {"environment":"production"}]:
        opts = dict(app_id="test-app", apple_app_id=APP_ID, platform="ios", environment="development", clock=lambda: NOW)
        opts.update(changes)
        from appguard.providers.apple import AppleAppAttestVerifier
        other = api.AppleAppAttestLifecycle(verifier=AppleAppAttestVerifier(**opts), store=service.store, clock=lambda: NOW)
        rejected(api, lambda: other.issue(subject="test-user", key_id=record.key_id, request=REQUEST))
    assert service.lookup(subject="other-user", key_id=record.key_id) is None


def test_expiry_limit_and_revocation_never_reset_counter_or_key_association(context, monkeypatch, tmp_path):
    api, pki, initial, clock, service, record = new_lifecycle(context, monkeypatch, tmp_path, max_pending=1, challenge_ttl=2)
    challenge = service.issue(subject="test-user", key_id=record.key_id, request=REQUEST)
    rejected(api, lambda: service.issue(subject="test-user", key_id=record.key_id, request=REQUEST), "APPLE_STORE_UNAVAILABLE")
    clock[0] = NOW + 2
    rejected(api, lambda: service.verify(challenge.nonce, subject="test-user", key_id=record.key_id, request=REQUEST, assertion=signed(pki, challenge)))
    next_challenge = service.issue(subject="test-user", key_id=record.key_id, request=REQUEST)
    assert service.revoke(subject="test-user", key_id=record.key_id) is True
    rejected(api, lambda: service.verify(next_challenge.nonce, subject="test-user", key_id=record.key_id, request=REQUEST,
        assertion=signed(pki, next_challenge)))
    rejected(api, lambda: service.issue(subject="test-user", key_id=record.key_id, request=REQUEST))
    rejected(api, lambda: service.register(initial, pki.evidence(initial)), "APPLE_STATE_REJECTED")
    restarted = api.AppleAppAttestLifecycle(verifier=service.verifier, store=api.SqliteAppleAppAttestStore(tmp_path/"apple.sqlite"), clock=lambda: clock[0])
    assert restarted.lookup(subject="test-user", key_id=record.key_id).revoked is True


def _child_attempt(path, key_id, challenge_nonce, assertion, output):
    # No private/test trust override is required to use a previously registered key.
    from appguard.providers.apple import AppleAppAttestVerifier
    from appguard.providers.apple_lifecycle import AppleAppAttestLifecycle, SqliteAppleAppAttestStore, AppleLifecycleError
    backend = AppleAppAttestVerifier(app_id="test-app", apple_app_id=APP_ID, platform="ios", environment="development")
    service = AppleAppAttestLifecycle(verifier=backend, store=SqliteAppleAppAttestStore(path), clock=lambda: NOW)
    try:
        output.put(service.verify(challenge_nonce, subject="test-user", key_id=key_id, request=REQUEST, assertion=assertion).counter)
    except AppleLifecycleError as error:
        output.put(error.code)


def test_independent_processes_atomically_consume_one_challenge(context, monkeypatch, tmp_path):
    api, pki, _, _, service, record = new_lifecycle(context, monkeypatch, tmp_path)
    challenge = service.issue(subject="test-user", key_id=record.key_id, request=REQUEST)
    process_context = multiprocessing.get_context("spawn")
    output = process_context.Queue()
    children = [process_context.Process(target=_child_attempt, args=(str(tmp_path/"apple.sqlite"),record.key_id,challenge.nonce,signed(pki,challenge,counter=10),output)) for _ in range(6)]
    for child in children: child.start()
    for child in children:
        child.join(15)
        assert child.exitcode == 0
    values = [output.get(timeout=2) for _ in children]
    assert values.count(10) == 1 and values.count("APPLE_ASSERTION_REJECTED") == 5
    assert service.lookup(subject="test-user", key_id=record.key_id).counter == 10


def test_concurrent_distinct_challenges_cannot_accept_same_counter(context, monkeypatch, tmp_path):
    api, pki, _, _, service, record = new_lifecycle(context, monkeypatch, tmp_path)
    challenges = [service.issue(subject="test-user", key_id=record.key_id, request=REQUEST) for _ in range(8)]
    def run(challenge):
        try:
            return service.verify(challenge.nonce, subject="test-user", key_id=record.key_id, request=REQUEST, assertion=signed(pki,challenge,counter=5)).counter
        except api.AppleLifecycleError as error: return error.code
    with ThreadPoolExecutor(max_workers=8) as pool: values = list(pool.map(run,challenges))
    assert values.count(5)==1 and values.count("APPLE_ASSERTION_REJECTED")==7
    remaining = challenges[values.index("APPLE_ASSERTION_REJECTED")]
    service.verify(remaining.nonce, subject="test-user", key_id=record.key_id, request=REQUEST, assertion=signed(pki,remaining,counter=6))


def test_store_rejects_unrelated_private_database_and_insecure_file(context, monkeypatch, tmp_path):
    api = importlib.import_module("appguard.providers.apple_lifecycle")
    unrelated = tmp_path/"unrelated.sqlite"
    with sqlite3.connect(unrelated) as db: db.execute("CREATE TABLE private_user_data (secret TEXT)")
    unrelated.chmod(0o600)
    before=unrelated.read_bytes()
    rejected(api, lambda: api.SqliteAppleAppAttestStore(unrelated), "APPLE_STORE_UNAVAILABLE")
    assert unrelated.read_bytes()==before
    insecure=tmp_path/"insecure.sqlite"; insecure.touch(mode=0o644)
    rejected(api, lambda: api.SqliteAppleAppAttestStore(insecure), "APPLE_STORE_UNAVAILABLE")


def test_store_rejects_file_replacement_or_removal_without_recreating(context, monkeypatch, tmp_path):
    api, pki, _, _, service, record = new_lifecycle(context, monkeypatch, tmp_path)
    path=tmp_path/"apple.sqlite"
    path.rename(tmp_path/"original.sqlite")
    rejected(api, lambda: service.issue(subject="test-user", key_id=record.key_id, request=REQUEST), "APPLE_STORE_UNAVAILABLE")
    assert not path.exists()
    other=tmp_path/"other.sqlite"; api.SqliteAppleAppAttestStore(other); other.rename(path)
    rejected(api, lambda: service.lookup(subject="test-user", key_id=record.key_id), "APPLE_STORE_UNAVAILABLE")


def test_error_callbacks_cannot_retain_private_exception_context(context, monkeypatch, tmp_path):
    api, pki, _, _, service, record = new_lifecycle(context, monkeypatch, tmp_path)
    def private_clock(): raise RuntimeError("PRIVATE_CLOCK_MATERIAL")
    service._clock=private_clock
    rejected(api, lambda: service.issue(subject="test-user", key_id=record.key_id, request=REQUEST), "APPLE_ASSERTION_REJECTED")


def test_counter_update_and_challenge_consumption_rollback_together(context, monkeypatch, tmp_path):
    api, pki, _, _, service, record = new_lifecycle(context, monkeypatch, tmp_path)
    challenge=service.issue(subject="test-user", key_id=record.key_id, request=REQUEST)
    with sqlite3.connect(tmp_path/"apple.sqlite") as db:
        db.execute("CREATE TRIGGER injected_storage_failure BEFORE DELETE ON apple_assertion_challenges BEGIN SELECT RAISE(ABORT, 'PRIVATE_DATABASE_DETAIL'); END")
    rejected(api, lambda: service.verify(challenge.nonce, subject="test-user", key_id=record.key_id,
        request=REQUEST, assertion=signed(pki,challenge,counter=25)), "APPLE_STORE_UNAVAILABLE")
    assert service.lookup(subject="test-user", key_id=record.key_id).counter == 0
    with sqlite3.connect(tmp_path/"apple.sqlite") as db: db.execute("DROP TRIGGER injected_storage_failure")
    service.verify(challenge.nonce, subject="test-user", key_id=record.key_id,
        request=REQUEST, assertion=signed(pki,challenge,counter=25))


def test_expiry_rechecked_after_final_write_lock_wait(context, monkeypatch, tmp_path):
    import threading
    from appguard.providers import apple_lifecycle as implementation
    api, pki, _, clock, service, record = new_lifecycle(context, monkeypatch, tmp_path)
    challenge=service.issue(subject="test-user", key_id=record.key_id, request=REQUEST)
    crypto_done, continue_to_finish, attempting_lock = (threading.Event() for _ in range(3))
    original=implementation._verify_assertion
    def pause_after_crypto(*args):
        result=original(*args)
        crypto_done.set()
        assert continue_to_finish.wait(5)
        return result
    real_connect=sqlite3.connect
    def traced_connect(*args,**kwargs):
        db=real_connect(*args,**kwargs)
        def trace(statement):
            if statement=="BEGIN IMMEDIATE" and continue_to_finish.is_set():
                attempting_lock.set()
        db.set_trace_callback(trace)
        return db
    monkeypatch.setattr(implementation,"_verify_assertion",pause_after_crypto)
    monkeypatch.setattr(sqlite3,"connect",traced_connect)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future=pool.submit(service.verify,challenge.nonce,subject="test-user",key_id=record.key_id,
            request=REQUEST,assertion=signed(pki,challenge))
        assert crypto_done.wait(5)
        with real_connect(tmp_path/"apple.sqlite",isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            continue_to_finish.set()
            assert attempting_lock.wait(5)
            assert not future.done()
            clock[0]=challenge.expires
            db.execute("COMMIT")
        rejected(api,lambda:future.result(timeout=5))
    assert service.lookup(subject="test-user", key_id=record.key_id).counter == 0


def test_revocation_between_crypto_and_commit_rejects(context, monkeypatch, tmp_path):
    from appguard.providers import apple_lifecycle as implementation
    api, pki, _, _, service, record = new_lifecycle(context, monkeypatch, tmp_path)
    challenge=service.issue(subject="test-user", key_id=record.key_id, request=REQUEST)
    original=implementation._verify_assertion
    def revoke_after_verify(*args):
        result=original(*args)
        assert service.revoke(subject="test-user",key_id=record.key_id)
        return result
    monkeypatch.setattr(implementation,"_verify_assertion",revoke_after_verify)
    rejected(api, lambda: service.verify(challenge.nonce, subject="test-user", key_id=record.key_id,
        request=REQUEST, assertion=signed(pki,challenge)))
    assert service.lookup(subject="test-user", key_id=record.key_id).counter == 0


def test_revoke_subject_cancels_all_devices_and_preserves_other_subject(context, monkeypatch, tmp_path):
    api, pki, initial, _, service, first = new_lifecycle(context, monkeypatch, tmp_path)
    second_pki=SyntheticPKI()
    second_pki.root, second_pki.inter, second_pki.inter_key = pki.root,pki.inter,pki.inter_key
    another = replace(initial, nonce="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA")
    second=service.register(another,second_pki.evidence(another))
    third_pki=SyntheticPKI()
    third_pki.root, third_pki.inter, third_pki.inter_key = pki.root,pki.inter,pki.inter_key
    third_initial=replace(initial,subject="other-user",nonce="CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA")
    third=service.register(third_initial,third_pki.evidence(third_initial))
    pending=service.issue(subject="test-user",key_id=second.key_id,request=REQUEST)
    assert service.revoke_subject(subject="test-user")==2
    assert service.revoke_subject(subject="test-user")==0
    for record in [first,second]:
        rejected(api,lambda: service.issue(subject="test-user",key_id=record.key_id,request=REQUEST))
    rejected(api,lambda: service.verify(pending.nonce,subject="test-user",key_id=second.key_id,
        request=REQUEST,assertion=signed(second_pki,pending)))
    ok=service.issue(subject="other-user",key_id=third.key_id,request=REQUEST)
    service.verify(ok.nonce,subject="other-user",key_id=third.key_id,request=REQUEST,assertion=signed(third_pki,ok))


def test_counter_exhaustion_never_wraps_or_resets(context, monkeypatch, tmp_path):
    api, pki, _, _, service, record = new_lifecycle(context, monkeypatch, tmp_path)
    last=service.issue(subject="test-user",key_id=record.key_id,request=REQUEST)
    service.verify(last.nonce,subject="test-user",key_id=record.key_id,request=REQUEST,assertion=signed(pki,last,counter=0xffffffff))
    next_challenge=service.issue(subject="test-user",key_id=record.key_id,request=REQUEST)
    for counter in [0,1,0xffffffff]:
        rejected(api,lambda: service.verify(next_challenge.nonce,subject="test-user",key_id=record.key_id,
            request=REQUEST,assertion=signed(pki,next_challenge,counter=counter)))
    assert service.lookup(subject="test-user",key_id=record.key_id).counter==0xffffffff


@pytest.mark.parametrize("mutation",["auth_trailing","auth_short","auth_oversize","signature_trailing","duplicate","indefinite","nonminimal"])
def test_strict_bounded_cbor_der_authenticator_shapes(context,monkeypatch,tmp_path,mutation):
    api,pki,_,_,service,record=new_lifecycle(context,monkeypatch,tmp_path)
    challenge=service.issue(subject="test-user",key_id=record.key_id,request=REQUEST)
    auth=hashlib.sha256(APP_ID.encode()).digest()+b"\0\0\0\0\1"
    if mutation=="auth_trailing": raw=signed(pki,challenge,auth=auth+cbor({}))
    elif mutation=="auth_short": raw=signed(pki,challenge,auth=auth[:-1])
    elif mutation=="auth_oversize": raw=signed(pki,challenge,auth=auth+b"X"*4096)
    else:
        valid=signed(pki,challenge)
        # Independent fixture parser isn't used; only fetch signature via the
        # known independent key signing recipe for malformed container fixtures.
        digest=hashlib.sha256(auth+hashlib.sha256(client_message(challenge)).digest()).digest()
        signature=pki.key.sign(digest,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        if mutation=="signature_trailing": raw=cbor({"signature":signature+b"\0","authenticatorData":auth})
        elif mutation=="duplicate": raw=b"\xa3"+cbor("signature")+cbor(signature)+cbor("signature")+cbor(signature)+cbor("authenticatorData")+cbor(auth)
        elif mutation=="indefinite": raw=b"\xbf"+valid[1:]+b"\xff"
        else: raw=b"\xb8\x02"+valid[1:]
    rejected(api,lambda:service.verify(challenge.nonce,subject="test-user",key_id=record.key_id,request=REQUEST,assertion=raw))
    service.verify(challenge.nonce,subject="test-user",key_id=record.key_id,request=REQUEST,assertion=signed(pki,challenge))


def test_ecdsa_high_s_and_low_s_both_verify_without_double_hash(context,monkeypatch,tmp_path):
    api,pki,_,_,service,record=new_lifecycle(context,monkeypatch,tmp_path)
    order=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    for counter,high in [(1,False),(2,True)]:
        challenge=service.issue(subject="test-user",key_id=record.key_id,request=REQUEST)
        auth=hashlib.sha256(APP_ID.encode()).digest()+b"\0"+counter.to_bytes(4,"big")
        digest=hashlib.sha256(auth+hashlib.sha256(client_message(challenge)).digest()).digest()
        r,s=utils.decode_dss_signature(pki.key.sign(digest,ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
        s=max(s,order-s) if high else min(s,order-s)
        raw=cbor({"signature":utils.encode_dss_signature(r,s),"authenticatorData":auth})
        service.verify(challenge.nonce,subject="test-user",key_id=record.key_id,request=REQUEST,assertion=raw)


@pytest.mark.parametrize("settings",[{"challenge_ttl":True},{"challenge_ttl":0},{"challenge_ttl":301},{"max_pending":True},
    {"max_pending":0},{"max_pending":1000001},{"clock":3},{"verifier":object()},{"store":object()}])
def test_lifecycle_configuration_is_explicit_and_bounded(context,monkeypatch,tmp_path,settings):
    api,pki,_,_,service,_=new_lifecycle(context,monkeypatch,tmp_path)
    opts=dict(verifier=service.verifier,store=service.store)
    opts.update(settings)
    rejected(api,lambda:api.AppleAppAttestLifecycle(**opts),"APPLE_LIFECYCLE_CONFIGURATION")


def test_bounded_random_assertions_cannot_escape_or_consume_challenge(context,monkeypatch,tmp_path):
    import random
    api,pki,_,_,service,record=new_lifecycle(context,monkeypatch,tmp_path)
    challenge=service.issue(subject="test-user",key_id=record.key_id,request=REQUEST)
    rng=random.Random(1973)
    for _ in range(100):
        raw=rng.randbytes(rng.randrange(1,512))
        rejected(api,lambda:service.verify(challenge.nonce,subject="test-user",key_id=record.key_id,request=REQUEST,assertion=raw))
    service.verify(challenge.nonce,subject="test-user",key_id=record.key_id,request=REQUEST,assertion=signed(pki,challenge))


def test_global_initial_challenge_cannot_bind_multiple_attested_keys(context,monkeypatch,tmp_path):
    api,pki,initial,_,service,record=new_lifecycle(context,monkeypatch,tmp_path)
    another=SyntheticPKI()
    another.root,another.inter,another.inter_key=pki.root,pki.inter,pki.inter_key
    rejected(api,lambda:service.register(initial,another.evidence(initial)),"APPLE_STATE_REJECTED")


def test_register_rechecks_verdict_expiry_inside_writer_lock(context,monkeypatch,tmp_path):
    api,pki,initial,clock,service,record=new_lifecycle(context,monkeypatch,tmp_path)
    another=replace(initial,nonce="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA")
    other_pki=SyntheticPKI()
    other_pki.root,other_pki.inter,other_pki.inter_key=pki.root,pki.inter,pki.inter_key
    original=service.verifier.verify_initial
    def expire_after_verification(*args):
        verified=original(*args)
        clock[0]=verified.verdict.expires
        return verified
    monkeypatch.setattr(service.verifier,"verify_initial",expire_after_verification)
    rejected(api,lambda:service.register(another,other_pki.evidence(another)),"APPLE_STATE_REJECTED")


def test_no_network_on_construction_or_assertion(context,monkeypatch,tmp_path):
    import socket
    def forbidden(*args,**kwargs): raise AssertionError("unexpected network")
    monkeypatch.setattr(socket,"socket",forbidden)
    monkeypatch.setattr(socket,"create_connection",forbidden)
    api,pki,_,_,service,record=new_lifecycle(context,monkeypatch,tmp_path)
    challenge=service.issue(subject="test-user",key_id=record.key_id,request=REQUEST)
    service.verify(challenge.nonce,subject="test-user",key_id=record.key_id,request=REQUEST,assertion=signed(pki,challenge))


@pytest.mark.parametrize("shape",["symlink","hardlink","directory"])
def test_store_rejects_aliases_and_nonregular_paths(context,monkeypatch,tmp_path,shape):
    api=importlib.import_module("appguard.providers.apple_lifecycle")
    path=tmp_path/"alias.sqlite"
    target=tmp_path/"target.sqlite"
    target.touch(mode=0o600)
    if shape=="symlink": path.symlink_to(target)
    elif shape=="hardlink": path.hardlink_to(target)
    else: path.mkdir()
    rejected(api,lambda:api.SqliteAppleAppAttestStore(path),"APPLE_STORE_UNAVAILABLE")
    assert target.read_bytes()==b""


@pytest.mark.parametrize("column,value",[("counter",-1),("counter",4294967296),("revoked",9),
    ("public_der",b"malformed DER"),("opaque_receipt",b""),("initial_hash","not-a-hash"),("category",10)])
def test_corrupt_persistent_key_state_fails_closed(context,monkeypatch,tmp_path,column,value):
    api,pki,_,_,service,record=new_lifecycle(context,monkeypatch,tmp_path)
    with sqlite3.connect(tmp_path/"apple.sqlite") as db:
        db.execute("PRAGMA ignore_check_constraints=ON")
        db.execute(f"UPDATE apple_keys SET {column}=? WHERE kid=?",(value,record.key_id))
    rejected(api,lambda:service.issue(subject="test-user",key_id=record.key_id,request=REQUEST),"APPLE_STORE_UNAVAILABLE")


def test_import_and_constructor_do_not_open_network_sockets(tmp_path):
    import subprocess,sys
    code='''
import socket,sys

def forbidden(*args,**kwargs): raise AssertionError("network on import/construction")
socket.socket=forbidden
socket.create_connection=forbidden
from appguard.providers.apple import AppleAppAttestVerifier
from appguard.providers.apple_lifecycle import AppleAppAttestLifecycle,SqliteAppleAppAttestStore
backend=AppleAppAttestVerifier(app_id="test-app",apple_app_id="ABCDEFGHIJ.co.example.mobile",platform="ios",environment="production")
AppleAppAttestLifecycle(verifier=backend,store=SqliteAppleAppAttestStore(sys.argv[1]))
print("OFFLINE_IMPORT_CONSTRUCTION_OK")
'''
    result=subprocess.run([sys.executable,"-c",code,str(tmp_path/"import.sqlite")],text=True,capture_output=True,timeout=10)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=="OFFLINE_IMPORT_CONSTRUCTION_OK"


@pytest.mark.parametrize("request_value",[None,bytearray(b"operation"),b"",b"X"*1048577],ids=["none","mutable","empty","oversize"])
def test_request_binding_rejects_unbounded_or_nonbyte_inputs(context,monkeypatch,tmp_path,request_value):
    api,pki,_,_,service,record=new_lifecycle(context,monkeypatch,tmp_path,max_pending=1)
    rejected(api,lambda:service.issue(subject="test-user",key_id=record.key_id,request=request_value))
    service.issue(subject="test-user",key_id=record.key_id,request=REQUEST)


@pytest.mark.parametrize("subject,key_id",[("",None),("test-user","unencoded"),("test-user",b64(b"X"*31)),
    ("test-user",b64(b"X"*32).rstrip("=")),("test-user",b64(b"X"*32)+"\n"),("private\nsubject",b64(b"X"*32))])
def test_untrusted_scope_values_reject_without_consuming_capacity(context,monkeypatch,tmp_path,subject,key_id):
    api,pki,_,_,service,record=new_lifecycle(context,monkeypatch,tmp_path,max_pending=1)
    rejected(api,lambda:service.issue(subject=subject,key_id=key_id,request=REQUEST))
    service.issue(subject="test-user",key_id=record.key_id,request=REQUEST)


def test_known_key_cannot_silently_downgrade_signed_extension_policy(context,monkeypatch,tmp_path):
    api,pki,_,_,service,record=new_lifecycle(context,monkeypatch,tmp_path,policy=True)
    from appguard.providers.apple import AppleAppAttestVerifier
    legacy=api.AppleAppAttestLifecycle(verifier=AppleAppAttestVerifier(app_id="test-app",apple_app_id=APP_ID,
        platform="ios",environment="development",clock=lambda:NOW),store=service.store,clock=lambda:NOW)
    challenge=legacy.issue(subject="test-user",key_id=record.key_id,request=REQUEST)
    rejected(api,lambda:legacy.verify(challenge.nonce,subject="test-user",key_id=record.key_id,
        request=REQUEST,assertion=signed(pki,challenge)))
    service.verify(challenge.nonce,subject="test-user",key_id=record.key_id,request=REQUEST,
        assertion=signed(pki,challenge,extensions={"apple_validation_category_01":b"\x03\0\0\0","apple_bundle_version_01":"42"}))


def test_client_data_known_literal_wire_vector():
    api=importlib.import_module("appguard.providers.apple_lifecycle")
    challenge=api.AppleAssertionChallenge("app","ABCDEFGHIJ.co.example.mobile","production","user",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",1792472400,1792472460)
    expected=(b"appguard-apple-assertion-v0\n"
        b"app-id: app\n"
        b"apple-app-id: ABCDEFGHIJ.co.example.mobile\n"
        b"environment: production\n"
        b"subject: user\n"
        b"key-id: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        b"request-sha256: 2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881\n"
        b"challenge: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        b"issued-at: 1792472400\nexpires: 1792472460")
    assert api.assertion_client_data(challenge)==expected
