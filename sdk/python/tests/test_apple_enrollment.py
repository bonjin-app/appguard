"""Atomic enrollment/Apple/verified-receipt tests with independent synthetic PKI."""
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime,timedelta,timezone
import hashlib
import importlib
import multiprocessing
import sqlite3
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,utils

from appguard.enrollment import EnrollmentService,EnrollmentError,SqliteEnrollmentStore
from appguard.enrollment_types import enrollment_message
from test_apple_provider import APP_ID,NOW,SyntheticPKI,verifier
from test_apple_receipts import setup as receipt_setup,payload,stamp,Response,connection_factory
from test_apple_lifecycle import REQUEST,signed


def proof(key,challenge):
    r,s=utils.decode_dss_signature(key.sign(enrollment_message(challenge),ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32,"big")+s.to_bytes(32,"big")


@pytest.fixture
def combined(tmp_path,monkeypatch,receipt_setup):
    api=importlib.import_module("appguard.providers.apple_enrollment")
    receipt_module,_,sign,_,receipt_root,*_=receipt_setup
    pki=SyntheticPKI()
    backend=verifier(pki,monkeypatch)
    clock=[NOW]
    backend._clock=lambda:clock[0]
    store=api.SqliteAppleEnrollmentStore(tmp_path/"combined.sqlite")
    service=api.AppleEnrollmentService(store=store,verifier=backend,clock=lambda:clock[0])
    key=ec.generate_private_key(ec.SECP256R1())
    pem=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    def issue(kid="request-key",subject="test-user"):
        return service.issue(app_id="test-app",subject=subject,key_id=kid,origin="https://api.example.test",public_key_pem=pem)
    def receipt(challenge,kind="ATTEST",changes=None):
        now=datetime.fromtimestamp(clock[0],timezone.utc)
        fields={2:APP_ID.encode(),4:hashlib.sha256(enrollment_message(challenge)).digest(),7:b"development",
            12:stamp(now-timedelta(seconds=1)),21:stamp(now+timedelta(days=30))}
        if kind=="RECEIPT": fields.update({19:stamp(now+timedelta(seconds=1)),17:b"5"})
        fields.update(changes or {})
        public=pki.key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        return sign(payload(public,kind=kind,changes=fields))
    def evidence(challenge,changes=None,raw_receipt=None):
        raw=receipt(challenge,changes=changes) if raw_receipt is None else raw_receipt
        return pki.evidence(challenge,top_change=lambda obj:obj["attStmt"].update(receipt=raw))
    return api,service,store,pki,key,clock,issue,receipt,evidence,receipt_module,receipt_root


def finish(service,challenge,key,evidence):
    return service.complete(challenge.nonce,app_id=challenge.app_id,subject=challenge.subject,proof=proof(key,challenge),evidence=evidence)


def reject(operation,code):
    with pytest.raises(EnrollmentError,match=f"^{code}$") as caught: operation()
    assert caught.value.__cause__ is None and caught.value.__context__ is None


def assert_empty(store,challenge):
    assert store.pending(challenge.nonce)==challenge
    assert store.lookup(challenge.app_id,challenge.subject,challenge.key_id) is None
    with sqlite3.connect(store.path) as db:
        for table in ["appguard_keys","apple_keys","apple_enrollment_links","apple_verified_receipts"]:
            assert db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]==0


def test_atomic_enrollment_persists_all_state_and_assertions_after_restart(combined):
    api,service,store,pki,key,clock,issue,receipt,evidence,*_=combined
    challenge=issue()
    credential=finish(service,challenge,key,evidence(challenge))
    assert credential.attestation=="verified" and credential.provider=="apple"
    assert store.pending(challenge.nonce) is None
    apple_key=store.apple_key("test-app","test-user","request-key")
    saved=store.verified_receipt("test-app","test-user",apple_key.key_id)
    assert saved.receipt_type=="ATTEST" and saved.fresh
    assert saved.client_hash==hashlib.sha256(enrollment_message(challenge)).digest()
    assert saved.receipt_sha256==hashlib.sha256(saved.receipt).hexdigest()
    assert apple_key.counter==0 and not apple_key.revoked
    assert "test-user" not in repr(saved) and saved.receipt.hex() not in repr(saved)
    reopened=api.SqliteAppleEnrollmentStore(store.path)
    restarted=api.AppleEnrollmentService(store=reopened,verifier=service.verifier,clock=lambda:clock[0])
    assert reopened.lookup("test-app","test-user","request-key")==credential
    assert reopened.verified_receipt("test-app","test-user",apple_key.key_id)==saved
    request_challenge=restarted.assertions.issue(subject="test-user",key_id=apple_key.key_id,request=REQUEST)
    assert restarted.assertions.verify(request_challenge.nonce,subject="test-user",key_id=apple_key.key_id,
        request=REQUEST,assertion=signed(pki,request_challenge)).counter==1
    reject(lambda:finish(service,challenge,key,evidence(challenge)),"CHALLENGE_REJECTED")


@pytest.mark.parametrize("changes",[{4:b"wrong hash"},{7:b"production"},{2:b"ABCDEFGHIJ.wrong"},{3:b"bad key"},{6:b"RECEIPT"},
    {12:stamp(datetime.fromtimestamp(NOW-301,timezone.utc))}])
def test_wrong_receipt_never_activates_request_or_apple_key(combined,changes):
    _,service,store,_,key,_,issue,_,evidence,*_=combined
    challenge=issue()
    reject(lambda:finish(service,challenge,key,evidence(challenge,changes=changes)),"ATTESTATION_UNAVAILABLE")
    assert_empty(store,challenge)
    finish(service,challenge,key,evidence(challenge))


@pytest.mark.parametrize("stage",["appguard_keys","apple_keys","apple_enrollment_links","apple_verified_receipts","challenge_delete","commit"])
def test_storage_failure_rolls_back_every_initial_association(combined,stage,monkeypatch):
    _,service,store,_,key,_,issue,_,evidence,*_=combined
    challenge=issue()
    raw=evidence(challenge)
    if stage!="commit":
        trigger=("BEFORE DELETE ON appguard_challenges" if stage=="challenge_delete" else f"BEFORE INSERT ON {stage}")
        with sqlite3.connect(store.path) as db:
            db.execute(f"CREATE TRIGGER injected_failure {trigger} BEGIN SELECT RAISE(ABORT,'PRIVATE_SQL_DETAIL'); END")
        reject(lambda:finish(service,challenge,key,raw),"STORE_UNAVAILABLE")
        assert_empty(store,challenge)
        with sqlite3.connect(store.path) as db: db.execute("DROP TRIGGER injected_failure")
    else:
        real_connect=sqlite3.connect
        class Connection(sqlite3.Connection):
            def execute(self,sql,parameters=()):
                if sql=="COMMIT": raise sqlite3.OperationalError("PRIVATE_COMMIT_DETAIL")
                return super().execute(sql,parameters)
        with monkeypatch.context() as patch:
            patch.setattr(sqlite3,"connect",lambda *a,**kw:real_connect(*a,**kw,factory=Connection))
            reject(lambda:finish(service,challenge,key,raw),"STORE_UNAVAILABLE")
        assert_empty(store,challenge)
    finish(service,challenge,key,raw)


def test_generic_service_or_standalone_apple_registration_cannot_bypass_combined_commit(combined):
    _,service,store,pki,key,clock,issue,_,evidence,*_=combined
    challenge=issue()
    generic=EnrollmentService(store,profile="basic",clock=lambda:clock[0])
    reject(lambda:generic.complete(challenge.nonce,app_id="test-app",subject="test-user",proof=proof(key,challenge)),"ATTESTATION_REQUIRED")
    assert_empty(store,challenge)
    from appguard.providers.apple_lifecycle import AppleAppAttestLifecycle,AppleLifecycleError
    lifecycle=AppleAppAttestLifecycle(verifier=service.verifier,store=store.apple,clock=lambda:clock[0])
    with pytest.raises(AppleLifecycleError,match="APPLE_STATE_REJECTED"):
        lifecycle.register(challenge,pki.evidence(challenge))
    assert_empty(store,challenge)
    finish(service,challenge,key,evidence(challenge))


def test_reused_apple_key_does_not_leave_second_request_credential(combined):
    _,service,store,_,key,_,issue,_,evidence,*_=combined
    first=issue()
    finish(service,first,key,evidence(first))
    second=issue("another-request","other-user")
    reject(lambda:finish(service,second,key,evidence(second)),"ATTESTATION_REJECTED")
    assert store.pending(second.nonce)==second
    assert store.lookup("test-app","other-user","another-request") is None
    assert store.apple_key("test-app","other-user","another-request") is None


def test_initial_completion_rechecks_time_after_receipt_verification(combined,monkeypatch):
    api,service,store,_,key,clock,issue,_,evidence,*_=combined
    challenge=issue()
    raw=evidence(challenge)
    original=api.AppleReceiptVerifier.verify
    def slow(self,*a,**kw):
        result=original(self,*a,**kw)
        clock[0]=challenge.expires
        return result
    monkeypatch.setattr(api.AppleReceiptVerifier,"verify",slow)
    reject(lambda:finish(service,challenge,key,raw),"CHALLENGE_REJECTED")
    assert_empty(store,challenge)


def test_subject_revocation_during_cms_work_cancels_all_initial_state(combined,monkeypatch):
    api,service,store,_,key,_,issue,_,evidence,*_=combined
    challenge=issue()
    raw=evidence(challenge)
    original=api.AppleReceiptVerifier.verify
    def revoke(self,*a,**kw):
        result=original(self,*a,**kw)
        assert store.revoke_subject("test-app","test-user").cancelled_challenges==1
        return result
    monkeypatch.setattr(api.AppleReceiptVerifier,"verify",revoke)
    reject(lambda:finish(service,challenge,key,raw),"CHALLENGE_REJECTED")
    assert store.pending(challenge.nonce) is None
    assert store.lookup("test-app","test-user","request-key") is None
    assert store.apple_key("test-app","test-user","request-key") is None


@pytest.mark.parametrize("direction",["request","apple","subject"])
def test_revocation_synchronizes_both_key_types_and_cancels_assertions(combined,direction):
    _,service,store,pki,key,_,issue,_,evidence,*_=combined
    challenge=issue()
    finish(service,challenge,key,evidence(challenge))
    apple_key=store.apple_key("test-app","test-user","request-key")
    pending=service.assertions.issue(subject="test-user",key_id=apple_key.key_id,request=REQUEST)
    if direction=="request": assert store.revoke("test-app","test-user","request-key")
    elif direction=="apple": assert service.assertions.revoke(subject="test-user",key_id=apple_key.key_id)
    else: assert store.revoke_subject("test-app","test-user").revoked_keys==1
    assert store.lookup("test-app","test-user","request-key").key.revoked
    assert store.apple_key("test-app","test-user","request-key").revoked
    from appguard.providers.apple_lifecycle import AppleLifecycleError
    with pytest.raises(AppleLifecycleError):
        service.assertions.verify(pending.nonce,subject="test-user",key_id=apple_key.key_id,request=REQUEST,assertion=signed(pki,pending))


def test_combined_store_rejects_existing_standalone_databases_without_mutation(tmp_path):
    api=importlib.import_module("appguard.providers.apple_enrollment")
    from appguard.providers.apple_store import SqliteAppleAppAttestStore
    for cls,name in [(SqliteEnrollmentStore,"enrollment"),(SqliteAppleAppAttestStore,"apple")]:
        path=tmp_path/(name+".sqlite")
        cls(path)
        before=path.read_bytes()
        reject(lambda:api.SqliteAppleEnrollmentStore(path),"STORE_UNAVAILABLE")
        assert path.read_bytes()==before


def _complete_child(path,attestation_root,receipt_root,nonce,raw_proof,raw_evidence,output,crash=False):
    import os
    import appguard.providers.apple as initial_module
    import appguard.providers.apple_receipts as receipt_module
    from appguard.providers.apple_enrollment import SqliteAppleEnrollmentStore,AppleEnrollmentService
    initial_module._trusted_root=lambda:x509.load_der_x509_certificate(attestation_root)
    receipt_module._receipt_root=lambda:x509.load_der_x509_certificate(receipt_root)
    store=SqliteAppleEnrollmentStore(path)
    backend=initial_module.AppleAppAttestVerifier(app_id="test-app",apple_app_id=APP_ID,platform="ios",environment="development",clock=lambda:NOW)
    service=AppleEnrollmentService(store=store,verifier=backend,clock=lambda:NOW)
    if crash:
        real_connect=sqlite3.connect
        class Connection(sqlite3.Connection):
            def execute(self,sql,parameters=()):
                result=super().execute(sql,parameters)
                if sql.startswith("INSERT INTO apple_verified_receipts"):
                    os._exit(73)
                return result
        sqlite3.connect=lambda *a,**kw:real_connect(*a,**kw,factory=Connection)
    try:
        service.complete(nonce,app_id="test-app",subject="test-user",proof=raw_proof,evidence=raw_evidence)
        output.put("ENROLLED")
    except EnrollmentError as error:
        output.put(error.code)


def test_independent_processes_commit_one_complete_association(combined):
    _,service,store,pki,key,_,issue,_,evidence,_,receipt_root=combined
    challenge=issue()
    ctx=multiprocessing.get_context("spawn")
    output=ctx.Queue()
    args=(store.path,pki.root.public_bytes(serialization.Encoding.DER),receipt_root.public_bytes(serialization.Encoding.DER),
        challenge.nonce,proof(key,challenge),evidence(challenge),output)
    children=[ctx.Process(target=_complete_child,args=args) for _ in range(4)]
    for child in children: child.start()
    for child in children:
        child.join(15)
        assert child.exitcode==0
    results=[output.get(timeout=2) for _ in children]
    assert results.count("ENROLLED")==1 and results.count("CHALLENGE_REJECTED")==3
    record=store.apple_key("test-app","test-user","request-key")
    assert store.verified_receipt("test-app","test-user",record.key_id) is not None
    assert store.pending(challenge.nonce) is None


def test_process_death_before_commit_recovers_without_partial_activation(combined):
    _,service,store,pki,key,_,issue,_,evidence,_,receipt_root=combined
    challenge=issue()
    raw=evidence(challenge)
    ctx=multiprocessing.get_context("spawn")
    output=ctx.Queue()
    child=ctx.Process(target=_complete_child,args=(store.path,pki.root.public_bytes(serialization.Encoding.DER),
        receipt_root.public_bytes(serialization.Encoding.DER),challenge.nonce,proof(key,challenge),raw,output,True))
    child.start()
    child.join(15)
    assert child.exitcode==73
    assert_empty(store,challenge)
    finish(service,challenge,key,raw)
    assert store.apple_key("test-app","test-user","request-key") is not None


def test_atomic_initial_expiry_rechecked_after_sqlite_writer_wait(combined,monkeypatch):
    _,service,store,_,key,clock,issue,_,evidence,*_=combined
    challenge=issue()
    raw=evidence(challenge)
    ready,proceed,attempting=(threading.Event() for _ in range(3))
    original=service._finish
    def paused(*args):
        ready.set()
        assert proceed.wait(5)
        return original(*args)
    monkeypatch.setattr(service,"_finish",paused)
    real_connect=sqlite3.connect
    def traced(*a,**kw):
        db=real_connect(*a,**kw)
        db.set_trace_callback(lambda sql:attempting.set() if sql=="BEGIN IMMEDIATE" and proceed.is_set() else None)
        return db
    monkeypatch.setattr(sqlite3,"connect",traced)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future=pool.submit(finish,service,challenge,key,raw)
        assert ready.wait(5)
        with real_connect(store.path,isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            proceed.set()
            assert attempting.wait(5) and not future.done()
            clock[0]=challenge.expires
            db.execute("COMMIT")
        reject(lambda:future.result(timeout=5),"CHALLENGE_REJECTED")
    assert_empty(store,challenge)


def test_refresh_verifies_outside_lock_and_persists_bound_newer_receipt(combined,monkeypatch):
    _,service,store,_,key,clock,issue,receipt,evidence,module,*_=combined
    challenge=issue()
    finish(service,challenge,key,evidence(challenge))
    record=store.apple_key("test-app","test-user","request-key")
    old=store.verified_receipt("test-app","test-user",record.key_id)
    new=receipt(challenge,kind="RECEIPT",changes={12:stamp(datetime.fromtimestamp(clock[0],timezone.utc))})
    calls=[]
    connection_factory(monkeypatch,module,Response(base64.b64encode(new)),calls)
    def token():
        with sqlite3.connect(store.path,timeout=0,isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("ROLLBACK")
        return "abc.def.ghi"
    result=service.refresh_receipt(subject="test-user",apple_key_id=record.key_id,token_provider=token)
    assert result.receipt==new and result.receipt_type=="RECEIPT"
    assert result.created_at>old.created_at
    assert store.verified_receipt("test-app","test-user",record.key_id)==result
    assert store.apple_key("test-app","test-user","request-key").counter==0
    assert calls[0][0]=="data-development.appattest.apple.com"


def test_concurrent_refreshes_use_compare_and_swap_not_last_writer_wins(combined,monkeypatch):
    _,service,store,_,key,clock,issue,receipt,evidence,module,*_=combined
    challenge=issue()
    finish(service,challenge,key,evidence(challenge))
    record=store.apple_key("test-app","test-user","request-key")
    new=receipt(challenge,kind="RECEIPT",changes={12:stamp(datetime.fromtimestamp(clock[0],timezone.utc))})
    # Each transport owns its response; both receive the same valid newer CMS.
    class Connection:
        def __init__(self,*a,**kw): self.sock=None
        def connect(self): pass
        def request(self,*a,**kw): pass
        def getresponse(self): return Response(base64.b64encode(new))
        def close(self): pass
    monkeypatch.setattr(module.http.client,"HTTPSConnection",Connection)
    gate=threading.Barrier(2,timeout=5)
    def token():
        gate.wait()
        return "abc.def.ghi"
    def refresh():
        try:
            service.refresh_receipt(subject="test-user",apple_key_id=record.key_id,token_provider=token)
            return "REFRESHED"
        except EnrollmentError as error: return error.code
    with ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(lambda _:refresh(),range(2)))
    assert sorted(results)==["ATTESTATION_REJECTED","REFRESHED"]
    assert store.verified_receipt("test-app","test-user",record.key_id).receipt==new


@pytest.mark.parametrize("mutation",["revoke","expiry","stale","wrong_binding"])
def test_refresh_cannot_revive_revoked_or_expired_state_or_replace_invalid_receipt(combined,monkeypatch,mutation):
    _,service,store,_,key,clock,issue,receipt,evidence,module,*_=combined
    challenge=issue()
    finish(service,challenge,key,evidence(challenge))
    record=store.apple_key("test-app","test-user","request-key")
    old=store.verified_receipt("test-app","test-user",record.key_id)
    changes={12:stamp(datetime.fromtimestamp(clock[0],timezone.utc))}
    if mutation=="stale": changes[12]=stamp(datetime.fromtimestamp(old.created_at,timezone.utc))
    if mutation=="wrong_binding": changes[4]=b"wrong"
    new=receipt(challenge,kind="RECEIPT",changes=changes)
    connection_factory(monkeypatch,module,Response(base64.b64encode(new)),[])
    def token():
        if mutation=="revoke": store.revoke("test-app","test-user","request-key")
        if mutation=="expiry": clock[0]=int(old.expires_at)
        return "abc.def.ghi"
    with pytest.raises(EnrollmentError) as caught:
        service.refresh_receipt(subject="test-user",apple_key_id=record.key_id,token_provider=token)
    assert caught.value.__context__ is None
    assert store.verified_receipt("test-app","test-user",record.key_id).receipt==old.receipt
    if mutation=="revoke": assert store.apple_key("test-app","test-user","request-key").revoked


def test_cms_verification_occurs_without_sqlite_write_lock(combined,monkeypatch):
    api,service,store,_,key,_,issue,_,evidence,*_=combined
    challenge=issue()
    raw=evidence(challenge)
    original=api.AppleReceiptVerifier.verify
    def verify_without_lock(self,*a,**kw):
        with sqlite3.connect(store.path,timeout=0,isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("ROLLBACK")
        return original(self,*a,**kw)
    monkeypatch.setattr(api.AppleReceiptVerifier,"verify",verify_without_lock)
    finish(service,challenge,key,raw)


def test_initial_receipt_freshness_rechecked_at_final_transaction(combined,monkeypatch):
    _,service,store,_,key,clock,issue,_,evidence,*_=combined
    challenge=issue()
    raw=evidence(challenge,changes={12:stamp(datetime.fromtimestamp(NOW-299,timezone.utc))})
    original=service._finish
    def delayed(*args):
        clock[0]=NOW+2
        return original(*args)
    monkeypatch.setattr(service,"_finish",delayed)
    reject(lambda:finish(service,challenge,key,raw),"ATTESTATION_REJECTED")
    assert_empty(store,challenge)


def test_postcommit_close_failure_requires_readback_but_has_no_partial_state(combined,monkeypatch):
    api,service,store,_,key,_,issue,_,evidence,*_=combined
    challenge=issue()
    raw=evidence(challenge)
    real_connect=sqlite3.connect
    class Connection(sqlite3.Connection):
        touched_receipt=False
        def execute(self,sql,parameters=()):
            if sql.startswith("INSERT INTO apple_verified_receipts"): self.touched_receipt=True
            return super().execute(sql,parameters)
        def close(self):
            super().close()
            if self.touched_receipt: raise sqlite3.OperationalError("PRIVATE_CLOSE_FAILURE")
    with monkeypatch.context() as patch:
        patch.setattr(sqlite3,"connect",lambda *a,**kw:real_connect(*a,**kw,factory=Connection))
        reject(lambda:finish(service,challenge,key,raw),"STORE_UNAVAILABLE")
    reopened=api.SqliteAppleEnrollmentStore(store.path)
    assert reopened.pending(challenge.nonce) is None
    assert reopened.lookup("test-app","test-user","request-key") is not None
    record=reopened.apple_key("test-app","test-user","request-key")
    assert record is not None and reopened.verified_receipt("test-app","test-user",record.key_id) is not None


def test_receipt_cas_storage_failure_preserves_previous_verified_receipt(combined,monkeypatch):
    _,service,store,_,key,clock,issue,receipt,evidence,module,*_=combined
    challenge=issue()
    finish(service,challenge,key,evidence(challenge))
    record=store.apple_key("test-app","test-user","request-key")
    old=store.verified_receipt("test-app","test-user",record.key_id)
    new=receipt(challenge,kind="RECEIPT",changes={12:stamp(datetime.fromtimestamp(clock[0],timezone.utc))})
    connection_factory(monkeypatch,module,Response(base64.b64encode(new)),[])
    with sqlite3.connect(store.path) as db:
        db.execute("CREATE TRIGGER fail_receipt_update BEFORE UPDATE ON apple_verified_receipts BEGIN SELECT RAISE(ABORT,'PRIVATE_REFRESH_STORAGE'); END")
    reject(lambda:service.refresh_receipt(subject="test-user",apple_key_id=record.key_id,token_provider=lambda:"abc.def.ghi"),"STORE_UNAVAILABLE")
    assert store.verified_receipt("test-app","test-user",record.key_id)==old
    with sqlite3.connect(store.path) as db: db.execute("DROP TRIGGER fail_receipt_update")


def test_verified_receipt_lookup_is_scoped_and_opaque_snapshot_corruption_rejects(combined):
    _,service,store,_,key,_,issue,_,evidence,*_=combined
    challenge=issue()
    finish(service,challenge,key,evidence(challenge))
    record=store.apple_key("test-app","test-user","request-key")
    assert store.verified_receipt("other-app","test-user",record.key_id) is None
    assert store.verified_receipt("test-app","other-user",record.key_id) is None
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE apple_verified_receipts SET receipt=? WHERE kid=?",(b"tampered",record.key_id))
    reject(lambda:store.verified_receipt("test-app","test-user",record.key_id),"STORE_UNAVAILABLE")


def test_apple_only_subject_revocation_preserves_unassociated_initial_challenges(combined):
    api,service,store,_,key,clock,issue,_,evidence,*_=combined
    challenge=issue()
    finish(service,challenge,key,evidence(challenge))
    development_pending=issue("development-pending")
    from appguard.providers.apple import AppleAppAttestVerifier
    production=api.AppleEnrollmentService(store=store,verifier=AppleAppAttestVerifier(app_id="test-app",apple_app_id=APP_ID,
        platform="ios",environment="production",clock=lambda:clock[0]),clock=lambda:clock[0])
    pem=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    production_pending=production.issue(app_id="test-app",subject="test-user",key_id="production-pending",
        origin="https://api.example.test",public_key_pem=pem)
    assert service.assertions.revoke_subject(subject="test-user")==1
    assert store.pending(development_pending.nonce)==development_pending
    assert store.pending(production_pending.nonce)==production_pending
    # Account-wide enrollment revocation explicitly cancels both pending scopes.
    assert store.revoke_subject("test-app","test-user").cancelled_challenges==2


def test_initial_receipt_clock_rollback_cannot_commit_future_verified_snapshot(combined,monkeypatch):
    api,service,store,_,key,clock,issue,_,evidence,*_=combined
    challenge=issue()
    raw=evidence(challenge)
    original=api.AppleReceiptVerifier.verify
    def verify_in_future(self,*a,**kw):
        clock[0]=NOW+10
        result=original(self,*a,**kw)
        clock[0]=NOW+1
        return result
    monkeypatch.setattr(api.AppleReceiptVerifier,"verify",verify_in_future)
    reject(lambda:finish(service,challenge,key,raw),"ATTESTATION_REJECTED")
    assert_empty(store,challenge)


@pytest.mark.parametrize("table",["apple_enrollment_links","apple_keys","appguard_keys","apple_verified_receipts"])
def test_combined_reopen_rejects_missing_schema_constraints_without_mutating_file(combined,table):
    api,_,store,*_=combined
    with sqlite3.connect(store.path) as db:
        columns=db.execute(f"PRAGMA table_info({table})").fetchall()
        db.execute(f"DROP TABLE {table}")
        # Same names/types, but all PK/UNIQUE/FK/NOT NULL/CHECK rules are lost.
        declaration=",".join(row[1]+" "+row[2] for row in columns)
        db.execute(f"CREATE TABLE {table} ({declaration})")
    from pathlib import Path
    before=Path(store.path).read_bytes()
    reject(lambda:api.SqliteAppleEnrollmentStore(store.path),"STORE_UNAVAILABLE")
    assert Path(store.path).read_bytes()==before
