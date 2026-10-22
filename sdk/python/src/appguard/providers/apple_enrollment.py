"""Opt-in atomic request-key, App Attest key and verified-receipt enrollment.

A dedicated combined database is explicit. Existing standalone enrollment and
Apple databases are neither migrated nor silently adopted. No provider network
calls occur during construction, initial verification, or a SQLite transaction.
"""
from contextlib import contextmanager
from dataclasses import dataclass,field
from functools import wraps
import hashlib
import hmac
import math
import os
from pathlib import Path
import sqlite3

from ..enrollment import EnrollmentService
from ..enrollment_store import SqliteEnrollmentStore
from ..enrollment_types import (AttestationVerdict,EnrollmentError,SubjectRevocationResult,
    _identifier,_time,enrollment_message)
from .apple import AppleAppAttestVerifier,VerifiedAppleAttestation
from .apple_assertions import AppleLifecycleError,_boundary as _apple_boundary,_key_id
from .apple_lifecycle import AppleAppAttestLifecycle
from .apple_receipts import AppleReceiptVerifier,AppleReceiptRefreshClient,VerifiedAppleReceipt
from .apple_store import SqliteAppleAppAttestStore


def _boundary(default):
    def decorate(operation):
        @wraps(operation)
        def call(*args,**kwargs):
            code=default
            try:
                return operation(*args,**kwargs)
            except EnrollmentError as error:
                code=error.code
            except Exception:
                pass
            raise EnrollmentError(code) from None
        return call
    return decorate


@dataclass(frozen=True)
class _AppleEnrollmentVerdict(AttestationVerdict):
    initial: VerifiedAppleAttestation = field(repr=False)
    receipt: VerifiedAppleReceipt = field(repr=False)


class _CombinedAppleState(SqliteAppleAppAttestStore):
    """Trusted assertion view of its owner's one combined SQLite database."""
    def __init__(self,owner,path):
        self._owner=owner
        owner.apple=self
        super().__init__(path)

    @staticmethod
    def _schema_snapshot(db):
        return set(db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall())

    @staticmethod
    def _create_combined_schema(db):
        SqliteAppleAppAttestStore._create_schema(db)
        db.execute("CREATE TABLE appguard_meta (version INTEGER NOT NULL)")
        db.execute("INSERT INTO appguard_meta VALUES (1)")
        db.execute("CREATE TABLE appguard_challenges (nonce TEXT PRIMARY KEY, app TEXT NOT NULL, subject TEXT NOT NULL, kid TEXT NOT NULL, origin TEXT NOT NULL, fingerprint TEXT NOT NULL, expires INTEGER NOT NULL, pem BLOB NOT NULL)")
        db.execute("CREATE TABLE appguard_keys (app TEXT NOT NULL, kid TEXT NOT NULL, subject TEXT NOT NULL, pem BLOB NOT NULL, revoked INTEGER NOT NULL, attestation TEXT NOT NULL, provider TEXT, att_expires INTEGER, PRIMARY KEY(app,kid))")
        db.execute("CREATE TABLE apple_enrollment_meta (version INTEGER NOT NULL)")
        db.execute("INSERT INTO apple_enrollment_meta VALUES (1)")
        db.execute("CREATE TABLE apple_enrollment_links (app TEXT NOT NULL, subject TEXT NOT NULL, request_kid TEXT NOT NULL, apple_kid TEXT NOT NULL UNIQUE REFERENCES apple_keys(kid), PRIMARY KEY(app,request_kid), FOREIGN KEY(app,request_kid) REFERENCES appguard_keys(app,kid))")
        db.execute("CREATE TABLE apple_verified_receipts (kid TEXT PRIMARY KEY REFERENCES apple_keys(kid), apple_app TEXT NOT NULL, environment TEXT NOT NULL, public_der BLOB NOT NULL, client_hash BLOB NOT NULL, receipt_type TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL, not_before REAL, risk_metric INTEGER, verified_at REAL NOT NULL, fresh INTEGER NOT NULL CHECK(fresh IN (0,1)), receipt BLOB NOT NULL, receipt_hash TEXT NOT NULL)")

    def _initialize_schema(self,db):
        objects=self._schema_snapshot(db)
        if not objects:
            self._create_combined_schema(db)
            return
        # SQLite's own schema SQL includes all column types, NOT NULL, primary
        # and unique keys, foreign keys and CHECK constraints. Compare against
        # the same creation recipe in a transient database, not just names or a
        # version marker. No data in the supplied database is changed here.
        reference=sqlite3.connect(":memory:")
        try:
            self._create_combined_schema(reference)
            expected=self._schema_snapshot(reference)
        finally:
            reference.close()
        if (objects!=expected or any(db.execute(f"SELECT version FROM {table}").fetchall()!=[(1,)]
                for table in ["appguard_meta","apple_meta","apple_enrollment_meta"])):
            raise AppleLifecycleError("APPLE_STORE_UNAVAILABLE")

    @contextmanager
    def _db(self):
        failure=None
        try:
            with self._owner._db() as db:
                yield db
        except EnrollmentError as error:
            failure="APPLE_STORE_UNAVAILABLE" if error.code=="STORE_UNAVAILABLE" else "APPLE_ASSERTION_REJECTED"
        if failure is not None:
            raise AppleLifecycleError(failure) from None

    @_apple_boundary("APPLE_STATE_REJECTED")
    def _register(self,initial,clock):
        # Standalone registration must never bypass proof + CMS + link insertion.
        raise AppleLifecycleError("APPLE_STATE_REJECTED")

    @_apple_boundary("APPLE_STORE_UNAVAILABLE")
    def _revoke(self,scope,*,entire_subject=False):
        return self._owner._revoke_apple(scope,entire_subject=entire_subject)


class SqliteAppleEnrollmentStore(SqliteEnrollmentStore):
    """A new, private, host-local combined database; `.apple` is its state view."""
    @_boundary("STORE_UNAVAILABLE")
    def __init__(self,path):
        self.path=str(Path(os.path.abspath(os.fspath(path))))
        self.apple=_CombinedAppleState(self,self.path)

    @contextmanager
    def _db(self):
        db,failure=None,None
        try:
            if self.path!=self.apple.path:
                raise ValueError
            self.apple._check_file()
            db=sqlite3.connect(Path(self.path).as_uri()+"?mode=rw",uri=True,timeout=5,isolation_level=None)
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            self.apple._check_file()
            yield db
            self.apple._check_file()
            db.execute("COMMIT")
        except EnrollmentError as error:
            failure=error.code
        except AppleLifecycleError as error:
            failure="STORE_UNAVAILABLE" if error.code=="APPLE_STORE_UNAVAILABLE" else "ATTESTATION_REJECTED"
        except Exception:
            failure="STORE_UNAVAILABLE"
        finally:
            if db is not None:
                try:
                    if db.in_transaction:
                        db.rollback()
                    db.close()
                except Exception:
                    failure="STORE_UNAVAILABLE"
        if failure is not None:
            raise EnrollmentError(failure) from None

    @_boundary("ATTESTATION_REQUIRED")
    def finish(self,challenge,credential,*,now,clock=None):
        """Generic EnrollmentService cannot activate a combined-store key."""
        raise EnrollmentError("ATTESTATION_REQUIRED")

    @staticmethod
    def _receipt_values(receipt):
        return (receipt.apple_app_id,receipt.environment,receipt.public_key_der,receipt.client_hash,
            receipt.receipt_type,receipt.created_at,receipt.expires_at,receipt.not_before,receipt.risk_metric,
            receipt.verified_at,int(receipt.fresh),receipt.receipt,receipt.receipt_sha256)

    @staticmethod
    def _receipt_record(row,record):
        if row is None:
            return None
        if (len(row)!=13 or type(row[10]) is not int or row[10] not in (0,1)
                or any(type(row[i]) not in (int,float) or not math.isfinite(row[i]) or row[i]<0 for i in [5,6,9])
                or not row[5]<=row[9]<row[6]
                or (row[10]==1 and row[9]-row[5]>300)
                or row[:3]!=(record.apple_app_id,record.environment,record.public_key_der)
                or type(row[3]) is not bytes or row[3]!=bytes.fromhex(record.initial_challenge_sha256)
                or type(row[11]) is not bytes or not 1<=len(row[11])<=262144
                or type(row[12]) is not str or hashlib.sha256(row[11]).hexdigest()!=row[12]
                or row[4] not in {"ATTEST","RECEIPT"}):
            raise ValueError
        if row[4]=="ATTEST":
            if row[7] is not None or row[8] is not None:
                raise ValueError
        elif (type(row[7]) not in (int,float) or not math.isfinite(row[7]) or not row[5]<=row[7]<row[6]
                or type(row[8]) is not int or not 0<=row[8]<=9999999999):
            raise ValueError
        return VerifiedAppleReceipt(*row[:10],bool(row[10]),*row[11:])

    @_boundary("STORE_UNAVAILABLE")
    def _finish_apple(self,challenge,credential,verdict,clock):
        if type(verdict) is not _AppleEnrollmentVerdict:
            raise EnrollmentError("ATTESTATION_REJECTED")
        initial,receipt=verdict.initial,verdict.receipt
        if type(initial) is not VerifiedAppleAttestation or type(receipt) is not VerifiedAppleReceipt:
            raise EnrollmentError("ATTESTATION_REJECTED")
        with self._db() as db:
            now=_time(clock())
            if now>=challenge.expires:
                raise EnrollmentError("CHALLENGE_REJECTED")
            if (not initial.verified_at<=receipt.verified_at<=now<verdict.expires or initial.verdict!=AttestationVerdict(
                    verdict.provider,verdict.status,verdict.app_id,verdict.subject,verdict.public_key_sha256,
                    verdict.challenge_sha256,verdict.expires)
                    or receipt.receipt_type!="ATTEST" or not receipt.fresh
                    or not receipt.created_at<=now<receipt.expires_at or now-receipt.created_at>300
                    or receipt.receipt!=initial.opaque_receipt):
                raise EnrollmentError("ATTESTATION_REJECTED")
            # Default proof/challenge/verdict checks execute inside this same
            # transaction. Later insert failures roll back their mutations too.
            self._finish_transaction(db,challenge,credential,now)
            record=self.apple._insert_initial(db,initial)
            values=self._receipt_values(receipt)
            self._receipt_record(values,record)
            db.execute("INSERT INTO apple_enrollment_links VALUES (?,?,?,?)",(
                challenge.app_id,challenge.subject,challenge.key_id,record.key_id))
            db.execute("INSERT INTO apple_verified_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(record.key_id,*values))

    @_boundary("STORE_UNAVAILABLE")
    def apple_key(self,app_id,subject,key_id):
        for value in [app_id,subject,key_id]: _identifier(value)
        with self._db() as db:
            row=db.execute("SELECT a.* FROM apple_keys a JOIN apple_enrollment_links l ON a.kid=l.apple_kid WHERE l.app=? AND l.subject=? AND l.request_kid=?",(app_id,subject,key_id)).fetchone()
            return self.apple._record(row)

    @_boundary("STORE_UNAVAILABLE")
    def verified_receipt(self,app_id,subject,apple_key_id):
        _identifier(app_id)
        _identifier(subject)
        _key_id(apple_key_id)
        with self._db() as db:
            row=db.execute("SELECT * FROM apple_keys WHERE app=? AND subject=? AND kid=?",(app_id,subject,apple_key_id)).fetchone()
            record=self.apple._record(row)
            if record is None:
                return None
            receipt=db.execute("SELECT apple_app,environment,public_der,client_hash,receipt_type,created_at,expires_at,not_before,risk_metric,verified_at,fresh,receipt,receipt_hash FROM apple_verified_receipts WHERE kid=?",(apple_key_id,)).fetchone()
            if receipt is None:
                raise ValueError
            return self._receipt_record(receipt,record)

    @_boundary("STORE_UNAVAILABLE")
    def _replace_verified_receipt(self,scope,expected_hash,replacement,clock):
        """CAS of an already verified in-process result; no callbacks/network."""
        if type(replacement) is not VerifiedAppleReceipt:
            raise EnrollmentError("ATTESTATION_REJECTED")
        with self._db() as db:
            now=_time(clock())
            record=self.apple._record(db.execute("SELECT * FROM apple_keys WHERE kid=?",(scope[4],)).fetchone())
            self.apple._scoped(record,scope,active=True)
            linked=db.execute("SELECT k.revoked FROM appguard_keys k JOIN apple_enrollment_links l ON k.app=l.app AND k.kid=l.request_kid WHERE l.apple_kid=? AND l.app=? AND l.subject=?",(scope[4],scope[0],scope[3])).fetchall()
            old_row=db.execute("SELECT apple_app,environment,public_der,client_hash,receipt_type,created_at,expires_at,not_before,risk_metric,verified_at,fresh,receipt,receipt_hash FROM apple_verified_receipts WHERE kid=?",(scope[4],)).fetchone()
            old=self._receipt_record(old_row,record)
            if (linked!=[(0,)] or old is None or type(expected_hash) is not str
                    or not hmac.compare_digest(old.receipt_sha256,expected_hash)
                    or replacement.receipt_type!="RECEIPT" or replacement.fresh is not True
                    or not old.created_at<replacement.created_at<=replacement.verified_at<=now<replacement.expires_at
                    or now-replacement.created_at>300 or now>=old.expires_at
                    or (old.not_before is not None and now<old.not_before)):
                raise EnrollmentError("ATTESTATION_REJECTED")
            values=self._receipt_values(replacement)
            self._receipt_record(values,record)
            db.execute("UPDATE apple_verified_receipts SET apple_app=?,environment=?,public_der=?,client_hash=?,receipt_type=?,created_at=?,expires_at=?,not_before=?,risk_metric=?,verified_at=?,fresh=?,receipt=?,receipt_hash=? WHERE kid=?",(*values,scope[4]))
            return replacement

    @_boundary("STORE_UNAVAILABLE")
    def revoke(self,app_id,subject,key_id):
        for value in [app_id,subject,key_id]: _identifier(value)
        with self._db() as db:
            count=db.execute("UPDATE appguard_keys SET revoked=1 WHERE app=? AND subject=? AND kid=?",(app_id,subject,key_id)).rowcount
            selection="SELECT apple_kid FROM apple_enrollment_links WHERE app=? AND subject=? AND request_kid=?"
            params=(app_id,subject,key_id)
            db.execute("UPDATE apple_keys SET revoked=1 WHERE kid IN ("+selection+")",params)
            db.execute("DELETE FROM apple_assertion_challenges WHERE kid IN ("+selection+")",params)
            return bool(count)

    @_boundary("STORE_UNAVAILABLE")
    def revoke_subject(self,app_id,subject):
        for value in [app_id,subject]: _identifier(value)
        with self._db() as db:
            count=db.execute("UPDATE appguard_keys SET revoked=1 WHERE app=? AND subject=? AND revoked=0",(app_id,subject)).rowcount
            selection="SELECT apple_kid FROM apple_enrollment_links WHERE app=? AND subject=?"
            db.execute("UPDATE apple_keys SET revoked=1 WHERE kid IN ("+selection+")",(app_id,subject))
            db.execute("DELETE FROM apple_assertion_challenges WHERE kid IN ("+selection+")",(app_id,subject))
            cancelled=db.execute("DELETE FROM appguard_challenges WHERE app=? AND subject=?",(app_id,subject)).rowcount
            return SubjectRevocationResult(count,cancelled)

    @_boundary("STORE_UNAVAILABLE")
    def _revoke_apple(self,scope,*,entire_subject):
        with self._db() as db:
            clause="app=? AND apple_app=? AND environment=? AND subject=?"
            params=scope[:4]
            if not entire_subject:
                clause+=" AND kid=?"
                params=scope
            selection="SELECT kid FROM apple_keys WHERE "+clause
            db.execute("UPDATE appguard_keys SET revoked=1 WHERE (app,kid) IN (SELECT app,request_kid FROM apple_enrollment_links WHERE apple_kid IN ("+selection+"))",params)
            count=db.execute("UPDATE apple_keys SET revoked=1 WHERE "+clause+" AND revoked=0",params).rowcount
            db.execute("DELETE FROM apple_assertion_challenges WHERE "+clause,params)
            return count


class AppleEnrollmentService(EnrollmentService):
    """Initial proof + App Attest + fresh verified CMS, one activation commit."""
    @_boundary("INVALID_ENROLLMENT")
    def __init__(self,*,store,verifier,clock=None,max_pending=10000):
        if type(store) is not SqliteAppleEnrollmentStore or type(verifier) is not AppleAppAttestVerifier:
            raise ValueError
        self.verifier=verifier
        super().__init__(store,profile="strict",clock=clock,attestation_verifier=self._verify_initial,max_pending=max_pending)
        self.assertions=AppleAppAttestLifecycle(verifier=verifier,store=store.apple,clock=self.clock,max_pending=max_pending)

    def _verify_initial(self,challenge,evidence):
        initial=self.verifier.verify_initial(challenge,evidence)
        receipt=AppleReceiptVerifier(apple_app_id=initial.apple_app_id,public_key_der=initial.public_key_der,
            environment=initial.environment,clock=self._now).verify(initial.opaque_receipt,
                expected_client_hash=hashlib.sha256(enrollment_message(challenge)).digest(),expected_type="ATTEST")
        verdict=initial.verdict
        return _AppleEnrollmentVerdict(verdict.provider,verdict.status,verdict.app_id,verdict.subject,
            verdict.public_key_sha256,verdict.challenge_sha256,verdict.expires,initial,receipt)

    def _finish(self,challenge,credential,verdict,now):
        self.store._finish_apple(challenge,credential,verdict,self._now)

    @_boundary("ATTESTATION_UNAVAILABLE")
    def refresh_receipt(self,*,subject,apple_key_id,token_provider,timeout=5):
        """Explicit fixed-host refresh outside SQL locks, then verified CAS.

        JWT provisioning remains operator-owned. Construction/import never
        invokes this method or discovers credentials.
        """
        scope=self.assertions._scope(subject,apple_key_id)
        record=self.store.apple._lookup(scope)
        if record is None or record.revoked:
            raise EnrollmentError("ATTESTATION_REJECTED")
        old=self.store.verified_receipt(record.app_id,subject,apple_key_id)
        if old is None:
            raise EnrollmentError("ATTESTATION_REJECTED")
        verifier=AppleReceiptVerifier(apple_app_id=record.apple_app_id,public_key_der=record.public_key_der,
            environment=record.environment,clock=self._now)
        client=AppleReceiptRefreshClient(verifier=verifier,token_provider=token_provider,timeout=timeout)
        replacement=client.refresh(old.receipt,expected_client_hash=bytes.fromhex(record.initial_challenge_sha256))
        return self.store._replace_verified_receipt(scope,old.receipt_sha256,replacement,self._now)
