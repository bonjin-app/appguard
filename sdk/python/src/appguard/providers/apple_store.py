"""Dedicated private SQLite App Attest state; independent of enrollment storage."""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat

from ..enrollment_types import _time
from .apple_assertions import (AppleAssertionChallenge, AppleAttestedKey, AppleLifecycleError,
    _boundary, _public_key, assertion_client_data)


class SqliteAppleAppAttestStore:
    """One host-local, durable shared store for every process serving these keys.

    Keep its directory private and stable. Do not use an enrollment/application
    database, a network filesystem, copied independent databases or a rollbacked
    backup as live counter state. A restored stale database needs key revocation.
    """
    @_boundary("APPLE_STORE_UNAVAILABLE")
    def __init__(self, path):
        self.path = str(Path(os.path.abspath(os.fspath(path))))
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(self.path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            descriptor = os.open(self.path, flags)
        try:
            self._identity = self._file_identity(os.fstat(descriptor))
        finally:
            os.close(descriptor)
        with self._db() as db:
            self._initialize_schema(db)

    def _initialize_schema(self, db):
        objects = db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        if not objects:
            self._create_schema(db)
        elif (set(objects) != {("table", "apple_meta"), ("table", "apple_keys"), ("table", "apple_assertion_challenges")}
                or db.execute("SELECT version FROM apple_meta").fetchall() != [(1,)]):
            raise AppleLifecycleError("APPLE_STORE_UNAVAILABLE")

    @staticmethod
    def _create_schema(db):
        db.execute("CREATE TABLE apple_meta (version INTEGER NOT NULL)")
        db.execute("INSERT INTO apple_meta VALUES (1)")
        db.execute("CREATE TABLE apple_keys (kid TEXT PRIMARY KEY, app TEXT NOT NULL, apple_app TEXT NOT NULL, environment TEXT NOT NULL, subject TEXT NOT NULL, public_der BLOB NOT NULL, opaque_receipt BLOB NOT NULL, category INTEGER, bundle_version TEXT, verified_at INTEGER NOT NULL, initial_hash TEXT NOT NULL UNIQUE, counter INTEGER NOT NULL CHECK(counter>=0 AND counter<=4294967295), revoked INTEGER NOT NULL CHECK(revoked IN (0,1)))")
        db.execute("CREATE TABLE apple_assertion_challenges (nonce TEXT PRIMARY KEY, app TEXT NOT NULL, apple_app TEXT NOT NULL, environment TEXT NOT NULL, subject TEXT NOT NULL, kid TEXT NOT NULL REFERENCES apple_keys(kid), request_hash TEXT NOT NULL, issued_at INTEGER NOT NULL, expires INTEGER NOT NULL)")

    @staticmethod
    def _file_identity(info):
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_nlink != 1
                or (hasattr(os, "getuid") and info.st_uid != os.getuid())):
            raise ValueError
        return info.st_dev, info.st_ino

    def _check_file(self):
        if self._file_identity(os.stat(self.path, follow_symlinks=False)) != self._identity:
            raise ValueError

    @contextmanager
    def _db(self):
        db, failure = None, None
        try:
            self._check_file()
            # mode=rw never silently recreates a removed counter database.
            uri = Path(self.path).as_uri() + "?mode=rw"
            db = sqlite3.connect(uri, uri=True, timeout=5, isolation_level=None)
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            self._check_file()
            yield db
            self._check_file()
            db.execute("COMMIT")
        except AppleLifecycleError as error:
            failure = error.code
        except Exception:
            failure = "APPLE_STORE_UNAVAILABLE"
        finally:
            if db is not None:
                try:
                    if db.in_transaction:
                        db.rollback()
                    db.close()
                except Exception:
                    failure = "APPLE_STORE_UNAVAILABLE"
        if failure is not None:
            raise AppleLifecycleError(failure) from None

    @staticmethod
    def _record(row):
        if row is None:
            return None
        if (len(row) != 13 or type(row[12]) is not int or row[12] not in (0, 1)
                or type(row[11]) is not int or not 0 <= row[11] <= 0xffffffff
                or type(row[6]) is not bytes or not 1 <= len(row[6]) <= 32768
                or (row[7] is None) != (row[8] is None)
                or (row[7] is not None and (type(row[7]) is not int or row[7] not in {2, 3, 4, 5}
                    or type(row[8]) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", row[8]) is None))
                or type(row[10]) is not str or re.fullmatch(r"[0-9a-f]{64}", row[10]) is None):
            raise ValueError
        _time(row[9])
        record = AppleAttestedKey(*row[:12], bool(row[12]))
        _public_key(record)
        return record

    @staticmethod
    def _scoped(record, scope, *, active):
        if (record is None or (record.app_id, record.apple_app_id, record.environment, record.subject, record.key_id) != scope
                or (active and record.revoked)):
            raise AppleLifecycleError("APPLE_ASSERTION_REJECTED")

    @_boundary("APPLE_STORE_UNAVAILABLE")
    def _register(self, initial, clock):
        verdict = initial.verdict
        with self._db() as db:
            now = _time(clock())
            if not initial.verified_at <= now < verdict.expires:
                raise AppleLifecycleError("APPLE_STATE_REJECTED")
            return self._insert_initial(db, initial)

    @classmethod
    def _insert_initial(cls, db, initial):
        verdict = initial.verdict
        if db.execute("SELECT 1 FROM apple_keys WHERE kid=? OR initial_hash=?", (initial.key_id, verdict.challenge_sha256)).fetchone():
            raise AppleLifecycleError("APPLE_STATE_REJECTED")
        row = (initial.key_id, verdict.app_id, initial.apple_app_id, initial.environment, verdict.subject,
            initial.public_key_der, initial.opaque_receipt, initial.validation_category, initial.bundle_version,
            initial.verified_at, verdict.challenge_sha256, 0, 0)
        record = cls._record(row)
        db.execute("INSERT INTO apple_keys VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
        return record

    @_boundary("APPLE_STORE_UNAVAILABLE")
    def _lookup(self, scope):
        with self._db() as db:
            record = self._record(db.execute("SELECT * FROM apple_keys WHERE kid=?", (scope[4],)).fetchone())
            if record is None or (record.app_id, record.apple_app_id, record.environment, record.subject, record.key_id) != scope:
                return None
            return record

    @_boundary("APPLE_STORE_UNAVAILABLE")
    def _issue(self, scope, request_hash, *, clock, ttl, max_pending):
        with self._db() as db:
            now = _time(clock())
            record = self._record(db.execute("SELECT * FROM apple_keys WHERE kid=?", (scope[4],)).fetchone())
            self._scoped(record, scope, active=True)
            db.execute("DELETE FROM apple_assertion_challenges WHERE expires<=?", (now,))
            if db.execute("SELECT count(*) FROM apple_assertion_challenges").fetchone()[0] >= max_pending:
                raise AppleLifecycleError("APPLE_STORE_UNAVAILABLE")
            challenge = AppleAssertionChallenge(*scope[:4], scope[4], request_hash, secrets.token_urlsafe(32), now, _time(now + ttl))
            assertion_client_data(challenge)
            db.execute("INSERT INTO apple_assertion_challenges VALUES (?,?,?,?,?,?,?,?,?)", (
                challenge.nonce, *scope, request_hash, now, challenge.expires))
            return challenge

    @_boundary("APPLE_STORE_UNAVAILABLE")
    def _pending(self, nonce, scope):
        with self._db() as db:
            row = db.execute("SELECT app,apple_app,environment,subject,kid,request_hash,nonce,issued_at,expires FROM apple_assertion_challenges WHERE nonce=?", (nonce,)).fetchone()
            record = self._record(db.execute("SELECT * FROM apple_keys WHERE kid=?", (scope[4],)).fetchone())
            self._scoped(record, scope, active=True)
            if row is None or row[:5] != scope:
                raise AppleLifecycleError("APPLE_ASSERTION_REJECTED")
            challenge = AppleAssertionChallenge(*row)
            assertion_client_data(challenge)
            return record, challenge

    @_boundary("APPLE_STORE_UNAVAILABLE")
    def _finish(self, expected, challenge, counter, clock):
        with self._db() as db:
            # Recheck after the actual writer lock, including concurrent revokes
            # and later assertions. No callback/storage request can reset state.
            now = _time(clock())
            row = db.execute("SELECT app,apple_app,environment,subject,kid,request_hash,nonce,issued_at,expires FROM apple_assertion_challenges WHERE nonce=?", (challenge.nonce,)).fetchone()
            current = self._record(db.execute("SELECT * FROM apple_keys WHERE kid=?", (expected.key_id,)).fetchone())
            if (row is None or AppleAssertionChallenge(*row) != challenge or current is None
                    or current.revoked or not challenge.issued_at <= now < challenge.expires
                    or not current.counter < counter <= 0xffffffff
                    or (current.app_id, current.apple_app_id, current.environment, current.subject, current.key_id,
                        current.public_key_der, current.initial_challenge_sha256) != (
                        expected.app_id, expected.apple_app_id, expected.environment, expected.subject, expected.key_id,
                        expected.public_key_der, expected.initial_challenge_sha256)):
                raise AppleLifecycleError("APPLE_ASSERTION_REJECTED")
            db.execute("UPDATE apple_keys SET counter=? WHERE kid=?", (counter, current.key_id))
            db.execute("DELETE FROM apple_assertion_challenges WHERE nonce=?", (challenge.nonce,))
            return now

    @_boundary("APPLE_STORE_UNAVAILABLE")
    def _revoke(self, scope, *, entire_subject=False):
        with self._db() as db:
            clause = "app=? AND apple_app=? AND environment=? AND subject=?"
            params = scope[:4]
            if not entire_subject:
                clause += " AND kid=?"
                params = scope
            count = db.execute("UPDATE apple_keys SET revoked=1 WHERE " + clause + " AND revoked=0", params).rowcount
            db.execute("DELETE FROM apple_assertion_challenges WHERE " + clause, params)
            return count
