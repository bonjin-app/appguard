"""Dedicated private SQLite enrollment database; no global service or user DB."""

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat

from .enrollment_types import Challenge, Credential, EnrollmentError, _identifier, _nonce
from .types import KeyRecord


class SqliteEnrollmentStore:
    def __init__(self, path):
        self.path = str(Path(os.path.abspath(os.fspath(path))))
        try:
            flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            try:
                descriptor = os.open(self.path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                descriptor = os.open(self.path, flags)
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                        or (hasattr(os, "getuid") and info.st_uid != os.getuid())):
                    raise EnrollmentError("STORE_UNAVAILABLE")
            finally:
                os.close(descriptor)
            with self._db() as db:
                names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                expected = {"appguard_meta", "appguard_challenges", "appguard_keys"}
                if not names:
                    db.execute("CREATE TABLE appguard_meta (version INTEGER NOT NULL)")
                    db.execute("INSERT INTO appguard_meta VALUES (1)")
                    db.execute("CREATE TABLE appguard_challenges (nonce TEXT PRIMARY KEY, app TEXT NOT NULL, subject TEXT NOT NULL, kid TEXT NOT NULL, origin TEXT NOT NULL, fingerprint TEXT NOT NULL, expires INTEGER NOT NULL, pem BLOB NOT NULL)")
                    db.execute("CREATE TABLE appguard_keys (app TEXT NOT NULL, kid TEXT NOT NULL, subject TEXT NOT NULL, pem BLOB NOT NULL, revoked INTEGER NOT NULL, attestation TEXT NOT NULL, provider TEXT, att_expires INTEGER, PRIMARY KEY(app,kid))")
                elif names != expected or db.execute("SELECT version FROM appguard_meta").fetchall() != [(1,)]:
                    raise EnrollmentError("STORE_UNAVAILABLE")
        except (OSError, ValueError, TypeError):
            raise EnrollmentError("STORE_UNAVAILABLE") from None

    @contextmanager
    def _db(self):
        db = None
        try:
            db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except EnrollmentError:
            if db is not None and db.in_transaction:
                db.rollback()
            raise
        except (sqlite3.Error, OSError, TypeError, ValueError):
            if db is not None and db.in_transaction:
                db.rollback()
            raise EnrollmentError("STORE_UNAVAILABLE") from None
        finally:
            if db is not None:
                db.close()

    def add_challenge(self, challenge, *, now, max_pending):
        with self._db() as db:
            db.execute("DELETE FROM appguard_challenges WHERE expires <= ?", (now,))
            if db.execute("SELECT 1 FROM appguard_keys WHERE app=? AND kid=?", (challenge.app_id, challenge.key_id)).fetchone():
                raise EnrollmentError("KEY_ID_IN_USE")
            if db.execute("SELECT count(*) FROM appguard_challenges").fetchone()[0] >= max_pending:
                raise EnrollmentError("STORE_UNAVAILABLE")
            db.execute("INSERT INTO appguard_challenges VALUES (?,?,?,?,?,?,?,?)", (
                challenge.nonce, challenge.app_id, challenge.subject, challenge.key_id, challenge.origin,
                challenge.public_key_sha256, challenge.expires, challenge.public_key_pem))

    def pending(self, nonce):
        _nonce(nonce)
        with self._db() as db:
            row = db.execute("SELECT app,subject,kid,origin,fingerprint,nonce,expires,pem FROM appguard_challenges WHERE nonce=?", (nonce,)).fetchone()
            return Challenge(*row) if row else None

    def finish(self, challenge, credential, *, now):
        with self._db() as db:
            row = db.execute("SELECT app,subject,kid,origin,fingerprint,nonce,expires,pem FROM appguard_challenges WHERE nonce=?", (challenge.nonce,)).fetchone()
            if row is None or Challenge(*row) != challenge or now >= challenge.expires:
                raise EnrollmentError("CHALLENGE_REJECTED")
            if db.execute("SELECT 1 FROM appguard_keys WHERE app=? AND kid=?", (challenge.app_id, challenge.key_id)).fetchone():
                raise EnrollmentError("KEY_ID_IN_USE")
            key = credential.key
            db.execute("INSERT INTO appguard_keys VALUES (?,?,?,?,?,?,?,?)", (key.app_id, key.key_id, key.subject,
                       key.public_key_pem, int(key.revoked), credential.attestation, credential.provider, credential.attestation_expires))
            db.execute("DELETE FROM appguard_challenges WHERE nonce=?", (challenge.nonce,))

    def lookup(self, app_id, subject, key_id):
        for value in (app_id, subject, key_id):
            _identifier(value)
        with self._db() as db:
            row = db.execute("SELECT pem,revoked,attestation,provider,att_expires FROM appguard_keys WHERE app=? AND subject=? AND kid=?", (app_id, subject, key_id)).fetchone()
            if row is None:
                return None
            pem, revoked, attestation, provider, expires = row
            if revoked not in (0, 1) or attestation not in {"missing", "verified"}:
                raise EnrollmentError("STORE_UNAVAILABLE")
            return Credential(KeyRecord(app_id, key_id, subject, pem, "ecdsa-p256-sha256", bool(revoked)), attestation, provider, expires)

    def revoke(self, app_id, subject, key_id):
        for value in (app_id, subject, key_id):
            _identifier(value)
        with self._db() as db:
            return db.execute("UPDATE appguard_keys SET revoked=1 WHERE app=? AND subject=? AND kid=?", (app_id, subject, key_id)).rowcount == 1
