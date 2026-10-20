"""Authenticated-caller enrollment with an explicit provider trust boundary."""

import hashlib
import secrets
import time

from cryptography.hazmat.primitives import serialization

from .canonical import _validate_origin
from .crypto import load_p256_key, verify_p256
from .types import KeyRecord, VerificationError
from .enrollment_types import (AttestationVerdict, Challenge, Credential, EnrollmentError, enrollment_message,
                               _MAX_TIME, _identifier, _nonce, _time)
from .enrollment_store import SqliteEnrollmentStore


class EnrollmentService:
    def __init__(self, store, *, profile="balanced", clock=None, attestation_verifier=None, max_pending=10000):
        if (profile not in {"basic", "balanced", "strict"} or not isinstance(store, SqliteEnrollmentStore)
                or (clock is not None and not callable(clock))
                or (attestation_verifier is not None and not callable(attestation_verifier))
                or type(max_pending) is not int or not 1 <= max_pending <= 1000000):
            raise EnrollmentError("INVALID_ENROLLMENT")
        self.store, self.profile = store, profile
        self.clock = clock if clock is not None else lambda: int(time.time())
        self.attestation_verifier, self.max_pending = attestation_verifier, max_pending

    def _now(self):
        try:
            return _time(self.clock())
        except Exception:
            pass
        raise EnrollmentError("CLOCK_UNAVAILABLE") from None

    def issue(self, *, app_id, subject, key_id, origin, public_key_pem, ttl=120):
        for value in (app_id, subject, key_id):
            _identifier(value)
        public = None
        try:
            _validate_origin(origin)
            public = load_p256_key(public_key_pem)
        except VerificationError:
            pass
        if public is None:
            raise EnrollmentError("INVALID_ENROLLMENT") from None
        now = self._now()
        if type(ttl) is not int or not 1 <= ttl <= 300 or now + ttl > _MAX_TIME:
            raise EnrollmentError("INVALID_ENROLLMENT")
        pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        spki = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        challenge = Challenge(app_id, subject, key_id, origin, hashlib.sha256(spki).hexdigest(),
                              secrets.token_urlsafe(32), now + ttl, pem)
        self.store.add_challenge(challenge, now=now, max_pending=self.max_pending)
        return challenge

    def complete(self, nonce, *, app_id, subject, proof, evidence=None):
        _nonce(nonce)
        _identifier(app_id)
        _identifier(subject)
        if evidence is not None and (type(evidence) is not bytes or not 1 <= len(evidence) <= 65536):
            raise EnrollmentError("INVALID_ENROLLMENT")
        challenge = self.store.pending(nonce)
        now = self._now()
        if (challenge is None or challenge.app_id != app_id or challenge.subject != subject or now >= challenge.expires):
            raise EnrollmentError("CHALLENGE_REJECTED")
        message = enrollment_message(challenge)
        proof_valid = False
        try:
            verify_p256(challenge.public_key_pem, message, proof)
            proof_valid = True
        except VerificationError:
            pass
        if not proof_valid:
            raise EnrollmentError("PROOF_REJECTED") from None
        verdict = None
        if evidence is not None:
            if self.attestation_verifier is None:
                raise EnrollmentError("ATTESTATION_UNAVAILABLE")
            provider_failed = False
            try:
                verdict = self.attestation_verifier(challenge, evidence)
            except Exception:
                provider_failed = True
            if provider_failed:
                raise EnrollmentError("ATTESTATION_UNAVAILABLE") from None
        elif self.profile != "basic":
            raise EnrollmentError("ATTESTATION_REQUIRED")
        # Re-sample after proof/provider work so slow verification cannot extend
        # a challenge's validity or persist an already stale provider verdict.
        now = self._now()
        if now >= challenge.expires:
            raise EnrollmentError("CHALLENGE_REJECTED")
        if evidence is not None:
            if (not isinstance(verdict, AttestationVerdict) or type(verdict.provider) is not str
                    or verdict.provider not in {"apple", "google"}
                    or verdict.status != "verified" or verdict.app_id != app_id or verdict.subject != subject
                    or verdict.public_key_sha256 != challenge.public_key_sha256
                    or verdict.challenge_sha256 != hashlib.sha256(message).hexdigest()
                    or type(verdict.expires) is not int or not now < verdict.expires <= _MAX_TIME):
                raise EnrollmentError("ATTESTATION_REJECTED")
        credential = Credential(KeyRecord(app_id, challenge.key_id, subject, challenge.public_key_pem,
                                          "ecdsa-p256-sha256", False),
                                "verified" if verdict else "missing", verdict.provider if verdict else None,
                                verdict.expires if verdict else None)
        self.store.finish(challenge, credential, now=now)
        return credential
