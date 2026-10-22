"""Opt-in initial association, one-use request challenges and monotonic assertions.

This module performs no network operations. Receipt CMS and risk assessments are
not verified by the assertion lifecycle; retained receipts are explicitly opaque.
"""
import hmac
import time

from ..enrollment_types import _identifier, _nonce, _time
from .apple import AppleAppAttestVerifier
from .apple_assertions import (AppleAssertionChallenge, AppleAssertionVerdict, AppleAttestedKey,
    AppleLifecycleError, _boundary, _key_id, _request_digest, _verify_assertion, assertion_client_data)
from .apple_store import SqliteAppleAppAttestStore

__all__ = ["AppleAppAttestLifecycle", "SqliteAppleAppAttestStore", "AppleLifecycleError",
    "AppleAssertionChallenge", "AppleAttestedKey", "AppleAssertionVerdict", "assertion_client_data"]


class AppleAppAttestLifecycle:
    @_boundary("APPLE_LIFECYCLE_CONFIGURATION")
    def __init__(self, *, verifier, store, clock=None, challenge_ttl=60, max_pending=10000):
        if (not isinstance(verifier, AppleAppAttestVerifier) or not isinstance(store, SqliteAppleAppAttestStore)
                or (clock is not None and not callable(clock)) or type(challenge_ttl) is not int
                or not 1 <= challenge_ttl <= 300 or type(max_pending) is not int or not 1 <= max_pending <= 1000000):
            raise ValueError
        self.verifier, self.store = verifier, store
        self._clock = clock if clock is not None else lambda: int(time.time())
        self._ttl, self._max_pending = challenge_ttl, max_pending

    @_boundary("APPLE_ASSERTION_REJECTED")
    def _now(self):
        return _time(self._clock())

    def _scope(self, subject, key_id):
        _identifier(subject)
        _key_id(key_id)
        return (self.verifier._app_id, self.verifier._apple_app_id, self.verifier._environment, subject, key_id)

    @_boundary("APPLE_STATE_REJECTED")
    def register(self, challenge, evidence):
        """Verify and atomically associate an initial attested key exactly once.

        challenge must be the authenticated server-issued enrollment Challenge,
        never an object decoded from the request. EnrollmentService consumption
        is separate: this API does not authorize its request-signing key.
        """
        initial = self.verifier.verify_initial(challenge, evidence)
        return self.store._register(initial, self._now)

    @_boundary("APPLE_ASSERTION_REJECTED")
    def lookup(self, *, subject, key_id):
        return self.store._lookup(self._scope(subject, key_id))

    @_boundary("APPLE_ASSERTION_REJECTED")
    def issue(self, *, subject, key_id, request):
        """Bind a randomized challenge to the trusted server's operation bytes."""
        scope, digest = self._scope(subject, key_id), _request_digest(request)
        return self.store._issue(scope, digest, clock=self._now, ttl=self._ttl, max_pending=self._max_pending)

    @_boundary("APPLE_ASSERTION_REJECTED")
    def verify(self, nonce, *, subject, key_id, request, assertion):
        _nonce(nonce)
        scope, digest = self._scope(subject, key_id), _request_digest(request)
        record, challenge = self.store._pending(nonce, scope)
        if not challenge.issued_at <= self._now() < challenge.expires or not hmac.compare_digest(challenge.request_sha256, digest):
            raise ValueError
        counter = _verify_assertion(record, challenge, assertion, self.verifier._categories, self.verifier._versions)
        verified_at = self.store._finish(record, challenge, counter, self._now)
        return AppleAssertionVerdict(record.app_id, record.subject, record.key_id, record.environment, digest, counter, verified_at)

    @_boundary("APPLE_ASSERTION_REJECTED")
    def revoke(self, *, subject, key_id):
        return bool(self.store._revoke(self._scope(subject, key_id)))

    @_boundary("APPLE_ASSERTION_REJECTED")
    def revoke_subject(self, *, subject):
        """Revoke every key in this exact app/environment/subject scope."""
        _identifier(subject)
        scope = (self.verifier._app_id, self.verifier._apple_app_id, self.verifier._environment, subject)
        return self.store._revoke(scope, entire_subject=True)
