"""Portable enrollment values and the domain-separated proof message."""

import base64
from dataclasses import dataclass, field
import re

from .canonical import _validate_origin, validate_identifier
from .types import KeyRecord, VerificationError

_MAX_TIME = 999999999999999


class EnrollmentError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _identifier(value):
    try:
        validate_identifier(value)
        return
    except VerificationError:
        pass
    raise EnrollmentError("INVALID_ENROLLMENT") from None


def _time(value):
    if type(value) is not int or not 0 <= value <= _MAX_TIME:
        raise EnrollmentError("INVALID_ENROLLMENT")
    return value


def _nonce(value):
    if (type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value)
            or base64.urlsafe_b64encode(base64.urlsafe_b64decode(value + "=")).decode().rstrip("=") != value):
        raise EnrollmentError("INVALID_ENROLLMENT")


@dataclass(frozen=True)
class Challenge:
    app_id: str
    subject: str = field(repr=False)
    key_id: str
    origin: str
    public_key_sha256: str
    nonce: str = field(repr=False)
    expires: int
    public_key_pem: bytes = field(repr=False)


@dataclass(frozen=True)
class AttestationVerdict:
    provider: str
    status: str
    app_id: str
    subject: str = field(repr=False)
    public_key_sha256: str
    challenge_sha256: str
    expires: int


@dataclass(frozen=True)
class Credential:
    key: KeyRecord
    attestation: str
    provider: str | None
    attestation_expires: int | None


@dataclass(frozen=True)
class SubjectRevocationResult:
    revoked_keys: int
    cancelled_challenges: int


def enrollment_message(challenge: Challenge) -> bytes:
    if not isinstance(challenge, Challenge):
        raise EnrollmentError("INVALID_ENROLLMENT")
    for value in (challenge.app_id, challenge.subject, challenge.key_id):
        _identifier(value)
    valid_origin = False
    try:
        _validate_origin(challenge.origin)
        valid_origin = True
    except VerificationError:
        pass
    if not valid_origin:
        raise EnrollmentError("INVALID_ENROLLMENT") from None
    _nonce(challenge.nonce)
    _time(challenge.expires)
    if type(challenge.public_key_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", challenge.public_key_sha256):
        raise EnrollmentError("INVALID_ENROLLMENT")
    return ("appguard-enrollment-v0\n"
            f"app-id: {challenge.app_id}\norigin: {challenge.origin}\nsubject: {challenge.subject}\n"
            f"key-id: {challenge.key_id}\npublic-key-sha256: {challenge.public_key_sha256}\n"
            f"challenge: {challenge.nonce}\nexpires: {challenge.expires}").encode("ascii")
