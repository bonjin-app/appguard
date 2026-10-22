"""Strict App Attest assertions and the versioned request-bound client message."""
from dataclasses import dataclass, field
from functools import wraps
import hashlib
import hmac
import re

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ..enrollment_types import _identifier, _nonce, _time
from .apple import _CBOR, _decode_base64, _signed_properties

_CODES = frozenset({"APPLE_LIFECYCLE_CONFIGURATION", "APPLE_ASSERTION_REJECTED", "APPLE_STATE_REJECTED", "APPLE_STORE_UNAVAILABLE"})
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class AppleLifecycleError(Exception):
    """Fixed public codes; provider evidence and callback exceptions are omitted."""
    def __init__(self, code):
        self.code = code if code in _CODES else "APPLE_ASSERTION_REJECTED"
        super().__init__(self.code)


def _boundary(default):
    def decorate(operation):
        @wraps(operation)
        def call(*args, **kwargs):
            code = default
            try:
                return operation(*args, **kwargs)
            except AppleLifecycleError as error:
                code = error.code
            except Exception:
                pass
            # Raise outside the handlers, including contextmanager unwinding.
            raise AppleLifecycleError(code) from None
        return call
    return decorate


def _key_id(value):
    if len(_decode_base64(value)) != 32:
        raise ValueError


def _scope(app_id, apple_app_id, environment, subject, key_id):
    _identifier(app_id)
    _identifier(subject)
    _key_id(key_id)
    if (type(apple_app_id) is not str or len(apple_app_id) > 266
            or re.fullmatch(r"[A-Z0-9]{10}\.[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*", apple_app_id) is None
            or type(environment) is not str or environment not in {"development", "production"}):
        raise ValueError


def _request_digest(request):
    if type(request) is not bytes or not 1 <= len(request) <= 1048576:
        raise ValueError
    return hashlib.sha256(request).hexdigest()


@dataclass(frozen=True)
class AppleAssertionChallenge:
    app_id: str
    apple_app_id: str
    environment: str
    subject: str = field(repr=False)
    key_id: str
    request_sha256: str
    nonce: str = field(repr=False)
    issued_at: int
    expires: int


@dataclass(frozen=True)
class AppleAttestedKey:
    key_id: str
    app_id: str
    apple_app_id: str
    environment: str
    subject: str = field(repr=False)
    public_key_der: bytes = field(repr=False)
    opaque_receipt: bytes = field(repr=False)
    validation_category: int | None
    bundle_version: str | None
    verified_at: int
    initial_challenge_sha256: str = field(repr=False)
    counter: int
    revoked: bool


@dataclass(frozen=True)
class AppleAssertionVerdict:
    app_id: str
    subject: str = field(repr=False)
    key_id: str
    environment: str
    request_sha256: str
    counter: int
    verified_at: int


@_boundary("APPLE_ASSERTION_REJECTED")
def assertion_client_data(challenge):
    """Exact bytes the native caller hashes once for generateAssertion.

    The service always reconstructs these from its stored challenge; client
    supplied challenge values are never accepted as server state.
    """
    if not isinstance(challenge, AppleAssertionChallenge):
        raise ValueError
    _scope(challenge.app_id, challenge.apple_app_id, challenge.environment, challenge.subject, challenge.key_id)
    _nonce(challenge.nonce)
    _time(challenge.issued_at)
    _time(challenge.expires)
    if (not challenge.issued_at < challenge.expires <= challenge.issued_at + 300
            or type(challenge.request_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", challenge.request_sha256) is None):
        raise ValueError
    return ("appguard-apple-assertion-v0\n"
        f"app-id: {challenge.app_id}\napple-app-id: {challenge.apple_app_id}\n"
        f"environment: {challenge.environment}\nsubject: {challenge.subject}\n"
        f"key-id: {challenge.key_id}\nrequest-sha256: {challenge.request_sha256}\n"
        f"challenge: {challenge.nonce}\nissued-at: {challenge.issued_at}\nexpires: {challenge.expires}").encode("ascii")


def _public_key(record):
    _scope(record.app_id, record.apple_app_id, record.environment, record.subject, record.key_id)
    if type(record.public_key_der) is not bytes or len(record.public_key_der) > 256:
        raise ValueError
    key = serialization.load_der_public_key(record.public_key_der)
    if (not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1)
            or key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != record.public_key_der
            or not hmac.compare_digest(hashlib.sha256(key.public_bytes(serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint)).digest(), _decode_base64(record.key_id))):
        raise ValueError
    return key


def _verify_assertion(record, challenge, assertion, categories, versions):
    if type(assertion) is not bytes or not 1 <= len(assertion) <= 8192:
        raise ValueError
    obj = _CBOR(assertion).complete()
    if type(obj) is not dict or set(obj) != {"signature", "authenticatorData"}:
        raise ValueError
    signature, auth = obj["signature"], obj["authenticatorData"]
    if (type(auth) is not bytes or not 37 <= len(auth) <= 4096 or auth[32] not in (0, 0x80)
            or not hmac.compare_digest(auth[:32], hashlib.sha256(record.apple_app_id.encode("ascii")).digest())
            or type(signature) is not bytes or not 8 <= len(signature) <= 72):
        raise ValueError
    reader = _CBOR(auth)
    reader.position = 37
    category, _ = _signed_properties(reader, auth[32], categories, versions)
    # A key registered with signed properties cannot silently lose them when a
    # host accidentally reconstructs its verifier with a legacy policy.
    if record.validation_category is not None and category is None:
        raise ValueError
    counter = int.from_bytes(auth[33:37], "big")
    if not record.counter < counter <= 0xffffffff:
        raise ValueError
    r, s = utils.decode_dss_signature(signature)
    if (not 0 < r < _P256_ORDER or not 0 < s < _P256_ORDER
            or utils.encode_dss_signature(r, s) != signature):
        raise ValueError
    nonce = hashlib.sha256(auth + hashlib.sha256(assertion_client_data(challenge)).digest()).digest()
    # nonce is already the SHA-256 digest. Hashing it again accepts the wrong
    # protocol. High-S is allowed: Apple does not promise low-S normalization.
    _public_key(record).verify(signature, nonce, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    return counter
