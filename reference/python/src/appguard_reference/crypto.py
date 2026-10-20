"""Supported library crypto only; RFC 9421 raw signature converts to DER."""

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .types import VerificationError


def load_p256_key(public_key_pem: bytes) -> ec.EllipticCurvePublicKey:
    if type(public_key_pem) is not bytes or not 1 <= len(public_key_pem) <= 4096:
        raise VerificationError("KEY_REJECTED")
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise VerificationError("KEY_REJECTED") from None
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise VerificationError("KEY_REJECTED")
    return key


def verify_p256(public_key_pem: bytes, signature_base: bytes, signature: bytes) -> None:
    key = load_p256_key(public_key_pem)
    if type(signature) is not bytes or len(signature) != 64:
        raise VerificationError("INVALID_SIGNATURE")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        key.verify(utils.encode_dss_signature(r, s), signature_base, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError):
        raise VerificationError("INVALID_SIGNATURE") from None
