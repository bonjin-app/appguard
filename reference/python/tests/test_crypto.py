"""Catch signature encoding confusion and algorithm/key substitution."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from appguard_reference.crypto import verify_p256
from appguard_reference.types import VerificationError
from conftest import EXPECTED_BASE


def test_openssl_signature_verifies(public_key, signature):
    assert verify_p256(public_key, EXPECTED_BASE, signature) is None


@pytest.mark.parametrize("length", [0, 1, 63, 65, 72, 1000])
def test_wrong_signature_length(public_key, length):
    with pytest.raises(VerificationError, match="^INVALID_SIGNATURE$"):
        verify_p256(public_key, EXPECTED_BASE, b"x" * length)


def test_changed_signature(public_key, signature):
    altered = bytes([signature[0] ^ 1]) + signature[1:]
    with pytest.raises(VerificationError, match="^INVALID_SIGNATURE$"):
        verify_p256(public_key, EXPECTED_BASE, altered)


def test_changed_signed_bytes(public_key, signature):
    with pytest.raises(VerificationError, match="^INVALID_SIGNATURE$"):
        verify_p256(public_key, EXPECTED_BASE + b"\n", signature)


@pytest.mark.parametrize("curve", [ec.SECP384R1(), ec.SECP521R1()])
def test_wrong_curve_rejected(curve, signature):
    pem = ec.generate_private_key(curve).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(VerificationError, match="^KEY_REJECTED$"):
        verify_p256(pem, EXPECTED_BASE, signature)


@pytest.mark.parametrize("pem", [b"bad-key", b"", b"x" * 4097])
def test_bad_public_key_is_fixed_error(pem, signature):
    with pytest.raises(VerificationError, match="^KEY_REJECTED$"):
        verify_p256(pem, EXPECTED_BASE, signature)
