"""Synthetic fixtures: the expected signature base is hand-written, not built."""

import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from appguard_reference.types import KeyRecord, RequestInput, SignatureParameters

ROOT = Path(__file__).resolve().parents[3]
ORIGIN = "https://api.example.test"
NOW = 1700000000
DIGEST = "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:"
EXPECTED_BASE = b'''"@method": POST
"@target-uri": https://api.example.test/v1/items?b=2&a=1
"content-type": application/json
"content-digest": sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:
"authorization": Bearer TEST_ONLY_TOKEN
"appguard-app-id": test-app
"@signature-params": ("@method" "@target-uri" "content-type" "content-digest" "authorization" "appguard-app-id");created=1700000000;expires=1700000120;nonce="AAECAwQFBgcICQoLDA0ODw";keyid="test-key";alg="ecdsa-p256-sha256";tag="appguard-request-v0"'''


@pytest.fixture
def request_input():
    return RequestInput("POST", "/v1/items?b=2&a=1", (
        ("Content-Type", "application/json"), ("Content-Digest", DIGEST),
        ("Authorization", "Bearer TEST_ONLY_TOKEN"), ("AppGuard-App-Id", "test-app"),
    ), b"{}")


@pytest.fixture
def parameters():
    return SignatureParameters(NOW, NOW + 120, "AAECAwQFBgcICQoLDA0ODw",
                               "test-key", "ecdsa-p256-sha256", "appguard-request-v0")


@pytest.fixture
def public_key():
    return (ROOT / "conformance/v0/test-public-key.pem").read_bytes()


@pytest.fixture
def signature():
    return base64.b64decode((ROOT / "conformance/v0/test-signature.b64").read_text(), validate=False)


@pytest.fixture
def key_record(public_key):
    return KeyRecord("test-app", "test-key", "test-user", public_key, "ecdsa-p256-sha256", False)


@pytest.fixture
def sign_case():
    """Test-only signer for boundary cases; fixed OpenSSL fixtures remain separate."""
    from appguard_reference.canonical import build_signature_base

    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign(request, parameters):
        base = build_signature_base(request, parameters, origin=ORIGIN)
        r, s = utils.decode_dss_signature(private.sign(base, ec.ECDSA(hashes.SHA256())))
        return KeyRecord("test-app", parameters.key_id, "test-user", pem, parameters.algorithm, False), (
            r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    return sign
