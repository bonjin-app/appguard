import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from appguard.types import KeyRecord

ROOT = Path(__file__).resolve().parents[3]
VECTOR = json.loads((ROOT / "conformance/v0/requests.json").read_text())[0]
NOW = VECTOR["context"]["now"]
ORIGIN = VECTOR["context"]["origin"]


@pytest.fixture
def key():
    data = {**VECTOR["key"], "public_key_pem": VECTOR["key"]["public_key_pem"].encode()}
    return KeyRecord(**data)


@pytest.fixture
def headers():
    return VECTOR["request"]["headers"] + [
        ["Signature-Input", "appguard=" + VECTOR["expected_signature_base"].split('"@signature-params": ', 1)[1]],
        ["Signature", "appguard=:" + VECTOR["signature_b64"] + ":"],
    ]


@pytest.fixture
def body():
    return base64.b64decode(VECTOR["request"]["body_b64"])


@pytest.fixture
def signed_case():
    """Test-only signing for new boundary inputs; fixed corpus remains independent."""
    import hashlib
    from appguard.canonical import build_signature_base
    from appguard.types import RequestInput, SignatureParameters

    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign(target, body=b"{}", content_type="application/json"):
        digest = "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"
        pairs = (("Content-Type", content_type), ("Content-Digest", digest),
                 ("Authorization", "Bearer TEST_ONLY_TOKEN"), ("AppGuard-App-Id", "test-app"))
        params = SignatureParameters(**VECTOR["parameters"])
        base = build_signature_base(RequestInput("POST", target, pairs, body), params, origin=ORIGIN)
        r, s = utils.decode_dss_signature(private.sign(base, ec.ECDSA(hashes.SHA256())))
        signature = base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()
        headers = list(pairs) + [("Signature-Input", "appguard=" + base.decode().split('"@signature-params": ', 1)[1]),
                                ("Signature", "appguard=:" + signature + ":")]
        key = KeyRecord("test-app", "test-key", "test-user", pem, "ecdsa-p256-sha256", False)
        return headers, key

    return sign
