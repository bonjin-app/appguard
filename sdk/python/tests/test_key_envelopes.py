"""Reject ambiguous trusted key encodings before reserving a nonce."""
import base64
import json
from pathlib import Path

import pytest

from appguard.replay import InMemoryReplayStore
from appguard.types import KeyRecord, RequestInput, SignatureParameters, VerificationError
from appguard.verify import verify_request
from conftest import VECTOR

CASES = json.loads((Path(__file__).resolve().parents[3] / "conformance/v0/public-key-pem.json").read_text())
assert len(CASES) == 23


def verify(pem, store):
    r = VECTOR["request"]
    key = KeyRecord(**{**VECTOR["key"], "public_key_pem": pem.encode()})
    return verify_request(RequestInput(r["method"], r["target"], tuple(map(tuple, r["headers"])),
                                      base64.b64decode(r["body_b64"])),
                          SignatureParameters(**VECTOR["parameters"]), base64.b64decode(VECTOR["signature_b64"]),
                          **VECTOR["context"], key=key, replay=store)


class CountingStore(InMemoryReplayStore):
    def __init__(self):
        super().__init__()
        self.calls = 0

    def claim(self, *args, **kwargs):
        self.calls += 1
        return super().claim(*args, **kwargs)


@pytest.mark.parametrize("row", CASES, ids=lambda row: row["id"])
def test_shared_key_envelopes(row):
    store = CountingStore()
    if row["expected_code"] == "VERIFIED":
        assert verify(row["pem"], store).code == "VERIFIED"
    else:
        with pytest.raises(VerificationError, match="^KEY_REJECTED$"):
            verify(row["pem"], store)
        assert store.calls == 0
        assert verify(VECTOR["key"]["public_key_pem"], store).code == "VERIFIED"
    assert store.calls == 1


def test_compressed_point_compatibility():
    der = base64.b64decode("".join(VECTOR["key"]["public_key_pem"].splitlines()[1:-1]))
    point = der[-65:]
    compressed = bytes([2 | (point[-1] & 1)]) + point[1:33]
    spki = bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200") + compressed
    pem = "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(spki).decode() + "\n-----END PUBLIC KEY-----\n"
    store = CountingStore()
    assert verify(pem, store).code == "VERIFIED" and store.calls == 1
