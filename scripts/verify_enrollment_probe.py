"""Test-only cross-language enrollment with a fixed synthetic challenge nonce.

The native producer owns the private key. Only this fixture's entropy source is
fixed; real EnrollmentService issuance always uses the OS-backed secrets module.
This does not exercise an HTTP/provider enrollment service.
"""

import base64
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from appguard.crypto import load_p256_key, verify_p256
from appguard.enrollment import EnrollmentError, EnrollmentService, SqliteEnrollmentStore, enrollment_message


def check(path):
    raw = Path(path).read_bytes()
    if len(raw) > 32768:
        raise ValueError("enrollment fixture too large")
    value = json.loads(raw)
    c = value["challenge"]
    pem = value["public_key_pem"].encode("ascii")
    proof = base64.b64decode(value["proof_b64"], validate=True)
    now = value["context"]["now"]
    with tempfile.TemporaryDirectory(prefix="appguard-enrollment-") as directory:
        store = SqliteEnrollmentStore(Path(directory) / "enrollment.sqlite")
        service = EnrollmentService(store, profile="basic", clock=lambda: now)
        with patch("appguard.enrollment.secrets.token_urlsafe", return_value=c["nonce"]):
            challenge = service.issue(app_id=c["app_id"], subject=c["subject"], key_id=c["key_id"],
                                      origin=c["origin"], public_key_pem=pem, ttl=c["expires"] - now)
        assert challenge.public_key_sha256 == c["public_key_sha256"]
        verify_p256(pem, enrollment_message(challenge), proof)
        result = service.complete(challenge.nonce, app_id=c["app_id"], subject=c["subject"], proof=proof)
        assert load_p256_key(result.key.public_key_pem).public_numbers() == load_p256_key(pem).public_numbers()
        assert result.attestation == "missing" and result.provider is None
        try:
            service.complete(challenge.nonce, app_id=c["app_id"], subject=c["subject"], proof=proof)
        except EnrollmentError as error:
            assert error.code == "CHALLENGE_REJECTED"
        else:
            raise AssertionError("native enrollment replay accepted")
        assert store.revoke(c["app_id"], c["subject"], c["key_id"])
        assert store.lookup(c["app_id"], c["subject"], c["key_id"]).key.revoked is True
    print(f"{Path(path).name}: native proof, SQLite one-use and revocation pass (Basic, unattested)", flush=True)


if __name__ == "__main__":
    for path in sys.argv[1:]:
        check(path)
