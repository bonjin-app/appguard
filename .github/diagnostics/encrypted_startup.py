"""Temporary CI-only startup diagnostics; remove after the failure is resolved."""
import base64
import importlib.util
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('owned_containers', ROOT / 'scripts/qualification/spring_containers.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
original = runner.startup_diagnostics
AAD = b'AppGuard ephemeral startup diagnostic v1'


def encrypted_diagnostics(docker, project, owner, error):
    try:
        records = runner.records_for(docker, project, owner)
        # records_for verifies full container IDs and exact ownership labels.
        errors = {role: record.get('State', {}).get('Error', '')[:8192]
                  for role, record in records.items() if role in {'gateway', 'backend', 'redis'}}
        plaintext = json.dumps(errors, sort_keys=True).encode()
        assert len(plaintext) <= 128 * 1024
        public = serialization.load_pem_public_key((Path(__file__).parent / 'startup-public.pem').read_bytes())
        assert isinstance(public, rsa.RSAPublicKey) and public.key_size == 3072
        key, nonce = os.urandom(32), os.urandom(12)
        packet = {'schema': 1, 'wrapped_key': public.encrypt(key, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=AAD)),
            'nonce': nonce, 'ciphertext': AESGCM(key).encrypt(nonce, plaintext, AAD)}
        packet = {k: base64.b64encode(v).decode() if isinstance(v, bytes) else v for k, v in packet.items()}
        output = Path(os.environ['RUNNER_TEMP']) / 'appguard-startup.encrypted.json'
        with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w') as stream:
            json.dump(packet, stream)
    except Exception:
        # Diagnostics must not prevent the qualifier's cleanup or expose errors.
        pass
    return original(docker, project, owner, error)


if __name__ == '__main__':
    runner.startup_diagnostics = encrypted_diagnostics
    raise SystemExit(runner.main())
