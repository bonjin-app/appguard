"""Temporary ciphertext-only capture of owned image reports for local triage."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import stat

from encrypted_startup import encrypt_packet, ROOT

spec = importlib.util.spec_from_file_location('owned_image_scan', ROOT / 'scripts/qualification/scan_container_images.py')
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)

if __name__ == '__main__':
    code = scanner.main()
    try:
        directory = Path(os.environ['RUNNER_TEMP']) / 'appguard-container-image-scans'
        reports = {}
        for role in ('gateway', 'backend', 'redis'):
            for name in ('trivy-' + role + '.json', role + '.log'):
                path = directory / name
                if not path.exists():
                    continue
                with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
                    before = os.fstat(stream.fileno())
                    assert stat.S_ISREG(before.st_mode) and before.st_size <= 16 * 1024 * 1024
                    data = stream.read(16 * 1024 * 1024 + 1)
                    after = os.fstat(stream.fileno())
                    fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                    assert len(data) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields)
                reports[name] = base64.b64encode(data).decode()
        encrypt_packet(json.dumps(reports, sort_keys=True).encode(), 'appguard-image-scan.encrypted.json')
    except Exception:
        pass
    raise SystemExit(code)
