#!/usr/bin/env python3
"""Validate safe, self-contained staged package contents and provenance."""
from pathlib import Path
import hashlib
import json
import tarfile
import tempfile

package = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(dir=package / '.evidence', prefix='package-check-') as scratch:
    root = Path(scratch)
    with tarfile.open(package / '.evidence/appguard_flutter.tar.gz') as archive:
        for member in archive.getmembers():
            assert member.isfile(), 'Only regular files are allowed'
            assert not member.name.startswith('/') and '..' not in Path(member.name).parts
        archive.extractall(root)
    manifest = json.loads((root / 'native-provenance.json').read_text())
    for source in manifest['sources']:
        assert not Path(source['path']).is_absolute() and '..' not in Path(source['path']).parts
        assert hashlib.sha256((root / source['path']).read_bytes()).hexdigest() == source['sha256']
    assert (root / 'android/src/main/java/io/appguard/android/NativeBridge.java').is_file()
    assert (root / 'ios/Classes/Native/NativeBridge.swift').is_file()
    assert not (root / 'tool').exists() and not (root / '.tools').exists()
    print(f'Package relocation: {len(manifest["sources"])} source/license SHA-256 hashes verified')
