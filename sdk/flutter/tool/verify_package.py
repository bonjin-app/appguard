#!/usr/bin/env python3
"""Validate safe, self-contained staged package contents and provenance."""
from pathlib import Path
import argparse
import hashlib
import json
import tarfile
import tempfile

package = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--archive', type=Path, default=package / '.evidence/appguard_flutter.tar.gz')
archive_path = parser.parse_args().archive.resolve()
with tempfile.TemporaryDirectory(dir=archive_path.parent, prefix='package-check-') as scratch:
    root = Path(scratch)
    with tarfile.open(archive_path) as archive:
        for member in archive.getmembers():
            assert member.isfile(), 'Only regular files are allowed'
            assert not member.name.startswith('/') and '..' not in Path(member.name).parts
        archive.extractall(root)
    manifest = json.loads((root / 'native-provenance.json').read_text())
    for source in manifest['sources']:
        assert not Path(source['path']).is_absolute() and '..' not in Path(source['path']).parts
        assert not Path(source['source']).is_absolute() and '..' not in Path(source['source']).parts
        assert hashlib.sha256((root / source['path']).read_bytes()).hexdigest() == source['sha256']
        assert hashlib.sha256((package.parents[1] / source['source']).read_bytes()).hexdigest() == source['sha256']
    assert (root / 'android/src/main/java/io/appguard/android/NativeBridge.java').is_file()
    assert (root / 'ios/Classes/Native/NativeBridge.swift').is_file()
    assert (root / 'ios/Classes/Native/Resources/PrivacyInfo.xcprivacy').is_file()
    assert not (root / 'ios/Tests').exists()
    assert not (root / 'tool').exists() and not (root / '.tools').exists()
    print(f'Package relocation: {len(manifest["sources"])} source/license SHA-256 hashes verified')
