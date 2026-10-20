#!/usr/bin/env python3
"""Stage owned native SDK sources before local use or packing; no build-time escapes."""
from pathlib import Path
import hashlib
import json
import shutil

package = Path(__file__).resolve().parents[1]
repo = package.parents[1]
manifest = {'schema': 1, 'sources': []}
for name, source, destination in [
    ('android', repo / 'sdk/android/src/main/java/io/appguard/android', package / 'android/src/main/java/io/appguard/android'),
    ('apple', repo / 'sdk/apple/Sources/AppGuardApple', package / 'ios/Classes/Native'),
]:
    if not (source / ('NativeBridge.java' if name == 'android' else 'NativeBridge.swift')).is_file():
        raise SystemExit(f'Native facade missing: {name}')
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for path in sorted(source.rglob('*')):
        if path.is_symlink():
            raise SystemExit('Refusing source symlink')
        if path.is_file():
            target = destination / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            manifest['sources'].append({'source': str(path.relative_to(repo)), 'path': str(target.relative_to(package)), 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()})
    license_path = package / 'native-licenses' / (name + '-LICENSE')
    license_path.parent.mkdir(exist_ok=True)
    shutil.copyfile(repo / 'sdk' / name / 'LICENSE', license_path)
    manifest['sources'].append({'source': f'sdk/{name}/LICENSE', 'path': str(license_path.relative_to(package)), 'sha256': hashlib.sha256(license_path.read_bytes()).hexdigest()})
(package / 'native-provenance.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(f'Staged {len(manifest["sources"])} native source/license files')
