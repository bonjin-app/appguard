#!/usr/bin/env python3
"""Create a relocatable local experimental package, never publish it."""
from pathlib import Path
import gzip
import io
import subprocess
import sys
import tarfile

package = Path(__file__).resolve().parents[1]
subprocess.run([sys.executable, str(package / 'tool/stage_native.py')], check=True)
output = package / '.evidence/appguard_flutter.tar.gz'
output.parent.mkdir(exist_ok=True)
roots = ['pubspec.yaml', 'lib', 'android/build.gradle', 'android/settings.gradle',
         'android/src/main', 'ios', 'native-licenses', 'native-provenance.json',
         'README.md', 'VERIFICATION.md', 'CHANGELOG.md', 'LICENSE']
with output.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0, filename='') as compressed:
    with tarfile.open(fileobj=compressed, mode='w') as archive:
        for root in roots:
            path = package / root
            files = [path] if path.is_file() else sorted(p for p in path.rglob('*') if p.is_file())
            for file in files:
                if file.is_symlink():
                    raise SystemExit('Refusing package symlink')
                info = tarfile.TarInfo(str(file.relative_to(package)))
                data = file.read_bytes()
                info.size, info.mtime, info.mode = len(data), 0, 0o644
                archive.addfile(info, io.BytesIO(data))
print(output)
