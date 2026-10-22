#!/usr/bin/env python3
"""Collect original JAR license/NOTICE bytes for private maintainer review.

No license is inferred from a filename, and no distribution/legal approval is
granted. Missing materials remain visible. Only recorded runtime artifacts are
read, and archive paths are never extracted to the filesystem.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import tempfile
import zipfile

from assess import _path, _files, _json, _stamp
from runtime_catalog import _relative, _coordinate

MAX_JAR_BYTES = 64 * 1024 * 1024
MAX_DIRECTORY_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 25000
MAX_MATERIAL_BYTES = 1024 * 1024
MAX_TOTAL_MATERIAL_BYTES = 32 * 1024 * 1024
MAX_RUNTIME_BYTES = 1024 * 1024 * 1024
_ERROR = 'license_materials_unverified'


def _pin(path, limit, copy_to=None, keep=False):
    path = _path(path)
    initial = path.lstat()
    if not stat.S_ISREG(initial.st_mode) or initial.st_size > limit:
        raise ValueError(_ERROR)
    digest, body, size = hashlib.sha256(), bytearray(), 0
    output = copy_to.open('xb') if copy_to is not None else None
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            current = os.fstat(stream.fileno())
            if not stat.S_ISREG(current.st_mode) or _stamp(initial) != _stamp(current):
                raise ValueError(_ERROR)
            while chunk := stream.read(65536):
                size += len(chunk)
                if size > limit:
                    raise ValueError(_ERROR)
                digest.update(chunk)
                if output is not None:
                    output.write(chunk)
                if keep:
                    body.extend(chunk)
            if _stamp(initial) != _stamp(os.fstat(stream.fileno())):
                raise ValueError(_ERROR)
        if _stamp(initial) != _stamp(path.lstat()):
            raise ValueError(_ERROR)
    finally:
        if output is not None:
            output.close()
    return {'path': path, 'stamp': _stamp(initial), 'sha256': digest.hexdigest(), 'size': size,
            'body': bytes(body) if keep else None}


def _end_record(path):
    # Bound the classic ZIP central directory before ZipFile allocates entries.
    # PKWARE APPNOTE 6.3.10, 4.3.16. Zip64/multi-volume/SFX are unsupported here.
    size = path.stat().st_size
    if not 22 <= size <= MAX_JAR_BYTES:
        raise ValueError(_ERROR)
    with path.open('rb') as stream:
        stream.seek(max(0, size - 65557))
        tail = stream.read(65557)
    offset = tail.rfind(b'PK\x05\x06')
    if offset < 0 or len(tail) - offset < 22:
        raise ValueError(_ERROR)
    _, disk, start_disk, count, total, directory_size, directory_offset, comment_size = struct.unpack(
        '<4s4H2LH', tail[offset:offset + 22])
    if (disk or start_disk or count != total or not 0 < total <= MAX_ENTRIES
            or not 0 < directory_size <= MAX_DIRECTORY_BYTES
            or directory_offset + directory_size != size - len(tail) + offset
            or offset + 22 + comment_size != len(tail)):
        raise ValueError(_ERROR)
    return total


def _materials(path):
    count = _end_record(path)
    result, names, total_bytes = [], set(), 0
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) != count:
            raise ValueError(_ERROR)
        for entry in entries:
            name = entry.filename
            if len(name) > 1024 or entry.orig_filename != name:
                raise ValueError(_ERROR)
            _relative(name[:-1] if entry.is_dir() else name)
            if name in names or stat.S_ISLNK(entry.external_attr >> 16) or entry.flag_bits & 1:
                raise ValueError(_ERROR)
            names.add(name)
            if entry.is_dir():
                continue
            basename = PurePosixPath(name).name.upper()
            if not basename.startswith(('LICENSE', 'NOTICE', 'COPYING')):
                continue
            if entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise ValueError(_ERROR)
            if not 0 < entry.file_size <= MAX_MATERIAL_BYTES:
                raise ValueError(_ERROR)
            with archive.open(entry) as stream:
                raw = stream.read(MAX_MATERIAL_BYTES + 1)
            if len(raw) != entry.file_size or len(raw) > MAX_MATERIAL_BYTES:
                raise ValueError(_ERROR)
            total_bytes += len(raw)
            if total_bytes > MAX_TOTAL_MATERIAL_BYTES:
                raise ValueError(_ERROR)
            result.append((name, raw, 'notice' if basename.startswith('NOTICE') else 'license'))
    return result


def _publish(output, staged):
    output.mkdir(mode=0o700)
    identity = _stamp(output.lstat())[:2]
    descriptor = None
    linked = []
    try:
        descriptor = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if _stamp(os.fstat(descriptor))[:2] != identity:
            raise ValueError(_ERROR)
        for name in ('license-materials.json', 'THIRD_PARTY_NOTICES.review.md', 'materials.zip'):
            os.link(staged / name, name, dst_dir_fd=descriptor, follow_symlinks=False)
            linked.append(name)
        if _stamp(output.lstat())[:2] != identity:
            raise ValueError(_ERROR)
    except Exception:
        if descriptor is not None:
            for name in linked:
                os.unlink(name, dir_fd=descriptor)
        if output.exists() and _stamp(output.lstat())[:2] == identity:
            output.rmdir()
        raise ValueError(_ERROR) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _collect_materials(artifacts, manifest, output):
    """Return the unapproved review index; output must be new and outside inputs."""
    root, manifest = _path(artifacts, directory=True), _path(manifest)
    output = _path(output, new=True)
    if output == root or root in output.parents or output in root.parents or manifest in (output, root):
        raise ValueError(_ERROR)
    original_manifest = _pin(manifest, 8 * 1024 * 1024, keep=True)
    data = _json(original_manifest['body'])
    expected, jars = data.get('sha256'), data.get('jar_sha256')
    if (type(data.get('returncode')) is not int or data['returncode'] != 0
            or not isinstance(expected, dict) or not isinstance(jars, dict)
            or not jars or len(expected) > 10000 or len(jars) > 2048):
        raise ValueError(_ERROR)
    for name, digest in expected.items():
        _relative(name)
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError(_ERROR)
    if jars != {name: digest for name, digest in expected.items() if name.endswith('.jar')}:
        raise ValueError(_ERROR)
    if {str(p.relative_to(root)) for p in _files(root)} != set(expected):
        raise ValueError(_ERROR)
    report = {'schema': 1, 'scope': 'Original material files in verified exported Maven runtime JARs only',
              'review_completed': False, 'third_party_notices_complete': False, 'release_ready': False,
              'manifest_sha256': original_manifest['sha256'], 'jar_count': len(jars),
              'missing_material_count': 0, 'material_count': 0, 'records': [],
              'limitations': ['No legal approval or license inference', 'Missing and conflicting obligations need maintainer review',
                             'Classic bounded ZIP only; OS/native/source dependencies require separate materials']}
    with tempfile.TemporaryDirectory(prefix='.license-materials-', dir=output.parent) as temporary:
        staged = Path(temporary)
        staged.chmod(0o700)
        pins, documents, total_input, total_material = [], {}, 0, 0
        for index, (name, digest) in enumerate(sorted(expected.items())):
            copied = staged / ('input-' + str(index)) if name in jars else None
            pin = _pin(root / name, MAX_JAR_BYTES, copy_to=copied)
            if pin['sha256'] != digest:
                raise ValueError(_ERROR)
            pins.append(pin)
            total_input += pin['size']
            if total_input > MAX_RUNTIME_BYTES:
                raise ValueError(_ERROR)
            if name not in jars:
                continue
            coordinate = _coordinate(name)
            materials = []
            for original, raw, kind in _materials(copied):
                content_hash = hashlib.sha256(raw).hexdigest()
                documents[content_hash] = raw
                total_material += len(raw)
                if total_material > MAX_TOTAL_MATERIAL_BYTES:
                    raise ValueError(_ERROR)
                materials.append({'archive_path': original, 'kind': kind, 'sha256': content_hash,
                                  'bytes': len(raw), 'bundle_path': 'materials/' + content_hash + '.txt'})
            copied.unlink()
            report['records'].append({'coordinate': coordinate, 'jar_sha256': digest, 'artifact_path': name,
                'materials': materials, 'review_status': 'pending' if materials else 'missing_original_materials'})
            report['material_count'] += len(materials)
            report['missing_material_count'] += not bool(materials)
        with zipfile.ZipFile(staged / 'materials.zip', 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            for digest, raw in sorted(documents.items()):
                info = zipfile.ZipInfo('materials/' + digest + '.txt', (1980, 1, 1, 0, 0, 0))
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, raw)
        report['bundle_sha256'] = hashlib.sha256((staged / 'materials.zip').read_bytes()).hexdigest()
        (staged / 'license-materials.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        lines = ['# Third-party original materials (unapproved)', '',
                 'Private review inventory; not complete distribution notices or a legal approval.',
                 'Exact original files are in materials.zip. Match hashes and inspect every obligation.', '',
                 'JARs: ' + str(report['jar_count']) + '; without material: ' + str(report['missing_material_count']), '']
        for record in report['records']:
            c = record['coordinate']
            lines.append('- ' + c['group'] + ':' + c['name'] + ':' + c['version'] + ' — ' + record['review_status'])
        (staged / 'THIRD_PARTY_NOTICES.review.md').write_text('\n'.join(lines) + '\n')
        if {str(p.relative_to(root)) for p in _files(root)} != set(expected):
            raise ValueError(_ERROR)
        for previous in (original_manifest, *pins):
            current = _pin(previous['path'], MAX_JAR_BYTES)
            if any(previous[key] != current[key] for key in ('sha256', 'stamp')):
                raise ValueError(_ERROR)
        for name in ('license-materials.json', 'THIRD_PARTY_NOTICES.review.md', 'materials.zip'):
            (staged / name).chmod(0o600)
        _publish(output, staged)
    return report


def collect_materials(artifacts, manifest, output):
    try:
        return _collect_materials(artifacts, manifest, output)
    except Exception:
        raise ValueError(_ERROR) from None


class _Parser(argparse.ArgumentParser):
    def error(self, _):
        self.exit(2, _ERROR + '\n')


def main():
    parser = _Parser(description=__doc__)
    for flag in ('artifacts', 'manifest', 'output'):
        parser.add_argument('--' + flag, required=True, type=Path)
    parser.add_argument('--check', action='store_true', help='Exit 2 if any JAR lacks original material; never grants legal approval')
    args = parser.parse_args()
    try:
        result = collect_materials(args.artifacts, args.manifest, args.output)
    except Exception:
        print('{"release_ready":false,"reason":"license_materials_unverified"}')
        return 2
    print(json.dumps({key: result[key] for key in ('jar_count', 'missing_material_count', 'material_count',
        'manifest_sha256', 'bundle_sha256', 'review_completed', 'release_ready')}, sort_keys=True))
    return 2 if args.check and result['missing_material_count'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
