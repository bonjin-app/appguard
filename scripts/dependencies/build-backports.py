#!/usr/bin/env python3
"""Reassemble retained, pinned tool derivatives. Data only; never execute packages."""
import argparse
import base64
import binascii
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import struct
import tarfile
import zlib

MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024
MAX_FILES = 512
IDENTITIES = {'braces': ('3.0.3', 'MIT'), 'node-forge': ('1.4.0', '(BSD-3-Clause OR GPL-2.0)')}
ERROR = 'backport verification failed'


class BackportError(ValueError):
    """Fixed public failure; do not expose local paths or input values."""


def require(condition):
    if not condition:
        raise BackportError(ERROR)


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected.split()))


def path_name(value, prefix=None):
    require(type(value) is str and bool(value) and '\\' not in value)
    parts = PurePosixPath(value).parts
    require('/'.join(parts) == value and all(p not in ('', '.', '..') for p in parts))
    require(not value.startswith('/') and (prefix is None or value.startswith(prefix + '/')))
    require(all(re.fullmatch(r'[A-Za-z0-9_@.+-]+', part) for part in parts))
    return value


def digest(data):
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}


def integrity(data):
    return 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode('ascii')


def hash_record(value, with_sri=False):
    require(type(value) is dict and type(value.get('size')) is int and 0 <= value['size'] <= MAX_EXPANDED)
    require(type(value.get('sha256')) is str and re.fullmatch(r'[0-9a-f]{64}', value['sha256']) is not None)
    if with_sri:
        sri = value.get('integrity')
        require(type(sri) is str and sri.startswith('sha512-'))
        try:
            decoded = base64.b64decode(sri[7:], validate=True)
        except (ValueError, binascii.Error):
            raise BackportError(ERROR) from None
        require(len(decoded) == 64 and base64.b64encode(decoded).decode('ascii') == sri[7:])


def checked_read(root, name, expected, cap=MAX_EXPANDED):
    path_name(name)
    target = root / name
    # Every component must be an ordinary directory/file in the retained input tree.
    require(root.is_dir() and not root.is_symlink())
    current = root
    for part in PurePosixPath(name).parts:
        current = current / part
        require(not current.is_symlink())
    require(target.is_file() and target.stat().st_size <= cap)
    data = target.read_bytes()
    require(digest(data) == {key: expected[key] for key in ('sha256', 'size')})
    if 'integrity' in expected:
        require(integrity(data) == expected['integrity'])
    return data


def json_data(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def validate_record(record):
    keys(record, 'id upstream fork inputs replacements result_files archive provenance')
    ident = record['id']
    require(type(ident) is str and ident in IDENTITIES)
    version = IDENTITIES[ident][0]
    up = record['upstream']
    keys(up, 'name version url path sha256 integrity size')
    require(up['name'] == ident and up['version'] == version)
    require(up['url'] == f'https://registry.npmjs.org/{ident}/-/{ident}-{version}.tgz')
    require(up['path'] == f'{ident}/upstream.tgz')
    hash_record(up, True)
    require(up['size'] <= MAX_ARCHIVE)
    keys(record['fork'], 'name version')
    require(record['fork'] == {'name': '@appguard/' + ident, 'version': version + '-appguard.1'})
    archive = record['archive']
    keys(archive, 'path sha256 integrity size')
    require(archive['path'] == f'archives/appguard-{ident}-{version}-appguard.1.tgz')
    hash_record(archive, True)
    require(archive['size'] <= MAX_ARCHIVE)
    inputs = record['inputs']
    require(type(inputs) is dict and 1 <= len(inputs) <= MAX_FILES)
    for name, value in inputs.items():
        path_name(name, ident)
        require(not any(part in {'build', 'dist', 'vendor', 'artifacts'} for part in PurePosixPath(name).parts))
        keys(value, 'sha256 size')
        hash_record(value)
    require(sum(value['size'] for value in inputs.values()) <= MAX_EXPANDED)
    require(record['provenance'] == ident + '/provenance.json' and record['provenance'] in inputs)
    for required in ('original-package.json', 'LICENSE', 'source.patch', 'replacements/package.json'):
        require(ident + '/' + required in inputs)
    replacements = record['replacements']
    require(type(replacements) is list and 1 <= len(replacements) <= MAX_FILES)
    names = set()
    for entry in replacements:
        keys(entry, 'path input')
        path_name(entry['path'], 'package')
        # The full original license is immutable, including after replacements.
        require(entry['path'] != 'package/LICENSE')
        require(entry['path'] not in names and entry['input'] in inputs)
        names.add(entry['path'])
    require('package/package.json' in names)
    results = record['result_files']
    require(type(results) is dict and 1 <= len(results) <= MAX_FILES)
    for name, value in results.items():
        path_name(name, 'package')
        keys(value, 'sha256 size')
        hash_record(value)
    require(sum(value['size'] for value in results.values()) <= MAX_EXPANDED)


def validate_manifest(manifest):
    keys(manifest, 'schema packages')
    require(type(manifest['schema']) is int and manifest['schema'] == 1)
    require(type(manifest['packages']) is list and len(manifest['packages']) == 2)
    require([p.get('id') if type(p) is dict else None for p in manifest['packages']] == list(IDENTITIES))
    for record in manifest['packages']:
        validate_record(record)


def public_guard(function):
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, tarfile.TarError, EOFError, struct.error, zlib.error):
            raise BackportError(ERROR) from None
    return guarded


@public_guard
def load_manifest(root: Path) -> dict:
    root = Path(root)
    target = root / 'manifest.json'
    require(not target.is_symlink() and target.stat().st_size <= 2 * 1024 * 1024)
    manifest = json_data(target.read_bytes())
    validate_manifest(manifest)
    return manifest


def upstream_files(data):
    # Bound decompression before tar parsing; never extract onto the filesystem.
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        expanded = compressed.read(MAX_EXPANDED + 1)
    require(len(expanded) <= MAX_EXPANDED)
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        count = 0
        for entry in archive:
            count += 1
            require(count <= MAX_FILES)
            path_name(entry.name, 'package')
            require(entry.isfile() and entry.name not in files and not entry.pax_headers)
            require(type(entry.size) is int and 0 <= entry.size <= MAX_EXPANDED)
            total += entry.size
            require(total <= MAX_EXPANDED)
            stream = archive.extractfile(entry)
            require(stream is not None)
            content = stream.read(entry.size + 1)
            require(len(content) == entry.size)
            files[entry.name] = content
    require(bool(files))
    return files


def validate_metadata(record, files, inputs):
    ident = record['id']
    original_bytes = inputs[ident + '/original-package.json']
    original = json_data(original_bytes)
    require(original_bytes == files['package/package.json'])
    require(original['name'] == ident and original['version'] == record['upstream']['version'])
    require(inputs[ident + '/LICENSE'] == files['package/LICENSE'])
    modified = json_data(inputs[ident + '/replacements/package.json'])
    expected = dict(original)
    expected.update(record['fork'])
    expected['private'] = True
    expected.pop('scripts', None)
    expected.pop('devDependencies', None)
    expected['engines'] = dict(original.get('engines', {}), node='>=22.13.0')
    require(type(modified) is dict and modified.get('private') is True)
    require(json.dumps(modified, sort_keys=True) == json.dumps(expected, sort_keys=True))
    replacement = [entry for entry in record['replacements'] if entry['path'] == 'package/package.json']
    require(replacement == [{'path': 'package/package.json', 'input': ident + '/replacements/package.json'}])
    provenance = json_data(inputs[record['provenance']])
    require(type(provenance) is dict)
    require(provenance.get('upstream') == {'name': ident, 'version': record['upstream']['version']})
    require(provenance.get('license') == IDENTITIES[ident][1])
    changes = {key: {'before': original.get(key), 'after': modified.get(key)}
               for key in set(original) | set(modified) if original.get(key) != modified.get(key)}
    require(json.dumps(provenance.get('metadata_changes'), sort_keys=True) == json.dumps(changes, sort_keys=True))
    if ident == 'node-forge':
        require(provenance.get('compilation_reproduction_verified') is False)
        require(provenance.get('producer_closure_verified') is False)


def stored_gzip(data):
    result = bytearray(bytes.fromhex('1f8b08000000000000ff'))
    for start in range(0, len(data), 65535):
        block = data[start:start + 65535]
        result += bytes([int(start + len(block) == len(data))])
        result += struct.pack('<HH', len(block), len(block) ^ 0xffff)
        result += block
    if not data:
        result += b'\x01\x00\x00\xff\xff'
    result += struct.pack('<II', zlib.crc32(data), len(data) & 0xffffffff)
    return bytes(result)


@public_guard
def assemble_package(root: Path, record: dict) -> bytes:
    root = Path(root)
    validate_record(record)
    upstream = checked_read(root, record['upstream']['path'], record['upstream'], MAX_ARCHIVE)
    files = upstream_files(upstream)
    inputs = {name: checked_read(root, name, expected) for name, expected in record['inputs'].items()}
    validate_metadata(record, files, inputs)
    for replacement in record['replacements']:
        files[replacement['path']] = inputs[replacement['input']]
    require({name: digest(content) for name, content in files.items()} == record['result_files'])
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, content in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(content), 0o644
            entry.uid = entry.gid = entry.mtime = 0
            entry.uname = entry.gname = ''
            archive.addfile(entry, io.BytesIO(content))
    result = stored_gzip(stream.getvalue())
    require(len(result) <= MAX_ARCHIVE)
    return result


def assembled(root, manifest):
    validate_manifest(manifest)
    result = []
    for record in manifest['packages']:
        data = assemble_package(root, record)
        expected = record['archive']
        require(digest(data) == {key: expected[key] for key in ('sha256', 'size')})
        require(integrity(data) == expected['integrity'])
        result.append((record, data))
    return result


def summary(values):
    return {'verified': True, 'packages': [dict(id=record['id'], files=len(record['result_files']),
            sha256=digest(data)['sha256'], integrity=integrity(data), size=len(data)) for record, data in values],
            'compilation_reproduction_verified': False, 'producer_closure_verified': False,
            'consumer_adoption_verified': False, 'source_gate_passed': False, 'release_ready': False}


@public_guard
def check_archives(root: Path, manifest: dict) -> dict:
    root = Path(root)
    values = assembled(root, manifest)
    for record, data in values:
        require(checked_read(root, record['archive']['path'], record['archive'], MAX_ARCHIVE) == data)
    return summary(values)


@public_guard
def write_archives(root: Path, manifest: dict, output: Path) -> dict:
    values = assembled(Path(root), manifest)
    output = Path(output)
    # mkdir(exist_ok=False) is the no-overwrite boundary, including empty directories.
    output.mkdir(mode=0o700, exist_ok=False)
    output.chmod(0o700)
    for record, data in values:
        target = output / PurePosixPath(record['archive']['path']).name
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(0o600)
    return summary(values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true')
    group.add_argument('--output', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2] / 'tools/dependency-backports'
    try:
        manifest = load_manifest(root)
        result = check_archives(root, manifest) if args.check else write_archives(root, manifest, args.output)
    except BackportError:
        print(json.dumps({'verified': False, 'error': ERROR}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
