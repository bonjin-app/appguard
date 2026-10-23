"""Data-only packaging regressions; no package or lifecycle code executes."""
import base64
import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/dependencies/build-backports.py'
spec = importlib.util.spec_from_file_location('tool_backports', SCRIPT)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


def info(data):
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}


def sri(data):
    return 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode()


def reference_tar(files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(data), 0o644
            archive.addfile(entry, io.BytesIO(data))
    return out.getvalue()


def reference_gzip(data):
    result = bytearray(bytes.fromhex('1f8b08000000000000ff'))
    for offset in range(0, len(data), 65535):
        block = data[offset:offset + 65535]
        result += bytes([int(offset + len(block) == len(data))])
        result += struct.pack('<HH', len(block), 65535 - len(block)) + block
    result += struct.pack('<II', __import__('zlib').crc32(data), len(data) & 0xffffffff)
    return bytes(result)


class BackportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'backports'
        self.root.mkdir()
        self.manifest = {'schema': 1, 'packages': []}
        for ident, version, license_name in [('braces', '3.0.3', 'MIT'), ('node-forge', '1.4.0', '(BSD-3-Clause OR GPL-2.0)')]:
            original = {'name': ident, 'version': version, 'main': 'index.js', 'license': license_name,
                        'scripts': {'test': 'unused'}, 'devDependencies': {'example': '1'}, 'engines': {'node': '>= 6'}}
            fork = dict(original, name='@appguard/' + ident, version=version + '-appguard.1', private=True,
                        engines={'node': '>=22.13.0'})
            del fork['scripts'], fork['devDependencies']
            encode = lambda value: (json.dumps(value, sort_keys=True) + '\n').encode()
            upstream_files = {'package/package.json': encode(original), 'package/index.js': b'original\n', 'package/LICENSE': b'full license\n', 'package/retained.txt': b'retained\n'}
            if ident == 'node-forge':
                upstream_files['package/dist/example.js'] = b'old distribution\n'
                upstream_files['package/dist/example.js.map'] = b'old map\n'
                upstream_files['package/flash/example.swf'] = b'original asset\n'
            upstream = gzip.compress(reference_tar(upstream_files), mtime=0)
            def put(path, data):
                target = self.root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                return info(data)
            up_path = ident + '/upstream.tgz'
            put(up_path, upstream)
            provenance = {'upstream': {'name': ident, 'version': version}, 'license': license_name,
                          'compilation_reproduction_verified': False, 'producer_closure_verified': False,
                          'metadata_changes': {key: {'before': original.get(key), 'after': fork.get(key)}
                                               for key in set(original) | set(fork) if original.get(key) != fork.get(key)}}
            inputs = {}
            values = {'original-package.json': encode(original), 'LICENSE': b'full license\n',
                      'provenance.json': encode(provenance), 'source.patch': b'ordinary patch record\n',
                      'replacements/package.json': encode(fork), 'replacements/source/index.js': b'changed\n'}
            replacements = [{'path': 'package/package.json', 'input': ident + '/replacements/package.json'},
                            {'path': 'package/index.js', 'input': ident + '/replacements/source/index.js'}]
            if ident == 'node-forge':
                for suffix in ['example.js', 'example.js.map']:
                    path = 'replacements/distribution/' + suffix
                    values[path] = b'new ' + suffix.encode() + b'\n'
                    replacements.append({'path': 'package/dist/' + suffix, 'input': ident + '/' + path})
            for path, data in values.items():
                inputs[ident + '/' + path] = put(ident + '/' + path, data)
            result = dict(upstream_files)
            for replacement in replacements:
                result[replacement['path']] = (self.root / replacement['input']).read_bytes()
            archive = reference_gzip(reference_tar(result))
            archive_path = 'archives/appguard-' + ident + '-' + version + '-appguard.1.tgz'
            put(archive_path, archive)
            self.manifest['packages'].append({'id': ident,
                'upstream': {'name': ident, 'version': version, 'url': 'https://registry.npmjs.org/' + ident + '/-/' + ident + '-' + version + '.tgz', 'path': up_path, 'integrity': sri(upstream), **info(upstream)},
                'fork': {'name': fork['name'], 'version': fork['version']}, 'inputs': inputs,
                'replacements': replacements, 'result_files': {name: info(data) for name, data in result.items()},
                'archive': {'path': archive_path, 'integrity': sri(archive), **info(archive)}, 'provenance': ident + '/provenance.json'})
        self.save()
        self.original_manifest = copy.deepcopy(self.manifest)

    def save(self):
        (self.root / 'manifest.json').write_text(json.dumps(self.manifest))

    def test_exact_assembly_and_repeat(self):
        manifest = b.load_manifest(self.root)
        for record in manifest['packages']:
            first = b.assemble_package(self.root, record)
            self.assertEqual(first, b.assemble_package(self.root, record))
            self.assertEqual(first, (self.root / record['archive']['path']).read_bytes())
            self.assertEqual(first[:10], bytes.fromhex('1f8b08000000000000ff'))
            with tarfile.open(fileobj=io.BytesIO(gzip.decompress(first))) as archive:
                self.assertEqual(archive.getnames(), sorted(record['result_files']))
                for entry in archive:
                    self.assertEqual((entry.mode, entry.uid, entry.gid, entry.mtime, entry.uname, entry.gname), (0o644, 0, 0, 0, '', ''))
        self.assertTrue(b.check_archives(self.root, manifest)['verified'])

    def test_input_edits_and_missing_retained_file(self):
        record = self.manifest['packages'][0]
        for path in list(record['inputs']) + [record['upstream']['path']]:
            target = self.root / path
            original = target.read_bytes()
            target.write_bytes(original + b'edit')
            with self.assertRaisesRegex(b.BackportError, '^backport verification failed$'):
                b.check_archives(self.root, self.manifest)
            target.write_bytes(original)
        del record['result_files']['package/retained.txt']
        with self.assertRaises(b.BackportError):
            b.assemble_package(self.root, record)

    def test_stale_distribution_or_map(self):
        record = self.manifest['packages'][1]
        for suffix in ['example.js', 'example.js.map']:
            target = self.root / ('node-forge/replacements/distribution/' + suffix)
            original = target.read_bytes()
            target.write_bytes(b'stale distribution')
            with self.assertRaises(b.BackportError):
                b.assemble_package(self.root, record)
            target.write_bytes(original)

    def test_schema_inventory_identity_and_sri_mutations(self):
        mutations = [lambda m: m.update(extra=1), lambda m: m.update(schema=True),
            lambda m: m['packages'].reverse(), lambda m: m['packages'][0]['inputs'].update(extra={'sha256': '0'*64, 'size': 1}),
            lambda m: m['packages'][0]['upstream'].update(integrity='sha512-invalid'),
            lambda m: m['packages'][0]['upstream'].update(size=True),
            lambda m: m['packages'][0]['fork'].update(name='different'),
            lambda m: m['packages'][0]['fork'].update(version='different'),
            lambda m: m['packages'][0]['result_files']['package/index.js'].update(sha256='0'*64),
            lambda m: m['packages'][0]['archive'].update(sha256='0'*64)]
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                self.manifest = copy.deepcopy(self.original_manifest)
                mutation(self.manifest)
                self.save()
                with self.assertRaises(b.BackportError):
                    b.check_archives(self.root, b.load_manifest(self.root))

    def test_metadata_policy_and_provenance(self):
        record = self.manifest['packages'][1]
        path = record['provenance']
        data = json.loads((self.root / path).read_text())
        data['compilation_reproduction_verified'] = True
        content = json.dumps(data).encode()
        (self.root / path).write_bytes(content)
        record['inputs'][path] = info(content)
        with self.assertRaises(b.BackportError):
            b.assemble_package(self.root, record)

    def test_new_private_output_only_and_drift(self):
        out = Path(self.temp.name) / 'output'
        summary = b.write_archives(self.root, self.manifest, out)
        self.assertTrue(summary['verified'])
        self.assertEqual(out.stat().st_mode & 0o777, 0o700)
        self.assertEqual(len(list(out.iterdir())), 2)
        with self.assertRaises(b.BackportError):
            b.write_archives(self.root, self.manifest, out)
        target = self.root / self.manifest['packages'][0]['archive']['path']
        target.write_bytes(target.read_bytes() + b'drift')
        with self.assertRaises(b.BackportError):
            b.check_archives(self.root, self.manifest)

    def test_valid_but_wrong_upstream_sri(self):
        self.manifest['packages'][0]['upstream']['integrity'] = 'sha512-' + base64.b64encode(bytes(64)).decode()
        with self.assertRaises(b.BackportError):
            b.check_archives(self.root, self.manifest)

    def test_missing_input_and_metadata_drift_with_updated_hash(self):
        record = self.manifest['packages'][0]
        target = self.root / 'braces/LICENSE'
        target.unlink()
        with self.assertRaises(b.BackportError):
            b.assemble_package(self.root, record)
        target.write_bytes(b'full license\n')
        path = 'braces/replacements/package.json'
        target = self.root / path
        original = target.read_bytes()
        for field, value in [('private', 1), ('main', 'different.js'), ('scripts', {'test': 'unused'}),
                             ('devDependencies', {'example': '1'}), ('engines', {'node': '>=6'})]:
            modified = json.loads(original)
            modified[field] = value
            data = json.dumps(modified).encode()
            target.write_bytes(data)
            record['inputs'][path] = info(data)
            record['result_files']['package/package.json'] = info(data)
            with self.subTest(field=field):
                with self.assertRaises(b.BackportError):
                    b.assemble_package(self.root, record)

    def test_provenance_metadata_changes_are_required(self):
        record = self.manifest['packages'][0]
        path = record['provenance']
        value = json.loads((self.root / path).read_text())
        value['metadata_changes'].pop('scripts')
        data = json.dumps(value).encode()
        (self.root / path).write_bytes(data)
        record['inputs'][path] = info(data)
        with self.assertRaises(b.BackportError):
            b.assemble_package(self.root, record)

    def test_stored_gzip_multiple_blocks(self):
        data = b'ordinary file content\n' * 10000
        result = b.stored_gzip(data)
        self.assertEqual(result, reference_gzip(data))
        self.assertEqual(gzip.decompress(result), data)
        self.assertEqual(gzip.decompress(b.stored_gzip(b'')), b'')
        offset = 10
        blocks = 0
        while True:
            final = result[offset]
            size, inverse = struct.unpack('<HH', result[offset + 1:offset + 5])
            self.assertEqual(size ^ inverse, 0xffff)
            self.assertLessEqual(size, 65535)
            offset += 5 + size
            blocks += 1
            if final:
                break
        self.assertGreater(blocks, 1)
        self.assertEqual(offset + 8, len(result))

    def test_retained_real_inputs_and_candidate_allowlist(self):
        root = SCRIPT.parents[2] / 'tools/dependency-backports'
        manifest = b.load_manifest(root)
        candidate_spec = importlib.util.spec_from_file_location('candidate', SCRIPT.parents[1] / 'release/candidate.py')
        candidate = importlib.util.module_from_spec(candidate_spec)
        candidate_spec.loader.exec_module(candidate)
        for path in root.rglob('*'):
            if path.is_file():
                self.assertTrue(candidate.allowed(path.relative_to(SCRIPT.parents[2]).as_posix()))
        self.assertTrue(b.check_archives(root, manifest)['verified'])
        for record in manifest['packages']:
            original = b.upstream_files((root / record['upstream']['path']).read_bytes())
            result = b.upstream_files((root / record['archive']['path']).read_bytes())
            replacements = {entry['path']: entry['input'] for entry in record['replacements']}
            self.assertEqual(set(result), set(original) | set(replacements))
            for name, content in original.items():
                if name not in replacements:
                    self.assertEqual(content, result[name])
            for name, physical in replacements.items():
                self.assertEqual(result[name], (root / physical).read_bytes())
            self.assertEqual(result['package/LICENSE'], original['package/LICENSE'])
            if record['id'] == 'node-forge':
                distributions = [entry for entry in record['replacements'] if entry['path'].startswith('package/dist/')]
                self.assertEqual(len(distributions), 9)
                for entry in distributions:
                    self.assertIn('/replacements/distribution/', entry['input'])
                flash = [name for name in original if name.endswith('.swf')]
                self.assertTrue(flash)
                for name in flash:
                    self.assertEqual(original[name], result[name])

if __name__ == '__main__':
    unittest.main()
