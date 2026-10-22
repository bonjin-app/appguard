"""Original notice bytes are evidence, not an automatic legal approval."""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SCRIPT = ROOT / 'license_materials.py'


class LicenseMaterialsTests(unittest.TestCase):
    def module(self):
        self.assertTrue(SCRIPT.is_file(), 'License materials collector missing')
        spec = importlib.util.spec_from_file_location('license_materials', SCRIPT)
        result = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(result)
        return result

    def fixture(self, base, entries=None):
        root = base / 'runtime'
        jar = root / 'org/example/library/1.0/library-1.0.jar'
        jar.parent.mkdir(parents=True)
        with zipfile.ZipFile(jar, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value in (entries if entries is not None else [
                    ('META-INF/LICENSE.txt', b'Original license\r\n'),
                    ('META-INF/NOTICE', b'Original copyright notice\n'), ('example.class', b'compiled')]):
                archive.writestr(name, value)
        metadata = jar.parent / '_remote.repositories'
        metadata.write_bytes(b'repository metadata')
        hashes = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
        manifest = base / 'manifest.json'
        manifest.write_text(json.dumps({'returncode': 0, 'sha256': hashes,
            'jar_sha256': {str(jar.relative_to(root)): hashes[str(jar.relative_to(root))]}}))
        return root, manifest, base / 'materials', jar

    def test_original_bytes_are_deduplicated_and_never_approved(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest, output, jar = self.fixture(Path(temporary).resolve())
            report = module.collect_materials(root, manifest, output)
            self.assertEqual(report['jar_count'], 1)
            self.assertEqual(report['missing_material_count'], 0)
            self.assertFalse(report['review_completed'])
            self.assertFalse(report['third_party_notices_complete'])
            self.assertFalse(report['release_ready'])
            self.assertEqual(report['records'][0]['jar_sha256'], hashlib.sha256(jar.read_bytes()).hexdigest())
            self.assertEqual(set(p.name for p in output.iterdir()), {'license-materials.json', 'THIRD_PARTY_NOTICES.review.md', 'materials.zip'})
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            with zipfile.ZipFile(output / 'materials.zip') as archive:
                raw = [archive.read(name) for name in archive.namelist()]
                self.assertIn(b'Original license\r\n', raw)
                self.assertIn(b'Original copyright notice\n', raw)
                self.assertTrue(all(name.startswith('materials/') and '..' not in name for name in archive.namelist()))

    def test_missing_materials_remain_visible_and_pending(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            args = self.fixture(Path(temporary).resolve(), [('example.class', b'compiled')])
            report = module.collect_materials(*args[:3])
            self.assertEqual(report['missing_material_count'], 1)
            self.assertEqual(report['records'][0]['review_status'], 'missing_original_materials')
            self.assertFalse(report['review_completed'])

    def test_changed_missing_or_unrecorded_runtime_file_rejected(self):
        module = self.module()
        for kind in ('changed', 'missing', 'extra', 'metadata'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root, manifest, output, jar = self.fixture(Path(temporary).resolve())
                if kind == 'changed': jar.write_bytes(b'changed')
                elif kind == 'missing': jar.unlink()
                elif kind == 'extra': (root / 'unrecorded').write_bytes(b'new')
                else: (jar.parent / '_remote.repositories').write_bytes(b'changed')
                with self.assertRaises(ValueError): module.collect_materials(root, manifest, output)
                self.assertFalse(output.exists())

    def test_duplicate_traversal_symlink_and_oversize_zip_entries_rejected(self):
        module = self.module()
        cases = [[('../LICENSE', b'unsafe')], [('/LICENSE', b'unsafe')],
                 [('META-INF/LICENSE', b'a'), ('META-INF/LICENSE', b'b')],
                 [('META-INF/LICENSE', b'x' * (module.MAX_MATERIAL_BYTES + 1))]]
        for entries in cases:
            with self.subTest(entries=[name for name, _ in entries]), tempfile.TemporaryDirectory() as temporary:
                root, manifest, output, _ = self.fixture(Path(temporary).resolve(), entries)
                with self.assertRaises(ValueError): module.collect_materials(root, manifest, output)
                self.assertFalse(output.exists())

    def test_zip_symlink_entry_never_becomes_license_material(self):
        module = self.module()
        entry = zipfile.ZipInfo('META-INF/LICENSE')
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        with tempfile.TemporaryDirectory() as temporary:
            args = self.fixture(Path(temporary).resolve(), [(entry, b'/private/secret')])
            with self.assertRaises(ValueError): module.collect_materials(*args[:3])

    def test_existing_and_symlink_outputs_preserved(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest, output, _ = self.fixture(Path(temporary).resolve())
            output.mkdir(); marker = output / 'existing'; marker.write_bytes(b'preserve')
            with self.assertRaises(ValueError): module.collect_materials(root, manifest, output)
            self.assertEqual(marker.read_bytes(), b'preserve')
            link = output.parent / 'link'; link.symlink_to(output, target_is_directory=True)
            with self.assertRaises(ValueError): module.collect_materials(root, manifest, link)
            self.assertEqual(marker.read_bytes(), b'preserve')

    def test_output_created_during_collection_is_never_overwritten(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest, output, _ = self.fixture(Path(temporary).resolve())
            publish = module._publish
            def race(target, staged):
                target.mkdir()
                (target / 'existing').write_bytes(b'preserve')
                return publish(target, staged)
            with patch.object(module, '_publish', side_effect=race):
                with self.assertRaises(ValueError): module.collect_materials(root, manifest, output)
            self.assertEqual((output / 'existing').read_bytes(), b'preserve')

    def test_fifo_replacement_during_open_does_not_block(self):
        self.module()
        code = '''
import os, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import license_materials as m
path=Path(sys.argv[2]);path.write_bytes(b'original')
original=os.open
def replace(value, flags, *args, **kwargs):
    if Path(value)==path:
        path.unlink();os.mkfifo(path)
    return original(value, flags, *args, **kwargs)
with patch.object(m.os,'open',side_effect=replace):
    try:m._pin(path,1024)
    except ValueError:sys.exit(0)
sys.exit(1)
'''
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([sys.executable, '-c', code, str(ROOT), str(Path(temporary) / 'input')],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_manifest_boolean_and_duplicate_keys_are_rejected(self):
        module = self.module()
        for raw in ('{"returncode":false,"sha256":{},"jar_sha256":{}}', '{"returncode":1,"returncode":0}'):
            with tempfile.TemporaryDirectory() as temporary:
                root, manifest, output, _ = self.fixture(Path(temporary).resolve())
                manifest.write_text(raw)
                with self.assertRaises(ValueError): module.collect_materials(root, manifest, output)

    def test_changed_inputs_during_collection_are_rejected_before_publication(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest, output, jar = self.fixture(Path(temporary).resolve())
            original = module._materials
            def mutate(path):
                result = original(path)
                jar.write_bytes(b'changed after inspection')
                return result
            with patch.object(module, '_materials', side_effect=mutate):
                with self.assertRaises(ValueError): module.collect_materials(root, manifest, output)
            self.assertFalse(output.exists())

    def test_oversized_central_directory_rejected_before_zip_parsing(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'input.jar'
            # An invalid large directory claim must not allocate ZipInfo objects.
            path.write_bytes(struct.pack('<4s4H2LH', b'PK\x05\x06', 0, 0, 1, 1, module.MAX_DIRECTORY_BYTES + 1, 0, 0))
            with patch.object(module.zipfile, 'ZipFile') as parser:
                with self.assertRaises(ValueError): module._materials(path)
                parser.assert_not_called()

    def test_cli_errors_do_not_echo_private_paths(self):
        self.module()
        marker = 'PRIVATE_INPUT_MARKER'
        run = subprocess.run([sys.executable, str(SCRIPT), '--artifacts', marker,
            '--manifest', marker, '--output', marker], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(run.returncode, 0)
        self.assertNotIn(marker, run.stdout + run.stderr)
        self.assertNotIn('Traceback', run.stderr)


if __name__ == '__main__':
    unittest.main()
