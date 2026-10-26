"""Data-only Forge recipe/preparation regressions; never invoke npm or a compiler."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BACKPORTS = ROOT / 'tools/dependency-backports'
spec = importlib.util.spec_from_file_location('forge_packaging', ROOT / 'scripts/dependencies/build-backports.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class ForgeProducerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()

    def fixture(self):
        root = self.base / 'copy/tools/dependency-backports'
        shutil.copytree(BACKPORTS, root)
        scripts = root.parents[1] / 'scripts/dependencies'
        scripts.mkdir(parents=True)
        for name in ('build-resolver.cjs', 'build-forge.py'):
            shutil.copyfile(ROOT / 'scripts/dependencies' / name, scripts / name)
        return root, b.load_manifest(root)['packages'][1]

    def require_api(self):
        for name in ('forge_recipe', 'prepare_forge', 'verify_forge_prepared', 'verify_forge_tools',
                     'check_forge_outputs', 'compare_forge_tree'):
            self.assertTrue(callable(getattr(b, name, None)), 'missing public producer API: ' + name)

    def test_complete_recipe_source_lock_and_output_joins(self):
        self.require_api()
        record = b.load_manifest(BACKPORTS)['packages'][1]
        recipe, source = b.forge_recipe(BACKPORTS, record)
        self.assertEqual(len(source), 52)
        self.assertEqual(len([name for name in source if name.startswith('lib/')]), 49)
        self.assertEqual(json.loads(source['package.json'])['name'], 'node-forge')
        self.assertEqual(source['lib/rsa.js'], (BACKPORTS / 'node-forge/replacements/source/lib/rsa.js').read_bytes())
        lock = json.loads((BACKPORTS / 'node-forge/producer/package-lock.json').read_bytes())
        self.assertEqual(len(lock['packages']), 86)
        self.assertEqual(lock['packages']['']['devDependencies'], {'webpack': '5.112.1', 'mocha': '12.0.3'})
        self.assertFalse(any(name.rsplit('node_modules/', 1)[-1] in
            {'braces', 'micromatch', 'node-forge', 'resolve-workspace-root'} for name in lock['packages']))
        self.assertEqual(len(recipe['outputs']), 9)
        self.assertEqual([len(row['entries']) for row in recipe['maps']], [46, 52, 5])
        self.assertTrue(recipe['observation']['recipe_retained'])
        for flag in ('fresh_install_verified', 'compilation_reproduction_verified', 'producer_closure_verified',
                     'publisher_build_reproduced', 'source_gate_passed', 'release_ready'):
            self.assertIs(recipe['observation'][flag], False)

    def test_each_retained_producer_input_is_bound(self):
        self.require_api()
        root, record = self.fixture()
        names = [name for name in record['inputs'] if name.startswith('node-forge/producer/')]
        self.assertGreaterEqual(len(names), 8)
        for name in names:
            target = root / name
            original = target.read_bytes()
            target.write_bytes(original + b'\n')
            with self.subTest(name=name), self.assertRaises(b.BackportError):
                b.assemble_package(root, record)
            target.write_bytes(original)

    def test_unbound_added_or_omitted_producer_input_fails(self):
        self.require_api()
        root, record = self.fixture()
        for mode in ('added', 'omitted', 'changed-recipe-expectation', 'lock', 'script'):
            changed = copy.deepcopy(record)
            if mode == 'added':
                changed['inputs']['node-forge/producer/extra.json'] = b.digest(b'{}')
            elif mode == 'omitted':
                del changed['inputs']['node-forge/producer/tool-tree.json']
            elif mode == 'script':
                script = root.parents[1] / 'scripts/dependencies/build-forge.py'
                script.write_bytes(script.read_bytes() + b'\n')
            else:
                name = 'node-forge/producer/' + ('recipe.json' if mode == 'changed-recipe-expectation' else 'package-lock.json')
                original = (root / name).read_bytes()
                value = json.loads(original)
                if mode == 'lock':
                    value['packages']['node_modules/webpack']['integrity'] = value['packages']['node_modules/mocha']['integrity']
                else:
                    value['outputs']['forge.js']['sha256'] = '0' * 64
                data = (json.dumps(value) + '\n').encode()
                (root / name).write_bytes(data)
                changed['inputs'][name] = b.digest(data)
            with self.subTest(mode=mode), self.assertRaises(b.BackportError):
                b.assemble_package(root, changed)
            if mode in ('lock', 'changed-recipe-expectation'):
                (root / name).write_bytes(original)

    def test_preparation_is_new_exact_source_and_two_file_producer(self):
        self.require_api()
        record = b.load_manifest(BACKPORTS)['packages'][1]
        output = self.base / 'prepared'
        recipe, expected = b.forge_recipe(BACKPORTS, record)
        result = b.prepare_forge(BACKPORTS, record, output)
        self.assertEqual(result['source_files'], 52)
        self.assertIs(result['compilation_reproduction_verified'], False)
        self.assertEqual(b.verify_forge_prepared(BACKPORTS, record, output), expected)
        self.assertEqual({p.relative_to(output / 'source').as_posix(): p.read_bytes()
            for p in (output / 'source').rglob('*') if p.is_file()}, expected)
        self.assertEqual({p.name for p in (output / 'producer').iterdir()}, {'package.json', 'package-lock.json'})
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in output.rglob('*') if p.is_file()))
        with self.assertRaises(b.BackportError):
            b.prepare_forge(BACKPORTS, record, output)

    def test_prepared_source_config_metadata_and_lock_drift_fails(self):
        self.require_api()
        record = b.load_manifest(BACKPORTS)['packages'][1]
        prepared = self.base / 'prepared'
        b.prepare_forge(BACKPORTS, record, prepared)
        for name in ('source/lib/rsa.js', 'source/lib/aes.js', 'source/webpack.config.js',
                     'source/package.json', 'producer/package-lock.json'):
            target = prepared / name
            original = target.read_bytes()
            target.write_bytes(original + b'\n')
            with self.subTest(name=name), self.assertRaises(b.BackportError):
                b.verify_forge_prepared(BACKPORTS, record, prepared)
            target.write_bytes(original)
        with self.assertRaises(b.BackportError):
            b.verify_forge_tools(BACKPORTS, record, prepared)  # no installed closure

    def test_all_nine_retained_outputs_match_and_each_drift_fails(self):
        self.require_api()
        record = b.load_manifest(BACKPORTS)['packages'][1]
        outputs = self.base / 'outputs'
        shutil.copytree(BACKPORTS / 'node-forge/replacements/distribution', outputs)
        self.assertEqual(b.check_forge_outputs(BACKPORTS, record, outputs)['outputs'], 9)
        expected_before = {p.name: p.read_bytes() for p in (BACKPORTS / 'node-forge/replacements/distribution').iterdir()}
        for target in outputs.iterdir():
            original = target.read_bytes()
            target.write_bytes(original + b'\n')
            with self.subTest(name=target.name), self.assertRaises(b.BackportError):
                b.check_forge_outputs(BACKPORTS, record, outputs)
            target.write_bytes(original)
        (outputs / 'extra.js').write_bytes(b'ordinary additional output\n')
        with self.assertRaises(b.BackportError):
            b.check_forge_outputs(BACKPORTS, record, outputs)
        self.assertEqual(expected_before, {p.name: p.read_bytes() for p in
            (BACKPORTS / 'node-forge/replacements/distribution').iterdir()})

    def test_tree_comparison_hashes_all_regular_files(self):
        self.require_api()
        root = self.base / 'ordinary-tree'
        root.mkdir()
        data = b'ordinary retained bytes\n'
        (root / 'package.json').write_bytes(data)
        expected = {'package.json': b.digest(data)['sha256']}
        b.compare_forge_tree(root, expected, {})
        (root / 'package.json').write_bytes(data + b'\n')
        with self.assertRaises(b.BackportError):
            b.compare_forge_tree(root, expected, {})
        (root / 'package.json').write_bytes(data)
        (root / 'extra.txt').write_bytes(data)
        with self.assertRaises(b.BackportError):
            b.compare_forge_tree(root, expected, {})

    def test_supported_cli_prepares_and_verifies_without_compiler(self):
        output = self.base / 'cli-prepared'
        command = [sys.executable, '-I', '-S', '-B', str(ROOT / 'scripts/dependencies/build-forge.py')]
        for option in ('--prepare', '--verify-prepared'):
            result = subprocess.run(command + [option, str(output)], cwd=ROOT,
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIs(json.loads(result.stdout)['compiler_executed'], False)
        result = subprocess.run(command + ['--verify-tools', str(output)], cwd=ROOT,
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertIs(json.loads(result.stdout)['verified'], False)
        self.assertFalse((output / 'producer/node_modules').exists())


if __name__ == '__main__':
    unittest.main()
