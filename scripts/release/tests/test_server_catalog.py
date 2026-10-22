"""Recorded server dependencies cannot disappear behind a successful source scan."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
RELEASE = ROOT / 'scripts/release'


def module():
    spec = importlib.util.spec_from_file_location('source_catalog_server_tests', RELEASE / 'source_catalog.py')
    result = importlib.util.module_from_spec(spec)
    with patch.object(sys, 'path', [str(RELEASE), *sys.path]):
        spec.loader.exec_module(result)
    return result


def component(kind, name, version, path):
    group, _, short = name.rpartition('/') if kind == 'composer' else ('', '', name)
    result = {'type': 'library', 'name': short, 'version': version, 'purl': f'pkg:{kind}/{name}@{version}',
              'properties': [{'name': 'syft:location:0:path', 'value': '/' + path}]}
    if group:
        result['group'] = group
    return result


class ServerCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.source = self.base / 'source'
        self.source.mkdir()
        self.sbom = self.base / 'sbom.cdx.json'
        self.components = []

    def write(self, path, data):
        target = self.source / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data if isinstance(data, str) else json.dumps(data))

    def uv(self, path='sdk/python/uv.lock'):
        self.write(path, 'version = 1\nrevision = 5\nrequires-python = ">=3.11"\n'
                   '[[package]]\nname = "cryptography"\nversion = "50.0.2"\n'
                   'source = { registry = "https://pypi.org/simple" }\n')
        return component('pypi', 'cryptography', '50.0.2', path)

    def nuget(self, path='sdk/dotnet/packages.lock.json'):
        self.write(path, {'version': 1, 'dependencies': {'net10.0': {
            'StackExchange.Redis': {'type': 'Direct', 'requested': '[3.4.5, 3.4.5]',
                                    'resolved': '3.4.5', 'contentHash': 'YQ=='}}}})
        return component('nuget', 'StackExchange.Redis', '3.4.5', path)

    def go(self, path='sdk/go/go.mod'):
        self.write(path, 'module example.com/project\n\ngo 1.26.0\n\n'
                   'require (\n github.com/redis/go-redis/v9 v9.23.0 // indirect\n)\n')
        self.write(str(Path(path).with_name('go.sum')),
                   'github.com/redis/go-redis/v9 v9.23.0 h1:/TTVdJa8BRNsybwwGGnmiYktHNlUXtbOQxlWpHBPL3s=\n'
                   'github.com/redis/go-redis/v9 v9.23.0/go.mod h1:EWP2UUk+XDaI1s5nQB5mablZN6vccXlmBQTyfnF87D0=\n'
                   'github.com/unused/history v1.0.0 h1:/TTVdJa8BRNsybwwGGnmiYktHNlUXtbOQxlWpHBPL3s=\n')
        return component('golang', 'github.com/redis/go-redis/v9', 'v9.23.0', path)

    def composer(self, path='sdk/php/composer.lock'):
        self.write(path, {'content-hash': 'a' * 32, 'packages': [
            {'name': 'psr/log', 'version': '3.0.2', 'type': 'library'}], 'packages-dev': [
            {'name': 'phpunit/phpunit', 'version': '12.5.0', 'type': 'library'}],
            'platform': {'php': '>=8.2'}, 'platform-dev': {}})
        return [component('composer', 'psr/log', '3.0.2', path),
                component('composer', 'phpunit/phpunit', '12.5.0', path)]

    def run_catalog(self):
        self.sbom.write_text(json.dumps({'bomFormat': 'CycloneDX', 'components': self.components}))
        return module().validate_source_catalog(self.source, self.sbom, self.base)

    def report(self):
        return json.loads((self.base / 'source-lock-coverage.json').read_text())

    def test_each_server_ecosystem_missing_from_sbom_fails_closed(self):
        for setup in ('uv', 'nuget', 'go', 'composer'):
            with self.subTest(ecosystem=setup):
                shutil.rmtree(self.source)
                self.source.mkdir()
                getattr(self, setup)()
                with self.assertRaises(ValueError):
                    self.run_catalog()
                self.assertFalse(self.report()['all_recorded_packages_cataloged'])

    def test_exact_versions_purls_names_and_locations_are_required(self):
        for setup in ('uv', 'nuget', 'go', 'composer'):
            for mutation in ('version', 'purl', 'name', 'path'):
                with self.subTest(ecosystem=setup, mutation=mutation):
                    shutil.rmtree(self.source)
                    self.source.mkdir()
                    values = getattr(self, setup)()
                    self.components = values if isinstance(values, list) else [values]
                    record = self.components[0]
                    if mutation == 'path':
                        record['properties'][0]['value'] = '/another-project/' + Path(record['properties'][0]['value']).name
                    elif mutation == 'purl':
                        record['purl'] = record['purl'].replace('@', '-forged@')
                    else:
                        record[mutation] += '-wrong'
                    with self.assertRaises(ValueError):
                        self.run_catalog()
                    self.assertFalse(self.report()['all_recorded_packages_cataloged'])

    def test_non_package_excluded_or_malformed_purl_components_cannot_clear_server_coverage(self):
        for change in ({'type': 'file'}, {'type': 'application'}, {'type': None}, {'scope': 'excluded'},
                       {'scope': 'invented'}, {'purl': 'pkg:pypi/cryptography@50.0.2?bad'},
                       {'purl': 'pkg:pypi/cryptography@50.0.2?package-id=123'},
                       {'purl': 'pkg:pypi/cryptography@50.0.2#other'},
                       {'purl': 'pkg:pypi/cryptography@50.0.2?x=1&x=2'}):
            with self.subTest(change=change):
                value = self.uv()
                value.update(change)
                self.components = [value]
                with self.assertRaises(ValueError):
                    self.run_catalog()
                self.assertFalse(self.report()['all_recorded_packages_cataloged'])

    def test_current_recorded_graph_keeps_classifications_and_input_hashes(self):
        self.components = [self.uv(), self.nuget(), self.go(), *self.composer()]
        report = self.run_catalog()
        self.assertTrue(report['all_recorded_packages_cataloged'])
        self.assertTrue(report['all_recorded_npm_packages_cataloged'])
        locks = {v['ecosystem']: v for v in report['server_locks']}
        self.assertEqual(set(locks), {'pypi', 'nuget', 'golang', 'composer'})
        self.assertEqual(locks['nuget']['records'][0]['dependency_type'], 'Direct')
        self.assertEqual(locks['nuget']['records'][0]['target_framework'], 'net10.0')
        self.assertTrue(locks['golang']['records'][0]['indirect'])
        self.assertEqual(locks['golang']['checksum_ledger_entries'], 3)
        self.assertEqual(len(locks['golang']['records']), 1)
        self.assertEqual([r['development'] for r in locks['composer']['records']], [False, True])
        for lock in locks.values():
            self.assertEqual(lock['sha256'], hashlib.sha256((self.source / lock['path']).read_bytes()).hexdigest())
            for path, digest in lock['input_sha256'].items():
                self.assertEqual(digest, hashlib.sha256((self.source / path).read_bytes()).hexdigest())
        self.assertEqual(report['sbom_sha256'], hashlib.sha256(self.sbom.read_bytes()).hexdigest())

    def test_identical_names_from_other_lock_or_ecosystem_do_not_fill_missing_entries(self):
        one = self.uv('one/uv.lock')
        self.uv('two/uv.lock')
        self.components = [one, component('nuget', 'cryptography', '50.0.2', 'two/uv.lock')]
        with self.assertRaises(ValueError):
            self.run_catalog()
        locks = self.report()['server_locks']
        self.assertTrue(locks[0]['records'][0]['cataloged'])
        self.assertFalse(locks[1]['records'][0]['cataloged'])

    def test_malformed_and_unsupported_formats_never_claim_coverage(self):
        cases = [('uv.lock', 'version=2\npackage=[]'), ('uv.lock', 'version=1\nrevision=999\npackage=[]'),
                 ('uv.lock', 'version=1\nrevision=5\n'), ('uv.lock', 'not TOML @'),
                 ('uv.lock', 'version=1\nrevision=5\n[[package]]\nname="external"\nversion="1"\nsource={git="https://example.com"}'),
                 ('packages.lock.json', {'version': 2, 'dependencies': {}}),
                 ('packages.lock.json', {'version': 1, 'dependencies': {'net10.0': {'x': {'type': 'Unknown'}}}}),
                 ('packages.lock.json', {'version': 1, 'dependencies': {'net10.0': {'x': {'type': 'Direct'}}}}),
                 ('composer.lock', {'packages': [], 'packages-dev': {}}),
                 ('composer.lock', {'packages': [{'name': 'vendor/pkg'}], 'packages-dev': []}),
                 ('composer.lock', 'not json'),
                 ('go.mod', 'module example.com/p\nreplace example.com/x => ../x\n'),
                 ('go.mod', 'module example.com/p\nexclude example.com/x v1.0.0\n'),
                 ('go.mod', 'module example.com/p\nretract v1.0.0\n'),
                 ('go.mod', 'module example.com/p\nrequire x not-version\n'),
                 ('go.mod', 'module example.com/p\nrequire (\n x v1.0.0\n')]
        for path, data in cases:
            with self.subTest(path=path, data=data):
                shutil.rmtree(self.source)
                self.source.mkdir()
                self.write(path, data)
                with self.assertRaises(ValueError):
                    self.run_catalog()
                report = self.report()
                self.assertFalse(report['all_recorded_packages_cataloged'])
                self.assertTrue(report['validation_errors'])

    def test_go_requires_matching_archive_and_go_mod_checksums_not_historical_versions(self):
        self.components = [self.go()]
        checksum = self.source / 'sdk/go/go.sum'
        good = checksum.read_text()
        for text in ('', good.replace('v9.23.0 ', 'v9.22.0 '), good.splitlines()[1] + '\n',
                     good.replace('h1:/TTVdJa8BRNsybwwGGnmiYktHNlUXtbOQxlWpHBPL3s=', 'h1:invalid')):
            with self.subTest(text=text):
                checksum.write_text(text)
                with self.assertRaises(ValueError):
                    self.run_catalog()
        checksum.unlink()
        with self.assertRaises(ValueError):
            self.run_catalog()

    def test_python_local_project_exclusion_requires_matching_contained_project(self):
        self.write('sdk/python/uv.lock', 'version=1\nrevision=5\n[[package]]\nname="local-project"\n'
                   'version="1.0.0"\nsource={editable="."}\n')
        with self.assertRaises(ValueError):
            self.run_catalog()
        self.write('sdk/python/pyproject.toml', '[project]\nname="external"\nversion="1.0.0"\n')
        with self.assertRaises(ValueError):
            self.run_catalog()
        self.write('sdk/python/pyproject.toml', '[project]\nname="local-project"\nversion="1.0.0"\n')
        report = self.run_catalog()
        lock = report['server_locks'][0]
        self.assertEqual(len(lock['records']), 0)
        self.assertEqual(lock['skipped_local_projects'][0]['name'], 'local-project')
        self.assertIn('sdk/python/pyproject.toml', lock['input_sha256'])

    def test_nuget_project_exclusion_requires_actual_matching_project_reference(self):
        self.write('tools/packages.lock.json', {'version': 1, 'dependencies': {'net10.0': {
            'AppGuard.Experimental': {'type': 'Project', 'dependencies': {}}}}})
        with self.assertRaises(ValueError):
            self.run_catalog()
        self.write('tools/Tool.csproj', '<Project><ItemGroup><ProjectReference Include="../sdk/AppGuard.csproj" /></ItemGroup></Project>')
        self.write('sdk/AppGuard.csproj', '<Project><PropertyGroup><PackageId>Other</PackageId></PropertyGroup></Project>')
        with self.assertRaises(ValueError):
            self.run_catalog()
        self.write('sdk/AppGuard.csproj', '<Project><PropertyGroup><PackageId>AppGuard.Experimental</PackageId></PropertyGroup></Project>')
        report = self.run_catalog()
        self.assertEqual(report['server_locks'][0]['skipped_local_projects'][0]['name'], 'AppGuard.Experimental')
        self.assertIn('sdk/AppGuard.csproj', report['server_locks'][0]['input_sha256'])

    def test_duplicate_conflicting_records_and_json_keys_fail_closed(self):
        cases = [('uv.lock', 'version=1\nrevision=5\n' +
                  ('[[package]]\nname="x"\nversion="1"\nsource={registry="https://pypi.org/simple"}\n' * 2)),
                 ('packages.lock.json', '{"version":1,"dependencies":{},"dependencies":{}}'),
                 ('composer.lock', '{"packages":[],"packages":[],"packages-dev":[]}'),
                 ('go.mod', 'module example.com/p\nrequire x v1.0.0\nrequire x v1.0.1\n')]
        for path, data in cases:
            with self.subTest(path=path):
                shutil.rmtree(self.source)
                self.source.mkdir()
                self.write(path, data)
                with self.assertRaises(ValueError):
                    self.run_catalog()

    def test_malformed_sbom_never_emits_complete_coverage(self):
        for raw in ('{}', '[]', '{"components":null}', '{"components":[42]}',
                    '{"components":[],"components":[]}', '{"bomFormat":"other","components":[]}',
                    '{"components":[],"metadata":NaN}'):
            with self.subTest(raw=raw):
                self.sbom.write_text(raw)
                with self.assertRaises(ValueError):
                    module().validate_source_catalog(self.source, self.sbom, self.base)
                self.assertFalse(self.report()['all_recorded_packages_cataloged'])
                self.assertTrue(self.report()['validation_errors'])

    def test_inputs_cannot_be_symlinks_or_escape_the_source_snapshot(self):
        self.components = [self.go()]
        sums = self.source / 'sdk/go/go.sum'
        outside = self.base / 'outside.sum'
        sums.rename(outside)
        sums.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.run_catalog()
        shutil.rmtree(self.source)
        self.source.mkdir()
        self.write('uv.lock', 'version=1\nrevision=5\n[[package]]\nname="outside"\n'
                   'version="1"\nsource={editable=".."}\n')
        (self.base / 'pyproject.toml').write_text('[project]\nname="outside"\nversion="1"\n')
        with self.assertRaises(ValueError):
            self.run_catalog()

    def test_invalid_registry_url_is_an_explicit_input_error(self):
        self.write('uv.lock', 'version=1\nrevision=5\n[[package]]\nname="x"\n'
                   'version="1"\nsource={registry="https://[invalid"}\n')
        with self.assertRaises(ValueError):
            self.run_catalog()
        self.assertTrue(self.report()['validation_errors'])

    @unittest.skipUnless(os.environ.get('APPGUARD_SYFT'), 'explicit reviewed Syft binary required')
    def test_actual_syft_composer_dev_omission_blocks_coverage(self):
        self.composer()
        config = self.base / 'syft.json'
        module().write_syft_config(config)
        subprocess.run([os.environ['APPGUARD_SYFT'], 'scan', 'dir:' + str(self.source), '--config', str(config),
                        '-o', 'cyclonedx-json=' + str(self.sbom)], check=True, capture_output=True, timeout=60)
        # Pinned Syft catalogs Composer runtime entries but currently drops
        # packages-dev. A future added PHP dev graph must block, not be cleared.
        with self.assertRaises(ValueError):
            module().validate_source_catalog(self.source, self.sbom, self.base)
        records = self.report()['server_locks'][0]['records']
        self.assertEqual([(v['name'], v['cataloged']) for v in records],
                         [('psr/log', True), ('phpunit/phpunit', False)])

    @unittest.skipUnless(os.environ.get('APPGUARD_SYFT'), 'explicit reviewed Syft binary required')
    def test_pinned_actual_syft_catalogs_current_server_records(self):
        # Snapshot only tracked source inputs, never installed or ignored caches.
        names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
        inputs = {'uv.lock', 'pyproject.toml', 'packages.lock.json', 'go.mod', 'go.sum', 'composer.lock', 'composer.json'}
        for name in names:
            if name and (Path(name).name in inputs or name.endswith('.csproj')):
                self.write(name, (ROOT / name).read_text())
        config = self.base / 'syft.json'
        module().write_syft_config(config)
        raw = self.base / 'sbom-source.raw.cdx.json'
        subprocess.run([os.environ['APPGUARD_SYFT'], 'scan', 'dir:' + str(self.source), '--config', str(config),
                        '-o', 'cyclonedx-json=' + str(raw)], check=True, capture_output=True, timeout=90)
        with patch.object(sys, 'path', [str(ROOT / 'scripts/release'), *sys.path]):
            from python_build_catalog import prepare_python_build_catalog
        prepare_python_build_catalog(self.source, raw, self.base)
        result = module().validate_source_catalog(self.source, self.sbom, self.base)
        self.assertTrue(result['all_recorded_packages_cataloged'])
        self.assertEqual(len(result['python_build_constraints']), 12)
        self.assertEqual(len({r['purl'] for r in result['python_build_constraints']}), 6)
        self.assertEqual(sum(r['purl'] == 'pkg:pypi/editables@0.6' for r in result['python_build_constraints']), 2)
        self.assertEqual(len(result['server_locks']), 8)
        self.assertEqual(sum(len(v['records']) for v in result['server_locks']), 83)


if __name__ == '__main__':
    unittest.main()
