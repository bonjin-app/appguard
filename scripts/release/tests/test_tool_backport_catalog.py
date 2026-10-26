"""Ordinary retained inputs must reconstruct ancestry and local-lock joins."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/release'))


def fixture(base, local=False):
    source, reports = base / 'source', base / 'reports'
    source.mkdir(); reports.mkdir()
    shutil.copytree(ROOT / 'tools/dependency-backports', source / 'tools/dependency-backports')
    script = source / 'scripts/dependencies/build-resolver.cjs'
    script.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / 'scripts/dependencies/build-resolver.cjs', script)
    shutil.copyfile(ROOT / 'scripts/dependencies/build-forge.py', script.with_name('build-forge.py'))
    manifest = json.loads((source / 'tools/dependency-backports/manifest.json').read_text())
    lock = source / 'sdk/expo/package-lock.json'
    lock.parent.mkdir(parents=True)
    packages = {'': {}, 'node_modules/resolve-workspace-root': {
        'version': '2.0.1', 'resolved': 'https://registry.npmjs.org/resolve-workspace-root/-/resolve-workspace-root-2.0.1.tgz'}}
    if local:
        for record in manifest['packages']:
            packages['node_modules/' + record['id']] = {
                **record['fork'], 'resolved': 'file:../../tools/dependency-backports/' + record['archive']['path'],
                'integrity': record['archive']['integrity'], 'dev': True}
    lock.write_text(json.dumps({'lockfileVersion': 3, 'packages': packages}))
    raw = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'components': [
        {'type': 'library', 'name': 'resolve-workspace-root', 'version': '2.0.1',
         'purl': 'pkg:npm/resolve-workspace-root@2.0.1',
         'properties': [{'name': 'syft:location:0:path', 'value': '/sdk/expo/package-lock.json'}]}]}
    # The complete retained compiler lock remains ordinary recorded npm input.
    # Include its 85 dependencies in the raw fixture SBOM instead of suppressing it.
    producer_lock = 'tools/dependency-backports/node-forge/producer/package-lock.json'
    producer = json.loads((source / producer_lock).read_bytes())
    for location, row in producer['packages'].items():
        if not location:
            continue
        name = location.rsplit('node_modules/', 1)[-1]
        raw['components'].append({'type': 'library', 'name': name, 'version': row['version'],
            'purl': 'pkg:npm/' + quote(name, safe='/') + '@' + row['version'],
            'properties': [{'name': 'syft:location:0:path', 'value': '/' + producer_lock}]})
    from python_build_catalog import prepare_python_build_catalog
    (reports / 'sbom-source.raw.cdx.json').write_text(json.dumps(raw))
    prepare_python_build_catalog(source, reports / 'sbom-source.raw.cdx.json', reports)
    return source, reports, manifest


class BackportCatalogTests(unittest.TestCase):
    def test_public_forge_driver_is_captured_as_data(self):
        from tool_backport_catalog import prepare_tool_backport_catalog
        with tempfile.TemporaryDirectory() as temp:
            source, reports, unused_manifest = fixture(Path(temp).resolve())
            result = prepare_tool_backport_catalog(source, reports)
            name = 'scripts/dependencies/build-forge.py'
            self.assertEqual(result['input_sha256'].get(name), hashlib.sha256((source / name).read_bytes()).hexdigest())

    def test_all_retained_forge_producer_dependencies_need_source_coverage(self):
        from tool_backport_catalog import prepare_tool_backport_catalog
        from source_catalog import validate_source_catalog
        from python_build_catalog import prepare_python_build_catalog
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            source, reports, unused_manifest = fixture(base, local=True)
            prepare_tool_backport_catalog(source, reports)
            output = base / 'coverage'; output.mkdir()
            result = validate_source_catalog(source, reports / 'sbom.cdx.json', output)
            producer = next(lock for lock in result['locks'] if lock['path'] ==
                'tools/dependency-backports/node-forge/producer/package-lock.json')
            self.assertEqual(len(producer['records']), 85)
            self.assertTrue(all(row['cataloged'] for row in producer['records']))
            raw_path = reports / 'sbom-source.raw.cdx.json'
            raw = json.loads(raw_path.read_bytes())
            raw['components'] = [row for row in raw['components'] if row.get('purl') != 'pkg:npm/webpack@5.112.1']
            raw_path.write_text(json.dumps(raw))
            for name in ('sbom.cdx.json', 'python-build-catalog-overlay.json'):
                (reports / name).unlink()
            prepare_python_build_catalog(source, raw_path, reports)
            with self.assertRaises(ValueError):
                validate_source_catalog(source, reports / 'sbom.cdx.json', output)
            failure = json.loads((output / 'source-lock-coverage.json').read_bytes())
            producer = next(lock for lock in failure['locks'] if lock['path'] ==
                'tools/dependency-backports/node-forge/producer/package-lock.json')
            webpack = next(row for row in producer['records'] if row['name'] == 'webpack')
            self.assertIs(webpack['cataloged'], False)

    def test_absent_root_is_explicitly_empty_but_incomplete_root_is_invalid(self):
        from tool_backport_catalog import prepare_tool_backport_catalog, validate_tool_backport_catalog
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve(); source = base / 'source'; reports = base / 'reports'
            source.mkdir(); reports.mkdir()
            result = prepare_tool_backport_catalog(source, reports)
            self.assertEqual(result['packages'], [])
            (source / 'tools/dependency-backports').mkdir(parents=True)
            with self.assertRaises(ValueError): validate_tool_backport_catalog(source, reports)

    def test_catalog_preserves_affected_ancestry_and_raw_python_documents(self):
        from tool_backport_catalog import prepare_tool_backport_catalog, validate_tool_backport_catalog
        with tempfile.TemporaryDirectory() as temp:
            source, reports, manifest = fixture(Path(temp).resolve())
            preserved = {p.name: p.read_bytes() for p in reports.iterdir()}
            result = prepare_tool_backport_catalog(source, reports)
            self.assertEqual(result, validate_tool_backport_catalog(source, reports))
            self.assertEqual(preserved, {name: (reports / name).read_bytes() for name in preserved})
            document = json.loads((reports / 'sbom-tool-backports.cdx.json').read_text())
            for purl in ('pkg:npm/braces@3.0.3', 'pkg:npm/node-forge@1.4.0', 'pkg:npm/resolve-workspace-root@2.0.1'):
                component = next(c for c in document['components'] if c['purl'] == purl)
                self.assertEqual(component['type'], 'library')
                self.assertEqual(component['scope'], 'required')
                self.assertIn({'name': 'appguard:tool-backports:classification',
                    'value': 'upstream-ancestry-not-installed-runtime'}, component['properties'])
            self.assertEqual(len(result['packages']), 3)
            self.assertFalse(result['advisory_closure_verified'])
            self.assertFalse(result['producer_closure_verified'])
            self.assertFalse(result['compilation_reproduction_verified'])
            self.assertEqual(result['unresolved_bundled_lineage'][0]['bundled_package'], 'braces')
            self.assertEqual(result['unresolved_bundled_lineage'][0]['status'], 'unresolved')
            self.assertEqual(result['affected_advisories'], ['GHSA-vfj7-8cjw-p6xm', 'GHSA-86w9-cpqp-85rv'])
            self.assertEqual(result['original_bundled_lineage'][0]['classification'], 'original-upstream-bundle-not-installed')
            self.assertIsNone(result['original_bundled_lineage'][0]['bundled_version'])
            self.assertFalse(result['original_bundled_lineage'][0]['installed_runtime_verified'])

    def test_changed_source_manifest_sri_or_provenance_fails_reconstruction(self):
        from tool_backport_catalog import prepare_tool_backport_catalog, validate_tool_backport_catalog
        for mode in ('source', 'sri', 'provenance', 'archive'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                source, reports, manifest = fixture(Path(temp).resolve())
                prepare_tool_backport_catalog(source, reports)
                root = source / 'tools/dependency-backports'
                if mode == 'sri':
                    manifest['packages'][0]['archive']['integrity'] = manifest['packages'][1]['archive']['integrity']
                    (root / 'manifest.json').write_text(json.dumps(manifest))
                else:
                    name = {'source': 'braces/replacements/source/lib/parse.js',
                            'provenance': 'braces/provenance.json',
                            'archive': manifest['packages'][0]['archive']['path']}[mode]
                    with (root / name).open('ab') as stream: stream.write(b'\n')
                with self.assertRaisesRegex(ValueError, 'tool backport'):
                    validate_tool_backport_catalog(source, reports)

    def test_rename_only_missing_ancestry_or_misclassification_fails(self):
        from tool_backport_catalog import prepare_tool_backport_catalog, validate_tool_backport_catalog
        for mode in ('remove', 'rename', 'excluded', 'classification', 'proof'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                source, reports, manifest = fixture(Path(temp).resolve())
                prepare_tool_backport_catalog(source, reports)
                path = reports / ('tool-backport-provenance.json' if mode == 'proof' else 'sbom-tool-backports.cdx.json')
                document = json.loads(path.read_text())
                if mode == 'proof': document['advisory_closure_verified'] = True
                else:
                    component = next(c for c in document['components'] if c['purl'] == 'pkg:npm/braces@3.0.3')
                    if mode == 'remove': document['components'].remove(component)
                    elif mode == 'rename': component['purl'] = 'pkg:npm/%40appguard/braces@3.0.3-appguard.1'
                    elif mode == 'excluded': component['scope'] = 'excluded'
                    else: component['properties'] = []
                path.write_text(json.dumps(document))
                with self.assertRaises(ValueError): validate_tool_backport_catalog(source, reports)

    def test_supplemental_coverage_requires_exact_local_archive_joins(self):
        from tool_backport_catalog import prepare_tool_backport_catalog
        from source_catalog import validate_source_catalog
        for change in (None, 'integrity', 'resolved', 'name', 'version', 'location', 'link'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                base = Path(temp).resolve()
                source, reports, manifest = fixture(base, local=True)
                lock = source / 'sdk/expo/package-lock.json'
                if change:
                    data = json.loads(lock.read_text())
                    row = data['packages']['node_modules/braces']
                    if change == 'location': data['packages']['node_modules/other'] = data['packages'].pop('node_modules/braces')
                    else: row[change] = {'integrity': manifest['packages'][1]['archive']['integrity'], 'link': True,
                        'resolved': 'file:../../other.tgz', 'name': 'braces', 'version': '3.0.3'}[change]
                    lock.write_text(json.dumps(data))
                    with self.assertRaises(ValueError):
                        prepare_tool_backport_catalog(source, reports)
                    continue
                prepare_tool_backport_catalog(source, reports)
                output = base / 'coverage-output'; output.mkdir()
                before = {p.name: p.read_bytes() for p in reports.iterdir()}
                try:
                    coverage = validate_source_catalog(source, reports / 'sbom.cdx.json', output)
                except ValueError:
                    self.fail('A fully reconstructed local archive binding must supplement source coverage')
                self.assertTrue(coverage['all_recorded_npm_packages_cataloged'])
                local = [r for r in coverage['locks'][0]['records'] if r['name'].startswith('@appguard/')]
                self.assertEqual(len(local), 3)
                self.assertTrue(all(r['cataloged'] for r in local))
                provenance = json.loads((reports / 'tool-backport-provenance.json').read_bytes())
                self.assertEqual(provenance['unresolved_bundled_lineage'], [])
                self.assertEqual(len(provenance['original_bundled_lineage']), 1)
                self.assertFalse(provenance['original_bundled_lineage'][0]['maintained_payload_contains_original_bundle'])
                self.assertEqual(before, {p.name: p.read_bytes() for p in reports.iterdir()})

    def test_candidate_builder_code_is_never_loaded(self):
        from tool_backport_catalog import prepare_tool_backport_catalog
        with tempfile.TemporaryDirectory() as temp:
            source, reports, manifest = fixture(Path(temp).resolve())
            script = source / 'scripts/dependencies/build-backports.py'
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text('raise RuntimeError("candidate code must not execute")\n')
            self.assertTrue(prepare_tool_backport_catalog(source, reports)['packages'])

    def test_raw_matching_fork_cannot_bypass_wrong_sri_or_removed_root(self):
        from tool_backport_catalog import prepare_tool_backport_catalog
        from python_build_catalog import prepare_python_build_catalog
        from source_catalog import validate_source_catalog
        for mode in ('wrong_sri', 'removed_root'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                source, reports, manifest = fixture(Path(temp).resolve(), local=True)
                raw_path = reports / 'sbom-source.raw.cdx.json'; raw = json.loads(raw_path.read_text())
                for record in manifest['packages']:
                    raw['components'].append({'type': 'library', 'group': '@appguard', 'name': record['id'],
                        'version': record['fork']['version'],
                        'purl': 'pkg:npm/%40appguard/' + record['id'] + '@' + record['fork']['version'],
                        'properties': [{'name': 'syft:location:0:path', 'value': '/sdk/expo/package-lock.json'}]})
                raw_path.write_text(json.dumps(raw))
                for name in ('sbom.cdx.json', 'python-build-catalog-overlay.json'): (reports / name).unlink()
                prepare_python_build_catalog(source, raw_path, reports)
                prepare_tool_backport_catalog(source, reports)
                if mode == 'removed_root': shutil.rmtree(source / 'tools/dependency-backports')
                else:
                    path = source / 'sdk/expo/package-lock.json'; data = json.loads(path.read_text())
                    data['packages']['node_modules/braces']['integrity'] = manifest['packages'][1]['archive']['integrity']
                    path.write_text(json.dumps(data))
                with self.assertRaises(ValueError): validate_source_catalog(source, reports / 'sbom.cdx.json', reports)


if __name__ == '__main__': unittest.main()
