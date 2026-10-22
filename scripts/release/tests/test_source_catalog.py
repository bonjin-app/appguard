"""Source catalogs must include recorded development and peer-test dependencies."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('source_catalog', ROOT / 'scripts/release/source_catalog.py')


def module():
    result = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(result)
    return result


class CatalogTests(unittest.TestCase):
    def test_missing_recorded_dev_dependency_fails_coverage(self):
        m = module()
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source = base / 'source'
            (source / 'sdk/node').mkdir(parents=True)
            (source / 'sdk/node/package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {
                '': {'name':'project'}, 'node_modules/express': {'version':'5.3.0','dev':True}}}))
            sbom = base / 'sbom.json'
            sbom.write_text(json.dumps({'components':[{'name':'project','version':'1'}]}))
            with self.assertRaisesRegex(ValueError, 'recorded npm'):
                m.validate_source_catalog(source, sbom, base)
            report = json.loads((base / 'source-lock-coverage.json').read_text())
            self.assertFalse(report['all_recorded_npm_packages_cataloged'])
            self.assertTrue(report['locks'][0]['records'][0]['development'])

    def test_unsupported_or_malformed_locks_never_report_complete_coverage(self):
        m = module()
        cases = [
            {'lockfileVersion': 1, 'dependencies': {}},
            {'lockfileVersion': 2, 'packages': {'': {}}},
            {'lockfileVersion': 3},
            {'lockfileVersion': 3, 'packages': []},
            {'lockfileVersion': 3, 'packages': {}},
            {'lockfileVersion': 3, 'packages': {'': []}},
            {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/test': 'invalid'}},
            {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/test': {}}},
            {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/test': {'version': 3}}},
            {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/test': {'version': ' '}}},
            {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/test': {'link': 'true'}}},
            {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/test': {'link': True}}},
        ]
        for data in cases:
            with self.subTest(data=data), tempfile.TemporaryDirectory() as temp:
                base = Path(temp)
                source = base / 'source'
                source.mkdir()
                (source / 'package-lock.json').write_text(json.dumps(data))
                sbom = base / 'sbom.json'
                sbom.write_text('{"components":[]}')
                with self.assertRaises(ValueError):
                    m.validate_source_catalog(source, sbom, base)
                report = json.loads((base / 'source-lock-coverage.json').read_text())
                self.assertFalse(report['all_recorded_npm_packages_cataloged'])
                self.assertTrue(report['validation_errors'])

    def test_explicit_resolved_link_is_recorded_without_inventing_package_version(self):
        m = module()
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source = base / 'source'
            source.mkdir()
            (source / 'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {
                '': {}, 'node_modules/workspace': {'link': True, 'resolved': 'packages/workspace'}}}))
            sbom = base / 'sbom.json'
            sbom.write_text('{"components":[]}')
            report = m.validate_source_catalog(source, sbom, base)
            self.assertEqual(report['locks'][0]['unversioned_or_link_records'], ['node_modules/workspace'])
            self.assertEqual(report['locks'][0]['records'], [])

    def test_component_name_cannot_hide_a_forged_purl(self):
        m = module()
        for purl, valid in [('pkg:npm/other-package@99', False), ('pkg:npm/%40scope/example@1.0.0', True)]:
            with self.subTest(purl=purl), tempfile.TemporaryDirectory() as temp:
                base = Path(temp)
                source = base / 'source'
                source.mkdir()
                (source / 'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages': {
                    '':{},'node_modules/@scope/example':{'version':'1.0.0'}}}))
                sbom = base / 'sbom.json'
                sbom.write_text(json.dumps({'components':[{'name':'example','group':'@scope','version':'1.0.0','purl':purl,
                    'properties':[{'name':'syft:location:0:path','value':'/package-lock.json'}]}]}))
                if valid:
                    self.assertTrue(m.validate_source_catalog(source,sbom,base)['all_recorded_npm_packages_cataloged'])
                else:
                    with self.assertRaises(ValueError):m.validate_source_catalog(source,sbom,base)

    @unittest.skipUnless(os.environ.get('APPGUARD_SYFT'), 'explicit reviewed Syft binary required')
    def test_actual_syft_catalogs_framework_redis_and_expo_peer_test_graph(self):
        m = module()
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source = base / 'source'
            for directory in ['sdk/node','sdk/expo']:
                (source / directory).mkdir(parents=True)
                for filename in ['package.json','package-lock.json']:
                    shutil.copyfile(ROOT / directory / filename, source / directory / filename)
            config = base / 'syft.json'
            m.write_syft_config(config)
            sbom = base / 'sbom.cdx.json'
            subprocess.run([os.environ['APPGUARD_SYFT'],'scan','dir:'+str(source),'--config',str(config),
                            '-o','cyclonedx-json='+str(sbom)],check=True,capture_output=True,timeout=60)
            report = m.validate_source_catalog(source, sbom, base)
            self.assertTrue(report['all_recorded_npm_packages_cataloged'])
            names = {c['name'] for c in json.loads(sbom.read_text())['components']}
            self.assertTrue({'express','fastify','redis','react-native'} <= names)


if __name__ == '__main__':
    unittest.main()
