import hashlib
import importlib.util
import json
import subprocess
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'runtime_catalog.py'


class RuntimeCatalogTests(unittest.TestCase):
    def module(self):
        self.assertTrue(MODULE.is_file(), 'Runtime coverage validator is missing')
        spec = importlib.util.spec_from_file_location('runtime_catalog', MODULE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def fixture(self, base, classifier=None):
        artifacts = base / 'artifacts'
        artifacts.mkdir()
        reports = base / 'reports'
        reports.mkdir()
        name = 'example-1.2' + ('-' + classifier if classifier else '') + '.jar'
        relative = 'org/example/example/1.2/' + name
        jar = artifacts / relative
        jar.parent.mkdir(parents=True)
        jar.write_bytes(b'owned test jar')
        digest = hashlib.sha256(jar.read_bytes()).hexdigest()
        manifest = base / 'manifest.json'
        manifest.write_text(json.dumps({'returncode': 0, 'command': ['mvn', '-DoutputDirectory=' + str(artifacts)], 'jar_sha256': {relative: digest}, 'sha256': {relative: digest}}))
        component = {'type': 'library', 'name': 'example', 'version': '1.2',
                     'purl': 'pkg:maven/org.example/example@1.2' + ('?classifier=' + classifier if classifier else ''),
                     'bom-ref': 'package-1',
                     'properties': [{'name': 'syft:location:0:path', 'value': '/' + relative}]}
        sbom = base / 'sbom.json'
        sbom.write_text(json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'components': [component]}))
        return artifacts, manifest, sbom, reports, jar, relative

    def rewrite(self, path, mutate):
        data = json.loads(path.read_text())
        mutate(data)
        path.write_text(json.dumps(data))

    def reject(self, module, fixture):
        artifacts, manifest, sbom, reports, *_ = fixture
        with self.assertRaises(ValueError):
            module.validate_runtime_catalog(artifacts, manifest, sbom, reports)
        report = json.loads((reports / 'runtime-lock-coverage.json').read_text())
        self.assertFalse(report['all_maven_runtime_jars_cataloged'])
        self.assertTrue(report['validation_errors'])
        return report

    def test_exact_maven_identity_and_location_pass_and_pin_input_bytes(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp).resolve())
            result = m.validate_runtime_catalog(*f[:4])
            self.assertTrue(result['all_maven_runtime_jars_cataloged'])
            self.assertEqual(result['jar_count'], 1)
            self.assertEqual(result['cataloged_jar_count'], 1)
            self.assertEqual(result['manifest_sha256'], hashlib.sha256(f[1].read_bytes()).hexdigest())
            self.assertEqual(result['sbom_sha256'], hashlib.sha256(f[2].read_bytes()).hexdigest())
            self.assertEqual(result['records'][0]['sha256'], hashlib.sha256(f[4].read_bytes()).hexdigest())
            self.assertEqual(result, json.loads((f[3] / 'runtime-lock-coverage.json').read_text()))

    def test_validator_rejects_regular_file_replaced_with_fifo_at_open_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp).resolve())
            script = '''
import importlib.util, json, os, pathlib, sys
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('owned_runtime_fifo_probe', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
paths = [pathlib.Path(p) for p in sys.argv[2:]]
target = paths[1]
original_open = os.open
def swap_at_open(path, flags, *args, **kwargs):
    if pathlib.Path(path) == target:
        target.unlink()
        os.mkfifo(target)
    return original_open(path, flags, *args, **kwargs)
with patch.object(os, 'open', side_effect=swap_at_open):
    try:
        m.validate_runtime_catalog(*paths)
    except ValueError:
        result = json.loads((paths[3] / 'runtime-lock-coverage.json').read_text())
        sys.exit(0 if result['all_maven_runtime_jars_cataloged'] is False else 2)
sys.exit(3)
'''
            try:
                result = subprocess.run([sys.executable, '-c', script, str(MODULE), *map(str, f[:4])],
                                        capture_output=True, timeout=0.75)
            except subprocess.TimeoutExpired:
                # subprocess.run kills and reaps this owned, child-only probe.
                self.fail('Runtime validator blocked on a concurrent FIFO; owned child killed and reaped')
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_json_exponent_overflow_and_nonfinite_encoder_values_are_rejected(self):
        m = self.module()
        for token in ('1e999', '-1e999', 'NaN', 'Infinity', '-Infinity'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                m._json('{"extension":' + token + '}')
        for number in (float('inf'), float('-inf'), float('nan')):
            with self.subTest(number=number), self.assertRaises(ValueError):
                m._encoded({'extension': number})
        self.assertEqual(m._json('{"extension":1e2}')['extension'], 100.0)

    def test_empty_or_anonymous_archive_sbom_cannot_satisfy_runtime_package_coverage(self):
        m = self.module()
        for components in ([], [{'type': 'file', 'name': 'example-1.2.jar', 'version': '1.2'}],
                           [{'type': 'library', 'name': 'example', 'version': '1.2', 'purl': 'pkg:generic/example@1.2'}]):
            with self.subTest(components=components), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp).resolve())
                self.rewrite(f[2], lambda b: b.update(components=components))
                self.reject(m, f)

    def test_wrong_coordinate_version_name_or_component_type_is_not_cataloged(self):
        m = self.module()
        changes = [{'purl': 'pkg:maven/org.other/example@1.2'}, {'purl': 'pkg:maven/org.example/example@1.3'},
                   {'version': '1.3'}, {'name': 'other'}, {'group': 'org.other'}, {'type': 'file'}, {'scope': 'excluded'},
                   {'purl': 'pkg:maven/org.example%2Fother/example@1.2'},
                   {'purl': 'pkg:maven/org.example/example@1.2#some/file'},
                   {'purl': 'pkg:maven/org.example/example@1.2?classifier=x&classifier=y'},
                   {'purl': 'pkg:maven/org.example/example@1.2?type=pom'},
                   {'purl': 'pkg:maven/org.example/example@1.2?unknown=x'}]
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp).resolve())
                self.rewrite(f[2], lambda b: b['components'][0].update(change))
                self.reject(m, f)

    def test_location_must_be_exact_safe_path_for_the_same_component(self):
        m = self.module()
        for location in ('/elsewhere/example-1.2.jar', '//org/example/example/1.2/example-1.2.jar',
                         '/org/example/../example/example/1.2/example-1.2.jar',
                         'org\\example\\example\\1.2\\example-1.2.jar', '/org/example/example/1.2/example-1.2.jar:inside.jar'):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp).resolve())
                self.rewrite(f[2], lambda b: b['components'][0]['properties'][0].update(value=location))
                self.reject(m, f)
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp).resolve())
            self.rewrite(f[2], lambda b: b['components'][0].pop('properties'))
            self.reject(m, f)

    def test_classifier_is_required_and_binds_exact_classifier_qualifier(self):
        m = self.module()
        for classifier in ('linux-x86_64', 'linux-aarch_64', 'tests'):
            with self.subTest(classifier=classifier), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp).resolve(), classifier)
                self.assertTrue(m.validate_runtime_catalog(*f[:4])['all_maven_runtime_jars_cataloged'])
                self.rewrite(f[2], lambda b: b['components'][0].update(purl='pkg:maven/org.example/example@1.2'))
                self.reject(m, f)

    def test_filename_only_or_unsupported_repository_layout_is_rejected(self):
        m = self.module()
        for relative in ('example-1.2.jar', 'org/example/example/1.2/other-1.2.jar',
                         'org/example/example/1.2/example-1.3.jar', 'org/example//1.2/example-1.2.jar',
                         'org/example/./example/1.2/example-1.2.jar', '../outside.jar', '/absolute.jar'):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp).resolve())
                digest = hashlib.sha256(b'owned test jar').hexdigest()
                self.rewrite(f[1], lambda b: b.update(jar_sha256={relative: digest}, sha256={relative: digest}))
                self.reject(m, f)

    def test_manifest_success_is_exact_integer_zero_and_nonempty_complete_jar_map(self):
        m = self.module()
        changes = [{'returncode': False}, {'returncode': '0'}, {'returncode': 1}, {'jar_sha256': {}},
                   {'jar_sha256': []}, {'sha256': {}}, {'jar_sha256': {'bad.jar': 'x'}},
                   {'sha256': {'bad.jar': '0' * 64}}, {'jar_sha256': {'bad.txt': '0' * 64}}]
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp).resolve())
                self.rewrite(f[1], lambda b: b.update(change))
                self.reject(m, f)

    def test_unrecorded_missing_or_changed_jar_and_mismatching_manifest_digests_fail(self):
        m = self.module()
        for mutation in ('missing', 'changed', 'extra', 'manifest_mismatch'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp).resolve())
                if mutation == 'missing': f[4].unlink()
                if mutation == 'changed': f[4].write_bytes(b'changed')
                if mutation == 'extra': (f[0] / 'untracked.jar').write_bytes(b'extra')
                if mutation == 'manifest_mismatch': self.rewrite(f[1], lambda b: b['jar_sha256'].update({f[5]: '0' * 64}))
                self.reject(m, f)

    def test_all_exported_files_are_hashed_not_only_jars(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp).resolve())
            metadata = f[4].parent / '_remote.repositories'
            metadata.write_bytes(b'repository')
            digest = hashlib.sha256(metadata.read_bytes()).hexdigest()
            self.rewrite(f[1], lambda b: b['sha256'].update({str(metadata.relative_to(f[0])): digest}))
            self.assertTrue(m.validate_runtime_catalog(*f[:4])['all_maven_runtime_jars_cataloged'])
            metadata.write_bytes(b'changed')
            self.reject(m, f)

    def test_symlink_input_file_directory_root_and_report_target_never_followed(self):
        m = self.module()
        for target in ('jar', 'parent', 'artifacts', 'manifest', 'sbom', 'report'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                f = list(self.fixture(base))
                if target == 'jar':
                    other = base / 'outside.jar'; other.write_bytes(f[4].read_bytes()); f[4].unlink(); f[4].symlink_to(other)
                elif target in ('manifest', 'sbom'):
                    index = 1 if target == 'manifest' else 2
                    other = base / 'outside.json'; f[index].rename(other); f[index].symlink_to(other)
                elif target == 'parent':
                    directory = f[0] / 'org'; other = base / 'outside'; directory.rename(other); directory.symlink_to(other, target_is_directory=True)
                elif target == 'artifacts':
                    other = base / 'outside'; f[0].rename(other); f[0].symlink_to(other, target_is_directory=True)
                else:
                    other = base / 'outside'; other.write_bytes(b'preserve'); (f[3] / 'runtime-lock-coverage.json').symlink_to(other)
                with self.assertRaises(ValueError): m.validate_runtime_catalog(*f[:4])
                if target == 'report': self.assertEqual(other.read_bytes(), b'preserve')

    def test_malformed_json_duplicate_fields_or_schema_never_passes(self):
        m = self.module()
        for data in ('null', '[]', '{"returncode":0,"returncode":1}', '{bad'):
            with self.subTest(manifest=data), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp).resolve()); f[1].write_text(data); self.reject(m, f)
        for data in ('null', '[]', '{"bomFormat":"CycloneDX","components":[]}',
                     '{"bomFormat":"Other","specVersion":"1.6","components":[]}',
                     '{"bomFormat":"CycloneDX","specVersion":"1.6","components":{}}',
                     '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[null]}',
                     '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[],"components":[]}', '{bad'):
            with self.subTest(sbom=data), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp).resolve()); f[2].write_text(data); self.reject(m, f)

    def test_mutation_after_initial_read_is_detected_by_final_recheck(self):
        m = self.module()
        for target in ('jar', 'manifest', 'sbom', 'extra'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp).resolve())
                original = m._component_records
                def mutate(data):
                    result = original(data)
                    if target == 'jar': f[4].write_bytes(b'changed during scan')
                    elif target == 'manifest': f[1].write_bytes(f[1].read_bytes() + b' ')
                    elif target == 'sbom': f[2].write_bytes(f[2].read_bytes() + b' ')
                    else: (f[0] / 'surprise.jar').write_bytes(b'extra')
                    return result
                with patch.object(m, '_component_records', side_effect=mutate): self.reject(m, f)


    def overlay_fixture(self, base):
        f = self.fixture(base)
        digest = hashlib.sha256(f[4].read_bytes()).hexdigest()
        self.rewrite(f[2], lambda b: (b['components'][0].update(purl='pkg:maven/org.wrong/example@1.2', group='org.wrong'),
            b['components'].append({'type': 'file', 'name': str(f[4]), 'bom-ref': 'file-1',
                                    'hashes': [{'alg': 'SHA-256', 'content': digest}]})))
        dependencies = base / 'dependencies.txt'
        dependencies.write_text('\nThe following files have been resolved:\n   org.example:example:jar:1.2:compile\n\n')
        return f, dependencies

    def test_overlay_preserves_every_raw_component_and_adds_only_missing_primary_gav(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            f, dependencies = self.overlay_fixture(Path(tmp).resolve())
            raw = json.loads(f[2].read_text())
            result = m.prepare_runtime_catalog(*f[:4], dependencies_path=dependencies)
            self.assertTrue(result['all_maven_runtime_jars_cataloged'])
            final = json.loads((f[3] / 'sbom-maven-runtime.cdx.json').read_text())
            self.assertEqual(final['components'][:len(raw['components'])], raw['components'])
            self.assertEqual(len(final['components']), len(raw['components']) + 1)
            overlay = json.loads((f[3] / 'runtime-catalog-overlay.json').read_text())
            self.assertEqual(overlay['raw_sbom_sha256'], hashlib.sha256(f[2].read_bytes()).hexdigest())
            self.assertEqual(overlay['dependencies_sha256'], hashlib.sha256(dependencies.read_bytes()).hexdigest())
            self.assertEqual(overlay['supplemented_jar_count'], 1)
            self.assertTrue(m.validate_runtime_catalog(f[0], f[1], f[3] / 'sbom-maven-runtime.cdx.json', f[3])['all_maven_runtime_jars_cataloged'])

    def test_empty_raw_sbom_wrong_or_missing_outer_hash_prevents_supplement(self):
        m = self.module()
        for mutation in ('empty', 'missing_file', 'wrong_hash', 'wrong_location'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                f, deps = self.overlay_fixture(Path(tmp).resolve())
                def change(b):
                    if mutation == 'empty': b['components'] = []
                    elif mutation == 'missing_file': b['components'].pop()
                    elif mutation == 'wrong_hash': b['components'][-1]['hashes'][0]['content'] = '0' * 64
                    else: b['components'][-1]['name'] = '/other/example-1.2.jar'
                self.rewrite(f[2], change)
                with self.assertRaises(ValueError): m.prepare_runtime_catalog(*f[:4], dependencies_path=deps)
                self.assertFalse((f[3] / 'sbom-maven-runtime.cdx.json').exists())

    def test_dependency_list_must_exactly_corroborate_every_exported_primary_coordinate(self):
        m = self.module()
        for text in ('', '   org.other:example:jar:1.2:compile\n', '   org.example:example:jar:1.3:compile\n',
                     '   org.example:example:jar:tests:1.2:compile\n', '   org.example:example:pom:1.2:compile\n',
                     '   org.example:example:jar:1.2:test\n',
                     '   org.example:example:jar:1.2:compile\n   org.other:other:jar:3:runtime\n'):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as tmp:
                f, deps = self.overlay_fixture(Path(tmp).resolve()); deps.write_text(text)
                with self.assertRaises(ValueError): m.prepare_runtime_catalog(*f[:4], dependencies_path=deps)

    def test_overlay_provenance_recomputed_not_trusted_after_mutations(self):
        m = self.module()
        for target in ('raw', 'dependencies', 'overlay', 'supplement', 'omitted_raw_component', 'deleted_provenance'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                f, deps = self.overlay_fixture(Path(tmp).resolve())
                m.prepare_runtime_catalog(*f[:4], dependencies_path=deps)
                final = f[3] / 'sbom-maven-runtime.cdx.json'
                if target == 'raw': (f[3] / 'sbom-maven-runtime.raw.cdx.json').write_text('{}')
                elif target == 'dependencies': (f[3] / 'maven-runtime-dependencies.txt').write_text('')
                elif target == 'overlay': self.rewrite(f[3] / 'runtime-catalog-overlay.json', lambda b: b.update(supplemented_jar_count=0))
                elif target == 'supplement': self.rewrite(final, lambda b: b['components'][-1].update(purl='pkg:maven/org.fake/example@1.2'))
                elif target == 'omitted_raw_component': self.rewrite(final, lambda b: b['components'].pop(0))
                else: (f[3] / 'runtime-catalog-overlay.json').unlink()
                with self.assertRaises(ValueError): m.validate_runtime_catalog(f[0], f[1], final, f[3])

    def test_valid_existing_primary_is_retained_without_duplicate_supplement(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            f, deps = self.overlay_fixture(Path(tmp).resolve())
            self.rewrite(f[2], lambda b: b['components'][0].update(purl='pkg:maven/org.example/example@1.2', group='org.example'))
            m.prepare_runtime_catalog(*f[:4], dependencies_path=deps)
            overlay = json.loads((f[3] / 'runtime-catalog-overlay.json').read_text())
            self.assertEqual(overlay['supplemented_jar_count'], 0)

    def test_fake_overlay_marker_without_recomputable_provenance_cannot_pass(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp).resolve())
            self.rewrite(f[2], lambda b: b['components'][0]['properties'].append({'name': 'appguard:runtime-catalog:source', 'value': 'maven-runtime-manifest'}))
            self.reject(m, f)


    def test_preserved_overlay_inputs_live_beside_sbom_and_output_can_be_separate(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            source = base / 'original'; source.mkdir()
            f, deps = self.overlay_fixture(source)
            initial = m.prepare_runtime_catalog(*f[:4], dependencies_path=deps)
            copied = base / 'copied'
            shutil.copytree(source, copied)
            output = base / 'new-verification'; output.mkdir()
            before = {str(p.relative_to(copied)): p.read_bytes() for p in copied.rglob('*') if p.is_file()}
            actual = m.validate_runtime_catalog(copied / 'artifacts', copied / 'manifest.json',
                                               copied / 'reports/sbom-maven-runtime.cdx.json', output)
            self.assertEqual(initial, actual)
            self.assertEqual(before, {str(p.relative_to(copied)): p.read_bytes() for p in copied.rglob('*') if p.is_file()})
            self.assertEqual({p.name for p in output.iterdir()}, {'runtime-lock-coverage.json'})

    def test_removing_all_markers_does_not_bypass_existing_provenance(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            f, deps = self.overlay_fixture(Path(tmp).resolve())
            m.prepare_runtime_catalog(*f[:4], dependencies_path=deps)
            final = f[3] / 'sbom-maven-runtime.cdx.json'
            def remove(document):
                document.pop('metadata', None)
                for c in document['components']:
                    if 'properties' in c:
                        c['properties'] = [p for p in c['properties'] if p['name'] != 'appguard:runtime-catalog:source']
            self.rewrite(final, remove)
            with self.assertRaises(ValueError): m.validate_runtime_catalog(f[0], f[1], final, f[3])

    def test_pinned_syft_classifier_shape_without_qualifier_is_supplemented(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp).resolve(), 'linux-x86_64')
            digest = hashlib.sha256(f[4].read_bytes()).hexdigest()
            self.rewrite(f[2], lambda b: (b['components'][0].update(purl='pkg:maven/org.example/example@1.2'),
                b['components'].append({'type': 'file', 'name': str(f[4]), 'bom-ref': 'classifier-file',
                                        'hashes': [{'alg': 'SHA-256', 'content': digest}]})))
            deps = f[0].parent / 'classifier-list.txt'
            deps.write_text('   org.example:example:jar:linux-x86_64:1.2:runtime\n')
            result = m.prepare_runtime_catalog(*f[:4], dependencies_path=deps)
            self.assertEqual(result['supplemented_jar_count'], 1)
            self.assertEqual(result['records'][0]['matching_purls'], ['pkg:maven/org.example/example@1.2?classifier=linux-x86_64'])


if __name__ == '__main__':
    unittest.main()
