"""Declared hashed build constraints are scanned without claiming runtime resolution."""
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
RELEASE = ROOT / 'scripts/release'


def module(name='python_build_catalog'):
    with patch.object(sys, 'path', [str(RELEASE), *sys.path]):
        return importlib.import_module(name)


def fixture(base, entries=None):
    entries = entries or [('Build_Helper', '2.0', ['a' * 64]), ('pluggy', '1.6.0', ['b' * 64])]
    source = base / 'source'
    source.mkdir()
    config = '[tool.uv]\nrequire-build-hashes=true\nbuild-constraint-dependencies=[\n'
    lock = 'version=1\nrevision=5\n[manifest]\nbuild-constraints=[\n'
    for name, version, hashes in entries:
        values = json.dumps(['sha256:' + h for h in hashes])
        config += '{requirement=' + json.dumps(name + '==' + version) + ',hashes=' + values + '},\n'
        canonical = name.lower().replace('_', '-').replace('.', '-')
        lock += '{name=' + json.dumps(canonical) + ',specifier=' + json.dumps('==' + version) + ',hashes=' + values + '},\n'
    config += ']\n'
    lock += ']\n[[package]]\nname="pluggy"\nversion="1.6.0"\nsource={registry="https://pypi.org/simple"}\n'
    (source / 'pyproject.toml').write_text(config)
    (source / 'uv.lock').write_text(lock)
    raw = base / 'sbom-source.raw.cdx.json'
    document = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'components': [
        {'type': 'library', 'name': 'pluggy', 'version': '1.6.0', 'purl': 'pkg:pypi/pluggy@1.6.0',
         'bom-ref': 'original-pluggy', 'licenses': [{'license': {'id': 'MIT'}}],
         'properties': [{'name': 'syft:location:0:path', 'value': '/uv.lock'}]}]}
    raw.write_text(json.dumps(document))
    return source, raw, document


class PythonBuildCatalogTests(unittest.TestCase):
    def test_nonfinite_raw_json_is_rejected_before_any_overlay_output(self):
        m = module()
        for declared in (False, True):
            for token in ('1e999', '-1e999', 'NaN', 'Infinity', '-Infinity'):
                with self.subTest(declared=declared, token=token), tempfile.TemporaryDirectory() as tmp:
                    base = Path(tmp).resolve()
                    source, raw, document = fixture(base)
                    if not declared:
                        for path in source.iterdir():
                            path.unlink()
                    raw.write_text(json.dumps(document)[:-1] + ',"extension":' + token + '}')
                    with self.assertRaises(ValueError):
                        m.prepare_python_build_catalog(source, raw, base)
                    self.assertFalse((base / 'sbom.cdx.json').exists())
                    self.assertFalse((base / 'python-build-catalog-overlay.json').exists())

    def test_nonfinite_final_and_provenance_documents_are_rejected(self):
        m = module()
        for filename in ('sbom.cdx.json', 'python-build-catalog-overlay.json'):
            for token in ('1e999', '-1e999'):
                with self.subTest(filename=filename, token=token), tempfile.TemporaryDirectory() as tmp:
                    base = Path(tmp).resolve()
                    source, raw, _ = fixture(base)
                    m.prepare_python_build_catalog(source, raw, base)
                    path = base / filename
                    path.write_text(path.read_text().rstrip()[:-1] + ',"extension":' + token + '}')
                    with self.assertRaises(ValueError):
                        m.validate_python_build_catalog(source, base / 'sbom.cdx.json')

    def test_generic_exact_pins_and_hashes_match_both_declarations(self):
        m = module()
        with tempfile.TemporaryDirectory() as tmp:
            source, _, _ = fixture(Path(tmp).resolve(), [('New.Tool', '3.4.5rc1', ['c' * 64, 'a' * 64])])
            result = m.declared_python_builds(source)
            self.assertEqual(result['records'], [{'pyproject': 'pyproject.toml', 'lock': 'uv.lock',
                'name': 'new-tool', 'version': '3.4.5rc1', 'hashes': ['sha256:' + 'a' * 64, 'sha256:' + 'c' * 64]}])
            self.assertEqual(result['input_sha256'], {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in source.iterdir()})

    def test_nonempty_build_system_requires_matching_hashed_declarations(self):
        m = module()
        for build_system in ('requires=["backend>=1"]', 'requires="backend>=1"', 'requires=[42]'):
            with self.subTest(build_system=build_system), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                source = base / 'source'
                source.mkdir()
                (source / 'pyproject.toml').write_text('[build-system]\n' + build_system)
                (source / 'uv.lock').write_text('version=1\nrevision=5\npackage=[]\n')
                with self.assertRaises(ValueError):
                    m.declared_python_builds(source)

    def test_two_projects_keep_separate_purpose_refs_and_missing_reference_pins_fail(self):
        m = module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            source, raw, _ = fixture(base)
            reference = source / 'reference/python'
            reference.mkdir(parents=True)
            for name in ('pyproject.toml', 'uv.lock'):
                shutil.copyfile(source / name, reference / name)
            result = m.prepare_python_build_catalog(source, raw, base)
            self.assertEqual(len(result['python_build_constraints']), 4)
            self.assertEqual(len({r['bom_ref'] for r in result['python_build_constraints']}), 4)
            self.assertEqual(len({r['purl'] for r in result['python_build_constraints']}), 2)
            self.assertEqual(len(result['python_build_input_sha256']), 4)
            self.assertFalse(result['python_build_resolved_closure_verified'])
            (reference / 'pyproject.toml').write_text('[build-system]\nrequires=["backend>=1"]\n')
            (reference / 'uv.lock').write_text('version=1\nrevision=5\npackage=[]\n')
            with self.assertRaises(ValueError):
                m.declared_python_builds(source)

    def test_no_declarations_are_explicitly_not_a_verified_build_closure(self):
        m = module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            source = base / 'source'
            source.mkdir()
            (source / 'pyproject.toml').write_text('[project]\nname="fixture"\n')
            raw = base / 'sbom-source.raw.cdx.json'
            raw.write_text('{"bomFormat":"CycloneDX","components":[]}')
            result = m.prepare_python_build_catalog(source, raw, base)
            self.assertFalse(result['python_build_resolved_closure_verified'])
            self.assertEqual(result['python_build_projects'][0]['status'], 'not_declared')
            self.assertFalse(result['python_build_projects'][0]['declared_constraints_cataloged'])

    def test_missing_extra_mismatched_or_unhashed_constraints_fail_closed(self):
        m = module()
        changes = [
            ('pyproject.toml', lambda s: s.replace('require-build-hashes=true', 'require-build-hashes=false')),
            ('pyproject.toml', lambda s: s.replace('require-build-hashes=true\n', '')),
            ('uv.lock', lambda s: s.replace('"==2.0"', '"==2.1"')),
            ('uv.lock', lambda s: s.replace('a' * 64, 'c' * 64)),
            ('uv.lock', lambda s: s.replace('[manifest]\nbuild-constraints=[', '[manifest]\nother=[')),
            ('pyproject.toml', lambda s: s.replace('build-constraint-dependencies=[', 'other=[')),
            ('uv.lock', lambda s: s.replace('{name="build-helper",specifier="==2.0",hashes=["sha256:' + 'a' * 64 + '"]},\n', '')),
            ('uv.lock', lambda s: s.replace('revision=5', 'revision=6')),
        ]
        for filename, change in changes:
            with self.subTest(filename=filename, change=changes.index((filename, change))), tempfile.TemporaryDirectory() as tmp:
                source, _, _ = fixture(Path(tmp).resolve())
                path = source / filename
                path.write_text(change(path.read_text()))
                with self.assertRaises(ValueError):
                    m.declared_python_builds(source)

    def test_duplicate_malformed_types_hashes_and_unbounded_inputs_rejected(self):
        m = module()
        cases = [
            [('example', '1', ['a' * 64]), ('EXAMPLE', '1', ['a' * 64])],
            [('example', '1', ['a' * 64, 'a' * 64])],
            [('example', '1', ['A' * 64])], [('example', '1', ['short'])],
            [('example', '1.*', ['a' * 64])], [('example[extra]', '1', ['a' * 64])],
            [('example', '1; python_version>"3"', ['a' * 64])],
            [('example', '1', ['a' * 64])] * 33,
        ]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as tmp:
                source, _, _ = fixture(Path(tmp).resolve(), entries)
                with self.assertRaises(ValueError):
                    m.declared_python_builds(source)

    def test_both_record_formats_reject_wrong_types_duplicates_and_extra_fields(self):
        m = module()
        changes = [lambda s: s.replace('name="build-helper"', 'name=42'),
                   lambda s: s.replace('specifier="==2.0"', 'specifier=false'),
                   lambda s: s.replace('hashes=["sha256:' + 'a' * 64 + '"]', 'hashes=[]'),
                   lambda s: s.replace('name="build-helper",', 'name="build-helper",extra=true,'),
                   lambda s: s.replace('name="pluggy"', 'name="build-helper"', 1)]
        for change in changes:
            with self.subTest(change=changes.index(change)), tempfile.TemporaryDirectory() as tmp:
                source, _, _ = fixture(Path(tmp).resolve())
                path = source / 'uv.lock'
                path.write_text(change(path.read_text()))
                with self.assertRaises(ValueError):
                    m.declared_python_builds(source)
        for invalid in ['false', '{}', '"not an array"', '[{requirement=42,hashes=[]}]',
                        '[{requirement="example==1",hashes="sha256:' + 'a' * 64 + '"}]',
                        '[{requirement="example==1",hashes=["sha256:' + 'a' * 64 + '"],extra=true}]']:
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as tmp:
                source, _, _ = fixture(Path(tmp).resolve())
                (source / 'pyproject.toml').write_text('[tool.uv]\nrequire-build-hashes=true\nbuild-constraint-dependencies=' + invalid)
                with self.assertRaises(ValueError):
                    m.declared_python_builds(source)

    def test_overlay_preserves_raw_input_runtime_identity_licenses_and_counts(self):
        m, server = module(), module('server_catalog')
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            source, raw, document = fixture(base)
            original = {p: p.read_bytes() for p in [raw, *source.iterdir()]}
            runtime_before = server.validate_server_catalog(source, document['components'])
            result = m.prepare_python_build_catalog(source, raw, base)
            output = json.loads((base / 'sbom.cdx.json').read_text())
            self.assertEqual(output['components'][:1], document['components'])
            self.assertEqual(server.validate_server_catalog(source, output['components']), runtime_before)
            self.assertEqual({p: p.read_bytes() for p in original}, original)
            refs = [c['bom-ref'] for c in output['components']]
            self.assertEqual(len(set(refs)), 3)
            self.assertEqual(sum(c['purl'] == 'pkg:pypi/pluggy@1.6.0' for c in output['components']), 2)
            for component in output['components'][1:]:
                self.assertNotIn('licenses', component)
                self.assertEqual(component['type'], 'library')
                self.assertEqual(component['scope'], 'required')
                props = {p['name']: p['value'] for p in component['properties']}
                self.assertEqual(props['appguard:python-build-catalog:resolved-runtime'], 'false')
                self.assertFalse(any(k.startswith('syft:location:') for k in props))
                self.assertEqual(component['hashes'][0]['alg'], 'SHA-256')
            self.assertTrue(result['all_declared_python_build_constraints_cataloged'])
            self.assertEqual(len(result['python_build_constraints']), 2)
            self.assertEqual(m.validate_python_build_catalog(source, base / 'sbom.cdx.json'), result)
            before = (base / 'sbom.cdx.json').read_bytes()
            m.prepare_python_build_catalog(source, raw, base)
            self.assertEqual((base / 'sbom.cdx.json').read_bytes(), before)

    def test_provenance_missing_malformed_or_tampered_never_clears_coverage(self):
        m = module()
        changes = [('python-build-catalog-overlay.json', None), ('sbom-source.raw.cdx.json', None),
                   ('python-build-catalog-overlay.json', b'{}'),
                   ('python-build-catalog-overlay.json', b'{"schema":1,"schema":1}'),
                   ('sbom-source.raw.cdx.json', b'{"bomFormat":"CycloneDX","components":[]}'),
                   ('sbom.cdx.json', b'{"bomFormat":"CycloneDX","components":[]}')]
        for name, replacement in changes:
            with self.subTest(name=name, replacement=replacement), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                source, raw, _ = fixture(base)
                m.prepare_python_build_catalog(source, raw, base)
                (base / name).unlink()
                if replacement is not None:
                    (base / name).write_bytes(replacement)
                with self.assertRaises(ValueError):
                    m.validate_python_build_catalog(source, base / 'sbom.cdx.json')

    def test_tampered_component_and_self_updated_proof_hash_still_fail(self):
        m = module()
        for field, replacement in [('licenses', [{'license': {'id': 'MIT'}}]), ('scope', 'excluded'),
                                   ('hashes', [{'alg': 'SHA-256', 'content': 'c' * 64}]),
                                   ('properties', [{'name': 'syft:location:0:path', 'value': '/uv.lock'}])]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                source, raw, _ = fixture(base)
                m.prepare_python_build_catalog(source, raw, base)
                path = base / 'sbom.cdx.json'
                final = json.loads(path.read_text())
                final['components'][-1][field] = replacement
                path.write_text(json.dumps(final))
                proof_path = base / 'python-build-catalog-overlay.json'
                proof = json.loads(proof_path.read_text())
                proof['sbom_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                proof_path.write_text(json.dumps(proof))
                with self.assertRaises(ValueError):
                    m.validate_python_build_catalog(source, path)

    def test_mutation_during_preparation_and_conflicting_output_are_rejected(self):
        m = module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            source, raw, _ = fixture(base)
            original_write = m._write_bytes
            def change_config(reports, name, data):
                original_write(reports, name, data)
                config = source / 'pyproject.toml'
                config.write_text(config.read_text() + '# concurrent change\n')
            with patch.object(m, '_write_bytes', side_effect=change_config), self.assertRaises(ValueError):
                m.prepare_python_build_catalog(source, raw, base)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            source, raw, _ = fixture(base)
            target = base / 'sbom.cdx.json'
            target.write_bytes(b'existing evidence')
            with self.assertRaises(ValueError):
                m.prepare_python_build_catalog(source, raw, base)
            self.assertEqual(target.read_bytes(), b'existing evidence')

    def test_fifo_replacement_at_open_is_rejected_without_blocking(self):
        m = module()
        with tempfile.TemporaryDirectory() as tmp:
            source, _, _ = fixture(Path(tmp).resolve())
            target = source / 'pyproject.toml'
            original = os.open
            def swap(path, flags, *args, **kwargs):
                if Path(path) == target:
                    target.unlink()
                    os.mkfifo(target)
                    self.assertTrue(flags & os.O_NONBLOCK, 'concurrent FIFO must not block the scan')
                return original(path, flags, *args, **kwargs)
            with patch.object(os, 'open', side_effect=swap), self.assertRaises(ValueError):
                m.declared_python_builds(source)

    def test_provenance_source_and_raw_hash_fields_are_required_and_exact(self):
        m = module()
        for key, replacement in [('input_sha256', {}), ('input_sha256', {'pyproject.toml': 'a' * 64}),
                                 ('raw_sbom_sha256', 'b' * 64), ('raw_sbom_sha256', True),
                                 ('raw_sbom_sha256', None), ('sbom_sha256', 'c' * 64), ('schema', True)]:
            with self.subTest(key=key, replacement=replacement), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                source, raw, _ = fixture(base)
                m.prepare_python_build_catalog(source, raw, base)
                path = base / 'python-build-catalog-overlay.json'
                overlay = json.loads(path.read_text())
                overlay[key] = replacement
                path.write_text(json.dumps(overlay))
                with self.assertRaises(ValueError):
                    m.validate_python_build_catalog(source, base / 'sbom.cdx.json')

    def test_duplicate_existing_bom_refs_and_raw_overlay_markers_rejected(self):
        m = module()
        for change in ('duplicate', 'metadata_duplicate', 'marked'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                source, raw, document = fixture(base)
                if change == 'duplicate':
                    document['components'].append(copy.deepcopy(document['components'][0]))
                elif change == 'metadata_duplicate':
                    document['metadata'] = {'component': copy.deepcopy(document['components'][0])}
                else:
                    document['components'][0]['properties'].append({'name': 'appguard:python-build-catalog:source',
                        'value': 'declared-hashed-build-constraint'})
                raw.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    m.prepare_python_build_catalog(source, raw, base)

    def test_changed_declaration_cannot_reuse_overlay_or_follow_symlinks(self):
        m = module()
        for action in ('mutate', 'symlink', 'output_in_source'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                source, raw, _ = fixture(base)
                m.prepare_python_build_catalog(source, raw, base)
                config = source / 'pyproject.toml'
                if action == 'mutate':
                    config.write_text(config.read_text() + '# changed\n')
                elif action == 'symlink':
                    moved = base / 'config.toml'
                    config.rename(moved)
                    config.symlink_to(moved)
                else:
                    with self.assertRaises(ValueError):
                        m.prepare_python_build_catalog(source, raw, source)
                    continue
                with self.assertRaises(ValueError):
                    m.validate_python_build_catalog(source, base / 'sbom.cdx.json')

    def test_source_coverage_keeps_runtime_records_and_separate_build_class(self):
        m, catalog = module(), module('source_catalog')
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            source, raw, document = fixture(base)
            before = catalog.validate_server_catalog(source, document['components'])
            with self.assertRaises(ValueError):
                catalog.validate_source_catalog(source, raw, base)
            m.prepare_python_build_catalog(source, raw, base)
            result = catalog.validate_source_catalog(source, base / 'sbom.cdx.json', base)
            self.assertEqual(result['server_locks'], before['server_locks'])
            self.assertTrue(result['all_recorded_packages_cataloged'])
            self.assertTrue(result['all_declared_python_build_constraints_cataloged'])
            self.assertEqual(len(result['python_build_constraints']), 2)
            # Publication recomputes coverage into a different private directory.
            verification = base / 'verification'
            verification.mkdir()
            self.assertEqual(catalog.validate_source_catalog(source, base / 'sbom.cdx.json', verification), result)

    def test_current_sdk_preserves_40_package_entries_and_six_separate_build_pins(self):
        m, server = module(), module('server_catalog')
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            source = base / 'source'
            source.mkdir()
            for name in ('uv.lock', 'pyproject.toml'):
                shutil.copyfile(ROOT / 'sdk/python' / name, source / name)
            lock = tomllib.loads((source / 'uv.lock').read_text())
            components = [{'type': 'library', 'name': p['name'], 'version': p['version'],
                'purl': 'pkg:pypi/' + p['name'] + '@' + p['version'], 'bom-ref': 'runtime-' + p['name'],
                'properties': [{'name': 'syft:location:0:path', 'value': '/uv.lock'}]}
                for p in lock['package'] if 'registry' in p['source']]
            raw = base / 'sbom-source.raw.cdx.json'
            raw.write_text(json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'components': components}))
            before = server.validate_server_catalog(source, components)
            result = m.prepare_python_build_catalog(source, raw, base)
            after = server.validate_server_catalog(source, json.loads((base / 'sbom.cdx.json').read_text())['components'])
            self.assertEqual(before, after)
            self.assertEqual(len(lock['package']), 40)
            self.assertEqual(before['server_locks'][0]['recorded_package_count'], 39)
            self.assertEqual(before['server_locks'][0]['skipped_local_project_count'], 1)
            self.assertEqual(len(result['python_build_constraints']), 6)
            self.assertIn('pkg:pypi/editables@0.6', {r['purl'] for r in result['python_build_constraints']})


if __name__ == '__main__':
    unittest.main()
