"""A failed or unavailable secret scan must not publish source or metadata."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote

SCRIPT = Path(__file__).resolve().parents[1] / 'publication_gate.py'
sys.path.insert(0, str(SCRIPT.parent))
WORKFLOW = SCRIPT.parents[2] / '.github/workflows/release-readiness.yml'
MARKER = 'SYNTHETIC-SECRET-DO-NOT-PUBLISH-8b117a'


class PublicationTests(unittest.TestCase):
    def setup_inputs(self, base, code=0, secrets=0, build_pin=False, backports=False):
        candidate = base / 'candidate'
        scans = base / 'scans'
        (candidate / 'source/docs').mkdir(parents=True)
        scans.mkdir()
        (candidate / 'source/docs/input.txt').write_text(MARKER)
        (candidate / 'source/sdk/spring-boot').mkdir(parents=True)
        pom = candidate / 'source/sdk/spring-boot/pom.xml'
        pom.write_text('<project/>')
        (candidate / 'source.tar.gz').write_text(MARKER)
        for name in ('dependency-coverage.json', 'licenses.json'):
            (candidate / name).write_text('{}')
        (candidate / 'source/package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {'': {}}}))
        raw_components = []
        if backports:
            shutil.copytree(SCRIPT.parents[2] / 'tools/dependency-backports',
                            candidate / 'source/tools/dependency-backports')
            for name in ('build-resolver.cjs', 'build-forge.py'):
                target = candidate / 'source/scripts/dependencies' / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(SCRIPT.parents[2] / 'scripts/dependencies' / name, target)
            # Keep the complete retained compiler lock in ordinary source coverage.
            producer_lock = 'tools/dependency-backports/node-forge/producer/package-lock.json'
            producer = json.loads((candidate / 'source' / producer_lock).read_bytes())
            for location, row in producer['packages'].items():
                if not location:
                    continue
                name = location.rsplit('node_modules/', 1)[-1]
                raw_components.append({'type': 'library', 'name': name, 'version': row['version'],
                    'purl': 'pkg:npm/' + quote(name, safe='/') + '@' + row['version'],
                    'properties': [{'name': 'syft:location:0:path', 'value': '/' + producer_lock}]})
        if build_pin:
            (candidate / 'source/pyproject.toml').write_text('[build-system]\nrequires=["builder>=1"]\n'
                '[tool.uv]\nrequire-build-hashes=true\nbuild-constraint-dependencies=['
                '{requirement="builder==1.2",hashes=["sha256:' + 'a' * 64 + '"]}]\n')
            (candidate / 'source/uv.lock').write_text('version=1\nrevision=5\npackage=[]\n'
                '[manifest]\nbuild-constraints=[{name="builder",specifier="==1.2",'
                'hashes=["sha256:' + 'a' * 64 + '"]}]\n')
        hashes = {str(path.relative_to(candidate)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in candidate.rglob('*') if path.is_file()}
        (candidate / 'manifest.json').write_text(json.dumps({'commit': 'a'*40, 'sha256': hashes}))
        status = {'candidate_commit': 'a'*40,
                  'candidate_manifest_sha256': hashlib.sha256((candidate / 'manifest.json').read_bytes()).hexdigest(),
                  'automated_checks_passed': code == 0, 'commands': [], 'unsafe_metadata': MARKER}
        for name in ('trivy-sbom', 'trivy-licenses', 'trivy-secrets', 'trivy-maven-runtime', 'trivy-maven-runtime-licenses', 'trivy-tool-backports', 'trivy-tool-backports-licenses'):
            count = secrets if name == 'trivy-secrets' else 0
            status['commands'].append({'name': name, 'returncode': code if name == 'trivy-secrets' else 0,
                                       'report_available': True,
                                       'finding_counts': {'Secrets': count, 'Vulnerabilities': 0, 'Licenses': 0}})
            report = {'SchemaVersion': 2, 'Results': [{'Target': MARKER, 'Secrets': [{'Match': MARKER}] if count else []}]}
            (scans / (name + '.json')).write_text(json.dumps(report))
        raw = scans / 'sbom-source.raw.cdx.json'
        raw.write_text(json.dumps({'bomFormat':'CycloneDX', 'specVersion': '1.6', 'components': raw_components, 'unsafe_metadata': MARKER}))
        (scans / 'trivy-secrets.log').write_text(MARKER)
        from python_build_catalog import prepare_python_build_catalog
        prepare_python_build_catalog(candidate / 'source', raw, scans)
        from tool_backport_catalog import prepare_tool_backport_catalog
        prepare_tool_backport_catalog(candidate / 'source', scans)
        from source_catalog import validate_source_catalog
        validate_source_catalog(candidate / 'source', scans / 'sbom.cdx.json', scans)
        status['commands'].append({'name':'syft','returncode':0,'recorded_npm_lock_coverage_passed':True,
                                   'recorded_source_lock_coverage_passed':True,
                                   'source_lock_coverage_sha256':hashlib.sha256((scans / 'source-lock-coverage.json').read_bytes()).hexdigest()})
        artifacts = scans / 'maven-runtime'
        relative = 'org/example/example/1.2/example-1.2.jar'
        jar = artifacts / relative
        jar.parent.mkdir(parents=True)
        jar.write_bytes(b'owned publication fixture')
        jar_hash = hashlib.sha256(jar.read_bytes()).hexdigest()
        manifest = {'returncode': 0, 'command': ['mvn', '-DoutputDirectory=' + str(artifacts)], 'pom_sha256': hashlib.sha256(pom.read_bytes()).hexdigest(),
                    'jar_sha256': {relative: jar_hash}, 'sha256': {relative: jar_hash}}
        (scans / 'maven-runtime-manifest.json').write_text(json.dumps(manifest))
        dependencies = scans / 'maven-runtime-dependencies.txt'
        dependencies.write_text('The following files have been resolved:\n   org.example:example:jar:1.2:compile\n')
        raw = scans / 'sbom-maven-runtime.raw.cdx.json'
        raw.write_text(json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'components': [
            {'type': 'library', 'name': 'example', 'version': '1.2', 'purl': 'pkg:maven/org.example/example@1.2',
             'bom-ref': 'package-1', 'properties': [{'name': 'syft:location:0:path', 'value': '/' + relative}]},
            {'type': 'file', 'name': str(jar), 'hashes': [{'alg': 'SHA-256', 'content': jar_hash}]}]}))
        from runtime_catalog import prepare_runtime_catalog
        prepare_runtime_catalog(artifacts, scans / 'maven-runtime-manifest.json', raw, scans, dependencies_path=dependencies)
        status['commands'].extend([{'name': 'maven-runtime', 'returncode': 0},
                                   {'name': 'syft-maven-runtime', 'returncode': 0,
                                    'recorded_runtime_coverage_passed': True,
                                    'runtime_lock_coverage_sha256': hashlib.sha256((scans / 'runtime-lock-coverage.json').read_bytes()).hexdigest()}])
        (scans / 'license-review.json').write_text('{}')
        (scans / 'THIRD_PARTY_NOTICES.review.md').write_text('Unapproved inventory')
        self.stamp_reports(scans, status)
        (scans / 'status.json').write_text(json.dumps(status))
        return candidate, scans

    def stamp_reports(self, scans, status):
        for command in status['commands']:
            name = command['name']
            if not name.startswith('trivy-'): continue
            target = 'source' if name == 'trivy-secrets' else 'sbom-tool-backports.cdx.json' if 'tool-backports' in name else 'sbom-maven-runtime.cdx.json' if 'maven-runtime' in name else 'sbom.cdx.json'
            path = scans / (name + '.json')
            report = json.loads(path.read_text())
            report.update(ArtifactType='filesystem' if name == 'trivy-secrets' else 'cyclonedx', ArtifactName='/original/' + target)
            path.write_text(json.dumps(report))
            command.update(scan_artifact_name=report['ArtifactName'], report_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                           input_sha256=status['candidate_manifest_sha256'] if name == 'trivy-secrets' else hashlib.sha256((scans / target).read_bytes()).hexdigest())

    def run_gate(self, base, candidate, scans):
        result = subprocess.run([sys.executable, str(SCRIPT), '--candidate', str(candidate), '--scans', str(scans),
                                 '--output', str(base / 'publication'), '--expected-commit', 'a'*40], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return base / 'publication'

    def test_partial_scan_set_cannot_publish_even_with_claimed_success(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.setup_inputs(base)
            status = json.loads((scans / 'status.json').read_text())
            status['commands'] = [item for item in status['commands'] if item['name'] in ('syft', 'trivy-secrets')]
            (scans / 'status.json').write_text(json.dumps(status))
            output = self.run_gate(base, candidate, scans)
            self.assertFalse(json.loads((output / 'public-status.json').read_text())['source_publication_allowed'])
            self.assertEqual([path.name for path in output.iterdir()], ['public-status.json'])

    def test_secret_fixture_is_not_published_on_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.setup_inputs(base, 1, 1)
            output = self.run_gate(base, candidate, scans)
            self.assertEqual([path.name for path in output.iterdir()], ['public-status.json'])
            safe = (output / 'public-status.json').read_text()
            self.assertNotIn(MARKER, safe)
            status = json.loads(safe)
            self.assertFalse(status['source_publication_allowed'])
            self.assertEqual(status['sha256']['source_archive'], hashlib.sha256(MARKER.encode()).hexdigest())
            self.assertFalse(status['release_ready'])

    def test_missing_malformed_stale_or_inconsistent_evidence_denies_publication(self):
        for mode in ['missing', 'malformed', 'stale_commit', 'reported_secret', 'mutated_input', 'rewritten_manifest', 'technical_failure', 'legacy_coverage', 'coverage_hash_mismatch', 'coverage_sbom_hash', 'coverage_lock_hash']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                base = Path(temp).resolve()
                candidate, scans = self.setup_inputs(base)
                if mode == 'missing':
                    (scans / 'trivy-secrets.json').unlink()
                elif mode == 'malformed':
                    (scans / 'status.json').write_text(MARKER)
                elif mode == 'stale_commit':
                    status = json.loads((scans / 'status.json').read_text())
                    status['candidate_commit'] = 'b'*40
                    (scans / 'status.json').write_text(json.dumps(status))
                elif mode == 'legacy_coverage':
                    status = json.loads((scans / 'status.json').read_text())
                    status['commands'] = [x for x in status['commands'] if x['name'] != 'syft']
                    (scans / 'status.json').write_text(json.dumps(status))
                    (scans / 'source-lock-coverage.json').unlink(missing_ok=True)
                elif mode.startswith('coverage_'):
                    coverage = json.loads((scans / 'source-lock-coverage.json').read_text())
                    if mode == 'coverage_lock_hash':
                        coverage['locks'][0]['sha256'] = '0'*64
                    else:
                        coverage['sbom_sha256'] = '0'*64
                    (scans / 'source-lock-coverage.json').write_text(json.dumps(coverage))
                    if mode != 'coverage_hash_mismatch':
                        status = json.loads((scans / 'status.json').read_text())
                        next(item for item in status['commands'] if item['name']=='syft')['source_lock_coverage_sha256'] = hashlib.sha256((scans / 'source-lock-coverage.json').read_bytes()).hexdigest()
                        (scans / 'status.json').write_text(json.dumps(status))
                elif mode == 'technical_failure':
                    status = json.loads((scans / 'status.json').read_text())
                    status['automated_checks_passed'] = False
                    (scans / 'status.json').write_text(json.dumps(status))
                elif mode == 'reported_secret':
                    (scans / 'trivy-secrets.json').write_text(json.dumps({'SchemaVersion':2,'Results':[{'Secrets':[{'Match':MARKER}]}]}))
                elif mode == 'rewritten_manifest':
                    (candidate / 'source/docs/input.txt').write_text('mutated ' + MARKER)
                    manifest = json.loads((candidate / 'manifest.json').read_text())
                    manifest['sha256']['source/docs/input.txt'] = hashlib.sha256(('mutated ' + MARKER).encode()).hexdigest()
                    (candidate / 'manifest.json').write_text(json.dumps(manifest))
                else:
                    (candidate / 'source/docs/input.txt').write_text('mutated ' + MARKER)
                output = self.run_gate(base, candidate, scans)
                self.assertEqual([path.name for path in output.iterdir()], ['public-status.json'])
                self.assertNotIn(MARKER, (output / 'public-status.json').read_text())

    def test_explicit_success_permits_fixed_artifacts_but_never_raw_secret_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.setup_inputs(base)
            output = self.run_gate(base, candidate, scans)
            self.assertTrue(json.loads((output / 'public-status.json').read_text())['source_publication_allowed'])
            self.assertTrue((output / 'candidate/source.tar.gz').exists())
            self.assertTrue((output / 'scans/sbom.cdx.json').exists())
            self.assertFalse((output / 'scans/trivy-secrets.json').exists())
            self.assertFalse((output / 'scans/trivy-secrets.log').exists())

    def test_backport_fixture_captures_drivers_and_full_producer_coverage(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.setup_inputs(base, backports=True)
            manifest = json.loads((candidate / 'manifest.json').read_bytes())
            proof = json.loads((scans / 'tool-backport-provenance.json').read_bytes())
            for name in ('scripts/dependencies/build-resolver.cjs', 'scripts/dependencies/build-forge.py'):
                expected = hashlib.sha256((SCRIPT.parents[2] / name).read_bytes()).hexdigest()
                self.assertEqual(hashlib.sha256((candidate / 'source' / name).read_bytes()).hexdigest(), expected)
                self.assertEqual(manifest['sha256']['source/' + name], expected)
                self.assertEqual(proof['input_sha256'][name], expected)
            producer_lock = 'tools/dependency-backports/node-forge/producer/package-lock.json'
            retained = json.loads((SCRIPT.parents[2] / producer_lock).read_bytes())
            expected_rows = [(name.rsplit('node_modules/', 1)[-1], row['version'])
                             for name, row in retained['packages'].items() if name]
            coverage = json.loads((scans / 'source-lock-coverage.json').read_bytes())
            producer = next(lock for lock in coverage['locks'] if lock['path'] == producer_lock)
            self.assertEqual(len(producer['records']), 85)
            self.assertCountEqual([(row['name'], row['version']) for row in producer['records']], expected_rows)
            self.assertTrue(all(row['cataloged'] for row in producer['records']))
            raw = json.loads((scans / 'sbom-source.raw.cdx.json').read_bytes())
            self.assertEqual(len(raw['components']), 85)
            self.assertEqual(raw['unsafe_metadata'], MARKER)

    def test_backport_catalog_and_both_bound_reports_are_staged(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.setup_inputs(base, backports=True)
            output = self.run_gate(base, candidate, scans)
            self.assertTrue(json.loads((output / 'public-status.json').read_text())['source_publication_allowed'])
            for name in ('sbom-tool-backports.cdx.json', 'tool-backport-provenance.json',
                         'trivy-tool-backports.json', 'trivy-tool-backports-licenses.json'):
                self.assertEqual((output / 'scans' / name).read_bytes(), (scans / name).read_bytes())

    def test_missing_or_changed_backport_catalog_and_positive_ancestry_deny(self):
        for mode in ('missing_catalog', 'missing_provenance', 'ancestry', 'classification', 'provenance',
                     'missing_vulnerability_command', 'missing_license_command', 'wrong_report_input', 'positive'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                base = Path(temp).resolve()
                candidate, scans = self.setup_inputs(base, backports=True)
                status = json.loads((scans / 'status.json').read_text())
                if mode.startswith('missing_'):
                    filename = {'missing_catalog': 'sbom-tool-backports.cdx.json',
                                'missing_provenance': 'tool-backport-provenance.json'}.get(mode)
                    if filename: (scans / filename).unlink()
                    else:
                        name = 'trivy-tool-backports' + ('-licenses' if mode == 'missing_license_command' else '')
                        status['commands'] = [c for c in status['commands'] if c['name'] != name]
                elif mode in ('ancestry', 'classification'):
                    path = scans / 'sbom-tool-backports.cdx.json'; document = json.loads(path.read_text())
                    component = next(c for c in document['components'] if c['purl'] == 'pkg:npm/braces@3.0.3')
                    if mode == 'ancestry': document['components'].remove(component)
                    else: component['scope'] = 'excluded'
                    path.write_text(json.dumps(document))
                    self.stamp_reports(scans, status)  # Updated report hashes cannot bypass reconstruction.
                elif mode == 'provenance':
                    path = scans / 'tool-backport-provenance.json'; document = json.loads(path.read_text())
                    document['advisory_closure_verified'] = True; path.write_text(json.dumps(document))
                elif mode == 'wrong_report_input':
                    next(c for c in status['commands'] if c['name'] == 'trivy-tool-backports')['input_sha256'] = hashlib.sha256((scans / 'sbom.cdx.json').read_bytes()).hexdigest()
                else:
                    path = scans / 'trivy-tool-backports.json'
                    path.write_text(json.dumps({'SchemaVersion': 2, 'Results': [{'Vulnerabilities': [
                        {'VulnerabilityID': 'GHSA-vfj7-8cjw-p6xm'}, {'VulnerabilityID': 'GHSA-86w9-cpqp-85rv'}]}]}))
                    target = next(c for c in status['commands'] if c['name'] == 'trivy-tool-backports')
                    target['finding_counts']['Vulnerabilities'] = 2; target['returncode'] = 1
                    status['automated_checks_passed'] = False; self.stamp_reports(scans, status)
                (scans / 'status.json').write_text(json.dumps(status))
                output = self.run_gate(base, candidate, scans)
                safe = json.loads((output / 'public-status.json').read_text())
                self.assertFalse(safe['source_publication_allowed'])
                self.assertFalse(safe['release_ready'])
                if mode == 'positive': self.assertEqual(safe['reason'], 'vulnerability_findings')
                self.assertEqual([p.name for p in output.iterdir()], ['public-status.json'])

    def test_late_and_staged_backport_evidence_mutations_are_denied(self):
        spec = importlib.util.spec_from_file_location('publication_gate_tool_mutation', SCRIPT)
        gate = importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)
        for mode in ('late', 'staged'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                base = Path(temp).resolve(); candidate, scans = self.setup_inputs(base, backports=True)
                if mode == 'late':
                    original = gate.validate_source_catalog
                    def change_after_validation(*args):
                        result = original(*args); (scans / 'tool-backport-provenance.json').write_text('{}'); return result
                    context = patch.object(gate, 'validate_source_catalog', side_effect=change_after_validation)
                else:
                    original = gate.shutil.copyfile
                    def change_copy(source, destination):
                        result = original(source, destination)
                        if Path(destination).name == 'tool-backport-provenance.json': Path(destination).write_text('{}')
                        return result
                    context = patch.object(gate.shutil, 'copyfile', side_effect=change_copy)
                with context: safe = gate.stage_publication(candidate, scans, base / 'publication', 'a' * 40)
                self.assertFalse(safe['source_publication_allowed'])
                self.assertEqual([p.name for p in (base / 'publication').iterdir()], ['public-status.json'])

    def test_declared_build_provenance_is_staged_with_bound_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.setup_inputs(base, build_pin=True)
            output = self.run_gate(base, candidate, scans)
            safe = json.loads((output / 'public-status.json').read_text())
            self.assertTrue(safe['source_publication_allowed'])
            coverage = json.loads((output / 'scans/source-lock-coverage.json').read_text())
            for filename, field in [('sbom-source.raw.cdx.json', 'python_build_raw_sbom_sha256'),
                                    ('python-build-catalog-overlay.json', 'python_build_overlay_sha256')]:
                staged = output / 'scans' / filename
                self.assertTrue(staged.is_file())
                self.assertEqual(staged.read_bytes(), (scans / filename).read_bytes())
                self.assertEqual(hashlib.sha256(staged.read_bytes()).hexdigest(), coverage[field])

    def test_late_build_provenance_mutation_is_denied(self):
        spec = importlib.util.spec_from_file_location('publication_gate_build_mutation', SCRIPT)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        for filename in ('sbom-source.raw.cdx.json', 'python-build-catalog-overlay.json'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temp:
                base = Path(temp).resolve()
                candidate, scans = self.setup_inputs(base, build_pin=True)
                original = gate.validate_source_catalog
                def validate_then_mutate(*args):
                    result = original(*args)
                    (scans / filename).write_text('{}')
                    return result
                with patch.object(gate, 'validate_source_catalog', side_effect=validate_then_mutate):
                    safe = gate.stage_publication(candidate, scans, base / 'publication', 'a' * 40)
                self.assertFalse(safe['source_publication_allowed'])
                self.assertEqual([p.name for p in (base / 'publication').iterdir()], ['public-status.json'])

    def test_zero_pin_pipeline_still_requires_both_provenance_files(self):
        for missing in (None, 'sbom-source.raw.cdx.json', 'python-build-catalog-overlay.json'):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temp:
                base = Path(temp).resolve()
                candidate, scans = self.setup_inputs(base)
                self.assertTrue((scans / 'python-build-catalog-overlay.json').is_file())
                if missing:
                    (scans / missing).unlink()
                output = self.run_gate(base, candidate, scans)
                safe = json.loads((output / 'public-status.json').read_text())
                self.assertEqual(safe['source_publication_allowed'], missing is None)
                if missing is None:
                    self.assertTrue((output / 'scans/sbom-source.raw.cdx.json').is_file())
                    self.assertTrue((output / 'scans/python-build-catalog-overlay.json').is_file())

    def test_corrupted_staged_build_provenance_is_denied(self):
        spec = importlib.util.spec_from_file_location('publication_gate_build_copy', SCRIPT)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        for filename in ('sbom-source.raw.cdx.json', 'python-build-catalog-overlay.json'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temp:
                base = Path(temp).resolve()
                candidate, scans = self.setup_inputs(base, build_pin=True)
                original = gate.shutil.copyfile
                def corrupt_copy(source, destination):
                    result = original(source, destination)
                    if Path(destination).name == filename:
                        Path(destination).write_text('{}')
                    return result
                with patch.object(gate.shutil, 'copyfile', side_effect=corrupt_copy):
                    safe = gate.stage_publication(candidate, scans, base / 'publication', 'a' * 40)
                self.assertFalse(safe['source_publication_allowed'])
                self.assertEqual([p.name for p in (base / 'publication').iterdir()], ['public-status.json'])

    def test_missing_checks_bad_catalog_or_raw_findings_are_not_publishable(self):
        for mode, reason in [('missing_vulnerability_check', 'scan_evidence_unverified'),
                             ('forged_zero_findings', 'scan_evidence_unverified'),
                             ('vulnerability', 'vulnerability_findings'),
                             ('legacy_source', 'source_coverage_unverified'),
                             ('runtime_coverage', 'runtime_coverage_unverified'),
                             ('runtime_jar_changed', 'runtime_coverage_unverified'),
                             ('runtime_raw_changed', 'runtime_coverage_unverified'),
                             ('wrong_pom', 'runtime_coverage_unverified')]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                base = Path(temp).resolve()
                candidate, scans = self.setup_inputs(base)
                status = json.loads((scans / 'status.json').read_text())
                if mode == 'missing_vulnerability_check':
                    status['commands'] = [c for c in status['commands'] if c['name'] != 'trivy-sbom']
                elif mode in ('forged_zero_findings', 'vulnerability'):
                    (scans / 'trivy-sbom.json').write_text(json.dumps({'SchemaVersion': 2, 'Results': [{'Vulnerabilities': [{'secret': MARKER}]}]}))
                    if mode == 'vulnerability':
                        next(c for c in status['commands'] if c['name'] == 'trivy-sbom')['finding_counts']['Vulnerabilities'] = 1
                        next(c for c in status['commands'] if c['name'] == 'trivy-sbom')['returncode'] = 1
                        status['automated_checks_passed'] = False
                elif mode == 'legacy_source':
                    next(c for c in status['commands'] if c['name'] == 'syft').pop('recorded_source_lock_coverage_passed')
                elif mode == 'runtime_coverage':
                    next(c for c in status['commands'] if c['name'] == 'syft-maven-runtime').pop('recorded_runtime_coverage_passed')
                elif mode == 'runtime_jar_changed':
                    next((scans / 'maven-runtime').rglob('*.jar')).write_bytes(b'mutated')
                elif mode == 'runtime_raw_changed':
                    (scans / 'sbom-maven-runtime.raw.cdx.json').write_text('{}')
                elif mode == 'wrong_pom':
                    manifest = json.loads((scans / 'maven-runtime-manifest.json').read_text())
                    manifest['pom_sha256'] = '0' * 64
                    (scans / 'maven-runtime-manifest.json').write_text(json.dumps(manifest))
                if mode in ('forged_zero_findings', 'vulnerability'):
                    self.stamp_reports(scans, status)
                (scans / 'status.json').write_text(json.dumps(status))
                output = self.run_gate(base, candidate, scans)
                safe = json.loads((output / 'public-status.json').read_text())
                self.assertEqual(safe['reason'], reason)
                self.assertFalse(safe['source_publication_allowed'])
                self.assertFalse(safe['release_ready'])
                self.assertNotIn(MARKER, (output / 'public-status.json').read_text())
                self.assertEqual([p.name for p in output.iterdir()], ['public-status.json'])

    def test_evidence_mutation_between_validation_and_pinning_denies_publication(self):
        spec = importlib.util.spec_from_file_location('publication_gate', SCRIPT)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.setup_inputs(base)
            original = gate.validate_runtime_catalog
            changed = False
            def validate_then_mutate(*args):
                nonlocal changed
                result = original(*args)
                if not changed:
                    changed = True
                    (scans / 'sbom.cdx.json').write_text('{"bomFormat":"CycloneDX","components":[],"unverified":"changed"}')
                return result
            with patch.object(gate, 'validate_runtime_catalog', side_effect=validate_then_mutate):
                result = gate.stage_publication(candidate, scans, base / 'publication', 'a' * 40)
            self.assertFalse(result['source_publication_allowed'])
            self.assertEqual([p.name for p in (base / 'publication').iterdir()], ['public-status.json'])

    def test_all_staged_candidate_inventories_must_match_verified_manifest(self):
        spec = importlib.util.spec_from_file_location('publication_gate', SCRIPT)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.setup_inputs(base)
            original = gate.shutil.copyfile
            def corrupt_copy(source, destination):
                result = original(source, destination)
                if Path(destination).name == 'licenses.json':
                    Path(destination).write_text('UNVERIFIED-COPY')
                return result
            with patch.object(gate.shutil, 'copyfile', side_effect=corrupt_copy):
                result = gate.stage_publication(candidate, scans, base / 'publication', 'a' * 40)
            self.assertFalse(result['source_publication_allowed'])
            self.assertEqual([p.name for p in (base / 'publication').iterdir()], ['public-status.json'])

    def test_zero_secret_report_cannot_replace_vulnerability_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.setup_inputs(base)
            for name in ('trivy-sbom', 'trivy-licenses', 'trivy-maven-runtime', 'trivy-maven-runtime-licenses', 'trivy-tool-backports', 'trivy-tool-backports-licenses'):
                (scans / (name + '.json')).write_bytes((scans / 'trivy-secrets.json').read_bytes())
            output = self.run_gate(base, candidate, scans)
            self.assertFalse(json.loads((output / 'public-status.json').read_text())['source_publication_allowed'])
            self.assertEqual([p.name for p in output.iterdir()], ['public-status.json'])

    def test_workflow_uploads_only_publication_staging(self):
        text = WORKFLOW.read_text()
        upload = text[text.index('uses: actions/upload-artifact@'):]
        self.assertIn('${{ runner.temp }}/appguard-publication', upload)
        self.assertNotIn('${{ runner.temp }}/appguard-candidate', upload)
        self.assertNotIn('${{ runner.temp }}/appguard-scans', upload)


if __name__ == '__main__':
    unittest.main()
