"""A failed or unavailable secret scan must not publish source or metadata."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'publication_gate.py'
WORKFLOW = SCRIPT.parents[2] / '.github/workflows/release-readiness.yml'
MARKER = 'SYNTHETIC-SECRET-DO-NOT-PUBLISH-8b117a'


class PublicationTests(unittest.TestCase):
    def setup_inputs(self, base, code=0, secrets=0):
        candidate = base / 'candidate'
        scans = base / 'scans'
        (candidate / 'source/docs').mkdir(parents=True)
        scans.mkdir()
        (candidate / 'source/docs/input.txt').write_text(MARKER)
        (candidate / 'source.tar.gz').write_text(MARKER)
        (candidate / 'source/package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {'': {}}}))
        hashes = {str(path.relative_to(candidate)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in candidate.rglob('*') if path.is_file()}
        (candidate / 'manifest.json').write_text(json.dumps({'commit': 'a'*40, 'sha256': hashes}))
        status = {'candidate_commit': 'a'*40, 'candidate_manifest_sha256': hashlib.sha256((candidate / 'manifest.json').read_bytes()).hexdigest(), 'automated_checks_passed': code == 0,
                  'commands': [{'name': 'trivy-secrets', 'returncode': code, 'report_available': True,
                                'finding_counts': {'Secrets': secrets}}],
                  'unsafe_metadata': MARKER}
        (scans / 'status.json').write_text(json.dumps(status))
        report = {'SchemaVersion': 2, 'Results': [{'Target': MARKER, 'Secrets': [{'Match': MARKER}] if secrets else []}]}
        (scans / 'trivy-secrets.json').write_text(json.dumps(report))
        (scans / 'sbom.cdx.json').write_text(json.dumps({'bomFormat':'CycloneDX', 'unsafe_metadata': MARKER}))
        (scans / 'trivy-secrets.log').write_text(MARKER)
        spec = importlib.util.spec_from_file_location('publication_source_catalog', SCRIPT.parent / 'source_catalog.py')
        catalog = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(catalog)
        catalog.validate_source_catalog(candidate / 'source', scans / 'sbom.cdx.json', scans)
        status['commands'].append({'name':'syft','returncode':0,'recorded_npm_lock_coverage_passed':True,
                                   'source_lock_coverage_sha256':hashlib.sha256((scans / 'source-lock-coverage.json').read_bytes()).hexdigest()})
        (scans / 'status.json').write_text(json.dumps(status))
        return candidate, scans

    def run_gate(self, base, candidate, scans):
        result = subprocess.run([sys.executable, str(SCRIPT), '--candidate', str(candidate), '--scans', str(scans),
                                 '--output', str(base / 'publication'), '--expected-commit', 'a'*40], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return base / 'publication'

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

    def test_workflow_uploads_only_publication_staging(self):
        text = WORKFLOW.read_text()
        upload = text[text.index('uses: actions/upload-artifact@'):]
        self.assertIn('${{ runner.temp }}/appguard-publication', upload)
        self.assertNotIn('${{ runner.temp }}/appguard-candidate', upload)
        self.assertNotIn('${{ runner.temp }}/appguard-scans', upload)


if __name__ == '__main__':
    unittest.main()
