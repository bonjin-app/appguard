"""Readiness is derived from validated evidence, never approval-shaped JSON."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_publication_gate as publication_fixture

MARKER = publication_fixture.MARKER

SCRIPT = ROOT / 'assess.py'
COMMIT = 'a' * 40
CHECKS = ('signed_fidelity', 'replay_rejected', 'backend_bypass_rejected',
          'absolute_upload_deadline', 'malformed_framing_rejected',
          'backend_failure_bounded', 'healthy_recovery', 'owned_process_cleanup')


class AssessmentTests(unittest.TestCase):
    def fixture(self, base):
        helper = publication_fixture.PublicationTests()
        candidate, scans = helper.setup_inputs(base)
        manifest_path = candidate / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['schema'] = 1
        manifest_path.write_text(json.dumps(manifest))
        status = json.loads((scans / 'status.json').read_text())
        status['candidate_manifest_sha256'] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        helper.stamp_reports(scans, status)
        (scans / 'status.json').write_text(json.dumps(status))
        (scans / 'license-review.json').write_text(json.dumps({'schema': 1, 'approved': True, 'private': MARKER}))
        return candidate, scans

    def qualification(self, base):
        from datetime import datetime, timezone
        report = {'schema': 1, 'candidate_commit': COMMIT, 'evidence_class': 'local_deployment',
                  'profile': 'spring-mtls-store-forward-v1',
                  'observed_at': datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
                  'checks': dict.fromkeys(CHECKS, True),
                  'artifact_sha256': dict.fromkeys(('sdk_jar', 'example_pom', 'ingress_source'), 'b' * 64),
                  'limits': {'body_bytes': 1048576, 'upload_seconds': 0.8, 'backend_seconds': 2.0},
                  'cleanup': True, 'metrics': {'private': MARKER}, 'sources': {'private': MARKER}}
        path = base / 'qualification.json'
        path.write_text(json.dumps(report))
        return path

    def run_cli(self, base, candidate, scans, *extra, expected_code=0):
        result = subprocess.run([sys.executable, str(SCRIPT), '--candidate', str(candidate), '--scans', str(scans),
                                 '--output', str(base / 'assessment'), '--expected-commit', COMMIT, *map(str, extra)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, expected_code, result.stderr)
        self.assertNotIn(MARKER, result.stdout + result.stderr)
        self.assertNotIn(str(base), result.stdout + result.stderr)
        return json.loads((base / 'assessment/assessment.json').read_text())

    @staticmethod
    def gate(report, name):
        return next(gate for gate in report['gates'] if gate['id'] == name)

    def test_complete_real_scan_validation_passes_only_scan_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.fixture(base)
            report = self.run_cli(base, candidate, scans)
            self.assertEqual(self.gate(report, 'source_and_runtime_scans')['state'], 'pass')
            self.assertTrue(report['automated_scan_checks_passed'])
            self.assertFalse(report['release_ready'])
            self.assertIn('physical_devices_excluded', report['scope'])
            self.assertNotIn('physical_device', {g['id'] for g in report['gates']})
            for name in ('hosted_ci', 'consumer_container_graph', 'deployment_ingress',
                         'external_security_audit', 'license_notice_approval', 'release_publication_approval'):
                self.assertEqual(self.gate(report, name)['state'], 'pending_external')
            self.assertEqual([p.name for p in (base / 'assessment').iterdir()], ['assessment.json'])
            self.assertNotIn(MARKER, (base / 'assessment/assessment.json').read_text())
            self.assertEqual(report['sha256']['scanner_status'], hashlib.sha256((scans / 'status.json').read_bytes()).hexdigest())

    def test_unfixed_findings_remain_blocking_despite_approval_and_zero_flag_claims(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.fixture(base)
            status_path = scans / 'status.json'
            status = json.loads(status_path.read_text())
            report_path = scans / 'trivy-sbom.json'
            report = json.loads(report_path.read_text())
            report['Results'][0]['Vulnerabilities'] = [{'Severity': 'HIGH', 'private': MARKER}] * 2
            report_path.write_text(json.dumps(report))
            command = next(c for c in status['commands'] if c['name'] == 'trivy-sbom')
            command['finding_counts']['Vulnerabilities'] = 2
            command['returncode'] = 1
            status['automated_checks_passed'] = False
            publication_fixture.PublicationTests().stamp_reports(scans, status)
            status_path.write_text(json.dumps(status))
            output = self.run_cli(base, candidate, scans, '--qualification', self.qualification(base), '--check', expected_code=2)
            self.assertEqual(self.gate(output, 'source_and_runtime_scans')['reason'], 'vulnerability_findings')
            self.assertFalse(output['automated_scan_checks_passed'])
            self.assertFalse(output['release_ready'])

    def test_qualification_is_only_a_reference_even_when_all_checks_and_cleanup_are_true(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.fixture(base)
            qualification = self.qualification(base)
            report = self.run_cli(base, candidate, scans, '--qualification', qualification, '--check', expected_code=2)
            gate = self.gate(report, 'local_spring_ingress')
            self.assertEqual(gate['state'], 'referenced_unverified')
            self.assertEqual(gate['evidence_class'], 'local_deployment')
            self.assertFalse(report['release_ready'])
            self.assertEqual(report['sha256']['qualification_report'], hashlib.sha256(qualification.read_bytes()).hexdigest())
            self.assertNotIn(MARKER, (base / 'assessment/assessment.json').read_text())

    def test_parent_receipt_extensions_are_referenced_without_trusting_their_claims(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.fixture(base)
            qualification = self.qualification(base)
            receipt = json.loads(qualification.read_text())
            receipt.update(release_ready=True, limitations=[MARKER], owned_process_cleanup={MARKER: True},
                           exampleclasses_sha256='c' * 64, provenance_unchanged=True, source_matches_commit=True)
            qualification.write_text(json.dumps(receipt))
            report = self.run_cli(base, candidate, scans, '--qualification', qualification, '--check', expected_code=2)
            self.assertEqual(self.gate(report, 'local_spring_ingress')['state'], 'referenced_unverified')
            self.assertFalse(report['release_ready'])
            self.assertEqual(self.gate(report, 'external_security_audit')['state'], 'pending_external')
            self.assertNotIn(MARKER, (base / 'assessment/assessment.json').read_text())

    def test_invalid_qualification_cannot_upgrade_any_gate(self):
        for mode in ('schema_bool', 'commit', 'class', 'profile', 'time', 'checks_bool',
                     'checks_missing', 'hash', 'cleanup_int', 'nonfinite', 'limits_bool', 'approved'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                base = Path(temp).resolve()
                candidate, scans = self.fixture(base)
                qualification = self.qualification(base)
                report = json.loads(qualification.read_text())
                if mode == 'schema_bool': report['schema'] = True
                elif mode == 'commit': report['candidate_commit'] = 'b' * 40
                elif mode == 'class': report['evidence_class'] = 'external_audit'
                elif mode == 'profile': report['profile'] = 'approved-production'
                elif mode == 'time': report['observed_at'] = '2026-10-22T00:00:00+09:00'
                elif mode == 'checks_bool': report['checks']['signed_fidelity'] = 1
                elif mode == 'checks_missing': del report['checks']['signed_fidelity']
                elif mode == 'hash': report['artifact_sha256']['sdk_jar'] = MARKER
                elif mode == 'cleanup_int': report['cleanup'] = 1
                elif mode == 'nonfinite': report['limits']['upload_seconds'] = float('inf')
                elif mode == 'limits_bool': report['limits']['body_bytes'] = True
                elif mode == 'approved': report['approved'] = True
                qualification.write_text(json.dumps(report))
                output = self.run_cli(base, candidate, scans, '--qualification', qualification)
                self.assertEqual(self.gate(output, 'local_spring_ingress')['state'], 'blocked')
                self.assertTrue(output['automated_scan_checks_passed'])
                self.assertFalse(output['release_ready'])

    def test_duplicate_keys_and_boolean_schemas_fail_before_publication_validation(self):
        for name in ('status.json', 'trivy-sbom.json', 'source-lock-coverage.json', 'license-review.json', 'manifest.json'):
            for malformed in ('duplicate', 'boolean_schema'):
                with self.subTest(name=name, malformed=malformed), tempfile.TemporaryDirectory() as temp:
                    base = Path(temp).resolve()
                    candidate, scans = self.fixture(base)
                    path = candidate / name if name == 'manifest.json' else scans / name
                    original = path.read_text()
                    if malformed == 'duplicate':
                        key = next(iter(json.loads(original)))
                        path.write_text('{"' + key + '":null,' + original[1:])
                    else:
                        value = json.loads(original)
                        value['schema' if name != 'trivy-sbom.json' else 'SchemaVersion'] = True
                        path.write_text(json.dumps(value))
                    output = self.run_cli(base, candidate, scans)
                    self.assertEqual(self.gate(output, 'source_and_runtime_scans')['state'], 'blocked')
                    self.assertFalse(output['automated_scan_checks_passed'])

    def test_source_runtime_and_report_tampering_are_blocking(self):
        for kind in ('source', 'runtime', 'report'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                base = Path(temp).resolve()
                candidate, scans = self.fixture(base)
                path = (candidate / 'source/docs/input.txt' if kind == 'source' else
                        next((scans / 'maven-runtime').rglob('*.jar')) if kind == 'runtime' else
                        scans / 'trivy-sbom.json')
                path.write_bytes(b'{}')
                report = self.run_cli(base, candidate, scans)
                self.assertEqual(self.gate(report, 'source_and_runtime_scans')['state'], 'blocked')
                self.assertFalse(report['release_ready'])

    def test_mutation_during_verification_is_detected_on_original_inputs(self):
        import assess
        for mode in ('candidate', 'scan', 'runtime', 'qualification'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                base = Path(temp).resolve()
                candidate, scans = self.fixture(base)
                qualification = self.qualification(base)
                original_stage = assess.stage_publication
                def change_after_stage(*args, **kwargs):
                    result = original_stage(*args, **kwargs)
                    path = {'candidate': candidate / 'source/docs/input.txt',
                            'scan': scans / 'status.json',
                            'runtime': next((scans / 'maven-runtime').rglob('*.jar')),
                            'qualification': qualification}[mode]
                    path.write_bytes(path.read_bytes() + b' ')
                    return result
                with patch.object(assess, 'stage_publication', side_effect=change_after_stage):
                    report = assess.assess(candidate, scans, base / 'assessment', COMMIT, qualification=qualification)
                self.assertEqual(self.gate(report, 'source_and_runtime_scans')['state'], 'blocked')
                self.assertEqual(self.gate(report, 'source_and_runtime_scans')['reason'], 'inputs_changed')
                self.assertFalse(report['automated_scan_checks_passed'])
                self.assertFalse(report['release_ready'])

    def test_symlink_inputs_and_existing_or_nested_output_are_rejected_without_overwrite(self):
        import assess
        for mode in ('candidate', 'scan', 'file', 'qualification', 'output_parent', 'existing', 'nested'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                base = Path(temp).resolve()
                candidate, scans = self.fixture(base)
                output = base / 'assessment'
                qualification = None
                if mode == 'candidate':
                    alias = base / 'candidate-alias'; alias.symlink_to(candidate, target_is_directory=True); candidate = alias
                elif mode == 'scan':
                    alias = base / 'scans-alias'; alias.symlink_to(scans, target_is_directory=True); scans = alias
                elif mode == 'file':
                    path = scans / 'status.json'; path.rename(base / 'status.json'); path.symlink_to(base / 'status.json')
                elif mode == 'qualification':
                    real = self.qualification(base); qualification = base / 'qualification-alias'; qualification.symlink_to(real)
                elif mode == 'output_parent':
                    parent = base / 'alias'; parent.symlink_to(base, target_is_directory=True); output = parent / 'assessment'
                elif mode == 'existing':
                    output.mkdir(); (output / 'keep').write_text(MARKER)
                elif mode == 'nested': output = candidate / 'assessment'
                with self.assertRaises(ValueError):
                    assess.assess(candidate, scans, output, COMMIT, qualification=qualification)
                if mode == 'existing': self.assertEqual((output / 'keep').read_text(), MARKER)
                elif mode != 'output_parent': self.assertFalse(output.exists())

    def test_output_appearing_during_verification_is_preserved_with_fixed_error(self):
        import assess
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.fixture(base)
            output = base / 'assessment'
            original = assess.stage_publication
            def create_existing(*args, **kwargs):
                result = original(*args, **kwargs)
                output.mkdir()
                (output / 'keep').write_text(MARKER)
                return result
            with patch.object(assess, 'stage_publication', side_effect=create_existing):
                with self.assertRaises(assess.AssessmentError) as caught:
                    assess.assess(candidate, scans, output, COMMIT)
            self.assertEqual(str(caught.exception), 'assessment_unavailable')
            self.assertEqual((output / 'keep').read_text(), MARKER)
            self.assertEqual(list(base.glob('.assessment-*')), [])

    def test_bounds_and_nonfinite_json_are_denied_without_raw_error_output(self):
        import assess
        for data in ('{"unsafe":"' + MARKER + '","number":1e999}', '[' * 2000 + ']' * 2000):
            with self.subTest(data=data[:10]), tempfile.TemporaryDirectory() as temp:
                base = Path(temp).resolve()
                candidate, scans = self.fixture(base)
                (scans / 'status.json').write_text(data)
                report = self.run_cli(base, candidate, scans)
                self.assertEqual(self.gate(report, 'source_and_runtime_scans')['state'], 'blocked')
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.fixture(base)
            with patch.object(assess, 'MAX_JSON_BYTES', 32):
                report = assess.assess(candidate, scans, base / 'assessment', COMMIT)
            self.assertEqual(self.gate(report, 'source_and_runtime_scans')['state'], 'blocked')

    def test_file_replaced_by_fifo_during_open_cannot_block_assessment(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.fixture(base)
            code = """
import json, os, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import assess
candidate, scans, output = map(Path, sys.argv[2:])
target = scans / 'status.json'
original = assess.os.open
replaced = False
def race(path, flags, *args, **kwargs):
    global replaced
    if Path(path) == target and not replaced:
        replaced = True
        target.unlink()
        os.mkfifo(target)
    return original(path, flags, *args, **kwargs)
with patch.object(assess.os, 'open', side_effect=race):
    report = assess.assess(candidate, scans, output, 'a' * 40)
print(json.dumps({'release_ready': report['release_ready'], 'state': report['gates'][0]['state']}))
"""
            try:
                result = subprocess.run([sys.executable, '-c', code, str(ROOT), str(candidate), str(scans), str(base / 'assessment')],
                                        capture_output=True, text=True, timeout=3)
            except subprocess.TimeoutExpired:
                self.fail('A replaced evidence file blocked in open instead of being rejected')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {'release_ready': False, 'state': 'blocked'})

    def test_mobile_profile_records_provider_gate_without_physical_device_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            candidate, scans = self.fixture(base)
            report = self.run_cli(base, candidate, scans, '--profile', 'mobile-attested')
            self.assertEqual(self.gate(report, 'provider_account_validation')['state'], 'pending_external')
            self.assertFalse(report['release_ready'])

    def test_invalid_cli_arguments_do_not_echo_paths_tokens_or_errors(self):
        for args in (['--expected-commit', MARKER], ['--profile', MARKER], ['--unexpected-' + MARKER]):
            result = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(MARKER, result.stdout + result.stderr)
            self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
