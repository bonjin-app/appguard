"""A claimed aggregate success cannot replace the complete raw scan evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('publication_evidence', ROOT / 'publication_evidence.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def fixture(self, root):
        for name in ('sbom.cdx.json', 'sbom-maven-runtime.cdx.json', 'sbom-tool-backports.cdx.json'):
            (root / name).write_text('{"bomFormat":"CycloneDX","components":[]}')
        commands = []
        for name in ('maven-runtime', 'syft', 'syft-maven-runtime'):
            commands.append({'name': name, 'returncode': 0, 'report_available': True})
        for name in ('trivy-sbom', 'trivy-licenses', 'trivy-secrets', 'trivy-maven-runtime', 'trivy-maven-runtime-licenses', 'trivy-tool-backports', 'trivy-tool-backports-licenses'):
            commands.append({'name': name, 'returncode': 0, 'report_available': True,
                             'finding_counts': {'Vulnerabilities': 0, 'Secrets': 0, 'Licenses': 0}})
            (root / (name + '.json')).write_text(json.dumps({'SchemaVersion': 2, 'Results': []}))
        status = {'automated_checks_passed': True, 'candidate_manifest_sha256': 'a' * 64, 'commands': commands}
        self.stamp(root, status)
        return status

    def stamp(self, root, status):
        for command in status['commands']:
            name = command['name']
            if not name.startswith('trivy-'): continue
            target = 'source' if name == 'trivy-secrets' else 'sbom-tool-backports.cdx.json' if 'tool-backports' in name else 'sbom-maven-runtime.cdx.json' if 'maven-runtime' in name else 'sbom.cdx.json'
            path = root / (name + '.json')
            report = json.loads(path.read_text())
            report.update(ArtifactType='filesystem' if name == 'trivy-secrets' else 'cyclonedx', ArtifactName='/original/' + target)
            path.write_text(json.dumps(report))
            command.update(scan_artifact_name=report['ArtifactName'], report_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                           input_sha256=status['candidate_manifest_sha256'] if name == 'trivy-secrets' else hashlib.sha256((root / target).read_bytes()).hexdigest())

    def test_complete_zero_finding_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            commands = self.module.validate_scan_evidence(root, self.fixture(root))
            self.assertEqual(len(commands), 10)

    def test_omitted_backport_scans_cannot_be_a_complete_scan_set(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            status = self.fixture(root)
            status['commands'] = [c for c in status['commands'] if 'tool-backports' not in c['name']]
            with self.assertRaises(self.module.EvidenceDenied):
                self.module.validate_scan_evidence(root, status)

    def test_incomplete_ambiguous_or_forged_status_denied(self):
        for mode in ('missing', 'duplicate', 'unknown', 'boolean_code', 'boolean_count', 'nonzero', 'claimed_failure', 'missing_report', 'wrong_schema', 'null_results', 'bad_finding', 'count_mismatch'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                status = self.fixture(root)
                target = next(x for x in status['commands'] if x['name'] == 'trivy-sbom')
                if mode == 'missing': status['commands'].pop()
                elif mode == 'duplicate': status['commands'].append(target.copy())
                elif mode == 'unknown': target['name'] = 'unrecognized'
                elif mode == 'boolean_code': target['returncode'] = False
                elif mode == 'boolean_count': target['finding_counts']['Vulnerabilities'] = False
                elif mode == 'nonzero': target['returncode'] = 65
                elif mode == 'claimed_failure': status['automated_checks_passed'] = False
                elif mode == 'missing_report': (root / 'trivy-sbom.json').unlink()
                elif mode == 'wrong_schema': (root / 'trivy-sbom.json').write_text('{"SchemaVersion":true,"Results":[]}')
                elif mode == 'null_results': (root / 'trivy-sbom.json').write_text('{"SchemaVersion":2,"Results":null}')
                elif mode == 'bad_finding': (root / 'trivy-sbom.json').write_text('{"SchemaVersion":2,"Results":[{"Vulnerabilities":["forged"]}]}')
                elif mode == 'count_mismatch': target['finding_counts']['Vulnerabilities'] = 1
                with self.assertRaises(self.module.EvidenceDenied):
                    self.module.validate_scan_evidence(root, status)

    def test_actual_findings_deny_with_accurate_fixed_reason(self):
        for kind, name, reason in [('Secrets', 'trivy-secrets', 'secret_findings'),
                                   ('Vulnerabilities', 'trivy-sbom', 'vulnerability_findings'),
                                   ('Vulnerabilities', 'trivy-maven-runtime', 'vulnerability_findings'),
                                   ('Vulnerabilities', 'trivy-tool-backports', 'vulnerability_findings')]:
            with self.subTest(kind=kind, name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                status = self.fixture(root)
                target = next(x for x in status['commands'] if x['name'] == name)
                target['finding_counts'][kind] = 1
                target['returncode'] = 1
                status['automated_checks_passed'] = False
                (root / (name + '.json')).write_text(json.dumps({'SchemaVersion': 2, 'Results': [{kind: [{'private': 'NEVER_PUBLISH'}]}]}))
                self.stamp(root, status)
                with self.assertRaises(self.module.EvidenceDenied) as denied:
                    self.module.validate_scan_evidence(root, status)
                self.assertEqual(denied.exception.reason, reason)
                self.assertNotIn('NEVER_PUBLISH', str(denied.exception))

    def test_swapped_stale_or_wrong_target_reports_are_denied(self):
        for mode in ('swapped_role', 'wrong_target', 'stale_report', 'wrong_input'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                status = self.fixture(root)
                target = next(c for c in status['commands'] if c['name'] == 'trivy-sbom')
                path = root / 'trivy-sbom.json'
                if mode == 'swapped_role': path.write_bytes((root / 'trivy-secrets.json').read_bytes())
                elif mode == 'wrong_target':
                    report = json.loads(path.read_text()); report['ArtifactName'] = '/old/sbom-maven-runtime.cdx.json'; path.write_text(json.dumps(report))
                elif mode == 'stale_report': path.write_text(path.read_text() + ' ')
                elif mode == 'wrong_input': target['input_sha256'] = '0' * 64
                if mode in ('swapped_role', 'wrong_target'):
                    target['report_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                with self.assertRaises(self.module.EvidenceDenied):
                    self.module.validate_scan_evidence(root, status)

    def test_license_inventory_is_not_treated_as_approved_or_as_vulnerability(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            status = self.fixture(root)
            target = next(x for x in status['commands'] if x['name'] == 'trivy-licenses')
            target['finding_counts']['Licenses'] = 1
            (root / 'trivy-licenses.json').write_text('{"SchemaVersion":2,"Results":[{"Licenses":[{"Name":"Apache-2.0"}]}]}')
            self.stamp(root, status)
            self.assertEqual(len(self.module.validate_scan_evidence(root, status)), 10)

    def test_both_backport_reports_require_their_own_input_and_report_hash(self):
        for name in ('trivy-tool-backports', 'trivy-tool-backports-licenses'):
            for mode in ('source_input', 'stale_report', 'missing_report', 'source_artifact'):
                with self.subTest(name=name, mode=mode), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp).resolve(); status = self.fixture(root)
                    command = next(c for c in status['commands'] if c['name'] == name)
                    path = root / (name + '.json')
                    if mode == 'source_input': command['input_sha256'] = 'b' * 64
                    elif mode == 'stale_report': path.write_text(path.read_text() + ' ')
                    elif mode == 'missing_report': path.unlink()
                    else:
                        report = json.loads(path.read_text()); report['ArtifactName'] = '/original/sbom.cdx.json'
                        path.write_text(json.dumps(report)); command['scan_artifact_name'] = report['ArtifactName']
                        command['report_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                    with self.assertRaises(self.module.EvidenceDenied): self.module.validate_scan_evidence(root, status)


if __name__ == '__main__': unittest.main()
