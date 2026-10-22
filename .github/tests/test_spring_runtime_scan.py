import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/qualification/scan_spring_runtime.py'
spec = importlib.util.spec_from_file_location('spring_runtime_scan', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RuntimeConsumptionTests(unittest.TestCase):
    def test_report_or_sbom_replacement_after_validation_invalidates_pinned_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            report = root / 'trivy-runtime.json'
            report.write_text('{"SchemaVersion":2,"Results":[]}')
            snapshot = module._read(report, True)
            module.verify_pins([snapshot])
            report.write_text('{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{}]}]}')
            with self.assertRaises(ValueError):
                module.verify_pins([snapshot])
            report.unlink()
            report.write_bytes(snapshot['bytes'])
            with self.assertRaises(ValueError):
                module.verify_pins([snapshot])

    def test_failed_qualification_and_changed_backend_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with zipfile.ZipFile(root / 'backend.jar', 'w') as archive:
                archive.writestr('example.class', b'compiled synthetic test')
            receipt = {'schema': 1, 'evidence_class': 'local_deployment',
                'profile': 'spring-mtls-store-forward-v1', 'cleanup': True, 'provenance_unchanged': True,
                'checks': dict.fromkeys(module.CHECKS, True),
                'sources': {'backend_jar': hashlib.sha256((root / 'backend.jar').read_bytes()).hexdigest()},
                'exampleclasses_sha256': {'example.class': hashlib.sha256(b'compiled synthetic test').hexdigest()}}
            def write():
                (root / 'receipt.json').write_text(json.dumps(receipt))
            write()
            module.validate_qualification(root)
            receipt['checks']['signed_fidelity'] = False
            write()
            with self.assertRaises(ValueError):
                module.validate_qualification(root)
            receipt['checks']['signed_fidelity'] = 1
            write()
            with self.assertRaises(ValueError):
                module.validate_qualification(root)
            receipt['checks']['signed_fidelity'] = True
            write()
            (root / 'backend.jar').write_bytes(b'replaced')
            with self.assertRaises(ValueError):
                module.validate_qualification(root)

    def test_missing_runtime_packages_cannot_be_a_zero_finding_success(self):
        coverage = {'records': [{'group': 'org.example', 'name': 'server', 'version': '1', 'classifier': None}]}
        with self.assertRaises(ValueError):
            module.validate_consumption({'Results': []}, coverage)

    def test_classifier_and_version_are_part_of_consumed_identity(self):
        record = {'group': 'org.example', 'name': 'server', 'version': '1', 'classifier': 'native'}
        for purl in ['pkg:maven/org.example/server@2?classifier=native', 'pkg:maven/org.example/server@1']:
            with self.subTest(purl=purl), self.assertRaises(ValueError):
                module.validate_consumption({'Results': [{'Packages': [{'Identifier': {'PURL': purl}}]}]}, {'records': [record]})
        module.validate_consumption({'Results': [{'Packages': [{'Identifier': {
            'PURL': 'pkg:maven/org.example/server@1?classifier=native&type=jar'}}]}]}, {'records': [record]})

    def test_untyped_package_and_malformed_result_do_not_satisfy_coverage(self):
        for value in [None, 'bad', [False], [{'Packages': [False]}], [{'Packages': [{'Name': 'server'}]}]]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.validate_consumption({'Results': value}, {'records': [
                    {'group': 'org.example', 'name': 'server', 'version': '1', 'classifier': None}]})


if __name__ == '__main__':
    unittest.main()
