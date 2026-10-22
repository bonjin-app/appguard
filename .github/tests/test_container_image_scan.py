import importlib.util
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
import sys
import contextlib
import io
import signal
import subprocess
import time
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/qualification/scan_container_images.py'
spec = importlib.util.spec_from_file_location('container_image_scan', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ContainerScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / 'qualification').mkdir()
        self.receipt = self.root / 'qualification/receipt.json'
        self.output = self.root / 'scan'
        self.ids = {role: 'sha256:' + str(i) * 64 for i, role in enumerate(module.ROLES, 1)}
        self.data = {'schema': 1, 'evidence_class': 'owned_container_deployment',
            'profile': 'spring-loopback-mtls-containers-v1', 'cleanup': True,
            'technical_verification': True, 'source_matches_commit': True,
            'candidate_commit': 'a' * 40, 'source_sha256': {'file': 'b' * 64},
            'checks': dict.fromkeys(module.CHECKS, True), 'containers': {'image_ids': self.ids}}
        self.write()

    def write(self):
        self.receipt.write_text(json.dumps(self.data))

    def runner(self, command, **kwargs):
        env = kwargs['env']
        self.assertEqual(env['DOCKER_CONTEXT'], 'default')
        self.assertNotIn('TRIVY_TOKEN', env)
        self.assertNotIn('DOCKER_HOST', env)
        if command[1:] == ['--context', 'default', 'context', 'inspect', 'default']:
            return 0, b'[{"Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock"}}}]'
        if command[1] == 'version':
            self.version_commands.append(command)
            raw = json.dumps({'Version': self.version}).encode()
            # Actual pinned Trivy logs configuration loading to stderr; the
            # bounded runner merges stderr with stdout. Quiet must suppress it.
            if self.version_noise and '--quiet' not in command:
                raw = b'2026-10-23T00:00:00Z\tINFO\tLoaded\tfile_path="/private/empty.json"\n' + raw
            return 0, raw
        for flag, directory, filename, schema in (
                ('--download-db-only', 'db', 'trivy.db', 2),
                ('--download-java-db-only', 'java-db', 'trivy-java.db', 1)):
            if flag not in command:
                continue
            self.downloads.append(flag)
            self.cache = Path(env['TRIVY_CACHE_DIR'])
            destination = self.cache / directory
            destination.mkdir(parents=True)
            (destination / filename).write_bytes(b'owned tiny database ' + directory.encode())
            metadata = dict(Version=schema, UpdatedAt='2026-10-22T00:00:00.123456789Z',
                NextUpdate='2026-10-24T00:00:00Z', DownloadedAt='2026-10-23T00:00:00Z')
            if self.database_change:
                self.database_change(destination, metadata)
            (destination / 'metadata.json').write_text(json.dumps(metadata))
            return 0, b'private setup output SECRET'
        self.assertEqual(command[1], 'image')
        self.commands.append(command)
        self.assertEqual(command[-1], self.ids[module.ROLES[self.scans]])
        self.assertEqual(command[command.index('--image-src') + 1], 'docker')
        self.assertNotIn('--ignore-unfixed', command)
        report = self.publication.output.parent / self.publication.name / ('trivy-' + module.ROLES[self.scans] + '.json')
        self.assertEqual(command[command.index('--output') + 1], '/dev/fd/' + str(kwargs['report']))
        image = command[-1]
        value = {'SchemaVersion': 2, 'Trivy': {'Version': '0.76.1'}, 'ArtifactType': 'container_image', 'ArtifactName': image,
                 'Metadata': {'ImageID': image, 'OS': {'Family': 'alpine', 'Name': '3.22'}},
                 'Results': [{'Class': 'os-pkgs', 'Type': 'alpine',
                     'Packages': [{'Name': 'pkg', 'Version': '1.0'}]}]}
        if module.ROLES[self.scans] == 'gateway':
            value['Results'].append({'Class': 'lang-pkgs', 'Type': 'python-pkg', 'Packages': [
                {'Name': name, 'Version': '1.0', 'FilePath':
                 '/opt/appguard/.venv/lib/python3.11/site-packages/' + name + '-1.0.dist-info/METADATA'}
                for name in ('cryptography', 'redis', 'uvicorn', 'h11')]})
        elif module.ROLES[self.scans] == 'backend':
            names = ('io.appguard:appguard-spring-boot-starter', 'io.appguard.examples:spring-ingress-backend',
                'org.springframework.boot:spring-boot', 'org.springframework:spring-web',
                'org.springframework.security:spring-security-core', 'org.springframework.data:spring-data-redis',
                'io.lettuce:lettuce-core')
            value['Results'].append({'Class': 'lang-pkgs', 'Type': 'jar', 'Packages': [
                {'Name': name, 'Version': '1.0', 'FilePath': '/opt/appguard/backend.jar'
                 if 'examples' in name else '/opt/appguard/lib/' + name.split(':')[1] + '-1.0.jar'}
                for name in names]})
        code, raw = self.transform(value, report)
        report.write_bytes(raw if raw is not None else json.dumps(value).encode())
        self.scans += 1
        if self.mutate and self.scans == 2:
            (self.publication.output.parent / self.publication.name / 'trivy-gateway.json').write_text('{}')
        if self.integrity_change:
            self.integrity_change(self.scans)
        return code, b'private scanner output SECRET'

    def run_scan(self, transform=None, mutate=False, *, version='0.76.1', database_change=None, integrity_change=None,
                 version_noise=False):
        self.scans, self.mutate = 0, mutate
        self.version, self.database_change, self.integrity_change = version, database_change, integrity_change
        self.version_noise = version_noise
        self.downloads, self.commands, self.version_commands = [], [], []
        self.transform = transform or (lambda value, report: (0, None))
        original_enter = module.Publication.__enter__
        def enter(publication):
            result = original_enter(publication)
            self.publication = publication
            return result
        def install(name, state):
            self.tool = state / name
            self.tool.write_bytes(b'owned fake scanner executable')
            self.tool.chmod(0o700)
            return self.tool
        with patch.object(module.Publication, '__enter__', enter), \
                patch.object(module, 'install_tool', side_effect=install), \
                patch.object(module, 'bounded_command', side_effect=self.runner), \
                patch.dict(os.environ, {'TRIVY_TOKEN': 'SECRET', 'DOCKER_HOST': 'tcp://secret'}):
            return module.scan(self.receipt, self.output)

    def test_clean_scan_is_bound_and_private(self):
        result = self.run_scan()
        self.assertTrue(result['automated_checks_passed'])
        self.assertFalse(result['release_ready'])
        self.assertIsNone(result['secrets'])
        self.assertEqual(result['vulnerabilities'], 0)
        self.assertTrue(result['coverage_passed'])
        for field in ('coverage_complete', 'native_binary_coverage', 'complete_resolved_graph'):
            self.assertFalse(result[field])
        self.assertEqual(set(result['images']), set(module.ROLES))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_schema_two_identifies_scanner_and_both_frozen_databases(self):
        result = self.run_scan()
        self.assertEqual(result['schema'], 2)
        self.assertTrue(result['finding_details_complete'])
        scanner = result['scanner']
        self.assertEqual(set(scanner), {'name', 'version', 'platform', 'archive_sha256', 'executable_sha256'})
        self.assertEqual((scanner['name'], scanner['version']), ('trivy', '0.76.1'))
        self.assertIn(scanner['platform'], ('Linux-x86_64', 'Darwin-arm64'))
        self.assertEqual(scanner['executable_sha256'], hashlib.sha256(b'owned fake scanner executable').hexdigest())
        self.assertEqual(self.downloads, ['--download-db-only', '--download-java-db-only'])
        for role in module.ROLES:
            self.assertTrue(result['images'][role]['finding_details_complete'])
            self.assertEqual(result['images'][role]['findings'], [])
        for name, directory, schema in (('vulnerability', 'db', 2), ('java', 'java-db', 1)):
            row = result['databases'][name]
            self.assertEqual(set(row), {'schema', 'metadata_sha256', 'database_sha256', 'updated_at', 'next_update', 'downloaded_at'})
            self.assertEqual(row['schema'], schema)
            self.assertEqual(row['database_sha256'], hashlib.sha256(b'owned tiny database ' + directory.encode()).hexdigest())
            self.assertEqual(row['updated_at'], '2026-10-22T00:00:00.123456789Z')
        for command in self.commands:
            self.assertIn('--skip-db-update', command)
            self.assertIn('--skip-java-db-update', command)

    def test_full_projection_preserves_duplicate_unfixed_and_all_severity_rows(self):
        def findings(value, report):
            value['Results'][0].update(Target='/SECRET/os/path', Vulnerabilities=[
                dict(VulnerabilityID='CVE-2026-12345', PkgName='libpkg:amd64', InstalledVersion='1:2.0~rc1-1',
                    FixedVersion='1:2.0-2, 1:2.1-1', Severity='UNKNOWN', PkgID='SECRET@1', PkgPath='/SECRET/pkg'),
                dict(VulnerabilityID='CVE-2026-12345', PkgName='libpkg:amd64', InstalledVersion='1:2.0~rc1-1',
                    FixedVersion='1:2.0-2, 1:2.1-1', Severity='UNKNOWN', PkgID='SECRET@1', PkgPath='/SECRET/pkg'),
                dict(VulnerabilityID='GHSA-abcd-1234-efgh', PkgName='@scope/name', InstalledVersion='1.0+build',
                    Severity='LOW')])
            return 0, None
        result = self.run_scan(findings)
        self.assertEqual(result['vulnerabilities'], 9)
        self.assertEqual(result['reason'], 'findings_present')
        self.assertTrue(result['finding_details_complete'])
        rows = result['images']['gateway']['findings']
        self.assertEqual(len(rows), 3)
        self.assertEqual(set(rows[0]), {'vulnerability_id', 'package', 'installed_version', 'fixed_versions',
            'severity', 'source_class', 'package_type', 'occurrence_sha256'})
        self.assertEqual(rows[0]['fixed_versions'], ['1:2.0-2', '1:2.1-1'])
        self.assertEqual(rows[2]['fixed_versions'], [])
        self.assertNotEqual(rows[0]['occurrence_sha256'], rows[1]['occurrence_sha256'])
        self.assertNotIn('SECRET', json.dumps(result))

    def test_unprojectable_or_excess_findings_keep_every_count_and_false_details(self):
        valid = dict(VulnerabilityID='CVE-2026-1', PkgName='pkg', InstalledVersion='1.0', Severity='HIGH')
        for i, rows in enumerate(([valid, {}], [valid, None], [valid] * 1025)):
            self.output = self.root / ('partial' + str(i))
            def findings(value, report):
                value['Results'][0]['Vulnerabilities'] = rows
                return 0, None
            with self.subTest(count=len(rows)):
                result = self.run_scan(findings)
                self.assertEqual(result['vulnerabilities'], len(rows) * 3)
                self.assertEqual(result['reason'], 'findings_present')
                self.assertFalse(result['finding_details_complete'])
                self.assertTrue(all(row['findings'] == [] and row['finding_details_complete'] is False
                    for row in result['images'].values()))

    def test_wrong_version_or_database_setup_never_claims_complete_details(self):
        result = self.run_scan(version='9.9.9')
        self.assertFalse(result['finding_details_complete'])
        self.assertFalse(result['automated_checks_passed'])
        self.assertIsNone(result['scanner'])
        self.assertIsNone(result['databases'])
        self.assertEqual(self.scans, 0)
        for i, change in enumerate((lambda d, m: m.update(Version=True),
                lambda d, m: m.update(DownloadedAt='2026-10-21T00:00:00Z'),
                lambda d, m: m.update(NextUpdate=m['UpdatedAt']),
                lambda d, m: m.update(UpdatedAt='2026-02-30T00:00:00Z'))):
            self.output = self.root / ('setup' + str(i))
            with self.subTest(change=change):
                result = self.run_scan(database_change=change)
                self.assertEqual(result['reason'], 'container_scan_unverified')
                self.assertFalse(result['finding_details_complete'])
                self.assertIsNone(result['databases'])
                self.assertEqual(self.scans, 0)

    def test_database_and_executable_changes_invalidate_detail_provenance(self):
        for i, name in enumerate(('trivy', 'db/trivy.db', 'java-db/trivy-java.db', 'db/metadata.json')):
            self.output = self.root / ('integrity' + str(i))
            def change(scans):
                if scans == 1:
                    path = self.tool if name == 'trivy' else self.cache / name
                    path.write_bytes(path.read_bytes() + b' ')
            with self.subTest(name=name):
                result = self.run_scan(integrity_change=change)
                self.assertEqual(result['reason'], 'container_scan_unverified')
                self.assertFalse(result['finding_details_complete'])
                self.assertFalse(result['automated_checks_passed'])

    def test_projection_lexical_rejection_never_drops_occurrences(self):
        valid = dict(VulnerabilityID='CVE-2026-1', PkgName='pkg', InstalledVersion='1.0', Severity='CRITICAL')
        for key, invalid in (('VulnerabilityID', 'cve-2026-1'), ('PkgName', '/SECRET/pkg'),
                ('InstalledVersion', 'https://SECRET'), ('Severity', 'IMPORTANT'),
                ('FixedVersion', '1.0,,2.0'), ('FixedVersion', ','.join(['1.0'] * 33)),
                ('FixedVersion', '1' * 201)):
            document = {'SchemaVersion': 2, 'Results': [{'Class': 'lang-pkgs', 'Type': 'jar',
                'Vulnerabilities': [valid, dict(valid, **{key: invalid})]}]}
            with self.subTest(key=key, invalid=invalid):
                count, rows, complete = module.finding_details(document)
                self.assertEqual((count, rows, complete), (2, [], False))
        for source, package_type in (('secret', 'jar'), ('lang-pkgs', 'RAW/PATH')):
            count, rows, complete = module.finding_details({'SchemaVersion': 2,
                'Results': [{'Class': source, 'Type': package_type, 'Vulnerabilities': [valid]}]})
            self.assertEqual((count, rows, complete), (1, [], False))

    def test_occurrence_digest_binds_raw_location_and_indexes_without_emitting_them(self):
        raw = dict(VulnerabilityID='CVE-2026-1', PkgName='pkg', InstalledVersion='1.0',
                   Severity='MEDIUM', PkgID='PRIVATE-ID', PkgPath='/PRIVATE/path')
        def project(target, padding=False):
            results = [{'Class': 'os-pkgs', 'Type': 'alpine', 'Target': target, 'Vulnerabilities': [raw]}]
            if padding: results.insert(0, {'Vulnerabilities': []})
            return module.finding_details({'SchemaVersion': 2, 'Results': results})[1][0]
        original = project('/PRIVATE/target')
        self.assertNotEqual(original['occurrence_sha256'], project('/PRIVATE/changed')['occurrence_sha256'])
        self.assertNotEqual(original['occurrence_sha256'], project('/PRIVATE/target', True)['occurrence_sha256'])
        expected = json.dumps(dict(result_index=0, finding_index=0, target='/PRIVATE/target',
            pkg_id='PRIVATE-ID', pkg_path='/PRIVATE/path'), sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(original['occurrence_sha256'], hashlib.sha256(expected).hexdigest())
        self.assertNotIn('PRIVATE', json.dumps(original))

    def test_status_envelope_degrades_details_without_erasing_counts(self):
        fixed = ','.join('1.' + '2' * 14 for _ in range(32))
        row = dict(VulnerabilityID='CVE-2026-1', PkgName='pkg', InstalledVersion='1.0',
                   FixedVersion=fixed, Severity='LOW')
        def findings(value, report):
            value['Results'][0]['Vulnerabilities'] = [row] * 1024
            return 0, None
        result = self.run_scan(findings)
        self.assertEqual(result['vulnerabilities'], 3072)
        self.assertEqual(result['reason'], 'findings_present')
        self.assertFalse(result['finding_details_complete'])
        self.assertFalse(result['automated_checks_passed'])
        self.assertTrue(all(row['vulnerabilities'] == 1024 and row['findings'] == []
            and row['finding_details_complete'] is False for row in result['images'].values()))
        self.assertLessEqual((self.output / 'status.json').stat().st_size, 2 * 1024 * 1024)

    def test_nanosecond_metadata_order_and_utc_calendar_validation(self):
        before = module.database_time('2026-10-23T00:00:00.123456780Z')
        after = module.database_time('2026-10-23T00:00:00.123456789Z')
        self.assertLess(before, after)
        for value in ('2026-02-30T00:00:00Z', '2026-10-23T00:00:00+00:00',
                '2026-10-23T00:00:00.1234567890Z', None, True):
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                module.database_time(value)
        def backwards(destination, metadata):
            metadata.update(UpdatedAt='2026-10-23T00:00:00.123456789Z',
                DownloadedAt='2026-10-23T00:00:00.123456780Z')
        self.assertEqual(self.run_scan(database_change=backwards)['reason'], 'container_scan_unverified')

    def test_streaming_file_bounds_regular_files_and_stability(self):
        regular = self.root / 'tiny.db'; regular.write_bytes(b'1234567')
        self.assertEqual(module.file_identity(regular, 7)['sha256'], hashlib.sha256(b'1234567').hexdigest())
        with self.assertRaises(ValueError): module.file_identity(regular, 6)
        link = self.root / 'link.db'; link.symlink_to(regular)
        with self.assertRaises(ValueError): module.file_identity(link, 7)
        fifo = self.root / 'fifo.db'; os.mkfifo(fifo)
        with self.assertRaises(ValueError): module.file_identity(fifo, 7)
        oversized = self.root / 'oversized.db'
        with oversized.open('wb') as stream: stream.truncate(4 * 1024 ** 3 + 1)
        with self.assertRaises(ValueError): module.file_identity(oversized, module.MAX_DATABASE)
        metadata = self.root / 'oversized.json'; metadata.write_bytes(b'x' * (64 * 1024 + 1))
        with self.assertRaises(ValueError): module.file_identity(metadata, module.MAX_METADATA, keep=True)
        pin = module.file_identity(regular, 7)
        regular.write_bytes(b'7654321')
        with self.assertRaises(ValueError): module.verify_files({regular: (7, pin)})

    def test_late_integrity_mutation_cannot_publish_complete_finding_status(self):
        original = module.Publication.publish
        def mutate(publication):
            original(publication)
            (self.cache / 'java-db/trivy-java.db').write_bytes(b'changed owned fixture')
        with patch.object(module.Publication, 'publish', mutate), self.assertRaises(ValueError):
            self.run_scan()
        self.assertFalse(self.output.exists())

    def test_unexpected_exit_and_partial_reports_have_false_top_details(self):
        result = self.run_scan(lambda v, p: (2, None))
        self.assertFalse(result['finding_details_complete'])
        self.assertEqual(result['reason'], 'container_scan_unverified')
        self.assertEqual(result['vulnerabilities'], 0)
        self.output = self.root / 'partial-images'
        def incomplete(value, report):
            return (0, b'{}') if self.scans == 1 else (0, None)
        result = self.run_scan(incomplete)
        self.assertEqual(set(result['images']), {'gateway'})
        self.assertIsNone(result['vulnerabilities'])
        self.assertFalse(result['finding_details_complete'])

    def test_returned_scanner_statuses_satisfy_independent_producer_contract(self):
        producer_spec = importlib.util.spec_from_file_location('independent_binding',
            SCRIPT.with_name('bind_container_evidence.py'))
        producer = importlib.util.module_from_spec(producer_spec)
        producer_spec.loader.exec_module(producer)
        def positive(value, report):
            value['Results'][0]['Vulnerabilities'] = [dict(VulnerabilityID='CVE-2026-1',
                PkgName='pkg', InstalledVersion='1.0', Severity='HIGH')]
            return 0, None
        def invalid(value, report):
            value['Results'][0]['Vulnerabilities'] = [{}]
            return 0, None
        def inventory_missing(value, report):
            value['Results'][0]['Packages'] = []
            return 0, None
        cases = ({}, {'transform': positive}, {'transform': invalid},
            {'database_change': lambda d, m: m.update(Version=False)},
            {'transform': lambda v, p: (2, None)}, {'transform': inventory_missing})
        for i, options in enumerate(cases):
            self.output = self.root / ('producer-contract' + str(i))
            with self.subTest(case=i):
                result = self.run_scan(**options)
                before = json.dumps(result, sort_keys=True)
                producer.STATUS(result)
                self.assertEqual(json.dumps(result, sort_keys=True), before)

    def test_every_image_report_must_identify_the_exact_scanner_version(self):
        for i, trivy in enumerate((None, {}, {'Version': '9.9.9'}, {'Version': True})):
            self.output = self.root / ('report-version' + str(i))
            def mismatch(value, report):
                if trivy is None: value.pop('Trivy')
                else: value['Trivy'] = trivy
                return 0, None
            with self.subTest(trivy=trivy):
                result = self.run_scan(mismatch)
                self.assertEqual(result['reason'], 'container_scan_unverified')
                self.assertFalse(result['automated_checks_passed'])
                self.assertFalse(result['finding_details_complete'])

    def test_version_command_suppresses_observed_config_log_and_keeps_strict_json(self):
        self.assertTrue(self.run_scan(version_noise=True)['automated_checks_passed'])
        self.assertIn('--quiet', self.version_commands[0])
        self.output = self.root / 'wrong-quiet-version'
        result = self.run_scan(version_noise=True, version='9.9.9')
        self.assertEqual(result['reason'], 'container_scan_unverified')
        self.assertIsNone(result['scanner'])
        original = self.runner
        def malformed_version(command, **kwargs):
            if len(command) > 1 and command[1] == 'version':
                return 0, b'arbitrary unexpected bytes\n{"Version":"0.76.1"}\n'
            return original(command, **kwargs)
        self.output = self.root / 'unexpected-version-prefix'
        with patch.object(self, 'runner', side_effect=malformed_version):
            result = self.run_scan()
        self.assertEqual(result['reason'], 'container_scan_unverified')
        self.assertIsNone(result['scanner'])

    def test_every_finding_counts_even_with_zero_exit(self):
        def finding(value, report):
            value['Results'][0]['Vulnerabilities'] = [{'Severity': 'UNKNOWN'}, {'Severity': 'LOW'}]
            return 0, None
        result = self.run_scan(finding)
        self.assertFalse(result['automated_checks_passed'])
        self.assertEqual(result['vulnerabilities'], 6)
        self.assertEqual(result['reason'], 'findings_present')

    def test_unknown_exit_or_malformed_or_wrong_image_never_pass(self):
        def mismatch(value, report):
            value['Metadata']['ImageID'] = self.ids['backend']
            return 0, None
        for transform in (lambda v, p: (2, None), lambda v, p: (0, b'{"x":NaN}'),
                          lambda v, p: (0, b'{"x":1,"x":2}'), mismatch,
                          lambda v, p: (0, b'{"SchemaVersion":true,"Results":[]}')):
            with self.subTest(transform=transform):
                self.output = self.root / ('scan' + str(len(list(self.root.iterdir()))))
                self.assertFalse(self.run_scan(transform)['automated_checks_passed'])

    def test_failed_receipt_rejected_before_scanner(self):
        for field in ('technical_verification', 'source_matches_commit', 'cleanup'):
            self.data[field] = 1
            self.write()
            with self.assertRaises(ValueError):
                module.validate_receipt(self.receipt)
            self.data[field] = True
        self.data['checks']['signed_fidelity'] = False
        self.write()
        with self.assertRaises(ValueError):
            module.validate_receipt(self.receipt)

    def test_report_mutation_invalidates_earlier_pin(self):
        self.assertFalse(self.run_scan(mutate=True)['automated_checks_passed'])

    def test_receipt_mutation_invalidates_pin(self):
        def mutate(value, report):
            self.receipt.write_text(json.dumps(self.data) + ' ')
            return 0, None
        self.assertFalse(self.run_scan(mutate)['automated_checks_passed'])

    def test_symlink_fifo_and_report_replacement_rejected(self):
        original = self.root / 'original'
        self.receipt.rename(original)
        self.receipt.symlink_to(original)
        with self.assertRaises(ValueError):
            module.validate_receipt(self.receipt)
        self.receipt.unlink()
        os.mkfifo(self.receipt)
        with self.assertRaises(ValueError):
            module.validate_receipt(self.receipt)
        self.receipt.unlink()
        original.rename(self.receipt)
        def replace(value, report):
            report.unlink()
            report.symlink_to(original)
            return 0, None
        self.assertFalse(self.run_scan(replace)['automated_checks_passed'])

    def test_cancellation_returns_fixed_failed_status(self):
        with patch.object(module, 'bounded_command', side_effect=KeyboardInterrupt):
            result = module.scan(self.receipt, self.output)
        self.assertFalse(result['automated_checks_passed'])
        self.assertEqual(result['reason'], 'container_scan_unverified')

    def test_cli_invalid_input_redacts_and_exits_two(self):
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            code = module.main(['--receipt', str(self.root / 'SECRET'), '--output', str(self.output)])
        self.assertEqual(code, 2)
        result = json.loads(captured.getvalue())
        self.assertFalse(result['automated_checks_passed'])
        self.assertIsNone(result['secrets'])
        self.assertNotIn('SECRET', captured.getvalue())

    def test_unknown_keys_and_nonimmutable_image_rejected(self):
        for value in ('ubuntu:latest', 'https://SECRET', 'sha256:' + 'a' * 63, 42):
            self.data['containers']['image_ids']['gateway'] = value
            self.write()
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.validate_receipt(self.receipt)

    def test_report_fifo_or_missing_rejected(self):
        def fifo(value, report):
            report.unlink()
            os.mkfifo(report)
            raise OSError('SECRET')
        self.assertFalse(self.run_scan(fifo)['automated_checks_passed'])

    def test_real_subprocess_output_and_timeout_are_bounded(self):
        for source, timeout in [('import time; time.sleep(5)', .1),
                                ('import os; os.write(1, b"x" * 2200000)', 5)]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                module.bounded_command([sys.executable, '-c', source], env={}, cwd=self.root, timeout=timeout)

    def test_actual_subprocess_small_output(self):
        code, output = module.bounded_command([sys.executable, '-c', 'print("ok")'],
                                              env={}, cwd=self.root)
        self.assertEqual((code, output), (0, b'ok\n'))

    def test_commit_lengths_are_exact(self):
        for length in (39, 40, 41, 63, 64, 65):
            self.data['candidate_commit'] = 'a' * length
            self.write()
            if length in (40, 64):
                module.validate_receipt(self.receipt)
            else:
                with self.subTest(length=length), self.assertRaises(ValueError):
                    module.validate_receipt(self.receipt)

    def test_empty_or_unproven_package_inventory_fails(self):
        def empty(value):
            value['Results'] = []
        def no_os(value):
            value['Metadata'].pop('OS')
        def no_packages(value):
            value['Results'][0]['Packages'] = []
        def no_version(value):
            value['Results'][0]['Packages'][0].pop('Version')
        def wrong_family(value):
            value['Results'][0]['Type'] = 'unknown'
        for i, change in enumerate((empty, no_os, no_packages, no_version, wrong_family)):
            self.output = self.root / ('inventory' + str(i))
            def transform(value, report):
                change(value)
                return 0, None
            with self.subTest(change=change):
                self.assertFalse(self.run_scan(transform)['automated_checks_passed'])

    def test_findings_and_application_inventory_are_independent(self):
        def only_os(value, report):
            value['Results'] = value['Results'][:1]
            value['Results'][0]['Vulnerabilities'] = [{}]
            return 0, None
        result = self.run_scan(only_os)
        self.assertEqual(result['vulnerabilities'], 3)
        self.assertFalse(result['coverage_passed'])
        self.assertFalse(result['automated_checks_passed'])
        self.assertEqual(result['reason'], 'findings_present')

    def test_base_python_metadata_cannot_satisfy_gateway_application_inventory(self):
        def wrong_path(value, report):
            for result in value['Results']:
                for package in result.get('Packages', []):
                    if 'FilePath' in package:
                        package['FilePath'] = package['FilePath'].replace('/opt/appguard/.venv', '/usr/local')
            return 0, None
        result = self.run_scan(wrong_path)
        self.assertFalse(result['images']['gateway']['coverage']['application_inventory'])
        self.assertFalse(result['automated_checks_passed'])
        self.assertEqual(result['vulnerabilities'], 0)
        self.assertEqual(result['reason'], 'inventory_unverified')

    def test_jar_results_support_per_file_target(self):
        def target_variant(value, report):
            for result in list(value['Results']):
                if result.get('Type') == 'jar':
                    packages = result.pop('Packages')
                    result['Packages'] = []
                    value['Results'].extend({'Class': 'lang-pkgs', 'Type': 'jar',
                        'Target': package.pop('FilePath'), 'Packages': [package]} for package in packages)
            return 0, None
        self.assertTrue(self.run_scan(target_variant)['automated_checks_passed'])

    def test_parser_errors_never_echo_private_arguments(self):
        for args in (['--private-SECRET'], ['--docker-context', 'SECRET'],
                     ['--receipt', 'SECRET'], ['--receipt', 'SECRET', '--output']):
            with contextlib.redirect_stdout(io.StringIO()) as stdout, \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                code = module.main(args)
            self.assertEqual(code, 2)
            self.assertNotIn('SECRET', stdout.getvalue() + stderr.getvalue())
            self.assertFalse(json.loads(stdout.getvalue())['automated_checks_passed'])

    def test_publication_collision_preserves_existing_directory(self):
        original = module.Publication.publish
        def collide(publication):
            self.output.mkdir()
            (self.output / 'keep').write_text('preserved')
            original(publication)
        with patch.object(module.Publication, 'publish', collide), self.assertRaises(ValueError):
            self.run_scan()
        self.assertEqual((self.output / 'keep').read_text(), 'preserved')
        self.assertEqual(set(path.name for path in self.output.iterdir()), {'keep'})
        self.assertFalse(list(self.root.glob('.appguard-image-*')))

    def test_output_ancestor_swap_after_verification_cannot_redirect_writes(self):
        destination = self.root / 'destination'
        destination.mkdir()
        existing = self.root / 'existing'
        existing.mkdir()
        (existing / 'keep').write_text('preserved')
        self.output = destination / 'scan'
        original_write = module.Publication.write
        def swap_on_status(publication, name, data):
            if name == 'status.json':
                destination.rename(self.root / 'moved')
                destination.symlink_to(existing, target_is_directory=True)
            original_write(publication, name, data)
        with patch.object(module.Publication, 'write', swap_on_status), self.assertRaises(ValueError):
            self.run_scan()
        self.assertEqual(set(path.name for path in existing.iterdir()), {'keep'})
        self.assertEqual((existing / 'keep').read_text(), 'preserved')
        self.assertEqual(list((self.root / 'moved').iterdir()), [])

    def test_parent_swap_during_atomic_publish_rolls_back_owned_tree(self):
        destination = self.root / 'destination'
        destination.mkdir()
        existing = self.root / 'existing'
        existing.mkdir()
        self.output = destination / 'scan'
        original = module.Publication.check_parent
        calls = 0
        def check(publication):
            nonlocal calls
            calls += 1
            if calls == 3:
                destination.rename(self.root / 'moved')
                destination.symlink_to(existing, target_is_directory=True)
            original(publication)
        with patch.object(module.Publication, 'check_parent', check), self.assertRaises(ValueError):
            self.run_scan()
        self.assertEqual(list(existing.iterdir()), [])
        self.assertEqual(list((self.root / 'moved').iterdir()), [])

    def test_report_mutation_during_publication_rolls_back(self):
        original = module.Publication.publish
        def publish(publication):
            original(publication)
            (self.output / 'trivy-gateway.json').write_text('{}')
        with patch.object(module.Publication, 'publish', publish), self.assertRaises(ValueError):
            self.run_scan()
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob('.appguard-image-*')))

    def test_stage_entry_swap_during_rename_cannot_publish_success(self):
        existing = self.root / 'existing'
        existing.mkdir()
        real_libc = module.ctypes.CDLL(None, use_errno=True)
        real_rename = real_libc.renameat2 if sys.platform == 'linux' else real_libc.renameatx_np
        real_rename.argtypes = [module.ctypes.c_int, module.ctypes.c_char_p,
            module.ctypes.c_int, module.ctypes.c_char_p, module.ctypes.c_uint]
        real_rename.restype = module.ctypes.c_int
        def swapped(parent_fd, source, target_fd, target, flags):
            os.rename(os.fsdecode(source), 'moved-stage', src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.symlink(str(existing), os.fsdecode(source), dir_fd=parent_fd)
            return real_rename(parent_fd, source, target_fd, target, flags)
        class Library:
            renameat2 = staticmethod(swapped)
            renameatx_np = staticmethod(swapped)
        with patch.object(module.ctypes, 'CDLL', return_value=Library()), self.assertRaises(ValueError):
            self.run_scan()
        self.assertTrue(self.output.is_symlink())
        self.assertEqual(list(existing.iterdir()), [])
        self.assertEqual(list((self.root / 'moved-stage').iterdir()), [])

    def test_report_descriptor_is_available_to_child(self):
        with module.Publication(self.output) as publication:
            with publication.report('report.json') as descriptor:
                code, _ = module.bounded_command([sys.executable, '-c',
                    'import pathlib,sys; pathlib.Path(sys.argv[1]).write_text("{}")',
                    '/dev/fd/' + str(descriptor)], env={}, cwd=self.root, pass_fds=(descriptor,))
            self.assertEqual(code, 0)
            self.assertEqual(publication.read('report.json')['json'], {})

    def test_successful_leader_cannot_leave_detached_stdout_grandchild(self):
        pidfile = self.root / 'pid'
        source = ('import os,sys,time; pid=os.fork(); '
            '\nif pid == 0:\n os.close(1); os.close(2); time.sleep(30)'
            '\nelse:\n open(sys.argv[1], "w").write(str(pid))')
        code, _ = module.bounded_command([sys.executable, '-c', source, str(pidfile)],
                                        env={}, cwd=self.root)
        self.assertEqual(code, 0)
        pid = int(pidfile.read_text())
        # A killed child can briefly remain a zombie until adopted/reaped.
        for _ in range(30):
            result = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='], capture_output=True, text=True)
            if not result.stdout.strip() or result.stdout.strip().startswith('Z'):
                break
            time.sleep(.02)
        self.assertTrue(not result.stdout.strip() or result.stdout.strip().startswith('Z'))

    @contextlib.contextmanager
    def cleanup_child(self, *, live_at_probe=False):
        read, write = os.pipe()
        os.close(write)
        child = Mock(pid=987654321, returncode=0, stdout=os.fdopen(read, 'rb'))
        child.poll.return_value = 0
        if live_at_probe:
            child.poll.side_effect = [0, 0, None]
        child.wait.return_value = 0
        try:
            with patch.object(module.subprocess, 'Popen', return_value=child):
                yield child
        finally:
            child.stdout.close()

    def test_cleanup_accepts_eperm_only_after_reaped_leader_and_actual_esrch(self):
        calls = []
        def raced(group, action):
            calls.append((group, action))
            if action == signal.SIGKILL:
                raise PermissionError(errno.EPERM, 'fixed vanished-group race')
            if action == 0:
                raise ProcessLookupError(errno.ESRCH, 'fixed absent group')
        with self.cleanup_child() as child, patch.object(module.os, 'killpg', new=raced):
            self.assertEqual(module.bounded_command(['unused'], env={}, cwd=self.root), (0, b''))
            self.assertTrue(child.stdout.closed)
            self.assertEqual(calls, [(child.pid, signal.SIGTERM), (child.pid, signal.SIGKILL), (child.pid, 0)])

    def test_cleanup_keeps_original_eperm_without_confirmed_group_absence(self):
        for probe_error in (None, PermissionError(errno.EPERM, 'fixed denied probe'),
                OSError(errno.EIO, 'fixed unknown probe'), PermissionError(errno.EACCES, 'fixed other denial'),
                ProcessLookupError(None, 'fixed untyped lookup failure')):
            original = PermissionError(errno.EPERM, 'fixed unconfirmed group')
            calls = []
            def denied(group, action):
                calls.append((group, action))
                if action == signal.SIGKILL:
                    raise original
                if action == 0 and probe_error is not None:
                    raise probe_error
            with self.subTest(probe_errno=getattr(probe_error, 'errno', None)), \
                    self.cleanup_child() as child, patch.object(module.os, 'killpg', new=denied):
                started = time.monotonic()
                with self.assertRaises(PermissionError) as caught:
                    module.bounded_command(['unused'], env={}, cwd=self.root)
                self.assertIs(caught.exception, original)
                self.assertIn((child.pid, 0), calls)
                self.assertTrue(all(group == child.pid for group, _ in calls))
                self.assertLess(time.monotonic() - started, 1)
                self.assertTrue(child.stdout.closed)

    def test_cleanup_never_probes_or_suppresses_non_eperm_permission_errors(self):
        for code in (errno.EACCES, None):
            original = PermissionError(code, 'fixed other permission error')
            calls = []
            def denied(group, action):
                calls.append((group, action))
                if action == signal.SIGKILL:
                    raise original
            with self.subTest(errno=code), self.cleanup_child() as child, patch.object(module.os, 'killpg', new=denied):
                with self.assertRaises(PermissionError) as caught:
                    module.bounded_command(['unused'], env={}, cwd=self.root)
                self.assertIs(caught.exception, original)
                self.assertNotIn((child.pid, 0), calls)
                self.assertTrue(child.stdout.closed)

    def test_cleanup_does_not_confirm_absence_for_a_live_owned_leader(self):
        original = PermissionError(errno.EPERM, 'fixed live leader')
        calls = []
        def denied(group, action):
            calls.append((group, action))
            if action == signal.SIGKILL:
                raise original
        with self.cleanup_child(live_at_probe=True) as child, patch.object(module.os, 'killpg', new=denied):
            with self.assertRaises(PermissionError) as caught:
                module.bounded_command(['unused'], env={}, cwd=self.root)
            self.assertIs(caught.exception, original)
            self.assertNotIn((child.pid, 0), calls)
            self.assertTrue(child.stdout.closed)

    def test_cooperative_sigterm_kills_owned_group(self):
        pidfile = self.root / 'owned-pid'
        child_source = 'import os,time,sys; open(sys.argv[1], "w").write(str(os.getpid())); time.sleep(30)'
        harness = ('import importlib.util, pathlib, sys; '
            'spec=importlib.util.spec_from_file_location("scan_images",sys.argv[1]); '
            'm=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); '
            '\nwith m.cooperative_termination():\n m.bounded_command([sys.executable,"-c",'
            + repr(child_source) + ', sys.argv[2]],env={},cwd=pathlib.Path(sys.argv[2]).parent)')
        process = subprocess.Popen([sys.executable, '-c', harness, str(SCRIPT), str(pidfile)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while not pidfile.exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(pidfile.exists())
            pid = int(pidfile.read_text())
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=5)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    def test_remote_context_rejected(self):
        with patch.object(module, 'bounded_command', return_value=(0, b'[{"Endpoints":{"docker":{"Host":"tcp://secret"}}}]')):
            result = module.scan(self.receipt, self.output)
        self.assertFalse(result['automated_checks_passed'])

    def test_diagnostic_arm64_pin_does_not_expand_production_host_contract(self):
        with patch.object(module.platform, 'system', return_value='Linux'), \
                patch.object(module.platform, 'machine', return_value='aarch64'):
            result = self.run_scan()
        self.assertFalse(result['automated_checks_passed'])
        self.assertIsNone(result['scanner'])
        self.assertEqual(self.scans, 0)


if __name__ == '__main__':
    unittest.main()
