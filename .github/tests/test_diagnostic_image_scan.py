"""Diagnostic image scans are measurements, never deployment qualifications."""
import contextlib
import importlib.util
import io
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('diagnostic_scan', ROOT / 'scripts/qualification/scan_diagnostic_images.py')
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.c = self.m.core
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve(); self.output = self.base / 'out'
        self.images = ['sha256:' + value * 64 for value in ('a', 'b')]
        self.arch = 'amd64'; self.transform = lambda kind, value: None
        self.calls = []; self.downloads = []; self.states = []; self.after = lambda kind: None
        self.inspect_change = lambda image, record: None

    def document(self, kind, image=None):
        document = {'SchemaVersion': 2, 'Trivy': {'Version': '0.76.1'},
            'ArtifactType': 'filesystem' if kind == 'calibration' else 'container_image',
            'ArtifactName': '/PRIVATE-CALIBRATION' if kind == 'calibration' else image,
            'Metadata': {'OS': {'Family': 'debian', 'Name': '13.0'}},
            'Results': [{'Class': 'os-pkgs', 'Type': 'debian', 'Packages': [
                {'Name': 'openssl', 'Version': '3.5.1-1', 'SrcName': 'openssl', 'SrcVersion': '3.5.1-1'}]}]}
        if kind == 'calibration':
            document['Results'][0]['Vulnerabilities'] = [self.finding()]
        else:
            document['Metadata']['ImageID'] = image
        return document

    def finding(self):
        return {'VulnerabilityID': 'CVE-2025-9230', 'PkgName': 'openssl', 'InstalledVersion': '3.5.1-1',
            'FixedVersion': '3.5.1-1+deb13u1', 'Severity': 'MEDIUM',
            'DataSource': {'ID': 'debian', 'Name': 'Debian Security Tracker', 'URL': 'PRIVATE-URL'}}

    def runner(self, command, **kwargs):
        self.calls.append(command)
        env = kwargs['env']
        self.assertNotIn('DOCKER_HOST', env); self.assertNotIn('TRIVY_TOKEN', env)
        if command[0] == sys.executable:
            self.states.append(Path(kwargs['cwd'])); self.tool = Path(kwargs['cwd']) / 'trivy'
            self.tool.write_bytes(b'fixed executable'); self.tool.chmod(0o700)
            self.assertLessEqual(kwargs['timeout'], 660)
            return 0, b''
        if command[0] == 'docker':
            args = command[3:]
            if args[:2] == ['context', 'inspect']:
                value = [{'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}]
            elif args[:2] == ['info', '--format']:
                value = {'OSType': 'linux', 'Architecture': 'x86_64' if self.arch == 'amd64' else 'aarch64'}
            else:
                self.assertEqual(args[:2], ['image', 'inspect'])
                image = args[2]
                record = {'Id': image, 'Os': 'linux', 'Architecture': self.arch, 'Size': 1000}
                self.inspect_change(image, record); value = [record]
            return 0, json.dumps(value).encode()
        if command[1] == 'version':
            self.assertIn('--quiet', command)
            return 0, b'{"Version":"0.76.1"}'
        for flag, folder, filename, schema in (('--download-db-only', 'db', 'trivy.db', 2),
                ('--download-java-db-only', 'java-db', 'trivy-java.db', 1)):
            if flag in command:
                self.downloads.append(flag); self.cache = Path(env['TRIVY_CACHE_DIR'])
                destination = self.cache / folder; destination.mkdir(parents=True)
                (destination / filename).write_bytes(b'fixed database')
                (destination / 'metadata.json').write_text(json.dumps({'Version': schema,
                    'UpdatedAt': '2026-10-22T00:00:00Z', 'DownloadedAt': '2026-10-23T00:00:00Z',
                    'NextUpdate': '2026-10-24T00:00:00Z'}))
                return 0, b'PRIVATE-DOWNLOAD-LOG'
        kind = 'calibration' if command[1] == 'rootfs' else 'image'
        for flag in ('--skip-db-update', '--skip-java-db-update', '--offline-scan', '--list-all-pkgs'):
            self.assertIn(flag, command)
        self.assertNotIn('--ignore-unfixed', command)
        self.assertEqual(command[command.index('--severity') + 1], 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL')
        self.assertEqual(command[command.index('--output') + 1], '/dev/fd/' + str(kwargs['report']))
        if kind == 'calibration':
            fixture = Path(command[-1])
            files = {str(path.relative_to(fixture)) for path in fixture.rglob('*') if path.is_file()}
            self.assertEqual(files, {'etc/os-release', 'etc/debian_version', 'var/lib/dpkg/status'})
            self.assertEqual((fixture / 'etc/debian_version').read_text(), '13.0\n')
            self.assertIn('Source: openssl (3.5.1-1)', (fixture / 'var/lib/dpkg/status').read_text())
        else:
            self.assertIn(command[-1], self.images)
            self.assertEqual(command[command.index('--image-src') + 1], 'docker')
        value = self.document(kind, command[-1])
        override = self.transform(kind, value)
        count = sum(len(row.get('Vulnerabilities', [])) for row in value['Results'])
        code, raw = override if override is not None else (int(count > 0), json.dumps(value).encode())
        os.write(kwargs['report'], raw)
        self.after(kind)
        return code, b'PRIVATE-SCANNER-LOG'

    def scan(self):
        def install(name, state, **kwargs):
            self.states.append(Path(state)); self.tool = Path(state) / name
            self.tool.write_bytes(b'fixed executable'); self.tool.chmod(0o700); return self.tool
        with patch.object(self.c, 'bounded_command', side_effect=self.runner), \
                patch.object(self.c, 'install_tool', side_effect=install), \
                patch.object(self.c.platform, 'system', return_value='Linux'), \
                patch.object(self.c.platform, 'machine', return_value='x86_64' if self.arch == 'amd64' else 'aarch64'), \
                patch.dict(os.environ, {'DOCKER_HOST': 'tcp://PRIVATE', 'TRIVY_TOKEN': 'PRIVATE-TOKEN'}):
            result = self.m.scan_images(self.images, 'linux/' + self.arch, self.output)
        self.assertEqual(result, json.loads((self.output / 'diagnostic.json').read_bytes()))
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertFalse(result['release_ready']); self.assertFalse(result['native_binary_coverage'])
        self.assertFalse(result['coverage_complete']); self.assertFalse(result['complete_resolved_graph'])
        self.assertTrue(all(not path.exists() for path in self.states))
        return result

    def test_pair_uses_one_frozen_session_and_separate_calibration(self):
        result = self.scan()
        self.assertTrue(result['measurement_complete'])
        self.assertTrue(result['calibration']['observed'])
        self.assertEqual(result['vulnerabilities'], 0)
        self.assertEqual(self.downloads, ['--download-db-only', '--download-java-db-only'])
        self.assertEqual(len(self.states), 1)
        self.assertEqual([row['image_id'] for row in result['images']], self.images)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in self.output.iterdir()))

    def test_tool_installation_has_an_owned_subprocess_wall_deadline(self):
        self.scan()
        commands = [command for command in self.calls if command[0] == sys.executable]
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][1], '-c')
        self.assertIn("install_tool('trivy'", commands[0][2])

    def test_invalid_cli_redacts_private_argument(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.m.main(['--image', 'PRIVATE-TOKEN', '--platform', 'wrong',
                '--output', str(self.output)]), 2)
        self.assertNotIn('PRIVATE', output.getvalue())

    def test_unfixed_duplicates_and_all_severities_remain_counted(self):
        def findings(kind, value):
            if kind == 'image':
                row = self.finding(); row['FixedVersion'] = ''; row['Severity'] = 'UNKNOWN'
                value['Results'][0]['Vulnerabilities'] = [row, dict(row)]
        self.transform = findings
        result = self.scan()
        self.assertTrue(result['measurement_complete']); self.assertEqual(result['vulnerabilities'], 4)
        self.assertEqual(len(result['images'][0]['findings']), 2)
        self.assertEqual(result['images'][0]['findings'][0]['fixed_versions'], [])

    def test_oversized_summary_clears_zero_interpretation_and_preserves_counts(self):
        def oversized(kind, value):
            if kind == 'image' and value['Metadata']['ImageID'] == self.images[1]:
                finding = self.finding()
                finding['FixedVersion'] = ','.join(['1.' + '0' * 198] * 32)
                value['Results'][0]['Vulnerabilities'] = [dict(finding) for _ in range(350)]
        self.transform = oversized
        result = self.scan()
        self.assertFalse(result['measurement_complete'])
        self.assertEqual(result['vulnerabilities'], 350)
        self.assertEqual([row['vulnerabilities'] for row in result['images']], [0, 350])
        self.assertTrue(result['calibration']['observed'])
        self.assertTrue(all(not row['finding_details_complete'] and not row['findings'] for row in result['images']))
        self.assertTrue(all(not row['zero_findings_interpretable'] for row in result['images']))
        self.assertLessEqual((self.output / 'diagnostic.json').stat().st_size, self.c.MAX_STATUS)

    def test_missing_control_never_erases_target_findings(self):
        def findings(kind, value):
            value['Results'][0]['Vulnerabilities'] = [self.finding()] if kind == 'image' else []
        self.transform = findings
        result = self.scan()
        self.assertFalse(result['measurement_complete']); self.assertFalse(result['calibration']['observed'])
        self.assertEqual(result['vulnerabilities'], 2)

    def test_wrong_control_release_fixed_version_source_and_package_fail(self):
        changes = [lambda v: v['Metadata']['OS'].update(Name='12.0'),
            lambda v: v['Results'][0]['Vulnerabilities'][0].update(FixedVersion='3.5.4'),
            lambda v: v['Results'][0]['Vulnerabilities'][0]['DataSource'].update(ID='nvd'),
            lambda v: v['Results'][0]['Packages'][0].update(SrcName='wrong')]
        for index, change in enumerate(changes):
            self.output = self.base / str(index)
            self.transform = lambda kind, value: change(value) if kind == 'calibration' else None
            with self.subTest(index=index): self.assertFalse(self.scan()['measurement_complete'])

    def test_bare_jre_requires_actual_os_package_inventory(self):
        self.transform = lambda kind, value: value['Results'][0].update(Packages=[]) if kind == 'image' else None
        self.assertFalse(self.scan()['measurement_complete'])

    def test_uncalibrated_ubuntu_zero_cannot_be_interpreted_as_clean(self):
        def ubuntu(kind, value):
            if kind == 'image':
                value['Metadata']['OS'] = {'Family': 'ubuntu', 'Name': '24.04'}
                value['Results'][0]['Type'] = 'ubuntu'
        self.transform = ubuntu
        result = self.scan()
        self.assertFalse(result['measurement_complete'])
        self.assertEqual(result['vulnerabilities'], 0)

    def test_ubuntu_positive_counts_do_not_claim_its_feed_is_calibrated(self):
        def ubuntu(kind, value):
            if kind == 'image':
                value['Metadata']['OS'] = {'Family': 'ubuntu', 'Name': '24.04'}
                value['Results'][0]['Type'] = 'ubuntu'
                value['Results'][0]['Vulnerabilities'] = [self.finding()]
        self.transform = ubuntu
        result = self.scan()
        self.assertTrue(result['measurement_complete'])
        self.assertEqual(result['vulnerabilities'], 2)
        self.assertFalse(result['images'][0]['debian13_control_observed'])
        self.assertFalse(result['images'][0]['zero_findings_interpretable'])

    def test_actual_dpkg_split_version_fields_are_recognized(self):
        def split(kind, value):
            if kind == 'calibration':
                value['Results'][0]['Packages'][0].update(Version='3.5.1', Release='1', SrcVersion='3.5.1', SrcRelease='1')
        self.transform = split
        self.assertTrue(self.scan()['calibration']['observed'])

    def test_late_report_mutation_aborts_publication(self):
        original = self.c.Publication.publish
        def publish(publication):
            original(publication)
            (publication.output / 'trivy-image-0.json').write_bytes(b'{}')
        with patch.object(self.c.Publication, 'publish', new=publish), self.assertRaises(ValueError):
            self.scan()
        self.assertFalse(self.output.exists())

    def test_handed_off_parent_descriptor_policy_is_checked_before_session(self):
        original_enter, original_fstat = self.c.Publication.__enter__, os.fstat
        for policy in ('owner', 'mode'):
            self.output = self.base / ('parent-' + policy)
            held = {}
            def enter(publication):
                result = original_enter(publication)
                held['descriptor'] = publication.parent_fd
                return result
            def fstat(descriptor):
                value = original_fstat(descriptor)
                if descriptor == held.get('descriptor'):
                    fields = list(value)
                    fields[4 if policy == 'owner' else 0] = value.st_uid + 1 if policy == 'owner' else value.st_mode | 0o022
                    return os.stat_result(fields)
                return value
            with self.subTest(policy=policy), patch.object(self.c.Publication, '__enter__', new=enter), \
                    patch.object(self.c.os, 'fstat', side_effect=fstat), \
                    patch.object(self.c, 'TrivySession', wraps=self.c.TrivySession) as session:
                with self.assertRaises(ValueError): self.scan()
                session.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_parent_policy_change_after_publication_aborts_output(self):
        original = self.c.Publication.publish
        def publish(publication):
            original(publication)
            self.base.chmod(0o777)
        try:
            with patch.object(self.c.Publication, 'publish', new=publish), self.assertRaises(ValueError):
                self.scan()
            self.assertFalse(self.output.exists())
        finally:
            self.base.chmod(0o700)

    def test_single_image_and_oversized_image_bounds(self):
        self.images = self.images[:1]
        self.assertTrue(self.scan()['measurement_complete'])
        self.output = self.base / 'oversized'
        self.inspect_change = lambda image, value: value.update(Size=2 * 1024 * 1024 * 1024 + 1)
        self.assertFalse(self.scan()['measurement_complete'])

    def test_wrong_image_report_never_passes(self):
        self.transform = lambda kind, value: value['Metadata'].update(ImageID='sha256:' + 'c' * 64) if kind == 'image' else None
        self.assertFalse(self.scan()['measurement_complete'])

    def test_architecture_mismatch_rejected_before_any_scan(self):
        self.inspect_change = lambda image, value: value.update(Architecture='arm64')
        self.assertFalse(self.scan()['measurement_complete'])
        self.assertFalse(any(command[1] in ('image', 'rootfs') and command[0] != 'docker'
            and '--output' in command for command in self.calls))

    def test_post_scan_image_identity_change_fails(self):
        seen = {}
        def change(image, value):
            seen[image] = seen.get(image, 0) + 1
            if seen[image] > 1: value['Id'] = 'sha256:' + 'c' * 64
        self.inspect_change = change
        self.assertFalse(self.scan()['measurement_complete'])

    def test_final_identity_failure_clears_calibration_interpretation_flags(self):
        seen = {}
        def change(image, value):
            seen[image] = seen.get(image, 0) + 1
            if seen[image] > 2: value['Id'] = 'sha256:' + 'c' * 64
        self.inspect_change = change
        result = self.scan()
        self.assertFalse(result['measurement_complete'])
        self.assertFalse(result['calibration']['observed'])
        self.assertTrue(all(not row['debian13_control_observed'] and not row['zero_findings_interpretable'] for row in result['images']))

    def test_native_arm64_uses_reviewed_arm64_pin(self):
        self.arch = 'arm64'; result = self.scan()
        self.assertTrue(result['measurement_complete'])
        self.assertEqual(result['scanner']['archive_sha256'], 'e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f')

    def test_unknown_exit_and_malformed_report_are_incomplete(self):
        for index, override in enumerate(((2, b'{}'), (0, b'not-json'))):
            self.output = self.base / str(index)
            self.transform = lambda kind, value: override if kind == 'image' else None
            with self.subTest(index=index): self.assertFalse(self.scan()['measurement_complete'])

    def test_mutated_database_cannot_publish_complete_measurement(self):
        self.after = lambda kind: (self.cache / 'db/trivy.db').write_bytes(b'changed')
        result = self.scan()
        self.assertFalse(result['measurement_complete'])

    def test_unprojectable_findings_keep_counts_and_fail_completeness(self):
        def invalid(kind, value):
            if kind == 'image':
                row = self.finding(); row['PkgName'] = 'PRIVATE invalid'; value['Results'][0]['Vulnerabilities'] = [row]
        self.transform = invalid
        result = self.scan(); self.assertEqual(result['vulnerabilities'], 2)
        self.assertFalse(result['measurement_complete'])

    def test_invalid_inputs_never_start_a_session(self):
        for images, platform in ((['latest'], 'linux/amd64'), ([], 'linux/amd64'),
                (self.images * 2, 'linux/amd64'), (self.images, 'linux/386')):
            with self.subTest(images=images, platform=platform), patch.object(self.c, 'TrivySession') as session:
                with self.assertRaises(ValueError): self.m.scan_images(images, platform, self.output)
                session.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_cli_distinguishes_complete_findings_and_incomplete_without_raw_errors(self):
        for complete, count, expected in ((True, 0, 0), (True, 1, 1), (False, 0, 2)):
            with patch.object(self.m, 'scan_images', return_value={'measurement_complete': complete,
                    'vulnerabilities': count, 'reason': 'fixed'}), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(self.m.main(['--image', self.images[0], '--platform', 'linux/amd64',
                    '--output', str(self.output)]), expected)


if __name__ == '__main__': unittest.main()
