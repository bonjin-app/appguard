import importlib.util
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
from unittest.mock import patch

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
        self.assertEqual(command[1], 'image')
        self.assertEqual(command[-1], self.ids[module.ROLES[self.scans]])
        self.assertEqual(command[command.index('--image-src') + 1], 'docker')
        self.assertNotIn('--ignore-unfixed', command)
        report = self.publication.output.parent / self.publication.name / ('trivy-' + module.ROLES[self.scans] + '.json')
        self.assertEqual(command[command.index('--output') + 1], '/dev/fd/' + str(kwargs['report']))
        image = command[-1]
        value = {'SchemaVersion': 2, 'ArtifactType': 'container_image', 'ArtifactName': image,
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
        return code, b'private scanner output SECRET'

    def run_scan(self, transform=None, mutate=False):
        self.scans, self.mutate = 0, mutate
        self.transform = transform or (lambda value, report: (0, None))
        original_enter = module.Publication.__enter__
        def enter(publication):
            result = original_enter(publication)
            self.publication = publication
            return result
        with patch.object(module.Publication, '__enter__', enter), \
                patch.object(module, 'install_tool', return_value=Path('/mock/trivy')), \
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


if __name__ == '__main__':
    unittest.main()
