"""Bounded native-runtime inventory semantics; no Docker or network required."""
import copy
import contextlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/qualification/inspect_java_runtime.py'


def inventory(*, missing=False, java_exit=0, arch='amd64', symlink=None):
    records = ['JRI\t1', 'OS_ID\tubuntu', 'OS_VERSION\t24.04',
        'ARCH\t' + ('x86_64' if arch == 'amd64' else 'aarch64'), 'UID\t10001',
        'PACKAGE\tlibc6:' + arch + '\t2.39-0ubuntu8.6\t' + arch + '\tinstalled']
    files = [('release', '000000000000'), ('legal/java.base/LICENSE', '000000000000'),
        ('legal/java.base/ASSEMBLY_EXCEPTION', '000000000000'), ('lib/security/cacerts', 'feedfeed0000'),
        ('lib/modules', 'dadafeca0000'),
        ('bin/java', '7f454c460201010000000000000000000200' + ('3e00' if arch == 'amd64' else 'b700')),
        ('lib/libawt_xawt.so', '7f454c460201010000000000000000000300' + ('3e00' if arch == 'amd64' else 'b700'))]
    for path, header in files:
        records.append('FILE\t' + path + '\t' + 'a' * 64 + '\t128\t' + header)
        if header.startswith('7f454c46'):
            records.extend(['ELF_BEGIN\t' + path + '\t0', 'LDD\t\tlinux-vdso.so.1 (0x00007fff00000000)',
                'LDD\t\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fff00000001)',
                'LDD\t\t/lib64/ld-linux-x86-64.so.2 (0x00007fff00000002)'])
            if missing and path.endswith('libawt_xawt.so'):
                records.append('LDD\t\tlibX11.so.6 => not found')
            records.append('ELF_END\t' + path)
    if symlink:
        records.append('SYMLINK\tlegal/java.sql/LICENSE\t' + symlink)
    records.extend(['JAVA_BEGIN\t' + str(java_exit), 'JAVA\tProperty settings:',
        'JAVA\t    java.vendor = Eclipse Adoptium', 'JAVA\t    java.version = 17.0.20.1',
        'JAVA\t    java.runtime.version = 17.0.20.1+1',
        'JAVA\t    os.arch = ' + ('amd64' if arch == 'amd64' else 'aarch64'), 'JAVA_END',
        'RELEASE_BEGIN', 'RELEASE\tJAVA_VERSION="17.0.20.1"',
        'RELEASE\tIMPLEMENTOR="Eclipse Adoptium"',
        'RELEASE\tJAVA_RUNTIME_VERSION="17.0.20.1+1"', 'RELEASE_END',
        'END\t7\t' + str(int(bool(symlink))) + '\t2'])
    return '\n'.join(records) + '\n'


def providers(paths):
    records = ['PROVIDERS\t1']
    for path in sorted(paths):
        records.extend(['LIB_BEGIN\t' + path, 'REAL\t' + path,
            'HASH\t' + 'b' * 64, 'OWNER_CODE\t0',
            'OWNER\tlibc6:amd64: ' + path, 'LIB_END\t' + path])
    return '\n'.join(records + ['END\t' + str(len(paths))]) + '\n'


FEATURE_CHECKS = ('crypto_p256', 'aes_gcm', 'pkcs12_roundtrip', 'jsse_default_trust',
    'mtls_loopback', 'utf8_io', 'locale_data', 'timezone_data', 'localhost_nss', 'headless_font')


def feature_protocol(*, failed=(), code=None):
    checks = {name: name not in failed for name in FEATURE_CHECKS}
    passed = all(checks.values())
    document = json.dumps({'schema': 1, 'checks': checks, 'passed': passed}, separators=(',', ':'))
    return 'FEATURE_BEGIN\n' + document + '\nFEATURE_EXIT\t' + str((0 if passed else 1) if code is None else code) + '\n'


class RuntimeInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('java_native_inventory', SCRIPT)
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)

    def closure_fixture(self):
        spec = importlib.util.spec_from_file_location('dependency_test_fixture', Path(__file__).with_name('test_java_runtime_dependencies.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module.DependencyClosureTests().fixture()

    def test_explicit_dependency_closure_reads_fixed_owned_files_and_binds_schema3(self):
        self.assertIn('dependency_closure', inspect.signature(self.m.inspect_runtime).parameters)
        _, _, _, protocol, packages = self.closure_fixture()
        fake = self.fake(missing=False)
        def call(command, **kwargs):
            if command[3] == 'exec' and 'CLOSURE' in command[-1]: return protocol
            if command[3] == 'exec' and command[-1] == self.m.INVENTORY_SCRIPT:
                raw = inventory(missing=False).replace('2.39-0ubuntu8.6', '2.41-12+deb13u4')
                extra = ''.join('PACKAGE\t{name}\t{version}\t{architecture}\tinstalled\n'.format(**row) for row in packages[:-1])
                return raw.replace('FILE\trelease', extra + 'FILE\trelease', 1)
            return fake(command, **kwargs)
        with tempfile.TemporaryDirectory() as directory, patch.object(self.m, 'bounded_command', side_effect=call):
            result = self.m.inspect_runtime(self.image, 'linux/amd64', Path(directory).resolve()/'out', dependency_closure=True)
        self.assertEqual(result['schema'], 3)
        self.assertTrue(result['inventory_complete'])
        self.assertTrue(result['dependency_closure']['verified'])
        self.assertTrue(result['checks']['dependency_closure_verified'])
        self.assertTrue(result['cleanup']); self.assertTrue(fake.removed)
        for flag in ('release_ready', 'native_binary_coverage', 'coverage_complete'): self.assertFalse(result[flag])

    def test_requested_missing_or_invalid_closure_cannot_complete_and_still_cleans(self):
        self.assertIn('dependency_closure', inspect.signature(self.m.inspect_runtime).parameters)
        for failure in (ValueError('SECRET'), 'SECRET malformed\n'):
            fake = self.fake(missing=False)
            def call(command, **kwargs):
                if command[3] == 'exec' and 'CLOSURE' in command[-1]:
                    if isinstance(failure, Exception): raise failure
                    return failure
                return fake(command, **kwargs)
            with tempfile.TemporaryDirectory() as directory, patch.object(self.m, 'bounded_command', side_effect=call):
                result = self.m.inspect_runtime(self.image, 'linux/amd64', Path(directory).resolve()/'out', dependency_closure=True)
            self.assertEqual(result['schema'], 3)
            self.assertFalse(result['inventory_complete']); self.assertFalse(result['native_checks_passed'])
            self.assertIsNone(result['dependency_closure'])
            self.assertTrue(result['cleanup']); self.assertTrue(fake.removed)
            self.assertNotIn('SECRET', json.dumps(result))

    def test_feature_protocol_preserves_measured_font_failure_and_all_attempted_checks(self):
        result = self.m.parse_features(feature_protocol(failed=('headless_font',)))
        self.assertFalse(result['passed'])
        self.assertEqual(result['exit_code'], 1)
        self.assertEqual(set(result['checks']), set(FEATURE_CHECKS))
        self.assertFalse(result['checks']['headless_font'])
        self.assertTrue(result['checks']['mtls_loopback'])
        self.assertTrue(self.m.parse_features(feature_protocol())['passed'])

    def test_feature_protocol_refuses_omissions_duplicates_nonbooleans_and_status_contradiction(self):
        original = feature_protocol()
        for raw in (original.replace('"headless_font":true', '"headless_font":1'),
                original.replace(',"headless_font":true', ''),
                original.replace('"schema":1', '"schema":1,"schema":1'),
                original.replace('"schema":1', '"schema":true'),
                original.replace('"passed":true', '"passed":false'),
                original.replace('"checks":{', '"checks":{"SECRET":true,'),
                original.replace('FEATURE_EXIT\t0', 'FEATURE_EXIT\t1'),
                original.replace('FEATURE_EXIT\t0', 'FEATURE_EXIT\t2'),
                original.replace('FEATURE_BEGIN\n', ''), original.rstrip('\n'),
                original + 'SECRET\n', 'x' * 16385):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                self.m.parse_features(raw)

    def test_optional_features_run_after_linkage_failure_and_retain_complete_schema2_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = self.fake(missing=True)
            def call(command, **kwargs):
                if command[3] == 'exec' and 'AppGuardRuntimeProbe' in command[-1]:
                    self.assertNotIn('/usr/bin/env', command)
                    return feature_protocol(failed=('headless_font',))
                return fake(command, **kwargs)
            with patch.object(self.m, 'bounded_command', side_effect=call):
                result = self.m.inspect_runtime(self.image, 'linux/amd64', Path(directory).resolve()/'out', features=True)
            self.assertEqual(result['schema'], 2)
            self.assertTrue(result['inventory_complete'])
            self.assertFalse(result['checks']['runtime_features_passed'])
            self.assertFalse(result['features']['checks']['headless_font'])
            self.assertTrue(result['cleanup'])
            self.assertTrue(fake.removed)
            self.assertFalse(result['release_ready'])
            self.assertFalse(result['native_binary_coverage'])

    def test_valid_unverified_java_result_is_retained_without_completing_inventory(self):
        raw = feature_protocol(failed=('headless_font',), code=2)
        parsed = self.m.parse_features(raw)
        self.assertEqual(parsed['exit_code'], 2)
        self.assertFalse(parsed['passed'])
        with tempfile.TemporaryDirectory() as directory:
            fake = self.fake(missing=False)
            def call(command, **kwargs):
                if command[3] == 'exec' and 'AppGuardRuntimeProbe' in command[-1]: return raw
                return fake(command, **kwargs)
            with patch.object(self.m, 'bounded_command', side_effect=call):
                result = self.m.inspect_runtime(self.image, 'linux/amd64', Path(directory).resolve()/'out', features=True)
            self.assertEqual(result['features'], parsed)
            self.assertTrue(result['features']['checks']['mtls_loopback'])
            self.assertFalse(result['features']['checks']['headless_font'])
            self.assertFalse(result['inventory_complete'])
            self.assertFalse(result['native_checks_passed'])
            self.assertNotIn('runtime_features_passed', result['checks'])
            for flag in ('release_ready', 'coverage_complete', 'native_binary_coverage'):
                self.assertFalse(result[flag])
            self.assertTrue(result['cleanup'])
            self.assertTrue(fake.removed)

    def test_malformed_feature_output_never_passes_or_leaks_and_still_cleans_owned_container(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = self.fake(missing=False)
            def call(command, **kwargs):
                if command[3] == 'exec' and 'AppGuardRuntimeProbe' in command[-1]:
                    return 'SECRET unframed failure\n'
                return fake(command, **kwargs)
            with patch.object(self.m, 'bounded_command', side_effect=call):
                result = self.m.inspect_runtime(self.image, 'linux/amd64', Path(directory).resolve()/'out', features=True)
            self.assertFalse(result['inventory_complete'])
            self.assertFalse(result['native_checks_passed'])
            self.assertNotIn('SECRET', json.dumps(result))
            self.assertTrue(result['cleanup'])
            self.assertTrue(fake.removed)

    def test_feature_command_timeout_keeps_collection_incomplete_and_cleans_owned_container(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = self.fake(missing=False)
            def call(command, **kwargs):
                if command[3] == 'exec' and 'AppGuardRuntimeProbe' in command[-1]:
                    raise self.m.CommandFailure('timeout', None, b'SECRET exception')
                return fake(command, **kwargs)
            with patch.object(self.m, 'bounded_command', side_effect=call):
                result = self.m.inspect_runtime(self.image, 'linux/amd64', Path(directory).resolve()/'out', features=True)
            self.assertFalse(result['inventory_complete'])
            self.assertFalse(result['native_checks_passed'])
            self.assertTrue(result['cleanup'])
            self.assertTrue(fake.removed)
            self.assertNotIn('SECRET', json.dumps(result))

    def test_feature_cli_preserves_exit_semantics_and_does_not_inject_host_environment(self):
        for response, expected in ((feature_protocol(), 0),
                (feature_protocol(failed=('headless_font',)), 1),
                (feature_protocol(failed=('headless_font',), code=2), 2), ('SECRET failure\n', 2)):
            with tempfile.TemporaryDirectory() as directory:
                fake = self.fake(missing=False)
                def call(command, **kwargs):
                    self.assertNotIn('HOST_SECRET', json.dumps(kwargs.get('env', {})))
                    self.assertNotIn('HOST_SECRET', ' '.join(command))
                    if command[3] == 'exec' and 'AppGuardRuntimeProbe' in command[-1]: return response
                    return fake(command, **kwargs)
                with self.subTest(expected=expected), patch.dict(os.environ,
                        {'LANG': 'HOST_SECRET', 'JAVA_TOOL_OPTIONS': 'HOST_SECRET'}), \
                        patch.object(self.m, 'bounded_command', side_effect=call), \
                        contextlib.redirect_stdout(io.StringIO()) as stdout:
                    code = self.m.main(['--image', self.image, '--platform', 'linux/amd64',
                        '--output', str(Path(directory).resolve()/'report'), '--features'])
                self.assertEqual(code, expected)
                self.assertNotIn('SECRET', stdout.getvalue())
                self.assertTrue(fake.removed)

    def test_complete_tree_and_actual_ldd_syntax_preserve_optional_missing_dependency(self):
        result = self.m.parse_inventory(inventory(missing=True), 'amd64')
        self.assertTrue(result['inventory_complete'])
        self.assertEqual(result['counts']['regular_files'], 7)
        self.assertEqual(result['counts']['elf_files'], 2)
        self.assertEqual(result['counts']['missing_dependencies'], 1)
        self.assertEqual(result['elfs'][1]['missing'], ['libX11.so.6'])
        self.assertFalse(result['checks']['linkage_resolved'])
        self.assertTrue(result['checks']['required_files_present'])
        self.assertEqual(len(result['jre_tree_sha256']), 64)
        self.assertNotIn('0x00007', json.dumps(result))
        self.assertNotIn('/lib/x86_64', json.dumps(result))

    def test_tree_digest_covers_non_elf_bytes_and_literal_in_tree_symlinks(self):
        original = self.m.parse_inventory(inventory(), 'amd64')
        modified = inventory().replace('FILE\tlib/modules\t' + 'a' * 64, 'FILE\tlib/modules\t' + 'c' * 64)
        self.assertNotEqual(original['jre_tree_sha256'], self.m.parse_inventory(modified, 'amd64')['jre_tree_sha256'])
        linked = self.m.parse_inventory(inventory(symlink='../java.base/LICENSE'), 'amd64')
        self.assertNotEqual(original['jre_tree_sha256'], linked['jre_tree_sha256'])
        lines = inventory().splitlines()
        first = next(i for i, line in enumerate(lines) if line.startswith('FILE\trelease\t'))
        second = next(i for i, line in enumerate(lines) if line.startswith('FILE\tlib/modules\t'))
        lines[first], lines[second] = lines[second], lines[first]
        reordered = '\n'.join(lines) + '\n'
        self.assertEqual(original['jre_tree_sha256'], self.m.parse_inventory(reordered, 'amd64')['jre_tree_sha256'])

    def test_symlink_escape_or_missing_ca_is_a_retained_failed_check(self):
        escaped = self.m.parse_inventory(inventory(symlink='/private/SECRET'), 'amd64')
        self.assertTrue(escaped['inventory_complete'])
        self.assertFalse(escaped['checks']['symlinks_contained'])
        self.assertIsNone(escaped['jre_tree_sha256'])
        self.assertNotIn('SECRET', json.dumps(escaped))
        missing = inventory().replace('FILE\tlib/security/cacerts\t' + 'a' * 64 + '\t128\tfeedfeed0000\n', '').replace('END\t7\t0\t2', 'END\t6\t0\t2')
        result = self.m.parse_inventory(missing, 'amd64')
        self.assertTrue(result['inventory_complete'])
        self.assertFalse(result['checks']['required_files_present'])

    def test_nonzero_java_and_loader_results_keep_the_complete_inventory(self):
        raw = inventory(java_exit=1).replace('ELF_BEGIN\tbin/java\t0', 'ELF_BEGIN\tbin/java\t1')
        raw = raw.replace('LDD\t\tlinux-vdso.so.1 (0x00007fff00000000)', 'LDD\tldd: fixed diagnostic fixture', 1)
        result = self.m.parse_inventory(raw, 'amd64')
        self.assertTrue(result['inventory_complete'])
        self.assertFalse(result['checks']['java_identity_matches'])
        self.assertFalse(result['checks']['linkage_resolved'])
        self.assertEqual(result['java']['exit_code'], 1)
        self.assertEqual(len(result['elfs']), 2)
        self.assertNotIn('diagnostic fixture', json.dumps(result))

    def test_bundled_dependency_may_be_enumerated_after_its_consumer(self):
        raw = inventory().replace('ELF_END\tbin/java',
            'LDD\t\tlibawt_xawt.so => /opt/java/openjdk/lib/libawt_xawt.so (0x00007fff00000003)\nELF_END\tbin/java')
        result = self.m.parse_inventory(raw, 'amd64')
        self.assertTrue(result['checks']['linkage_resolved'])
        self.assertEqual(result['elfs'][0]['dependencies'][-1]['sha256'], 'a' * 64)

    def test_nonzero_not_dynamic_output_is_not_silently_reclassified_as_success(self):
        raw = inventory()
        first = raw.index('ELF_BEGIN\tbin/java')
        last = raw.index('ELF_END\tbin/java', first)
        raw = raw[:first] + 'ELF_BEGIN\tbin/java\t1\nLDD\tnot a dynamic executable\n' + raw[last:]
        self.assertFalse(self.m.parse_inventory(raw, 'amd64')['checks']['linkage_resolved'])

    def test_bundled_library_symlink_resolves_and_empty_loader_output_fails(self):
        raw = inventory().replace('ELF_END\tbin/java',
            'LDD\t\tlibalias.so => /opt/java/openjdk/lib/libalias.so (0x00007fff00000003)\nELF_END\tbin/java')
        raw = raw.replace('JAVA_BEGIN', 'SYMLINK\tlib/libalias.so\tlibawt_xawt.so\nJAVA_BEGIN').replace('END\t7\t0\t2', 'END\t7\t1\t2')
        result = self.m.parse_inventory(raw, 'amd64')
        with self.subTest(kind='symlink'):
            self.assertTrue(result['checks']['linkage_resolved'])
            self.assertEqual(result['elfs'][0]['dependencies'][-1]['sha256'], 'a' * 64)
        raw = inventory(); first = raw.index('ELF_BEGIN\tbin/java'); last = raw.index('ELF_END\tbin/java', first)
        raw = raw[:first] + 'ELF_BEGIN\tbin/java\t0\nLDD\t\n' + raw[last:]
        with self.subTest(kind='empty_loader'):
            self.assertFalse(self.m.parse_inventory(raw, 'amd64')['checks']['linkage_resolved'])

    def test_malformed_truncated_duplicate_and_oversized_protocols_fail_closed(self):
        original = inventory()
        for raw in (original.rsplit('END\t7', 1)[0], original + 'unexpected\n',
                original.replace('END\t7\t0\t2', 'END\t6\t0\t2'),
                original.replace('JRI\t1', 'JRI\t1\nJRI\t1'),
                original.replace('FILE\trelease', 'FILE\t../../SECRET'),
                original.replace('a' * 64, 'not-a-hash', 1), 'x' * (self.m.MAX_PROTOCOL + 1)):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                self.m.parse_inventory(raw, 'amd64')

    def test_elf_header_and_reported_architecture_are_checked(self):
        for raw in (inventory().replace('7f454c460201', '7f454c46'),
                inventory().replace('ARCH\tx86_64', 'ARCH\taarch64'),
                inventory().replace('02003e00', '0200b700')):
            result = self.m.parse_inventory(raw, 'amd64')
            self.assertFalse(result['checks']['elf_platform_matches'])
        self.assertTrue(self.m.parse_inventory(inventory(arch='arm64'), 'arm64')['checks']['java_identity_matches'])

    def test_provider_resolution_joins_installed_package_inventory_and_hashes(self):
        parsed = self.m.parse_inventory(inventory(), 'amd64')
        requested = {'/lib/x86_64-linux-gnu/libc.so.6', '/lib64/ld-linux-x86-64.so.2'}
        result = self.m.parse_providers(providers(requested), requested, parsed['packages'])
        self.assertEqual(set(result), requested)
        for row in result.values():
            self.assertEqual(row['sha256'], 'b' * 64)
            self.assertEqual(row['providers'][0]['version'], '2.39-0ubuntu8.6')
        raw = providers(requested).replace('libc6:amd64:', 'unknown:amd64:')
        result = self.m.parse_providers(raw, requested, parsed['packages'])
        self.assertFalse(all(row['provider_verified'] for row in result.values()))
        with self.assertRaises(ValueError):
            self.m.parse_providers(providers(requested).replace('END\t2', 'END\t1'), requested, parsed['packages'])

    def test_owned_container_validation_rejects_privilege_network_mount_or_owner_changes(self):
        record = self.record()
        self.m.validate_container(record, self.image, self.owner)
        for key, value in (('ReadonlyRootfs', False), ('Privileged', True), ('NetworkMode', 'bridge'),
                ('MemorySwap', -1), ('CapAdd', ['SYS_ADMIN'])):
            changed = copy.deepcopy(record); changed['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.m.validate_container(changed, self.image, self.owner)
        record['Config']['Labels']['io.appguard.owner'] = 'foreign'
        with self.assertRaises(ValueError): self.m.validate_container(record, self.image, self.owner)

    image = 'sha256:' + 'a' * 64
    owner = 'b' * 32

    @classmethod
    def record(cls):
        return {'Id': 'c' * 64, 'Image': cls.image, 'Config': {'User': '10001:10001',
            'Labels': {'io.appguard.owner': cls.owner, 'io.appguard.scope': 'java-runtime-inventory-v1'}},
            'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'NetworkMode': 'none',
                'CapDrop': ['ALL'], 'CapAdd': [], 'SecurityOpt': ['no-new-privileges:true'],
                'Memory': 268435456, 'MemorySwap': 268435456, 'NanoCpus': 1000000000,
                'PidsLimit': 64, 'Binds': [], 'PortBindings': {}, 'RestartPolicy': {'Name': 'no'},
                'LogConfig': {'Type': 'none', 'Config': {}},
                'Tmpfs': {'/tmp': 'rw,noexec,nosuid,nodev,size=16m,mode=1777'}},
            'Mounts': [], 'State': {'Running': True, 'OOMKilled': False}, 'RestartCount': 0}

    def test_complete_failure_artifact_and_owned_cleanup_are_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); output = root/'report'
            fake = self.fake()
            with patch.object(self.m, 'bounded_command', side_effect=fake):
                result = self.m.inspect_runtime(self.image, 'linux/amd64', output)
            self.assertTrue(result['inventory_complete'])
            self.assertFalse(result['native_checks_passed'])
            self.assertTrue(result['cleanup'])
            self.assertEqual(result['reason'], 'native_requirements_unmet')
            self.assertEqual((output/'java-runtime.json').stat().st_mode & 0o777, 0o600)
            self.assertTrue(fake.removed)

    @contextlib.contextmanager
    def parent_policy_fixture(self, policy, *, deny=False):
        publication = __import__('scan_container_images').Publication
        original_enter, original_fstat = publication.__enter__, os.fstat
        state = {'deny': deny}
        def enter(value):
            result = original_enter(value)
            state['descriptor'] = value.parent_fd
            return result
        def fstat(descriptor):
            value = original_fstat(descriptor)
            if state['deny'] and descriptor == state.get('descriptor'):
                fields = list(value)
                fields[4 if policy == 'owner' else 0] = value.st_uid + 1 if policy == 'owner' else value.st_mode | 0o022
                return os.stat_result(fields)
            return value
        with patch.object(publication, '__enter__', new=enter), patch.object(os, 'fstat', side_effect=fstat):
            yield publication, state

    def test_parent_descriptor_handoff_denies_before_private_state_or_docker(self):
        for policy in ('owner', 'mode'):
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as directory:
                target = Path(directory).resolve()/'out'
                with self.parent_policy_fixture(policy, deny=True), \
                        patch.object(self.m, 'bounded_command', side_effect=self.fake(missing=False)) as command, \
                        patch.object(self.m.tempfile, 'TemporaryDirectory', wraps=tempfile.TemporaryDirectory) as temporary, \
                        contextlib.redirect_stdout(io.StringIO()) as stdout:
                    code = self.m.main(['--image', self.image, '--platform', 'linux/amd64', '--output', str(target)])
                self.assertEqual(code, 2)
                self.assertFalse(json.loads(stdout.getvalue())['inventory_complete'])
                self.assertFalse(json.loads(stdout.getvalue())['native_checks_passed'])
                temporary.assert_not_called(); command.assert_not_called()
                self.assertFalse(target.exists())

    def test_parent_descriptor_final_policy_failure_rolls_back_and_keeps_owned_cleanup(self):
        for policy in ('owner', 'mode'):
            for phase in ('before_publish', 'after_publish'):
                with self.subTest(policy=policy, phase=phase), tempfile.TemporaryDirectory() as directory:
                    target = Path(directory).resolve()/'out'; fake = self.fake(missing=False)
                    with self.parent_policy_fixture(policy) as (publication, state):
                        original_publish = publication.publish
                        def publish(value):
                            original_publish(value)
                            if phase == 'after_publish': state['deny'] = True
                        def call(command, **kwargs):
                            raw = fake(command, **kwargs)
                            if phase == 'before_publish' and command[3] == 'ps': state['deny'] = True
                            return raw
                        with patch.object(publication, 'publish', new=publish), \
                                patch.object(self.m, 'bounded_command', side_effect=call), \
                                contextlib.redirect_stdout(io.StringIO()) as stdout:
                            code = self.m.main(['--image', self.image, '--platform', 'linux/amd64', '--output', str(target)])
                    self.assertEqual(code, 2)
                    self.assertFalse(json.loads(stdout.getvalue())['inventory_complete'])
                    self.assertFalse(json.loads(stdout.getvalue())['native_checks_passed'])
                    self.assertTrue(fake.removed)
                    self.assertFalse(target.exists())

    def test_incomplete_probe_and_cancellation_still_remove_only_owned_container(self):
        for failure in (ValueError('SECRET'), KeyboardInterrupt()):
            with tempfile.TemporaryDirectory() as directory:
                fake = self.fake(failure=failure)
                with self.subTest(failure=type(failure).__name__), patch.object(self.m, 'bounded_command', side_effect=fake):
                    result = self.m.inspect_runtime(self.image, 'linux/amd64', Path(directory).resolve()/'out')
                self.assertFalse(result['native_checks_passed'])
                self.assertFalse(result['inventory_complete'])
                self.assertTrue(result['cleanup'])
                self.assertNotIn('SECRET', json.dumps(result))
                self.assertTrue(fake.removed)

    def test_oom_failure_still_cleans_owned_container_but_foreign_identity_is_preserved(self):
        for foreign in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                fake = self.fake(failure=ValueError('SECRET'), unhealthy=True, foreign=foreign)
                with self.subTest(foreign=foreign), patch.object(self.m, 'bounded_command', side_effect=fake):
                    result = self.m.inspect_runtime(self.image, 'linux/amd64', Path(directory).resolve()/'out')
                self.assertEqual(fake.removed, not foreign)
                self.assertEqual(result['cleanup'], not foreign)
                self.assertFalse(result['native_checks_passed'])

    def test_create_warning_retains_name_discovery_for_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = self.fake()
            def warning(command, **kwargs):
                raw = fake(command, **kwargs)
                return 'WARNING: normal Docker diagnostic\n' + raw if command[3] == 'create' else raw
            with patch.object(self.m, 'bounded_command', side_effect=warning):
                result = self.m.inspect_runtime(self.image, 'linux/amd64', Path(directory).resolve()/'out')
            self.assertFalse(result['inventory_complete'])
            self.assertTrue(result['cleanup'])
            self.assertTrue(fake.removed)

    def test_cli_distinguishes_healthy_complete_failure_and_incomplete_collection(self):
        for missing, failure, expected in ((False, None, 0), (True, None, 1), (False, ValueError('SECRET'), 2)):
            with tempfile.TemporaryDirectory() as directory:
                fake = self.fake(missing=missing, failure=failure)
                with self.subTest(expected=expected), patch.object(self.m, 'bounded_command', side_effect=fake), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    code = self.m.main(['--image', self.image, '--platform', 'linux/amd64',
                        '--output', str(Path(directory).resolve()/'report')])
                self.assertEqual(code, expected)
                self.assertNotIn('SECRET', output.getvalue())
                self.assertEqual(json.loads(output.getvalue())['native_checks_passed'], expected == 0)

    def fake(self, failure=None, *, unhealthy=False, foreign=False, missing=True):
        test = self
        class Fake:
            removed = False
            def __call__(self, command, **kwargs):
                args = command[3:]
                if args[:2] == ['context', 'inspect']:
                    return json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}])
                if args[0] == 'info': return '{"OSType":"linux","Architecture":"x86_64"}'
                if args[:2] == ['image', 'inspect']:
                    return json.dumps([{'Id': test.image, 'Os': 'linux', 'Architecture': 'amd64', 'Config': {'Volumes': None}}])
                if args[0] == 'create':
                    self.owner = args[args.index('--label') + 1].split('=', 1)[1]
                    return 'c' * 64 + '\n'
                if args[0] == 'start': return 'c' * 64 + '\n'
                if args[0] == 'inspect':
                    if args[1] not in ('c' * 64, 'appguard-java-audit-' + self.owner):
                        raise ValueError('unknown owned fixture identity')
                    row=test.record(); row['Config']['Labels']['io.appguard.owner']=self.owner
                    if getattr(self, 'probed', False):
                        row['State']['OOMKilled'] = unhealthy
                        if foreign: row['Config']['Labels']['io.appguard.owner']='foreign'
                    return json.dumps([row])
                if args[0] == 'exec':
                    self.probed=True
                    if failure: raise failure
                    return inventory(missing=missing) if 'JRI' in args[-1] else providers({'/lib/x86_64-linux-gnu/libc.so.6','/lib64/ld-linux-x86-64.so.2'})
                if args[0] == 'stop': return 'c' * 64 + '\n'
                if args[0] == 'rm': self.removed=True; return 'c' * 64 + '\n'
                if args[0] == 'ps': return ''
                raise AssertionError('unexpected fixed command')
        return Fake()


class RpmRuntimeTests(unittest.TestCase):
    # Share owned fixture setup without repeating the legacy test methods.
    setUpClass = classmethod(RuntimeInventoryTests.setUpClass.__func__)
    image = RuntimeInventoryTests.image
    record = RuntimeInventoryTests.record
    fake = RuntimeInventoryTests.fake
    parent_policy_fixture = RuntimeInventoryTests.parent_policy_fixture
    def rpm_call(self, unavailable=(), feature_code=0, failed=(), mutate=None):
        from test_java_runtime_rpm import envelope,feature
        fake=self.fake(missing=False);modes=[];commands=[]
        lines=inventory().splitlines();tree=[];inside=False
        for line in lines:
            if line.startswith('ELF_BEGIN\t'):inside=True;continue
            if line.startswith('ELF_END\t'):inside=False;continue
            if inside or line.startswith('PACKAGE\t'):continue
            tree.append(line.replace('OS_ID\tubuntu','OS_ID\trhel').replace('OS_VERSION\t24.04','OS_VERSION\t10.1'))
        header='7f454c4602010100000000000000000002003e00'
        def call(command,**kwargs):
            commands.append((command,kwargs));args=command[3:]
            if args[:2]==['image','inspect']:
                row=json.loads(fake(command,**kwargs));row[0]['Config']['Env']=['JAVA_HOME=/opt/java/openjdk','LANG=C.UTF-8']
                if mutate:mutate(row[0])
                return json.dumps(row)
            if args[0]=='exec':
                self.assertEqual(args[2],'/opt/java/openjdk/bin/java')
                self.assertNotIn('/bin/sh',args);self.assertNotIn('/usr/bin/env',args)
                index=args.index('AppGuardRuntimeInventory')+1;mode=args[index];modes.append(mode)
                if mode in unavailable:return envelope(None,False,'tool_unavailable')
                if mode=='identity':return envelope(dict(uids=[10001]*4,gids=[10001]*4,pid1_elf=header,self_elf=header,
                    java_vendor='Eclipse Adoptium',java_version='17.0.20.1',java_runtime_version='17.0.20.1+1',os_arch='amd64'))
                if mode=='features':return envelope(feature(code=feature_code,failed=failed))
                if mode=='tree':return envelope('\n'.join(tree)+'\n')
                if mode=='database-hashes':return envelope([dict(tag='usr-rpmdb.sqlite',sha256='a'*64,size=128)])
                if mode=='rpm':return envelope(dict(rows='glibc\t0\t2.39\t58.el10\tx86_64\tglibc-2.39-58.el10.src.rpm\tLGPL\n',count=1))
                if mode=='linkage':return envelope([dict(path=name,code=0,lines=['linux-vdso.so.1 (0x00000001)',
                    'libc.so.6 => /usr/lib64/libc.so.6 (0x00000002)']) for name in args[index+1:]])
                if mode=='providers':return envelope([dict(path=name,real=name,sha256='b'*64,
                    owners='glibc\t0\t2.39\t58.el10\tx86_64\tglibc-2.39-58.el10.src.rpm\tLGPL\n') for name in args[index+1:]])
                raise AssertionError('unrecognized fixed Java mode')
            return fake(command,**kwargs)
        return fake,modes,commands,call

    def test_rpm_feature_first_preserves_real_results_without_shell_or_rpm_ldd_tools(self):
        fake,modes,commands,call=self.rpm_call(unavailable=('rpm','linkage'))
        with tempfile.TemporaryDirectory() as directory,patch.object(self.m,'bounded_command',side_effect=call), \
                patch('platform.system',return_value='Linux'),patch('platform.machine',return_value='x86_64'):
            result=self.m.inspect_runtime(self.image,'linux/amd64',Path(directory).resolve()/'out',features=True,package_profile='rpm-ubi10-v1')
        self.assertEqual(modes[:4],['identity','features','tree','database-hashes'])
        create=next(command for command,_ in commands if command[3]=='create')
        self.assertEqual(create[create.index('--entrypoint')+1],'/opt/java/openjdk/bin/java')
        self.assertNotIn('/bin/sh',create);self.assertNotIn('sleep',create)
        self.assertEqual(result['schema'],4);self.assertTrue(result['features']['passed'])
        self.assertTrue(result['stages']['jre_tree']['complete']);self.assertTrue(result['stages']['rpm_database_hashes']['complete'])
        self.assertFalse(result['stages']['rpm_inventory']['complete']);self.assertFalse(result['inventory_complete'])
        self.assertFalse(result['measurement_complete']);self.assertTrue(result['cleanup']);self.assertTrue(fake.removed)
        self.assertEqual(len(result['files']),7)

    def test_rpm_complete_measurement_preserves_home_and_codex_values_and_raw_metadata(self):
        fake,modes,commands,call=self.rpm_call()
        with tempfile.TemporaryDirectory() as directory,patch.object(self.m,'bounded_command',side_effect=call), \
                patch('platform.system',return_value='Linux'),patch('platform.machine',return_value='x86_64'), \
                patch.dict(os.environ,{'HOME':'/owned/caller-home','CODEX_HOME':'/owned/caller-codex','JAVA_TOOL_OPTIONS':'HOST_SECRET'}):
            output=Path(directory).resolve()/'out'
            result=self.m.inspect_runtime(self.image,'linux/amd64',output,features=True,package_profile='rpm-ubi10-v1')
            self.assertTrue((output/'rpm-inventory.tsv').is_file())
            self.assertEqual((output/'rpm-inventory.tsv').stat().st_mode&0o777,0o600)
        self.assertTrue(result['measurement_complete']);self.assertTrue(result['native_checks_passed'])
        for command,kwargs in commands:
            self.assertEqual(kwargs['env'].get('HOME'),'/owned/caller-home')
            self.assertEqual(kwargs['env'].get('CODEX_HOME'),'/owned/caller-codex')
            self.assertNotIn('HOST_SECRET',json.dumps(kwargs['env']))
            self.assertNotIn('HOME=', ' '.join(command));self.assertNotIn('CODEX_HOME=', ' '.join(command))
        self.assertNotIn('_rpm_raw',result)

    def test_rpm_configuration_rejects_unsafe_image_env_before_create(self):
        for values in (['JAVA_TOOL_OPTIONS='],['LD_PRELOAD=SECRET'],['UNKNOWN=SECRET']):
            fake,modes,commands,call=self.rpm_call(mutate=lambda row:row['Config'].update(Env=values))
            with tempfile.TemporaryDirectory() as directory,patch.object(self.m,'bounded_command',side_effect=call), \
                    patch('platform.system',return_value='Linux'),patch('platform.machine',return_value='x86_64'):
                result=self.m.inspect_runtime(self.image,'linux/amd64',Path(directory).resolve()/'out',features=True,package_profile='rpm-ubi10-v1')
            self.assertFalse(any(command[3]=='create' for command,_ in commands))
            self.assertNotIn('SECRET',json.dumps(result));self.assertFalse(result['measurement_complete'])

    def test_rpm_profile_requires_features_and_forbids_closure_before_any_docker(self):
        for options in ({},{'features':True,'dependency_closure':True}):
            with tempfile.TemporaryDirectory() as directory,patch.object(self.m,'bounded_command') as command,self.assertRaises(ValueError):
                self.m.inspect_runtime(self.image,'linux/amd64',Path(directory).resolve()/'out',package_profile='rpm-ubi10-v1',**options)
            command.assert_not_called()

    def test_rpm_features_survive_result_two_late_timeout_cleanup_failure_and_overflow(self):
        from spring_containers import CommandFailure
        for failure in ('result_two','timeout','cleanup','overflow'):
            fake,modes,commands,base=self.rpm_call(feature_code=2 if failure=='result_two' else 0)
            def call(command,**kwargs):
                if failure=='timeout' and command[-1]=='rpm':raise CommandFailure('timeout',None,b'SECRET')
                if failure=='cleanup' and command[3]=='stop':raise ValueError('SECRET')
                return base(command,**kwargs)
            limit=1000 if failure=='overflow' else self.m.MAX_REPORT
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as directory, \
                    patch.object(self.m,'bounded_command',side_effect=call),patch.object(self.m,'MAX_REPORT',limit), \
                    patch('platform.system',return_value='Linux'),patch('platform.machine',return_value='x86_64'):
                if failure=='overflow':
                    # A report cannot fit at this tiny test cap; the publication
                    # must roll back rather than drop the feature observation.
                    output=Path(directory).resolve()/'out'
                    with self.assertRaises(ValueError):self.m.inspect_runtime(self.image,'linux/amd64',output,features=True,package_profile='rpm-ubi10-v1')
                    self.assertFalse(output.exists());continue
                result=self.m.inspect_runtime(self.image,'linux/amd64',Path(directory).resolve()/'out',features=True,package_profile='rpm-ubi10-v1')
            self.assertTrue(result['features']['checks_passed']);self.assertFalse(result['measurement_complete'])
            self.assertFalse(result['native_checks_passed']);self.assertNotIn('SECRET',json.dumps(result))
            if failure=='result_two':
                self.assertEqual(result['features']['result_code'],2);self.assertFalse(result['features']['passed'])
                self.assertEqual(modes,['identity','features'])
                self.assertEqual(result['stages']['features']['reason'],'resource_unverified')
                self.assertFalse(result['stages']['features']['complete'])
                self.assertFalse(result['final_identity_verified'])
                self.assertFalse(result['inventory_complete'])
                for name in ('jre_tree','rpm_database_hashes','rpm_inventory','native_linkage','native_providers'):
                    self.assertFalse(result['stages'][name]['attempted'])
                    self.assertEqual(result['stages'][name]['reason'],'not_attempted')
                self.assertTrue(result['cleanup']);self.assertTrue(fake.removed)
            else:self.assertTrue(result['features']['passed'])
            if failure=='timeout':self.assertNotIn('linkage',modes)

    def test_rpm_package_end_count_and_final_image_mutation_cannot_complete(self):
        from test_java_runtime_rpm import envelope
        for failure in ('count','image'):
            fake,modes,commands,base=self.rpm_call();inspects=[]
            def call(command,**kwargs):
                if command[-1]=='rpm':return envelope(dict(rows='glibc\t0\t2.39\t58.el10\tx86_64\tglibc-2.39-58.el10.src.rpm\tLGPL\n',count=2 if failure=='count' else 1))
                value=base(command,**kwargs)
                if command[3:5]==['image','inspect']:
                    inspects.append(True)
                    if failure=='image' and len(inspects)>1:
                        row=json.loads(value);row[0]['Config']['Env'].append('JAVA_TOOL_OPTIONS=SECRET');return json.dumps(row)
                return value
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as directory,patch.object(self.m,'bounded_command',side_effect=call), \
                    patch('platform.system',return_value='Linux'),patch('platform.machine',return_value='x86_64'):
                result=self.m.inspect_runtime(self.image,'linux/amd64',Path(directory).resolve()/'out',features=True,package_profile='rpm-ubi10-v1')
            self.assertFalse(result['measurement_complete']);self.assertTrue(result['cleanup'])
            self.assertTrue(result['features']['passed']);self.assertNotIn('SECRET',json.dumps(result))

    def test_rpm_held_parent_policy_initial_denial_and_late_change_roll_back(self):
        for policy in ('owner','mode'):
            for phase in ('initial','before_publish','after_publish'):
                fake,modes,commands,base=self.rpm_call()
                with self.subTest(policy=policy,phase=phase),tempfile.TemporaryDirectory() as directory, \
                        self.parent_policy_fixture(policy,deny=phase=='initial') as (publication,state), \
                        patch('platform.system',return_value='Linux'),patch('platform.machine',return_value='x86_64'):
                    target=Path(directory).resolve()/'out';original=publication.publish
                    def publish(value):
                        original(value)
                        if phase=='after_publish':state['deny']=True
                    def call(command,**kwargs):
                        value=base(command,**kwargs)
                        if phase=='before_publish' and command[3]=='ps':state['deny']=True
                        return value
                    with patch.object(publication,'publish',new=publish),patch.object(self.m,'bounded_command',side_effect=call), \
                            contextlib.redirect_stdout(io.StringIO()) as stdout:
                        code=self.m.main(['--image',self.image,'--platform','linux/amd64','--features',
                            '--package-profile','rpm-ubi10-v1','--output',str(target)])
                    self.assertEqual(code,2);self.assertFalse(target.exists())
                    if phase=='initial':self.assertEqual(commands,[])
                    else:self.assertTrue(fake.removed)

if __name__ == '__main__': unittest.main()
