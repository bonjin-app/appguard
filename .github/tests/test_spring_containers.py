"""Container qualifier boundaries; real Docker integration runs on an owned CI runner."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load_module():
    path = ROOT / 'scripts/qualification/spring_containers.py'
    if not path.is_file():
        raise AssertionError('the owned container qualifier has not been implemented')
    spec = importlib.util.spec_from_file_location('spring_containers', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROJECT = 'appguard-spring-' + 'a' * 24
OWNER = 'b' * 24
IDS = {name: char * 64 for name, char in [('gateway', '1'), ('backend', '2'), ('redis', '3')]}


def container(name):
    """Full fields consumed from the Docker Engine's container inspect boundary."""
    return {
        'Id': IDS[name], 'Image': 'sha256:' + 'c' * 64,
        'Config': {'User': '10001:10001', 'Labels': {
            'com.docker.compose.project': PROJECT, 'com.docker.compose.service': name,
            'io.appguard.owner': OWNER, 'io.appguard.scope': 'spring-ingress-v1'}},
        'State': {'Running': True},
        'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'CapDrop': ['ALL'],
            'CapAdd': None, 'SecurityOpt': ['no-new-privileges:true'], 'Memory': 134217728,
            'MemorySwap': 134217728, 'PidsLimit': 32, 'NanoCpus': 500000000,
            'NetworkMode': 'bridge' if name == 'gateway' else 'container:' + IDS['gateway'],
            'PortBindings': {'8443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '43123'}]} if name == 'gateway' else {},
            'Tmpfs': {'/tmp': 'rw,noexec,nosuid,nodev,size=16777216,mode=1777'}},
        'NetworkSettings': {'Ports': {'8443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '43123'}]} if name == 'gateway' else {'6379/tcp': None}},
        'Mounts': [{'Type': 'volume', 'Destination': '/data', 'Name': PROJECT + '_redis-data', 'Driver': 'local', 'RW': True}]
            if name == 'redis' else [{'Type': 'bind', 'Destination': '/run/secrets/' + filename, 'RW': False}
                for filename in ({'frontend.pem', 'frontend.key', 'server-ca.pem', 'ingress-client.pem', 'ingress-client.key'}
                    if name == 'gateway' else {'backend.p12', 'trust.p12', 'backend-password', 'enrolled.pem'})],
    }


class FakeDocker:
    """External Engine substitute; mutations are recorded independently of inspect data."""
    def __init__(self, records, network=None, volume=None, references=None):
        self.records = records
        self.network = network
        self.volume = volume
        self.references = references or []
        self.mutations = []

    def call(self, args, **kwargs):
        if args[0] == 'ps':
            if any(argument.startswith('volume=') for argument in args):
                return '\n'.join(self.references)
            return '\n'.join(self.records)
        if args[:2] == ['container', 'inspect']:
            return json.dumps([self.records[args[2]]])
        if args[:2] in (['container', 'stop'], ['container', 'rm']):
            self.mutations.append(args)
            if args[1] == 'rm':
                del self.records[args[-1]]
            return args[-1]
        if args[:2] == ['network', 'ls']:
            return '' if self.network is None else self.network['Id']
        if args[:2] == ['network', 'inspect']:
            return json.dumps([self.network])
        if args[:2] == ['network', 'rm']:
            self.mutations.append(args)
            self.network = None
            return args[-1]
        if args[:2] == ['volume', 'ls']:
            return '' if self.volume is None else self.volume['Name']
        if args[:2] == ['volume', 'inspect']:
            return json.dumps([self.volume])
        if args[:2] == ['volume', 'rm']:
            self.mutations.append(args)
            self.volume = None
            return args[-1]
        raise AssertionError('unexpected Docker boundary command: ' + str(args))


class ContainerQualificationTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_context_rejects_tcp_ssh_and_malformed_endpoints(self):
        self.module.validate_local_context({'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}})
        for host in ('tcp://127.0.0.1:2375', 'ssh://localhost', 'unix://relative.sock', 'unix:///tmp/../docker.sock', ''):
            with self.subTest(host=host), self.assertRaises(ValueError):
                self.module.validate_local_context({'Endpoints': {'docker': {'Host': host}}})

    def test_builder_rejects_remote_or_container_driver_before_sending_build_context(self):
        self.module.validate_builder('Name: default\nDriver: docker\nNodes:\nName: default\nEndpoint: default\n', 'default')
        for text in ('Name: default\nDriver: docker-container\nEndpoint: default\n',
                     'Name: default\nDriver: docker\nEndpoint: tcp://remote:2375\n',
                     'Name: default\nDriver: docker\nEndpoint: default\nEndpoint: other\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.module.validate_builder(text, 'default')

    def test_real_command_bounds_output_and_timeout_without_echoing_private_data(self):
        self.assertEqual(self.module.bounded_command([sys.executable, '-c', 'print("ok")'], timeout=3, limit=1024), 'ok\n')
        for program in ('print("PRIVATE" * 2000)', 'import time; time.sleep(10)'):
            with self.subTest(program=program), self.assertRaises(RuntimeError) as error:
                self.module.bounded_command([sys.executable, '-c', program], timeout=.2, limit=1024)
            self.assertNotIn('PRIVATE', str(error.exception))

    def test_command_failure_retains_only_exit_number_and_fixed_cause_categories(self):
        program = 'import sys;sys.stderr.write("PRIVATE arbitrary-value permission denied");sys.exit(7)'
        with self.assertRaises(RuntimeError) as caught:
            self.module.bounded_command([sys.executable, '-c', program], timeout=3, limit=1024)
        result = self.module.failure_summary(caught.exception)
        self.assertEqual(result, {'category': 'nonzero_exit', 'exit_code': 7, 'causes': ['permission_denied']})
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertNotIn('arbitrary-value', str(caught.exception))

    def test_startup_diagnostics_publish_only_fixed_owned_states_and_constraint_fields(self):
        records = {IDS[name]: container(name) for name in IDS}
        records[IDS['redis']]['State'] = {'Running': False, 'ExitCode': 1, 'OOMKilled': False,
            'Error': 'PRIVATE service value', 'Health': {'Status': 'unhealthy', 'FailingStreak': 3}}
        records[IDS['redis']]['HostConfig']['MemorySwap'] = -1
        volume = {'Name': PROJECT + '_redis-data', 'Driver': 'local', 'Options': {},
            'Labels': {'io.appguard.owner': OWNER, 'com.docker.compose.project': PROJECT, 'io.appguard.scope': 'spring-ingress-v1'}}
        class DiagnosticDocker(FakeDocker):
            def call(self, args, **kwargs):
                if args[0] == 'logs':
                    return 'PRIVATE request=value append-only file: Permission denied'
                return super().call(args, **kwargs)
        result = self.module.startup_diagnostics(DiagnosticDocker(records, volume=volume), PROJECT, OWNER, ValueError('PRIVATE'))
        self.assertTrue(result['complete'])
        self.assertEqual(result['discovered_containers'], 3)
        self.assertTrue(result['volume_owned_valid'])
        redis = result['services']['redis']
        self.assertTrue(redis['present'])
        self.assertFalse(redis['running'])
        self.assertEqual(redis['exit_code'], 1)
        self.assertEqual(redis['health'], 'unhealthy')
        self.assertEqual(redis['limits']['swap_bytes'], -1)
        self.assertFalse(redis['constraints']['swap_bounded'])
        self.assertEqual(redis['log_causes'], ['permission_denied'])
        self.assertEqual(set(result), {'schema','complete','budget_exhausted','discovered_containers',
            'ownership_rejections','metadata_errors','failure','services','volume_owned_valid'})
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertNotIn(OWNER, json.dumps(result))
        self.assertNotIn(PROJECT, json.dumps(result))

    def test_startup_diagnostics_skip_foreign_logs_and_survive_unavailable_daemon(self):
        record = container('backend')
        record['Config']['Labels']['io.appguard.owner'] = 'foreign'
        class ForeignDocker(FakeDocker):
            def call(self, args, **kwargs):
                if args[0] == 'logs':
                    raise AssertionError('must not read a foreign container log')
                return super().call(args, **kwargs)
        result = self.module.startup_diagnostics(ForeignDocker({IDS['backend']: record}), PROJECT, OWNER, RuntimeError('PRIVATE'))
        self.assertEqual(result['ownership_rejections'], 1)
        self.assertFalse(result['services']['backend']['present'])
        self.assertFalse(result['complete'])
        self.assertEqual(set(result['services']['backend']), {'present','running','exit_code','oom_killed',
            'state_error_present','state_error_causes','health','health_failures','restart_count','constraints','limits','log_causes'})
        class UnavailableDocker:
            def call(self, args, **kwargs):
                raise OSError('PRIVATE daemon failure')
        result = self.module.startup_diagnostics(UnavailableDocker(), PROJECT, OWNER, OSError('PRIVATE'))
        self.assertFalse(result['complete'])
        self.assertGreater(result['metadata_errors'], 0)
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_never_started_state_error_retains_only_fixed_runtime_cause_codes(self):
        volume = {'Name': PROJECT + '_redis-data', 'Driver': 'local', 'Options': {},
            'Labels': {'io.appguard.owner': OWNER, 'com.docker.compose.project': PROJECT, 'io.appguard.scope': 'spring-ingress-v1'}}
        class NeverStartedDocker(FakeDocker):
            def call(self, args, **kwargs):
                if args[0] == 'logs':
                    raise RuntimeError('logs unavailable for never-started container')
                return super().call(args, **kwargs)
        cases = [
            ('OCI runtime create failed: exec: /PRIVATE_PATH/python: no such file or directory',
                ['file_missing','container_runtime_failure']),
            ('exec /PRIVATE_PATH/python: exec format error', ['invalid_executable']),
            ('cannot configure cgroup /PRIVATE_PATH: operation not permitted',
                ['operation_not_permitted','cgroup_failure']),
            ('sysctl /PRIVATE_PATH: permission denied', ['permission_denied','sysctl_failure']),
            ('failed to mount /PRIVATE_PATH: invalid argument', ['mount_failure']),
        ]
        for message, causes in cases:
            record = container('gateway')
            record['State'] = {'Running':False,'ExitCode':128,'Error':message+' PRIVATE_TOKEN=secret'}
            with self.subTest(causes=causes):
                result = self.module.startup_diagnostics(NeverStartedDocker({IDS['gateway']:record},volume=volume),
                    PROJECT, OWNER, RuntimeError('PRIVATE message'))
                observed = result['services']['gateway']
                self.assertEqual(observed['state_error_causes'],causes)
                self.assertEqual(observed['exit_code'],128)
                self.assertEqual(observed['log_causes'],[])
                self.assertNotIn('PRIVATE',json.dumps(result))
                self.assertNotIn('secret',json.dumps(result))

    def test_startup_diagnostic_budget_exhaustion_makes_no_daemon_call(self):
        class UnusedDocker:
            def call(self, args, **kwargs):
                raise AssertionError('diagnostic deadline already expired')
        with patch.object(self.module.time, 'monotonic', side_effect=[0,13,13]):
            result = self.module.startup_diagnostics(UnusedDocker(), PROJECT, OWNER, ValueError('PRIVATE'))
        self.assertTrue(result['budget_exhausted'])
        self.assertFalse(result['complete'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_startup_subphase_stops_at_the_failed_component_boundary(self):
        records = {name: container(name) for name in IDS}
        volume = {'Name': PROJECT + '_redis-data', 'Driver': 'local', 'Options': {},
            'Labels': {'io.appguard.owner': OWNER, 'com.docker.compose.project': PROJECT, 'io.appguard.scope': 'spring-ingress-v1'}}
        for failure, phase in [('compose','startup_compose_up'),('records','startup_runtime_inspection'),
                ('volume','startup_volume_inspection'),('readiness','startup_readiness'),('effective','startup_effective_restrictions')]:
            class StartupDocker(FakeDocker):
                version = 'test-version'
                def call(self, args, **kwargs):
                    if args[0] == 'compose':
                        if failure == 'compose':
                            raise RuntimeError('PRIVATE')
                        return ''
                    return super().call(args, **kwargs)
            report = {'checks': {}}
            def failed():
                raise ValueError('PRIVATE')
            with self.subTest(failure=failure), \
                    patch.object(self.module, 'records_for', side_effect=lambda *args: failed() if failure == 'records' else records), \
                    patch.object(self.module, 'inspect_volume', side_effect=lambda *args: failed() if failure == 'volume' else volume), \
                    patch.object(self.module, 'wait_ready', side_effect=lambda *args: failed() if failure == 'readiness' else None), \
                    patch.object(self.module, 'effective_restrictions', side_effect=lambda *args: failed() if failure == 'effective' else None):
                with self.assertRaises((ValueError, RuntimeError)):
                    self.module.run_startup(StartupDocker({}, volume=volume), ['compose'], report, PROJECT, OWNER)
            self.assertEqual(report['phase'], phase)

    def test_successful_command_stops_owned_grandchild_after_redirected_output(self):
        # The command exits successfully and closes its pipe, but its child
        # still belongs to our process group despite redirecting both streams.
        program = ('import os,subprocess,sys; '
            'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"],'
            'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); '
            'print(p.pid,os.getpid())')
        output = self.module.bounded_command([sys.executable, '-c', program], timeout=3, limit=1024)
        pid, group = map(int, output.split())
        try:
            deadline = time.monotonic() + 1
            stopped = False
            while time.monotonic() < deadline:
                observed = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)],
                    capture_output=True, text=True, timeout=1)
                # An exited orphan may remain briefly as a zombie until init
                # reaps it. It cannot execute or retain a live pipe/process.
                status = observed.stdout.strip()
                if observed.returncode != 0 or not status or status.startswith('Z'):
                    stopped = True
                    break
                time.sleep(.02)
            self.assertTrue(stopped, 'successful command leaked its owned process group')
        finally:
            # Preserve test isolation even when exercising the unfixed runner.
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_receipt_publication_uses_held_directory_and_private_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve()
            with self.module.ReceiptDirectory(path) as output:
                output.publish('{"technical_verification":false}\n')
            self.assertEqual((path / 'receipt.json').read_text(), '{"technical_verification":false}\n')
            self.assertEqual((path / 'receipt.json').stat().st_mode & 0o777, 0o600)

    def test_receipt_rejects_output_swap_before_publication_without_touching_other_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            path, moved, foreign = base / 'out', base / 'moved', base / 'foreign'
            path.mkdir(); foreign.mkdir()
            with self.module.ReceiptDirectory(path) as output:
                path.rename(moved)
                path.symlink_to(foreign, target_is_directory=True)
                with self.assertRaises(ValueError):
                    output.publish('{}\n')
            self.assertEqual(list(foreign.iterdir()), [])
            self.assertEqual(list(moved.iterdir()), [])

    def test_receipt_rolls_back_own_file_when_ancestor_changes_during_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            parent, moved, foreign = base / 'parent', base / 'moved', base / 'foreign'
            parent.mkdir(); foreign.mkdir()
            path = parent / 'out'; path.mkdir()
            (foreign / 'out').mkdir()
            (foreign / 'out/keep').write_text('existing')
            original_write = os.write
            def swapped_write(descriptor, value):
                result = original_write(descriptor, value)
                parent.rename(moved)
                parent.symlink_to(foreign, target_is_directory=True)
                return result
            with self.module.ReceiptDirectory(path) as output:
                with patch.object(self.module.os, 'write', side_effect=swapped_write):
                    with self.assertRaises(ValueError):
                        output.publish('{}\n')
            self.assertEqual(list((moved / 'out').iterdir()), [])
            self.assertEqual([file.name for file in (foreign / 'out').iterdir()], ['keep'])
            self.assertEqual((foreign / 'out/keep').read_text(), 'existing')

    def test_candidate_commit_accepts_only_exact_sha1_or_sha256_length(self):
        for length in (40, 64):
            self.assertTrue(self.module.valid_commit('a' * length))
        for length in (0, 39, 41, 63, 65):
            self.assertFalse(self.module.valid_commit('a' * length))
        self.assertFalse(self.module.valid_commit('A' * 40))

    def test_runtime_accepts_only_shared_namespace_and_loopback_gateway_publication(self):
        records = {name: container(name) for name in IDS}
        result = self.module.validate_runtime(records, PROJECT, OWNER)
        self.assertEqual(result['gateway_port'], 43123)
        self.assertEqual(result['container_ids'], IDS)
        self.assertNotIn('Config', result)

    def test_runtime_rejects_escape_root_unbounded_limits_or_writable_secret(self):
        original = {name: container(name) for name in IDS}
        changes = [
            ('backend', ('HostConfig', 'NetworkMode'), 'host'),
            ('backend', ('HostConfig', 'PortBindings'), {'8444/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8444'}]}),
            ('gateway', ('HostConfig', 'PortBindings'), {'8443/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '8443'}]}),
            ('redis', ('Config', 'User'), '0:0'),
            ('gateway', ('HostConfig', 'ReadonlyRootfs'), False),
            ('redis', ('HostConfig', 'Memory'), 0),
            ('backend', ('HostConfig', 'MemorySwap'), -1),
            ('gateway', ('HostConfig', 'PidsLimit'), -1),
            ('gateway', ('HostConfig', 'NanoCpus'), 0),
            ('backend', ('HostConfig', 'Privileged'), True),
            ('gateway', ('HostConfig', 'CapAdd'), ['SYS_ADMIN']),
            ('redis', ('HostConfig', 'CapDrop'), []),
            ('backend', ('HostConfig', 'SecurityOpt'), []),
            ('redis', ('HostConfig', 'Tmpfs'), {'/tmp': 'rw,size=0'}),
            ('gateway', ('Mounts',), [{'Type': 'bind', 'Destination': '/run/secrets/key', 'RW': True}]),
        ]
        for name, path, value in changes:
            with self.subTest(name=name, path=path):
                records = copy.deepcopy(original)
                cursor = records[name]
                for key in path[:-1]:
                    cursor = cursor[key]
                cursor[path[-1]] = value
                with self.assertRaises((ValueError, AssertionError)):
                    self.module.validate_runtime(records, PROJECT, OWNER)

    def test_runtime_rejects_ownership_mismatch_before_accepting_receipt(self):
        records = {name: container(name) for name in IDS}
        records['backend']['Config']['Labels']['io.appguard.owner'] = 'another-owner'
        with self.assertRaises(ValueError):
            self.module.validate_runtime(records, PROJECT, OWNER)

    def test_runtime_uses_actual_ephemeral_port_and_rejects_nonloopback_mapping(self):
        records = {name: container(name) for name in IDS}
        records['gateway']['HostConfig']['PortBindings']['8443/tcp'][0]['HostPort'] = '0'
        result = self.module.validate_runtime(records, PROJECT, OWNER)
        self.assertEqual(result['gateway_port'], 43123)
        records['gateway']['NetworkSettings']['Ports']['8443/tcp'][0]['HostIp'] = '0.0.0.0'
        with self.assertRaises(ValueError):
            self.module.validate_runtime(records, PROJECT, OWNER)

    def test_cleanup_rechecks_each_id_and_continues_after_foreign_container(self):
        records = {IDS[name]: container(name) for name in IDS}
        records[IDS['backend']]['Config']['Labels']['io.appguard.owner'] = 'foreign'
        docker = FakeDocker(records)
        self.assertFalse(self.module.cleanup_owned(docker, PROJECT, OWNER))
        touched = [args[-1] for args in docker.mutations]
        self.assertNotIn(IDS['backend'], touched)
        self.assertIn(IDS['gateway'], touched)
        self.assertIn(IDS['redis'], touched)
        self.assertTrue(all(args[0] == 'container' for args in docker.mutations))

    def test_cleanup_never_removes_foreign_or_in_use_network(self):
        network = {'Id': 'd' * 64, 'Labels': {'io.appguard.owner': OWNER,
            'com.docker.compose.project': PROJECT, 'io.appguard.scope': 'spring-ingress-v1'}, 'Containers': {'foreign': {}}}
        docker = FakeDocker({}, network)
        self.assertFalse(self.module.cleanup_owned(docker, PROJECT, OWNER))
        self.assertEqual(docker.mutations, [])
        network['Containers'] = {}
        network['Labels']['io.appguard.owner'] = 'foreign'
        self.assertFalse(self.module.cleanup_owned(docker, PROJECT, OWNER))
        self.assertEqual(docker.mutations, [])

    def test_cleanup_rechecks_ownership_between_stop_and_remove(self):
        original = container('gateway')
        class ChangedDocker(FakeDocker):
            def call(self, args, **kwargs):
                result = super().call(args, **kwargs)
                if args[:2] == ['container', 'stop']:
                    self.records[args[-1]]['Config']['Labels']['io.appguard.owner'] = 'foreign'
                return result
        docker = ChangedDocker({IDS['gateway']: original})
        self.assertFalse(self.module.cleanup_owned(docker, PROJECT, OWNER))
        self.assertEqual([command[1] for command in docker.mutations], ['stop'])

    def test_cleanup_continues_other_owned_children_after_engine_oserror(self):
        class FailingDocker(FakeDocker):
            def call(self, args, **kwargs):
                if args[:2] == ['container', 'stop'] and args[-1] == IDS['backend']:
                    raise OSError('private daemon failure')
                return super().call(args, **kwargs)
        docker = FailingDocker({IDS[name]: container(name) for name in IDS})
        self.assertFalse(self.module.cleanup_owned(docker, PROJECT, OWNER))
        self.assertEqual(set(docker.records), {IDS['backend']})

    def test_redis_restart_never_signals_foreign_container(self):
        record = container('redis')
        record['Config']['Labels']['io.appguard.owner'] = 'foreign'
        docker = FakeDocker({IDS['redis']: record})
        with self.assertRaises(ValueError):
            self.module.restart_redis(docker, IDS['redis'], PROJECT, OWNER,
                8443, None, None, b'previous-request', None)
        self.assertEqual(docker.mutations, [])

    def test_redis_restart_demands_outage_denial_recovery_and_retained_original_nonce(self):
        local_wire = self.module.helpers().wire
        for failure in (None, 'outage_accepted', 'replay_accepted', 'unsafe_config', 'slow_recovery'):
            class RestartDocker(FakeDocker):
                restarted = False
                def call(self, args, **kwargs):
                    if args[:2] == ['container', 'start']:
                        self.restarted = True
                        self.records[IDS['redis']]['State']['Running'] = True
                        self.mutations.append(args)
                        return IDS['redis']
                    if args[0] == 'exec':
                        if 'CONFIG' in args:
                            pairs = ['appendonly','yes','appendfsync','everysec' if failure == 'unsafe_config' else 'always',
                                'maxmemory','67108864','maxmemory-policy','noeviction','bind','127.0.0.1','port','6379','dir','/data','save','']
                            return json.dumps(pairs)
                        if args[-1] == 'server':
                            return 'run_id:' + ('1' if self.restarted else '0') * 40 + '\r\n'
                        return 'aof_enabled:1\r\naof_last_write_status:ok\r\naof_current_size:100\r\nloading:0\r\n'
                    result = super().call(args, **kwargs)
                    if args[:2] == ['container', 'stop']:
                        self.records[IDS['redis']]['State']['Running'] = False
                    return result
            class Local:
                wire = staticmethod(local_wire)
                calls = 0
                @staticmethod
                def counters(path):
                    return {'resource': 0}
                def exchange(self, port, tls, data):
                    self.calls += 1
                    if self.calls == 1:
                        return (200,b'bad') if failure == 'outage_accepted' else (503,b'{"code":"REPLAY_STORE_UNAVAILABLE"}')
                    if self.calls == 2:
                        return 200, data.split(b'\r\n\r\n', 1)[1]
                    return (200,b'bad') if failure == 'replay_accepted' else (403,b'{"code":"REPLAY_DETECTED"}')
            class Signer:
                def headers(self, target, body):
                    return []
            volume = {'Name': PROJECT + '_redis-data', 'Driver': 'local', 'Options': {},
                'Labels': {'io.appguard.owner': OWNER, 'com.docker.compose.project': PROJECT, 'io.appguard.scope': 'spring-ingress-v1'}}
            docker = RestartDocker({IDS['redis']: container('redis')}, volume=volume)
            with self.subTest(failure=failure):
                if failure == 'slow_recovery':
                    with patch.object(self.module.time, 'monotonic', side_effect=[0, 0, 0, 0, 16]):
                        with self.assertRaises(ValueError):
                            self.module.restart_redis(docker, IDS['redis'], PROJECT, OWNER, 8443, None,
                                Signer(), b'original', Local(), Path('/private/test-counter'))
                elif failure:
                    with self.assertRaises(ValueError):
                        self.module.restart_redis(docker, IDS['redis'], PROJECT, OWNER, 8443, None,
                            Signer(), b'original', Local(), Path('/private/test-counter'))
                else:
                    result = self.module.restart_redis(docker, IDS['redis'], PROJECT, OWNER, 8443, None,
                        Signer(), b'original', Local(), Path('/private/test-counter'))
                    self.assertEqual(result['original_replay_status'], 403)
                    self.assertTrue(result['run_identity_changed'])
                    self.assertEqual([args[1] for args in docker.mutations], ['stop', 'start'])

    def test_sigterm_unwinds_cleanup_and_restores_original_handler(self):
        previous = signal.getsignal(signal.SIGTERM)
        cleaned = []
        with self.assertRaises(KeyboardInterrupt):
            with self.module.cancellation_scope():
                try:
                    os.kill(os.getpid(), signal.SIGTERM)
                finally:
                    cleaned.append(True)
        self.assertEqual(cleaned, [True])
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_runtime_requires_complete_leaf_mount_set_and_persistent_redis(self):
        for name in IDS:
            records = {role: container(role) for role in IDS}
            records[name]['Mounts'] = []
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.module.validate_runtime(records, PROJECT, OWNER)

    def test_cleanup_removes_only_newly_owned_containers_and_empty_owned_network(self):
        network = {'Id': 'd' * 64, 'Labels': {'io.appguard.owner': OWNER,
            'com.docker.compose.project': PROJECT, 'io.appguard.scope': 'spring-ingress-v1'}, 'Containers': {}}
        docker = FakeDocker({IDS[name]: container(name) for name in IDS}, network)
        self.assertTrue(self.module.cleanup_owned(docker, PROJECT, OWNER))
        self.assertEqual(docker.records, {})
        self.assertIsNone(docker.network)
        stopped = [args[-1] for args in docker.mutations if args[:2] == ['container', 'stop']]
        self.assertEqual(stopped[-1], IDS['gateway'])

    def test_cleanup_reports_remaining_owned_container_even_if_rm_returns_success(self):
        class NonremovingDocker(FakeDocker):
            def call(self, args, **kwargs):
                if args[:2] == ['container', 'rm']:
                    return args[-1]
                return super().call(args, **kwargs)
        docker = NonremovingDocker({IDS['gateway']: container('gateway')})
        self.assertFalse(self.module.cleanup_owned(docker, PROJECT, OWNER))

    def test_cleanup_removes_owned_persistence_only_after_all_references_are_gone(self):
        volume = {'Name': PROJECT + '_redis-data', 'Driver': 'local', 'Options': {},
            'Labels': {'io.appguard.owner': OWNER, 'com.docker.compose.project': PROJECT,
                       'io.appguard.scope': 'spring-ingress-v1'}}
        docker = FakeDocker({}, volume=volume)
        self.assertTrue(self.module.cleanup_owned(docker, PROJECT, OWNER))
        self.assertIsNone(docker.volume)
        for foreign, references in ((True, []), (False, ['e' * 64])):
            copy_volume = copy.deepcopy(volume)
            if foreign:
                copy_volume['Labels']['io.appguard.owner'] = 'foreign'
            docker = FakeDocker({}, volume=copy_volume, references=references)
            self.assertFalse(self.module.cleanup_owned(docker, PROJECT, OWNER))
            self.assertIsNotNone(docker.volume)
            self.assertEqual(docker.mutations, [])

    def test_cleanup_verifies_owned_volume_and_network_are_actually_removed(self):
        class NonremovingDocker(FakeDocker):
            def call(self, args, **kwargs):
                if args[:2] in (['network', 'rm'], ['volume', 'rm']):
                    return args[-1]
                return super().call(args, **kwargs)
        labels = {'io.appguard.owner': OWNER, 'com.docker.compose.project': PROJECT, 'io.appguard.scope': 'spring-ingress-v1'}
        for network, volume in (({'Id': 'd' * 64, 'Labels': labels, 'Containers': {}}, None),
                (None, {'Name': PROJECT + '_redis-data', 'Driver': 'local', 'Options': {}, 'Labels': labels})):
            with self.subTest(network=network is not None):
                self.assertFalse(self.module.cleanup_owned(NonremovingDocker({}, network, volume), PROJECT, OWNER))

    def test_runtime_accepts_only_owned_named_redis_data_volume(self):
        records = {name: container(name) for name in IDS}
        records['redis']['Mounts'] = [{'Type': 'volume', 'Destination': '/data',
            'Name': PROJECT + '_redis-data', 'Driver': 'local', 'RW': True}]
        self.module.validate_runtime(records, PROJECT, OWNER)
        records['redis']['Mounts'][0]['Name'] = 'existing-customer-data'
        with self.assertRaises(ValueError):
            self.module.validate_runtime(records, PROJECT, OWNER)

    def test_source_hashes_cover_deployment_and_locks_and_detect_new_files(self):
        hashes = self.module.source_hashes()
        for name in ('sdk/python/uv.lock', 'sdk/python/pyproject.toml', 'sdk/spring-boot/pom.xml',
                     'examples/spring-ingress/backend/pom.xml', 'deploy/spring-ingress/compose.json'):
            self.assertIn(name, hashes)
        self.assertTrue(all(len(value) == 64 for value in hashes.values()))


if __name__ == '__main__':
    unittest.main()
