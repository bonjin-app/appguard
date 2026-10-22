"""Sustained container qualification: real boundaries, fixed private evidence."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from test_spring_containers import FakeDocker, IDS, OWNER, PROJECT, ROOT, container, load_module


def records():
    result = {name: container(name) for name in IDS}
    for record in result.values():
        record['RestartCount'] = 0
        record['State'].update(OOMKilled=False, ExitCode=0, StartedAt='2026-10-22T12:00:00.000000000Z')
    return result


def stats_rows():
    return '\n'.join(json.dumps({'ID': identifier, 'Name': 'PRIVATE', 'CPUPerc': '12.34%',
        'MemUsage': '48.125MiB / 128MiB', 'PIDs': '9', 'NetIO': 'PRIVATE'}) for identifier in IDS.values())


def cgroup_text():
    return ('[memory.current]\n52428800\n[memory.max]\n134217728\n'
        '[memory.swap.max]\n0\n[memory.swap.current]\n0\n'
        '[memory.events]\nlow 0\nhigh 0\nmax 2\noom 0\noom_kill 0\noom_group_kill 0\n'
        '[cpu.stat]\nusage_usec 12345\nuser_usec 10000\nsystem_usec 2345\n'
        'nr_periods 50\nnr_throttled 4\nthrottled_usec 6789\n'
        '[cpu.max]\n50000 100000\n[pids.current]\n9\n[pids.max]\n32\n')


def successful_result(local):
    latency = local.LatencyMetrics(); outcomes = local.OutcomeMetrics()
    for _ in range(2):
        for role, response in (('normal', (200, b'body')), ('replay', (403, b'{"code":"REPLAY_DETECTED"}'))):
            latency.observe(.02); outcomes.observe(role, response)
    return {'signed_requests': 2, 'replay_requests': 2, 'fidelity_failures': 0, 'replay_failures': 0,
        'transport_errors': 0, 'requested_seconds': 1, 'concurrency': 8, 'elapsed_seconds': 1.01,
        'requests_per_second': 4 / 1.01, 'error_rate': 0., 'latency': latency.report(), 'outcomes': outcomes.report()}


class ContainerSoakTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_options_reject_nonintegers_and_out_of_bounds_before_owned_work(self):
        for seconds, concurrency in ((0, 1), (1, 32), (3600, 8)):
            self.module.validate_soak_options(seconds, concurrency)
        for seconds, concurrency in ((-1, 8), (3601, 8), (1, 0), (1, 33),
                (True, 8), (1., 8), ('1', 8), (1, False), (1, 8.)):
            with self.subTest(seconds=seconds, concurrency=concurrency), self.assertRaises(ValueError):
                self.module.validate_soak_options(seconds, concurrency)

    def test_invalid_cli_options_do_not_create_output_or_contact_docker(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, value in (('--soak-seconds', '3601'), ('--soak-concurrency', '0')):
                output = Path(directory) / 'uncreated'
                result = subprocess.run([sys.executable, str(ROOT / 'scripts/qualification/spring_containers.py'),
                    '--output', str(output), '--docker-context', 'default', name, value],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 1)
                self.assertFalse(output.exists())
                self.assertEqual(result.stderr, 'SPRING_CONTAINER_QUALIFICATION_FAILED\n')

    def test_actual_stats_normalize_units_and_drop_names_and_unrelated_fields(self):
        result = self.module.normalize_stats(stats_rows(), IDS)
        self.assertEqual(result['backend'], {'cpu_percent': 12.34, 'memory_bytes': 50462720,
            'memory_limit_bytes': 134217728, 'pids': 9})
        self.assertNotIn('PRIVATE', json.dumps(result))
        for broken in (stats_rows().replace('12.34%', 'NaN%'),
                stats_rows().replace('48.125MiB', '-1MiB'),
                stats_rows().replace(IDS['backend'], 'f' * 64), stats_rows() + '\n' + stats_rows()):
            with self.subTest(broken=broken[:40]), self.assertRaises(ValueError):
                self.module.normalize_stats(broken, IDS)

    def test_cgroup_v2_numeric_readback_requires_effective_limits(self):
        host = records()['redis']['HostConfig']
        result = self.module.normalize_cgroup(cgroup_text(), host)
        self.assertEqual(result['version'], 2)
        self.assertEqual(result['memory_bytes'], 52428800)
        self.assertEqual(result['memory_oom_kills'], 0)
        self.assertEqual(result['cpu_throttled_usec'], 6789)
        self.assertEqual(result['pids_limit'], 32)
        for broken in (cgroup_text().replace('134217728', 'max'),
                cgroup_text().replace('50000 100000', '100000 100000'),
                cgroup_text().replace('[pids.max]\n32', '[pids.max]\n64'),
                cgroup_text().replace('oom 0', 'oom PRIVATE'), cgroup_text() + '[memory.max]\n134217728\n'):
            with self.subTest(broken=broken[:40]), self.assertRaises(ValueError):
                self.module.normalize_cgroup(broken, host)

    def test_effective_cgroup_swap_requires_present_numeric_zero_limit_and_usage(self):
        host = records()['redis']['HostConfig']
        result = self.module.normalize_cgroup(cgroup_text(), host)
        self.assertEqual(result['swap_limit_bytes'], 0)
        self.assertEqual(result['swap_bytes'], 0)
        for broken in (cgroup_text().replace('[memory.swap.max]\n0\n', ''),
                cgroup_text().replace('[memory.swap.current]\n0\n', ''),
                cgroup_text().replace('[memory.swap.max]\n0', '[memory.swap.max]\nmax'),
                cgroup_text().replace('[memory.swap.max]\n0', '[memory.swap.max]\n4096'),
                cgroup_text().replace('[memory.swap.current]\n0', '[memory.swap.current]\n4096')):
            with self.subTest(readback=broken), self.assertRaises(ValueError):
                self.module.normalize_cgroup(broken, host)

    def test_resource_sample_is_owned_only_and_detects_oom_restart_or_restriction_change(self):
        original = records()
        class ResourceDocker(FakeDocker):
            def call(self, args, **kwargs):
                if args[0] == 'stats':
                    self.stats_args = args
                    return stats_rows()
                if args[0] == 'exec':
                    return cgroup_text()
                return super().call(args, **kwargs)
        docker = ResourceDocker(copy.deepcopy({record['Id']: record for record in original.values()}))
        before = self.module.sample_container_resources(docker, original, PROJECT, OWNER)
        self.assertTrue(set(IDS.values()) <= set(docker.stats_args))
        self.module.require_resource_continuity(before, before)
        for mutation in ('oom', 'restart', 'start', 'limit', 'image'):
            after = copy.deepcopy(before)
            if mutation == 'oom':
                after['backend']['cgroup']['memory_oom_kills'] += 1
            elif mutation == 'restart':
                after['backend']['state']['restart_count'] += 1
            elif mutation == 'start':
                after['backend']['state']['started_at'] = '2026-10-22T12:01:00.000000000Z'
            else:
                after['backend']['restriction_sha256'] = 'f' * 64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.module.require_resource_continuity(before, after)
        docker.records[IDS['backend']]['Config']['Labels']['io.appguard.owner'] = 'foreign'
        with self.assertRaises(ValueError):
            self.module.sample_container_resources(docker, original, PROJECT, OWNER)

    def test_restriction_inspection_rejects_actual_limit_or_image_change(self):
        for key in ('Memory', 'Image'):
            original = records(); current = copy.deepcopy(original)
            if key == 'Memory':
                current['backend']['HostConfig']['Memory'] *= 2
                current['backend']['HostConfig']['MemorySwap'] *= 2
            else:
                current['backend']['Image'] = 'sha256:' + 'f' * 64
            docker = FakeDocker({row['Id']: row for row in current.values()})
            with self.subTest(change=key), self.assertRaises(ValueError):
                self.module.sample_container_resources(docker, original, PROJECT, OWNER)

    def test_sustained_result_requires_exact_outcomes_zero_errors_and_bounded_time(self):
        local = self.module.helpers(); result = successful_result(local)
        self.module.normalize_soak_result(result, 1, 8, local)
        self.module.require_sustained_success(result, local)
        for mutation in ('timeout', 'replay_accepted', 'bad_body', 'transport', 'time', 'histogram', 'private_field'):
            changed = copy.deepcopy(result)
            if mutation == 'timeout':
                changed['outcomes']['normal']['statuses'] = [{'status': 504, 'count': 2}]
            elif mutation == 'replay_accepted':
                changed['outcomes']['replay']['statuses'] = [{'status': 200, 'count': 2}]
            elif mutation == 'bad_body':
                changed['fidelity_failures'] = 1
            elif mutation == 'transport':
                changed['transport_errors'] = 1
            elif mutation == 'time':
                changed['elapsed_seconds'] = 12
            elif mutation == 'histogram':
                changed['latency']['histogram_counts'][0] += 1
            else:
                changed['PRIVATE'] = 'request-secret'
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, AssertionError)):
                self.module.normalize_soak_result(changed, 1, 8, local)
                self.module.require_sustained_success(changed, local)

    def test_bounded_traffic_observer_failure_stops_its_process_before_returning(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'pid'
            program = 'import os,sys,time;open(sys.argv[1],"w").write(str(os.getpid()));time.sleep(30)'
            def failed_sample():
                raise ValueError('fixed sample failure')
            with self.assertRaises(ValueError):
                self.module.bounded_command([sys.executable, '-c', program, str(path)], timeout=3,
                    observer=failed_sample, observer_interval=.05)
            pid = int(path.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_private_control_rejects_links_permissions_and_extra_secret_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'control.json'
            self.module.write_private(path, json.dumps({'PRIVATE': 'not published'}))
            self.assertEqual(self.module.read_private_control(path), {'PRIVATE': 'not published'})
            os.chmod(path, 0o644)
            with self.assertRaises(ValueError):
                self.module.read_private_control(path)
            os.chmod(path, 0o600)
            link = path.with_name('link')
            link.symlink_to(path)
            with self.assertRaises((ValueError, OSError)):
                self.module.read_private_control(link)
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/qualification/spring_containers.py'),
                '--traffic-control', str(path)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, '')
            self.assertEqual(result.stderr, 'SPRING_CONTAINER_TRAFFIC_FAILED\n')

    def test_backend_restart_preserves_replay_and_never_signals_foreign_service(self):
        for foreign in (False, True):
            original = records(); engine = copy.deepcopy(original)
            if foreign: engine['backend']['Config']['Labels']['io.appguard.owner'] = 'foreign'
            with tempfile.TemporaryDirectory() as directory:
                counter = Path(directory) / 'counter'
                self.module.write_private(counter, 'old counts')
                class RestartDocker(FakeDocker):
                    def call(self, args, **kwargs):
                        if args[:2] == ['container', 'stop']:
                            self.mutations.append(args)
                            self.records[args[-1]]['State']['Running'] = False
                            return args[-1]
                        if args[:2] == ['container', 'start']:
                            self.mutations.append(args)
                            self.assert_counter_reset = counter.read_bytes() == b''
                            self.records[args[-1]]['State']['Running'] = True
                            self.records[args[-1]]['State']['StartedAt'] = '2026-10-22T12:01:00.000000000Z'
                            return args[-1]
                        return super().call(args, **kwargs)
                docker = RestartDocker({row['Id']: row for row in engine.values()})
                local = self.module.helpers(); signer = SimpleNamespace(headers=lambda *args: [])
                with patch.object(self.module, 'redis_values', return_value={'run_id': 'a' * 40}), \
                        patch.object(self.module, 'wait_ready'), patch.object(self.module.secrets, 'token_bytes', return_value=b'body'), \
                        patch.object(local, 'exchange', side_effect=[(200, b'body'), (200, b'body'), (403, b'{"code":"REPLAY_DETECTED"}')]):
                    if foreign:
                        with self.assertRaises(ValueError):
                            self.module.restart_backend(docker, original, PROJECT, OWNER, 1, None, signer, local, counter)
                        self.assertEqual(docker.mutations, [])
                        self.assertEqual(counter.read_text(), 'old counts')
                    else:
                        result = self.module.restart_backend(docker, original, PROJECT, OWNER, 1, None, signer, local, counter)
                        self.assertTrue(result['recovered'])
                        self.assertTrue(result['redis_run_unchanged'])
                        self.assertTrue(docker.assert_counter_reset)

    def test_operational_child_uses_private_control_and_preserves_successful_metrics(self):
        local = self.module.helpers(); result = successful_result(local)
        original = records()
        sample = {name: {'state': {'running': True, 'oom_killed': False, 'exit_code': 0,
            'restart_count': 0, 'started_at': row['State']['StartedAt']}, 'restriction_sha256': 'a' * 64,
            'docker': {'memory_bytes': 1, 'cpu_percent': 1.},
            'cgroup': self.module.normalize_cgroup(cgroup_text(), row['HostConfig'])} for name, row in original.items()}
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory).resolve(); signer = local.Signer(private)
            report = self.module.new_operational(1, 8)
            def command(args, **kwargs):
                self.assertNotIn(signer.token, str(args) + str(kwargs.get('env')))
                control = self.module.read_private_control(Path(args[-1]))
                self.assertEqual(control['token'], signer.token)
                self.assertEqual(set(control), {'seconds', 'concurrency', 'port', 'ca_file', 'private_key', 'token'})
                return json.dumps(result)
            before = {name: 0 for name in ('dispatch', 'auth', 'key', 'replay', 'resource')}
            after = {name: 4 if name != 'resource' else 2 for name in before}
            with patch.object(self.module, 'sample_container_resources', return_value=sample), \
                    patch.object(self.module, 'bounded_command', side_effect=command), \
                    patch.object(self.module, 'restart_backend', return_value={'recovered': True}), \
                    patch.object(local, 'counters', side_effect=[before, after]):
                self.module.run_operational(report, 1, 8, FakeDocker({}), original, PROJECT, OWNER, 1, None, signer, local, private)
            self.assertEqual(report['soak'], result)
            self.assertEqual(report['resources']['samples'], 2)
            self.assertTrue(report['checks']['sustained_traffic'])
            self.assertTrue(report['checks']['counter_fidelity'])
            self.assertTrue(report['checks']['no_oom_or_restart'])
            self.assertNotIn(signer.token, json.dumps(report))

    def test_failed_sustained_stage_keeps_core_receipt_and_owned_cleanup(self):
        local = self.module.helpers()
        sample = records()
        inspected = self.module.validate_runtime(sample, PROJECT, OWNER)
        responses = [(200, b'\x00\xff\r\n'), (200, b''), (200, '한글日本語'.encode()),
            (200, b'container-replay'), (403, b'{"code":"REPLAY_DETECTED"}'),
            (408, b''), (408, b''), *[(400, b'')] * 4]
        probe = {'Id': '4' * 64, 'State': {'Running': False, 'ExitCode': 0}}
        class CoreDocker(FakeDocker):
            def call(self, args, **kwargs):
                return json.dumps({'plaintext': True, 'no_client': True, 'wrong_client': True}) if args[0] == 'logs' else ''
        docker = CoreDocker({})
        def startup(docker, compose, receipt, project, owner):
            receipt['checks']['resource_and_isolation_inspection'] = True
            receipt['checks']['effective_process_restrictions'] = True
            return sample, inspected
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / 'receipt'
            output.mkdir(mode=0o700)
            with patch.object(self.module, 'helpers', return_value=local), \
                    patch.object(self.module, 'generate_certificates', return_value='p' * 32), \
                    patch.object(self.module, 'source_hashes', return_value={'source': 'a' * 64}), \
                    patch.object(self.module, 'bounded_command', side_effect=lambda args, **kw: 'a' * 40 if args[1:3] == ['rev-parse', 'HEAD'] else ''), \
                    patch.object(self.module, 'Docker', return_value=docker), \
                    patch.object(self.module.secrets, 'token_hex', side_effect=['a' * 24, 'b' * 24]), \
                    patch.object(self.module, 'discovered', return_value=[]), \
                    patch.object(self.module, 'run_startup', side_effect=startup), \
                    patch.object(self.module.ssl, 'create_default_context', return_value=object()), \
                    patch.object(local, 'exchange', side_effect=responses), \
                    patch.object(local, 'counters', return_value={name: 0 for name in ('dispatch', 'auth', 'key', 'replay', 'resource')}), \
                    patch.object(self.module, 'restart_redis', return_value={}), \
                    patch.object(self.module, 'records_for', return_value={**sample, 'probe': probe}), \
                    patch.object(self.module, 'inspect_container', return_value=probe), \
                    patch.object(self.module, 'run_operational', side_effect=ValueError('PRIVATE')) as operating, \
                    patch.object(self.module, 'cleanup_owned', return_value=True) as cleanup:
                with self.assertRaises(ValueError):
                    self.module.qualify(output, Path('/docker'), 'default', Path('/java'), 1, 8)
            receipt = json.loads((output / 'receipt.json').read_text())
            cleanup.assert_called_once()
            operating.assert_called_once()
            self.assertTrue(receipt['cleanup'])
            self.assertTrue(receipt['operational']['checks']['owned_container_cleanup'])
            self.assertFalse(receipt['technical_verification'])
            self.assertFalse(receipt['operational']['passed'])
            self.assertFalse(receipt['release_ready'])
            self.assertEqual(set(receipt['checks']), set(self.module.CHECKS))
            self.assertTrue(all(receipt['checks'].values()))
            self.assertNotIn('PRIVATE', json.dumps(receipt))


if __name__ == '__main__':
    unittest.main()
