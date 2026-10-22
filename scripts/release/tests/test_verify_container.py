"""Live metadata authenticates bounded container artifacts, never release approval."""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import zipfile

RELEASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RELEASE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_verify_hosted as hosted_fixture

COMMIT = 'a' * 40
NOW = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)
MARKER = 'PRIVATE-/Users/person/token-not-for-summary'
WORKFLOW = '.github/workflows/container-readiness.yml'
STATIC = ('scripts/qualification/spring_containers.py', 'scripts/qualification/spring_ingress.py',
          'sdk/python/pyproject.toml', 'sdk/python/uv.lock', 'sdk/python/README.md', 'sdk/python/LICENSE',
          'LICENSE', 'sdk/spring-boot/pom.xml', 'examples/spring-ingress/backend/pom.xml')
EXTRA = ('deploy/spring-ingress/compose.json', 'sdk/python/src/appguard/__init__.py',
         'sdk/spring-boot/src/main/Sample.java', 'examples/spring-ingress/README.md')


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()


class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.m = importlib.import_module('verify_container')
        helper = self.helper = hosted_fixture.HostedTests()
        helper.setUp()
        self.addCleanup(helper.doCleanups)
        self.base, self.candidate = helper.base, helper.candidate
        source = self.candidate / 'source'
        for name in STATIC + EXTRA:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture\n')
            path.chmod(0o644)
        (source / 'sdk/python/pyproject.toml').write_text('[project]\nname="fixture"\n')
        packages = {'cryptography': '50.0.2', 'h11': '0.16.0', 'redis': '8.1.0', 'uvicorn': '0.54.0'}
        (source / 'sdk/python/uv.lock').write_text('version=1\nrevision=5\n' + ''.join(
            '\n[[package]]\nname="' + name + '"\nversion="' + version + '"\nsource={registry="https://pypi.org/simple"}\n'
            for name, version in packages.items()))
        workflow = source / WORKFLOW
        workflow.write_text('name: container\non: [push, workflow_dispatch]\njobs: {}\n')
        self.workflow = workflow.read_bytes()
        helper.restamp(); helper.remote_source()
        self.run = {'id': 42, 'workflow_id': 8, 'run_attempt': 1, 'event': 'push',
            'head_branch': 'main', 'head_sha': COMMIT, 'path': WORKFLOW,
            'repository': {'full_name': 'bonjin-app/appguard', 'id': 17},
            'head_repository': {'full_name': 'bonjin-app/appguard', 'id': 17},
            'status': 'completed', 'conclusion': 'success', 'created_at': '2026-10-23T10:00:00Z',
            'updated_at': '2026-10-23T11:00:00Z'}
        names = ('Set up job', *self.m.PRIMARY_STEPS, 'Post Set up Temurin 17', 'Post Checkout exact candidate', 'Complete job')
        self.jobs = [{'id': 90, 'run_id': 42, 'run_attempt': 1, 'head_sha': COMMIT, 'head_branch': 'main',
            'name': 'owned-container-deployment', 'status': 'completed', 'conclusion': 'success',
            'started_at': '2026-10-23T10:00:01Z', 'completed_at': '2026-10-23T10:59:59Z',
            'steps': [{'name': name, 'number': i + 1, 'status': 'completed', 'conclusion': 'success'} for i, name in enumerate(names)]}]
        self.receipt = self.receipt_fixture(packages)
        self.image = {'schema': 1, 'evidence_class': 'owned_container_image_scan', 'release_ready': False,
            'automated_checks_passed': True, 'reason': 'local_images_checked', 'qualification_sha256': '',
            'scanners': ['vuln'], 'vulnerabilities': 0, 'secrets': None, 'coverage_complete': False,
            'native_binary_coverage': False, 'complete_resolved_graph': False, 'coverage_passed': True,
            'coverage_limitations': ['redis_native_binary_unverified', 'native_runtimes_unverified', 'complete_dependency_closure_unverified'],
            'images': {role: {'image_id': image, 'report_sha256': str(i + 5) * 64, 'vulnerabilities': 0,
                'coverage': {'os_inventory': True, 'os_package_count': 20, 'application_package_count': 10 if role != 'redis' else 0,
                             'application_inventory': True if role != 'redis' else None,
                             'native_binary_coverage': False, 'coverage_complete': False}}
                for i, (role, image) in enumerate(self.receipt['containers']['image_ids'].items())}}
        self.binding = {'schema': 1, 'evidence_class': 'owned_container_ci_binding', 'repository': 'bonjin-app/appguard',
            'candidate_commit': COMMIT, 'run_id': 42, 'run_attempt': 1, 'event': 'push', 'head_branch': 'main',
            'workflow_path': WORKFLOW, 'receipt_sha256': '', 'image_status_sha256': ''}
        self.artifact = {'id': 77, 'name': 'owned-container-readiness-' + COMMIT + '-42-1',
            'size_in_bytes': 0, 'digest': '', 'expired': False, 'created_at': '2026-10-23T10:59:40Z',
            'updated_at': '2026-10-23T10:59:40Z', 'expires_at': '2026-10-30T10:59:40Z',
            'workflow_run': {'id': 42, 'repository_id': 17, 'head_repository_id': 17,
                             'head_branch': 'main', 'head_sha': COMMIT}, 'archive_download_url': MARKER}
        self.archive = self.base / 'artifact.zip'
        self.seal()
        self.listed, self.artifacts, self.calls, self.hook = [self.run], [self.artifact], [], None

    def receipt_fixture(self, packages):
        m = self.m
        limits = {'gateway': (268435456, 1000000000, 64), 'backend': (536870912, 1000000000, 128), 'redis': (134217728, 500000000, 32)}
        points = {}
        for index, (role, (memory, cpu, pids)) in enumerate(limits.items()):
            points[role] = {'state': {'running': True, 'oom_killed': False, 'exit_code': 0, 'restart_count': 0,
                'started_at': '2026-10-23T10:03:01.123456789Z'}, 'restriction_sha256': str(index + 1) * 64,
                'docker': {'cpu_percent': 2.0, 'memory_bytes': 10000000, 'memory_limit_bytes': memory, 'pids': 3},
                'cgroup': {'version': 2, 'memory_bytes': 10000000, 'memory_limit_bytes': memory,
                    'swap_bytes': 0, 'swap_limit_bytes': 0, 'memory_oom_events': 0, 'memory_oom_kills': 0,
                    'memory_max_events': 0, 'cpu_usage_usec': 10000, 'cpu_throttled_usec': 100,
                    'cpu_throttled_periods': 1, 'cpu_periods': 10, 'cpu_quota_usec': cpu // 10000,
                    'cpu_period_usec': 100000, 'pids': 3, 'pids_limit': pids}}
        normal = {'missing_status': 0, 'invalid_status': 0, 'unrecognized_error_body': 0, 'transport_errors': 0,
            'statuses': [{'status': 200, 'count': 10}], 'error_codes': {code: 0 for code in m.OUTCOME_CODES}}
        replay = copy.deepcopy(normal); replay['statuses'][0]['status'] = 403; replay['error_codes']['REPLAY_DETECTED'] = 10
        before = dict(dispatch=9, auth=9, key=9, replay=9, resource=5)
        delta = dict(dispatch=20, auth=20, key=20, replay=20, resource=10)
        op = {'schema': 1, 'scope': m.OP_SCOPE, 'requested_seconds': 1800, 'concurrency': 8, 'phase': 'completed',
            'passed': True, 'release_ready': False, 'checks': dict.fromkeys(m.OP_CHECKS, True), 'limitations': list(m.OP_LIMITATIONS),
            'backend_restart': {'recovered': True, 'recovery_seconds': 6.0, 'original_replay_status': 403,
                'redis_run_unchanged': True, 'counter_reset_expected': True, 'scope': m.BACKEND_RESTART_SCOPE},
            'counters': {'before': before, 'after': {key: before[key] + delta[key] for key in before}, 'delta': delta},
            'soak': {'requested_seconds': 1800, 'concurrency': 8, 'elapsed_seconds': 1800.1, 'requests_per_second': 20 / 1800.1,
                'error_rate': 0.0, 'signed_requests': 10, 'replay_requests': 10, 'fidelity_failures': 0, 'replay_failures': 0,
                'transport_errors': 0, 'outcomes': {'schema': 1, 'normal': normal, 'replay': replay},
                'latency': {'samples': 20, 'min_ms': 10., 'max_ms': 10., 'mean_ms': 10., 'p50_upper_bound_ms': 10.,
                    'p95_upper_bound_ms': 10., 'p99_upper_bound_ms': 10., 'histogram_upper_bounds_ms': list(m.LATENCY_BOUNDS),
                    'histogram_counts': [0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}},
            'resources': {'samples': 300, 'interval_seconds': 5, 'scope': m.RESOURCE_SCOPE, 'before': points, 'after': copy.deepcopy(points),
                'peak': {role: {'docker_memory_bytes': 10000000, 'cgroup_memory_bytes': 10000000, 'pids': 3, 'cpu_percent': 2.0} for role in limits},
                'sampling_diagnostic': {'stage': 'completed', 'role': 'gateway', 'code': None, 'field': None,
                    'checks': {key: True for key in m.RESOURCE_DIAGNOSTIC_CHECKS},
                    'numbers': {'memory_limit_bytes': 268435456, 'expected_memory_limit_bytes': 268435456,
                        'pids_limit': 64, 'expected_pids_limit': 64, 'cpu_quota_usec': 100000, 'cpu_period_usec': 100000,
                        'expected_nano_cpus': 1000000000, 'docker_memory_limit_bytes': 268435456, 'docker_pids': 3,
                        'memory_bytes': 10000000, 'pids': 3, 'swap_limit_bytes': 0, 'swap_bytes': 0}}}}
        return {'schema': 1, 'evidence_class': 'owned_container_deployment', 'profile': 'spring-loopback-mtls-containers-v1',
            'observed_at': '2026-10-23T10:03:00Z', 'candidate_commit': COMMIT, 'source_matches_commit': True,
            'source_sha256': {name: hashlib.sha256((self.candidate / 'source' / name).read_bytes()).hexdigest() for name in STATIC + EXTRA},
            'checks': dict.fromkeys(m.CORE_CHECKS, True), 'release_ready': False, 'external_approval': False,
            'technical_verification': True, 'cleanup': True, 'phase': 'completed', 'limitations': list(m.RECEIPT_LIMITATIONS),
            'docker_server_version': '28.0.4', 'resolved_compose_sha256': 'd' * 64,
            'runtime_versions': {'python': '3.11.17', 'java': '17.0.20.1', 'redis': '7.2.16',
                'installers_absent': dict.fromkeys(('pip', 'setuptools', 'wheel', 'ensurepip'), True),
                'python_inventory_matches_build': True, 'python_required_packages': packages},
            'redis_restart': {'outage_status': 503, 'outage_seconds': .1, 'recovery_seconds': .3, 'recovery_attempts': 2,
                'run_identity_changed': True, 'aof_enabled': True, 'appendfsync': 'always', 'original_replay_status': 403,
                'scope': m.REDIS_RESTART_SCOPE}, 'backend_counters': before,
            'resource_limits': {role: dict(Memory=memory, MemorySwap=memory, NanoCpus=cpu, PidsLimit=pids) for role, (memory, cpu, pids) in limits.items()},
            'containers': {'container_ids': {role: str(i + 1) * 64 for i, role in enumerate(limits)},
                'image_ids': {role: 'sha256:' + str(i + 4) * 64 for i, role in enumerate(limits)}, 'gateway_port': 32768,
                'logging': {role: {'driver': 'local', 'max_size_bytes': 1048576, 'max_files': 1, 'compress': False} for role in limits}},
            'operational': op}

    def seal(self):
        receipt = encoded(self.receipt)
        self.image['qualification_sha256'] = hashlib.sha256(receipt).hexdigest()
        image = encoded(self.image)
        self.binding.update(receipt_sha256=hashlib.sha256(receipt).hexdigest(), image_status_sha256=hashlib.sha256(image).hexdigest())
        with zipfile.ZipFile(self.archive, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in [('binding.json', encoded(self.binding)), ('receipt.json', receipt), ('image-status.json', image)]:
                archive.writestr(name, data)
        self.authenticate_zip()

    def authenticate_zip(self):
        self.artifact.update(size_in_bytes=self.archive.stat().st_size,
            digest='sha256:' + hashlib.sha256(self.archive.read_bytes()).hexdigest())

    def fetch(self, path):
        self.calls.append(path)
        if self.hook:
            value = self.hook(path)
            if value is not None:
                return value
        route = urlsplit(path); query = parse_qs(route.query); offset = (int(query.get('page', ['1'])[0]) - 1) * 100
        if route.path.endswith('/git/commits/' + COMMIT):
            data = {'sha': COMMIT, 'tree': {'sha': self.helper.tree_sha}}
        elif '/git/trees/' in path:
            data = self.helper.tree
        elif '/contents/' in path:
            data = {'type': 'file', 'path': WORKFLOW, 'encoding': 'base64', 'size': len(self.workflow),
                'content': base64.b64encode(self.workflow).decode(),
                'sha': hashlib.sha1(b'blob ' + str(len(self.workflow)).encode() + b'\0' + self.workflow).hexdigest()}
        elif route.path.endswith('/actions/runs'):
            data = {'total_count': len(self.listed), 'workflow_runs': self.listed[offset:offset + 100]}
        elif route.path.endswith('/jobs'):
            data = {'total_count': len(self.jobs), 'jobs': self.jobs[offset:offset + 100]}
        elif route.path.endswith('/runs/42/artifacts'):
            data = {'total_count': len(self.artifacts), 'artifacts': self.artifacts[offset:offset + 100]}
        elif route.path.endswith('/actions/artifacts/77'):
            data = self.artifact
        elif route.path.endswith(('/runs/42', '/runs/42/attempts/1')):
            data = self.run
        else:
            raise AssertionError(path)
        return encoded(data)

    def verify(self):
        output = self.base / ('result-' + str(len(list(self.base.glob('result-*')))))
        result = self.m.verify_container(self.candidate, COMMIT, 42, self.archive, output, fetch=self.fetch, now=NOW)
        self.assertEqual(result, json.loads((output / 'container.json').read_bytes()))
        self.assertFalse(result['release_ready'])
        self.assertNotIn(MARKER, json.dumps(result)); self.assertNotIn(str(self.base), json.dumps(result))
        return result

    def test_sustained_success_binds_exact_sources_run_and_zip(self):
        result = self.verify()
        self.assertTrue(result['technical_gate_verified']); self.assertTrue(result['artifact_verified'])
        self.assertEqual(result['sha256']['artifact_zip'], self.artifact['digest'][7:])
        self.assertEqual(result['sha256']['candidate_manifest'], hashlib.sha256((self.candidate / 'manifest.json').read_bytes()).hexdigest())
        self.assertEqual(result['sha256']['source_archive'], hashlib.sha256((self.candidate / 'source.tar.gz').read_bytes()).hexdigest())

    def image_v2(self, findings=False):
        self.image.update(schema=2, finding_details_complete=True,
            scanner={'name': 'trivy', 'version': '0.76.1', 'platform': 'Linux-x86_64',
                'archive_sha256': 'c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0',
                'executable_sha256': 'b' * 64}, databases={})
        for name, schema in (('vulnerability', 2), ('java', 1)):
            self.image['databases'][name] = dict(schema=schema, metadata_sha256='c' * 64,
                database_sha256='d' * 64, updated_at='2026-10-23T08:00:00.123456789Z',
                next_update='2026-10-24T08:00:00Z', downloaded_at='2026-10-23T10:59:00Z')
        for row in self.image['images'].values():
            row.update(findings=[], finding_details_complete=True)
        if findings:
            record = {'vulnerability_id': 'CVE-2026-10001', 'package': 'org.example:library',
                'installed_version': '1.0.0', 'fixed_versions': ['1.0.1', '2.0.0'], 'severity': 'HIGH',
                'source_class': 'lang-pkgs', 'package_type': 'jar', 'occurrence_sha256': 'e' * 64}
            row = self.image['images']['backend']
            # Distinct raw occurrences of the same advisory/package must survive.
            row['findings'] = [record, dict(record, occurrence_sha256='f' * 64, fixed_versions=[])]
            row['vulnerabilities'] = self.image['vulnerabilities'] = 2
            self.image.update(automated_checks_passed=False, reason='findings_present')
            self.run['conclusion'] = self.jobs[0]['conclusion'] = 'failure'
            next(step for step in self.jobs[0]['steps'] if step['name'] == self.m.SCAN_STEP)['conclusion'] = 'failure'

    def test_legacy_operating_evidence_does_not_claim_finding_details(self):
        result = self.verify()
        self.assertTrue(result['technical_gate_verified'])
        self.assertEqual(result['image_status_schema'], 1)
        self.assertFalse(result['image_finding_details_verified'])

    def test_schema2_binds_complete_details_without_clearing_image_gate(self):
        self.image_v2(findings=True); self.seal()
        result = self.verify()
        self.assertTrue(result['artifact_verified']); self.assertTrue(result['technical_gate_verified'])
        self.assertTrue(result['image_finding_details_verified'])
        self.assertEqual(result['image_status_schema'], 2)
        self.assertEqual(result['image_vulnerabilities'], 2)
        self.assertFalse(result['native_binary_coverage']); self.assertFalse(result['release_ready'])
        self.assertNotIn('org.example:library', json.dumps(result))

    def test_schema2_complete_zero_findings_supported(self):
        self.image_v2(); self.seal()
        result = self.verify()
        self.assertTrue(result['technical_gate_verified']); self.assertTrue(result['image_finding_details_verified'])
        self.assertEqual(result['image_vulnerabilities'], 0)

    def test_schema2_tool_database_or_incomplete_details_cannot_verify(self):
        self.image_v2()
        original = copy.deepcopy(self.image)
        changes = (lambda x: x['scanner'].update(version='latest'),
            lambda x: x['scanner'].update(archive_sha256='0' * 64),
            lambda x: x.update(scanner=None), lambda x: x.update(databases=None),
            lambda x: x['databases']['java'].update(schema=2),
            lambda x: x['databases']['java'].update(downloaded_at='2026-10-24T10:00:00Z'),
            lambda x: x['databases']['vulnerability'].update(next_update='2026-10-22T08:00:00Z'),
            lambda x: x.update(finding_details_complete=False),
            lambda x: x['images']['redis'].update(finding_details_complete=False),
            lambda x: x['databases']['java'].update(extra=MARKER))
        for change in changes:
            with self.subTest(change=change):
                self.image = copy.deepcopy(original); change(self.image); self.seal()
                result = self.verify()
                self.assertFalse(result['artifact_verified']); self.assertFalse(result['image_finding_details_verified'])
                self.assertEqual(result['reason'], 'image_status_unverified')

    def test_schema2_findings_conserve_counts_and_reject_raw_fields(self):
        self.image_v2(findings=True)
        original = copy.deepcopy(self.image)
        changes = (lambda x: x['images']['backend'].update(vulnerabilities=1),
            lambda x: x.update(vulnerabilities=1),
            lambda x: x['images']['backend']['findings'][0].update(package=MARKER),
            lambda x: x['images']['backend']['findings'][0].update(installed_version='https://private.invalid/path'),
            lambda x: x['images']['backend']['findings'][0].update(fixed_versions=['1.0.1\nSECRET']),
            lambda x: x['images']['backend']['findings'][0].update(severity='high'),
            lambda x: x['images']['backend']['findings'][0].update(source_class='private/path'),
            lambda x: x['images']['backend']['findings'][0].update(package_type='private/path'),
            lambda x: x['images']['backend']['findings'][0].update(PrimaryURL=MARKER))
        for change in changes:
            with self.subTest(change=change):
                self.image = copy.deepcopy(original); change(self.image); self.seal()
                result = self.verify()
                self.assertFalse(result['artifact_verified']); self.assertFalse(result['image_finding_details_verified'])
                self.assertEqual(result['reason'], 'image_status_unverified')

    def test_schema2_database_nanosecond_ordering_is_exact(self):
        self.image_v2()
        row = self.image['databases']['java']
        row.update(updated_at='2026-10-23T10:59:00.000000002Z',
            downloaded_at='2026-10-23T10:59:00.000000001Z')
        self.seal()
        result = self.verify()
        self.assertFalse(result['artifact_verified'])
        row['downloaded_at'] = '2026-10-23T10:59:00.000000003Z'
        row['next_update'] = '2026-10-23T10:59:00.000000001Z'
        self.seal()
        self.assertFalse(self.verify()['artifact_verified'])
        row['next_update'] = '2026-10-23T10:59:00.000000004Z'
        self.seal()
        self.assertTrue(self.verify()['image_finding_details_verified'])
        self.assertGreaterEqual(sum('/runs/42/artifacts?' in p for p in self.calls), 2)
        self.assertGreaterEqual(sum(p.endswith('/attempts/1') for p in self.calls), 2)
        self.assertFalse(any('archive_download' in p or p.endswith('/zip') for p in self.calls))

    def test_actual_github_streaming_descriptor_zip_shape_is_supported(self):
        class Streaming(io.BytesIO):
            def seekable(self): return False
            def seek(self, *args): raise io.UnsupportedOperation('non-seekable')
        stream = Streaming()
        with zipfile.ZipFile(self.archive) as original:
            entries = [(info.filename, original.read(info)) for info in original.infolist()]
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in entries: archive.writestr(name, payload)
        raw = stream.getvalue()
        self.assertEqual(struct.unpack_from('<H', raw, 6)[0] & 8, 8)
        self.assertEqual(struct.unpack_from('<II', raw, 18), (0, 0))
        self.assertIn(b'PK\x07\x08', raw)
        self.archive.write_bytes(raw); self.authenticate_zip()
        self.assertTrue(self.verify()['technical_gate_verified'])

    def test_short_or_non_eight_worker_runs_are_only_observations(self):
        for seconds, workers in ((30, 8), (1800, 7), (1800, 9)):
            with self.subTest(seconds=seconds, workers=workers):
                self.receipt['operational']['requested_seconds'] = seconds
                self.receipt['operational']['concurrency'] = workers
                soak = self.receipt['operational']['soak']
                soak.update(requested_seconds=seconds, concurrency=workers, elapsed_seconds=seconds + .1, requests_per_second=20 / (seconds + .1))
                self.receipt['operational']['resources']['samples'] = min(300, seconds // 5 + 2)
                self.seal(); result = self.verify()
                self.assertTrue(result['artifact_verified']); self.assertFalse(result['technical_gate_verified'])

    def test_image_findings_remain_separate_when_all_other_primary_steps_pass(self):
        self.image.update(vulnerabilities=3, automated_checks_passed=False, reason='findings_present')
        self.image['images']['backend']['vulnerabilities'] = 3
        self.run['conclusion'] = self.jobs[0]['conclusion'] = 'failure'
        next(s for s in self.jobs[0]['steps'] if s['name'] == self.m.SCAN_STEP)['conclusion'] = 'failure'
        next(s for s in self.jobs[0]['steps'] if s['name'] == 'Post Set up Temurin 17')['conclusion'] = 'skipped'
        self.seal(); result = self.verify()
        self.assertTrue(result['technical_gate_verified']); self.assertEqual(result['image_vulnerabilities'], 3)
        self.assertFalse(result['native_binary_coverage'])

    def test_identity_attempt_artifact_and_binding_changes_deny(self):
        mutations = [lambda: self.run.update(run_attempt=2), lambda: self.run.update(event='pull_request'),
            lambda: self.run.update(head_branch='feature'), lambda: self.artifact.update(expired=True),
            lambda: self.artifact.update(name='owned-container-readiness-' + COMMIT),
            lambda: self.artifact.update(digest='sha256:' + 'f' * 64),
            lambda: self.artifact['workflow_run'].update(head_repository_id=18),
            lambda: self.binding.update(extra=MARKER), lambda: self.binding.update(run_attempt=True)]
        original = copy.deepcopy((self.run, self.artifact, self.binding))
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                self.run.clear(); self.run.update(copy.deepcopy(original[0]))
                self.artifact.clear(); self.artifact.update(copy.deepcopy(original[1]))
                self.binding.clear(); self.binding.update(copy.deepcopy(original[2]))
                mutation()
                if mutations.index(mutation) >= 7: self.seal()
                self.assertFalse(self.verify()['technical_gate_verified'])

    def test_newer_applicable_run_across_both_events_including_pending_denies(self):
        for event in ('push', 'workflow_dispatch'):
            with self.subTest(event=event):
                newer = dict(self.run, id=43, event=event, status='queued', conclusion=None, created_at='2026-10-23T11:30:00Z', updated_at='2026-10-23T11:30:00Z')
                self.listed = [self.run, newer]
                self.assertFalse(self.verify()['technical_gate_verified'])

    def test_same_second_fractional_timestamp_orders_runs_chronologically(self):
        # Both are ordinary accepted UTC timestamps. The fractional instant is
        # newer, although the older timestamp's terminal Z sorts after a dot.
        self.listed = [self.run, dict(self.run, id=43, event='workflow_dispatch', status='queued',
            conclusion=None, created_at='2026-10-23T10:00:00.900Z', updated_at='2026-10-23T10:00:00.900Z')]
        self.assertFalse(self.verify()['technical_gate_verified'])

    def test_duplicate_artifacts_late_artifact_and_rerun_changes_deny(self):
        self.artifacts.append(copy.deepcopy(self.artifact)); self.assertFalse(self.verify()['technical_gate_verified'])
        self.artifacts.pop()
        def late(path):
            if '/runs/42/artifacts?' in path and sum('/runs/42/artifacts?' in p for p in self.calls) >= 2:
                self.artifact['digest'] = 'sha256:' + 'e' * 64
        self.calls.clear(); self.hook = late
        self.assertFalse(self.verify()['technical_gate_verified'])

    def test_rerun_during_final_artifact_recheck_is_denied(self):
        def rerun(path):
            if '/actions/artifacts/77' in path and sum('/actions/artifacts/77' in p for p in self.calls) >= 2:
                self.run['run_attempt'] = 2
        self.hook = rerun
        self.assertFalse(self.verify()['technical_gate_verified'])

    def test_ordered_primary_steps_and_only_enumerated_benign_post_skips(self):
        original = copy.deepcopy(self.jobs)
        mutations = [lambda s: s[1].update(conclusion='skipped'),
            lambda s: s[1].update(name=MARKER), lambda s: s[1].update(number=s[2]['number']),
            lambda s: s[1].update(name=s[2]['name']), lambda s: s.reverse(),
            lambda s: s[-2].update(conclusion='failure'),
            lambda s: s[-2].update(name='Post unknown cleanup'),
            lambda s: next(r for r in s if r['name'] == self.m.SCAN_STEP).update(conclusion='failure')]
        for mutate in mutations:
            with self.subTest(change=mutations.index(mutate)):
                self.jobs = copy.deepcopy(original); mutate(self.jobs[0]['steps'])
                self.assertFalse(self.verify()['technical_gate_verified'])

    def test_latest_run_pagination_cannot_hide_a_newer_failed_dispatch(self):
        self.listed = [self.run] + [dict(self.run, id=100 + i, path='.github/workflows/other.yml') for i in range(99)]
        self.listed.append(dict(self.run, id=43, event='workflow_dispatch', conclusion='failure',
            created_at='2026-10-23T11:30:00Z', updated_at='2026-10-23T11:40:00Z'))
        self.assertFalse(self.verify()['technical_gate_verified'])
        self.assertTrue(any('page=2' in p and '/actions/runs?' in p for p in self.calls))

    def test_source_file_addition_and_remote_mode_or_workflow_mismatch_deny(self):
        added = self.candidate / 'source/sdk/python/src/appguard/extra.py'
        added.write_text('raise RuntimeError("candidate code must never execute")\n')
        added.chmod(0o644)
        self.helper.restamp(); self.helper.remote_source()
        self.assertFalse(self.verify()['technical_gate_verified'])
        added.unlink(); self.helper.restamp(); self.helper.remote_source()
        self.helper.tree['tree'][-1]['sha'] = 'e' * 40
        self.assertFalse(self.verify()['technical_gate_verified'])

    def test_cpu_display_above_nominal_quota_is_descriptive(self):
        for point in ('before', 'after'):
            self.receipt['operational']['resources'][point]['backend']['docker']['cpu_percent'] = 250.0
        self.receipt['operational']['resources']['peak']['backend']['cpu_percent'] = 300.0
        self.seal(); self.assertTrue(self.verify()['technical_gate_verified'])

    def test_elapsed_traffic_cannot_exceed_authenticated_run_window(self):
        self.run['created_at'] = self.jobs[0]['started_at'] = '2026-10-23T10:50:00Z'
        self.receipt['observed_at'] = '2026-10-23T10:53:00Z'
        for point in ('before', 'after'):
            for row in self.receipt['operational']['resources'][point].values():
                row['state']['started_at'] = '2026-10-23T10:53:01.123456789Z'
        self.seal(); self.assertFalse(self.verify()['technical_gate_verified'])

    def test_impossible_histogram_or_sampling_counts_are_denied(self):
        original = copy.deepcopy(self.receipt)
        latency = self.receipt['operational']['soak']['latency']
        for key in ('min_ms', 'max_ms', 'mean_ms', 'p50_upper_bound_ms', 'p95_upper_bound_ms', 'p99_upper_bound_ms'):
            latency[key] = 1.
        with self.subTest(kind='histogram'):
            self.seal(); self.assertFalse(self.verify()['technical_gate_verified'])
        self.receipt = original
        self.receipt['operational']['resources']['samples'] = 2500
        with self.subTest(kind='sampling_count'):
            self.seal(); self.assertFalse(self.verify()['technical_gate_verified'])

    def test_mean_is_bounded_by_histogram_and_maximum_by_total_elapsed(self):
        original = copy.deepcopy(self.receipt)
        latency = self.receipt['operational']['soak']['latency']
        latency.update(min_ms=10., max_ms=1000., mean_ms=1000., p50_upper_bound_ms=10.,
            p95_upper_bound_ms=10., p99_upper_bound_ms=1000.,
            histogram_counts=[0, 0, 0, 19, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0])
        with self.subTest(kind='weighted_mean'):
            self.seal(); self.assertFalse(self.verify()['technical_gate_verified'])
        self.receipt = original
        latency = self.receipt['operational']['soak']['latency']
        latency.update(min_ms=1e9, max_ms=1e9, mean_ms=1e9, p50_upper_bound_ms=1e9,
            p95_upper_bound_ms=1e9, p99_upper_bound_ms=1e9,
            histogram_counts=[0] * 13 + [20])
        with self.subTest(kind='total_elapsed'):
            self.seal(); self.assertFalse(self.verify()['technical_gate_verified'])

    def test_private_publication_guards_before_visibility_and_preserves_destination_collision(self):
        output = self.base / 'publication'
        fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            identity = self.m._stamp(os.fstat(fd))[:2]
            visible = []
            self.m._publish(output, fd, identity, {'schema': 1}, lambda: visible.append(output.exists()))
            self.assertFalse(visible[0])
            (output / 'container.json').unlink(); output.rmdir()
            def collision():
                output.mkdir(exist_ok=True)
                (output / 'preserve').write_text('owned ordinary collision fixture')
            with self.assertRaises(self.m.ContainerError):
                self.m._publish(output, fd, identity, {'schema': 1}, collision)
            self.assertEqual([p.name for p in output.iterdir()], ['preserve'])
        finally: os.close(fd)

    def test_publication_cancellation_re_raises_and_removes_owned_staging(self):
        fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            identity = self.m._stamp(os.fstat(fd))[:2]
            for cancellation in (KeyboardInterrupt, SystemExit):
                output = self.base / ('cancel-' + cancellation.__name__)
                def cancel(): raise cancellation()
                with self.assertRaises(cancellation):
                    self.m._publish(output, fd, identity, {'schema': 1}, cancel)
                self.assertFalse(output.exists())
                self.assertEqual(list(self.base.glob('.container-result-*')), [])
        finally: os.close(fd)

    def test_output_parent_requires_current_owner_and_no_group_or_other_write(self):
        for permissions in (0o770, 0o702, 0o777):
            with self.subTest(permissions=oct(permissions)):
                self.base.chmod(permissions)
                try:
                    with self.assertRaises(self.m.ContainerError):
                        self.m.verify_container(self.candidate, COMMIT, 42, self.archive,
                            self.base / 'untrusted-parent-result', fetch=self.fetch, now=NOW)
                    self.assertEqual(self.calls, [])
                    self.assertEqual(list(self.base.glob('.container-result-*')), [])
                finally: self.base.chmod(0o700)
        with patch.object(os, 'getuid', return_value=os.getuid() + 1), self.assertRaises(self.m.ContainerError):
            self.m.verify_container(self.candidate, COMMIT, 42, self.archive,
                self.base / 'wrong-owner-result', fetch=self.fetch, now=NOW)
        self.assertEqual(self.calls, [])

    def test_owned_parent_may_be_readable_but_not_writable_by_others(self):
        self.base.chmod(0o755)
        try: self.assertTrue(self.verify()['technical_gate_verified'])
        finally: self.base.chmod(0o700)

    def test_finite_json_and_fixed_transport_endpoints_are_enforced(self):
        for path in ('/repos/bonjin-app/appguard/actions/runs/42/artifacts?per_page=100&page=1',
                     '/repos/bonjin-app/appguard/actions/artifacts/77',
                     '/repos/bonjin-app/appguard/contents/' + WORKFLOW + '?ref=' + COMMIT):
            self.assertIsNotNone(self.m.hosted._ENDPOINT.fullmatch(path))
        for path in ('https://evil.example/', '/repos/bonjin-app/appguard/actions/artifacts/77/zip',
                     '/repos/bonjin-app/appguard/contents/.github/workflows/evil.yml'):
            self.assertIsNone(self.m.hosted._ENDPOINT.fullmatch(path))
        self.hook = lambda path: b'{"extension":1e999}'
        self.assertFalse(self.verify()['technical_gate_verified'])

    def test_initial_fifo_zip_rejects_before_any_network(self):
        self.archive.unlink(); os.mkfifo(self.archive)
        self.assertFalse(self.verify()['technical_gate_verified'])
        self.assertEqual(self.calls, [])

    def test_output_parent_swap_never_writes_to_replacement_directory(self):
        parent = self.base / 'reports'; parent.mkdir()
        existing = self.base / 'existing'; existing.mkdir()
        (existing / 'preserve').write_text(MARKER)
        output = parent / 'new'
        original = self.m._rename_exclusive
        def swap(*args):
            parent.rename(self.base / 'moved-reports'); parent.symlink_to(existing, target_is_directory=True)
            return original(*args)
        with patch.object(self.m, '_rename_exclusive', side_effect=swap), self.assertRaises(self.m.ContainerError):
            self.m.verify_container(self.candidate, COMMIT, 42, self.archive, output, fetch=self.fetch, now=NOW)
        self.assertEqual([p.name for p in existing.iterdir()], ['preserve'])
        self.assertEqual((existing / 'preserve').read_text(), MARKER)
        self.assertFalse((self.base / 'moved-reports/new').exists())

    def test_original_zip_change_during_publication_rolls_back_passing_summary(self):
        original = self.m._publish
        def change(*args):
            self.archive.write_bytes(b'changed original')
            return original(*args)
        output = self.base / 'publication'
        with patch.object(self.m, '_publish', side_effect=change), self.assertRaises(self.m.ContainerError):
            self.m.verify_container(self.candidate, COMMIT, 42, self.archive, output, fetch=self.fetch, now=NOW)
        self.assertFalse(output.exists())

    def test_counter_resource_restart_and_unknown_data_claims_deny(self):
        original = copy.deepcopy(self.receipt)
        changes = [lambda r: r['checks'].update(signed_fidelity=False),
            lambda r: r.update(extra=MARKER), lambda r: r['source_sha256'].pop(STATIC[0]),
            lambda r: r['source_sha256'].update({'unrecorded.py': 'a' * 64}),
            lambda r: r['operational']['soak'].update(transport_errors=1),
            lambda r: r['operational']['counters']['delta'].update(resource=11),
            lambda r: r['operational']['resources']['after']['backend']['cgroup'].update(swap_bytes=1),
            lambda r: r['operational']['resources']['after']['backend']['state'].update(restart_count=1),
            lambda r: r['operational']['resources']['after']['backend'].update(restriction_sha256='f' * 64),
            lambda r: r['operational']['resources']['peak']['backend'].update(cgroup_memory_bytes=1),
            lambda r: r['operational']['backend_restart'].update(recovered=False),
            lambda r: r['operational']['soak']['outcomes']['normal']['statuses'][0].update(count=True)]
        for mutate in changes:
            with self.subTest(change=changes.index(mutate)):
                self.receipt = copy.deepcopy(original); mutate(self.receipt); self.seal()
                self.assertFalse(self.verify()['technical_gate_verified'])

    def test_zip_layout_duplicate_symlink_and_expansion_attacks_deny(self):
        original = self.archive.read_bytes()
        for kind in ('duplicate', 'path', 'symlink', 'extra', 'oversized', 'trailing'):
            with self.subTest(kind=kind):
                self.archive.write_bytes(original)
                if kind == 'trailing': self.archive.write_bytes(original + b'UNTRUSTED')
                else:
                    with zipfile.ZipFile(io.BytesIO(original)) as old:
                        records = [(i.filename, old.read(i)) for i in old.infolist()]
                    if kind == 'duplicate': records.append(records[0])
                    if kind == 'extra': records.append(('unknown.json', b'{}'))
                    if kind == 'path': records[0] = ('../binding.json', records[0][1])
                    if kind == 'oversized': records[0] = ('binding.json', b' ' * (self.m.MAX_ENTRY_BYTES + 1))
                    with zipfile.ZipFile(self.archive, 'w', compression=zipfile.ZIP_DEFLATED) as changed:
                        for name, value in records:
                            if kind == 'symlink' and name == 'binding.json':
                                info = zipfile.ZipInfo(name); info.create_system = 3; info.external_attr = (stat.S_IFLNK | 0o777) << 16
                                changed.writestr(info, value)
                            else: changed.writestr(name, value)
                self.authenticate_zip()
                self.assertFalse(self.verify()['technical_gate_verified'])

    def test_crc_header_overlap_flags_and_central_directory_bounds_deny(self):
        original = self.archive.read_bytes()
        central = original.index(b'PK\x01\x02')
        eocd = original.rfind(b'PK\x05\x06')
        for kind in ('local_crc', 'actual_crc', 'encrypted', 'huge_count', 'huge_directory', 'overlap'):
            with self.subTest(kind=kind):
                raw = bytearray(original)
                if kind == 'local_crc': raw[14] ^= 1
                if kind == 'actual_crc': raw[14] ^= 1; raw[central + 16] ^= 1
                if kind == 'encrypted':
                    struct.pack_into('<H', raw, 6, 1); struct.pack_into('<H', raw, central + 8, 1)
                if kind == 'huge_count':
                    struct.pack_into('<HH', raw, eocd + 8, 65535, 65535)
                if kind == 'huge_directory': struct.pack_into('<I', raw, eocd + 12, 1 << 30)
                if kind == 'overlap':
                    size = struct.unpack_from('<I', raw, 18)[0] + 100
                    struct.pack_into('<I', raw, 18, size); struct.pack_into('<I', raw, central + 20, size)
                self.archive.write_bytes(raw); self.authenticate_zip()
                self.assertFalse(self.verify()['technical_gate_verified'])

    def test_actual_inflated_bytes_are_bounded_even_with_forged_small_sizes(self):
        with zipfile.ZipFile(self.archive) as old:
            records = [(i.filename, old.read(i)) for i in old.infolist()]
        records[0] = ('binding.json', b'{"data":"' + b'A' * (self.m.MAX_ENTRY_BYTES + 1) + b'"}')
        with zipfile.ZipFile(self.archive, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, body in records: archive.writestr(name, body)
        raw = bytearray(self.archive.read_bytes()); central = raw.index(b'PK\x01\x02')
        struct.pack_into('<I', raw, 22, 50); struct.pack_into('<I', raw, central + 24, 50)
        self.archive.write_bytes(raw); self.authenticate_zip()
        self.assertFalse(self.verify()['technical_gate_verified'])

    def test_duplicate_nonfinite_and_non_object_member_json_deny(self):
        original = self.archive.read_bytes()
        for invalid in (b'{"schema":1,"schema":1}', b'{"extension":1e999}', b'{"extension":NaN}', b'[]', b'\xff'):
            with self.subTest(invalid=invalid):
                with zipfile.ZipFile(io.BytesIO(original)) as old:
                    records = [(i.filename, old.read(i)) for i in old.infolist()]
                records[0] = ('binding.json', invalid)
                with zipfile.ZipFile(self.archive, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                    for name, body in records: archive.writestr(name, body)
                self.authenticate_zip(); self.assertFalse(self.verify()['technical_gate_verified'])

    def test_final_attempt_endpoint_and_api_budget_fail_closed(self):
        def changed_attempt(path):
            if path.endswith('/attempts/1') and sum(p.endswith('/attempts/1') for p in self.calls) >= 2:
                return encoded(dict(self.run, run_attempt=2))
        self.hook = changed_attempt
        self.assertFalse(self.verify()['technical_gate_verified'])
        self.hook = None; self.calls.clear()
        with patch.object(self.m, 'MAX_API_REQUESTS', 5):
            result = self.verify()
        self.assertFalse(result['technical_gate_verified']); self.assertEqual(len(self.calls), 5)

    def test_api_failures_and_original_input_mutation_are_redacted(self):
        def fail(path): raise RuntimeError(MARKER)
        self.hook = fail
        self.assertFalse(self.verify()['technical_gate_verified'])
        self.hook = lambda path: self.archive.write_bytes(b'changed') and None
        self.assertFalse(self.verify()['technical_gate_verified'])

    def test_cli_rejects_offline_token_host_and_redirect_options(self):
        result = __import__('subprocess').run([sys.executable, str(RELEASE / 'verify_container.py'), '--token', MARKER],
            capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0); self.assertNotIn(MARKER, result.stdout + result.stderr)


if __name__ == '__main__': unittest.main()
