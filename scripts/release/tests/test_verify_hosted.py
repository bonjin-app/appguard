"""Hosted status requires live endpoint semantics, never approval-shaped input."""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import verify_hosted as hosted
from candidate import write_archive

COMMIT = 'a' * 40
REPOSITORY = 'bonjin-app/appguard'
NOW = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
MARKER = 'PRIVATE-ERROR-/Users/person/token-secret'
WORKFLOW = b'name: test\non: push\njobs: {}\n'


class HostedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.candidate = self.base / 'candidate'
        workflow = self.candidate / 'source/.github/workflows/verify.yml'
        workflow.parent.mkdir(parents=True)
        workflow.write_bytes(WORKFLOW)
        (self.candidate / 'source/LICENSE').write_text('Apache-2.0\n')
        self.manifest = {'schema': 1, 'commit': COMMIT, 'archive_prefix': 'appguard/', 'excluded': []}
        self.restamp()
        self.tree_sha = 'b' * 40
        self.tree = {'sha': self.tree_sha, 'truncated': False, 'tree': []}
        self.remote_source()
        self.api_state()

    def restamp(self, *, rebuild_archive=True):
        source = self.candidate / 'source'
        if rebuild_archive:
            files = [(str(p.relative_to(source)), p.stat().st_mode & 0o777)
                     for p in sorted(source.rglob('*')) if p.is_file()]
            write_archive(source, self.candidate / 'source.tar.gz', files)
        self.manifest['sha256'] = {
            str(p.relative_to(self.candidate)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.candidate.rglob('*') if p.is_file() and p != self.candidate / 'manifest.json'}
        (self.candidate / 'manifest.json').write_text(json.dumps(self.manifest))

    def remote_source(self):
        self.tree['tree'] = []
        source = self.candidate / 'source'
        for path in sorted(source.rglob('*')):
            name = str(path.relative_to(source))
            if path.is_dir():
                self.tree['tree'].append({'path': name, 'type': 'tree', 'mode': '040000', 'sha': 'c' * 40})
            else:
                data = path.read_bytes()
                self.tree['tree'].append({'path': name, 'type': 'blob', 'size': len(data),
                    'mode': '100755' if path.stat().st_mode & 0o111 else '100644',
                    'sha': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()})

    def api_state(self):
        self.run = {'id': 42, 'workflow_id': 8, 'run_attempt': 2, 'event': 'push',
                    'head_branch': 'main', 'head_sha': COMMIT, 'path': hosted.WORKFLOW,
                    'repository': {'full_name': REPOSITORY},
                    'head_repository': {'full_name': REPOSITORY},
                    'status': 'completed', 'conclusion': 'success',
                    'created_at': '2026-10-22T10:00:00Z', 'updated_at': '2026-10-22T10:05:00Z'}
        self.jobs = [{'id': i + 100, 'run_id': 42, 'head_sha': COMMIT, 'head_branch': 'main',
                      'status': 'completed', 'conclusion': 'success', 'name': name}
                     for i, name in enumerate(hosted.REQUIRED_JOBS)]
        self.content = {'type': 'file', 'path': hosted.WORKFLOW, 'encoding': 'base64',
                        'size': len(WORKFLOW), 'content': base64.b64encode(WORKFLOW).decode(),
                        'sha': hashlib.sha1(b'blob ' + str(len(WORKFLOW)).encode() + b'\0' + WORKFLOW).hexdigest()}
        self.listed = [self.run]
        self.calls = []
        self.hook = None

    def fetch(self, path):
        self.calls.append(path)
        if self.hook:
            result = self.hook(path)
            if result is not None:
                return result
        prefix = '/repos/' + REPOSITORY
        if path.startswith(prefix + '/contents/'):
            result = self.content
        elif path == prefix + '/git/commits/' + COMMIT:
            result = {'sha': COMMIT, 'tree': {'sha': self.tree_sha}}
        elif path == prefix + '/git/trees/' + self.tree_sha + '?recursive=1':
            result = self.tree
        elif path.startswith(prefix + '/actions/runs?'):
            result = {'total_count': len(self.listed), 'workflow_runs': self.listed}
        elif '/jobs?' in path:
            result = {'total_count': len(self.jobs), 'jobs': self.jobs}
        elif path in {prefix + '/actions/runs/42', prefix + '/actions/runs/42/attempts/2'}:
            result = self.run
        else:
            raise AssertionError(path)
        return json.dumps(result).encode()

    def verify(self, *, expected_commit=COMMIT, repository=REPOSITORY, run_id=42, fetch=None):
        output = self.base / ('result-' + str(len(list(self.base.glob('result-*')))))
        result = hosted.verify_hosted(self.candidate, expected_commit, repository, run_id,
                                      output, fetch=fetch or self.fetch, now=NOW)
        self.assertEqual(result, json.loads((output / 'hosted.json').read_bytes()))
        self.assertEqual([p.name for p in output.iterdir()], ['hosted.json'])
        self.assertFalse(result['release_ready'])
        self.assertEqual(result['external_approvals'], 'not_verified')
        self.assertNotIn(MARKER, json.dumps(result))
        self.assertNotIn(str(self.base), json.dumps(result))
        return result

    def deny(self, reason=None, **kwargs):
        result = self.verify(**kwargs)
        self.assertFalse(result['technical_gate_verified'])
        if reason:
            self.assertEqual(result['reason'], reason)
        return result

    def test_success_binds_manifest_workflow_and_attempt(self):
        result = self.verify()
        self.assertTrue(result['technical_gate_verified'])
        self.assertEqual(result['reason'], 'verified')
        self.assertEqual(result['run_attempt'], 2)
        self.assertEqual(result['job_count'], 5)
        self.assertEqual(result['source_file_count'], 2)
        self.assertEqual(result['api_response_count'], 8)
        self.assertEqual(result['sha256']['candidate_manifest'], hashlib.sha256(
            (self.candidate / 'manifest.json').read_bytes()).hexdigest())
        self.assertEqual(result['sha256']['workflow'], hashlib.sha256(WORKFLOW).hexdigest())
        self.assertTrue(any('/attempts/2/jobs?' in p for p in self.calls))
        self.assertTrue(any('/contents/' in p and ('ref=' + COMMIT) in p for p in self.calls))
        self.assertGreaterEqual(self.calls.count('/repos/' + REPOSITORY + '/actions/runs/42'), 2)

    def test_every_identity_field_is_required(self):
        changes = {'id': 41, 'workflow_id': None, 'event': 'pull_request', 'head_branch': 'develop',
                   'head_sha': 'b' * 40, 'path': '.github/workflows/other.yml',
                   'repository': {'full_name': 'attacker/appguard'},
                   'head_repository': {'full_name': 'attacker/appguard'}, 'run_attempt': True}
        original = copy.deepcopy(self.run)
        for name, value in changes.items():
            with self.subTest(name=name):
                self.run.clear(); self.run.update(copy.deepcopy(original)); self.run[name] = value
                self.deny()
        self.run.clear(); self.run.update(original)

    def test_no_pending_failed_skipped_cancelled_or_neutral_runs(self):
        for state, conclusion in [('in_progress', None), ('queued', None), ('completed', 'failure'),
                                  ('completed', 'cancelled'), ('completed', 'skipped'), ('completed', 'neutral')]:
            with self.subTest(state=state, conclusion=conclusion):
                self.run.update(status=state, conclusion=conclusion)
                self.deny('run_unverified')

    def test_bad_jobs_missing_duplicate_wrong_commit_and_failure(self):
        original = copy.deepcopy(self.jobs)
        mutations = [lambda: self.jobs.pop(), lambda: self.jobs.append(copy.deepcopy(self.jobs[0])),
                     lambda: self.jobs[0].update(name='wrong'),
                     lambda: self.jobs[0].update(id=self.jobs[1]['id']),
                     lambda: self.jobs[0].update(run_id=43),
                     lambda: self.jobs[0].update(head_sha='b' * 40),
                     lambda: self.jobs[0].update(run_attempt=1),
                     lambda: self.jobs[0].update(status='queued'),
                     lambda: self.jobs[0].update(conclusion='skipped'),
                     lambda: self.jobs[0].update(conclusion='failure')]
        for mutation in mutations:
            self.jobs = copy.deepcopy(original)
            mutation()
            self.deny('jobs_unverified')

    def test_stale_future_invalid_and_reversed_times(self):
        for field, value in [('created_at', '2026-10-01T10:00:00Z'),
                             ('updated_at', '2026-10-22T12:00:01Z'),
                             ('created_at', 'not-a-time'),
                             ('created_at', '2026-10-22T11:00:00Z')]:
            original = self.run[field]
            with self.subTest(field=field, value=value):
                self.run[field] = value
                self.deny('run_unverified')
            self.run[field] = original

    def test_old_success_cannot_hide_newer_failed_or_pending_run(self):
        for status, conclusion in [('completed', 'failure'), ('in_progress', None)]:
            newer = dict(self.run, id=43, status=status, conclusion=conclusion,
                         created_at='2026-10-22T11:00:00Z', updated_at='2026-10-22T11:01:00Z')
            self.listed = [newer, self.run]
            self.deny('latest_run_unverified')

    def test_list_must_include_exact_run_and_have_no_duplicate_ids(self):
        for listed in [[], [dict(self.run, run_attempt=3)], [self.run, self.run]]:
            self.listed = listed
            self.deny('latest_run_unverified')

    def test_rerun_or_new_run_during_verification_is_rejected(self):
        for changed in ('attempt', 'run'):
            self.listed = [self.run]
            run_reads = 0
            def hook(path):
                nonlocal run_reads
                if path.endswith('/actions/runs/42'):
                    run_reads += 1
                    if run_reads == 2:
                        if changed == 'attempt':
                            return json.dumps(dict(self.run, run_attempt=3)).encode()
                        self.listed = [self.run, dict(self.run, id=44, created_at='2026-10-22T11:00:00Z',
                                                     updated_at='2026-10-22T11:02:00Z')]
                return None
            self.hook = hook
            self.deny()

    def test_workflow_bytes_git_sha_size_path_and_type_are_bound(self):
        original = copy.deepcopy(self.content)
        for field, value in [('content', base64.b64encode(b'altered').decode()), ('sha', 'b' * 40),
                             ('size', 900), ('path', 'README.md'), ('type', 'symlink'),
                             ('encoding', 'none'), ('content', '%%%')]:
            self.content = dict(original, **{field: value})
            self.deny('workflow_unverified')

    def test_candidate_tampering_before_or_during_network_rejects(self):
        workflow = self.candidate / 'source/.github/workflows/verify.yml'
        workflow.write_bytes(b'altered')
        self.deny('candidate_unverified')
        self.assertEqual(self.calls, [])
        workflow.write_bytes(WORKFLOW)
        def hook(path):
            workflow.write_bytes(b'altered')
        self.hook = hook
        self.deny('candidate_changed')

    def test_candidate_is_rechecked_around_every_network_observation(self):
        manifest = self.candidate / 'manifest.json'
        original = manifest.read_bytes()
        for at_request in range(1, 9):
            self.calls.clear()
            manifest.write_bytes(original)
            def change(path):
                if len(self.calls) == at_request:
                    # Even semantically equivalent manifest bytes must remain pinned.
                    manifest.write_bytes(original + b'\n')
            self.hook = change
            self.deny('candidate_changed')
            self.assertEqual(len(self.calls), at_request)

    def test_candidate_symlink_file_and_bounded_snapshot_reject_before_api(self):
        workflow = self.candidate / 'source/.github/workflows/verify.yml'
        workflow.unlink()
        target = self.base / 'workflow.yml'
        target.write_bytes(WORKFLOW)
        workflow.symlink_to(target)
        self.deny('candidate_unverified')
        workflow.unlink()
        workflow.write_bytes(WORKFLOW)
        with patch('assess.MAX_FILES', 1):
            self.deny('candidate_unverified')
        self.assertEqual(self.calls, [])

    def test_manifest_duplicate_nonfinite_and_unknown_files_rejected(self):
        path = self.candidate / 'manifest.json'
        original = path.read_bytes()
        for raw in [b'{"schema":1,"schema":1}', b'{"x":NaN}', b'{"x":1e999}']:
            path.write_bytes(raw)
            self.deny('candidate_unverified')
        path.write_bytes(original)
        (self.candidate / 'private').write_text(MARKER)
        self.deny('candidate_unverified')

    def test_symlink_candidate_input_and_output_and_existing_output_refused(self):
        link = self.base / 'linked'
        link.symlink_to(self.candidate, target_is_directory=True)
        with self.assertRaises(hosted.HostedError):
            hosted.verify_hosted(link, COMMIT, REPOSITORY, 42, self.base / 'out', fetch=self.fetch, now=NOW)
        with self.assertRaises(hosted.HostedError):
            hosted.verify_hosted(self.candidate, COMMIT, REPOSITORY, 42, self.candidate / 'result', fetch=self.fetch, now=NOW)
        with self.assertRaises(hosted.HostedError):
            hosted.verify_hosted(self.candidate, COMMIT, REPOSITORY, 42, self.candidate, fetch=self.fetch, now=NOW)

    def test_api_duplicate_nonfinite_depth_size_and_error_details_redacted(self):
        raws = [b'{"id":42,"id":42}', b'{"x":NaN}', b'{"x":1e999}',
                b'{"x":' + b'[' * 100 + b'0' + b']' * 100 + b'}',
                b' ' * (hosted.MAX_RESPONSE_BYTES + 1)]
        for raw in raws:
            self.deny(fetch=lambda _: raw)
        for exception in [TimeoutError(MARKER), OSError(MARKER), ValueError(MARKER)]:
            def fail(_):
                raise exception
            self.deny('api_unavailable', fetch=fail)

    def test_invalid_arguments_never_contact_network(self):
        for kwargs in [{'expected_commit': 'main'}, {'repository': 'attacker/appguard'},
                       {'repository': 'https://evil.example'}, {'expected_commit': 'a' * 64},
                       {'run_id': -1}, {'run_id': True}]:
            with self.assertRaises(hosted.HostedError):
                self.verify(**kwargs)
        self.assertEqual(self.calls, [])

    def test_output_appearing_after_final_check_is_not_overwritten(self):
        output = self.base / 'raced'
        original = hosted._path
        checks = 0
        def appeared(value, **kwargs):
            nonlocal checks
            result = original(value, **kwargs)
            if kwargs.get('new'):
                checks += 1
                if checks == 2:
                    output.mkdir()
                    (output / 'preserve').write_text(MARKER)
            return result
        with patch.object(hosted, '_path', side_effect=appeared), self.assertRaises(hosted.HostedError):
            hosted.verify_hosted(self.candidate, COMMIT, REPOSITORY, 42, output, fetch=self.fetch, now=NOW)
        self.assertEqual((output / 'preserve').read_text(), MARKER)
        self.assertEqual([p.name for p in output.iterdir()], ['preserve'])

    def test_output_ancestor_swap_never_writes_to_existing_directory(self):
        output = self.base / 'raced'
        target = self.base / 'existing'
        target.mkdir()
        (target / 'preserve').write_text(MARKER)
        original = hosted.os.link
        def swapped(source, destination, **kwargs):
            output.rmdir()
            output.symlink_to(target, target_is_directory=True)
            return original(source, destination, **kwargs)
        with patch.object(hosted.os, 'link', side_effect=swapped), self.assertRaises(hosted.HostedError):
            hosted.verify_hosted(self.candidate, COMMIT, REPOSITORY, 42, output, fetch=self.fetch, now=NOW)
        self.assertEqual((target / 'preserve').read_text(), MARKER)
        self.assertEqual([p.name for p in target.iterdir()], ['preserve'])

    def test_renamed_output_descriptor_is_unlinked_when_path_changes(self):
        output, moved = self.base / 'raced', self.base / 'moved'
        target = self.base / 'existing'
        target.mkdir()
        original = hosted.os.link
        def swapped(source, destination, **kwargs):
            output.rename(moved)
            output.symlink_to(target, target_is_directory=True)
            return original(source, destination, **kwargs)
        with patch.object(hosted.os, 'link', side_effect=swapped), self.assertRaises(hosted.HostedError):
            hosted.verify_hosted(self.candidate, COMMIT, REPOSITORY, 42, output, fetch=self.fetch, now=NOW)
        self.assertEqual(list(target.iterdir()), [])
        self.assertEqual(list(moved.iterdir()), [])

    def test_pagination_is_bounded_and_totals_must_match(self):
        def hook(path):
            if '/jobs?' in path:
                return json.dumps({'total_count': 1001, 'jobs': self.jobs}).encode()
        self.hook = hook
        self.deny('jobs_unverified')
        def missing(path):
            if '/jobs?' in path:
                return json.dumps({'total_count': 6, 'jobs': self.jobs}).encode()
        self.hook = missing
        self.deny('jobs_unverified')

    def test_pagination_fetches_all_pages_without_following_api_links(self):
        # Smaller page size makes a second page meaningful with five required jobs.
        with patch.object(hosted, 'PAGE_SIZE', 3):
            def hook(path):
                if '/jobs?' in path:
                    page = int(path.rsplit('page=', 1)[1])
                    return json.dumps({'total_count': 5, 'jobs': self.jobs[(page - 1) * 3:page * 3],
                                       'next': 'https://evil.example/' + MARKER}).encode()
            self.hook = hook
            self.assertTrue(self.verify()['technical_gate_verified'])
        self.assertTrue(any('/jobs?per_page=3&page=2' in p for p in self.calls))

    def test_newer_failure_on_second_run_page_is_blocking(self):
        unrelated = [dict(self.run, id=i, path='.github/workflows/another.yml') for i in range(1, 5)]
        newer = dict(self.run, id=43, conclusion='failure', created_at='2026-10-22T11:00:00Z',
                     updated_at='2026-10-22T11:01:00Z')
        with patch.object(hosted, 'PAGE_SIZE', 5):
            def hook(path):
                if '/actions/runs?' in path:
                    page = int(path.rsplit('page=', 1)[1])
                    return json.dumps({'total_count': 6, 'workflow_runs':
                                       ([self.run, *unrelated] if page == 1 else [newer])}).encode()
            self.hook = hook
            self.deny('latest_run_unverified')

    def test_restamped_modified_source_and_archive_cannot_borrow_ci(self):
        (self.candidate / 'source/LICENSE').write_text('modified source\n')
        self.restamp()
        self.deny('source_git_provenance')

    def test_restamped_arbitrary_archive_cannot_borrow_verified_source(self):
        (self.candidate / 'source.tar.gz').write_bytes(b'arbitrary archive contents')
        self.restamp(rebuild_archive=False)
        self.deny('source_git_provenance')

    def test_remote_tree_and_exact_commit_linkage_are_required(self):
        original = copy.deepcopy(self.tree)
        mutations = [lambda: self.tree.update(truncated=True), lambda: self.tree.update(truncated=0),
                     lambda: self.tree.update(sha='d' * 40),
                     lambda: self.tree['tree'].pop(),
                     lambda: self.tree['tree'].append(copy.deepcopy(self.tree['tree'][0])),
                     lambda: self.tree['tree'].append({'path': 'README.extra.md', 'type': 'blob',
                                                       'mode': '100644', 'size': 1, 'sha': 'd' * 40}),
                     lambda: self.tree['tree'][0].update(path='../escape'),
                     lambda: self.tree['tree'][0].update(sha='d' * 64)]
        for mutation in mutations:
            self.tree = copy.deepcopy(original)
            mutation()
            self.deny('source_git_provenance')
        self.tree = original
        def wrong_commit(path):
            if '/git/commits/' in path:
                return json.dumps({'sha': 'd' * 40, 'tree': {'sha': self.tree_sha}}).encode()
        self.hook = wrong_commit
        self.deny('source_git_provenance')

    def test_symlinks_submodules_and_special_tree_modes_are_rejected(self):
        original = copy.deepcopy(self.tree)
        for mode, kind in [('120000', 'blob'), ('160000', 'commit'), ('100600', 'blob'), ('100644', 'tree')]:
            self.tree = copy.deepcopy(original)
            self.tree['tree'].append({'path': 'README.extra.md', 'type': kind, 'mode': mode,
                                      'size': 1, 'sha': 'd' * 40})
            self.deny('source_git_provenance')

    def test_unicode_source_paths_and_executable_mode_are_bound(self):
        source = self.candidate / 'source/docs/설계-α.md'
        source.parent.mkdir()
        source.write_text('Unicode source\n')
        source.chmod(0o755)
        self.restamp()
        self.remote_source()
        self.assertTrue(self.verify()['technical_gate_verified'])
        source.chmod(0o644)
        self.restamp()
        self.deny('source_git_provenance')

    def test_excluded_tree_files_must_match_manifest_inventory(self):
        self.tree['tree'].append({'path': 'secret.bin', 'type': 'blob', 'mode': '100644',
                                  'size': 9, 'sha': 'd' * 40})
        self.deny('source_git_provenance')
        self.manifest['excluded'] = ['secret.bin']
        self.restamp()
        self.assertTrue(self.verify()['technical_gate_verified'])

    def test_api_request_budget_is_fixed_and_fail_closed(self):
        with patch.object(hosted, 'MAX_API_REQUESTS', 7):
            result = self.deny('api_budget_exceeded')
        self.assertEqual(len(self.calls), 7)
        self.assertEqual(result['api_response_count'], 7)

    def test_attempt_endpoint_cannot_substitute_a_different_attempt(self):
        def hook(path):
            if path.endswith('/attempts/2'):
                return json.dumps(dict(self.run, run_attempt=1)).encode()
        self.hook = hook
        self.deny('run_unverified')

    def test_transport_fixed_https_timeouts_and_redirect_denial(self):
        for status in (301, 302, 307, 308, 403, 500):
            with self.subTest(status=status), patch.object(hosted.http.client, 'HTTPSConnection') as connect:
                response = connect.return_value.getresponse.return_value
                response.status = status
                with self.assertRaises(hosted.HostedError):
                    hosted._fetch_direct('/repos/bonjin-app/appguard/actions/runs/42')
                self.assertEqual(connect.call_args.args, ('api.github.com',))
                self.assertGreater(connect.call_args.kwargs['timeout'], 0)
                response.read.assert_not_called()
                response.read1.assert_not_called()
        for path in ('https://evil.example/', '//evil.example/', '/repos/attacker/appguard/actions/runs/42', '/repos/bonjin-app/appguard/../x'):
            with patch.object(hosted.http.client, 'HTTPSConnection') as connect:
                with self.assertRaises(hosted.HostedError):
                    hosted._fetch_direct(path)
                connect.assert_not_called()

    def test_transport_bounds_body_and_time_even_without_content_length(self):
        class Response:
            status = 200
            def __init__(self, chunks, length=None, close_at_end=False):
                self.chunks, self.length, self.closed = list(chunks), length, False
                self.close_at_end = close_at_end
            def getheader(self, name):
                return self.length
            def isclosed(self):
                return self.closed
            def read1(self, count):
                chunk = self.chunks.pop(0) if self.chunks else b''
                if not self.chunks and self.close_at_end:
                    self.closed = True
                return chunk
        for length, chunks, passes in [('2', [b'{}'], True), (None, [b'{}'], True),
                                       ('3', [b'{}'], False), ('999999999', [b'{}'], False),
                                       ('invalid', [b'{}'], False), (None, [b'X' * 11], False)]:
            with self.subTest(length=length, passes=passes), patch.object(hosted.http.client, 'HTTPSConnection') as connect:
                response = Response(chunks, length, close_at_end=True)
                connect.return_value.getresponse.return_value = response
                with patch.object(hosted, 'MAX_RESPONSE_BYTES', 10):
                    if passes:
                        self.assertEqual(hosted._fetch_direct('/repos/' + REPOSITORY + '/actions/runs/42'), b'{}')
                    else:
                        with self.assertRaises(hosted.HostedError):
                            hosted._fetch_direct('/repos/' + REPOSITORY + '/actions/runs/42')
                connect.return_value.close.assert_called_once()
                for call in connect.return_value.sock.settimeout.call_args_list:
                    self.assertGreater(call.args[0], 0)
                    self.assertLessEqual(call.args[0], hosted.READ_TIMEOUT)
        with patch.object(hosted.http.client, 'HTTPSConnection') as connect:
            connect.return_value.getresponse.return_value = Response([b'{}'])
            with patch.object(hosted.time, 'monotonic', side_effect=[0, 1, hosted.REQUEST_TIMEOUT + 1]):
                with self.assertRaises(hosted.HostedError):
                    hosted._fetch_direct('/repos/' + REPOSITORY + '/actions/runs/42')
        for stage in ('connect', 'getresponse'):
            with patch.object(hosted.http.client, 'HTTPSConnection') as connect:
                getattr(connect.return_value, stage).side_effect = TimeoutError(MARKER)
                with self.assertRaises(hosted.HostedError) as caught:
                    hosted._fetch_direct('/repos/' + REPOSITORY + '/actions/runs/42')
                self.assertNotIn(MARKER, str(caught.exception))

    def test_overall_transport_budget_kills_dns_headers_and_late_empty_responses(self):
        original = hosted.subprocess.Popen
        prefix = ('import sys,time\nsys.path.insert(0,' + repr(str(ROOT)) + ')\n'
                  'import verify_hosted as h\n')
        scenarios = [
            # An actual child gets stuck inside name resolution before TCP connect.
            "h.http.client.socket.getaddrinfo=lambda *a,**k: time.sleep(5)\n",
            # Header parsing can trickle beyond individual socket read timeouts.
            "class Sock:\n def settimeout(self,*a): pass\n"
            "class Connection:\n"
            " def __init__(self,*a,**k): self.sock=Sock()\n"
            " def connect(self): pass\n def request(self,*a,**k): pass\n"
            " def getresponse(self):\n  time.sleep(5)\n  return None\n"
            " def close(self): pass\n"
            "h.http.client.HTTPSConnection=Connection\n",
            # The response is already closed/zero length when late headers arrive.
            "class Sock:\n def settimeout(self,*a): pass\n"
            "class Response:\n status=200\n def getheader(self,*a): return '0'\n def isclosed(self): return True\n"
            "class Connection:\n"
            " def __init__(self,*a,**k): self.sock=Sock()\n"
            " def connect(self): pass\n def request(self,*a,**k): pass\n"
            " def getresponse(self):\n  time.sleep(5)\n  return Response()\n"
            " def close(self): pass\n"
            "h.http.client.HTTPSConnection=Connection\n",
        ]
        for scenario in scenarios:
            children = []
            def controlled_child(command, **kwargs):
                code = prefix + scenario + "h._fetch_direct('/repos/bonjin-app/appguard/actions/runs/42')\n"
                child = original([sys.executable, '-E', '-s', '-c', code], **kwargs)
                children.append(child)
                return child
            start = time.monotonic()
            with patch.object(hosted, 'REQUEST_TIMEOUT', 0.4), patch.object(hosted.subprocess, 'Popen', side_effect=controlled_child):
                with self.assertRaises(hosted.HostedError):
                    hosted.fetch_github('/repos/' + REPOSITORY + '/actions/runs/42')
            self.assertLess(time.monotonic() - start, 2)
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll())
            self.assertTrue(children[0].stdout.closed)

    def test_cli_cannot_select_offline_transport_or_custom_host(self):
        result = subprocess.run([sys.executable, str(ROOT / 'verify_hosted.py'), '--api-url', MARKER],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(MARKER, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
