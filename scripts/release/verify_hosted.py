#!/usr/bin/env python3
"""Verify current GitHub CI through fixed public HTTPS endpoints; never approve a release.

There is no offline report, token, host or transport option in the CLI. Python
callers may inject raw endpoint responses solely for deterministic unit tests.
This is point-in-time technical evidence; it does not establish workflow trust,
independent review, legal approval, or protection against a compromised host.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

from assess import _json, _path, _read, _snapshot, _stamp, _unchanged, _DIGEST, _UTC
from candidate import allowed, validate_path, write_archive, write_json
from scan import verify_candidate

REPOSITORY = 'bonjin-app/appguard'
WORKFLOW = '.github/workflows/verify.yml'
REQUIRED_JOBS = (
    'Python, Node and Java with disposable Redis',
    'Go race/vet, .NET and PHP',
    'Owned Redis resilience and bounded adversarial qualification',
    'CLI and Expo TypeScript/package checks',
    'Apple Swift host tests',
)
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_WORKFLOW_BYTES = 1024 * 1024
PAGE_SIZE = 100
MAX_PAGES = 10
# Eight normal observations leave one extra page within the rate-use budget.
MAX_API_REQUESTS = 9
MAX_TREE_ENTRIES = 50000
MAX_AGE = timedelta(days=7)
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 15
REQUEST_TIMEOUT = 30
API_PREFIX = '/repos/' + REPOSITORY + '/'
# Official REST contracts checked 2026-10-22, with the supported 2022-11-28 API:
# https://docs.github.com/en/rest/actions/workflow-runs
# https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt
# https://docs.github.com/en/rest/repos/contents#get-repository-content
# https://docs.github.com/en/rest/git/commits#get-a-commit-object
# https://docs.github.com/en/rest/git/trees#get-a-tree
_SHA1 = re.compile(r'[0-9a-f]{40}\Z')
_ENDPOINT = re.compile(
    re.escape(API_PREFIX) + r'(?:actions/runs(?:/[1-9][0-9]*(?:/attempts/[1-9][0-9]*(?:/jobs)?|/artifacts)?)?'
    r'|actions/artifacts/[1-9][0-9]*|contents/\.github/workflows/(?:verify|container-readiness)\.yml'
    r'|git/(?:commits|trees)/[0-9a-f]{40})(?:\?[a-z0-9_=&]+)?\Z')


class HostedError(ValueError):
    """Fixed public error, without filesystem, provider, or credential details."""

    def __init__(self):
        super().__init__('hosted_verification_unavailable')


class _Denied(Exception):
    def __init__(self, reason):
        self.reason = reason


def _require(condition, reason):
    if not condition:
        raise _Denied(reason)


def _positive(value):
    return type(value) is int and 0 < value < 2 ** 63


def _fetch_direct(path):
    """No proxies, redirects, token access, URL fields, or caller-selected hosts."""
    if not isinstance(path, str) or not _ENDPOINT.fullmatch(path):
        raise HostedError()
    connection = http.client.HTTPSConnection('api.github.com', timeout=CONNECT_TIMEOUT)
    deadline = time.monotonic() + REQUEST_TIMEOUT
    try:
        connection.connect()
        connection.sock.settimeout(min(READ_TIMEOUT, max(0.001, deadline - time.monotonic())))
        connection.request('GET', path, headers={
            'Accept': 'application/vnd.github+json', 'User-Agent': 'AppGuard-hosted-verifier',
            'X-GitHub-Api-Version': '2022-11-28', 'Cache-Control': 'no-cache',
        })
        response = connection.getresponse()
        if response.status != 200:
            raise HostedError()
        length = response.getheader('Content-Length')
        if length is not None and (not length.isdecimal() or int(length) > MAX_RESPONSE_BYTES):
            raise HostedError()
        chunks, size = [], 0
        while True:
            if response.isclosed():
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HostedError()
            # A response may have detached the socket on Connection: close.
            sock = connection.sock or getattr(getattr(response.fp, 'raw', None), '_sock', None)
            if sock is None:
                raise HostedError()
            sock.settimeout(min(READ_TIMEOUT, remaining))
            chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise HostedError()
        if length is not None and size != int(length):
            raise HostedError()
        return b''.join(chunks)
    except Exception:
        raise HostedError() from None
    finally:
        connection.close()


def fetch_github(path):
    """An owned child bounds DNS, TLS, header parsing and body reads together."""
    if not isinstance(path, str) or not _ENDPOINT.fullmatch(path):
        raise HostedError()
    deadline, process = time.monotonic() + REQUEST_TIMEOUT, None
    try:
        process = subprocess.Popen(
            [sys.executable, '-E', '-s', str(Path(__file__).resolve()), '--_github-fetch', path],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={'PATH': os.defpath, 'LC_ALL': 'C', 'LANG': 'C'}, close_fds=True, start_new_session=True)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise HostedError()
        raw, _ = process.communicate(timeout=remaining)
        if process.returncode != 0 or len(raw) > MAX_RESPONSE_BYTES or time.monotonic() > deadline:
            raise HostedError()
        return raw
    except Exception:
        raise HostedError() from None
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                process.wait(timeout=2)
            except Exception:
                raise HostedError() from None
            finally:
                if process.stdout is not None:
                    process.stdout.close()


def _timestamp(value, now, reason):
    _require(isinstance(value, str) and _UTC.fullmatch(value), reason)
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise _Denied(reason) from None
    _require(now - MAX_AGE <= result <= now, reason)
    return result


def _run(document, commit, run_id, now, *, success=True):
    reason = 'run_unverified'
    _require(isinstance(document, dict), reason)
    _require(document.get('id') == run_id and _positive(document.get('id'))
             and _positive(document.get('workflow_id')) and _positive(document.get('run_attempt'))
             and document.get('head_sha') == commit and document.get('event') == 'push'
             and document.get('head_branch') == 'main' and document.get('path') == WORKFLOW, reason)
    for label in ('repository', 'head_repository'):
        _require(isinstance(document.get(label), dict)
                 and document[label].get('full_name') == REPOSITORY, reason)
    created = _timestamp(document.get('created_at'), now, reason)
    updated = _timestamp(document.get('updated_at'), now, reason)
    _require(created <= updated, reason)
    if success:
        _require(document.get('status') == 'completed' and document.get('conclusion') == 'success', reason)
    return tuple(document.get(key) for key in ('id', 'workflow_id', 'run_attempt', 'head_sha',
                 'event', 'head_branch', 'path', 'status', 'conclusion', 'created_at', 'updated_at'))


def _run_identity(document):
    # Call only after _run validates the resource. Run and attempt resources
    # have independent timestamps; same-resource stability uses _run in full.
    return tuple(document[key] for key in ('id', 'workflow_id', 'run_attempt', 'head_sha',
                 'event', 'head_branch', 'path', 'status', 'conclusion'))


def _pages(request, endpoint, key, reason):
    result, total = [], None
    for page in range(1, MAX_PAGES + 1):
        document = request(endpoint + ('&' if '?' in endpoint else '?')
                           + f'per_page={PAGE_SIZE}&page={page}')
        count, rows = document.get('total_count'), document.get(key)
        _require(type(count) is int and 0 <= count <= PAGE_SIZE * MAX_PAGES
                 and isinstance(rows, list) and len(rows) <= PAGE_SIZE
                 and all(isinstance(row, dict) for row in rows), reason)
        _require(total is None or count == total, reason)
        total = count
        result.extend(rows)
        _require(len(result) <= total, reason)
        if len(result) == total:
            return result
        _require(len(rows) == PAGE_SIZE, reason)
    raise _Denied(reason)


def _latest(request, commit, selected, now):
    reason = 'latest_run_unverified'
    rows = _pages(request, API_PREFIX + 'actions/runs?head_sha=' + commit
                  + '&branch=main&event=push', 'workflow_runs', reason)
    ids, applicable = set(), []
    for row in rows:
        identity = row.get('id')
        _require(_positive(identity) and identity not in ids, reason)
        ids.add(identity)
        if row.get('path') != WORKFLOW:
            continue
        try:
            fingerprint = _run(row, commit, identity, now, success=False)
        except _Denied:
            raise _Denied(reason) from None
        applicable.append((row['created_at'], identity, fingerprint))
    _require(bool(applicable), reason)
    latest = max(applicable, key=lambda item: (datetime.fromisoformat(item[0].replace('Z', '+00:00')), item[1]))
    _require(latest[2] == selected, reason)
    return len(applicable)


def _jobs(request, run_id, attempt, commit):
    reason = 'jobs_unverified'
    rows = _pages(request, API_PREFIX + f'actions/runs/{run_id}/attempts/{attempt}/jobs', 'jobs', reason)
    names, ids = set(), set()
    for row in rows:
        name, identity = row.get('name'), row.get('id')
        _require(isinstance(name, str) and 0 < len(name) <= 512 and name not in names
                 and _positive(identity) and identity not in ids
                 and type(row.get('run_id')) is int and row['run_id'] == run_id
                 and row.get('head_sha') == commit and row.get('head_branch') == 'main'
                 and row.get('status') == 'completed' and row.get('conclusion') == 'success', reason)
        if 'run_attempt' in row:
            _require(type(row['run_attempt']) is int and row['run_attempt'] == attempt, reason)
        names.add(name)
        ids.add(identity)
    _require(set(REQUIRED_JOBS) <= names, reason)
    return len(rows)


def _workflow(document, expected):
    reason = 'workflow_unverified'
    _require(document.get('type') == 'file' and document.get('path') == WORKFLOW
             and document.get('encoding') == 'base64' and isinstance(document.get('content'), str)
             and type(document.get('size')) is int and 0 < document['size'] <= MAX_WORKFLOW_BYTES, reason)
    try:
        data = base64.b64decode(document['content'].replace('\n', ''), validate=True)
    except (ValueError, UnicodeError):
        raise _Denied(reason) from None
    _require(len(data) == document['size'] and data == expected
             and document.get('sha') == hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(), reason)
    return hashlib.sha256(data).hexdigest()


def _source_provenance(request, commit, candidate, snapshot, manifest, pins, private):
    """Bind every distributed blob/mode and the deterministic archive to Git."""
    reason = 'source_git_provenance'
    git_commit = request(API_PREFIX + 'git/commits/' + commit)
    tree = git_commit.get('tree')
    _require(git_commit.get('sha') == commit and isinstance(tree, dict)
             and isinstance(tree.get('sha'), str) and _SHA1.fullmatch(tree['sha']), reason)
    document = request(API_PREFIX + 'git/trees/' + tree['sha'] + '?recursive=1')
    rows = document.get('tree')
    _require(document.get('sha') == tree['sha'] and document.get('truncated') is False
             and isinstance(rows, list) and 0 < len(rows) <= MAX_TREE_ENTRIES, reason)
    entries, source, excluded = {}, {}, []
    for row in rows:
        _require(isinstance(row, dict), reason)
        name, mode, kind, oid = (row.get(key) for key in ('path', 'mode', 'type', 'sha'))
        _require(isinstance(name, str) and len(name.encode('utf-8')) <= 4096
                 and name not in entries and isinstance(oid, str) and _SHA1.fullmatch(oid), reason)
        validate_path(name)
        _require((kind == 'tree' and mode == '040000')
                 or (kind == 'blob' and mode in {'100644', '100755'}), reason)
        entries[name] = row
        if kind == 'tree':
            continue
        _require(type(row.get('size')) is int and row['size'] >= 0, reason)
        if allowed(name):
            source[name] = row
        else:
            excluded.append(name)
    for name in entries:
        for parent in validate_path(name).parents:
            if str(parent) != '.':
                _require(str(parent) in entries and entries[str(parent)]['type'] == 'tree', reason)
    actual = {name[len('source/'):] for name in pins if name.startswith('source/')}
    _require(set(source) == actual and 'LICENSE' in actual
             and manifest.get('excluded') == sorted(excluded)
             and manifest.get('archive_prefix') == 'appguard/', reason)
    files = []
    for name, row in sorted(source.items()):
        pin = pins['source/' + name]
        permissions = 0o755 if row['mode'] == '100755' else 0o644
        _require(pin['size'] == row['size']
                 and stat.S_IMODE((candidate / 'source' / name).lstat().st_mode) == permissions, reason)
        digest = hashlib.sha1(b'blob ' + str(pin['size']).encode() + b'\0')
        with (snapshot / 'source' / name).open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        _require(digest.hexdigest() == row['sha'], reason)
        files.append((name, permissions))
    _require('source.tar.gz' in pins, reason)
    rebuilt = private / 'source.tar.gz'
    write_archive(snapshot / 'source', rebuilt, files)
    _require(_read(rebuilt)['sha256'] == pins['source.tar.gz']['sha256'], reason)
    _require(_unchanged(candidate, pins), 'candidate_changed')
    return len(files)


def verify_hosted(candidate, expected_commit, repository, run_id, output, *, fetch=None, now=None):
    """Write a new bounded report; invalid evidence produces a denied gate."""
    try:
        candidate, output = _path(candidate, directory=True), _path(output, new=True)
        if (not isinstance(expected_commit, str) or not _SHA1.fullmatch(expected_commit)
                or repository != REPOSITORY or not _positive(run_id)
                or output == candidate or candidate in output.parents):
            raise HostedError()
        parent_identity = _stamp(output.parent.stat())[:2]
        now = datetime.now(timezone.utc) if now is None else now
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise HostedError()
    except Exception:
        raise HostedError() from None
    report = {'schema': 1, 'evidence_class': 'github_public_https_api',
              'technical_gate_verified': False, 'release_ready': False,
              'external_approvals': 'not_verified', 'reason': 'candidate_unverified',
              'candidate_commit': expected_commit, 'repository': REPOSITORY, 'workflow_path': WORKFLOW,
              'run_id': run_id, 'run_attempt': None, 'job_count': 0, 'applicable_run_count': 0,
              'source_file_count': 0,
              'api_response_count': 0, 'observed_at': now.isoformat(timespec='seconds').replace('+00:00', 'Z'),
              'sha256': {}}
    with tempfile.TemporaryDirectory(prefix='.hosted-', dir=output.parent) as temp:
        private = Path(temp)
        try:
            pins, documents = _snapshot(candidate, private / 'candidate', candidate=True)
            manifest = documents.get('manifest.json')
            _require(isinstance(manifest, dict) and type(manifest.get('schema')) is int
                     and manifest['schema'] == 1 and manifest.get('commit') == expected_commit
                     and isinstance(manifest.get('sha256'), dict) and bool(manifest['sha256'])
                     and all(isinstance(name, str) and isinstance(digest, str) and _DIGEST.fullmatch(digest)
                             for name, digest in manifest['sha256'].items()), 'candidate_unverified')
            verify_candidate(private / 'candidate')
            report['sha256']['candidate_manifest'] = pins['manifest.json']['sha256']
            workflow_name = 'source/' + WORKFLOW
            _require(workflow_name in pins and pins[workflow_name]['size'] <= MAX_WORKFLOW_BYTES,
                     'candidate_unverified')
            expected = (private / 'candidate' / workflow_name).read_bytes()
            response_hashes = hashlib.sha256()

            def request(path):
                _require(_unchanged(candidate, pins), 'candidate_changed')
                _require(report['api_response_count'] < MAX_API_REQUESTS, 'api_budget_exceeded')
                try:
                    raw = (fetch or fetch_github)(path)
                except Exception:
                    raise _Denied('api_unavailable') from None
                finally:
                    _require(_unchanged(candidate, pins), 'candidate_changed')
                _require(type(raw) is bytes and len(raw) <= MAX_RESPONSE_BYTES, 'api_invalid')
                try:
                    result = _json(raw)
                except Exception:
                    raise _Denied('api_invalid') from None
                # Length-prefixed endpoint and body hashes bind the ordered API observation.
                for value in (path.encode(), raw):
                    response_hashes.update(len(value).to_bytes(8, 'big'))
                    response_hashes.update(value)
                report['api_response_count'] += 1
                report['sha256']['api_responses'] = response_hashes.hexdigest()
                return result

            report['reason'] = 'run_unverified'
            run_path = API_PREFIX + f'actions/runs/{run_id}'
            run = request(run_path)
            selected = _run(run, expected_commit, run_id, now)
            attempt = run['run_attempt']
            report['run_attempt'] = attempt
            attempt_document = request(run_path + f'/attempts/{attempt}')
            _run(attempt_document, expected_commit, run_id, now)
            _require(_run_identity(attempt_document) == _run_identity(run), 'run_unverified')
            report['reason'] = 'source_git_provenance'
            report['source_file_count'] = _source_provenance(request, expected_commit, candidate,
                private / 'candidate', manifest, pins, private)
            report['sha256']['source_archive'] = pins['source.tar.gz']['sha256']
            report['reason'] = 'workflow_unverified'
            report['sha256']['workflow'] = _workflow(request(API_PREFIX + 'contents/' + WORKFLOW
                                                           + '?ref=' + expected_commit), expected)
            report['reason'] = 'jobs_unverified'
            report['job_count'] = _jobs(request, run_id, attempt, expected_commit)
            report['reason'] = 'run_unverified'
            _require(_run(request(run_path), expected_commit, run_id, now) == selected, 'run_unverified')
            report['reason'] = 'latest_run_unverified'
            report['applicable_run_count'] = _latest(request, expected_commit, selected, now)
            _require(_unchanged(candidate, pins), 'candidate_changed')
            report.update(technical_gate_verified=True, reason='verified')
        except _Denied as denied:
            report['reason'] = denied.reason
        except Exception:
            # No provider exception, raw report content, or local path is public.
            pass
        result = private / 'result'
        result.mkdir(mode=0o700)
        write_json(result / 'hosted.json', report)
        (result / 'hosted.json').chmod(0o600)
        try:
            _path(output, new=True)
            if _stamp(output.parent.stat())[:2] != parent_identity:
                raise HostedError()
            # mkdir is an atomic no-overwrite claim. POSIX rename could replace
            # an empty directory that appeared after the preceding check.
            output.mkdir(mode=0o700)
            identity = _stamp(output.lstat())[:2]
            descriptor, linked = None, False
            try:
                descriptor = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                _require(_stamp(os.fstat(descriptor))[:2] == identity, 'output_unavailable')
                os.link(result / 'hosted.json', 'hosted.json', dst_dir_fd=descriptor, follow_symlinks=False)
                linked = True
                _path(output, directory=True)
                _require(_stamp(output.lstat())[:2] == identity, 'output_unavailable')
            except Exception:
                if linked:
                    os.unlink('hosted.json', dir_fd=descriptor)
                raise
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        except Exception:
            raise HostedError() from None
    return report


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'hosted_verification_unavailable\n')


def main():
    parser = _Parser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify_hosted(args.candidate, args.expected_commit, args.repository, args.run_id, args.output)
    except Exception:
        parser.exit(2, 'hosted_verification_unavailable\n')
    print(json.dumps({key: report[key] for key in ('technical_gate_verified', 'release_ready', 'reason')}, sort_keys=True))
    if not report['technical_gate_verified']:
        parser.exit(1)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--_github-fetch':
        try:
            sys.stdout.buffer.write(_fetch_direct(sys.argv[2]))
        except Exception:
            sys.exit('hosted_verification_unavailable')
    else:
        main()
