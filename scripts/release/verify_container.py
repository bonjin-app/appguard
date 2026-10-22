#!/usr/bin/env python3
"""Authenticate bounded container evidence through fixed public GitHub metadata.

The caller supplies an untrusted ZIP, never a provider URL or credential. Only
fresh API metadata authenticates its bytes. No candidate code is executed and
neither an authenticated observation nor an operating pass approves a release.

The output parent must belong to the current user and deny group/other writes.
Staging assumes no same-user or host compromise; SIGKILL can prevent cleanup.
"""
import argparse
import base64
import binascii
import ctypes
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import sys
import tempfile
import tomllib
import zlib

import verify_hosted as hosted
from assess import _json, _path, _snapshot, _stamp, _unchanged
from scan import verify_candidate

REPOSITORY = hosted.REPOSITORY
WORKFLOW = '.github/workflows/container-readiness.yml'
JOB = 'owned-container-deployment'
SCAN_STEP = 'Scan the exact runtime images without suppressions'
PRIMARY_STEPS = ('Checkout exact candidate', 'Set up Python 3.11', 'Set up pinned uv 0.13.4',
    'Set up Temurin 17', 'Frozen tooling and focused container safety tests',
    'Build and exercise the owned container deployment', SCAN_STEP,
    'Prepare fixed-schema container evidence', 'Retain fixed-schema operating and image status only')
POST_STEPS = tuple('Post ' + name for name in reversed(PRIMARY_STEPS[:4]))
ROLES = ('gateway', 'backend', 'redis')
LIMITS = {'gateway': (268435456, 1000000000, 64), 'backend': (536870912, 1000000000, 128),
          'redis': (134217728, 500000000, 32)}
CORE_CHECKS = ('resource_and_isolation_inspection', 'effective_process_restrictions', 'signed_fidelity',
    'replay_rejected', 'backend_bypass_zero_dispatch', 'absolute_upload_deadline_zero_dispatch',
    'malformed_zero_dispatch', 'redis_outage_denied', 'redis_recovery', 'redis_restart_replay_retained',
    'owned_container_cleanup', 'provenance_unchanged')
OP_CHECKS = ('sustained_traffic', 'counter_fidelity', 'runtime_unchanged', 'no_oom_or_restart',
    'backend_restart_replay_retained', 'owned_container_cleanup', 'provenance_unchanged')
OUTCOME_CODES = ('BACKEND_TIMEOUT', 'BACKEND_UNAVAILABLE', 'UPLOAD_TIMEOUT', 'INVALID_REQUEST',
    'INGRESS_OVERLOADED', 'APPLICATION_UNAVAILABLE', 'REPLAY_DETECTED', 'REPLAY_STORE_UNAVAILABLE',
    'INVALID_TIME', 'INVALID_SIGNATURE', 'DIGEST_MISMATCH', 'KEY_REJECTED', 'UNSUPPORTED_PROFILE',
    'AUTHENTICATION_REQUIRED', 'IDENTITY_UNAVAILABLE', 'KEY_RESOLVER_UNAVAILABLE')
LATENCY_BOUNDS = (1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000)
OP_SCOPE = 'owned resource-constrained Linux containers; synthetic signed/replay HTTP traffic'
RESOURCE_SCOPE = 'sampled Docker CLI and exact cgroup-v2 readbacks; observer exec processes contribute to usage; no leak proof'
REDIS_RESTART_SCOPE = 'routine owned Redis container stop/start; no power-loss or disk-failure claim'
BACKEND_RESTART_SCOPE = 'owned backend container stop/start; existing Redis volume and network namespace retained'
RECEIPT_LIMITATIONS = ('owned local Linux Docker daemon only', 'no external security or license approval',
    'no provider account or physical device evidence', 'image vulnerabilities require a separate current scan')
OP_LIMITATIONS = ('sampled resource points are not leak or long-term capacity proof',
    'cgroup v2 is required for effective resource evidence', 'Docker CLI memory excludes inactive file cache and is rounded',
    'no external security, provider, production or physical-device approval')
RESOURCE_DIAGNOSTIC_CHECKS = ('core_scheduling_metric_present', 'cpu_limit_matches', 'memory_limit_matches',
    'memory_usage_bounded', 'pids_limit_matches', 'pids_usage_bounded', 'swap_disabled')
STATIC_SOURCES = ('scripts/qualification/spring_containers.py', 'scripts/qualification/spring_ingress.py',
    'sdk/python/pyproject.toml', 'sdk/python/uv.lock', 'sdk/python/README.md', 'sdk/python/LICENSE', 'LICENSE',
    'sdk/spring-boot/pom.xml', 'examples/spring-ingress/backend/pom.xml')
SOURCE_DIRECTORIES = ('deploy/spring-ingress', 'sdk/python/src', 'sdk/spring-boot/src/main', 'examples/spring-ingress')
MAX_ZIP_BYTES = 8 * 1024 * 1024
MAX_ENTRY_BYTES = 4 * 1024 * 1024
MAX_EXPANDED_BYTES = 8 * 1024 * 1024
MAX_API_REQUESTS = 24
SHA = re.compile(r'[0-9a-f]{64}\Z')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
FILES = frozenset(('binding.json', 'receipt.json', 'image-status.json'))
SCANNER_PINS = {
    'Linux-x86_64': 'c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0',
    'Darwin-arm64': '11a9b6cd2752011b54f01ea4bd0dbfa9f0c41dc6538d5a3f9d23955f471bf4e5',
}
FINDING_ID = re.compile(r'[A-Z][A-Z0-9]{1,19}(?:-[A-Za-z0-9]+){1,9}\Z')
PACKAGE = re.compile(r'(?:[A-Za-z0-9][A-Za-z0-9._+:-]*|@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)\Z')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+~:!*-]*\Z')
PACKAGE_TYPE = re.compile(r'[a-z][a-z0-9-]{0,39}\Z')
DB_TIME = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z\Z')
_require, _Denied = hosted._require, hosted._Denied


class ContainerError(ValueError):
    def __init__(self):
        super().__init__('container_verification_unavailable')


def _exact(value, keys, reason='operating_unverified'):
    _require(type(value) is dict and set(value) == set(keys), reason)
    return value


def _count(value, maximum=2 ** 40, reason='operating_unverified'):
    _require(type(value) is int and 0 <= value <= maximum, reason)
    return value


def _number(value, maximum=2 ** 63 - 1, reason='operating_unverified'):
    _require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum, reason)
    return value


def _digest(value, reason='operating_unverified'):
    _require(type(value) is str and SHA.fullmatch(value), reason)


def _checks(value, names):
    _exact(value, names)
    _require(all(v is True for v in value.values()), 'operating_unverified')


def _finding_text(value, pattern, maximum=200):
    _require(type(value) is str and 0 < len(value) <= maximum and pattern.fullmatch(value), 'image_status_unverified')


def _image_time(value):
    _finding_text(value, DB_TIME, 40)
    try: base = datetime.strptime(value[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    except ValueError: raise _Denied('image_status_unverified') from None
    fraction = value[20:-1] if value[19] == '.' else ''
    return base, int(fraction.ljust(9, '0'))


def _image_details(image, run):
    """Validate only bounded schema-2 data; never copy raw finding strings.

    Schema 1 supports historical operating evidence without claiming detailed
    finding provenance. Database digests identify observed bytes, not coverage.
    """
    reason = 'image_status_unverified'
    scanner = _exact(image['scanner'], ('name', 'version', 'platform', 'archive_sha256', 'executable_sha256'), reason)
    _require(scanner['name'] == 'trivy' and scanner['version'] == '0.76.1'
        and type(scanner['platform']) is str and scanner['platform'] in SCANNER_PINS
        and scanner['archive_sha256'] == SCANNER_PINS[scanner['platform']], reason)
    _digest(scanner['executable_sha256'], reason)
    databases = _exact(image['databases'], ('vulnerability', 'java'), reason)
    run_created, run_updated = (_image_time(run[key]) for key in ('created_at', 'updated_at'))
    for name, schema in (('vulnerability', 2), ('java', 1)):
        row = _exact(databases[name], ('schema', 'metadata_sha256', 'database_sha256',
            'updated_at', 'next_update', 'downloaded_at'), reason)
        _require(type(row['schema']) is int and row['schema'] == schema, reason)
        for key in ('metadata_sha256', 'database_sha256'): _digest(row[key], reason)
        times = {key: _image_time(row[key]) for key in ('updated_at', 'next_update', 'downloaded_at')}
        _require(times['updated_at'] <= times['downloaded_at']
            and times['updated_at'] < times['next_update']
            and run_created <= times['downloaded_at'] <= run_updated, reason)
    _require(image['finding_details_complete'] is True, reason)
    for row in image['images'].values():
        _require(row['finding_details_complete'] is True and type(row['findings']) is list
            and len(row['findings']) <= 1024 and len(row['findings']) == row['vulnerabilities'], reason)
        for finding in row['findings']:
            _exact(finding, ('vulnerability_id', 'package', 'installed_version', 'fixed_versions',
                'severity', 'source_class', 'package_type', 'occurrence_sha256'), reason)
            _finding_text(finding['vulnerability_id'], FINDING_ID)
            _finding_text(finding['package'], PACKAGE)
            _finding_text(finding['installed_version'], VERSION)
            _finding_text(finding['package_type'], PACKAGE_TYPE, 40)
            _require(type(finding['severity']) is str and finding['severity'] in ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
                and type(finding['source_class']) is str and finding['source_class'] in ('os-pkgs', 'lang-pkgs'), reason)
            _digest(finding['occurrence_sha256'], reason)
            _require(type(finding['fixed_versions']) is list and len(finding['fixed_versions']) <= 32, reason)
            for version in finding['fixed_versions']: _finding_text(version, VERSION)


def _pin_zip(path, copy_to=None):
    path = _path(path)
    initial = path.lstat()
    _require(stat.S_ISREG(initial.st_mode) and 22 <= initial.st_size <= MAX_ZIP_BYTES, 'artifact_zip_unverified')
    digest, size = hashlib.sha256(), 0
    output = copy_to.open('xb') if copy_to is not None else None
    if output is not None: copy_to.chmod(0o600)
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            current = os.fstat(stream.fileno())
            _require(stat.S_ISREG(current.st_mode) and _stamp(current) == _stamp(initial), 'artifact_zip_changed')
            while chunk := stream.read(65536):
                size += len(chunk)
                _require(size <= MAX_ZIP_BYTES, 'artifact_zip_unverified')
                digest.update(chunk)
                if output is not None: output.write(chunk)
            _require(_stamp(os.fstat(stream.fileno())) == _stamp(initial), 'artifact_zip_changed')
        _require(_stamp(path.lstat()) == _stamp(initial), 'artifact_zip_changed')
    finally:
        if output is not None: output.close()
    return {'stamp': _stamp(initial), 'size': size, 'sha256': digest.hexdigest()}


def _archive(raw):
    """Parse only three classic ZIP members; no extraction or ZipFile allocation.

    Validate bounded EOCD/central metadata first, then stream actual DEFLATE
    output with a maximum length on every decompressor call. ZIP64, comments,
    SFX/trailing bytes, encryption, links and special files are unsupported.
    """
    reason = 'artifact_zip_unverified'
    _require(type(raw) is bytes and 22 <= len(raw) <= MAX_ZIP_BYTES, reason)
    position = raw.rfind(b'PK\x05\x06', max(0, len(raw) - 65557))
    _require(position >= 0 and position + 22 == len(raw), reason)
    _, disk, start_disk, count, total, size, offset, comment = struct.unpack_from('<4s4H2IH', raw, position)
    _require(disk == start_disk == comment == 0 and count == total == 3
             and 0 < size <= 16384 and offset + size == position, reason)
    records, cursor = [], offset
    def extra(data):
        cursor = 0
        while cursor < len(data):
            _require(cursor + 4 <= len(data), reason)
            kind, length = struct.unpack_from('<HH', data, cursor); cursor += 4
            _require(kind in {0x5455, 0x7875} and cursor + length <= len(data), reason)
            cursor += length
    while cursor < position:
        _require(len(records) < 3 and cursor + 46 <= position, reason)
        fields = struct.unpack_from('<4s6H3I5H2I', raw, cursor)
        signature, made, version, flags, method, _, _, crc, compressed, expanded, namesize, extrasize, commentsize, disk, _, attributes, local = fields
        _require(signature == b'PK\x01\x02' and version in {10, 20} and flags & ~0x808 == 0
            and method in {0, 8} and disk == commentsize == 0 and 0 < namesize <= 128 and extrasize <= 1024
            and 0 < compressed <= MAX_ZIP_BYTES and 0 < expanded <= MAX_ENTRY_BYTES
            and expanded <= compressed * 200 and stat.S_IFMT(attributes >> 16) in {0, stat.S_IFREG}
            and attributes & 0x10 == 0 and local < offset, reason)
        end = cursor + 46 + namesize + extrasize
        _require(end <= position, reason)
        name = raw[cursor + 46:cursor + 46 + namesize].decode('ascii')
        _require(name in FILES and all(r['name'] != name and r['offset'] != local for r in records), reason)
        extra(raw[cursor + 46 + namesize:end])
        records.append(dict(name=name, offset=local, flags=flags, method=method, crc=crc,
                            compressed=compressed, expanded=expanded))
        cursor = end
    _require(cursor == position and len(records) == 3 and {r['name'] for r in records} == FILES, reason)
    records.sort(key=lambda r: r['offset'])
    _require(records[0]['offset'] == 0, reason)
    documents, hashes, expanded_total = {}, {}, 0
    for index, record in enumerate(records):
        start = record['offset']; stop = records[index + 1]['offset'] if index + 1 < len(records) else offset
        _require(start + 30 <= stop, reason)
        signature, version, flags, method, _, _, crc, compressed, expanded, namesize, extrasize = struct.unpack_from('<4s5H3I2H', raw, start)
        header_end = start + 30 + namesize + extrasize
        _require(signature == b'PK\x03\x04' and version in {10, 20} and flags == record['flags']
            and method == record['method'] and 0 < namesize <= 128 and extrasize <= 1024 and header_end <= stop, reason)
        _require(raw[start + 30:start + 30 + namesize] == record['name'].encode(), reason)
        extra(raw[start + 30 + namesize:header_end])
        if flags & 8:
            _require(crc in {0, record['crc']} and compressed in {0, record['compressed']}
                     and expanded in {0, record['expanded']}, reason)
        else:
            _require((crc, compressed, expanded) == (record['crc'], record['compressed'], record['expanded']), reason)
        body_end = header_end + record['compressed']
        _require(body_end <= stop, reason)
        suffix = raw[body_end:stop]
        if flags & 8:
            if len(suffix) == 16 and suffix[:4] == b'PK\x07\x08': suffix = suffix[4:]
            _require(len(suffix) == 12 and struct.unpack('<3I', suffix) == (record['crc'], record['compressed'], record['expanded']), reason)
        else: _require(not suffix, reason)
        body, checksum = bytearray(), 0
        def consume(chunk):
            nonlocal expanded_total, checksum
            expanded_total += len(chunk)
            _require(len(body) + len(chunk) <= MAX_ENTRY_BYTES and expanded_total <= MAX_EXPANDED_BYTES, reason)
            body.extend(chunk); checksum = binascii.crc32(chunk, checksum)
        decoder = zlib.decompressobj(-15) if method == 8 else None
        for cursor in range(header_end, body_end, 65536):
            pending = raw[cursor:min(cursor + 65536, body_end)]
            if decoder is None: consume(pending)
            else:
                while pending:
                    previous = pending
                    consume(decoder.decompress(pending, min(65536, MAX_ENTRY_BYTES - len(body) + 1)))
                    pending = decoder.unconsumed_tail
                    _require(not decoder.unused_data and (not pending or pending != previous), reason)
        _require(decoder is None or decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail, reason)
        _require(len(body) == record['expanded'] and checksum & 0xffffffff == record['crc'], reason)
        documents[record['name']] = _json(bytes(body))
        hashes[record['name']] = hashlib.sha256(body).hexdigest()
    return documents, hashes


def _sources(snapshot, pins):
    expected = set(STATIC_SOURCES)
    for directory in SOURCE_DIRECTORIES:
        _require((snapshot / 'source' / directory).is_dir(), 'source_hashes_unverified')
        prefix = 'source/' + directory + '/'
        for name in pins:
            if name.startswith(prefix) and not {'__pycache__', 'target', '.venv'} & set(Path(name[len(prefix):]).parts):
                expected.add(name[len('source/'):])
    _require(0 < len(expected) <= 2048 and all('source/' + name in pins for name in expected), 'source_hashes_unverified')
    _require(all(pins['source/' + name]['size'] <= 16777216 for name in expected), 'source_hashes_unverified')
    return {name: pins['source/' + name]['sha256'] for name in sorted(expected)}


def _soak(op, baseline):
    seconds, workers = op['requested_seconds'], op['concurrency']
    _require(type(seconds) is int and 1 <= seconds <= 3600 and type(workers) is int and 1 <= workers <= 32, 'operating_unverified')
    s = _exact(op['soak'], ('requested_seconds', 'concurrency', 'elapsed_seconds', 'requests_per_second', 'error_rate',
        'signed_requests', 'replay_requests', 'fidelity_failures', 'replay_failures', 'transport_errors', 'latency', 'outcomes'))
    _require(type(s['requested_seconds']) is int and s['requested_seconds'] == seconds
        and type(s['concurrency']) is int and s['concurrency'] == workers, 'operating_unverified')
    elapsed = _number(s['elapsed_seconds'], 3610)
    n = _count(s['signed_requests'])
    _require(n > 0 and type(s['replay_requests']) is int and s['replay_requests'] == n
        and seconds <= elapsed <= seconds + 10, 'operating_unverified')
    for key in ('fidelity_failures', 'replay_failures', 'transport_errors'):
        _require(_count(s[key]) == 0, 'operating_unverified')
    _require(_number(s['error_rate'], 1) == 0 and math.isclose(_number(s['requests_per_second']), 2 * n / elapsed, rel_tol=1e-9, abs_tol=1e-9), 'operating_unverified')
    outcomes = _exact(s['outcomes'], ('schema', 'normal', 'replay'))
    _require(type(outcomes['schema']) is int and outcomes['schema'] == 1, 'operating_unverified')
    for role, status in (('normal', 200), ('replay', 403)):
        row = _exact(outcomes[role], ('missing_status', 'invalid_status', 'unrecognized_error_body', 'transport_errors', 'statuses', 'error_codes'))
        for key in ('missing_status', 'invalid_status', 'unrecognized_error_body', 'transport_errors'):
            _require(_count(row[key]) == 0, 'operating_unverified')
        _require(type(row['statuses']) is list and len(row['statuses']) == 1, 'operating_unverified')
        outcome = _exact(row['statuses'][0], ('status', 'count'))
        _require(type(outcome['status']) is int and outcome['status'] == status and _count(outcome['count']) == n, 'operating_unverified')
        codes = _exact(row['error_codes'], OUTCOME_CODES)
        for code, number in codes.items():
            _require(_count(number) == (n if role == 'replay' and code == 'REPLAY_DETECTED' else 0), 'operating_unverified')
    latency = _exact(s['latency'], ('samples', 'min_ms', 'max_ms', 'mean_ms', 'p50_upper_bound_ms', 'p95_upper_bound_ms',
        'p99_upper_bound_ms', 'histogram_upper_bounds_ms', 'histogram_counts'))
    _require(type(latency['histogram_upper_bounds_ms']) is list and all(type(v) is int for v in latency['histogram_upper_bounds_ms'])
        and latency['histogram_upper_bounds_ms'] == list(LATENCY_BOUNDS), 'operating_unverified')
    histogram = latency['histogram_counts']
    _require(type(histogram) is list and len(histogram) == len(LATENCY_BOUNDS) + 1, 'operating_unverified')
    _require(sum(_count(v) for v in histogram) == _count(latency['samples']) == 2 * n, 'operating_unverified')
    for key in ('min_ms', 'max_ms', 'mean_ms', 'p50_upper_bound_ms', 'p95_upper_bound_ms', 'p99_upper_bound_ms'): _number(latency[key])
    _require(0 <= latency['min_ms'] <= latency['mean_ms'] <= latency['max_ms'], 'operating_unverified')
    elapsed_ms = elapsed * 1000
    tolerance = max(1e-6, elapsed_ms * 1e-9)
    _require(latency['max_ms'] <= elapsed_ms + tolerance, 'operating_unverified')
    occupied = [i for i, count in enumerate(histogram) if count]
    for key, index in (('min_ms', occupied[0]), ('max_ms', occupied[-1])):
        lower = LATENCY_BOUNDS[index - 1] if index else 0
        upper = LATENCY_BOUNDS[index] if index < len(LATENCY_BOUNDS) else sys.float_info.max
        _require((latency[key] > lower if index else latency[key] >= lower) and latency[key] <= upper, 'operating_unverified')
    lower_mean = math.fsum(count * max(latency['min_ms'], LATENCY_BOUNDS[i - 1] if i else 0)
        for i, count in enumerate(histogram)) / (2 * n)
    upper_mean = math.fsum(count * min(latency['max_ms'], LATENCY_BOUNDS[i] if i < len(LATENCY_BOUNDS)
        else latency['max_ms']) for i, count in enumerate(histogram)) / (2 * n)
    mean_tolerance = max(1e-6, latency['max_ms'] * 1e-9)
    _require(lower_mean - mean_tolerance <= latency['mean_ms'] <= upper_mean + mean_tolerance, 'operating_unverified')
    for fraction, key in ((.5, 'p50_upper_bound_ms'), (.95, 'p95_upper_bound_ms'), (.99, 'p99_upper_bound_ms')):
        total, quantile = 0, None
        for index, count in enumerate(histogram):
            total += count
            if total >= math.ceil(2 * n * fraction):
                quantile = min(LATENCY_BOUNDS[index], latency['max_ms']) if index < len(LATENCY_BOUNDS) else latency['max_ms']
                break
        _require(latency[key] == quantile, 'operating_unverified')
    counters = _exact(op['counters'], ('before', 'after', 'delta'))
    for point in counters:
        _exact(counters[point], ('dispatch', 'auth', 'key', 'replay', 'resource'))
        for value in counters[point].values(): _count(value)
    _require(counters['before'] == baseline, 'operating_unverified')
    for key in counters['before']:
        _require(counters['after'][key] - counters['before'][key] == counters['delta'][key]
                 == (n if key == 'resource' else 2 * n), 'operating_unverified')
    return seconds, workers, elapsed, n


def _moment(value, now, reason):
    _require(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z', value), reason)
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    _require(now - hosted.MAX_AGE <= result <= now, reason)
    return result


def _resources(value, created, updated, now, seconds):
    r = _exact(value, ('samples', 'interval_seconds', 'scope', 'before', 'after', 'peak', 'sampling_diagnostic'))
    _require(2 <= _count(r['samples'], 2 + math.ceil((seconds + 15) / 5)) and type(r['interval_seconds']) is int
             and r['interval_seconds'] == 5 and r['scope'] == RESOURCE_SCOPE, 'operating_unverified')
    group_keys = ('version', 'memory_bytes', 'memory_limit_bytes', 'swap_limit_bytes', 'swap_bytes',
        'memory_oom_events', 'memory_oom_kills', 'memory_max_events', 'cpu_usage_usec', 'cpu_throttled_usec',
        'cpu_throttled_periods', 'cpu_periods', 'cpu_quota_usec', 'cpu_period_usec', 'pids', 'pids_limit')
    for point in ('before', 'after'):
        _exact(r[point], ROLES)
        for role, row in r[point].items():
            memory, cpu, pids = LIMITS[role]
            _exact(row, ('state', 'docker', 'cgroup', 'restriction_sha256'))
            _digest(row['restriction_sha256'])
            state = _exact(row['state'], ('running', 'oom_killed', 'exit_code', 'restart_count', 'started_at'))
            _require(state['running'] is True and state['oom_killed'] is False
                and _count(state['restart_count']) == _count(state['exit_code']) == 0
                and created <= _moment(state['started_at'], now, 'operating_unverified') <= updated, 'operating_unverified')
            d = _exact(row['docker'], ('cpu_percent', 'memory_bytes', 'memory_limit_bytes', 'pids'))
            _number(d['cpu_percent'], sys.float_info.max)
            for name in ('memory_bytes', 'memory_limit_bytes', 'pids'): _count(d[name], 2 ** 63 - 1)
            _require(abs(d['memory_limit_bytes'] - memory) <= 1048576
                and d['memory_bytes'] <= memory and d['pids'] <= pids, 'operating_unverified')
            c = _exact(row['cgroup'], group_keys)
            for number in c.values(): _count(number, 2 ** 63 - 1)
            _require(c['version'] == 2 and c['memory_limit_bytes'] == memory and c['pids_limit'] == pids
                and c['memory_bytes'] <= memory and c['pids'] <= pids
                and c['swap_limit_bytes'] == c['swap_bytes'] == c['memory_oom_events'] == c['memory_oom_kills'] == 0
                and c['cpu_period_usec'] > 0 and c['cpu_quota_usec'] * 1000000000 == cpu * c['cpu_period_usec'], 'operating_unverified')
    _exact(r['peak'], ROLES)
    for role, peak in r['peak'].items():
        memory, _, pids = LIMITS[role]
        before, after = r['before'][role], r['after'][role]
        _require(before['restriction_sha256'] == after['restriction_sha256'] and before['state'] == after['state'], 'operating_unverified')
        for key in ('cpu_usage_usec', 'cpu_throttled_usec', 'cpu_throttled_periods', 'cpu_periods', 'memory_max_events'):
            _require(after['cgroup'][key] >= before['cgroup'][key], 'operating_unverified')
        _exact(peak, ('docker_memory_bytes', 'cgroup_memory_bytes', 'pids', 'cpu_percent'))
        for key, limit, source, field in (('docker_memory_bytes', memory, 'docker', 'memory_bytes'),
                ('cgroup_memory_bytes', memory, 'cgroup', 'memory_bytes'), ('pids', pids, 'cgroup', 'pids')):
            _require(max(before[source][field], after[source][field]) <= _count(peak[key], limit), 'operating_unverified')
        _require(_number(peak['cpu_percent'], sys.float_info.max) >= max(before['docker']['cpu_percent'], after['docker']['cpu_percent']), 'operating_unverified')
    diagnostic = _exact(r['sampling_diagnostic'], ('stage', 'role', 'code', 'field', 'checks', 'numbers'))
    _require(diagnostic['stage'] == 'completed' and diagnostic['role'] in ROLES
             and diagnostic['code'] is diagnostic['field'] is None, 'operating_unverified')
    checks = _exact(diagnostic['checks'], RESOURCE_DIAGNOSTIC_CHECKS)
    _require(type(checks['core_scheduling_metric_present']) is bool
        and all(value is True for key, value in checks.items() if key != 'core_scheduling_metric_present'), 'operating_unverified')
    numbers = _exact(diagnostic['numbers'], ('cpu_period_usec', 'cpu_quota_usec', 'docker_memory_limit_bytes',
        'docker_pids', 'expected_memory_limit_bytes', 'expected_nano_cpus', 'expected_pids_limit', 'memory_bytes',
        'memory_limit_bytes', 'pids', 'pids_limit', 'swap_bytes', 'swap_limit_bytes'))
    for number in numbers.values(): _count(number, 2 ** 63 - 1)
    memory, cpu, pids = LIMITS[diagnostic['role']]
    _require(numbers['memory_limit_bytes'] == numbers['expected_memory_limit_bytes'] == memory
        and numbers['pids_limit'] == numbers['expected_pids_limit'] == pids and numbers['expected_nano_cpus'] == cpu
        and numbers['cpu_period_usec'] > 0 and numbers['cpu_quota_usec'] * 1000000000 == cpu * numbers['cpu_period_usec']
        and numbers['memory_bytes'] <= memory and max(numbers['pids'], numbers['docker_pids']) <= pids
        and abs(numbers['docker_memory_limit_bytes'] - memory) <= 1048576
        and numbers['swap_bytes'] == numbers['swap_limit_bytes'] == 0, 'operating_unverified')
    return r['samples']


def _receipt(receipt, image, hashes, commit, expected_sources, snapshot, run, now):
    reason = 'operating_unverified'
    r = _exact(receipt, ('schema', 'evidence_class', 'profile', 'observed_at', 'candidate_commit',
        'source_matches_commit', 'source_sha256', 'checks', 'release_ready', 'external_approval',
        'technical_verification', 'cleanup', 'phase', 'limitations', 'containers', 'docker_server_version',
        'resolved_compose_sha256', 'runtime_versions', 'redis_restart', 'backend_counters', 'resource_limits', 'operational'))
    _require(type(r['schema']) is int and r['schema'] == 1 and r['evidence_class'] == 'owned_container_deployment'
        and r['profile'] == 'spring-loopback-mtls-containers-v1' and r['candidate_commit'] == commit
        and r['source_matches_commit'] is r['technical_verification'] is r['cleanup'] is True
        and r['release_ready'] is r['external_approval'] is False and r['phase'] == 'completed'
        and r['limitations'] == list(RECEIPT_LIMITATIONS), reason)
    _require(type(r['source_sha256']) is dict and r['source_sha256'] == expected_sources, 'source_hashes_unverified')
    created = hosted._timestamp(run['created_at'], now, reason)
    updated = hosted._timestamp(run['updated_at'], now, reason)
    observed = _moment(r['observed_at'], now, reason)
    _require(created <= observed <= updated, reason)
    _checks(r['checks'], CORE_CHECKS); _digest(r['resolved_compose_sha256'])
    _require(type(r['docker_server_version']) is str
        and re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:[-+][A-Za-z0-9._-]{1,64})?', r['docker_server_version']), reason)
    c = _exact(r['containers'], ('container_ids', 'image_ids', 'logging', 'gateway_port'))
    _require(1 <= _count(c['gateway_port'], 65535), reason)
    for key, pattern in (('container_ids', SHA), ('image_ids', IMAGE)):
        _exact(c[key], ROLES)
        _require(all(type(value) is str and pattern.fullmatch(value) for value in c[key].values())
                 and len(set(c[key].values())) == 3, reason)
    _exact(c['logging'], ROLES); _exact(r['resource_limits'], ROLES)
    for role in ROLES:
        policy = _exact(c['logging'][role], ('driver', 'max_size_bytes', 'max_files', 'compress'))
        _require(policy['driver'] == 'local' and _count(policy['max_size_bytes']) == 1048576
                 and _count(policy['max_files']) == 1 and policy['compress'] is False, reason)
        memory, cpu, pids = LIMITS[role]
        limits = _exact(r['resource_limits'][role], ('Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit'))
        for value in limits.values(): _count(value)
        _require(limits == dict(Memory=memory, MemorySwap=memory, NanoCpus=cpu, PidsLimit=pids), reason)
    versions = _exact(r['runtime_versions'], ('python', 'java', 'redis', 'installers_absent',
        'python_inventory_matches_build', 'python_required_packages'))
    _require(versions['python'] == '3.11.17' and versions['java'] == '17.0.20.1' and versions['redis'] == '7.2.16'
        and versions['python_inventory_matches_build'] is True, reason)
    _checks(versions['installers_absent'], ('pip', 'setuptools', 'wheel', 'ensurepip'))
    required = ('cryptography', 'h11', 'redis', 'uvicorn')
    _exact(versions['python_required_packages'], required)
    lock = tomllib.loads((snapshot / 'source/sdk/python/uv.lock').read_text())
    _require(type(lock.get('package')) is list and len(lock['package']) <= 2048, reason)
    for name in required:
        matches = [p for p in lock['package'] if type(p) is dict and p.get('name') == name]
        _require(len(matches) == 1 and type(matches[0].get('version')) is str
            and re.fullmatch(r'[A-Za-z0-9.+_-]{1,128}', matches[0]['version'])
            and matches[0].get('source') == {'registry': 'https://pypi.org/simple'}
            and versions['python_required_packages'][name] == matches[0]['version'], reason)
    redis = _exact(r['redis_restart'], ('outage_status', 'outage_seconds', 'recovery_seconds', 'recovery_attempts',
        'run_identity_changed', 'aof_enabled', 'appendfsync', 'original_replay_status', 'scope'))
    _require(_count(redis['outage_status']) == 503 and _count(redis['original_replay_status']) == 403
        and _number(redis['outage_seconds'], 3.5) < 3.5 and _number(redis['recovery_seconds'], 15) <= 15
        and 1 <= _count(redis['recovery_attempts'], 128) and redis['run_identity_changed'] is redis['aof_enabled'] is True
        and redis['appendfsync'] == 'always' and redis['scope'] == REDIS_RESTART_SCOPE, reason)
    baseline = _exact(r['backend_counters'], ('dispatch', 'auth', 'key', 'replay', 'resource'))
    for value in baseline.values(): _count(value)
    _require(baseline['dispatch'] == baseline['auth'] == baseline['key'] == baseline['replay']
             and 5 <= baseline['resource'] <= baseline['dispatch'], reason)
    op = _exact(r['operational'], ('schema', 'scope', 'requested_seconds', 'concurrency', 'phase', 'passed',
        'release_ready', 'checks', 'limitations', 'resources', 'soak', 'counters', 'backend_restart'))
    _require(type(op['schema']) is int and op['schema'] == 1 and op['scope'] == OP_SCOPE
        and op['phase'] == 'completed' and op['passed'] is True and op['release_ready'] is False
        and op['limitations'] == list(OP_LIMITATIONS), reason)
    _checks(op['checks'], OP_CHECKS)
    seconds, workers, elapsed, requests = _soak(op, baseline)
    _require(elapsed <= (updated - observed).total_seconds(), reason)
    samples = _resources(op['resources'], created, updated, now, seconds)
    backend = _exact(op['backend_restart'], ('recovered', 'recovery_seconds', 'original_replay_status',
        'redis_run_unchanged', 'counter_reset_expected', 'scope'))
    _require(backend['recovered'] is backend['redis_run_unchanged'] is backend['counter_reset_expected'] is True
        and _count(backend['original_replay_status']) == 403 and 0 < _number(backend['recovery_seconds'], 45) < 45
        and backend['scope'] == BACKEND_RESTART_SCOPE, reason)
    image_fields = ('schema', 'evidence_class', 'release_ready', 'automated_checks_passed', 'reason',
        'qualification_sha256', 'images', 'scanners', 'vulnerabilities', 'secrets', 'coverage_complete',
        'native_binary_coverage', 'complete_resolved_graph', 'coverage_passed', 'coverage_limitations')
    _require(type(image) is dict and type(image.get('schema')) is int and image['schema'] in (1, 2), 'image_status_unverified')
    detail = image['schema'] == 2
    image = _exact(image, image_fields + (('scanner', 'databases', 'finding_details_complete') if detail else ()), 'image_status_unverified')
    _require(image['evidence_class'] == 'owned_container_image_scan'
        and image['release_ready'] is image['coverage_complete'] is image['native_binary_coverage'] is image['complete_resolved_graph'] is False
        and image['coverage_passed'] is True and image['qualification_sha256'] == hashes['receipt.json']
        and image['scanners'] == ['vuln'] and image['secrets'] is None
        and image['coverage_limitations'] == ['redis_native_binary_unverified', 'native_runtimes_unverified', 'complete_dependency_closure_unverified'], 'image_status_unverified')
    _exact(image['images'], ROLES, 'image_status_unverified')
    total = 0
    for role, row in image['images'].items():
        _exact(row, ('image_id', 'report_sha256', 'vulnerabilities', 'coverage')
            + (('findings', 'finding_details_complete') if detail else ()), 'image_status_unverified')
        _require(row['image_id'] == c['image_ids'][role], 'image_status_unverified')
        _digest(row['report_sha256'], 'image_status_unverified')
        total += _count(row['vulnerabilities'], reason='image_status_unverified')
        coverage = _exact(row['coverage'], ('os_inventory', 'os_package_count', 'application_package_count',
            'application_inventory', 'native_binary_coverage', 'coverage_complete'), 'image_status_unverified')
        _require(coverage['os_inventory'] is True and _count(coverage['os_package_count']) > 0
            and coverage['native_binary_coverage'] is coverage['coverage_complete'] is False, 'image_status_unverified')
        app_count = _count(coverage['application_package_count'])
        _require((coverage['application_inventory'] is True and app_count > 0) if role != 'redis'
            else coverage['application_inventory'] is None and app_count == 0, 'image_status_unverified')
    _require(_count(image['vulnerabilities']) == total and image['automated_checks_passed'] is (total == 0)
        and image['reason'] == ('findings_present' if total else 'local_images_checked'), 'image_status_unverified')
    if detail: _image_details(image, run)
    return dict(requested_seconds=seconds, concurrency=workers, elapsed_seconds=elapsed,
                signed_requests=requests, resource_samples=samples, image_vulnerabilities=total,
                image_status_schema=image['schema'], image_finding_details_verified=detail)


def _run(document, commit, run_id, now, complete=True):
    reason = 'run_unverified'
    _require(type(document) is dict and type(document.get('id')) is int and document['id'] == run_id
        and hosted._positive(document.get('workflow_id')) and type(document.get('run_attempt')) is int
        and document['run_attempt'] == 1 and document.get('head_sha') == commit
        and document.get('event') in {'push', 'workflow_dispatch'} and document.get('head_branch') == 'main'
        and document.get('path') == WORKFLOW, reason)
    for name in ('repository', 'head_repository'):
        value = document.get(name)
        _require(type(value) is dict and value.get('full_name') == REPOSITORY and hosted._positive(value.get('id')), reason)
    _require(document['repository']['id'] == document['head_repository']['id'], reason)
    created = hosted._timestamp(document.get('created_at'), now, reason)
    updated = hosted._timestamp(document.get('updated_at'), now, reason)
    _require(created <= updated, reason)
    if complete:
        _require(document.get('status') == 'completed' and document.get('conclusion') in {'success', 'failure'}, reason)
    else:
        _require(document.get('status') in {'queued', 'in_progress', 'waiting', 'requested', 'pending', 'completed'}, reason)
    return tuple(document.get(key) for key in ('id', 'workflow_id', 'run_attempt', 'head_sha', 'event',
        'head_branch', 'path', 'status', 'conclusion', 'created_at', 'updated_at')) + (document['repository']['id'],)


def _run_identity(document):
    # _run has already validated both repository IDs and their equality.
    return hosted._run_identity(document) + (document['repository']['id'],)


def _workflow(document, expected):
    reason = 'workflow_unverified'
    _require(document.get('type') == 'file' and document.get('path') == WORKFLOW
        and document.get('encoding') == 'base64' and type(document.get('content')) is str
        and type(document.get('size')) is int and 0 < document['size'] <= hosted.MAX_WORKFLOW_BYTES, reason)
    data = base64.b64decode(document['content'].replace('\n', ''), validate=True)
    _require(len(data) == document['size'] and data == expected
        and document.get('sha') == hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(), reason)
    return hashlib.sha256(data).hexdigest()


def _artifact(document, run, pin, now):
    reason = 'artifact_metadata_unverified'
    name = 'owned-container-readiness-' + run['head_sha'] + '-' + str(run['id']) + '-1'
    _require(type(document) is dict and hosted._positive(document.get('id')) and document.get('name') == name
        and document.get('expired') is False and type(document.get('size_in_bytes')) is int
        and document['size_in_bytes'] == pin['size'] and document.get('digest') == 'sha256:' + pin['sha256'], reason)
    workflow = document.get('workflow_run')
    _require(type(workflow) is dict and type(workflow.get('id')) is int and workflow['id'] == run['id']
        and type(workflow.get('repository_id')) is int and workflow['repository_id'] == run['repository']['id']
        and type(workflow.get('head_repository_id')) is int and workflow['head_repository_id'] == run['head_repository']['id']
        and workflow.get('head_branch') == 'main' and workflow.get('head_sha') == run['head_sha'], reason)
    created = hosted._timestamp(document.get('created_at'), now, reason)
    updated = hosted._timestamp(document.get('updated_at'), now, reason)
    expiry = document.get('expires_at')
    _require(type(expiry) is str and hosted._UTC.fullmatch(expiry), reason)
    expiry = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
    _require(hosted._timestamp(run['created_at'], now, reason) <= created <= updated
        <= hosted._timestamp(run['updated_at'], now, reason) and now < expiry and updated < expiry, reason)
    return tuple(document[key] for key in ('id', 'name', 'size_in_bytes', 'digest', 'expired',
        'created_at', 'updated_at', 'expires_at')) + tuple(workflow[key] for key in (
            'id', 'repository_id', 'head_repository_id', 'head_branch', 'head_sha'))


def _artifact_list(request, run, pin, now):
    rows = hosted._pages(request, hosted.API_PREFIX + f'actions/runs/{run["id"]}/artifacts', 'artifacts', 'artifact_metadata_unverified')
    ids, matches = set(), []
    expected = 'owned-container-readiness-' + run['head_sha'] + '-' + str(run['id']) + '-1'
    for row in rows:
        _require(hosted._positive(row.get('id')) and row['id'] not in ids, 'artifact_metadata_unverified')
        ids.add(row['id'])
        if row.get('name') == expected: matches.append(row)
    _require(len(matches) == 1, 'artifact_metadata_unverified')
    return matches[0], _artifact(matches[0], run, pin, now)


def _latest(request, commit, selected, now):
    # No event/status/conclusion filter can hide a newer failed or pending run.
    rows = hosted._pages(request, hosted.API_PREFIX + 'actions/runs?head_sha=' + commit + '&branch=main',
                         'workflow_runs', 'latest_run_unverified')
    ids, applicable = set(), []
    for row in rows:
        identity = row.get('id')
        _require(hosted._positive(identity) and identity not in ids, 'latest_run_unverified')
        ids.add(identity)
        if row.get('path') == WORKFLOW and row.get('event') in {'push', 'workflow_dispatch'}:
            fingerprint = _run(row, commit, identity, now, complete=False)
            applicable.append((row['created_at'], identity, fingerprint))
    _require(applicable and max(applicable, key=lambda r: (
        datetime.fromisoformat(r[0].replace('Z', '+00:00')), r[1]))[2] == selected, 'latest_run_unverified')
    return len(applicable)


def _jobs(request, run, vulnerabilities, now):
    reason = 'jobs_unverified'
    rows = hosted._pages(request, hosted.API_PREFIX + f'actions/runs/{run["id"]}/attempts/1/jobs', 'jobs', reason)
    _require(len(rows) == 1, reason)
    row = rows[0]
    _require(hosted._positive(row.get('id')) and row.get('name') == JOB and row.get('status') == 'completed'
        and type(row.get('run_id')) is int and row['run_id'] == run['id'] and row.get('head_sha') == run['head_sha']
        and row.get('head_branch') == 'main' and row.get('conclusion') == run['conclusion'], reason)
    if 'run_attempt' in row: _require(type(row['run_attempt']) is int and row['run_attempt'] == 1, reason)
    _require(hosted._timestamp(run['created_at'], now, reason) <= hosted._timestamp(row.get('started_at'), now, reason)
        <= hosted._timestamp(row.get('completed_at'), now, reason) <= hosted._timestamp(run['updated_at'], now, reason), reason)
    steps = row.get('steps')
    _require(type(steps) is list and len(PRIMARY_STEPS) + 2 <= len(steps) <= len(PRIMARY_STEPS) + 6, reason)
    names, numbers = [], []
    for step in steps:
        _require(type(step) is dict and type(step.get('name')) is str and step.get('status') == 'completed'
            and hosted._positive(step.get('number')) and step['number'] <= 1000, reason)
        names.append(step['name']); numbers.append(step['number'])
    _require(len(set(names)) == len(names) and len(set(numbers)) == len(numbers) and numbers == sorted(numbers)
        and names[0] == 'Set up job' and names[-1] == 'Complete job'
        and names[1:len(PRIMARY_STEPS) + 1] == list(PRIMARY_STEPS), reason)
    post = names[len(PRIMARY_STEPS) + 1:-1]
    _require(post == [name for name in POST_STEPS if name in post], reason)
    expected_conclusion = 'failure' if vulnerabilities else 'success'
    _require(run['conclusion'] == row['conclusion'] == expected_conclusion, reason)
    for step in steps:
        allowed = {'success', 'skipped'} if step['name'] in POST_STEPS else {
            expected_conclusion if step['name'] == SCAN_STEP else 'success'}
        _require(step.get('conclusion') in allowed, reason)
    return 1


def _rename_exclusive(source_fd, source, destination_fd, destination):
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'linux':
        rename, flag = libc.renameat2, 1  # RENAME_NOREPLACE
    elif sys.platform == 'darwin':
        rename, flag = libc.renameatx_np, 4  # RENAME_EXCL
    else:
        raise ContainerError()
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    _require(rename(source_fd, os.fsencode(source), destination_fd, os.fsencode(destination), flag) == 0, 'output_unavailable')


def _output_directory(info, *, private=False):
    """Trust directory creation only beneath a current-user write boundary."""
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
        and not info.st_mode & 0o022
        and (not private or stat.S_IMODE(info.st_mode) == 0o700), 'output_unavailable')
    return _stamp(info)[:2]


def _publish(output, parent_fd, parent_identity, report, guard):
    """Preopen private staging; guard before an exclusive final directory rename.

    The held parent is current-user-owned and denies group/other writes; created
    staging directories must be current-user-owned with exact mode 0700. This
    boundary excludes same-user or host compromise. Only descriptor-owned files
    are rolled back on cooperative cancellation.
    SIGKILL/host failure can interrupt cleanup; abrupt cleanup is not guaranteed.
    """
    outer_fd, directory_fd, file_fd, outer_identity, identity = None, None, None, None, None
    name = '.container-result-' + secrets.token_hex(16)
    linked = False
    try:
        _path(output, new=True)
        _require(_output_directory(os.fstat(parent_fd)) == parent_identity
            and _stamp(output.parent.stat())[:2] == parent_identity, 'output_unavailable')
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        outer_identity = _output_directory(os.stat(name, dir_fd=parent_fd, follow_symlinks=False), private=True)
        outer_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        _require(_output_directory(os.fstat(outer_fd), private=True) == outer_identity, 'output_unavailable')
        os.mkdir('result', 0o700, dir_fd=outer_fd)
        initial = _output_directory(os.stat('result', dir_fd=outer_fd, follow_symlinks=False), private=True)
        directory_fd = os.open('result', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=outer_fd)
        identity = _output_directory(os.fstat(directory_fd), private=True)
        _require(initial == identity, 'output_unavailable')
        data = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
        _require(len(data) <= 16384, 'output_unavailable')
        file_fd = os.open('container.json', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        linked = True
        with os.fdopen(os.dup(file_fd), 'wb') as stream: stream.write(data)
        guard()
        _path(output, new=True)
        _path(output.parent / name, directory=True)
        _require(_output_directory(os.fstat(parent_fd)) == parent_identity
            and _stamp(output.parent.stat())[:2] == parent_identity
            and _output_directory(os.stat(name, dir_fd=parent_fd, follow_symlinks=False), private=True) == outer_identity
            and _output_directory(os.stat('result', dir_fd=outer_fd, follow_symlinks=False), private=True) == identity,
            'output_unavailable')
        _rename_exclusive(outer_fd, 'result', parent_fd, output.name)
        _path(output, directory=True)
        _require(_output_directory(os.fstat(parent_fd)) == parent_identity
            and _stamp(output.parent.stat())[:2] == parent_identity
            and _output_directory(output.lstat(), private=True) == identity
            and _stamp(os.stat('container.json', dir_fd=directory_fd, follow_symlinks=False))[:2] == _stamp(os.fstat(file_fd))[:2]
            and os.pread(file_fd, len(data) + 1, 0) == data, 'output_unavailable')
    except BaseException as error:
        if linked and directory_fd is not None and file_fd is not None:
            try:
                if _stamp(os.stat('container.json', dir_fd=directory_fd, follow_symlinks=False))[:2] == _stamp(os.fstat(file_fd))[:2]:
                    os.unlink('container.json', dir_fd=directory_fd)
            except OSError: pass
        if identity is not None:
            for descriptor, basename in ((outer_fd, 'result'), (parent_fd, output.name)):
                if descriptor is None: continue
                try:
                    if _stamp(os.stat(basename, dir_fd=descriptor, follow_symlinks=False))[:2] == identity:
                        os.rmdir(basename, dir_fd=descriptor)
                except OSError: pass
        if isinstance(error, (KeyboardInterrupt, SystemExit)): raise
        raise ContainerError() from None
    finally:
        if file_fd is not None: os.close(file_fd)
        if directory_fd is not None: os.close(directory_fd)
        if outer_identity is not None:
            try:
                if _stamp(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))[:2] == outer_identity:
                    os.rmdir(name, dir_fd=parent_fd)
            except OSError: pass
        if outer_fd is not None: os.close(outer_fd)


def verify_container(candidate, expected_commit, run_id, artifact_zip, output, *, fetch=None, now=None):
    """Write only container.json; false results never clear independent gates."""
    parent_fd = None
    try:
        candidate, artifact_zip, output = _path(candidate, directory=True), _path(artifact_zip), _path(output, new=True)
        _require(type(expected_commit) is str and hosted._SHA1.fullmatch(expected_commit) and hosted._positive(run_id)
            and not output.is_relative_to(candidate) and not artifact_zip.is_relative_to(candidate), 'invalid_arguments')
        now = datetime.now(timezone.utc) if now is None else now
        _require(type(now) is datetime and now.tzinfo is not None and now.utcoffset() == timedelta(0), 'invalid_arguments')
        parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_identity = _output_directory(os.fstat(parent_fd))
    except BaseException as error:
        if parent_fd is not None: os.close(parent_fd)
        if isinstance(error, (KeyboardInterrupt, SystemExit)): raise
        raise ContainerError() from None
    report = {'schema': 1, 'evidence_class': 'github_container_artifact_verification', 'technical_gate_verified': False,
        'sustained_operating_verified': False, 'artifact_verified': False, 'release_ready': False,
        'image_status_schema': None, 'image_finding_details_verified': False,
        'candidate_commit': expected_commit, 'run_id': run_id, 'run_attempt': None, 'repository': REPOSITORY,
        'workflow_path': WORKFLOW, 'observed_at': now.isoformat(timespec='seconds').replace('+00:00', 'Z'),
        'reason': 'candidate_unverified', 'api_response_count': 0, 'source_file_count': 0, 'applicable_run_count': 0,
        'external_approvals': 'not_verified', 'native_binary_coverage': False, 'coverage_complete': False, 'sha256': {},
        'limitations': ['Authenticated workflow observations rely on the reviewed workflow and GitHub runner.',
            'Sampled resources are not continuous peaks, leak, capacity or SLA proof.',
            'Output requires a current-user-owned parent without group/other writes; same-user or host compromise is excluded.',
            'SIGKILL or host failure can interrupt cleanup; abrupt-termination cleanup is not guaranteed.',
            'Image vulnerabilities, native closure, consumer graphs and external approvals remain separate gates.']}
    pins, zip_pin = None, None
    try:
        with tempfile.TemporaryDirectory(prefix='appguard-container-verifier-') as temp:
            private = Path(temp).resolve(); private.chmod(0o700)
            try:
                pins, documents = _snapshot(candidate, private / 'candidate', candidate=True)
                manifest = documents.get('manifest.json')
                _require(type(manifest) is dict and type(manifest.get('schema')) is int and manifest['schema'] == 1
                    and manifest.get('commit') == expected_commit and type(manifest.get('sha256')) is dict
                    and bool(manifest['sha256']) and all(type(name) is str and type(digest) is str
                        and SHA.fullmatch(digest) for name, digest in manifest['sha256'].items()), 'candidate_unverified')
                verify_candidate(private / 'candidate')
                zip_pin = _pin_zip(artifact_zip, private / 'artifact.zip')
                report['sha256'].update(candidate_manifest=pins['manifest.json']['sha256'],
                    source_archive=pins['source.tar.gz']['sha256'], artifact_zip=zip_pin['sha256'])
                expected_sources = _sources(private / 'candidate', pins)
                workflow_name = 'source/' + WORKFLOW
                _require(workflow_name in pins and pins[workflow_name]['size'] <= hosted.MAX_WORKFLOW_BYTES, 'candidate_unverified')
                response_hashes = hashlib.sha256()
                def original_inputs():
                    _require(_unchanged(candidate, pins), 'candidate_changed')
                    _require(_pin_zip(artifact_zip) == zip_pin, 'artifact_zip_changed')
                def request(path):
                    original_inputs()
                    _require(hosted._ENDPOINT.fullmatch(path) and report['api_response_count'] < MAX_API_REQUESTS, 'api_budget_exceeded')
                    try: raw = (fetch or hosted.fetch_github)(path)
                    except Exception: raise _Denied('api_unavailable') from None
                    finally: original_inputs()
                    _require(type(raw) is bytes and len(raw) <= hosted.MAX_RESPONSE_BYTES, 'api_invalid')
                    try: value = _json(raw)
                    except Exception: raise _Denied('api_invalid') from None
                    for part in (path.encode(), raw):
                        response_hashes.update(len(part).to_bytes(8, 'big')); response_hashes.update(part)
                    report['api_response_count'] += 1
                    report['sha256']['api_responses'] = response_hashes.hexdigest()
                    return value
                run_path = hosted.API_PREFIX + f'actions/runs/{run_id}'
                report['reason'] = 'run_unverified'
                run = request(run_path); selected = _run(run, expected_commit, run_id, now)
                report['run_attempt'] = 1
                attempt_document = request(run_path + '/attempts/1')
                selected_attempt = _run(attempt_document, expected_commit, run_id, now)
                _require(_run_identity(attempt_document) == _run_identity(run), 'run_unverified')
                report['reason'] = 'source_git_provenance'
                report['source_file_count'] = hosted._source_provenance(request, expected_commit, candidate,
                    private / 'candidate', manifest, pins, private)
                report['reason'] = 'workflow_unverified'
                report['sha256']['workflow'] = _workflow(request(hosted.API_PREFIX + 'contents/' + WORKFLOW + '?ref=' + expected_commit),
                    (private / 'candidate' / workflow_name).read_bytes())
                report['reason'] = 'artifact_metadata_unverified'
                artifact, fingerprint = _artifact_list(request, run, zip_pin, now)
                artifact_path = hosted.API_PREFIX + 'actions/artifacts/' + str(artifact['id'])
                _require(_artifact(request(artifact_path), run, zip_pin, now) == fingerprint, 'artifact_metadata_unverified')
                report['reason'] = 'artifact_zip_unverified'
                payload, hashes = _archive((private / 'artifact.zip').read_bytes())
                report['reason'] = 'binding_unverified'
                binding = _exact(payload['binding.json'], ('schema', 'evidence_class', 'repository', 'candidate_commit',
                    'run_id', 'run_attempt', 'event', 'head_branch', 'workflow_path', 'receipt_sha256', 'image_status_sha256'), 'binding_unverified')
                _require(type(binding['schema']) is int and binding['schema'] == 1
                    and binding['evidence_class'] == 'owned_container_ci_binding' and binding['repository'] == REPOSITORY
                    and binding['candidate_commit'] == expected_commit and type(binding['run_id']) is int and binding['run_id'] == run_id
                    and type(binding['run_attempt']) is int and binding['run_attempt'] == 1 and binding['event'] == run['event']
                    and binding['head_branch'] == 'main' and binding['workflow_path'] == WORKFLOW
                    and binding['receipt_sha256'] == hashes['receipt.json']
                    and binding['image_status_sha256'] == hashes['image-status.json'], 'binding_unverified')
                report['reason'] = 'operating_unverified'
                operating = _receipt(payload['receipt.json'], payload['image-status.json'], hashes, expected_commit,
                    expected_sources, private / 'candidate', run, now)
                report['reason'] = 'jobs_unverified'
                _jobs(request, run, operating['image_vulnerabilities'], now)
                report['reason'] = 'artifact_metadata_unverified'
                _, final_fingerprint = _artifact_list(request, run, zip_pin, now)
                _require(final_fingerprint == fingerprint and _artifact(request(artifact_path), run, zip_pin, now) == fingerprint,
                         'artifact_metadata_unverified')
                # Artifact endpoints have no attempt field. Re-read the selected
                # run/attempt after them, then observe the complete latest union.
                report['reason'] = 'run_unverified'
                _require(_run(request(run_path), expected_commit, run_id, now) == selected
                    and _run(request(run_path + '/attempts/1'), expected_commit, run_id, now) == selected_attempt, 'run_unverified')
                report['reason'] = 'latest_run_unverified'
                report['applicable_run_count'] = _latest(request, expected_commit, selected, now)
                original_inputs()
                report['sha256'].update(receipt=hashes['receipt.json'], image_status=hashes['image-status.json'], binding=hashes['binding.json'])
                report.update(operating, artifact_verified=True)
                if operating['requested_seconds'] < 1800 or operating['elapsed_seconds'] < 1800:
                    report['reason'] = 'sustained_duration_below_minimum'
                elif operating['concurrency'] != 8: report['reason'] = 'sustained_concurrency_not_supported'
                else: report.update(technical_gate_verified=True, sustained_operating_verified=True, reason='verified')
            except _Denied as denied: report['reason'] = denied.reason
            except Exception: pass
            def final_guard():
                if report['artifact_verified']:
                    _require(_unchanged(candidate, pins) and _pin_zip(artifact_zip) == zip_pin, 'inputs_changed')
            _publish(output, parent_fd, parent_identity, report, final_guard)
    finally:
        os.close(parent_fd)
    return report


class _Parser(argparse.ArgumentParser):
    def error(self, message): self.exit(2, 'container_verification_unavailable\n')


def main():
    parser = _Parser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--artifact', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try: report = verify_container(args.candidate, args.expected_commit, args.run_id, args.artifact, args.output)
    except Exception: parser.exit(2, 'container_verification_unavailable\n')
    print(json.dumps({key: report[key] for key in ('technical_gate_verified', 'artifact_verified', 'release_ready', 'reason')}, sort_keys=True))
    if not report['technical_gate_verified']: parser.exit(1)


if __name__ == '__main__': main()
