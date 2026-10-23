#!/usr/bin/env python3
"""Produce a privacy-bounded release evidence ledger, without release approval.

Validated source/exported-runtime scans may satisfy one technical gate. Local
qualification receipts are unverified references. Live GitHub verifiers can pass
only their technical CI/owned-container gates. Deployed, independent security,
license and publication approval gates cannot be passed by this reader,
including when an input document claims ``approved: true``. This command
never publishes a package, contacts providers or changes an installed project.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile

from publication_gate import stage_publication

MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILES = 50000
MAX_JSON_NODES = 2000000
MAX_JSON_DEPTH = 64
_COMMIT = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_UTC = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z')
_PROFILES = ('server-signature', 'mobile-attested')
QUALIFICATION_CHECKS = frozenset((
    'signed_fidelity', 'replay_rejected', 'backend_bypass_rejected',
    'absolute_upload_deadline', 'malformed_framing_rejected',
    'backend_failure_bounded', 'healthy_recovery', 'owned_process_cleanup',
))
QUALIFICATION_ARTIFACTS = frozenset(('sdk_jar', 'example_pom', 'ingress_source'))
# Bounded opaque extensions from the local runner are never approval evidence.
QUALIFICATION_EXTENSIONS = frozenset((
    'metrics', 'sources', 'release_ready', 'limitations', 'owned_process_cleanup',
    'exampleclasses_sha256', 'provenance_unchanged', 'source_matches_commit', 'source_sha256', 'operational',
    'core_diagnostics',
))
_SCAN_REASONS = frozenset((
    'candidate_unverified', 'scan_evidence_unverified', 'source_coverage_unverified',
    'runtime_coverage_unverified', 'secret_findings', 'vulnerability_findings',
    'scan_checks_failed', 'publication_copy_failed',
))
_JSON_SOURCE_NAMES = frozenset(('package-lock.json', 'packages.lock.json', 'composer.lock'))
_VERIFIER_FILES = {'hosted_verification': 'hosted.json', 'container_verification': 'container.json'}
_ERROR = 'Unable to create privacy-bounded readiness assessment\n'


class AssessmentError(ValueError):
    """Invalid arguments or unsafe filesystem inputs; never expose raw details."""

    def __init__(self):
        super().__init__('assessment_unavailable')


class _InvalidEvidence(ValueError):
    pass


def _path(value, *, directory=False, new=False):
    path = Path(value).absolute()
    if path != path.resolve(strict=not new):
        raise AssessmentError()
    for parent in (path.parent if new else path, *(path.parent.parents if new else path.parents)):
        if stat.S_ISLNK(parent.lstat().st_mode):
            raise AssessmentError()
    if new:
        if path.exists() or path.is_symlink() or not path.parent.is_dir():
            raise AssessmentError()
    elif directory and not path.is_dir():
        raise AssessmentError()
    return path


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _files(root):
    """Inspect every entry, including ignored logs, without following symlinks."""
    result, count = [], 0
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in (*directories, *files):
            path = _path(Path(directory) / name)
            mode = path.lstat().st_mode
            count += 1
            if count > MAX_FILES or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise _InvalidEvidence()
            if stat.S_ISREG(mode):
                result.append(path)
    return sorted(result)


def _json(raw):
    if len(raw) > MAX_JSON_BYTES:
        raise _InvalidEvidence()
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise _InvalidEvidence()
            result[key] = value
        return result
    def constant(_):
        raise _InvalidEvidence()
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise _InvalidEvidence() from None
    queue, count = [(value, 0)], 0
    while queue:
        item, depth = queue.pop()
        count += 1
        if depth > MAX_JSON_DEPTH or count > MAX_JSON_NODES:
            raise _InvalidEvidence()
        if isinstance(item, float) and not math.isfinite(item):
            raise _InvalidEvidence()
        if isinstance(item, dict):
            queue.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            queue.extend((child, depth + 1) for child in item)
    if not isinstance(value, dict):
        raise _InvalidEvidence()
    return value


def _read(path, *, copy_to=None, keep=False):
    """Pin identity and bytes before and after an O_NOFOLLOW read."""
    path = _path(path)
    initial = path.lstat()
    if not stat.S_ISREG(initial.st_mode) or initial.st_size > (MAX_JSON_BYTES if keep else MAX_FILE_BYTES):
        raise _InvalidEvidence()
    digest, chunks, size = hashlib.sha256(), [], 0
    target = None
    try:
        if copy_to is not None:
            copy_to.parent.mkdir(parents=True, exist_ok=True)
            target = copy_to.open('xb')
            copy_to.chmod(0o600)
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or _stamp(initial) != _stamp(opened):
                raise _InvalidEvidence()
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                size += len(chunk)
                if size > (MAX_JSON_BYTES if keep else MAX_FILE_BYTES):
                    raise _InvalidEvidence()
                digest.update(chunk)
                if keep:
                    chunks.append(chunk)
                if target is not None:
                    target.write(chunk)
            if _stamp(initial) != _stamp(os.fstat(stream.fileno())):
                raise _InvalidEvidence()
        if _stamp(initial) != _stamp(path.lstat()):
            raise _InvalidEvidence()
    finally:
        if target is not None:
            target.close()
    return {'stamp': _stamp(initial), 'sha256': digest.hexdigest(), 'size': size,
            'json': _json(b''.join(chunks)) if keep else None}


def _snapshot(root, destination, *, candidate=False):
    """Validation consumes private snapshots, never mutable original reports."""
    destination.mkdir()
    pins, documents, total = {}, {}, 0
    for path in _files(root):
        name = str(path.relative_to(root))
        is_json = (path.suffix == '.json' if not candidate else
                   path.parent == root and path.suffix == '.json' or path.name in _JSON_SOURCE_NAMES)
        pin = _read(path, copy_to=destination / name, keep=is_json)
        total += pin['size']
        if total > MAX_TOTAL_BYTES:
            raise _InvalidEvidence()
        if is_json:
            documents[name] = pin.pop('json')
        else:
            pin.pop('json')
        pins[name] = pin
    return pins, documents


def _unchanged(root, pins):
    paths = _files(root)
    if {str(p.relative_to(root)) for p in paths} != set(pins):
        return False
    for path in paths:
        pin = _read(path)
        pin.pop('json')
        if pin != pins[str(path.relative_to(root))]:
            return False
    return True


def _preflight(candidate, scans, expected_commit):
    manifest = candidate.get('manifest.json')
    if (not isinstance(manifest, dict) or type(manifest.get('schema')) is not int or manifest['schema'] != 1
            or manifest.get('commit') != expected_commit or not isinstance(manifest.get('sha256'), dict)
            or not manifest['sha256'] or len(manifest['sha256']) > MAX_FILES
            or any(not isinstance(name, str) or not isinstance(value, str) or not _DIGEST.fullmatch(value)
                   for name, value in manifest['sha256'].items())):
        raise _InvalidEvidence()
    for name, document in scans.items():
        if 'schema' in document and (type(document['schema']) is not int or document['schema'] != 1):
            raise _InvalidEvidence()
        if name.startswith('trivy-') and name.endswith('.json'):
            if type(document.get('SchemaVersion')) is not int or document['SchemaVersion'] != 2:
                raise _InvalidEvidence()
        if name.startswith('sbom') and name.endswith('.json'):
            if document.get('bomFormat') != 'CycloneDX' or not isinstance(document.get('components'), list):
                raise _InvalidEvidence()
    for name in ('source-lock-coverage.json', 'runtime-lock-coverage.json', 'runtime-catalog-overlay.json', 'license-review.json'):
        document = scans.get(name)
        if not isinstance(document, dict) or type(document.get('schema')) is not int or document['schema'] != 1:
            raise _InvalidEvidence()


def _qualification(document, expected_commit):
    required = {'schema', 'candidate_commit', 'evidence_class', 'profile', 'observed_at',
                'checks', 'artifact_sha256', 'limits', 'cleanup'}
    if (not required <= set(document) or set(document) - required - QUALIFICATION_EXTENSIONS
            or type(document['schema']) is not int or document['schema'] != 1
            or document['candidate_commit'] != expected_commit
            or document['evidence_class'] != 'local_deployment'
            or document['profile'] != 'spring-mtls-store-forward-v1'
            or type(document['cleanup']) is not bool):
        raise _InvalidEvidence()
    observed = document['observed_at']
    if not isinstance(observed, str) or not _UTC.fullmatch(observed):
        raise _InvalidEvidence()
    try:
        datetime.fromisoformat(observed.replace('Z', '+00:00'))
    except ValueError:
        raise _InvalidEvidence() from None
    checks, artifacts, limits = document['checks'], document['artifact_sha256'], document['limits']
    if (not isinstance(checks, dict) or set(checks) != QUALIFICATION_CHECKS
            or any(type(value) is not bool for value in checks.values())
            or not isinstance(artifacts, dict) or set(artifacts) != QUALIFICATION_ARTIFACTS
            or any(not isinstance(value, str) or not _DIGEST.fullmatch(value) for value in artifacts.values())
            or not isinstance(limits, dict) or set(limits) != {'body_bytes', 'upload_seconds', 'backend_seconds'}
            or type(limits['body_bytes']) is not int or not 1 <= limits['body_bytes'] <= 1048576):
        raise _InvalidEvidence()
    for name in ('upload_seconds', 'backend_seconds'):
        value = limits[name]
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 300:
            raise _InvalidEvidence()


def _gate(name, state, evidence_class, reason, requirements):
    return {'id': name, 'state': state, 'evidence_class': evidence_class,
            'reason': reason, 'requirements': list(requirements)}


def _ledger(expected_commit, profile, passed, reason, qualification_state, qualification_reason, hashes, count,
            hosted_state='pending_external', hosted_reason='hosted_result_not_verified',
            container_state='pending_external', container_reason='container_result_not_verified'):
    gates = [
        _gate('source_and_runtime_scans', 'pass' if passed else 'blocked', 'local_scan', reason,
              ('exact_candidate_hashes', 'complete_raw_reports', 'zero_security_findings', 'recorded_lock_and_runtime_coverage')),
        _gate('hosted_ci', hosted_state, 'hosted_ci', hosted_reason,
              ('exact_candidate_commit', 'trusted_workflow_identity', 'all_required_jobs_completed_successfully')),
        _gate('owned_container_ci', container_state, 'owned_container_operating', container_reason,
              ('live_run_and_artifact_identity', 'exact_candidate_source_hashes',
               'at_least_1800_seconds_and_eight_workers', 'resource_recovery_and_cleanup_checks')),
        _gate('consumer_container_graph', 'pending_external', 'consumer_runtime', 'consumer_graph_not_verified',
              ('exact_deployed_artifact_hashes', 'provided_and_container_dependencies', 'complete_runtime_scan')),
        _gate('local_spring_ingress', qualification_state, 'local_deployment', qualification_reason,
              ('exact_packaged_sdk_and_configuration', 'real_tls_mtls_and_adversarial_probes', 'owned_process_cleanup')),
        _gate('deployment_ingress', 'pending_external', 'deployed_ingress', 'deployed_environment_not_verified',
              ('actual_environment_identity', 'backend_bypass_prevention', 'absolute_upload_and_admission_limits', 'operational_observation')),
        _gate('external_security_audit', 'pending_external', 'external_audit', 'independent_audit_not_verified',
              ('candidate_and_deployment_bound_scope', 'independent_auditor_identity', 'findings_and_remediation', 'review_approval')),
        _gate('license_notice_approval', 'pending_external', 'license_approval', 'license_approval_not_verified',
              ('exact_distribution_contents', 'dependency_license_and_notice_obligations', 'maintainer_review_approval')),
        _gate('release_publication_approval', 'pending_external', 'maintainer_approval', 'publication_approval_not_verified',
              ('version_and_registry_ownership', 'signing_and_provenance', 'maintainer_release_approval')),
    ]
    if profile == 'mobile-attested':
        gates.append(_gate('provider_account_validation', 'pending_external', 'provider_account', 'provider_configuration_not_verified',
                           ('actual_app_and_account_identity', 'trusted_provider_live_verification', 'failure_and_replay_cases')))
    return {'schema': 1, 'profile': profile, 'candidate_commit': expected_commit,
            'generated_at': datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
            'release_ready': all(gate['state'] == 'pass' for gate in gates), 'automated_scan_checks_passed': passed,
            'assessment_policy': 'unverified_references_cannot_approve_release_v1',
            'scope': ['server_signature_verification', 'source_and_exported_maven_runtime_only',
                      'owned_container_operating_requires_live_artifact_verification',
                      'physical_devices_excluded', 'external_approval_validators_not_implemented'],
            'sha256': hashes, 'pinned_input_file_count': count,
            'unresolved_gate_count': sum(gate['state'] != 'pass' for gate in gates), 'gates': gates}


def _document_pin(path, *, generated=False):
    # A generated ledger is not input JSON: a lowered input parser bound must
    # still permit the original blocked-assessment result to be published.
    pin = _read(path, keep=not generated)
    pin.pop('json')
    return pin


def _private_document_pin(path, *, generated=False):
    pin = _document_pin(path, generated=generated)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or _stamp(info) != pin['stamp']):
        raise _InvalidEvidence()
    return pin


def _publish(output, report, workspace, decisions=None):
    """Link complete, pinned decisions first and the assessment commit marker last.

    Only fixed redacted decision files are retained. Cooperative failure removes
    recorded owned links; replacement objects are preserved. Cancellation before
    the new directory's identity is recorded may leave an empty reservation.
    SIGKILL/host failure cannot guarantee cleanup. Current-user processes and the
    operating system are trusted.
    """
    decisions = decisions or {}
    directory = parent = identity = None
    linked, records = {}, {}
    try:
        output = _path(output, new=True)
        ancestors = {path: _stamp(path.lstat())[:2] for path in (output.parent, *output.parent.parents)}
        parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        required = {key for key in _VERIFIER_FILES if key in report['sha256']}
        if set(decisions) != required:
            raise _InvalidEvidence()
        for key, decision in decisions.items():
            if decision['pin']['sha256'] != report['sha256'][key]:
                raise _InvalidEvidence()
            records[_VERIFIER_FILES[key]] = decision
        staged = workspace / 'assessment.json'
        raw = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
        with os.fdopen(os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
            created = _stamp(os.fstat(stream.fileno()))[:2]
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        pin = _private_document_pin(staged, generated=True)
        if pin['stamp'][:2] != created or pin['sha256'] != hashlib.sha256(raw).hexdigest():
            raise _InvalidEvidence()
        records['assessment.json'] = {'path': staged, 'pin': pin, 'generated': True}

        def guard():
            for path, expected in ancestors.items():
                info = path.lstat()
                if not stat.S_ISDIR(info.st_mode) or _stamp(info)[:2] != expected:
                    raise _InvalidEvidence()
            if _stamp(os.fstat(parent))[:2] != ancestors[output.parent]:
                raise _InvalidEvidence()
            if directory is not None:
                info = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
                held = os.fstat(directory)
                if (not stat.S_ISDIR(info.st_mode) or _stamp(info)[:2] != identity
                        or _stamp(held)[:2] != identity or held.st_uid != os.getuid()
                        or stat.S_IMODE(held.st_mode) != 0o700):
                    raise _InvalidEvidence()
            for name, record in records.items():
                if 'source' in record and _document_pin(record['source']) != record['source_pin']:
                    raise _InvalidEvidence()
                if _private_document_pin(record['path'], generated=record.get('generated', False)) != record['pin']:
                    raise _InvalidEvidence()
                if name in linked:
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                            or stat.S_IMODE(info.st_mode) != 0o600 or _stamp(info) != record['pin']['stamp']):
                        raise _InvalidEvidence()

        guard()
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        info = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise _InvalidEvidence()
        identity = _stamp(info)[:2]
        directory = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        for name, record in records.items():
            guard()
            previous = record['pin']
            # Record the expected inode before the syscall so cancellation after
            # a successful link can still remove only that owned entry.
            linked[name] = previous['stamp'][:2]
            os.link(record['path'], name, dst_dir_fd=directory, follow_symlinks=False)
            current = _private_document_pin(record['path'], generated=record.get('generated', False))
            # A hard link changes ctime; every other identity/content pin remains.
            if (current['stamp'][:4] != previous['stamp'][:4]
                    or current['sha256'] != previous['sha256'] or current['size'] != previous['size']):
                raise _InvalidEvidence()
            record['pin'] = current
            guard()
    except BaseException as error:
        if directory is not None:
            def owned(name):
                try:
                    return _stamp(os.stat(name, dir_fd=directory, follow_symlinks=False))[:2] == linked.get(name)
                except FileNotFoundError:
                    return False
            # Never remove a companion while our final marker could remain.
            try:
                if owned('assessment.json'):
                    os.unlink('assessment.json', dir_fd=directory)
                if not owned('assessment.json'):
                    for name in linked:
                        if name != 'assessment.json' and owned(name):
                            os.unlink(name, dir_fd=directory)
            except OSError:
                pass
        if parent is not None and identity is not None:
            try:
                info = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode) and _stamp(info)[:2] == identity:
                    os.rmdir(output.name, dir_fd=parent)
            except OSError:
                pass
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise AssessmentError() from None
    finally:
        if directory is not None:
            os.close(directory)
        if parent is not None:
            os.close(parent)


def _verifier_report(path, returned, destination):
    """Pin a matching live decision and preserve its exact bounded bytes."""
    if type(returned) is not dict:
        raise _InvalidEvidence()
    pin = _read(path, keep=True)
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
    if canonical(pin['json']) != canonical(returned):
        raise _InvalidEvidence()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or _stamp(info) != pin['stamp']:
            raise _InvalidEvidence()
        raw = stream.read(MAX_JSON_BYTES + 1)
        if (len(raw) != pin['size'] or hashlib.sha256(raw).hexdigest() != pin['sha256']
                or _stamp(os.fstat(stream.fileno())) != pin['stamp']):
            raise _InvalidEvidence()
    if _stamp(path.lstat()) != pin['stamp']:
        raise _InvalidEvidence()
    destination.parent.mkdir(mode=0o700, exist_ok=True)
    with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        created = _stamp(os.fstat(stream.fileno()))[:2]
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    copied = _private_document_pin(destination)
    if copied['stamp'][:2] != created or copied['sha256'] != pin['sha256'] or copied['size'] != pin['size']:
        raise _InvalidEvidence()
    pin.pop('json')
    return {'source': path, 'source_pin': pin, 'path': destination, 'pin': copied}


def _assess(candidate, scans, output, expected_commit, *, qualification=None, profile='server-signature',
            hosted_run_id=None, container_run_id=None, container_artifact=None):
    """Create a redacted assessment. Even a perfect local scan cannot approve release.

    Input trees must be stable, private local evidence directories. Original
    identity/hash pins are rechecked after validators consume owned snapshots.
    This detects changed evidence; it does not authenticate scanners, establish
    hosted workflow trust or defend against a compromised account/operating system.
    """
    if (not isinstance(expected_commit, str) or not _COMMIT.fullmatch(expected_commit) or profile not in _PROFILES
            or (hosted_run_id is not None and (type(hosted_run_id) is not int or not 0 < hosted_run_id < 2**63))
            or (container_run_id is None) != (container_artifact is None)
            or (container_run_id is not None and (type(container_run_id) is not int or not 0 < container_run_id < 2**63))):
        raise AssessmentError()
    try:
        candidate, scans = _path(candidate, directory=True), _path(scans, directory=True)
        output = _path(output, new=True)
        if candidate == scans or candidate in scans.parents or scans in candidate.parents:
            raise AssessmentError()
        if any(output == root or root in output.parents for root in (candidate, scans)):
            raise AssessmentError()
        qualification = _path(qualification) if qualification is not None else None
        container_artifact = _path(container_artifact) if container_artifact is not None else None
        # Validate all path entries before copying, including symlinked logs.
        _files(candidate)
        _files(scans)
    except (OSError, ValueError, TypeError):
        raise AssessmentError() from None
    passed, reason, hashes, count = False, 'scan_evidence_unverified', {}, 0
    qual_state, qual_reason = 'pending_external', 'local_qualification_not_provided'
    hosted_state, hosted_reason = 'pending_external', 'hosted_result_not_verified'
    container_state, container_reason = 'pending_external', 'container_result_not_verified'
    with tempfile.TemporaryDirectory(prefix='.assessment-', dir=output.parent) as temporary:
        workspace = Path(temporary)
        decisions = {}
        candidate_pins, scan_pins, qual_pin, container_pin = {}, {}, None, None
        try:
            candidate_pins, candidate_docs = _snapshot(candidate, workspace / 'candidate', candidate=True)
            scan_pins, scan_docs = _snapshot(scans, workspace / 'scans')
            count = len(candidate_pins) + len(scan_pins)
            if container_artifact is not None:
                container_state, container_reason = 'blocked', 'container_result_unverified'
                container_pin = _read(container_artifact)
                hashes['container_artifact'] = container_pin['sha256']
                count += 1
            for label, pins, name in (('candidate_manifest', candidate_pins, 'manifest.json'),
                                     ('source_archive', candidate_pins, 'source.tar.gz'),
                                     ('scanner_status', scan_pins, 'status.json')):
                if name in pins:
                    hashes[label] = pins[name]['sha256']
            _preflight(candidate_docs, scan_docs, expected_commit)
            if qualification is not None:
                qual_state, qual_reason = 'blocked', 'qualification_unverified'
                try:
                    qual_pin = _read(qualification, keep=True)
                    hashes['qualification_report'] = qual_pin['sha256']
                    _qualification(qual_pin.pop('json'), expected_commit)
                    qual_state, qual_reason = 'referenced_unverified', 'local_qualification_reference_unverified'
                except (OSError, ValueError, TypeError, KeyError, OverflowError):
                    pass
            result = stage_publication(workspace / 'candidate', workspace / 'scans', workspace / 'staging', expected_commit)
            passed = (result.get('source_publication_allowed') is True
                      and result.get('automated_checks_passed') is True
                      and result.get('reason') == 'verified_checks_passed')
            reason = 'verified_checks_passed' if passed else result.get('reason')
            if reason not in _SCAN_REASONS | {'verified_checks_passed'}:
                reason = 'scan_evidence_unverified'
            if hosted_run_id is not None:
                hosted_state, hosted_reason = 'blocked', 'hosted_result_unverified'
                try:
                    # Runtime import avoids a cycle: the verifier reuses the
                    # bounded filesystem helpers defined in this module.
                    from verify_hosted import verify_hosted
                    # It snapshots/pins the original itself, including Git file
                    # modes. Our privacy snapshot intentionally chmods to0600.
                    hosted = verify_hosted(candidate, expected_commit,
                                           'bonjin-app/appguard', hosted_run_id, workspace / 'hosted')
                    decision = _verifier_report(workspace / 'hosted/hosted.json', hosted, workspace / 'decisions/hosted.json')
                    if (hosted.get('technical_gate_verified') is True
                            and hosted.get('candidate_commit') == expected_commit
                            and hosted.get('sha256', {}).get('candidate_manifest') == hashes.get('candidate_manifest')
                            and hosted.get('sha256', {}).get('source_archive') == hashes.get('source_archive')):
                        hosted_state, hosted_reason = 'pass', 'hosted_result_verified'
                    decisions['hosted_verification'] = decision
                    hashes['hosted_verification'] = decision['pin']['sha256']
                except Exception:
                    hosted_state, hosted_reason = 'blocked', 'hosted_result_unverified'
            if container_run_id is not None:
                try:
                    from verify_container import verify_container
                    container = verify_container(candidate, expected_commit, container_run_id,
                                                 container_artifact, workspace / 'container')
                    decision = _verifier_report(workspace / 'container/container.json', container, workspace / 'decisions/container.json')
                    if (container.get('technical_gate_verified') is True
                            and container.get('artifact_verified') is True
                            and container.get('candidate_commit') == expected_commit
                            and type(container.get('run_id')) is int and container['run_id'] == container_run_id
                            and container.get('sha256', {}).get('candidate_manifest') == hashes.get('candidate_manifest')
                            and container.get('sha256', {}).get('source_archive') == hashes.get('source_archive')
                            and container.get('sha256', {}).get('artifact_zip') == container_pin['sha256']):
                        container_state, container_reason = 'pass', 'container_result_verified'
                    decisions['container_verification'] = decision
                    hashes['container_verification'] = decision['pin']['sha256']
                except Exception:
                    container_state, container_reason = 'blocked', 'container_result_unverified'
            unchanged = _unchanged(candidate, candidate_pins) and _unchanged(scans, scan_pins)
            if qual_pin is not None:
                latest = _read(qualification)
                latest.pop('json')
                unchanged = unchanged and latest == qual_pin
            if container_pin is not None:
                unchanged = unchanged and _read(container_artifact) == container_pin
            if not unchanged:
                passed, reason = False, 'inputs_changed'
                if qualification is not None:
                    qual_state, qual_reason = 'blocked', 'qualification_unverified'
                if hosted_run_id is not None:
                    hosted_state, hosted_reason = 'blocked', 'hosted_result_unverified'
                if container_run_id is not None:
                    container_state, container_reason = 'blocked', 'container_result_unverified'
        except (OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError):
            passed = False
            reason = 'scan_evidence_unverified'
            if qualification is not None and qual_state != 'referenced_unverified':
                qual_state, qual_reason = 'blocked', 'qualification_unverified'
            if hosted_run_id is not None:
                hosted_state, hosted_reason = 'blocked', 'hosted_result_unverified'
            if container_run_id is not None:
                container_state, container_reason = 'blocked', 'container_result_unverified'
        report = _ledger(expected_commit, profile, passed, reason, qual_state, qual_reason, hashes, count,
                         hosted_state, hosted_reason, container_state, container_reason)
        _publish(output, report, workspace, decisions)
    return report


def assess(candidate, scans, output, expected_commit, *, qualification=None, profile='server-signature',
           hosted_run_id=None, container_run_id=None, container_artifact=None):
    """Write one fixed-schema assessment; filesystem/input failures stay redacted."""
    try:
        return _assess(candidate, scans, output, expected_commit, qualification=qualification, profile=profile,
                       hosted_run_id=hosted_run_id, container_run_id=container_run_id, container_artifact=container_artifact)
    except (OSError, ValueError, TypeError):
        raise AssessmentError() from None


class _Parser(argparse.ArgumentParser):
    def error(self, _):
        self.exit(1, _ERROR)


def main(argv=None):
    parser = _Parser(description=__doc__)
    for name in ('candidate', 'scans', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--qualification', type=Path)
    parser.add_argument('--hosted-run-id', type=int, help='Verify this exact main push run from the fixed GitHub HTTPS API')
    parser.add_argument('--container-run-id', type=int, help='Verify exact-main owned sustained container evidence; requires --container-artifact')
    parser.add_argument('--container-artifact', type=Path, help='Untrusted local artifact ZIP, authenticated against live public GitHub metadata')
    parser.add_argument('--profile', choices=_PROFILES, default='server-signature')
    parser.add_argument('--check', action='store_true', help='Exit 2 unless all required gates pass; v1 always retains external gates')
    args = parser.parse_args(argv)
    try:
        report = assess(args.candidate, args.scans, args.output, args.expected_commit,
                        qualification=args.qualification, profile=args.profile, hosted_run_id=args.hosted_run_id,
                        container_run_id=args.container_run_id, container_artifact=args.container_artifact)
    except (OSError, ValueError, TypeError):
        parser.exit(1, _ERROR)
    if args.check and not report['release_ready']:
        parser.exit(2)


if __name__ == '__main__':
    main()
