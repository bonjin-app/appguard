#!/usr/bin/env python3
"""Produce a privacy-bounded release evidence ledger, without release approval.

Validated source/exported-runtime scans may satisfy one technical gate. Local
qualification receipts are unverified references. Hosted, deployed, independent
security, license and publication approval gates cannot be passed by this v1
reader, including when an input document claims ``approved: true``. This command
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
    'exampleclasses_sha256', 'provenance_unchanged', 'source_matches_commit', 'source_sha256',
))
_SCAN_REASONS = frozenset((
    'candidate_unverified', 'scan_evidence_unverified', 'source_coverage_unverified',
    'runtime_coverage_unverified', 'secret_findings', 'vulnerability_findings',
    'scan_checks_failed', 'publication_copy_failed',
))
_JSON_SOURCE_NAMES = frozenset(('package-lock.json', 'packages.lock.json', 'composer.lock'))
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


def _ledger(expected_commit, profile, passed, reason, qualification_state, qualification_reason, hashes, count):
    gates = [
        _gate('source_and_runtime_scans', 'pass' if passed else 'blocked', 'local_scan', reason,
              ('exact_candidate_hashes', 'complete_raw_reports', 'zero_security_findings', 'recorded_lock_and_runtime_coverage')),
        _gate('hosted_ci', 'pending_external', 'hosted_ci', 'hosted_result_not_verified',
              ('exact_candidate_commit', 'trusted_workflow_identity', 'all_required_jobs_completed_successfully')),
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
            'release_ready': False, 'automated_scan_checks_passed': passed,
            'assessment_policy': 'unverified_references_cannot_approve_release_v1',
            'scope': ['server_signature_verification', 'source_and_exported_maven_runtime_only',
                      'physical_devices_excluded', 'external_approval_validators_not_implemented'],
            'sha256': hashes, 'pinned_input_file_count': count,
            'unresolved_gate_count': sum(gate['state'] != 'pass' for gate in gates), 'gates': gates}


def _publish(output, report, workspace):
    """Exclusively reserve a new directory, then atomically link one complete file.

    An existing result is never renamed over or removed. The only visible report
    file appears with all bytes present. No raw private snapshot is linked.
    """
    staged = workspace / 'assessment.json'
    staged.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    staged.chmod(0o600)
    output.mkdir(mode=0o700)
    identity = _stamp(output.lstat())[:2]
    directory = None
    linked = False
    try:
        directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if _stamp(os.fstat(directory))[:2] != identity:
            raise AssessmentError()
        os.link(staged, 'assessment.json', dst_dir_fd=directory, follow_symlinks=False)
        linked = True
        if _stamp(output.lstat())[:2] != identity:
            raise AssessmentError()
    except (OSError, ValueError):
        if linked and directory is not None:
            os.unlink('assessment.json', dir_fd=directory)
        if output.exists() and _stamp(output.lstat())[:2] == identity:
            output.rmdir()
        raise AssessmentError() from None
    finally:
        if directory is not None:
            os.close(directory)


def _assess(candidate, scans, output, expected_commit, *, qualification=None, profile='server-signature'):
    """Create a redacted assessment. Even a perfect local scan cannot approve release.

    Input trees must be stable, private local evidence directories. Original
    identity/hash pins are rechecked after validators consume owned snapshots.
    This detects changed evidence; it does not authenticate scanners, establish
    hosted workflow trust or defend against a compromised account/operating system.
    """
    if not isinstance(expected_commit, str) or not _COMMIT.fullmatch(expected_commit) or profile not in _PROFILES:
        raise AssessmentError()
    try:
        candidate, scans = _path(candidate, directory=True), _path(scans, directory=True)
        output = _path(output, new=True)
        if candidate == scans or candidate in scans.parents or scans in candidate.parents:
            raise AssessmentError()
        if any(output == root or root in output.parents for root in (candidate, scans)):
            raise AssessmentError()
        qualification = _path(qualification) if qualification is not None else None
        # Validate all path entries before copying, including symlinked logs.
        _files(candidate)
        _files(scans)
    except (OSError, ValueError, TypeError):
        raise AssessmentError() from None
    passed, reason, hashes, count = False, 'scan_evidence_unverified', {}, 0
    qual_state, qual_reason = 'pending_external', 'local_qualification_not_provided'
    with tempfile.TemporaryDirectory(prefix='.assessment-', dir=output.parent) as temporary:
        workspace = Path(temporary)
        candidate_pins, scan_pins, qual_pin = {}, {}, None
        try:
            candidate_pins, candidate_docs = _snapshot(candidate, workspace / 'candidate', candidate=True)
            scan_pins, scan_docs = _snapshot(scans, workspace / 'scans')
            count = len(candidate_pins) + len(scan_pins)
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
            unchanged = _unchanged(candidate, candidate_pins) and _unchanged(scans, scan_pins)
            if qual_pin is not None:
                latest = _read(qualification)
                latest.pop('json')
                unchanged = unchanged and latest == qual_pin
            if not unchanged:
                passed, reason = False, 'inputs_changed'
                if qualification is not None:
                    qual_state, qual_reason = 'blocked', 'qualification_unverified'
        except (OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError):
            passed = False
            reason = 'scan_evidence_unverified'
            if qualification is not None and qual_state != 'referenced_unverified':
                qual_state, qual_reason = 'blocked', 'qualification_unverified'
        report = _ledger(expected_commit, profile, passed, reason, qual_state, qual_reason, hashes, count)
        _publish(output, report, workspace)
    return report


def assess(candidate, scans, output, expected_commit, *, qualification=None, profile='server-signature'):
    """Write one fixed-schema assessment; filesystem/input failures stay redacted."""
    try:
        return _assess(candidate, scans, output, expected_commit, qualification=qualification, profile=profile)
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
    parser.add_argument('--profile', choices=_PROFILES, default='server-signature')
    parser.add_argument('--check', action='store_true', help='Exit 2 unless all required gates pass; v1 always retains external gates')
    args = parser.parse_args(argv)
    try:
        report = assess(args.candidate, args.scans, args.output, args.expected_commit,
                        qualification=args.qualification, profile=args.profile)
    except (OSError, ValueError, TypeError):
        parser.exit(1, _ERROR)
    if args.check and not report['release_ready']:
        parser.exit(2)


if __name__ == '__main__':
    main()
