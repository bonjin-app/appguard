#!/usr/bin/env python3
"""Stage artifact contents only after verified zero-finding secret evidence.

On denial, publish a fixed-schema status and opaque artifact digests only.
Never copy raw scanner errors, paths, component metadata or secret snippets.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

from candidate import write_json
from scan import verify_candidate
from source_catalog import validate_source_catalog

CANDIDATE_FILES = ('source.tar.gz', 'manifest.json', 'dependency-coverage.json', 'licenses.json')
SCAN_FILES = ('status.json', 'source-lock-coverage.json', 'license-review.json', 'THIRD_PARTY_NOTICES.review.md',
              'trivy-sbom.json', 'trivy-maven-runtime.json', 'trivy-licenses.json',
              'trivy-maven-runtime-licenses.json', 'sbom.cdx.json', 'sbom-maven-runtime.cdx.json',
              'maven-runtime-manifest.json', 'maven-runtime-dependencies.txt')


def regular_file(path):
    return path.is_file() and not path.is_symlink() and path == path.resolve()


def digest(path):
    if not regular_file(path):
        return None
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def stage_publication(candidate, scans, output, expected_commit):
    candidate, scans, output = map(lambda value: Path(value).absolute(), (candidate, scans, output))
    if output.exists() or output != output.resolve() or not output.parent.is_dir():
        raise ValueError('Publication output must be a new directory without symlinks')
    if output == candidate or output == scans or candidate in output.parents or scans in output.parents:
        raise ValueError('Publication output must be outside inputs')
    safe = {'schema': 1, 'source_publication_allowed': False, 'release_ready': False,
            'automated_checks_passed': False, 'secret_scan_returncode': None,
            'reason': 'secret_scan_not_verified', 'sha256': {}}
    # Fixed labels only. Even filenames and scanner error strings can contain secrets.
    for label, path in [('source_archive', candidate / 'source.tar.gz'),
                        ('candidate_manifest', candidate / 'manifest.json'),
                        ('scanner_status', scans / 'status.json'),
                        ('secret_report', scans / 'trivy-secrets.json')]:
        try:
            value = digest(path)
            if value:
                safe['sha256'][label] = value
        except OSError:
            pass
    allowed = False
    try:
        manifest = verify_candidate(candidate)
        if not regular_file(scans / 'status.json') or not regular_file(scans / 'trivy-secrets.json'):
            raise ValueError('Unavailable evidence')
        status = json.loads((scans / 'status.json').read_text())
        report = json.loads((scans / 'trivy-secrets.json').read_text())
        safe['automated_checks_passed'] = status.get('automated_checks_passed') is True
        commands = [item for item in status['commands'] if item.get('name') == 'trivy-secrets']
        if len(commands) != 1:
            raise ValueError('Ambiguous evidence')
        secret = commands[0]
        code = secret.get('returncode')
        if type(code) is int:
            safe['secret_scan_returncode'] = code
        manifest_pin = safe['sha256'].get('candidate_manifest')
        if ('error' in status or status.get('automated_checks_passed') is not True or not manifest_pin or status.get('candidate_manifest_sha256') != manifest_pin
                or not expected_commit or manifest['commit'] != expected_commit
                or status['candidate_commit'] != expected_commit or type(code) is not int or code != 0
                or secret.get('report_available') is not True
                or secret.get('finding_counts', {}).get('Secrets') != 0
                or not isinstance(report.get('SchemaVersion'), int)
                or not isinstance(report.get('Results'), list)
                or any(not isinstance(item, dict) or not isinstance(item.get('Secrets', []), list)
                       or item.get('Secrets', []) for item in report['Results'])):
            raise ValueError('Secret scan not verified')
        catalogs = [item for item in status['commands'] if item.get('name') == 'syft']
        coverage_path = scans / 'source-lock-coverage.json'
        sbom_path = scans / 'sbom.cdx.json'
        if (len(catalogs) != 1 or catalogs[0].get('returncode') != 0
                or catalogs[0].get('recorded_npm_lock_coverage_passed') is not True
                or not regular_file(coverage_path) or not regular_file(sbom_path)
                or catalogs[0].get('source_lock_coverage_sha256') != digest(coverage_path)):
            raise ValueError('Recorded source coverage not verified')
        recorded_coverage = json.loads(coverage_path.read_text())
        if recorded_coverage.get('schema') != 1 or recorded_coverage.get('all_recorded_npm_packages_cataloged') is not True:
            raise ValueError('Recorded source coverage not complete')
        with tempfile.TemporaryDirectory(prefix='.coverage-check-', dir=output.parent) as verification:
            actual_coverage = validate_source_catalog(candidate / 'source', sbom_path, Path(verification))
        if recorded_coverage != actual_coverage:
            raise ValueError('Recorded source coverage integrity mismatch')
        allowed = True
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        pass  # Intentionally omit untrusted error strings and source metadata.
    with tempfile.TemporaryDirectory(prefix='.publication-', dir=output.parent) as temp:
        staged = Path(temp) / 'result'
        staged.mkdir()
        if allowed:
            try:
                for prefix, root, names in [('candidate', candidate, CANDIDATE_FILES), ('scans', scans, SCAN_FILES)]:
                    destination = staged / prefix
                    destination.mkdir()
                    for name in names:
                        source = root / name
                        if source.exists():
                            if not regular_file(source):
                                raise ValueError('Invalid artifact file')
                            shutil.copyfile(source, destination / name)
                verify_candidate(candidate)
                if (digest(candidate / 'manifest.json') != manifest_pin
                        or digest(staged / 'candidate/manifest.json') != manifest_pin
                        or digest(staged / 'candidate/source.tar.gz') != safe['sha256'].get('source_archive')):
                    raise ValueError('Candidate changed while staging')
            except (OSError, ValueError, KeyError, TypeError):
                allowed = False
                for child in staged.iterdir():
                    shutil.rmtree(child)
        safe['source_publication_allowed'] = allowed
        safe['automated_checks_passed'] = safe['automated_checks_passed'] and allowed
        if allowed:
            safe['reason'] = 'verified_zero_finding_secret_scan'
        write_json(staged / 'public-status.json', safe)
        staged.rename(output)
    return safe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--scans', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--expected-commit', required=True)
    args = parser.parse_args()
    try:
        stage_publication(args.candidate, args.scans, args.output, args.expected_commit)
    except (OSError, ValueError):
        parser.exit(1, 'Unable to create privacy-bounded publication staging\n')


if __name__ == '__main__':
    main()
