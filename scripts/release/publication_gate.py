#!/usr/bin/env python3
"""Stage artifacts only after complete, consistent zero-finding scan evidence.

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
from runtime_catalog import validate_runtime_catalog
from tool_backport_catalog import validate_tool_backport_catalog
from publication_evidence import EvidenceDenied, read_evidence, validate_scan_evidence

CANDIDATE_FILES = ('source.tar.gz', 'manifest.json', 'dependency-coverage.json', 'licenses.json')
SCAN_FILES = ('status.json', 'source-lock-coverage.json', 'license-review.json', 'THIRD_PARTY_NOTICES.review.md',
              'trivy-sbom.json', 'trivy-maven-runtime.json', 'trivy-licenses.json',
              'trivy-maven-runtime-licenses.json', 'sbom.cdx.json', 'sbom-maven-runtime.cdx.json',
              'sbom-source.raw.cdx.json', 'python-build-catalog-overlay.json',
              'sbom-tool-backports.cdx.json', 'tool-backport-provenance.json',
              'trivy-tool-backports.json', 'trivy-tool-backports-licenses.json',
              'maven-runtime-manifest.json', 'maven-runtime-dependencies.txt',
              'runtime-lock-coverage.json', 'runtime-catalog-overlay.json', 'sbom-maven-runtime.raw.cdx.json')


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
            'reason': 'scan_evidence_unverified', 'sha256': {}}
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
        safe['reason'] = 'candidate_unverified'
        manifest = verify_candidate(candidate)
        manifest_pin = safe['sha256'].get('candidate_manifest')
        safe['reason'] = 'scan_evidence_unverified'
        # Pin all bytes BEFORE semantic validation; late pinning could adopt a
        # replacement report after it was checked.
        scan_pins = {name: digest(scans / name) for name in (*SCAN_FILES, 'trivy-secrets.json')}
        if (any(value is None for value in scan_pins.values())
                or scan_pins['status.json'] != safe['sha256'].get('scanner_status')):
            raise EvidenceDenied('scan_evidence_unverified')
        status = read_evidence(scans / 'status.json')
        if (not manifest_pin or status.get('candidate_manifest_sha256') != manifest_pin
                or not expected_commit or manifest['commit'] != expected_commit
                or status.get('candidate_commit') != expected_commit):
            raise EvidenceDenied('candidate_unverified')
        safe['reason'] = 'scan_evidence_unverified'
        secret_rows = [row for row in status.get('commands', [])
                       if isinstance(row, dict) and row.get('name') == 'trivy-secrets']
        if len(secret_rows) == 1 and type(secret_rows[0].get('returncode')) is int:
            safe['secret_scan_returncode'] = secret_rows[0]['returncode']
        commands = validate_scan_evidence(scans, status)
        safe['automated_checks_passed'] = True
        safe['reason'] = 'source_coverage_unverified'
        catalog = commands['syft']
        coverage_path = scans / 'source-lock-coverage.json'
        sbom_path = scans / 'sbom.cdx.json'
        if (catalog.get('recorded_source_lock_coverage_passed') is not True
                or not regular_file(coverage_path) or not regular_file(sbom_path)
                or catalog.get('source_lock_coverage_sha256') != digest(coverage_path)):
            raise EvidenceDenied('source_coverage_unverified')
        recorded_coverage = read_evidence(coverage_path)
        if recorded_coverage.get('schema') != 1 or recorded_coverage.get('all_recorded_packages_cataloged') is not True:
            raise EvidenceDenied('source_coverage_unverified')
        with tempfile.TemporaryDirectory(prefix='.coverage-check-', dir=output.parent) as verification:
            backports = validate_tool_backport_catalog(candidate / 'source', scans)
            actual_coverage = validate_source_catalog(candidate / 'source', sbom_path, Path(verification))
            if recorded_coverage != actual_coverage:
                raise EvidenceDenied('source_coverage_unverified')
            safe['reason'] = 'runtime_coverage_unverified'
            runtime = commands['syft-maven-runtime']
            runtime_path = scans / 'runtime-lock-coverage.json'
            if (runtime.get('recorded_runtime_coverage_passed') is not True
                    or runtime.get('runtime_lock_coverage_sha256') != digest(runtime_path)):
                raise EvidenceDenied('runtime_coverage_unverified')
            runtime_manifest = read_evidence(scans / 'maven-runtime-manifest.json')
            if runtime_manifest.get('pom_sha256') != digest(candidate / 'source/sdk/spring-boot/pom.xml'):
                raise EvidenceDenied('runtime_coverage_unverified')
            recorded_runtime = read_evidence(runtime_path)
            for field, name in [('raw_sbom_sha256', 'sbom-maven-runtime.raw.cdx.json'),
                                ('dependencies_sha256', 'maven-runtime-dependencies.txt'),
                                ('overlay_sha256', 'runtime-catalog-overlay.json')]:
                if not recorded_runtime.get(field) or recorded_runtime[field] != digest(scans / name):
                    raise EvidenceDenied('runtime_coverage_unverified')
            actual_runtime = validate_runtime_catalog(scans / 'maven-runtime', scans / 'maven-runtime-manifest.json',
                                                     scans / 'sbom-maven-runtime.cdx.json', Path(verification))
            if recorded_runtime != actual_runtime or recorded_runtime.get('all_maven_runtime_jars_cataloged') is not True:
                raise EvidenceDenied('runtime_coverage_unverified')
        if any(digest(scans / name) != value for name, value in scan_pins.items()):
            raise EvidenceDenied('scan_evidence_unverified')
        allowed = True
    except EvidenceDenied as denial:
        safe['reason'] = denial.reason
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
                if any(digest(scans / name) != value for name, value in scan_pins.items()):
                    raise ValueError('Scan evidence changed while staging')
                if any(digest(staged / 'scans' / name) != scan_pins[name] for name in SCAN_FILES):
                    raise ValueError('Staged scan evidence integrity mismatch')
                with tempfile.TemporaryDirectory(prefix='.runtime-recheck-', dir=output.parent) as verification:
                    if validate_tool_backport_catalog(candidate / 'source', scans) != backports:
                        raise ValueError('Tool backport evidence changed while staging')
                    if validate_runtime_catalog(scans / 'maven-runtime', scans / 'maven-runtime-manifest.json',
                                                scans / 'sbom-maven-runtime.cdx.json', Path(verification)) != recorded_runtime:
                        raise ValueError('Runtime artifacts changed while staging')
                for name in CANDIDATE_FILES:
                    expected = manifest_pin if name == 'manifest.json' else manifest['sha256'].get(name)
                    if not expected or digest(staged / 'candidate' / name) != expected:
                        raise ValueError('Staged candidate integrity mismatch')
                if (digest(candidate / 'manifest.json') != manifest_pin
                        or digest(staged / 'candidate/manifest.json') != manifest_pin
                        or digest(staged / 'candidate/source.tar.gz') != safe['sha256'].get('source_archive')):
                    raise ValueError('Candidate changed while staging')
            except (OSError, ValueError, KeyError, TypeError):
                allowed = False
                safe['reason'] = 'publication_copy_failed'
                for child in staged.iterdir():
                    shutil.rmtree(child)
        safe['source_publication_allowed'] = allowed
        safe['automated_checks_passed'] = safe['automated_checks_passed'] and allowed
        if allowed:
            safe['reason'] = 'verified_checks_passed'
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
