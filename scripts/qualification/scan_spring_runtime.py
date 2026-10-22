#!/usr/bin/env python3
"""Scan the JARs exported and used by the local Spring qualification.

This is local supply-chain evidence, never a release approval. Reports stay
private; stdout contains only fixed status fields and opaque hashes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'release'))
from runtime_catalog import _read, _json, _path, _purl, prepare_runtime_catalog, validate_runtime_catalog
from scan import install_tool, count_findings

CHECKS = frozenset(('signed_fidelity', 'replay_rejected', 'backend_bypass_rejected',
    'absolute_upload_deadline', 'malformed_framing_rejected', 'backend_failure_bounded',
    'healthy_recovery', 'owned_process_cleanup'))


def verify_pins(snapshots):
    for snapshot in snapshots:
        current = _read(snapshot['path'])
        if any(current[key] != snapshot[key] for key in ('stamp', 'sha256')):
            raise ValueError('input_changed')


def validate_qualification(root):
    receipt = _read(root / 'receipt.json', True)
    data = _json(receipt['bytes'])
    if (type(data.get('schema')) is not int or data['schema'] != 1
            or data.get('evidence_class') != 'local_deployment'
            or data.get('profile') != 'spring-mtls-store-forward-v1'
            or data.get('cleanup') is not True or data.get('provenance_unchanged') is not True
            or not isinstance(data.get('checks'), dict)
            or set(data['checks']) != CHECKS or any(value is not True for value in data['checks'].values())):
        raise ValueError('qualification_unverified')
    backend = _read(root / 'backend.jar', True)
    if backend['sha256'] != data.get('sources', {}).get('backend_jar'):
        raise ValueError('artifact_mismatch')
    with zipfile.ZipFile(root / 'backend.jar') as archive:
        names = archive.namelist()
        if (len(names) > 4096 or len(names) != len(set(names))
                or sum(i.file_size for i in archive.infolist()) > 32 * 1024 * 1024
                or any(i.file_size > 16 * 1024 * 1024 for i in archive.infolist())):
            raise ValueError('invalid_backend_archive')
        classes = {name: hashlib.sha256(archive.read(name)).hexdigest() for name in names if name.endswith('.class')}
    if not classes or classes != data.get('exampleclasses_sha256'):
        raise ValueError('artifact_mismatch')
    if _read(root / 'backend.jar')['sha256'] != backend['sha256']:
        raise ValueError('input_changed')
    return receipt, data, backend


def validate_consumption(document, coverage):
    """An empty vulnerability list must not conceal an unconsumed Maven graph."""
    consumed = set()
    results = document.get('Results')
    if not isinstance(results, list):
        raise ValueError('invalid_scanner_packages')
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get('Packages', []), list):
            raise ValueError('invalid_scanner_packages')
        for package in result.get('Packages', []):
            if not isinstance(package, dict) or not isinstance(package.get('Identifier'), dict):
                raise ValueError('invalid_scanner_packages')
            identity = _purl(package['Identifier'].get('PURL'))
            if identity:
                consumed.add(identity)
    expected = {(r['group'], r['name'], r['version'], r['classifier']) for r in coverage['records']}
    if not expected or not expected <= consumed:
        raise ValueError('runtime_packages_unconsumed')


def scan(qualification, output):
    root = _path(qualification, directory=True)
    output = Path(output).absolute()
    if (output != output.resolve() or output.exists() or not output.parent.is_dir()
            or output == root or root in output.parents):
        raise ValueError('unsafe_output')
    receipt, data, backend = validate_qualification(root)
    manifest = _read(root / 'maven-runtime-manifest.json', True)
    manifest_data = _json(manifest['bytes'])
    sdk = manifest_data.get('jar_sha256', {}).get(
        'io/appguard/appguard-spring-boot-starter/0.1.0-SNAPSHOT/appguard-spring-boot-starter-0.1.0-SNAPSHOT.jar')
    if (not sdk or sdk != data.get('artifact_sha256', {}).get('sdk_jar')
            or manifest_data.get('pom_sha256') != data.get('artifact_sha256', {}).get('example_pom')):
        raise ValueError('artifact_mismatch')
    output.mkdir(mode=0o700)
    result = {'schema': 1, 'release_ready': False, 'automated_checks_passed': False,
              'evidence_class': 'local_runtime_scan', 'reason': 'runtime_scan_unverified',
              'qualification_sha256': receipt['sha256'], 'jar_count': 0,
              'scanners': ['vuln'], 'vulnerabilities': None, 'secrets': None}
    try:
        with tempfile.TemporaryDirectory(prefix='appguard-consumer-scan-') as temporary:
            state = Path(temporary).resolve()
            home = state / 'home'; home.mkdir()
            config = state / 'empty.json'; config.write_text('{}')
            ignore = state / 'empty.ignore'; ignore.write_text('')
            env = {k: os.environ[k] for k in ('PATH', 'SYSTEMROOT', 'SSL_CERT_FILE', 'SSL_CERT_DIR') if k in os.environ}
            env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), XDG_CACHE_HOME=str(state / 'cache'),
                       SYFT_CHECK_FOR_APP_UPDATE='false', TRIVY_SKIP_VERSION_CHECK='true',
                       TRIVY_DISABLE_TELEMETRY='true', TRIVY_CACHE_DIR=str(state / 'cache/trivy'))
            syft, trivy = install_tool('syft', state), install_tool('trivy', state)
            raw = output / 'sbom-maven-runtime.raw.cdx.json'
            with (output / 'scanner.log').open('wb') as log:
                subprocess.run([str(syft), 'scan', 'dir:' + str(root / 'maven-runtime'),
                                '--config', str(config), '-o', 'cyclonedx-json=' + str(raw)],
                               check=True, timeout=600, cwd=state, env=env, stdout=log, stderr=log)
                coverage = prepare_runtime_catalog(root / 'maven-runtime',
                    root / 'maven-runtime-manifest.json', raw, output,
                    dependencies_path=root / 'maven-runtime-dependencies.txt')
                result['jar_count'] = coverage['jar_count']
                sbom = output / 'sbom-maven-runtime.cdx.json'
                sbom_pin = _read(sbom)
                if sbom_pin['sha256'] != coverage['sbom_sha256']:
                    raise ValueError('input_changed')
                report = output / 'trivy-runtime.json'
                code = subprocess.run([str(trivy), 'sbom', '--config', str(config), '--ignorefile', str(ignore),
                    '--scanners', 'vuln', '--list-all-pkgs', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', '--exit-code', '1',
                    '--timeout', '10m', '--format', 'json', '--output', str(report), str(sbom)],
                    timeout=660, cwd=state, env=env, stdout=log, stderr=log).returncode
            report_pin = _read(report, True)
            document = _json(report_pin['bytes'])
            if type(document.get('SchemaVersion')) is not int or not isinstance(document.get('Results'), list):
                raise ValueError('invalid_scanner_report')
            if (document.get('ArtifactType') != 'cyclonedx' or document.get('ArtifactName') != str(sbom)):
                raise ValueError('scanner_input_mismatch')
            counts = count_findings(document)
            validate_consumption(document, coverage)
            # Recheck the runtime after scanning; hashes and package coverage must
            # still describe the bytes that were exported for execution.
            validate_runtime_catalog(root / 'maven-runtime', root / 'maven-runtime-manifest.json', sbom, output)
            verify_pins([receipt, backend, manifest, sbom_pin, report_pin])
            result.update(vulnerabilities=counts['Vulnerabilities'],
                          sbom_sha256=sbom_pin['sha256'], report_sha256=report_pin['sha256'],
                          automated_checks_passed=code == 0 and counts['Vulnerabilities'] == 0 and counts['Secrets'] == 0,
                          reason=('findings_present' if counts['Vulnerabilities'] or counts['Secrets'] else
                                  'local_runtime_checked' if code == 0 else 'runtime_scan_unverified'))
    except Exception:
        # Logs remain private; no path or scanner exception enters public output.
        result['reason'] = 'runtime_scan_unverified'
    (output / 'status.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        result = scan(args.qualification, args.output)
        print(json.dumps(result, sort_keys=True))
        return 0 if result['automated_checks_passed'] else 2
    except Exception:
        print('{"release_ready":false,"reason":"runtime_scan_unverified"}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
