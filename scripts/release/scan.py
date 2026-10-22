#!/usr/bin/env python3
"""Scan a candidate with checksum-pinned official binaries; never publish."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

from candidate import validate_path, write_json
from source_catalog import write_syft_config, validate_source_catalog
from runtime_catalog import prepare_runtime_catalog
from publication_evidence import count_findings, validate_report_binding

# Official immutable GitHub release asset digests, read 2026-10-22 from
# https://api.github.com/repos/{anchore/syft,aquasecurity/trivy}/releases/tags/{version}
# Updating any pin is a reviewed source change, never a runtime latest lookup.
TOOLS = {
    'syft': {
        ('Linux', 'x86_64'): {'version': '1.54.1', 'url': 'https://github.com/anchore/syft/releases/download/v1.54.1/syft_1.54.1_linux_amd64.tar.gz', 'sha256': 'c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47'},
        ('Darwin', 'arm64'): {'version': '1.54.1', 'url': 'https://github.com/anchore/syft/releases/download/v1.54.1/syft_1.54.1_darwin_arm64.tar.gz', 'sha256': 'b4319c3abaa87a0170ab76ee83ea2260ca34b53aecfa3ab0dd5428d2319d744f'},
    },
    'trivy': {
        ('Linux', 'x86_64'): {'version': '0.76.1', 'url': 'https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz', 'sha256': 'c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0'},
        ('Darwin', 'arm64'): {'version': '0.76.1', 'url': 'https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_macOS-ARM64.tar.gz', 'sha256': '11a9b6cd2752011b54f01ea4bd0dbfa9f0c41dc6538d5a3f9d23955f471bf4e5'},
    },
}


def install_tool(name, state, host=None):
    host = host or (platform.system(), platform.machine())
    if host not in TOOLS[name]:
        raise ValueError('No reviewed scanner pin for host ' + repr(host))
    pin = TOOLS[name][host]
    archive = state / (name + '.tar.gz')
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(pin['url'], timeout=60) as response, archive.open('wb') as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > 512 * 1024 * 1024:
                raise ValueError('Scanner download exceeded 512 MiB')
            output.write(chunk)
            digest.update(chunk)
    if digest.hexdigest() != pin['sha256']:
        raise ValueError('Scanner checksum mismatch: ' + name)
    with tarfile.open(archive) as tar:
        matches = [member for member in tar.getmembers() if member.name == name]
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 512 * 1024 * 1024:
            raise ValueError('Expected one regular scanner binary: ' + name)
        # Never extract archive paths, symlinks, scripts, or extra members.
        with tar.extractfile(matches[0]) as binary:
            (state / name).write_bytes(binary.read())
    (state / name).chmod(0o700)
    return state / name


def verify_candidate(candidate):
    manifest_path = candidate / 'manifest.json'
    if candidate.is_symlink() or manifest_path.is_symlink():
        raise ValueError('Candidate cannot be a symlink')
    manifest = json.loads(manifest_path.read_text())
    expected = manifest['sha256']
    for name, digest in expected.items():
        validate_path(name)
        path = candidate / name
        if path.is_symlink() or path.resolve() != path or not path.is_file():
            raise ValueError('Invalid candidate file: ' + name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Candidate checksum mismatch: ' + name)
    actual = {str(path.relative_to(candidate)) for path in candidate.rglob('*') if path.is_file() or path.is_symlink()}
    if actual != set(expected) | {'manifest.json'}:
        raise ValueError('Candidate has unexpected or missing files')
    return manifest


def export_maven(source, state, reports, env):
    """Resolve actual runtime JARs from the candidate POM, outside candidate input."""
    requested = os.environ.get('APPGUARD_MAVEN_CMD', 'mvn')
    executable = shutil.which(requested)
    if not executable:
        return {'name': 'maven-runtime', 'returncode': 127, 'error': 'Configured Maven executable unavailable'}
    executable = str(Path(executable).resolve())
    module = state / 'maven-source'
    shutil.copytree(source / 'sdk/spring-boot', module)
    artifacts = reports / 'maven-runtime'
    artifacts.mkdir()
    cache = Path(os.environ.get('APPGUARD_MAVEN_REPOSITORY', str(state / 'maven-cache'))).resolve()
    command = [executable, '-B', '-ntp', '-f', str(module / 'pom.xml'),
               '-Dmaven.repo.local=' + str(cache), '-Duser.home=' + str(state / 'home'),
               'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies',
               'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:list',
               '-DincludeScope=runtime', '-Dmdep.useRepositoryLayout=true',
               '-DoutputDirectory=' + str(artifacts),
               '-DoutputFile=' + str(reports / 'maven-runtime-dependencies.txt'), '-DappendOutput=false']
    with (reports / 'maven-runtime.log').open('wb') as log:
        try:
            result = subprocess.run(command, env=env, cwd=module, stdout=log, stderr=subprocess.STDOUT, timeout=600)
            code = result.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            log.write((str(error) + '\n').encode())
            code = 124
    files = sorted(path for path in artifacts.rglob('*') if path.is_file() or path.is_symlink())
    if code == 0 and (not any(path.suffix == '.jar' for path in files) or any(path.is_symlink() for path in files)
                      or not (reports / 'maven-runtime-dependencies.txt').is_file()):
        code = 65
    write_json(reports / 'maven-runtime-manifest.json', {
        'scope': 'Maven runtime scope (compile/runtime plus optional dependencies of this project); provided/container and test dependencies are excluded',
        'pom_sha256': hashlib.sha256((module / 'pom.xml').read_bytes()).hexdigest(),
        'command': command, 'returncode': code,
        'jar_sha256': {str(path.relative_to(artifacts)): hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in files if path.suffix == '.jar' and not path.is_symlink()},
        'sha256': {str(path.relative_to(artifacts)): hashlib.sha256(path.read_bytes()).hexdigest()
                   for path in files if not path.is_symlink()},
    })
    return {'name': 'maven-runtime', 'returncode': code,
            'scope': 'Actual exported runtime JARs; see maven-runtime-manifest.json'}


def evaluate_report(item, report):
    """Keep legal inventory visible; fail on every reported vulnerability/secret."""
    item['finding_counts'] = count_findings(report)
    if item['finding_counts']['Vulnerabilities'] or item['finding_counts']['Secrets']:
        item['security_findings_present'] = True
        if item['returncode'] == 0:
            item['returncode'] = 1
    if item['finding_counts']['Licenses']:
        item['license_review_required'] = True


def write_license_review(reports):
    entries, evidence = [], {}
    for path in sorted(reports.glob('trivy-*licenses.json')):
        evidence[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        report = json.loads(path.read_text())
        for result in report.get('Results', []):
            for finding in result.get('Licenses', []):
                entries.append({'source_report': path.name, 'target': result.get('Target'), 'finding': finding,
                                'obligation': 'notice_obligation_review' if finding.get('Category') == 'notice' else 'terms_review_required',
                                'review_status': 'pending'})
    missing = []
    for path in sorted(reports.glob('sbom*.cdx.json')):
        evidence[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        for component in json.loads(path.read_text()).get('components', []):
            if not component.get('licenses'):
                missing.append({'source_sbom': path.name, 'name': component.get('name'),
                                'version': component.get('version'), 'purl': component.get('purl'),
                                'obligation': 'missing_license_metadata_review', 'review_status': 'pending'})
    review = {'schema': 1, 'review_completed': False, 'third_party_notices_complete': False,
              'scope': 'Unapproved license/notice evidence inventory; no legal compliance determination',
              'evidence_sha256': evidence, 'entries': entries, 'missing_license_metadata': missing}
    write_json(reports / 'license-review.json', review)
    lines = ['# Third-party notice review inventory (unapproved)', '',
             'This generated index is not complete distribution notices or a license compliance determination.',
             'Maintainers must inspect the original dependency license/copyright texts and approve obligations.', '',
             'License findings (including NOTICE and unknown terms) remain pending:', '']
    for entry in entries:
        finding = entry['finding']
        lines.append('- ' + json.dumps({'package': finding.get('PkgName'), 'license': finding.get('Name'),
                                        'obligation': entry['obligation'], 'source_report': entry['source_report']}, sort_keys=True))
    lines.extend(['', 'Missing license metadata records: ' + str(len(missing)), '', 'Evidence SHA-256:', ''])
    lines.extend('- ' + name + ': ' + digest for name, digest in sorted(evidence.items()))
    (reports / 'THIRD_PARTY_NOTICES.review.md').write_text('\n'.join(lines) + '\n')
    return review


def run_scans(candidate, output):
    candidate = Path(candidate).absolute()
    output = Path(output).absolute()
    if output != output.resolve() or candidate == output or candidate in output.parents:
        raise ValueError('Scan output must be outside the candidate without symlinks')
    if output.exists() or not output.parent.is_dir():
        raise ValueError('Scan output must be new with an existing parent')
    initial_manifest_bytes = (candidate / 'manifest.json').read_bytes()
    manifest = verify_candidate(candidate)
    if manifest != json.loads(initial_manifest_bytes) or (candidate / 'manifest.json').read_bytes() != initial_manifest_bytes:
        raise ValueError('Candidate manifest changed during initial verification')
    status = {'schema': 1, 'candidate_commit': manifest.get('commit'),
              'candidate_manifest_sha256': hashlib.sha256(initial_manifest_bytes).hexdigest(),
              'scope': 'Source/lockfile SBOM plus actual Maven runtime JAR SBOM when resolution succeeds; see dependency-coverage.json',
              'complete_resolved_graph': False, 'commands': [], 'tools': {}}
    with tempfile.TemporaryDirectory(prefix='.scan-', dir=output.parent) as temp:
        state = Path(temp)
        reports = state / 'reports'
        reports.mkdir()
        home = state / 'home'
        home.mkdir()
        config = state / 'empty.yaml'
        config.write_text('{}\n')
        syft_config = state / 'syft.json'
        write_syft_config(syft_config)
        ignore = state / 'empty.ignore'
        ignore.write_text('')
        # Do not inherit scanner settings, account credentials, or user's caches.
        env = {key: os.environ[key] for key in ('PATH', 'SYSTEMROOT', 'JAVA_HOME', 'SSL_CERT_FILE', 'SSL_CERT_DIR') if key in os.environ}
        env.update(HOME=str(home), XDG_CACHE_HOME=str(state / 'cache'), XDG_CONFIG_HOME=str(home),
                   SYFT_CHECK_FOR_APP_UPDATE='false', TRIVY_SKIP_VERSION_CHECK='true', TRIVY_DISABLE_TELEMETRY='true', TRIVY_CACHE_DIR=str(state / 'cache/trivy'))
        try:
            syft = install_tool('syft', state)
            trivy = install_tool('trivy', state)
            host = (platform.system(), platform.machine())
            status['tools'] = {name: TOOLS[name][host] for name in TOOLS}
            try:
                maven = export_maven(candidate / 'source', state, reports, env)
            except (OSError, ValueError) as error:
                maven = {'name': 'maven-runtime', 'returncode': 1, 'error': str(error)}
            status['commands'].append(maven)
            commands = [
                ('syft', [str(syft), 'scan', 'dir:' + str(candidate / 'source'), '--config', str(syft_config),
                          '-o', 'cyclonedx-json=' + str(reports / 'sbom.cdx.json')]),
                ('trivy-sbom', [str(trivy), 'sbom', '--config', str(config), '--ignorefile', str(ignore),
                                '--scanners', 'vuln', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
                                '--exit-code', '1', '--format', 'json', '--output', str(reports / 'trivy-sbom.json'),
                                '--timeout', '10m', str(reports / 'sbom.cdx.json')]),
                ('trivy-licenses', [str(trivy), 'sbom', '--config', str(config), '--ignorefile', str(ignore),
                                    '--scanners', 'license', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
                                    '--exit-code', '0', '--format', 'json', '--output', str(reports / 'trivy-licenses.json'),
                                    '--timeout', '10m', str(reports / 'sbom.cdx.json')]),
                ('trivy-secrets', [str(trivy), 'fs', '--config', str(config), '--ignorefile', str(ignore),
                                   '--scanners', 'secret', '--offline-scan', '--exit-code', '1', '--format', 'json',
                                   '--output', str(reports / 'trivy-secrets.json'), '--timeout', '10m',
                                   str(candidate / 'source')]),
            ]
            if maven['returncode'] == 0:
                commands.extend([
                    ('syft-maven-runtime', [str(syft), 'scan', 'dir:' + str(reports / 'maven-runtime'),
                                            '--config', str(config), '-o', 'cyclonedx-json=' + str(reports / 'sbom-maven-runtime.raw.cdx.json')]),
                    ('trivy-maven-runtime', [str(trivy), 'sbom', '--config', str(config), '--ignorefile', str(ignore),
                                             '--scanners', 'vuln', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
                                             '--exit-code', '1', '--format', 'json', '--output', str(reports / 'trivy-maven-runtime.json'),
                                             '--timeout', '10m', str(reports / 'sbom-maven-runtime.cdx.json')]),
                    ('trivy-maven-runtime-licenses', [str(trivy), 'sbom', '--config', str(config), '--ignorefile', str(ignore),
                                                      '--scanners', 'license', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
                                                      '--exit-code', '0', '--format', 'json', '--output', str(reports / 'trivy-maven-runtime-licenses.json'),
                                                      '--timeout', '10m', str(reports / 'sbom-maven-runtime.cdx.json')]),
                ])
            for name, command in commands:
                input_sha256 = None
                if name.startswith('trivy-'):
                    if name == 'trivy-secrets':
                        input_sha256 = status['candidate_manifest_sha256']
                    elif Path(command[-1]).is_file():
                        input_sha256 = hashlib.sha256(Path(command[-1]).read_bytes()).hexdigest()
                with (reports / (name + '.log')).open('wb') as log:
                    try:
                        result = subprocess.run(command, cwd=state, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=900)
                        code = result.returncode
                    except (OSError, subprocess.TimeoutExpired) as error:
                        log.write((str(error) + '\n').encode())
                        code = 124
                item = {'name': name, 'returncode': code}
                if code == 0:
                    report_name = {'syft': 'sbom.cdx.json', 'syft-maven-runtime': 'sbom-maven-runtime.raw.cdx.json'}.get(name, name + '.json')
                    try:
                        report = json.loads((reports / report_name).read_text())
                        valid = report.get('bomFormat') == 'CycloneDX' if name.startswith('syft') else isinstance(report.get('SchemaVersion'), int)
                        if not valid:
                            raise ValueError('Unexpected report schema')
                    except (OSError, ValueError, AttributeError) as error:
                        item.update(returncode=65, report_validation_error=str(error))
                report_name = {'syft': 'sbom.cdx.json', 'syft-maven-runtime': 'sbom-maven-runtime.raw.cdx.json'}.get(name, name + '.json')
                item['report_available'] = (reports / report_name).is_file()
                if not name.startswith('syft') and item['report_available']:
                    try:
                        report = json.loads((reports / report_name).read_text())
                        evaluate_report(item, report)
                    except (ValueError, TypeError, AttributeError):
                        item.update(report_parse_error=True, returncode=65)
                if name == 'syft' and item['returncode'] == 0:
                    try:
                        validate_source_catalog(candidate / 'source', reports / 'sbom.cdx.json', reports)
                        item['recorded_npm_lock_coverage_passed'] = True
                        item['recorded_source_lock_coverage_passed'] = True
                        item['source_lock_coverage_sha256'] = hashlib.sha256((reports / 'source-lock-coverage.json').read_bytes()).hexdigest()
                    except (OSError, ValueError, TypeError, KeyError) as error:
                        item.update(returncode=65, recorded_npm_lock_coverage_passed=False,
                                    recorded_source_lock_coverage_passed=False, coverage_error=str(error))
                if name == 'syft-maven-runtime' and item['returncode'] == 0:
                    try:
                        prepare_runtime_catalog(reports / 'maven-runtime', reports / 'maven-runtime-manifest.json',
                                                reports / 'sbom-maven-runtime.raw.cdx.json', reports,
                                                dependencies_path=reports / 'maven-runtime-dependencies.txt')
                        item['recorded_runtime_coverage_passed'] = True
                        item['runtime_lock_coverage_sha256'] = hashlib.sha256((reports / 'runtime-lock-coverage.json').read_bytes()).hexdigest()
                    except (OSError, ValueError, TypeError, KeyError) as error:
                        item.update(returncode=65, recorded_runtime_coverage_passed=False, coverage_error=str(error))
                if name.startswith('trivy-') and item['report_available']:
                    item['report_sha256'] = hashlib.sha256((reports / report_name).read_bytes()).hexdigest()
                    item['scan_artifact_name'] = command[-1]
                    item['input_sha256'] = input_sha256
                    try:
                        validate_report_binding(reports, status, item, json.loads((reports / report_name).read_text()))
                    except (OSError, ValueError, TypeError, AttributeError):
                        item.update(returncode=65, report_binding_error=True)
                status['commands'].append(item)
            write_license_review(reports)
            if (candidate / 'manifest.json').read_bytes() != initial_manifest_bytes:
                raise ValueError('Candidate manifest changed during scanning')
            verify_candidate(candidate)
            if (candidate / 'manifest.json').read_bytes() != initial_manifest_bytes:
                raise ValueError('Candidate manifest changed during final verification')
        except Exception as error:
            status['error'] = str(error)
        failed = 'error' in status or any(item['returncode'] != 0 for item in status['commands'])
        status['automated_checks_passed'] = not failed
        status['release_ready'] = False
        status['remaining_release_gates'] = [
            'Independent security audit appropriate to intended deployment',
            'Maintainer approval of dependency licenses, third-party notices and distribution obligations',
            'Native/platform and deployment consumer coverage, including provided/container dependencies',
            'Resolution of dependency graph coverage gaps recorded in dependency-coverage.json',
            'Maintainer approval of versions, registry ownership, signing/provenance and publication',
        ]
        write_json(reports / 'status.json', status)
        reports.rename(output)
    return 1 if failed else 0


def public_check_summary(status):
    """Fixed-label counts for CI debugging; never raw errors, paths or findings."""
    known = {'maven-runtime', 'syft', 'trivy-sbom', 'trivy-licenses', 'trivy-secrets',
             'syft-maven-runtime', 'trivy-maven-runtime', 'trivy-maven-runtime-licenses'}
    checks = []
    for item in status.get('commands', []):
        if not isinstance(item, dict) or not isinstance(item.get('name'), str) or item['name'] not in known:
            continue
        code = item.get('returncode')
        entry = {'check': item['name'], 'returncode': code if type(code) is int and -255 <= code <= 255 else None}
        counts = item.get('finding_counts', {})
        for kind in ('Vulnerabilities', 'Secrets', 'Licenses'):
            count = counts.get(kind) if isinstance(counts, dict) else None
            if type(count) is int and 0 <= count <= 2147483647:
                entry[kind.lower()] = count
        checks.append(entry)
    return {'automated_checks_passed': status.get('automated_checks_passed') is True,
            'release_ready': False, 'checks': checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        code = run_scans(args.candidate, args.output)
        print(json.dumps(public_check_summary(json.loads((args.output / 'status.json').read_text())), sort_keys=True))
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, str(error) + '\n')
    parser.exit(code)


if __name__ == '__main__':
    main()
