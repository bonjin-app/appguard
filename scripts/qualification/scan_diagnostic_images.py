#!/usr/bin/env python3
"""Calibrated local image vulnerability measurements, never release evidence."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scan_container_images as core

ROOT = Path(__file__).resolve().parents[2]
CVE = 'CVE-2025-9230'
INSTALLED = '3.5.1-1'
FIXED = '3.5.1-1+deb13u1'
LIMITATIONS = [
    'metadata-only Debian 13 calibration is not an installed runtime or deployment artifact',
    'one Debian advisory control does not prove feed completeness or coverage of other distributions',
    'OS package metadata does not establish bundled JRE or other native binary coverage',
    'different vendor advisory policies prevent security equivalence from finding-count comparisons',
    'scanner process RSS is not hard capped; command time, image size, files and output are bounded',
    'no secret scan, production compatibility, external approval or release readiness']


def package_version(package, source=False):
    prefix = 'Src' if source else ''
    version, release, epoch = (package.get(prefix + key, default)
        for key, default in (('Version', ''), ('Release', ''), ('Epoch', 0)))
    core.require(type(version) is str and 0 < len(version) <= 200 and core.VERSION.fullmatch(version)
        and type(release) is str and len(release) <= 200 and (not release or core.VERSION.fullmatch(release))
        and type(epoch) is int and 0 <= epoch <= 2147483647)
    return (str(epoch) + ':' if epoch else '') + version + ('-' + release if release else '')


def inventory(document):
    metadata = document.get('Metadata')
    core.require(type(metadata) is dict and type(metadata.get('OS')) is dict)
    operating = metadata['OS']; family, name = operating.get('Family'), operating.get('Name')
    core.require(type(family) is str and re.fullmatch('[a-z][a-z0-9-]{0,39}', family)
        and type(name) is str and re.fullmatch('[0-9]{1,3}(?:\\.[0-9]{1,3}){0,3}', name))
    rows = document.get('Results'); core.require(type(rows) is list and len(rows) <= 4096)
    packages = []
    for row in rows:
        core.require(type(row) is dict and type(row.get('Packages', [])) is list)
        if row.get('Class') != 'os-pkgs' or row.get('Type') != family:
            continue
        for package in row.get('Packages', []):
            core.require(type(package) is dict and type(package.get('Name')) is str
                and 0 < len(package['Name']) <= 200 and core.PACKAGE.fullmatch(package['Name']))
            package_version(package)
            packages.append(package)
            core.require(len(packages) <= 100000)
    return {'family': family, 'name': name, 'package_count': len(packages)}, packages


def calibration_fixture(state, architecture):
    directory = state / 'calibration'; directory.mkdir(mode=0o700)
    files = {
        'etc/os-release': 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n',
        'etc/debian_version': '13.0\n',
        'var/lib/dpkg/status': 'Package: openssl\nStatus: install ok installed\nArchitecture: ' + architecture +
            '\nVersion: ' + INSTALLED + '\nSource: openssl (' + INSTALLED + ')\n' +
            'Description: Metadata-only diagnostic calibration; no installed binaries.\n\n'}
    pins = {}
    for name, value in files.items():
        path = directory / name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        core.private_file(path, value.encode())
        pins[path] = (core.MAX_METADATA, core.file_identity(path, core.MAX_METADATA))
    serialized = json.dumps({name: pins[directory / name][1]['sha256'] for name in sorted(files)}, sort_keys=True).encode()
    return directory, pins, hashlib.sha256(serialized).hexdigest()


def calibration_observed(document):
    # https://security-tracker.debian.org/tracker/CVE-2025-9230
    # Pinned Trivy's Debian analyzer uses etc/debian_version. Its detector
    # queries the frozen DB with major release and dpkg source package/version.
    operating, packages = inventory(document)
    if operating['family'] != 'debian' or operating['name'].split('.')[0] != '13':
        return False
    exact = [package for package in packages if package.get('Name') == 'openssl'
        and package.get('SrcName') == 'openssl' and package_version(package) == INSTALLED
        and package_version(package, source=True) == INSTALLED]
    if len(packages) != 1 or len(exact) != 1:
        return False
    return any(row.get('Class') == 'os-pkgs' and row.get('Type') == 'debian'
        and finding.get('VulnerabilityID') == CVE and finding.get('PkgName') == 'openssl'
        and finding.get('InstalledVersion') == INSTALLED and finding.get('FixedVersion') == FIXED
        and type(finding.get('DataSource')) is dict and finding['DataSource'].get('ID') == 'debian'
        and finding['DataSource'].get('Name') == 'Debian Security Tracker'
        for row in document['Results'] for finding in row.get('Vulnerabilities', []))


def base_report(platform):
    return dict(schema=1, evidence_class='diagnostic_image_vulnerability_comparison', platform=platform,
        measurement_complete=False, reason='diagnostic_scan_unverified', release_ready=False,
        external_approval=False, native_binary_coverage=False, coverage_complete=False,
        complete_resolved_graph=False, scanner=None, databases=None, images=[], vulnerabilities=None,
        secrets=None, calibration=dict(kind='metadata_only_debian13_feed_control', observed=False,
            advisory=CVE, installed_version=INSTALLED, fixed_version=FIXED, fixture_sha256=None, report_sha256=None),
        limitations=LIMITATIONS.copy())


def check_parent_policy(publication):
    publication.check_parent()
    parent = os.fstat(publication.parent_fd)
    core.require(parent.st_uid == os.getuid() and not parent.st_mode & 0o022)


@contextmanager
def private_publication(output):
    with core.Publication(output) as publication:
        check_parent_policy(publication)
        yield publication


def scan_images(images, platform, output, docker_context='default'):
    core.require(type(images) is list and 1 <= len(images) <= 2 and len(set(images)) == len(images)
        and all(type(image) is str and core.IMAGE.fullmatch(image) for image in images)
        and platform in ('linux/amd64', 'linux/arm64') and docker_context == 'default')
    output = core._path(output, new=True)
    core.require(ROOT != output and ROOT not in output.parents)
    parent = output.parent.stat()
    core.require(parent.st_uid == os.getuid() and not parent.st_mode & 0o022)
    architecture = platform.split('/')[1]
    status = base_report(platform)
    with private_publication(output) as publication, tempfile.TemporaryDirectory(prefix='appguard-diagnostic-scan-') as temporary:
        state = Path(temporary).resolve(); state.chmod(0o700)
        session = core.TrivySession(state)
        reports, image_pins, fixture_pins = [], {}, {}
        integrity_verified = False
        try:
            session.prepare(); status.update(scanner=session.scanner, databases=session.databases)
            daemon = core._json(session.docker(['info', '--format', '{{json .}}']))
            core.require(daemon.get('OSType') == 'linux' and daemon.get('Architecture') in
                (('x86_64', 'amd64') if architecture == 'amd64' else ('aarch64', 'arm64')))
            image_pins = {image: session.image_identity(image, architecture) for image in images}
            valid_images = True
            for index, image in enumerate(images):
                name = 'trivy-image-' + str(index)
                code, document, pin = session.report(publication, name, image)
                core.require(document.get('ArtifactType') == 'container_image' and document.get('ArtifactName') == image
                    and type(document.get('Metadata')) is dict and document['Metadata'].get('ImageID') == image)
                count, findings, complete = core.finding_details(document)
                # Inventory errors do not erase an otherwise parsed finding count.
                try:
                    operating, packages = inventory(document)
                    os_inventory = len(packages) > 0
                except (ValueError, TypeError):
                    operating, os_inventory = None, False
                status['images'].append(dict(image_id=image, report_sha256=pin['sha256'], os=operating,
                    os_inventory=os_inventory, vulnerabilities=count, findings=findings,
                    debian13_control_observed=False, zero_findings_interpretable=False,
                    finding_details_complete=complete, scan_exit_code=code if type(code) is int and 0 <= code <= 255 else None))
                reports.append((name + '.json', pin))
                valid_images = valid_images and os_inventory and complete and code == int(count > 0)
                core.require(session.image_identity(image, architecture) == image_pins[image])
            status['vulnerabilities'] = sum(row['vulnerabilities'] for row in status['images'])
            fixture, fixture_pins, fixture_hash = calibration_fixture(state, architecture)
            status['calibration']['fixture_sha256'] = fixture_hash
            core.verify_files(fixture_pins)
            code, control, pin = session.report(publication, 'trivy-calibration', fixture, rootfs=True)
            core.verify_files(fixture_pins)
            reports.append(('trivy-calibration.json', pin))
            count, _, complete = core.finding_details(control)
            observed = (control.get('ArtifactType') == 'filesystem' and code == 1 and complete and count > 0
                and calibration_observed(control))
            status['calibration'].update(observed=observed, report_sha256=pin['sha256'])
            zero_supported = True
            for image in status['images']:
                operating = image['os'] or {}
                applicable = bool(observed and operating.get('family') == 'debian'
                    and operating.get('name', '').split('.')[0] == '13')
                image['debian13_control_observed'] = applicable
                image['zero_findings_interpretable'] = bool(applicable and image['os_inventory']
                    and image['finding_details_complete'] and image['vulnerabilities'] == 0 and image['scan_exit_code'] == 0)
                zero_supported = zero_supported and (image['vulnerabilities'] > 0 or image['zero_findings_interpretable'])
            session.verify()
            for image, expected in image_pins.items():
                core.require(session.image_identity(image, architecture) == expected)
            for name, pin in reports: publication.verify(name, pin)
            integrity_verified = True
            status['measurement_complete'] = bool(valid_images and observed and zero_supported)
            status['reason'] = ('calibration_unverified' if not observed else 'inventory_unverified' if not valid_images
                else 'os_feed_unverified' if not zero_supported
                else 'findings_present' if status['vulnerabilities'] else 'no_findings_reported')
        except (Exception, KeyboardInterrupt):
            status.update(measurement_complete=False, reason='diagnostic_scan_unverified')
            status['calibration']['observed'] = False
            for image in status['images']:
                image.update(debian13_control_observed=False, zero_findings_interpretable=False)
        def final_guard():
            check_parent_policy(publication)
            if integrity_verified:
                session.verify(); core.verify_files(fixture_pins)
                for image, expected in image_pins.items():
                    core.require(session.image_identity(image, architecture) == expected)
                for name, pin in reports: publication.verify(name, pin)
        raw = (json.dumps(status, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
        if len(raw) > core.MAX_STATUS:
            for row in status['images']:
                row.update(findings=[], finding_details_complete=False, zero_findings_interpretable=False)
            status.update(measurement_complete=False, reason='diagnostic_scan_unverified')
            raw = (json.dumps(status, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
        core.require(len(raw) <= core.MAX_STATUS)
        publication.write('diagnostic.json', raw)
        final_guard(); publication.publish(); final_guard(); publication.check_output()
    return status


class FixedParser(argparse.ArgumentParser):
    def error(self, message): raise ValueError('diagnostic_scan_unverified')


def main(argv=None):
    parser = FixedParser(description=__doc__)
    parser.add_argument('--image', action='append', required=True)
    parser.add_argument('--platform', choices=('linux/amd64', 'linux/arm64'), required=True)
    parser.add_argument('--docker-context', choices=('default',), default='default')
    parser.add_argument('--output', required=True)
    try:
        args = parser.parse_args(argv)
        with core.cooperative_termination():
            status = scan_images(args.image, args.platform, args.output, args.docker_context)
        print(json.dumps({key: status[key] for key in ('measurement_complete', 'vulnerabilities', 'reason')}, sort_keys=True))
        return 0 if status['measurement_complete'] and status['vulnerabilities'] == 0 else 1 if status['measurement_complete'] else 2
    except (Exception, KeyboardInterrupt):
        print('{"measurement_complete":false,"reason":"diagnostic_scan_unverified","vulnerabilities":null}')
        return 2


if __name__ == '__main__': raise SystemExit(main())
