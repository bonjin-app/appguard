"""Explicit development cataloging and npm lock-to-SBOM coverage evidence."""
import hashlib
import json
from pathlib import Path
from urllib.parse import unquote


def write_syft_config(path):
    # Official Syft 1.54.1 option; defaults otherwise omit development-only JS graphs.
    Path(path).write_text(json.dumps({'javascript': {'include-dev-dependencies': True}}, indent=2) + '\n')


def validate_source_catalog(source, sbom, reports):
    source, sbom, reports = map(Path, (source, sbom, reports))
    components = json.loads(sbom.read_text()).get('components', [])
    observed = set()
    for component in components:
        purl = component.get('purl', '')
        if not isinstance(purl, str) or not purl.startswith('pkg:npm/'):
            continue
        name = component.get('name', '')
        if component.get('group'):
            name = component['group'] + '/' + name
        identity = purl[len('pkg:npm/'):].split('?', 1)[0].split('#', 1)[0]
        if '@' not in identity:
            continue
        package_name, package_version = map(unquote, identity.rsplit('@', 1))
        if package_name != name or package_version != component.get('version'):
            continue
        for prop in component.get('properties', []):
            if prop.get('name', '').startswith('syft:location:') and prop['name'].endswith(':path'):
                observed.add((prop.get('value', '').lstrip('/'), name, component.get('version')))
    locks = []
    for lock in sorted(source.rglob('package-lock.json')):
        relative = str(lock.relative_to(source))
        records, links = [], []
        def reject(code):
            invalid = {'schema': 1, 'all_recorded_npm_packages_cataloged': False,
                       'validation_errors': [{'path': relative, 'code': code}], 'locks': locks,
                       'sbom_sha256': hashlib.sha256(sbom.read_bytes()).hexdigest()}
            (reports / 'source-lock-coverage.json').write_text(json.dumps(invalid, indent=2, sort_keys=True) + '\n')
            raise ValueError('Invalid recorded npm lock input; see source-lock-coverage.json')
        try:
            data = json.loads(lock.read_text())
        except ValueError:
            reject('invalid_json')
        if not isinstance(data, dict) or type(data.get('lockfileVersion')) is not int or data['lockfileVersion'] != 3:
            reject('unsupported_lockfile_version')
        packages = data.get('packages')
        if not isinstance(packages, dict) or not isinstance(packages.get(''), dict):
            reject('invalid_packages_or_root')
        for location, item in packages.items():
            if not isinstance(item, dict):
                reject('invalid_package_record')

            if not location:
                continue
            if any(key in item and type(item[key]) is not bool for key in ('link', 'dev', 'optional', 'peer', 'devOptional')):
                reject('invalid_package_flags')
            if item.get('link') is True:
                if not isinstance(item.get('resolved'), str) or not item['resolved'].strip():
                    reject('invalid_link_record')
                links.append(location)
                continue
            if not isinstance(item.get('version'), str) or not item['version'].strip():
                reject('missing_or_invalid_package_version')
            if 'name' in item and (not isinstance(item['name'], str) or not item['name'].strip()):
                reject('invalid_package_name')
            name = item.get('name') or location.rsplit('node_modules/', 1)[-1]
            records.append({'name': name, 'version': item['version'], 'development': bool(item.get('dev')),
                            'optional': bool(item.get('optional')), 'peer': bool(item.get('peer')),
                            'dev_optional': bool(item.get('devOptional')),
                            'cataloged': (relative, name, item['version']) in observed})
        locks.append({'path': relative, 'sha256': hashlib.sha256(lock.read_bytes()).hexdigest(),
                      'records': records, 'unversioned_or_link_records': links})
    result = {'schema': 1, 'all_recorded_npm_packages_cataloged': all(r['cataloged'] for lock in locks for r in lock['records']),
              'sbom_sha256': hashlib.sha256(sbom.read_bytes()).hexdigest(), 'locks': locks,
              'scope': 'Recorded versioned npm lock entries including development, peer-test and optional entries; not proof of installation/native closure',
              'classification': 'Original lock development/optional/peer flags are preserved here; Syft CycloneDX does not encode npm dev as component scope',
              'other_ecosystems': 'Default source catalogers retain their recorded package inputs; no global/native graph completeness is asserted'}
    (reports / 'source-lock-coverage.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    if not result['all_recorded_npm_packages_cataloged']:
        raise ValueError('Source SBOM omitted recorded npm package versions; see source-lock-coverage.json')
    return result
