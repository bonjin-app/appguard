"""Explicit recorded source lock-to-SBOM coverage, including development inputs."""
import hashlib
import json
from pathlib import Path
from server_catalog import CatalogInputError, catalog_observations, parse_recorded_json, source_components, validate_server_catalog
from python_build_catalog import PythonBuildCatalogError, validate_python_build_catalog
from tool_backport_catalog import (ToolBackportCatalogError, validate_tool_backport_catalog,
                                   SBOM as TOOL_SBOM, PROVENANCE as TOOL_PROVENANCE)
from runtime_catalog import _json, _read


def write_syft_config(path):
    # Official Syft 1.54.1 option; defaults otherwise omit development-only JS graphs.
    Path(path).write_text(json.dumps({'javascript': {'include-dev-dependencies': True}}, indent=2) + '\n')


def validate_source_catalog(source, sbom, reports):
    source, sbom, reports = map(Path, (source, sbom, reports))
    sbom_snapshot = _read(sbom, True)
    sbom_bytes, sbom_sha256 = sbom_snapshot['bytes'], sbom_snapshot['sha256']
    def reject_server(error, locks):
        invalid = {'schema': 1, 'all_recorded_packages_cataloged': False,
                   'all_recorded_npm_packages_cataloged': False,
                   'all_declared_python_build_constraints_cataloged': False,
                   'python_build_resolved_closure_verified': False,
                   'validation_errors': [{'path': error.path, 'code': error.code}],
                   'locks': locks, 'server_locks': [], 'sbom_sha256': sbom_sha256}
        (reports / 'source-lock-coverage.json').write_text(json.dumps(invalid, indent=2, sort_keys=True) + '\n')
        raise ValueError('Invalid recorded server lock input; see source-lock-coverage.json')
    try:
        _json(sbom_bytes)
    except (ValueError, UnicodeError):
        reject_server(CatalogInputError('<sbom>', 'invalid_sbom_json'), [])
    try:
        components = source_components(sbom_bytes)
        server = validate_server_catalog(source, components)
        build = validate_python_build_catalog(source, sbom)
        evidence = sbom.parent
        if ((source / 'tools/dependency-backports').exists() or (source / 'tools/dependency-backports').is_symlink() or
                any((evidence / name).exists() or (evidence / name).is_symlink()
                    for name in (TOOL_SBOM, TOOL_PROVENANCE))):
            backports = validate_tool_backport_catalog(source, evidence)
        else:
            backports = {'local_lock_records': [], 'all_tool_backports_cataloged': True}
    except (CatalogInputError, PythonBuildCatalogError, ToolBackportCatalogError) as error:
        reject_server(error, [])
    local = {(r['lock'], r['location'], r['name'], r['version']) for r in backports['local_lock_records']}
    observed = {(path, name, version) for kind, path, name, version in catalog_observations(components) if kind == 'npm'}
    locks = []
    for lock in sorted(source.rglob('package-lock.json')):
        relative = str(lock.relative_to(source))
        records, links = [], []
        def reject(code):
            invalid = {'schema': 1, 'all_recorded_npm_packages_cataloged': False,
                       'all_recorded_packages_cataloged': False, 'server_locks': server['server_locks'],
                       'validation_errors': [{'path': relative, 'code': code}], 'locks': locks,
                       'sbom_sha256': sbom_sha256}
            (reports / 'source-lock-coverage.json').write_text(json.dumps(invalid, indent=2, sort_keys=True) + '\n')
            raise ValueError('Invalid recorded npm lock input; see source-lock-coverage.json')
        try:
            data = parse_recorded_json(lock.read_text())
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
                logical = location.rsplit('node_modules/', 1)[-1]
                if (item.get('name') in {'@appguard/braces', '@appguard/node-forge'} or
                        (logical in {'braces', 'node-forge'} and isinstance(item.get('version'), str)
                         and item['version'].endswith('-appguard.1')) or
                        (isinstance(item.get('resolved'), str) and
                         Path(item['resolved']).name.startswith(('appguard-braces-', 'appguard-node-forge-')))):
                    reject('unverified_local_tool_backport')
                if not isinstance(item.get('resolved'), str) or not item['resolved'].strip():
                    reject('invalid_link_record')
                links.append(location)
                continue
            if not isinstance(item.get('version'), str) or not item['version'].strip():
                reject('missing_or_invalid_package_version')
            if 'name' in item and (not isinstance(item['name'], str) or not item['name'].strip()):
                reject('invalid_package_name')
            name = item.get('name') or location.rsplit('node_modules/', 1)[-1]
            joined = (relative, location, name, item['version']) in local
            logical = location.rsplit('node_modules/', 1)[-1]
            owned = (name in {'@appguard/braces', '@appguard/node-forge'} or
                     (logical in {'braces', 'node-forge'} and item['version'].endswith('-appguard.1')) or
                     (isinstance(item.get('resolved'), str) and item['resolved'].startswith('file:') and
                      Path(item['resolved'][5:]).name.startswith(('appguard-braces-', 'appguard-node-forge-'))))
            if owned and not joined:
                reject('unverified_local_tool_backport')
            records.append({'name': name, 'version': item['version'], 'development': bool(item.get('dev')),
                            'optional': bool(item.get('optional')), 'peer': bool(item.get('peer')),
                            'dev_optional': bool(item.get('devOptional')),
                            'cataloged': joined or (relative, name, item['version']) in observed})
        locks.append({'path': relative, 'sha256': hashlib.sha256(lock.read_bytes()).hexdigest(),
                      'records': records, 'unversioned_or_link_records': links})
    result = {'schema': 1, 'all_recorded_npm_packages_cataloged': all(r['cataloged'] for lock in locks for r in lock['records']),
              'sbom_sha256': sbom_sha256, 'locks': locks, **server, **build,
              'tool_backport_catalog': backports,
              'scope': 'Recorded npm, uv, NuGet, Go require versions with checksums and Composer package entries plus separately classified declared hashed Python build constraints; includes recorded development/optional entries; not proof of installed/native or resolved runtime closure',
              'classification': 'Original lock development/optional/peer flags are preserved here; Syft CycloneDX does not encode npm dev as component scope',
              'other_ecosystems': 'Maven runtime JARs are checked separately; native/platform graphs are outside this recorded-lock comparison'}
    result['all_recorded_packages_cataloged'] = (result['all_recorded_npm_packages_cataloged'] and
                                                result['all_recorded_server_packages_cataloged'] and
                                                result['all_declared_python_build_constraints_cataloged'])
    (reports / 'source-lock-coverage.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    if not result['all_recorded_npm_packages_cataloged']:
        raise ValueError('Source SBOM omitted recorded npm package versions; see source-lock-coverage.json')
    if not result['all_recorded_server_packages_cataloged']:
        raise ValueError('Source SBOM omitted recorded server package versions; see source-lock-coverage.json')
    return result
