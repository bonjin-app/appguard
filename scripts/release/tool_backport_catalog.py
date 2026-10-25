"""Data-only catalog of maintained tool archives and unsuppressed ancestry.

The builder is trusted running-tool code, never code from the candidate. No npm,
JavaScript, compiler, lifecycle hook, network lookup or candidate script runs.
"""
import hashlib
import importlib.util
from pathlib import Path
from urllib.parse import quote

from runtime_catalog import _encoded, _json, _path, _write_bytes
from python_build_catalog import _read
from server_catalog import parse_recorded_json

SBOM = 'sbom-tool-backports.cdx.json'
PROVENANCE = 'tool-backport-provenance.json'
_ROOT = 'tools/dependency-backports'
_CLASS = 'upstream-ancestry-not-installed-runtime'
_ERROR = 'Invalid tool backport catalog evidence'
_VERSIONS = {'braces': '3.0.3', 'node-forge': '1.4.0', 'resolve-workspace-root': '2.0.1'}
_ADVISORIES = ['GHSA-vfj7-8cjw-p6xm', 'GHSA-86w9-cpqp-85rv']
_SCOPE = ('Maintained archive identities and affected upstream ancestry; ancestry '
          'is not installed-runtime evidence and all findings remain unsuppressed')


class ToolBackportCatalogError(ValueError):
    def __init__(self):
        self.path, self.code = '<tool-backports>', 'invalid_tool_backport_evidence'
        super().__init__(_ERROR)


def _require(condition):
    if not condition:
        raise ToolBackportCatalogError()


# Resolve from this reviewed tool installation, not source/scripts in a snapshot.
_SPEC = importlib.util.spec_from_file_location('_appguard_trusted_backport_builder',
    Path(__file__).resolve().parents[1] / 'dependencies/build-backports.py')
_BUILDER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_BUILDER)


def _lock_names(source):
    names = sorted(p.relative_to(source).as_posix() for p in source.rglob('package-lock.json'))
    _require(len(names) <= 128)
    return names


def _component(name, version, classification, binding, license_expression=None):
    purl = 'pkg:npm/' + quote(name, safe='/') + '@' + version
    props = {'appguard:tool-backports:classification': classification,
             'appguard:tool-backports:installed-runtime-verified': 'false', **binding}
    component = {'type': 'library', 'scope': 'required', 'name': name.rsplit('/', 1)[-1],
                 'version': version, 'purl': purl,
                 'bom-ref': 'appguard:tool-backports:' + hashlib.sha256(_encoded([purl, props])).hexdigest(),
                 'properties': [{'name': k, 'value': v} for k, v in sorted(props.items())]}
    if name.startswith('@'):
        component['group'] = name.split('/')[0]
    if license_expression:
        component['licenses'] = [{'expression': license_expression}]
    return component


def _assemble(source):
    source = _path(source, directory=True)
    root = source / _ROOT
    snapshots, inputs, packages, components, local, unresolved, original_bundles = [], {}, [], [], [], [], []
    names = _lock_names(source)
    root_present = root.exists() or root.is_symlink()
    manifest = {'packages': []}
    def capture(path, limit=32 * 1024 * 1024):
        snap = _read(path, True, limit=limit)
        snapshots.append(snap)
        inputs[path.relative_to(source).as_posix()] = snap['sha256']
        return snap
    if root_present:
        _path(root, directory=True)
        snap = capture(root / 'manifest.json', 2 * 1024 * 1024)
        manifest = _BUILDER.json_data(snap['bytes'])
        _BUILDER.validate_manifest(manifest)
        for record in manifest['packages']:
            for name in sorted(set(record['inputs']) | {record['upstream']['path'], record['archive']['path']}):
                capture(root / name)
        # The reviewed source producer is data here. Never import/evaluate candidate JS.
        capture(source / 'scripts/dependencies/build-resolver.cjs')
        _BUILDER.check_archives(root, manifest)
        for record in manifest['packages']:
            up, fork, archive = record['upstream'], record['fork'], record['archive']
            proof = _json((root / record['provenance']).read_bytes())
            binding = {'appguard:tool-backports:manifest-sha256': inputs[_ROOT + '/manifest.json'],
                       'appguard:tool-backports:archive-path': _ROOT + '/' + archive['path'],
                       'appguard:tool-backports:archive-sha256': archive['sha256'],
                       'appguard:tool-backports:archive-integrity': archive['integrity'],
                       'appguard:tool-backports:upstream-sha256': up['sha256'],
                       'appguard:tool-backports:upstream-integrity': up['integrity'],
                       'appguard:tool-backports:provenance-sha256': inputs[_ROOT + '/' + record['provenance']]}
            if record['id'] == 'resolve-workspace-root':
                lineage = proof['original_bundled_lineage']
                _require(lineage == {'package': 'braces', 'version': None, 'bundled_version_verified': False,
                    'classification': 'original-upstream-bundle-not-installed',
                    'old_bundle_sha256': 'ee3be37ce5bce6f0de05ee538653d13f8cbf6a7ec8c8f4ed24466025e5e34f2e',
                    'maintained_payload_contains_original_bundle': False, 'installed_runtime_verified': False})
                original_bundles.append({'upstream': up, 'bundled_package': 'braces',
                    'bundled_version': None, 'bundled_version_verified': False,
                    'classification': 'original-upstream-bundle-not-installed',
                    'scope': 'Retained upstream ancestry; absent from maintained archive payload. Actual installation is separate.',
                    'maintained_payload_contains_original_bundle': False,
                    'installed_runtime_verified': False, 'old_bundle_sha256': lineage['old_bundle_sha256']})
                binding.update({'appguard:tool-backports:original-bundle-classification': 'original-upstream-bundle-not-installed',
                    'appguard:tool-backports:original-bundled-braces-version-verified': 'false',
                    'appguard:tool-backports:maintained-payload-contains-original-bundle': 'false'})
            components.extend([_component(fork['name'], fork['version'], 'maintained-derivative-not-upstream-fixed', binding, proof['license']),
                               _component(up['name'], up['version'], _CLASS, binding, proof['license'])])
            packages.append({'id': record['id'], 'upstream': up, 'fork': fork, 'archive': archive,
                             'provenance': record['provenance'], 'provenance_sha256': binding['appguard:tool-backports:provenance-sha256'],
                             'result_files': record['result_files'], 'ancestry_classification': _CLASS})
    for name in names:
        snap = capture(source / name, 16 * 1024 * 1024)
        data = parse_recorded_json(snap['bytes'].decode('utf-8'))
        _require(isinstance(data, dict) and type(data.get('lockfileVersion')) is int and data['lockfileVersion'] == 3)
        rows = data.get('packages')
        _require(isinstance(rows, dict) and isinstance(rows.get(''), dict))
        for location, row in rows.items():
            _require(isinstance(location, str) and isinstance(row, dict))
            if not location:
                continue
            logical = location.rsplit('node_modules/', 1)[-1]
            identity = row.get('name') or logical
            resolved = row.get('resolved')
            owned = [ident for ident, version in _VERSIONS.items()
                     if identity == '@appguard/' + ident or
                     (logical in (ident, '@appguard/' + ident) and row.get('version') == version + '-appguard.1') or
                     (isinstance(resolved, str) and resolved.startswith('file:') and
                      Path(resolved[5:]).name == f'appguard-{ident}-{version}-appguard.1.tgz')]
            if owned:
                _require(len(owned) == 1)
                record = next((r for r in manifest['packages'] if r['id'] == owned[0]), None)
                _require(record is not None and row.get('link') is not True)
                archive, fork = record['archive'], record['fork']
                _require(logical in (record['id'], fork['name']) and identity == fork['name'] and row.get('version') == fork['version'])
                _require(isinstance(resolved, str) and resolved.startswith('file:') and row.get('integrity') == archive['integrity'])
                _require((source / name).parent.joinpath(resolved[5:]).resolve() == root / archive['path'])
                _require(location == str(Path(location)) and not Path(location).is_absolute() and '..' not in Path(location).parts)
                local.append({'lock': name, 'lock_sha256': snap['sha256'], 'location': location,
                              'logical_name': logical, 'name': fork['name'], 'version': fork['version'],
                              'resolved': resolved, 'integrity': row['integrity'],
                              'archive_path': _ROOT + '/' + archive['path'], 'archive_sha256': archive['sha256'],
                              'classification': 'archive-bound-local-lock-not-installed-runtime'})
            if row.get('link') is True:
                continue
            if identity == 'resolve-workspace-root' and row.get('version') == '2.0.1':
                lineage = {'lock': name, 'lock_sha256': snap['sha256'], 'location': location,
                           'name': identity, 'version': row['version'], 'resolved': resolved,
                           'integrity': row.get('integrity'), 'bundled_package': 'braces',
                           'bundled_version_verified': False, 'status': 'unresolved',
                           'classification': 'unresolved-bundled-copy-not-remediated'}
                unresolved.append(lineage)
                components.append(_component(identity, row['version'], _CLASS,
                    {'appguard:tool-backports:lock': name, 'appguard:tool-backports:lock-sha256': snap['sha256'],
                     'appguard:tool-backports:lock-location': location,
                     'appguard:tool-backports:bundled-braces-status': 'unresolved',
                     'appguard:tool-backports:bundled-braces-version-verified': 'false'}))
    def recheck():
        _require(_lock_names(source) == names and (root.exists() or root.is_symlink()) == root_present)
        for snap in snapshots:
            current = _read(snap['path'])
            _require(current['sha256'] == snap['sha256'] and current['stamp'] == snap['stamp'])
    recheck()
    document = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1, 'components': components}
    proof = {'schema': 1, 'scope': _SCOPE, 'packages': packages, 'input_sha256': inputs,
             'local_lock_records': local, 'unresolved_bundled_lineage': unresolved,
             'original_bundled_lineage': original_bundles,
             'affected_advisories': _ADVISORIES if packages else [], 'ancestry_classification': _CLASS,
             'sbom_sha256': hashlib.sha256(_encoded(document)).hexdigest(),
             'preserves_all_raw_source_and_python_components': True,
             **{key: False for key in ('advisory_closure_verified', 'compilation_reproduction_verified',
                 'producer_closure_verified', 'consumer_adoption_verified', 'complete_resolved_graph',
                 'native_coverage_verified', 'external_audit_approved', 'legal_approved',
                 'provider_approved', 'deployment_approved', 'release_ready')}}
    return document, proof, recheck


def _guard(function):
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError):
            raise ToolBackportCatalogError() from None
    return guarded


@_guard
def prepare_tool_backport_catalog(source, reports):
    """Create separate immutable catalog evidence without touching source SBOMs."""
    source, reports = _path(source, directory=True), _path(reports, directory=True)
    _require(not reports.is_relative_to(source))
    document, proof, recheck = _assemble(source)
    for name, value in ((SBOM, document), (PROVENANCE, proof)):
        path, data = reports / name, _encoded(value)
        if path.exists() or path.is_symlink():
            _require(_read(path, True)['bytes'] == data)
        else:
            _write_bytes(reports, name, data)
    recheck()
    return validate_tool_backport_catalog(source, reports)


@_guard
def validate_tool_backport_catalog(source, reports):
    """Reconstruct every component, classification and hash/SRI/location join."""
    reports = _path(reports, directory=True)
    document, proof, recheck = _assemble(source)
    sbom, provenance = _read(reports / SBOM, True), _read(reports / PROVENANCE, True)
    _require(sbom['bytes'] == _encoded(document) and provenance['bytes'] == _encoded(proof))
    recheck()
    return {**proof, 'provenance_sha256': provenance['sha256'], 'all_tool_backports_cataloged': True}
