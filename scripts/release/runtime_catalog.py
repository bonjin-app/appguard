"""Bind Maven runtime JAR bytes to scanable CycloneDX Maven identities.

This is deliberately limited to the repository-layout runtime export. It neither
asserts a native/container closure nor accepts anonymous archive counts as GAVs.
"""
import copy
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from urllib.parse import parse_qsl, quote, unquote

_HEX = re.compile(r'[0-9a-f]{64}\Z')
_TOKEN = re.compile(r'[A-Za-z0-9_+.-]+\Z')
_LOCATION = re.compile(r'syft:location:[0-9]+:path\Z')
_MARKER = 'appguard:runtime-catalog:source'
_SCOPE = ('Verified exported Maven compile/runtime JARs only; provided/container, test, '
          'native and complete transitive/bundled closure are not asserted')


def _path(path, directory=False):
    path = Path(path).absolute()
    if path != path.resolve(strict=True):
        raise ValueError('unsafe_path')
    for parent in (path, *path.parents):
        if stat.S_ISLNK(parent.lstat().st_mode):
            raise ValueError('unsafe_path')
    if directory and not path.is_dir():
        raise ValueError('not_directory')
    return path


def _relative(name):
    if (not isinstance(name, str) or not name or name.startswith('/') or '\\' in name
            or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or any(p in {'', '.', '..'} for p in name.split('/'))):
        raise ValueError('unsafe_relative_path')
    return PurePosixPath(name)


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read(path, keep=False):
    path = _path(path)
    initial = path.lstat()
    if not stat.S_ISREG(initial.st_mode):
        raise ValueError('not_regular_file')
    digest, chunks = hashlib.sha256(), []
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        if _stamp(initial) != _stamp(os.fstat(stream.fileno())):
            raise ValueError('input_changed')
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
            if keep:
                chunks.append(chunk)
                if stream.tell() > 128 * 1024 * 1024:
                    raise ValueError('json_input_too_large')
        if _stamp(initial) != _stamp(os.fstat(stream.fileno())):
            raise ValueError('input_changed')
    if _stamp(initial) != _stamp(path.lstat()):
        raise ValueError('input_changed')
    return {'path': path, 'stamp': _stamp(initial), 'sha256': digest.hexdigest(),
            'bytes': b''.join(chunks) if keep else None}


def _json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate_json_field')
            result[key] = value
        return result
    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError('nonfinite_json')
        return number
    return json.loads(data, object_pairs_hook=unique,
                      parse_float=finite_float,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite_json')))


def _files(root):
    files = set()
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            _path(Path(directory) / name, directory=True)
        for name in names:
            path = _path(Path(directory) / name)
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError('not_regular_file')
            files.add(str(path.relative_to(root)))
    return files


def _coordinate(relative):
    parts = _relative(relative).parts
    if len(parts) < 4 or any(not _TOKEN.fullmatch(p) or p in {'.', '..'} for p in parts):
        raise ValueError('unsupported_repository_layout')
    group, artifact, version, filename = '.'.join(parts[:-3]), *parts[-3:]
    prefix = artifact + '-' + version
    if not filename.endswith('.jar') or not filename.startswith(prefix):
        raise ValueError('unsupported_repository_layout')
    suffix = filename[len(prefix):-4]
    if suffix and (not suffix.startswith('-') or len(suffix) == 1):
        raise ValueError('unsupported_repository_layout')
    return {'group': group, 'name': artifact, 'version': version, 'classifier': suffix[1:] if suffix else None}


def _inputs(artifacts_dir, manifest_path, sbom_path):
    root = _path(artifacts_dir, directory=True)
    manifest, sbom = _read(manifest_path, True), _read(sbom_path, True)
    data = _json(manifest['bytes'])
    if not isinstance(data, dict) or type(data.get('returncode')) is not int or data['returncode'] != 0:
        raise ValueError('unsuccessful_maven_export')
    expected, jars = data.get('sha256'), data.get('jar_sha256')
    if not isinstance(expected, dict) or not isinstance(jars, dict) or not jars:
        raise ValueError('invalid_manifest_hash_maps')
    for entries in (expected, jars):
        for name, digest in entries.items():
            _relative(name)
            if not isinstance(digest, str) or not _HEX.fullmatch(digest):
                raise ValueError('invalid_manifest_digest')
    if jars != {name: digest for name, digest in expected.items() if name.endswith('.jar')}:
        raise ValueError('mismatching_jar_hash_maps')
    if _files(root) != set(expected):
        raise ValueError('missing_or_unrecorded_export')
    snapshots, records = [manifest, sbom], []
    for name, digest in sorted(expected.items()):
        snapshot = _read(root / name)
        if snapshot['sha256'] != digest:
            raise ValueError('export_checksum_mismatch')
        snapshots.append(snapshot)
        if name in jars:
            records.append({'path': name, 'sha256': digest, **_coordinate(name)})
    document = _json(sbom['bytes'])
    return root, manifest, sbom, data, document, snapshots, records, set(expected)


def _purl(value):
    if not isinstance(value, str) or not value.startswith('pkg:maven/') or '#' in value:
        return None
    identity, separator, query = value[len('pkg:maven/'):].partition('?')
    if identity.count('/') != 1 or identity.count('@') != 1:
        return None
    group, package = identity.split('/')
    name, version = package.split('@')
    fields = [unquote(s) for s in (group, name, version)]
    if any(not _TOKEN.fullmatch(s) or s in {'.', '..'} for s in fields):
        return None
    qualifiers = parse_qsl(query, keep_blank_values=True, strict_parsing=True) if separator else []
    if len({key for key, _ in qualifiers}) != len(qualifiers):
        return None
    values = dict(qualifiers)
    if set(values) - {'classifier', 'type'} or ('type' in values and values['type'] != 'jar'):
        return None
    classifier = values.get('classifier')
    if classifier is not None and (not _TOKEN.fullmatch(classifier) or classifier in {'.', '..'}):
        return None
    return (*fields, classifier)


def _locations(component):
    result = set()
    properties = component.get('properties', [])
    if not isinstance(properties, list):
        raise ValueError('invalid_component_properties')
    for prop in properties:
        if not isinstance(prop, dict) or not isinstance(prop.get('name'), str) or not isinstance(prop.get('value'), str):
            raise ValueError('invalid_component_properties')
        if _LOCATION.fullmatch(prop['name']):
            value = prop['value']
            relative = value[1:] if value.startswith('/') else value
            try:
                _relative(relative)
            except ValueError:
                continue
            result.add(relative)
    return result


def _component_records(document):
    if (not isinstance(document, dict) or document.get('bomFormat') != 'CycloneDX'
            or document.get('specVersion') not in {'1.4', '1.5', '1.6', '1.7'}
            or not isinstance(document.get('components'), list)):
        raise ValueError('invalid_cyclonedx_document')
    observed = {}
    for component in document['components']:
        if not isinstance(component, dict):
            raise ValueError('invalid_component')
        locations = _locations(component)
        try:
            identity = _purl(component.get('purl'))
        except ValueError:
            identity = None
        if (identity is None or component.get('type') != 'library'
                or component.get('scope') not in {None, 'required', 'optional'}
                or component.get('name') != identity[1] or component.get('version') != identity[2]
                or ('group' in component and component['group'] != identity[0])):
            continue
        for location in locations:
            observed.setdefault((location, *identity), []).append(component)
    return observed


def _catalog(records, document):
    observed = _component_records(document)
    result = []
    for record in records:
        matches = observed.get((record['path'], record['group'], record['name'], record['version'], record['classifier']), [])
        result.append({**record, 'cataloged': bool(matches),
                       'matching_purls': sorted({c['purl'] for c in matches}),
                       'matching_bom_refs': sorted({c['bom-ref'] for c in matches if isinstance(c.get('bom-ref'), str)})})
    return result


def _recheck(root, snapshots, names):
    if _files(root) != names:
        raise ValueError('export_changed_during_validation')
    for snapshot in snapshots:
        current = _read(snapshot['path'])
        if current['sha256'] != snapshot['sha256'] or current['stamp'] != snapshot['stamp']:
            raise ValueError('input_changed_during_validation')


def _write_bytes(reports, name, data):
    reports = _path(reports, directory=True)
    path = reports / name
    if path.is_symlink():
        raise ValueError('unsafe_report_target')
    descriptor, temporary = tempfile.mkstemp(prefix='.' + name + '-', dir=reports)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
        if path.is_symlink():
            raise ValueError('unsafe_report_target')
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode('utf-8')


def _write(reports, name, value):
    _write_bytes(reports, name, _encoded(value))


def _dependencies(snapshot, records):
    declared = {}
    for line in snapshot['bytes'].decode('utf-8').splitlines():
        line = line.strip()
        if not line or line == 'The following files have been resolved:':
            continue
        match = re.fullmatch(r'([^\s]+)(?: \(optional\))?(?: -- module [^\r\n]+)?', line)
        if match is None:
            raise ValueError('unsupported_dependency_list_line')
        parts = match[1].split(':')
        if len(parts) not in {5, 6}:
            raise ValueError('unsupported_dependency_coordinate')
        group, name, kind = parts[:3]
        version, scope = parts[-2:]
        classifier = parts[3] if len(parts) == 6 else None
        values = [group, name, version] + ([classifier] if classifier is not None else [])
        if (kind != 'jar' or scope not in {'compile', 'runtime'}
                or any(not _TOKEN.fullmatch(v) or v in {'.', '..'} for v in values)):
            raise ValueError('unsupported_dependency_coordinate')
        identity = (group, name, version, classifier)
        if identity in declared:
            raise ValueError('duplicate_dependency_coordinate')
        declared[identity] = {'group': group, 'name': name, 'version': version,
                              'classifier': classifier, 'scope': scope}
    expected = {(r['group'], r['name'], r['version'], r['classifier']) for r in records}
    if set(declared) != expected or len(expected) != len(records):
        raise ValueError('dependency_list_export_mismatch')
    return sorted(declared.values(), key=lambda r: (r['group'], r['name'], r['version'], r['classifier'] or ''))


def _outer_jar_observations(document, records, manifest, root):
    roots = {str(root)}
    command = manifest.get('command', [])
    if not isinstance(command, list) or any(not isinstance(v, str) for v in command):
        raise ValueError('invalid_maven_command')
    exported = [v.split('=', 1)[1] for v in command if v.startswith('-DoutputDirectory=')]
    if len(exported) > 1:
        raise ValueError('ambiguous_export_directory')
    if exported:
        # This is a recorded scanner location, never a path to open outside root.
        location = exported[0]
        if not location.startswith('/'):
            raise ValueError('invalid_recorded_export_directory')
        _relative(location[1:])
        roots.add(location)
    result = []
    for record in records:
        matches = []
        allowed_names = {base + '/' + record['path'] for base in roots}
        for component in document['components']:
            at_location = (component.get('type') == 'file' and component.get('name') in allowed_names)
            at_location = at_location or record['path'] in _locations(component)
            if not at_location:
                continue
            hashes = component.get('hashes', [])
            if not isinstance(hashes, list) or any(not isinstance(h, dict) for h in hashes):
                raise ValueError('invalid_component_hashes')
            sha256 = [h.get('content') for h in hashes if h.get('alg') == 'SHA-256']
            if sha256 == [record['sha256']]:
                matches.append(component.get('bom-ref'))
        if not matches:
            raise ValueError('raw_sbom_missing_outer_jar_hash')
        result.append({'path': record['path'], 'sha256': record['sha256'],
                       'raw_bom_refs': sorted({v for v in matches if isinstance(v, str)})})
    return result


def _overlay_document(root, manifest, raw, data, dependencies, records):
    document = _json(raw['bytes'])
    if _marked(document):
        raise ValueError('raw_sbom_already_supplemented')
    catalog = _catalog(records, document)  # validates the original scanner document
    resolved = _dependencies(dependencies, records)
    observations = _outer_jar_observations(document, records, data, root)
    output = copy.deepcopy(document)
    additions = []
    existing_refs = {c.get('bom-ref') for c in document['components'] if isinstance(c.get('bom-ref'), str)}
    for record in catalog:
        if record['cataloged']:
            continue
        purl = 'pkg:maven/' + record['group'] + '/' + record['name'] + '@' + record['version']
        if record['classifier'] is not None:
            purl += '?classifier=' + quote(record['classifier'], safe='._-')
        reference = 'appguard:maven-runtime:' + hashlib.sha256((record['path'] + '\0' + record['sha256']).encode()).hexdigest()
        if reference in existing_refs:
            raise ValueError('supplement_bom_ref_collision')
        component = {'type': 'library', 'group': record['group'], 'name': record['name'],
                     'version': record['version'], 'purl': purl, 'bom-ref': reference,
                     'hashes': [{'alg': 'SHA-256', 'content': record['sha256']}],
                     'properties': [{'name': _MARKER, 'value': 'verified-maven-runtime-export'},
                                    {'name': 'syft:location:0:path', 'value': '/' + record['path']},
                                    {'name': 'appguard:runtime-catalog:manifest-sha256', 'value': manifest['sha256']},
                                    {'name': 'appguard:runtime-catalog:raw-sbom-sha256', 'value': raw['sha256']},
                                    {'name': 'appguard:runtime-catalog:dependencies-sha256', 'value': dependencies['sha256']}]}
        output['components'].append(component)
        additions.append({'path': record['path'], 'sha256': record['sha256'], 'purl': purl, 'bom_ref': reference})
    metadata = output.setdefault('metadata', {})
    if not isinstance(metadata, dict) or not isinstance(metadata.get('properties', []), list):
        raise ValueError('invalid_cyclonedx_metadata')
    metadata.setdefault('properties', []).append({'name': _MARKER, 'value': 'verified-maven-runtime-export'})
    overlay = {'schema': 1, 'scope': _SCOPE,
               'coordinate_source': 'exact_dependency_list_and_verified_maven_repository_layout',
               'manifest_sha256': manifest['sha256'], 'raw_sbom_sha256': raw['sha256'],
               'dependencies_sha256': dependencies['sha256'],
               'sbom_sha256': hashlib.sha256(_encoded(output)).hexdigest(),
               'raw_sbom_path': 'sbom-maven-runtime.raw.cdx.json', 'dependencies_path': 'maven-runtime-dependencies.txt',
               'jar_count': len(records), 'observed_jar_count': len(observations),
               'supplemented_jar_count': len(additions), 'supplements': additions,
               'raw_jar_observations': observations, 'resolved_dependency_records': resolved,
               'preserves_all_raw_components': True}
    return output, overlay


def _marked(document):
    if not isinstance(document, dict):
        return False
    metadata = document.get('metadata', {})
    components = document.get('components', [])
    values = ([metadata] if isinstance(metadata, dict) else []) + (components if isinstance(components, list) else [])
    return any(isinstance(c, dict) and isinstance(c.get('properties'), list)
               and any(isinstance(p, dict) and p.get('name') == _MARKER for p in c['properties']) for c in values)


def _verify_overlay(root, manifest, sbom, data, document, records, reports):
    raw = _read(reports / 'sbom-maven-runtime.raw.cdx.json', True)
    dependencies = _read(reports / 'maven-runtime-dependencies.txt', True)
    provenance = _read(reports / 'runtime-catalog-overlay.json', True)
    expected, overlay = _overlay_document(root, manifest, raw, data, dependencies, records)
    if document != expected or _json(provenance['bytes']) != overlay or sbom['sha256'] != overlay['sbom_sha256']:
        raise ValueError('runtime_overlay_provenance_mismatch')
    return [raw, dependencies, provenance], overlay


def prepare_runtime_catalog(artifacts_dir, manifest_path, raw_sbom_path, reports_dir, *, dependencies_path):
    """Preserve raw evidence and add only corroborated primary GAVs missing from Syft.

    The raw scanner must independently observe every outer JAR's SHA-256. The
    dependency list and repository layout must agree exactly. Raw/embedded
    components are retained, including incorrect upstream identities.
    """
    reports = _path(reports_dir, directory=True)
    output = reports / 'sbom-maven-runtime.cdx.json'
    if output.exists() or output.is_symlink():
        raise ValueError('prepared_runtime_sbom_already_exists')
    try:
        root, manifest, raw, data, document, snapshots, records, names = _inputs(artifacts_dir, manifest_path, raw_sbom_path)
        dependencies = _read(dependencies_path, True)
        snapshots.append(dependencies)
        final, overlay = _overlay_document(root, manifest, raw, data, dependencies, records)
        _recheck(root, snapshots, names)
        for name, snapshot in (('sbom-maven-runtime.raw.cdx.json', raw), ('maven-runtime-dependencies.txt', dependencies)):
            target = reports / name
            if target.exists() or target.is_symlink():
                if _read(target, True)['bytes'] != snapshot['bytes']:
                    raise ValueError('conflicting_preserved_runtime_evidence')
            else:
                _write_bytes(reports, name, snapshot['bytes'])
        _write(reports, 'sbom-maven-runtime.cdx.json', final)
        _write(reports, 'runtime-catalog-overlay.json', overlay)
    except (OSError, ValueError, TypeError, UnicodeError) as error:
        _write(reports, 'runtime-lock-coverage.json', {'schema': 1, 'scope': _SCOPE,
               'all_maven_runtime_jars_cataloged': False, 'jar_count': 0, 'cataloged_jar_count': 0,
               'records': [], 'validation_errors': [{'code': 'runtime_catalog_preparation_failed', 'error_type': type(error).__name__}]})
        raise ValueError('Maven runtime catalog preparation failed; see runtime-lock-coverage.json') from None
    return validate_runtime_catalog(root, manifest_path, output, reports)


def validate_runtime_catalog(artifacts_dir, manifest_path, sbom_path, reports_dir):
    """Write coverage evidence and raise ValueError unless every exported JAR has a GAV."""
    reports = _path(reports_dir, directory=True)
    result = {'schema': 1, 'scope': _SCOPE, 'all_maven_runtime_jars_cataloged': False,
              'jar_count': 0, 'cataloged_jar_count': 0, 'records': [], 'validation_errors': []}
    try:
        root, manifest, sbom, data, document, snapshots, records, names = _inputs(artifacts_dir, manifest_path, sbom_path)
        result.update(manifest_sha256=manifest['sha256'], sbom_sha256=sbom['sha256'], jar_count=len(records))
        evidence_dir = sbom['path'].parent
        if _marked(document) or (evidence_dir / 'runtime-catalog-overlay.json').exists():
            extra_snapshots, overlay = _verify_overlay(root, manifest, sbom, data, document, records, evidence_dir)
            snapshots.extend(extra_snapshots)
            result.update(raw_sbom_sha256=overlay['raw_sbom_sha256'], dependencies_sha256=overlay['dependencies_sha256'],
                          supplemented_jar_count=overlay['supplemented_jar_count'],
                          overlay_sha256=extra_snapshots[-1]['sha256'])
        result['records'] = _catalog(records, document)
        _recheck(root, snapshots, names)
        result['cataloged_jar_count'] = sum(r['cataloged'] for r in result['records'])
        result['validation_errors'] = [{'code': 'missing_exact_maven_identity', 'path': r['path']}
                                       for r in result['records'] if not r['cataloged']]
        result['all_maven_runtime_jars_cataloged'] = not result['validation_errors']
    except (OSError, ValueError, TypeError, UnicodeError) as error:
        result['validation_errors'].append({'code': 'invalid_or_changed_runtime_input', 'error_type': type(error).__name__})
    _write(reports, 'runtime-lock-coverage.json', result)
    if not result['all_maven_runtime_jars_cataloged']:
        raise ValueError('Maven runtime catalog coverage incomplete; see runtime-lock-coverage.json')
    return result
