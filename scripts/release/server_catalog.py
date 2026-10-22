"""Strict recorded server-lock coverage, without resolving or installing packages.

Supported inputs are uv lock v1/revision5, NuGet lock v1, Composer package
arrays, and a conservative go.mod subset (module/go/toolchain/require).
Go's checksum ledger is not a selected dependency graph. Only declared require
versions are catalog obligations; replace/exclude/retract need future resolver
integration and are rejected instead of guessed. No network or compiler runs.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import tomllib
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET


class CatalogInputError(ValueError):
    def __init__(self, path, code):
        self.path, self.code = path, code
        super().__init__('Invalid recorded server lock input: ' + code)


def _fail(path, code):
    raise CatalogInputError(str(path), code)


def _text(value):
    return isinstance(value, str) and bool(value.strip()) and value == value.strip() and not any(ord(c) < 32 for c in value)


def parse_recorded_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate_json_key')
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError('non_json_number')
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)


def source_components(raw):
    """Reject missing/ambiguous SBOM arrays before any completeness decision."""
    try:
        data = parse_recorded_json(raw)
    except (ValueError, UnicodeDecodeError):
        _fail('<sbom>', 'invalid_sbom_json')
    if not isinstance(data, dict) or ('bomFormat' in data and data['bomFormat'] != 'CycloneDX'):
        _fail('<sbom>', 'invalid_sbom_document')
    components = data.get('components')
    if not isinstance(components, list) or any(not isinstance(c, dict) for c in components):
        _fail('<sbom>', 'invalid_components')
    return components


def _read(path, source, inputs):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.resolve() != path.absolute() or not path.is_relative_to(source):
        _fail(path.relative_to(source) if path.is_relative_to(source) else '<outside-source>', 'missing_or_unsafe_input')
    raw = path.read_bytes()
    inputs[str(path.relative_to(source))] = hashlib.sha256(raw).hexdigest()
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        _fail(path.relative_to(source), 'invalid_utf8')


def _data(path, source, inputs, parser):
    text = _read(path, source, inputs)
    try:
        result = parser(text)
    except (ValueError, ET.ParseError):
        _fail(path.relative_to(source), 'invalid_serialization')
    if not isinstance(result, dict):
        _fail(path.relative_to(source), 'invalid_document')
    return result


def _canonical(kind, name):
    if kind == 'pypi':
        return re.sub(r'[-_.]+', '-', name).lower()
    return name.casefold() if kind == 'nuget' else name


def catalog_observations(components):
    if not isinstance(components, list) or any(not isinstance(c, dict) for c in components):
        _fail('<sbom>', 'invalid_components')
    observed = set()
    for component in components:
        # Pinned Syft emits recorded package entries as libraries. A file,
        # excluded component, or unsupported scope must not satisfy coverage
        # while the downstream vulnerability scanner ignores that component.
        if component.get('type') != 'library' or component.get('scope', 'required') not in ('required', 'optional'):
            continue
        purl = component.get('purl')
        # Current pinned source catalogers emit unqualified package URLs.
        # Unsupported qualifiers/subpaths cannot be silently discarded.
        if not isinstance(purl, str) or not purl.startswith('pkg:') or '?' in purl or '#' in purl:
            continue
        kind, separator, identity = purl[4:].partition('/')
        if not separator or kind not in {'npm', 'pypi', 'nuget', 'golang', 'composer'}:
            continue
        if '@' not in identity or re.search(r'%(?![0-9A-Fa-f]{2})', identity):
            continue
        try:
            name, version = (unquote(v, errors='strict') for v in identity.rsplit('@', 1))
        except UnicodeDecodeError:
            continue
        reported = component.get('name')
        group = component.get('group')
        if not _text(reported) or (group is not None and not _text(group)):
            continue
        if group:
            reported = group + '/' + reported
        if (_canonical(kind, name) != _canonical(kind, reported) or not _text(version)
                or version != component.get('version')):
            continue
        properties = component.get('properties', [])
        if not isinstance(properties, list):
            continue
        for prop in properties:
            if not isinstance(prop, dict) or not isinstance(prop.get('name'), str):
                continue
            if not re.fullmatch(r'syft:location:\d+:path', prop['name']):
                continue
            location = prop.get('value')
            if not _text(location):
                continue
            location = location[1:] if location.startswith('/') else location
            if '\\' in location or any(p in {'', '.', '..'} for p in location.split('/')):
                continue
            observed.add((kind, location, _canonical(kind, name), version))
    return observed


def _record(lock, observed, name, version, **classification):
    if not _text(name) or not _text(version):
        _fail(lock['path'], 'missing_or_invalid_package_identity')
    record = {'name': name, 'version': version, **classification}
    record['cataloged'] = (lock['ecosystem'], lock['path'], _canonical(lock['ecosystem'], name), version) in observed
    lock['records'].append(record)
    return record


def _local_python(item, path, source, lock):
    kind, relative = next(iter(item['source'].items()))
    if kind not in {'editable', 'directory', 'virtual'} or not _text(relative) or Path(relative).is_absolute():
        _fail(lock['path'], 'unsupported_python_source')
    project = (path.parent / relative).absolute()
    resolved = project.resolve()
    if not resolved.is_relative_to(source):
        _fail(lock['path'], 'local_project_outside_source')
    # Resolve lexical '..' only; reject symlinks at every traversed project path.
    if any(p.is_symlink() for p in [project, *project.parents] if p.is_relative_to(source)):
        _fail(lock['path'], 'unsafe_local_project')
    manifest = resolved / 'pyproject.toml'
    data = _data(manifest, source, lock['input_sha256'], tomllib.loads).get('project')
    if (not isinstance(data, dict) or not _text(data.get('name')) or
            _canonical('pypi', data['name']) != _canonical('pypi', item['name']) or data.get('version') != item['version']):
        _fail(lock['path'], 'local_project_identity_mismatch')
    lock['skipped_local_projects'].append({'name': item['name'], 'version': item['version'],
                                          'source': item['source'], 'manifest': str(manifest.relative_to(source)),
                                          'reason': 'verified_local_project_not_external_distribution'})


def _uv(path, source, lock, observed):
    data = _data(path, source, lock['input_sha256'], tomllib.loads)
    if type(data.get('version')) is not int or data['version'] != 1 or type(data.get('revision')) is not int or data['revision'] != 5:
        _fail(lock['path'], 'unsupported_uv_lock_version_or_revision')
    if not isinstance(data.get('package'), list):
        _fail(lock['path'], 'invalid_uv_packages')
    lock['lock_version'], lock['lock_revision'] = data['version'], data['revision']
    lock['dependency_classification'] = []
    seen = set()
    for item in data['package']:
        if not isinstance(item, dict) or not _text(item.get('name')) or not _text(item.get('version')):
            _fail(lock['path'], 'missing_or_invalid_package_identity')
        identity = (_canonical('pypi', item['name']), item['version'])
        if identity in seen:
            _fail(lock['path'], 'ambiguous_duplicate_python_identity')
        seen.add(identity)
        origin = item.get('source')
        if not isinstance(origin, dict) or len(origin) != 1:
            _fail(lock['path'], 'invalid_python_source')
        lock['dependency_classification'].append({key: item[key] for key in
            ('name', 'version', 'dependencies', 'optional-dependencies', 'dev-dependencies', 'resolution-markers', 'metadata') if key in item})
        if 'registry' not in origin:
            _local_python(item, path, source, lock)
            continue
        if not _text(origin['registry']):
            _fail(lock['path'], 'invalid_python_registry')
        try:
            url = urlsplit(origin['registry'])
        except ValueError:
            _fail(lock['path'], 'invalid_python_registry')
        if url.scheme != 'https' or not url.netloc or url.username or url.password:
            _fail(lock['path'], 'unsupported_python_registry')
        _record(lock, observed, item['name'], item['version'], source=origin,
                resolution_markers=item.get('resolution-markers', []))


def _xml(path, source, inputs):
    text = _read(path, source, inputs)
    if '<!DOCTYPE' in text or '<!ENTITY' in text:
        _fail(path.relative_to(source), 'unsupported_project_xml')
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        _fail(path.relative_to(source), 'invalid_project_xml')


def _nuget_projects(path, source, lock):
    manifests = sorted(path.parent.glob('*.csproj'))
    if len(manifests) != 1:
        _fail(lock['path'], 'ambiguous_or_missing_nuget_project')
    root = _xml(manifests[0], source, lock['input_sha256'])
    projects = {}
    for ref in root.iter('ProjectReference'):
        relative = ref.get('Include')
        if not _text(relative) or any(c in relative for c in '$*?') or Path(relative).is_absolute() or ref.get('Condition'):
            _fail(lock['path'], 'unsupported_project_reference')
        target = (path.parent / relative).resolve()
        if not target.is_relative_to(source) or any(p.is_symlink() for p in
                [path.parent / relative, *(path.parent / relative).parents] if p.is_relative_to(source)):
            _fail(lock['path'], 'unsafe_project_reference')
        document = _xml(target, source, lock['input_sha256'])
        names = [node.text for node in document.iter('PackageId')]
        if not names:
            names = [node.text for node in document.iter('AssemblyName')]
        name = names[0] if len(names) == 1 else target.stem if not names else None
        if not _text(name) or '$' in name or name.casefold() in projects:
            _fail(lock['path'], 'ambiguous_nuget_project_identity')
        projects[name.casefold()] = str(target.relative_to(source))
    return projects


def _nuget(path, source, lock, observed):
    data = _data(path, source, lock['input_sha256'], parse_recorded_json)
    if type(data.get('version')) is not int or data['version'] != 1:
        _fail(lock['path'], 'unsupported_nuget_lock_version')
    frameworks = data.get('dependencies')
    if not isinstance(frameworks, dict):
        _fail(lock['path'], 'invalid_nuget_dependencies')
    projects = None
    for framework, dependencies in frameworks.items():
        if not _text(framework) or not isinstance(dependencies, dict):
            _fail(lock['path'], 'invalid_nuget_target_framework')
        seen = set()
        for name, item in dependencies.items():
            if not _text(name) or name.casefold() in seen or not isinstance(item, dict):
                _fail(lock['path'], 'invalid_or_duplicate_nuget_identity')
            seen.add(name.casefold())
            kind = item.get('type')
            if kind not in {'Direct', 'Transitive', 'Project'}:
                _fail(lock['path'], 'unsupported_nuget_dependency_type')
            constraints = item.get('dependencies', {})
            if not isinstance(constraints, dict) or any(not _text(k) or not _text(v) for k, v in constraints.items()):
                _fail(lock['path'], 'invalid_nuget_dependency_constraints')
            if kind == 'Project':
                if projects is None:
                    projects = _nuget_projects(path, source, lock)
                if name.casefold() not in projects or 'resolved' in item:
                    _fail(lock['path'], 'unverified_nuget_local_project')
                lock['skipped_local_projects'].append({'name': name, 'dependency_type': kind,
                    'target_framework': framework, 'manifest': projects[name.casefold()], 'dependencies': constraints,
                    'reason': 'verified_project_reference_not_external_package'})
                continue
            if not _text(item.get('contentHash')) or ('requested' in item and not _text(item['requested'])):
                _fail(lock['path'], 'invalid_nuget_package_metadata')
            _record(lock, observed, name, item.get('resolved'), target_framework=framework,
                    dependency_type=kind, requested=item.get('requested'), content_hash=item['contentHash'], dependencies=constraints)


_MODULE = re.compile(r'[A-Za-z0-9._~+\-]+(?:/[A-Za-z0-9._~+\-]+)*\Z')
_VERSION = re.compile(r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?\Z')


def _go(path, source, lock, observed):
    text = _read(path, source, lock['input_sha256'])
    requirements, module, block, directives = [], None, False, set()
    for line in text.splitlines():
        content, _, comment = line.partition('//')
        tokens = content.strip().split()
        if not tokens:
            continue
        if block and tokens == [')']:
            block = False
            continue
        if not block and tokens == ['require', '(']:
            block = True
            continue
        if block or tokens[0] == 'require':
            values = tokens if block else tokens[1:]
            if len(values) != 2 or not _MODULE.fullmatch(values[0]) or not _VERSION.fullmatch(values[1]) or (comment.strip() not in {'', 'indirect'}):
                _fail(lock['path'], 'unsupported_go_require_syntax')
            if any(name == values[0] for name, _, _ in requirements):
                _fail(lock['path'], 'duplicate_go_requirement')
            requirements.append((*values, comment.strip() == 'indirect'))
        elif tokens[0] in {'module', 'go', 'toolchain'}:
            directive = tokens[0]
            if directive in directives or len(tokens) != 2:
                _fail(lock['path'], 'invalid_go_directive')
            directives.add(directive)
            if directive == 'module':
                if not _MODULE.fullmatch(tokens[1]):
                    _fail(lock['path'], 'unsupported_go_module_path')
                module = tokens[1]
            elif not re.fullmatch(r'(?:go)?\d+\.\d+(?:\.\d+)?', tokens[1]):
                _fail(lock['path'], 'unsupported_go_toolchain_version')
        else:
            _fail(lock['path'], 'unsupported_go_directive')
    if block or module is None:
        _fail(lock['path'], 'incomplete_go_mod')
    lock['module'] = module
    sums, sumfile = {}, path.with_name('go.sum')
    if requirements or sumfile.exists():
        for line in _read(sumfile, source, lock['input_sha256']).splitlines():
            values = line.split()
            if len(values) != 3 or not _MODULE.fullmatch(values[0]) or not _VERSION.fullmatch(values[1].removesuffix('/go.mod')) or not values[2].startswith('h1:'):
                _fail(lock['path'], 'invalid_go_checksum_ledger')
            try:
                digest = base64.b64decode(values[2][3:], validate=True)
            except ValueError:
                _fail(lock['path'], 'invalid_go_checksum_ledger')
            identity = (values[0], values[1])
            if len(digest) != 32 or identity in sums:
                _fail(lock['path'], 'invalid_or_duplicate_go_checksum')
            sums[identity] = values[2]
    lock['checksum_ledger_entries'] = len(sums)
    lock['checksum_scope'] = 'Declared require versions only; other checksum entries are historical/test metadata, not an asserted selected graph'
    for name, version, indirect in requirements:
        if (name, version) not in sums or (name, version + '/go.mod') not in sums:
            _fail(lock['path'], 'missing_matching_go_checksum')
        _record(lock, observed, name, version, indirect=indirect,
                archive_checksum=sums[name, version], go_mod_checksum=sums[name, version + '/go.mod'])


def _composer(path, source, lock, observed):
    data = _data(path, source, lock['input_sha256'], parse_recorded_json)
    if not isinstance(data.get('content-hash'), str) or not re.fullmatch(r'[0-9a-f]{32}', data['content-hash']):
        _fail(lock['path'], 'invalid_composer_content_hash')
    if data.get('aliases', []) != []:
        _fail(lock['path'], 'unsupported_composer_aliases')
    seen = set()
    for section in ('packages', 'packages-dev'):
        if not isinstance(data.get(section), list):
            _fail(lock['path'], 'invalid_composer_packages')
        for item in data[section]:
            if not isinstance(item, dict) or not isinstance(item.get('name'), str) or not re.fullmatch(r'[a-z0-9_.-]+/[a-z0-9_.-]+', item['name']):
                _fail(lock['path'], 'invalid_composer_package_identity')
            name = item['name']
            if name in seen:
                _fail(lock['path'], 'duplicate_composer_package')
            seen.add(name)
            _record(lock, observed, name, item.get('version'), development=section == 'packages-dev',
                    package_type=item.get('type'), section=section)
    lock['platform_requirements'] = {}
    for section in ('platform', 'platform-dev'):
        values = data.get(section, {})
        if not isinstance(values, dict) or any(not _text(k) or not _text(v) for k, v in values.items()):
            _fail(lock['path'], 'invalid_composer_platform_requirements')
        lock['platform_requirements'][section] = values


def validate_server_catalog(source, components):
    """Return exact per-lock recorded coverage; malformed/unsupported input raises."""
    source = Path(source).resolve(strict=True)
    observed = catalog_observations(components)
    formats = {'uv.lock': ('pypi', _uv), 'packages.lock.json': ('nuget', _nuget),
               'go.mod': ('golang', _go), 'composer.lock': ('composer', _composer)}
    paths = sorted(path for path in source.rglob('*') if path.name in {*formats, 'go.sum'})
    locks = []
    for path in paths:
        if path.name == 'go.sum':
            if not path.with_name('go.mod').is_file():
                _fail(path.relative_to(source), 'orphan_go_checksum_ledger')
            continue
        ecosystem, parser = formats[path.name]
        lock = {'ecosystem': ecosystem, 'path': str(path.relative_to(source)), 'records': [],
                'skipped_local_projects': [], 'input_sha256': {}}
        parser(path, source, lock, observed)
        lock['sha256'] = lock['input_sha256'][lock['path']]
        lock['recorded_package_count'] = len(lock['records'])
        lock['cataloged_package_count'] = sum(r['cataloged'] for r in lock['records'])
        lock['skipped_local_project_count'] = len(lock['skipped_local_projects'])
        locks.append(lock)
    return {'server_locks': locks, 'all_recorded_server_packages_cataloged':
            all(record['cataloged'] for lock in locks for record in lock['records'])}
