"""Scan declared hashed Python build pins separately from resolved runtime inputs.

No resolver or installer runs here. A constraint hash is an accepted artifact
digest from the two declarations, not evidence that its wheel was downloaded.
The raw Syft document and its runtime/license classifications stay untouched.
"""
import copy
import hashlib
import os
from pathlib import Path
import re
import stat
import tomllib

from runtime_catalog import _encoded, _json, _path, _stamp, _write_bytes

_MARKER = 'appguard:python-build-catalog:source'
_PURPOSE = 'declared-hashed-build-constraint'
_RAW = 'sbom-source.raw.cdx.json'
_OVERLAY = 'python-build-catalog-overlay.json'
_SCOPE = ('Declared hashed isolated Python build constraints only; not evidence of '
          'downloaded/installed artifacts, resolved runtime or complete native/build closure')
_NAME = r'[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?'
_VERSION = r'[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?'
_PIN = re.compile('(' + _NAME + r')==(' + _VERSION + r')\Z')
_HASH = re.compile(r'sha256:[0-9a-f]{64}\Z')


class PythonBuildCatalogError(ValueError):
    def __init__(self, path, code):
        self.path, self.code = str(path), code
        super().__init__('Invalid declared Python build input: ' + code)


def _fail(path, code):
    raise PythonBuildCatalogError(path, code)


def _read(path, keep=False, limit=128 * 1024 * 1024):
    path = _path(path)
    initial = path.lstat()
    if not stat.S_ISREG(initial.st_mode) or initial.st_size > limit:
        _fail('<input>', 'invalid_or_oversized_input')
    digest, body, size = hashlib.sha256(), bytearray(), 0
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        current = os.fstat(stream.fileno())
        if not stat.S_ISREG(current.st_mode) or _stamp(initial) != _stamp(current):
            _fail('<input>', 'input_changed')
        while chunk := stream.read(65536):
            size += len(chunk)
            if size > limit:
                _fail('<input>', 'input_too_large')
            digest.update(chunk)
            if keep:
                body.extend(chunk)
        if _stamp(initial) != _stamp(os.fstat(stream.fileno())):
            _fail('<input>', 'input_changed')
    if _stamp(initial) != _stamp(path.lstat()):
        _fail('<input>', 'input_changed')
    return {'path': path, 'stamp': _stamp(initial), 'sha256': digest.hexdigest(),
            'bytes': bytes(body) if keep else None}


def _names(source):
    names = sorted({p.relative_to(source).as_posix() for pattern in ('pyproject.toml', 'uv.lock')
                    for p in source.rglob(pattern)})
    if len(names) > 128:
        _fail('<source>', 'too_many_python_inputs')
    return names


def _toml(source, name):
    try:
        path = source / name
        snapshot = _read(path, True, limit=16 * 1024 * 1024)
        return tomllib.loads(snapshot['bytes'].decode('utf-8')), snapshot
    except (OSError, ValueError, UnicodeError):
        _fail(name, 'invalid_or_unsafe_python_input')


def _rows(value, path, config):
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        _fail(path, 'invalid_build_constraint_array')
    result = {}
    for row in value:
        keys = {'requirement', 'hashes'} if config else {'name', 'specifier', 'hashes'}
        if not isinstance(row, dict) or set(row) != keys:
            _fail(path, 'invalid_build_constraint_record')
        if config:
            requirement = row['requirement']
        else:
            if not isinstance(row['name'], str) or not isinstance(row['specifier'], str):
                _fail(path, 'invalid_build_constraint_identity')
            requirement = row['name'] + row['specifier']
        match = _PIN.fullmatch(requirement) if isinstance(requirement, str) and len(requirement) <= 256 else None
        if match is None:
            _fail(path, 'unsupported_build_constraint_pin')
        name, version = re.sub(r'[-_.]+', '-', match[1]).lower(), match[2]
        if name in result:
            _fail(path, 'duplicate_build_constraint_name')
        hashes = row['hashes']
        if (not isinstance(hashes, list) or not 1 <= len(hashes) <= 16
                or any(not isinstance(h, str) or not _HASH.fullmatch(h) for h in hashes)
                or len(set(hashes)) != len(hashes)):
            _fail(path, 'invalid_build_constraint_hashes')
        result[name] = {'name': name, 'version': version, 'hashes': sorted(hashes)}
    return result


def _declarations(source):
    source = _path(source, directory=True)
    names = _names(source)
    documents, snapshots = {}, []
    for name in names:
        data, snapshot = _toml(source, name)
        documents[name] = data
        snapshots.append(snapshot)
    records, inputs, projects = [], {}, []
    for directory in sorted({str(Path(name).parent) for name in names}):
        config_name, lock_name = ((Path(directory) / name).as_posix() for name in ('pyproject.toml', 'uv.lock'))
        config, lock = documents.get(config_name, {}), documents.get(lock_name, {})
        tool, manifest = config.get('tool', {}), lock.get('manifest', {})
        if not isinstance(tool, dict) or not isinstance(tool.get('uv', {}), dict) or not isinstance(manifest, dict):
            _fail(config_name, 'invalid_python_build_tables')
        uv = tool.get('uv', {})
        build_system = config.get('build-system', {})
        requires = build_system.get('requires', []) if isinstance(build_system, dict) else None
        if (not isinstance(requires, list) or len(requires) > 32
                or any(not isinstance(r, str) or not r.strip() or len(r) > 512 for r in requires)):
            _fail(config_name, 'invalid_build_system_requires')
        declared = 'build-constraint-dependencies' in uv
        locked = 'build-constraints' in manifest
        project = {'pyproject': config_name if config_name in documents else None,
                   'lock': lock_name if lock_name in documents else None,
                   'build_system_requires_present': bool(requires), 'status': 'not_declared',
                   'declared_constraint_count': 0, 'declared_constraints_cataloged': False}
        projects.append(project)
        if not requires and not declared and not locked and uv.get('require-build-hashes') is not True:
            continue
        if not declared or not locked or uv.get('require-build-hashes') is not True:
            _fail(config_name, 'missing_hashed_build_declaration')
        if type(lock.get('version')) is not int or lock['version'] != 1 or type(lock.get('revision')) is not int or lock['revision'] != 5:
            _fail(lock_name, 'unsupported_uv_lock_version')
        expected = _rows(uv['build-constraint-dependencies'], config_name, True)
        actual = _rows(manifest['build-constraints'], lock_name, False)
        if expected != actual:
            _fail(lock_name, 'build_declaration_manifest_mismatch')
        project.update(status='declared_hashed_constraints', declared_constraint_count=len(expected),
                       declared_constraints_cataloged=True)
        records.extend({'pyproject': config_name, 'lock': lock_name, **expected[name]} for name in sorted(expected))
        for snapshot in snapshots:
            relative = snapshot['path'].relative_to(source).as_posix()
            if relative in {config_name, lock_name}:
                inputs[relative] = snapshot['sha256']
    return source, names, snapshots, {'records': records, 'input_sha256': inputs, 'projects': projects}


def _recheck(source, names, snapshots):
    if _names(source) != names:
        _fail('<source>', 'python_inputs_changed')
    for snapshot in snapshots:
        current = _read(snapshot['path'])
        if current['sha256'] != snapshot['sha256'] or current['stamp'] != snapshot['stamp']:
            _fail('<source>', 'python_input_changed')


def declared_python_builds(source):
    """Return generic exact pins only when config and uv manifest agree exactly."""
    source, names, snapshots, result = _declarations(source)
    _recheck(source, names, snapshots)
    return result


def _references(document):
    refs, marked, count = set(), False, 0
    def visit(value, depth=0):
        nonlocal count, marked
        count += 1
        if count > 1000000 or depth > 64:
            _fail('<sbom>', 'sbom_structure_too_large')
        if isinstance(value, dict):
            if value.get('name') == _MARKER:
                marked = True
            if 'bom-ref' in value:
                ref = value['bom-ref']
                if not isinstance(ref, str) or not ref or ref in refs:
                    _fail('<sbom>', 'invalid_or_duplicate_bom_ref')
                refs.add(ref)
            for child in value.values():
                visit(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                visit(child, depth + 1)
    visit(document)
    return refs, marked


def _document(raw):
    document = _json(raw['bytes'])
    if (not isinstance(document, dict) or ('bomFormat' in document and document['bomFormat'] != 'CycloneDX')
            or not isinstance(document.get('components'), list)
            or any(not isinstance(c, dict) for c in document['components'])):
        _fail('<sbom>', 'invalid_cyclonedx_document')
    return document


def _assemble(raw, declarations):
    document = _document(raw)
    refs, marked = _references(document)
    if marked:
        _fail('<sbom>', 'raw_sbom_already_supplemented')
    if declarations['records'] and (document.get('bomFormat') != 'CycloneDX'
                                    or document.get('specVersion') not in {'1.4', '1.5', '1.6', '1.7'}):
        _fail('<sbom>', 'unsupported_cyclonedx_version')
    final, additions = copy.deepcopy(document), []
    for record in declarations['records']:
        ref = 'appguard:python-build:' + hashlib.sha256(_encoded(record)).hexdigest()
        if ref in refs:
            _fail('<sbom>', 'build_bom_ref_collision')
        refs.add(ref)
        purl = 'pkg:pypi/' + record['name'] + '@' + record['version']
        props = {_MARKER: _PURPOSE, 'appguard:python-build-catalog:purpose': 'isolated-python-build',
                 'appguard:python-build-catalog:resolved-runtime': 'false',
                 'appguard:python-build-catalog:hash-origin': 'declared-accepted-artifact-sha256',
                 'appguard:python-build-catalog:pyproject': record['pyproject'],
                 'appguard:python-build-catalog:lock': record['lock'],
                 'appguard:python-build-catalog:pyproject-sha256': declarations['input_sha256'][record['pyproject']],
                 'appguard:python-build-catalog:lock-sha256': declarations['input_sha256'][record['lock']],
                 'appguard:python-build-catalog:raw-sbom-sha256': raw['sha256']}
        final['components'].append({'type': 'library', 'scope': 'required', 'name': record['name'],
            'version': record['version'], 'purl': purl, 'bom-ref': ref,
            'hashes': [{'alg': 'SHA-256', 'content': h.removeprefix('sha256:')} for h in record['hashes']],
            'properties': [{'name': name, 'value': value} for name, value in sorted(props.items())]})
        additions.append({**record, 'purl': purl, 'bom_ref': ref, 'cataloged': True})
    overlay = {'schema': 1, 'scope': _SCOPE, 'classification': _PURPOSE,
               'raw_sbom_path': _RAW, 'raw_sbom_sha256': raw['sha256'],
               'input_sha256': declarations['input_sha256'], 'records': additions, 'projects': declarations['projects'],
               'sbom_sha256': hashlib.sha256(_encoded(final)).hexdigest(),
               'preserves_all_raw_components': True}
    return final, overlay


def _empty(projects):
    return {'python_build_constraints': [], 'python_build_input_sha256': {},
            'python_build_projects': projects, 'python_build_resolved_closure_verified': False,
            'all_declared_python_build_constraints_cataloged': True, 'python_build_scope': _SCOPE}


def _preserve(reports, name, data):
    path = reports / name
    if path.exists() or path.is_symlink():
        if _read(path, True)['bytes'] != data:
            _fail('<reports>', 'conflicting_python_build_evidence')
    else:
        _write_bytes(reports, name, data)


def prepare_python_build_catalog(source, raw_sbom_path, reports_dir):
    """Keep immutable raw Syft evidence; supply the existing Trivy source input."""
    try:
        source, names, snapshots, declarations = _declarations(source)
        reports = _path(reports_dir, directory=True)
        if reports.is_relative_to(source):
            _fail('<reports>', 'reports_inside_source')
        raw = _read(raw_sbom_path, True)
        snapshots.append(raw)
        final, overlay = _assemble(raw, declarations)
        _recheck(source, names, snapshots)
        _preserve(reports, _RAW, raw['bytes'])
        _preserve(reports, 'sbom.cdx.json', _encoded(final))
        _preserve(reports, _OVERLAY, _encoded(overlay))
        _recheck(source, names, snapshots)
        return validate_python_build_catalog(source, reports / 'sbom.cdx.json')
    except PythonBuildCatalogError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError):
        _fail('<python-build>', 'invalid_or_changed_python_build_evidence')


def validate_python_build_catalog(source, sbom_path):
    """Recompute every added component and all bindings, including at publication."""
    try:
        source, names, snapshots, declarations = _declarations(source)
        sbom = _read(sbom_path, True)
        snapshots.append(sbom)
        document = _document(sbom)
        evidence = sbom['path'].parent
        provenance = evidence / _OVERLAY
        raw_path = evidence / _RAW
        if (not declarations['records'] and not provenance.exists() and not provenance.is_symlink()
                and not raw_path.exists() and not raw_path.is_symlink()):
            if _references(document)[1]:
                _fail('<sbom>', 'unexpected_python_build_overlay')
            _recheck(source, names, snapshots)
            return _empty(declarations['projects'])
        raw, proof = _read(raw_path, True), _read(provenance, True)
        snapshots.extend([raw, proof])
        final, overlay = _assemble(raw, declarations)
        if (document != final or _encoded(_json(proof['bytes'])) != _encoded(overlay)
                or sbom['sha256'] != overlay['sbom_sha256']):
            _fail('<sbom>', 'python_build_overlay_provenance_mismatch')
        _recheck(source, names, snapshots)
        return {'python_build_constraints': overlay['records'],
                'python_build_input_sha256': declarations['input_sha256'],
                'python_build_projects': declarations['projects'], 'python_build_resolved_closure_verified': False,
                'python_build_raw_sbom_sha256': raw['sha256'], 'python_build_overlay_sha256': proof['sha256'],
                'all_declared_python_build_constraints_cataloged': True, 'python_build_scope': _SCOPE}
    except PythonBuildCatalogError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError):
        _fail('<python-build>', 'invalid_or_changed_python_build_evidence')
