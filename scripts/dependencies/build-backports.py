#!/usr/bin/env python3
"""Reassemble retained, pinned tool derivatives. Data only; never execute packages."""
import argparse
import base64
import binascii
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import struct
import tarfile
import zlib

MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024
MAX_FILES = 512
IDENTITIES = {'braces': ('3.0.3', 'MIT'), 'node-forge': ('1.4.0', '(BSD-3-Clause OR GPL-2.0)'),
              'resolve-workspace-root': ('2.0.1', 'MIT')}
PREFIXES = {'braces': 'braces', 'node-forge': 'node-forge', 'resolve-workspace-root': 'resolver'}
RESOLVER_LICENSE = {'sha256': '0cff14eaf2736ff712a34ef8d61f4144082e61387fff1ee3bef9da003d96a4ce', 'size': 1142}
RESOLVER_SOURCES = {
    'resolver/src/index.ts': {'sha256': '2f8cf6bf8b4dac2720a2834b56400ba28973c0c5dec3123879cf2c9764a0f640', 'size': 5864},
    'resolver/src/utils/dirs.ts': {'sha256': '4fc2cc6c11006d5c4b6f30582294efd64126ab1695c5cba9bd52738ed16cef5b', 'size': 1074},
    'resolver/src/utils/files.ts': {'sha256': '1727f0d92eebd7fa4ffa4f2dc2970ea3838f15304924f12201ba1a3da2fdcca8', 'size': 814},
    'resolver/src/utils/workspaces.ts': {'sha256': 'd063b82b49eefdf60fa1a305031b65c87508691f1ba859203ffcc3ccf14c07f9', 'size': 1102},
}
RESOLVER_MAPPING = {name: name.replace('/src/', '/compiled/').replace('.ts', '.js') for name in RESOLVER_SOURCES}
RESOLVER_OUTPUTS = {
    'resolver/compiled/index.js': {'sha256': '1a0e171d5e48f7744027b5c563e92ebcd8a9bad952addcfd63310a06a1af8ead', 'size': 6687},
    'resolver/compiled/utils/dirs.js': {'sha256': '2564bf0e4220ea2864059e687082e7043a6cdc5a609b4a3b3564a3ef6bf0172f', 'size': 1456},
    'resolver/compiled/utils/files.js': {'sha256': 'b951177cd202ee333836ef6f8b73a149d6ef2603cc17aec263deeb4208e97413', 'size': 1120},
    'resolver/compiled/utils/workspaces.js': {'sha256': 'bf9c5dcdca4e7c444414dc2378659a3acf0e7cfc2f227f99d5754b0045149721', 'size': 1525},
}
RESOLVER_SCRIPT = {'path': 'scripts/dependencies/build-resolver.cjs',
                   'sha256': '808757bfb498cb848ca7b45d1307ad567ce4cb6c6c810fcfec5f4604fe9bd3e7', 'size': 5389}
RESOLVER_DEPENDENCIES = {'js-yaml': '4.3.2', 'micromatch': '4.0.8'}
FORGE_INPUTS = {
    'node-forge/LICENSE': {'sha256': 'f63ff0e4e239244aa79280da2dd4811a0469e5e201caf5cbc0d97c3a1dff8e82', 'size': 17972},
    'node-forge/distribution-record.json': {'sha256': 'ffdb7bacc0b5b97c31fab4146fc15a6081ea7b4d1d1d65b637e7f6d9f122529b', 'size': 1508},
    'node-forge/original-package.json': {'sha256': 'a907bca8a62d97478062f2bd8ed5cd47d00b79385d3f08a8cad1c3bd7e3eb5bf', 'size': 3256},
    'node-forge/producer/README.md': {'sha256': '1f14c84e1eb82f60266e5bb4f3017d3b61150dfcc8e9bc9f48ac2ca52a0ca485', 'size': 5510},
    'node-forge/producer/build.cjs': {'sha256': '7c04de88e83a1cac4ad5f79326151f102df2a730d4a435808f5e4159c1b77be3', 'size': 9312},
    'node-forge/producer/package-lock.json': {'sha256': 'c127accb22afdf25b5390e9e609e385156ecf10fed1bb9db9f5d69666246de07', 'size': 41158},
    'node-forge/producer/package.json': {'sha256': '03b77ade721014a05b693fada1eff19f33d7a37e24a08d4e6ef85dac00a766c1', 'size': 98},
    'node-forge/producer/recipe.json': {'sha256': '5a7667e0364a038dd120af9be51fc824d39f0879ba6fec1b3c16ae96e22d17a8', 'size': 38865},
    'node-forge/producer/source-reference.json': {'sha256': 'd087f3dacbca028144b0a9ddc56682424f438e4b228970d0e7fcf5d51cec02cc', 'size': 1255},
    'node-forge/producer/tool-tree.json': {'sha256': '8bbdd826a8f65b4faac61cbf45b086b19cfebf576b9f99dc1c348b63e24fc9a4', 'size': 513447},
    'node-forge/producer/webpack.config.js': {'sha256': '5e70f8af959af5edf27b5a42985da607ad4047ba014a0a3da39d83973449f1dd', 'size': 3424},
    'node-forge/provenance.json': {'sha256': '7fdb284b48206b7016e11d9c798e589c301b2068c9dead697ee8996c0b5ffdc2', 'size': 4604},
    'node-forge/replacements/distribution/forge.all.js': {'sha256': '10de696dad31d6549b4c3a7c137769b669249bff881cd665e20f25b542434e66', 'size': 989544},
    'node-forge/replacements/distribution/forge.all.min.js': {'sha256': 'faa549f650a5515cfcdfbae4fde7905c37b14cb147bd11bd44b19444e02f7cbf', 'size': 304792},
    'node-forge/replacements/distribution/forge.all.min.js.map': {'sha256': '3f645f54db8efe29ed3018ddad138b5476a6cbcb39ae61bd61ef19d3d6988681', 'size': 1362789},
    'node-forge/replacements/distribution/forge.js': {'sha256': 'e36b46a7bb2a14b27a68406d8997bddbd1c1188750d185f68822d9e8a89ad5c8', 'size': 903743},
    'node-forge/replacements/distribution/forge.min.js': {'sha256': 'dbf3da77a28b8755efbf197ce803a7464a8c485a1e4a3f2b93de427fccc3f240', 'size': 283243},
    'node-forge/replacements/distribution/forge.min.js.map': {'sha256': '07206f91fb2bcb76afd8306b62075e0fa5022476beed4c74648d6e5fd0a42efc', 'size': 1248932},
    'node-forge/replacements/distribution/prime.worker.js': {'sha256': '8a7899ff13703d4098f22c288cf02540cdf3dd0a212f703736654a727961a154', 'size': 46606},
    'node-forge/replacements/distribution/prime.worker.min.js': {'sha256': '067f3b94bb7fca9c62bdc960fc5da01b7a22dfaafd972b6c369c078964859102', 'size': 20642},
    'node-forge/replacements/distribution/prime.worker.min.js.map': {'sha256': 'bb2d57a0e0b5490be2e0e40de9fbe838cf6ac33a07272b5b55217494225129fc', 'size': 77109},
    'node-forge/replacements/package.json': {'sha256': '25f2f15bf20a6f22cb33ea7f1513c8f2ffad9864ed0676f69fc559ee4e8e80e3', 'size': 1587},
    'node-forge/replacements/source/lib/rsa.js': {'sha256': 'c7b72e7ef41f4fc0e5228dce3e37851e9ca064c789365d5e392c25d1c5f6e710', 'size': 64490},
    'node-forge/source.patch': {'sha256': '37b89ad5884509ccd246b120bf6ad185eaf8963da91769b7781de111c4a4bb92', 'size': 4801},
}
FORGE_UPSTREAM = {'sha256': 'bf9d7ca0d774235354697bd4b5e642af6505e7ce2066762c3b855138cf870820', 'size': 435334}
FORGE_SCRIPT = {'path': 'scripts/dependencies/build-forge.py', 'sha256': '4938da059001bae6176ea52c49cd3aa38ad5c3c03f0049646f1bc36ef726a069', 'size': 3350}
FORGE_OUTPUT_NAMES = ('forge.all.js', 'forge.all.min.js', 'forge.all.min.js.map', 'forge.js', 'forge.min.js', 'forge.min.js.map', 'prime.worker.js', 'prime.worker.min.js', 'prime.worker.min.js.map')
ERROR = 'backport verification failed'


class BackportError(ValueError):
    """Fixed public failure; do not expose local paths or input values."""


def require(condition):
    if not condition:
        raise BackportError(ERROR)


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected.split()))


def path_name(value, prefix=None):
    require(type(value) is str and bool(value) and '\\' not in value)
    parts = PurePosixPath(value).parts
    require('/'.join(parts) == value and all(p not in ('', '.', '..') for p in parts))
    require(not value.startswith('/') and (prefix is None or value.startswith(prefix + '/')))
    require(all(re.fullmatch(r'[A-Za-z0-9_@.+-]+', part) for part in parts))
    return value


def digest(data):
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}


def integrity(data):
    return 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode('ascii')


def hash_record(value, with_sri=False):
    require(type(value) is dict and type(value.get('size')) is int and 0 <= value['size'] <= MAX_EXPANDED)
    require(type(value.get('sha256')) is str and re.fullmatch(r'[0-9a-f]{64}', value['sha256']) is not None)
    if with_sri:
        sri = value.get('integrity')
        require(type(sri) is str and sri.startswith('sha512-'))
        try:
            decoded = base64.b64decode(sri[7:], validate=True)
        except (ValueError, binascii.Error):
            raise BackportError(ERROR) from None
        require(len(decoded) == 64 and base64.b64encode(decoded).decode('ascii') == sri[7:])


def checked_read(root, name, expected, cap=MAX_EXPANDED):
    path_name(name)
    target = root / name
    # Every component must be an ordinary directory/file in the retained input tree.
    require(root.is_dir() and not root.is_symlink())
    current = root
    for part in PurePosixPath(name).parts:
        current = current / part
        require(not current.is_symlink())
    require(target.is_file() and target.stat().st_size <= cap)
    data = target.read_bytes()
    require(digest(data) == {key: expected[key] for key in ('sha256', 'size')})
    if 'integrity' in expected:
        require(integrity(data) == expected['integrity'])
    return data


def json_data(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def validate_record(record):
    keys(record, 'id upstream fork inputs replacements result_files archive provenance')
    ident = record['id']
    require(type(ident) is str and ident in IDENTITIES)
    prefix = PREFIXES[ident]
    version = IDENTITIES[ident][0]
    up = record['upstream']
    keys(up, 'name version url path sha256 integrity size')
    require(up['name'] == ident and up['version'] == version)
    require(up['url'] == f'https://registry.npmjs.org/{ident}/-/{ident}-{version}.tgz')
    require(up['path'] == f'{prefix}/upstream.tgz')
    hash_record(up, True)
    require(up['size'] <= MAX_ARCHIVE)
    keys(record['fork'], 'name version')
    require(record['fork'] == {'name': '@appguard/' + ident, 'version': version + '-appguard.1'})
    archive = record['archive']
    keys(archive, 'path sha256 integrity size')
    require(archive['path'] == f'archives/appguard-{ident}-{version}-appguard.1.tgz')
    hash_record(archive, True)
    require(archive['size'] <= MAX_ARCHIVE)
    inputs = record['inputs']
    require(type(inputs) is dict and 1 <= len(inputs) <= MAX_FILES)
    for name, value in inputs.items():
        path_name(name, prefix)
        require(not any(part in {'build', 'dist', 'vendor', 'artifacts'} for part in PurePosixPath(name).parts))
        keys(value, 'sha256 size')
        hash_record(value)
    require(sum(value['size'] for value in inputs.values()) <= MAX_EXPANDED)
    require(record['provenance'] == prefix + '/provenance.json' and record['provenance'] in inputs)
    for required in ('original-package.json', 'LICENSE', 'source.patch', 'replacements/package.json'):
        require(prefix + '/' + required in inputs)
    replacements = record['replacements']
    require(type(replacements) is list and 1 <= len(replacements) <= MAX_FILES)
    names = set()
    for entry in replacements:
        keys(entry, 'path input')
        path_name(entry['path'], 'package')
        # The full original license is immutable, including after replacements.
        require(entry['path'] != 'package/LICENSE' or
                (ident == 'resolve-workspace-root' and entry['input'] == 'resolver/LICENSE'))
        require(entry['path'] not in names and entry['input'] in inputs)
        names.add(entry['path'])
    require('package/package.json' in names)
    results = record['result_files']
    require(type(results) is dict and 1 <= len(results) <= MAX_FILES)
    for name, value in results.items():
        path_name(name, 'package')
        keys(value, 'sha256 size')
        hash_record(value)
    require(sum(value['size'] for value in results.values()) <= MAX_EXPANDED)
    if ident == 'node-forge':
        # Exact retained producer extension, not an exception for unbound inputs.
        require(inputs == FORGE_INPUTS)
        require({key: up[key] for key in ('sha256', 'size')} == FORGE_UPSTREAM)
    if ident == 'resolve-workspace-root':
        require(set(inputs) == set(RESOLVER_SOURCES) | set(RESOLVER_OUTPUTS) | {
            'resolver/' + name for name in ('LICENSE', 'original-package.json', 'original-index.d.ts',
                'original-readme.md', 'upstream-capture.json', 'provenance.json', 'source.patch',
                'replacements/package.json', 'recipe.json', 'runtime-dependencies.json',
                'dependency-metadata-readback.json', 'bounded-advisory-readback.json',
                'compiler/package.json', 'compiler/LICENSE.txt', 'compiler/lock-record.json')})
        require({key: up[key] for key in ('sha256', 'size')} == {
            'sha256': '161fd5f13b2fc116b4332c25bb1d4983a2f983b15e01d647d5ac1209fd309694', 'size': 31755})
        for name, pin in {**RESOLVER_SOURCES, **RESOLVER_OUTPUTS, 'resolver/LICENSE': RESOLVER_LICENSE,
            'resolver/original-package.json': {'sha256': '2a4dd519ada0fb79a87f4de720961be61cd906ee3c91dbf17dcc82bd31236ade', 'size': 1572},
            'resolver/original-index.d.ts': {'sha256': '4e5e42c6632ef9e9859a8d22b4c71572c2a19f8088a84ccaeab7f2f0a30a623e', 'size': 2773}}.items():
            require(inputs.get(name) == pin)
        expected = {'package/package.json': 'resolver/replacements/package.json', 'package/LICENSE': 'resolver/LICENSE',
                    **{'package/build/' + output.removeprefix('resolver/compiled/'): output for output in RESOLVER_MAPPING.values()}}
        require(record['replacements'] == [{'path': name, 'input': value} for name, value in sorted(expected.items())])
        require(set(results) == {'package/package.json', 'package/LICENSE', 'package/LICENSE.md', 'package/README.md',
            'package/build/index.d.ts', *[name for name in expected if name.startswith('package/build/')]})
        require(results['package/LICENSE'] == results['package/LICENSE.md'] == RESOLVER_LICENSE)


def validate_manifest(manifest):
    keys(manifest, 'schema packages')
    require(type(manifest['schema']) is int and manifest['schema'] == 1)
    require(type(manifest['packages']) is list and len(manifest['packages']) == 3)
    require([p.get('id') if type(p) is dict else None for p in manifest['packages']] == list(IDENTITIES))
    for record in manifest['packages']:
        validate_record(record)


def public_guard(function):
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, tarfile.TarError, EOFError, struct.error, zlib.error):
            raise BackportError(ERROR) from None
    return guarded


@public_guard
def load_manifest(root: Path) -> dict:
    root = Path(root)
    target = root / 'manifest.json'
    require(not target.is_symlink() and target.stat().st_size <= 2 * 1024 * 1024)
    manifest = json_data(target.read_bytes())
    validate_manifest(manifest)
    return manifest


def upstream_files(data):
    # Bound decompression before tar parsing; never extract onto the filesystem.
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        expanded = compressed.read(MAX_EXPANDED + 1)
    require(len(expanded) <= MAX_EXPANDED)
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        count = 0
        for entry in archive:
            count += 1
            require(count <= MAX_FILES)
            path_name(entry.name, 'package')
            require(entry.isfile() and entry.name not in files and not entry.pax_headers)
            require(type(entry.size) is int and 0 <= entry.size <= MAX_EXPANDED)
            total += entry.size
            require(total <= MAX_EXPANDED)
            stream = archive.extractfile(entry)
            require(stream is not None)
            content = stream.read(entry.size + 1)
            require(len(content) == entry.size)
            files[entry.name] = content
    require(bool(files))
    return files


def validate_metadata(record, files, inputs):
    ident = record['id']
    prefix = PREFIXES[ident]
    original_bytes = inputs[prefix + '/original-package.json']
    original = json_data(original_bytes)
    require(original_bytes == files['package/package.json'])
    require(original['name'] == ident and original['version'] == record['upstream']['version'])
    license_name = 'package/LICENSE.md' if ident == 'resolve-workspace-root' else 'package/LICENSE'
    require(inputs[prefix + '/LICENSE'] == files[license_name])
    modified = json_data(inputs[prefix + '/replacements/package.json'])
    expected = dict(original)
    expected.update(record['fork'])
    expected['private'] = True
    expected.pop('scripts', None)
    expected.pop('devDependencies', None)
    expected['engines'] = dict(original.get('engines', {}), node='>=22.13.0')
    if ident == 'resolve-workspace-root':
        expected['files'] = ['build']
        expected['dependencies'] = RESOLVER_DEPENDENCIES
    require(type(modified) is dict and modified.get('private') is True)
    require(json.dumps(modified, sort_keys=True) == json.dumps(expected, sort_keys=True))
    replacement = [entry for entry in record['replacements'] if entry['path'] == 'package/package.json']
    require(replacement == [{'path': 'package/package.json', 'input': prefix + '/replacements/package.json'}])
    provenance = json_data(inputs[record['provenance']])
    require(type(provenance) is dict)
    require(provenance.get('upstream') == {'name': ident, 'version': record['upstream']['version']})
    require(provenance.get('license') == IDENTITIES[ident][1])
    changes = {key: {'before': original.get(key), 'after': modified.get(key)}
               for key in set(original) | set(modified) if original.get(key) != modified.get(key)}
    require(json.dumps(provenance.get('metadata_changes'), sort_keys=True) == json.dumps(changes, sort_keys=True))
    if ident == 'node-forge':
        require(provenance.get('compilation_reproduction_verified') is False)
        require(provenance.get('producer_closure_verified') is False)
    if ident == 'resolve-workspace-root':
        require(inputs['resolver/original-index.d.ts'] == files['package/build/index.d.ts'])
        require(inputs['resolver/original-readme.md'] == files['package/README.md'])
        require(provenance.get('publisher_git_head') == '72f675ae9ea952e832c63f1138346406b0d8630b')
        require(provenance.get('canonical_patch_sha256') == digest(inputs['resolver/source.patch'])['sha256'])
        for flag in ('compilation_reproduction_verified', 'producer_closure_verified', 'source_gate_passed', 'release_ready'):
            require(provenance.get(flag) is False)


def validate_resolver_recipe(root, record, inputs):
    recipe = json_data(inputs['resolver/recipe.json'])
    keys(recipe, 'schema script compiler options sources outputs mapping producer_observation')
    require(recipe['schema'] == 1 and recipe['sources'] == RESOLVER_SOURCES and recipe['mapping'] == RESOLVER_MAPPING)
    require(recipe['options'] == {'module': 'CommonJS', 'target': 'ES2020', 'esModuleInterop': True})
    keys(recipe['script'], 'path sha256 size')
    require(recipe['script'] == RESOLVER_SCRIPT)
    hash_record(recipe['script'])
    checked_read(root.parents[1], recipe['script']['path'], recipe['script'])
    require(recipe['outputs'] == RESOLVER_OUTPUTS)
    for name, pin in recipe['outputs'].items():
        require(record['inputs'].get(name) == pin)
        require(record['result_files'].get('package/build/' + name.removeprefix('resolver/compiled/')) == pin)
    compiler = recipe['compiler']
    keys(compiler, 'name version integrity files')
    require(compiler['name'] == 'typescript' and compiler['version'] == '6.0.3')
    require(compiler['integrity'] == 'sha512-y2TvuxSZPDyQakkFRPZHKFm+KKVqIisdg9/CZwm9ftvKXLP8NRWj38/ODjNbr43SsoXqNuAisEf1GdCxqWcdBw==')
    require(compiler['files'] == {
        'package.json': {'sha256': '9332e97c30d3e53ed54910b89207ed657fb444066484df6e5b6965bf130865e9', 'size': 3527},
        'lib/typescript.js': {'sha256': '569177652966bd528c319171c7dd22860dbf72bde116cbc4f644f1d02bb12e39', 'size': 9144216},
        'LICENSE.txt': {'sha256': 'a7d00bfd54525bc694b6e32f64c7ebcf5e6b7ae3657be5cc12767bce74654a47', 'size': 9197}})
    for name in ('package.json', 'LICENSE.txt'):
        require(digest(inputs['resolver/compiler/' + name]) == compiler['files'][name])
    locked = json_data(inputs['resolver/compiler/lock-record.json'])
    require(locked['version'] == compiler['version'] and locked['integrity'] == compiler['integrity'])
    require(locked['resolved'] == 'https://registry.npmjs.org/typescript/-/typescript-6.0.3.tgz')


@public_guard
def forge_recipe(root, record):
    """Verify public retained recipe and reconstruct source bytes without execution."""
    root = Path(root)
    validate_record(record)
    require(record['id'] == 'node-forge')
    inputs = {name: checked_read(root, name, pin) for name, pin in record['inputs'].items()}
    producer = root / 'node-forge/producer'
    require({path.relative_to(root).as_posix() for path in producer.rglob('*') if path.is_file() or path.is_symlink()} ==
            {name for name in FORGE_INPUTS if name.startswith('node-forge/producer/')})
    recipe = json_data(inputs['node-forge/producer/recipe.json'])
    keys(recipe, 'schema runtime preparation_script compiler_script source_reference source_archive '
         'rsa_replacement sources tools outputs maps compiler_warnings observation')
    require(recipe['schema'] == 1 and recipe['runtime'] == {'node': '22.23.2', 'npm': '10.9.8'})
    require(recipe['preparation_script'] == FORGE_SCRIPT)
    checked_read(root.parents[1], FORGE_SCRIPT['path'], FORGE_SCRIPT)
    require(recipe['compiler_script'] == 'node-forge/producer/build.cjs')
    require(recipe['source_reference'] == 'node-forge/producer/source-reference.json')
    require(recipe['source_archive'] == record['upstream'])
    require(recipe['rsa_replacement'] == 'node-forge/replacements/source/lib/rsa.js')
    upstream = upstream_files(checked_read(root, record['upstream']['path'], record['upstream'], MAX_ARCHIVE))
    validate_metadata(record, upstream, inputs)
    sources = {name.removeprefix('package/'): data for name, data in upstream.items() if name.startswith('package/lib/')}
    require(len(sources) == 49)
    sources['lib/rsa.js'] = inputs[recipe['rsa_replacement']]
    sources.update({'package.json': upstream['package/package.json'], 'LICENSE': upstream['package/LICENSE'],
                    'webpack.config.js': inputs['node-forge/producer/webpack.config.js']})
    require(recipe['sources'] == {name: digest(data) for name, data in sources.items()})
    require(json_data(sources['package.json'])['name'] == 'node-forge')
    reference = json_data(inputs[recipe['source_reference']])
    require(reference['official_webpack_config'] == digest(sources['webpack.config.js']))
    require(reference['published_source_archive'] == record['upstream'])
    require(reference['lib_source_count'] == 49 and reference['publisher_build_reproduced'] is False)
    lock = json_data(inputs['node-forge/producer/package-lock.json'])
    require(lock['lockfileVersion'] == 3 and len(lock['packages']) == 86)
    package = json_data(inputs['node-forge/producer/package.json'])
    require(package == {'private': True, 'devDependencies': {'webpack': '5.112.1', 'mocha': '12.0.3'}})
    require(lock['packages']['']['devDependencies'] == package['devDependencies'])
    require(recipe['tools'] == {'package': 'node-forge/producer/package.json',
        'lock': 'node-forge/producer/package-lock.json', 'tree': 'node-forge/producer/tool-tree.json',
        'package_records': 86, 'versions': {'webpack': '5.112.1', 'mocha': '12.0.3',
            'minimizer-webpack-plugin': '5.13.1', 'terser': '5.51.2', 'acorn': '8.19.0', 'webpack-sources': '3.6.0'}})
    tree = json_data(inputs['node-forge/producer/tool-tree.json'])
    keys(tree, 'schema expected_archive_files package_records files_sha256 symlinks')
    require(tree['schema'] == 1 and tree['package_records'] == 85 and tree['expected_archive_files'] == 4018)
    require(len(tree['files_sha256']) == 4021 and len(tree['symlinks']) == 9)
    for name, row in lock['packages'].items():
        if not name:
            continue
        path_name(name, 'node_modules')
        logical = name.rsplit('node_modules/', 1)[-1]
        require(logical not in {'braces', 'micromatch', 'node-forge', 'resolve-workspace-root'})
        require(name + '/package.json' in tree['files_sha256'])
        require(row['resolved'] == 'https://registry.npmjs.org/' + logical + '/-/' +
                logical.rsplit('/', 1)[-1] + '-' + row['version'] + '.tgz')
        hash_record(dict(size=0, sha256='0' * 64, integrity=row['integrity']), True)
    for name in ('package.json', 'package-lock.json'):
        require(tree['files_sha256'][name] == FORGE_INPUTS['node-forge/producer/' + name]['sha256'])
    for name, version in recipe['tools']['versions'].items():
        require(lock['packages']['node_modules/' + name]['version'] == version)
    distribution = json_data(inputs['node-forge/distribution-record.json'])
    require(recipe['outputs'] == {name.removeprefix('dist/'): pin for name, pin in distribution['outputs'].items()})
    require(set(recipe['outputs']) == set(FORGE_OUTPUT_NAMES))
    for name, pin in recipe['outputs'].items():
        require(record['result_files']['package/dist/' + name] == pin)
        require(record['inputs']['node-forge/replacements/distribution/' + name] == pin)
    require(recipe['observation'] == {'recipe_retained': True, **{flag: False for flag in
        ('fresh_install_verified', 'compilation_reproduction_verified', 'producer_closure_verified',
         'publisher_build_reproduced', 'source_gate_passed', 'release_ready')}})
    forge_map_checks(root, recipe)
    return recipe, sources


def forge_map_checks(root, recipe, output=None):
    """Data-only normal source-map/source/generator joins; no bundle execution."""
    tree = json_data((Path(root) / 'node-forge/producer/tool-tree.json').read_bytes())
    require([row['filename'] for row in recipe['maps']] == ['forge.min.js', 'forge.all.min.js', 'prime.worker.min.js'])
    for expected in recipe['maps']:
        filename = expected['filename']
        target = (Path(output) / (filename + '.map') if output is not None else
                  Path(root) / 'node-forge/replacements/distribution' / (filename + '.map'))
        pin = recipe['outputs'][filename + '.map']
        require(not target.is_symlink() and digest(target.read_bytes()) == pin)
        mapping = json_data(target.read_bytes())
        require(mapping['version'] == 3 and mapping['file'] == filename and mapping.get('sourceRoot', '') == '')
        require(mapping['sources'] == [entry['source'] for entry in expected['entries']])
        require(len(mapping['sourcesContent']) == expected['entry_count'] == len(expected['entries']))
        for index, entry in enumerate(expected['entries']):
            content = mapping['sourcesContent'][index]
            require(type(content) is str and entry['source'].startswith('webpack://node-forge/'))
            require(digest(content.encode('utf-8'))['sha256'] == entry['sha256'])
            if entry['classification'] == 'source_inventory':
                require(recipe['sources'][entry['inventory_path']]['sha256'] == entry['sha256'])
            else:
                require(entry['classification'] in ('webpack_generated', 'webpack_ignored'))
                require(tree['files_sha256']['node_modules/' + entry['generator_file']] == entry['generator_sha256'])
        require(expected['external_module_count'] == expected['unknown_entry_count'] == 0)
        require(expected['source_inventory_entries_hash_matched'] is True)


@public_guard
def compare_forge_tree(root, expected_files, expected_links):
    """Compare every file and only the historically recorded internal bin aliases."""
    root = Path(root).absolute()
    require(root.is_dir() and not root.is_symlink())
    actual_files, actual_links = {}, {}
    def visit(directory):
        for target in directory.iterdir():
            name = target.relative_to(root).as_posix()
            if target.is_symlink():
                resolved = target.resolve(strict=True)
                require(resolved.is_relative_to(root) and resolved.is_file() and not resolved.is_symlink())
                actual_links[name] = {'target': os.readlink(target),
                                      'resolved_file_sha256': digest(resolved.read_bytes())['sha256']}
            elif target.is_dir():
                visit(target)
            else:
                require(target.is_file() and target.stat().st_size <= MAX_EXPANDED)
                actual_files[name] = digest(target.read_bytes())['sha256']
    visit(root)
    require(actual_files == expected_files and actual_links == expected_links)


@public_guard
def forge_new_parent(output):
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink())
    parent = output.parent
    stat = parent.stat()
    require(parent.is_dir() and not parent.is_symlink() and parent.resolve() == parent)
    require(stat.st_uid == os.getuid() and stat.st_mode & 0o022 == 0)


@public_guard
def prepare_forge(root, record, output):
    recipe, sources = forge_recipe(root, record)
    output = Path(output).absolute()
    forge_new_parent(output)
    require(not output.is_relative_to(Path(root).absolute()))
    payloads = {'source/' + name: data for name, data in sources.items()}
    for name in ('package.json', 'package-lock.json'):
        retained = 'node-forge/producer/' + name
        payloads['producer/' + name] = checked_read(Path(root), retained, record['inputs'][retained])
    output.mkdir(mode=0o700)
    for name, data in sorted(payloads.items()):
        target = output / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(0o600)
    verify_forge_prepared(root, record, output)
    return {'verified': True, 'source_files': 52, 'producer_package_records': 86, 'compiler_executed': False,
            'compilation_reproduction_verified': False, 'producer_closure_verified': False, 'release_ready': False}


@public_guard
def verify_forge_prepared(root, record, prepared):
    recipe, sources = forge_recipe(root, record)
    prepared = Path(prepared).absolute()
    require(prepared.is_dir() and not prepared.is_symlink())
    compare_forge_tree(prepared / 'source', {name: pin['sha256'] for name, pin in recipe['sources'].items()}, {})
    for name in ('package.json', 'package-lock.json'):
        checked_read(prepared / 'producer', name, FORGE_INPUTS['node-forge/producer/' + name])
    return sources


@public_guard
def verify_forge_tools(root, record, prepared):
    verify_forge_prepared(root, record, prepared)
    tree = json_data(checked_read(Path(root), 'node-forge/producer/tool-tree.json', FORGE_INPUTS['node-forge/producer/tool-tree.json']))
    producer = Path(prepared).absolute() / 'producer'
    compare_forge_tree(producer, tree['files_sha256'], tree['symlinks'])
    lock = json_data((producer / 'package-lock.json').read_bytes())
    hidden = json_data((producer / 'node_modules/.package-lock.json').read_bytes())
    require(set(hidden['packages']) == set(lock['packages']) - {''})
    for name, row in hidden['packages'].items():
        expected = lock['packages'][name]
        require(all(row[key] == expected[key] for key in ('version', 'resolved', 'integrity')))
        metadata = json_data((producer / name / 'package.json').read_bytes())
        require(metadata['name'] == name.rsplit('node_modules/', 1)[-1] and metadata['version'] == expected['version'])
    return {'verified': True, 'producer_package_records': 86, 'regular_tool_files': 4021, 'internal_tool_aliases': 9,
            'compiler_executed': False, 'fresh_install_verified': False, 'release_ready': False}


@public_guard
def check_forge_outputs(root, record, output, with_receipts=False):
    recipe, unused_source = forge_recipe(root, record)
    output = Path(output)
    require(output.is_dir() and not output.is_symlink())
    expected = set(recipe['outputs'])
    if with_receipts:
        expected |= {name + '.compiler.json' for name in FORGE_OUTPUT_NAMES if name.endswith('.js')}
        expected.add('compilation-receipt.json')
    require({target.name for target in output.iterdir()} == expected)
    for name, pin in recipe['outputs'].items():
        checked_read(output, name, pin)
    forge_map_checks(root, recipe, output)
    if with_receipts:
        receipt = json_data((output / 'compilation-receipt.json').read_bytes())
        require(receipt['outputs'] == 9 and receipt['independent_output_hashes_matched'] is True)
        require(receipt['es5_syntax_and_literal_eval_parsed'] is True)
        require(receipt['compiler_warnings'] == recipe['compiler_warnings'])
        require(all(receipt[flag] is False for flag in ('publisher_build_reproduced',
            'consumer_adoption_verified', 'source_gate_passed', 'legal_approved', 'release_ready')))
    return {'verified': True, 'outputs': 9, 'compilation_reproduction_verified': False,
            'producer_closure_verified': False, 'publisher_build_reproduced': False, 'release_ready': False}


def stored_gzip(data):
    result = bytearray(bytes.fromhex('1f8b08000000000000ff'))
    for start in range(0, len(data), 65535):
        block = data[start:start + 65535]
        result += bytes([int(start + len(block) == len(data))])
        result += struct.pack('<HH', len(block), len(block) ^ 0xffff)
        result += block
    if not data:
        result += b'\x01\x00\x00\xff\xff'
    result += struct.pack('<II', zlib.crc32(data), len(data) & 0xffffffff)
    return bytes(result)


@public_guard
def assemble_package(root: Path, record: dict) -> bytes:
    root = Path(root)
    validate_record(record)
    upstream = checked_read(root, record['upstream']['path'], record['upstream'], MAX_ARCHIVE)
    files = upstream_files(upstream)
    inputs = {name: checked_read(root, name, expected) for name, expected in record['inputs'].items()}
    validate_metadata(record, files, inputs)
    if record['id'] == 'resolve-workspace-root':
        validate_resolver_recipe(root, record, inputs)
    if record['id'] == 'node-forge':
        forge_recipe(root, record)
    for replacement in record['replacements']:
        files[replacement['path']] = inputs[replacement['input']]
    if record['id'] == 'resolve-workspace-root':
        require(files['package/LICENSE'] == files['package/LICENSE.md'] == inputs['resolver/LICENSE'])
    require({name: digest(content) for name, content in files.items()} == record['result_files'])
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, content in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(content), 0o644
            entry.uid = entry.gid = entry.mtime = 0
            entry.uname = entry.gname = ''
            archive.addfile(entry, io.BytesIO(content))
    result = stored_gzip(stream.getvalue())
    require(len(result) <= MAX_ARCHIVE)
    return result


def assembled(root, manifest):
    validate_manifest(manifest)
    result = []
    for record in manifest['packages']:
        data = assemble_package(root, record)
        expected = record['archive']
        require(digest(data) == {key: expected[key] for key in ('sha256', 'size')})
        require(integrity(data) == expected['integrity'])
        result.append((record, data))
    return result


def summary(values):
    return {'verified': True, 'packages': [dict(id=record['id'], files=len(record['result_files']),
            sha256=digest(data)['sha256'], integrity=integrity(data), size=len(data)) for record, data in values],
            'compilation_reproduction_verified': False, 'producer_closure_verified': False,
            'consumer_adoption_verified': False, 'source_gate_passed': False, 'release_ready': False}


@public_guard
def check_archives(root: Path, manifest: dict) -> dict:
    root = Path(root)
    values = assembled(root, manifest)
    for record, data in values:
        require(checked_read(root, record['archive']['path'], record['archive'], MAX_ARCHIVE) == data)
    return summary(values)


@public_guard
def write_archives(root: Path, manifest: dict, output: Path) -> dict:
    values = assembled(Path(root), manifest)
    output = Path(output)
    # mkdir(exist_ok=False) is the no-overwrite boundary, including empty directories.
    output.mkdir(mode=0o700, exist_ok=False)
    output.chmod(0o700)
    for record, data in values:
        target = output / PurePosixPath(record['archive']['path']).name
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(0o600)
    return summary(values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true')
    group.add_argument('--output', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2] / 'tools/dependency-backports'
    try:
        manifest = load_manifest(root)
        result = check_archives(root, manifest) if args.check else write_archives(root, manifest, args.output)
    except BackportError:
        print(json.dumps({'verified': False, 'error': ERROR}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
