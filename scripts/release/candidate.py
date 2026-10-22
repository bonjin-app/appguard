#!/usr/bin/env python3
"""Create a deterministic, unpublished source candidate from clean Git HEAD."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile

ROOT_FILES = {'LICENSE', 'NOTICE', 'SECURITY.md', 'CONTRIBUTING.md', '.gitignore'}
ROOT_DIRS = {'sdk', 'reference', 'scripts', 'tools', 'docs', 'conformance', 'protocol', 'examples', '.github'}
EXCLUDED_PARTS = {'.git', '.tools', '.evidence', '.artifacts', '.venv', 'venv', 'node_modules', '__pycache__',
                  '.pytest_cache', '.gradle', '.build', 'build', 'dist', 'target',
                  'bin', 'obj', 'vendor', 'private', 'artifacts', '.idea', '.vscode'}
# CLI bin/ is source, explicitly permitted below. Other bin/ outputs are excluded.
PRIVATE_SUFFIXES = {'.keystore', '.jks', '.p12', '.pfx', '.p8', '.key', '.mobileprovision'}
INPUT_NAMES = {'package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'pyproject.toml',
               'uv.lock', 'requirements.txt', 'go.mod', 'go.sum', 'pom.xml', 'packages.lock.json',
               'composer.json', 'composer.lock', 'Package.swift', 'Package.resolved',
               'pubspec.yaml', 'pubspec.lock', 'build.gradle', 'build.gradle.kts',
               'settings.gradle', 'settings.gradle.kts', 'libs.versions.toml', 'gradle-wrapper.properties'}


def git(repo, *args):
    return subprocess.check_output(['git', '--no-replace-objects', '-C', str(repo), *args], stderr=subprocess.PIPE)


def validate_path(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or '\\' in name or '\x00' in name
            or any(p in {'', '.', '..'} for p in name.split('/'))):
        raise ValueError('Unsafe source path: ' + repr(name))
    return path


def allowed(name):
    path = validate_path(name)
    parts = path.parts
    if len(parts) == 1:
        return name in ROOT_FILES or (name.startswith('README') and name.endswith('.md'))
    if parts[0] not in ROOT_DIRS:
        return False
    for index, part in enumerate(parts):
        if part in EXCLUDED_PARTS and not (part == 'bin' and parts[:index] == ('tools', 'cli')):
            return False
    if any(p.startswith('.env') for p in parts) or path.suffix.lower() in PRIVATE_SUFFIXES:
        return False
    if any(token in path.name.lower() for token in ('private-key', 'private_key', 'credentials', 'id_rsa', 'id_ed25519')):
        return False
    return True


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def write_archive(source, destination, files):
    with destination.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for name, mode in files:
                data = (source / name).read_bytes()
                info = tarfile.TarInfo('appguard/' + name)
                info.size = len(data)
                info.mode = mode
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                archive.addfile(info, io.BytesIO(data))


def assert_clean(repo, commit):
    if git(repo, 'rev-parse', 'HEAD').decode().strip() != commit:
        raise RuntimeError('HEAD changed while creating the candidate')
    if git(repo, 'status', '--porcelain=v1', '--untracked-files=all'):
        raise RuntimeError('Candidate requires clean tracked and untracked Git state; commit or isolate changes first')


def coverage(files):
    inputs = []
    for name, _ in files:
        path = PurePosixPath(name)
        if path.name in INPUT_NAMES or path.suffix in {'.csproj', '.podspec', '.nuspec'}:
            inputs.append({'path': name, 'kind': 'lockfile' if path.name in {
                'package-lock.json', 'npm-shrinkwrap.json', 'uv.lock', 'go.sum',
                'packages.lock.json', 'composer.lock', 'Package.resolved', 'pubspec.lock'} else 'manifest'})
    projects = []
    for item in inputs:
        if item['kind'] == 'manifest':
            locks = [other['path'] for other in inputs if other['kind'] == 'lockfile' and
                     PurePosixPath(other['path']).parent == PurePosixPath(item['path']).parent]
            projects.append({'manifest': item['path'], 'recorded_lockfiles': locks,
                             'resolution_coverage': 'lockfile_recorded_not_runtime_verified' if locks else 'no_recorded_lockfile'})
    return {'schema': 1, 'projects': projects, 'complete_resolved_graph': False,
            'scope': 'All recognized manifests and lockfiles in the allowlisted tracked source; no dependency resolution performed',
            'inputs': inputs,
            'limitations': ['Syft cataloging must run separately; this inventory is not an SBOM.',
                            'Lockfiles describe recorded resolution, not proof of installed or bundled artifacts.',
                            'Swift, Gradle/Android, Flutter, Unity and native dependencies may require platform-specific resolution.',
                            'Build outputs, vendored code, toolchains and private material are excluded; inspect excluded paths in manifest.json.',
                            'No physical device, external security audit, registry publication or maintainer approval is implied.']}


def create_candidate(repo, output):
    repo = Path(repo).resolve(strict=True)
    output = Path(os.path.abspath(output))
    if output != output.resolve():
        raise ValueError('Output and its parents must not use symlinks')
    if output == repo or repo in output.parents:
        raise ValueError('Output must be outside the repository')
    if output.exists():
        raise FileExistsError('Output already exists; refusing to overwrite')
    if not output.parent.is_dir():
        raise ValueError('Output parent must already exist')
    if Path(git(repo, 'rev-parse', '--show-toplevel').decode().strip()).resolve() != repo:
        raise ValueError('--repo must be the Git repository root')
    commit = git(repo, 'rev-parse', 'HEAD').decode().strip()
    assert_clean(repo, commit)
    entries = git(repo, 'ls-tree', '-rz', '--full-tree', commit).split(b'\0')
    included, excluded = [], []
    with tempfile.TemporaryDirectory(prefix='.candidate-', dir=output.parent) as temp:
        staging = Path(temp) / 'result'
        source = staging / 'source'
        source.mkdir(parents=True)
        for entry in entries:
            if not entry:
                continue
            metadata, raw_name = entry.split(b'\t', 1)
            mode, kind, oid = metadata.decode().split()
            name = raw_name.decode('utf-8', errors='strict')
            validate_path(name)
            if not allowed(name):
                excluded.append(name)
                continue
            if kind != 'blob' or mode not in {'100644', '100755'}:
                raise ValueError('Symlink/submodule/special source is unsupported: ' + name)
            data = git(repo, 'cat-file', 'blob', oid)
            algorithm = {40: 'sha1', 64: 'sha256'}.get(len(oid))
            if algorithm is None or hashlib.new(algorithm, b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() != oid:
                raise ValueError('Git blob object identity mismatch')
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            permissions = 0o755 if mode == '100755' else 0o644
            target.chmod(permissions)
            included.append((name, permissions))
        included.sort()
        if not any(name == 'LICENSE' for name, _ in included):
            raise ValueError('Tracked root LICENSE is required')
        write_archive(source, staging / 'source.tar.gz', included)
        write_json(staging / 'dependency-coverage.json', coverage(included))
        licenses = [name for name, _ in included if PurePosixPath(name).name.upper().startswith(('LICENSE', 'NOTICE', 'COPYING'))]
        write_json(staging / 'licenses.json', {'source_license_files': licenses,
                    'dependency_license_review': 'Pending scanner results and maintainer review; source licenses do not cover dependency obligations'})
        hashes = {str(path.relative_to(staging)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in sorted(staging.rglob('*')) if path.is_file()}
        write_json(staging / 'manifest.json', {'schema': 1, 'commit': commit, 'archive_prefix': 'appguard/',
                   'excluded': sorted(excluded), 'sha256': hashes,
                   'scope': 'Unpublished source candidate; scans and build/consumer evidence are separate'})
        assert_clean(repo, commit)
        # Rename a complete directory on the same filesystem; never overwrite an existing result.
        if output.exists():
            raise FileExistsError('Output appeared during candidate creation')
        staging.rename(output)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        print(create_candidate(args.repo, args.output))
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
