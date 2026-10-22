"""Strict diagnostic readback of the fixed historical Debian package addition.

Build-time APT verification is recorded, not independently repeated by this
parser. This is never native vulnerability closure or production approval.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

SNAPSHOT = '20261022T200000Z'
DIRECT_PACKAGES = frozenset(('fontconfig', 'fonts-dejavu-core', 'libasound2t64',
    'libx11-6', 'libxext6', 'libxi6', 'libxrender1', 'libxtst6'))
SHA = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[a-z0-9][a-z0-9+.-]{0,99}\Z')
VERSION = re.compile(r'[0-9][A-Za-z0-9.+:~\-]{0,199}\Z')

# Only these owned image paths are read. No manifest value becomes a command or
# path. The live package inventory must still equal the build-time inventory.
CLOSURE_SCRIPT = r'''set -eu
export LC_ALL=C
root=/usr/share/appguard-java-runtime
printf 'CLOSURE\t1\n'
for key in lock keyring debian debian-security archives installed verification; do
  case "$key" in
    lock) file="$root/dependencies.lock";;
    keyring) file=/usr/share/keyrings/debian-archive-keyring.gpg;;
    debian|debian-security) file="$root/$key.InRelease";;
    archives) file="$root/apt-archives.tsv";;
    installed) file="$root/installed-packages.tsv";;
    verification) file="$root/verification.tsv";;
  esac
  test -f "$file" && test ! -L "$file"
  maximum=200000; test "$key" != keyring || maximum=1048576
  test "$(stat -c %s "$file")" -le "$maximum"
  hash=$(sha256sum "$file"); hash=${hash%% *}
  printf 'HASH\t%s\t%s\n' "$key" "$hash"
done
cat "$root/verification.tsv"
printf 'ARCHIVES_BEGIN\n'
cat "$root/apt-archives.tsv"
printf 'ARCHIVES_END\t%s\n' "$(wc -l < "$root/apt-archives.tsv" | tr -d ' ')"
printf 'INSTALLED_BEGIN\n'
cat "$root/installed-packages.tsv"
printf 'INSTALLED_END\t%s\n' "$(wc -l < "$root/installed-packages.tsv" | tr -d ' ')"
printf 'LIVE_BEGIN\n'
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n' |
  awk -F '\t' '$4 != "installed" {exit 1} {print "INSTALLED\t" $1 "\t" $2 "\t" $3}' | sort
printf 'LIVE_END\t%s\n' "$(dpkg-query -W -f='${Package}\n' | wc -l | tr -d ' ')"
printf 'END\n'
'''


def require(value):
    if not value: raise ValueError('java_dependency_closure_unverified')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_lock():
    path = Path(__file__).with_name('java-runtime-dependencies.lock')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 16384)
        with os.fdopen(os.dup(descriptor), 'rb') as stream: raw = stream.read(16385)
        after = os.fstat(descriptor); current = path.stat(follow_symlinks=False)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            and (after.st_dev, after.st_ino) == (current.st_dev, current.st_ino))
        parse_lock(raw)
        return raw
    finally: os.close(descriptor)


def lines(raw, limit):
    require(type(raw) is bytes and 0 < len(raw) <= limit and raw.endswith(b'\n') and b'\x00' not in raw)
    text = raw.decode('ascii')
    require('\r' not in text)
    result = text.splitlines()
    require(len(result) <= 2000 and all(len(row) <= 1024 for row in result))
    return result


def identity(name, version, architecture, selected):
    require(NAME.fullmatch(name) and VERSION.fullmatch(version) and architecture in (selected, 'all'))
    return name, version, architecture


def parse_lock(raw):
    rows = lines(raw, 16384)
    require(len(rows) == 21 and rows[:2] == ['APPGUARD_JAVA_RUNTIME_LOCK\t1', 'SNAPSHOT\t' + SNAPSHOT]
        and rows[-1] == 'END\t16')
    releases = {}
    for row, expected in zip(rows[2:4], (('debian', 'trixie'), ('debian-security', 'trixie-security'))):
        fields = row.split('\t')
        require(len(fields) == 4 and fields[:3] == ['RELEASE', *expected] and SHA.fullmatch(fields[3]))
        releases[fields[1]] = fields[3]
    packages = {'amd64': [], 'arm64': []}
    seen = set()
    for row in rows[4:-1]:
        fields = row.split('\t')
        require(len(fields) == 7 and fields[0] == 'PACKAGE' and fields[1] in packages)
        _, selected, name, version, architecture, digest, size = fields
        identity(name, version, architecture, selected)
        require(name in DIRECT_PACKAGES and (selected, name) not in seen and SHA.fullmatch(digest)
            and re.fullmatch(r'[1-9][0-9]{0,7}', size) and int(size) <= 20000000
            and architecture == ('all' if name == 'fonts-dejavu-core' else selected))
        seen.add((selected, name))
        packages[selected].append(dict(name=name, version=version, architecture=architecture, sha256=digest, size=int(size)))
    require(all({row['name'] for row in group} == DIRECT_PACKAGES for group in packages.values()))
    common = [next(row for row in packages[arch] if row['name'] == 'fonts-dejavu-core') for arch in packages]
    require(common[0] == common[1])
    return dict(schema=1, snapshot=SNAPSHOT, releases=releases, packages=packages)


def package_set(packages, selected):
    require(type(packages) is list and 0 < len(packages) <= 512)
    result = {}
    for row in packages:
        name = row['name'].split(':')
        require(len(name) <= 2 and (len(name) == 1 or name[1] == row['architecture']))
        identity(name[0], row['version'], row['architecture'], selected)
        key = (name[0], row['architecture'])
        require(key not in result)
        result[key] = row['version']
    return result


def parse_closure(raw, lock_raw, selected, live_packages):
    try: return _parse_closure(raw, lock_raw, selected, live_packages)
    except (IndexError, KeyError, TypeError, UnicodeError):
        raise ValueError('java_dependency_closure_unverified') from None


def _parse_closure(raw, lock_raw, selected, live_packages):
    require(selected in ('amd64', 'arm64') and type(raw) is str)
    lock = parse_lock(lock_raw)
    rows = lines(raw.encode('ascii'), 262144)
    require(rows.pop(0) == 'CLOSURE\t1')
    hashes = {}
    for key in ('lock', 'keyring', 'debian', 'debian-security', 'archives', 'installed', 'verification'):
        fields = rows.pop(0).split('\t')
        require(len(fields) == 3 and fields[:2] == ['HASH', key] and SHA.fullmatch(fields[2]))
        hashes[key] = fields[2]
    require(hashes['lock'] == sha(lock_raw) and all(hashes[key] == value for key, value in lock['releases'].items()))
    verification = rows[:4]; del rows[:4]
    require(verification == ['VERIFY\tapt-signatures\ttrue', 'VERIFY\tarchive-hashes\ttrue',
        'VERIFY\tinstalled-identities\ttrue', 'KEYRING\t' + hashes['keyring']])
    require(sha(('\n'.join(verification) + '\n').encode()) == hashes['verification'])

    def section(label, prefix, maximum):
        require(rows.pop(0) == label + '_BEGIN')
        body = []
        while rows and rows[0].startswith(prefix + '\t'):
            body.append(rows.pop(0)); require(len(body) <= maximum)
        require(body and rows.pop(0) == label + '_END\t' + str(len(body)))
        return body

    archive_rows = section('ARCHIVES', 'ARCHIVE', 128)
    installed_rows = section('INSTALLED', 'INSTALLED', 512)
    current_rows = section('LIVE', 'INSTALLED', 512)
    require(rows == ['END'] and installed_rows == current_rows)
    require(sha(('\n'.join(archive_rows) + '\n').encode()) == hashes['archives']
        and sha(('\n'.join(installed_rows) + '\n').encode()) == hashes['installed'])
    installed = []
    for row in installed_rows:
        fields = row.split('\t'); require(len(fields) == 4)
        name, version, architecture = identity(*fields[1:], selected)
        installed.append(dict(name=name, version=version, architecture=architecture))
    installed_set = package_set(installed, selected)
    require(installed_set == package_set(live_packages, selected))
    archives = []; seen = set()
    for row in archive_rows:
        fields = row.split('\t'); require(len(fields) == 6)
        _, name, version, architecture, digest, size = fields
        identity(name, version, architecture, selected)
        key = (name, architecture)
        require(key not in seen and SHA.fullmatch(digest) and re.fullmatch(r'[1-9][0-9]{0,7}', size)
            and int(size) <= 20000000 and installed_set.get(key) == version)
        seen.add(key)
        archives.append(dict(name=name, version=version, architecture=architecture, sha256=digest, size=int(size)))
    require(all(row in archives for row in lock['packages'][selected]))
    return dict(schema=1, snapshot=SNAPSHOT, architecture=selected, verified=True, sha256=hashes,
        apt_signatures_verified_at_build=True, archive_hashes_verified_at_build=True,
        installed_identities_verified=True, direct_packages=lock['packages'][selected],
        archives=archives, installed_packages=installed,
        limitations=['APT verification is recorded build-time evidence, not independently repeated signature verification',
            'installed inventory and linkage do not establish native vulnerability or license closure'])


def compare_reports(documents, images, platform, lock_raw):
    """Bind complete observations to the same image IDs, without upgrading proof."""
    from scan_container_images import _json
    require(type(images) is dict and set(images) == {'baseline', 'debian_closure'} and
        all(type(value) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', value) for value in images.values())
        and len(set(images.values())) == 2 and platform in ('linux/amd64', 'linux/arm64'))
    require(type(documents) is dict and set(documents) == {'baseline', 'debian_closure', 'diagnostic'}
        and all(type(raw) is bytes and 0 < len(raw) <= 2*1024*1024 for raw in documents.values()))
    parse_lock(lock_raw)
    reported = {}; jre_digests = []
    for role, schema in (('baseline', 2), ('debian_closure', 3)):
        value = _json(documents[role])
        require(type(value) is dict and type(value.get('schema')) is int and value['schema'] == schema
            and value.get('evidence_class') == 'owned_java_runtime_inventory'
            and value.get('image_id') == images[role] and value.get('platform') == platform
            and value.get('inventory_complete') is True and value.get('cleanup') is True
            and type(value.get('native_checks_passed')) is bool
            and type(value.get('jre_tree_sha256')) is str and SHA.fullmatch(value['jre_tree_sha256'])
            and type(value.get('features')) is dict and type(value['features'].get('passed')) is bool
            and all(value.get(key) is False for key in ('release_ready', 'native_binary_coverage', 'coverage_complete')))
        if role == 'debian_closure':
            closure = value.get('dependency_closure')
            require(type(closure) is dict and closure.get('verified') is True
                and type(closure.get('sha256')) is dict and closure['sha256'].get('lock') == sha(lock_raw))
        reported[role] = dict(native_checks_passed=value['native_checks_passed'], features_passed=value['features']['passed'])
        jre_digests.append(value['jre_tree_sha256'])
    require(jre_digests[0] == jre_digests[1])
    scan = _json(documents['diagnostic'])
    require(type(scan) is dict and type(scan.get('schema')) is int and scan['schema'] == 1
        and scan.get('evidence_class') == 'diagnostic_image_vulnerability_comparison'
        and scan.get('platform') == platform and scan.get('measurement_complete') is True
        and type(scan.get('images')) is list and len(scan['images']) == 2
        and all(type(row) is dict and row.get('image_id') == images[role]
            for row, role in zip(scan['images'], ('baseline', 'debian_closure')))
        and all(scan.get(key) is False for key in ('release_ready', 'external_approval', 'native_binary_coverage',
            'coverage_complete', 'complete_resolved_graph')))
    return dict(schema=1, evidence_class='same_image_diagnostic_comparison', platform=platform,
        image_ids=images.copy(), sha256={key:sha(raw) for key,raw in documents.items()},
        dependency_lock_sha256=sha(lock_raw), artifact_bindings_verified=True,
        whole_jre_identity_matches=True,
        reported_native_results=reported, release_ready=False, external_approval=False,
        native_binary_coverage=False, coverage_complete=False, complete_resolved_graph=False,
        limitations=['identity and original report hashes are bound; complete native and vulnerability semantics are not independently reverified',
            'recipe equality never substitutes for identical immutable image IDs; no production approval'])


def main(argv=None):
    import argparse
    import json
    from scan_container_images import Publication, _path, file_identity, verify_files
    class Parser(argparse.ArgumentParser):
        def error(self, message): raise ValueError('java_comparison_unverified')
    parser = Parser(description='Bind three fixed diagnostic reports to the same immutable images; never approve release.')
    parser.add_argument('command', choices=['compare'])
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--baseline-image', required=True)
    parser.add_argument('--closure-image', required=True)
    parser.add_argument('--platform', required=True)
    try:
        args = parser.parse_args(argv)
        root = _path(args.input, directory=True); output = _path(args.output, new=True)
        parent = output.parent.stat()
        require(parent.st_uid == os.getuid() and not parent.st_mode & 0o022)
        paths = dict(baseline=root/'native/baseline/java-runtime.json',
            debian_closure=root/'native/debian-closure/java-runtime.json', diagnostic=root/'scan/diagnostic.json')
        documents = {}; pins = {}
        for name, path in paths.items():
            pin, raw = file_identity(path, 2*1024*1024, keep=True)
            documents[name] = raw; pins[path] = (2*1024*1024, pin)
        lock_path = Path(__file__).with_name('java-runtime-dependencies.lock')
        lock_pin, lock_raw = file_identity(lock_path, 16384, keep=True)
        pins[lock_path] = (16384, lock_pin)
        value = compare_reports(documents, dict(baseline=args.baseline_image, debian_closure=args.closure_image), args.platform, lock_raw)
        raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
        require(len(raw) <= 16384)
        with Publication(output) as publication:
            publication.write('comparison.json', raw)
            verify_files(pins); publication.publish(); verify_files(pins)
        print('{"artifact_bindings_verified":true,"release_ready":false}')
        return 0
    except (Exception, KeyboardInterrupt):
        print('{"artifact_bindings_verified":false,"release_ready":false}')
        return 2


if __name__ == '__main__': sys.exit(main())
