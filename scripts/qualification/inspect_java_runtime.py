#!/usr/bin/env python3
"""Bounded, private native-linkage diagnostics for one immutable local Java image.

No packages are installed and no runtime or distribution features are removed.
Complete inventory is distinct from successful linkage and from native closure.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import platform as host_platform
import re
import secrets
import shutil
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from spring_containers import bounded_command, cancellation_scope, validate_local_context
from scan_container_images import _json, _path
from java_runtime_dependencies import CLOSURE_SCRIPT, parse_closure, read_lock, private_publication, check_private_parent
import java_runtime_rpm as rpm

ROOT = '/opt/java/openjdk'
SCOPE = 'java-runtime-inventory-v1'
MAX_PROTOCOL = 8 * 1024 * 1024
MAX_REPORT = 2 * 1024 * 1024
MAX_FEATURE_BYTES = 16384
FEATURE_CHECKS = frozenset(('crypto_p256', 'aes_gcm', 'pkcs12_roundtrip', 'jsse_default_trust',
    'mtls_loopback', 'utf8_io', 'locale_data', 'timezone_data', 'localhost_nss', 'headless_font'))
SHA = re.compile(r'[0-9a-f]{64}\Z')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
RELATIVE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+@/-]{0,255}\Z')
SONAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,199}\Z')
PACKAGE = re.compile(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?\Z')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+~:!*-]{0,199}\Z')
TMPFS = 'rw,noexec,nosuid,nodev,size=16m,mode=1777'

# All inputs and temporary files are inside the new networkless, read-only-root
# owned container. Capture Java/ldd failures without aborting the file inventory.
INVENTORY_SCRIPT = r'''set -eu
export LC_ALL=C
printf 'JRI\t1\n'
awk -F= '$1=="ID" {gsub(/"/,"",$2); printf "OS_ID\t%s\n",$2} $1=="VERSION_ID" {gsub(/"/,"",$2); printf "OS_VERSION\t%s\n",$2}' /etc/os-release
printf 'ARCH\t%s\n' "$(uname -m)"
printf 'UID\t%s\n' "$(id -u)"
dpkg-query -W -f='PACKAGE\t${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'
list=$(mktemp /tmp/jre-files.XXXXXX)
trap 'rm -f "$list"' EXIT
find /opt/java/openjdk \( -type f -o -type l \) -print > "$list"
files=0; links=0; elfs=0
while IFS= read -r file; do
  relative=${file#/opt/java/openjdk/}
  if [ -L "$file" ]; then
    printf 'SYMLINK\t%s\t%s\n' "$relative" "$(readlink "$file")"
    links=$((links+1)); continue
  fi
  hash=$(sha256sum "$file"); hash=${hash%% *}
  head=$(od -An -N20 -tx1 "$file" | tr -d ' \n')
  printf 'FILE\t%s\t%s\t%s\t%s\n' "$relative" "$hash" "$(stat -c %s "$file")" "${head:--}"
  files=$((files+1))
  case "$head" in 7f454c46*)
    set +e; result=$(ldd "$file" 2>&1); code=$?; set -e
    printf 'ELF_BEGIN\t%s\t%s\n' "$relative" "$code"
    printf '%s\n' "$result" | sed 's/^/LDD\t/'
    printf 'ELF_END\t%s\n' "$relative"
    elfs=$((elfs+1));;
  esac
done < "$list"
set +e
result=$(/opt/java/openjdk/bin/java -XshowSettings:properties -version 2>&1); code=$?
set -e
printf 'JAVA_BEGIN\t%s\n' "$code"
printf '%s\n' "$result" | sed 's/^/JAVA\t/'
printf 'JAVA_END\nRELEASE_BEGIN\n'
if [ -r /opt/java/openjdk/release ]; then sed 's/^/RELEASE\t/' /opt/java/openjdk/release; fi
printf 'RELEASE_END\nEND\t%s\t%s\t%s\n' "$files" "$links" "$elfs"
'''

PROVIDER_SCRIPT = r'''set -eu
export LC_ALL=C
printf 'PROVIDERS\t1\n'
count=0
for file do
  printf 'LIB_BEGIN\t%s\n' "$file"
  real=$(readlink -f "$file")
  printf 'REAL\t%s\n' "$real"
  hash=$(sha256sum "$real"); printf 'HASH\t%s\n' "${hash%% *}"
  set +e
  owners=$(dpkg-query -S "$real" 2>/dev/null); code=$?
  if [ "$code" != 0 ] && [ "$real" != "$file" ]; then owners=$(dpkg-query -S "$file" 2>/dev/null); code=$?; fi
  set -e
  printf 'OWNER_CODE\t%s\n' "$code"
  if [ -n "$owners" ]; then printf '%s\n' "$owners" | sed 's/^/OWNER\t/'; fi
  printf 'LIB_END\t%s\n' "$file"
  count=$((count+1))
done
printf 'END\t%s\n' "$count"
'''


# Preserve the diagnostic image's configured locale and trust defaults. Docker
# exec inherits container image environment, never the caller's host variables.
# Capture the fixed Java exit code while the shell itself completes normally.
FEATURE_SCRIPT = r'''printf 'FEATURE_BEGIN\n'
/opt/java/openjdk/bin/java -Xmx64m -XX:ActiveProcessorCount=1 -Djava.io.tmpdir=/tmp -Duser.home=/tmp -Djava.awt.headless=true -cp /opt/appguard/java-runtime-probe AppGuardRuntimeProbe 2>/dev/null
code=$?
printf 'FEATURE_EXIT\t%s\n' "$code"
'''


def require(value):
    if not value: raise ValueError('java_runtime_inventory_unverified')


def relative(value):
    require(type(value) is str and RELATIVE.fullmatch(value) and
        all(part not in ('', '.', '..') for part in value.split('/')))
    return value


def library_path(value, extra_roots=()):
    require(type(value) is str and len(value) <= 512 and re.fullmatch(r'/[A-Za-z0-9._+@/:-]+', value))
    value = posixpath.normpath(value)
    require(any(value.startswith(prefix + '/') for prefix in ('/lib', '/lib64', '/usr/lib', '/usr/local/lib', ROOT, *extra_roots)))
    return value


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class Inventory(dict):
    # Container-only paths are transient parsing state, never JSON artifacts.
    pass


def protocol(raw):
    require(type(raw) is str and 0 < len(raw.encode()) <= MAX_PROTOCOL and raw.endswith('\n') and '\x00' not in raw)
    rows = raw.splitlines()
    require(len(rows) <= 50000 and all(len(row) <= 4096 for row in rows))
    return rows


def parse_features(raw):
    require(type(raw) is str and 0 < len(raw.encode()) <= MAX_FEATURE_BYTES and raw.endswith('\n'))
    rows = raw.splitlines()
    require(len(rows) == 3 and rows[0] == 'FEATURE_BEGIN' and re.fullmatch(r'FEATURE_EXIT\t[012]', rows[2]))
    code = int(rows[2].split('\t')[1])
    value = _json(rows[1].encode())
    require(type(value) is dict and set(value) == {'schema', 'checks', 'passed'}
        and type(value['schema']) is int and value['schema'] == 1
        and type(value['checks']) is dict and set(value['checks']) == FEATURE_CHECKS
        and all(type(flag) is bool for flag in value['checks'].values())
        and type(value['passed']) is bool and value['passed'] is all(value['checks'].values())
        and (code == 0 if value['passed'] else code in (1, 2)))
    return dict(schema=1, checks={key: value['checks'][key] for key in sorted(FEATURE_CHECKS)},
        passed=value['passed'], exit_code=code)


def parse_ldd(lines, code, files, extra_roots=()):
    dependencies, missing, valid = [], [], code == 0 and any(line.strip() for line in lines)
    require(len(lines) <= 512)
    for line in lines:
        line = line.strip()
        if not line: continue
        if line in ('statically linked', 'not a dynamic executable'):
            # Retain nonzero loader status even when its text resembles a
            # static binary: the message alone cannot prove a valid static ELF.
            continue
        match = re.fullmatch(r'(linux-vdso\.so\.[0-9]+) \(0x[0-9a-fA-F]{1,16}\)', line)
        if match:
            dependencies.append(dict(soname=match[1], resolution='virtual', path_sha256=None, sha256=None, providers=[]))
            continue
        match = re.fullmatch(r'([A-Za-z0-9._+-]+) => not found', line)
        if match and SONAME.fullmatch(match[1]):
            missing.append(match[1]); continue
        match = re.fullmatch(r'(?:(\S+) => )?(/\S+) \(0x[0-9a-fA-F]{1,16}\)', line)
        if not match:
            valid = False; continue
        try:
            path = library_path(match[2], extra_roots); soname = match[1] or posixpath.basename(path)
            require(SONAME.fullmatch(soname))
            bundled = path.startswith(ROOT + '/')
            name = path[len(ROOT) + 1:] if bundled else None
            file_hash = files.get(name, {}).get('sha256') if bundled else None
            if bundled and file_hash is None: valid = False
            dependencies.append(dict(soname=soname, resolution='bundled_jre' if bundled else 'os',
                path_sha256=digest(path), sha256=file_hash, providers=[]))
        except ValueError:
            valid = False
    return dependencies, missing, valid


def parse_inventory(raw, architecture, *, tree_only=False):
    require(architecture in ('amd64', 'arm64'))
    rows = protocol(raw); require(rows[0] == 'JRI\t1')
    fields, files, links, packages, elfs, release, java = {}, {}, {}, {}, [], {}, {}
    mode, block, code, lines, counts = None, None, None, [], None
    seen_java = seen_release = False
    paths = set()
    for row in rows[1:]:
        parts = row.split('\t'); key = parts[0]
        if mode:
            if key == {'ELF': 'ELF_END', 'JAVA': 'JAVA_END', 'RELEASE': 'RELEASE_END'}[mode]:
                require((parts == [key, block]) if mode == 'ELF' else parts == [key])
                if mode == 'ELF':
                    for line in lines:
                        found = re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-fA-F]{1,16}\)\s*', line)
                        if found:
                            try:
                                path = library_path(found[1])
                                if not path.startswith(ROOT + '/'): paths.add(path)
                            except ValueError: pass
                    elfs.append(dict(path=block, sha256=files[block]['sha256'], exit_code=code, _lines=lines))
                elif mode == 'JAVA':
                    java = {'exit_code': code}
                    for line in lines:
                        found = re.fullmatch(r'\s*(java\.vendor|java\.version|java\.runtime\.version|os\.arch) = (.{1,200})', line)
                        if found:
                            require(found[1] not in java); java[found[1]] = found[2]
                else:
                    for line in lines:
                        found = re.fullmatch(r'([A-Z_]+)="([^"\r\n]{0,2000})"', line)
                        require(found is not None and found[1] not in release)
                        release[found[1]] = found[2]
                mode = None; continue
            require(key == {'ELF': 'LDD', 'JAVA': 'JAVA', 'RELEASE': 'RELEASE'}[mode] and row.startswith(key + '\t'))
            lines.append(row[len(key) + 1:]); require(len(lines) <= 512); continue
        require(counts is None)
        if key in ('OS_ID', 'OS_VERSION', 'ARCH', 'UID'):
            require(len(parts) == 2 and key not in fields); fields[key] = parts[1]
        elif key == 'PACKAGE':
            require(len(parts) == 5 and PACKAGE.fullmatch(parts[1]) and VERSION.fullmatch(parts[2])
                and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}', parts[3]) and parts[4] == 'installed'
                and parts[1] not in packages and len(packages) < 1024)
            packages[parts[1]] = dict(name=parts[1], version=parts[2], architecture=parts[3])
        elif key == 'FILE':
            require(len(parts) == 5); name = relative(parts[1])
            require(name not in files and name not in links and SHA.fullmatch(parts[2]) and parts[3].isdigit()
                and int(parts[3]) <= 512 * 1024 * 1024 and (parts[4] == '-' or re.fullmatch(r'(?:[0-9a-f]{2}){1,20}', parts[4])))
            files[name] = dict(path=name, sha256=parts[2], size=int(parts[3]), header=parts[4])
        elif key == 'SYMLINK':
            require(len(parts) == 3); name = relative(parts[1])
            require(name not in files and name not in links and 0 < len(parts[2]) <= 512
                and re.fullmatch(r'[A-Za-z0-9._+@/:-]+', parts[2]))
            links[name] = parts[2]
        elif key == 'ELF_BEGIN':
            require(len(parts) == 3 and parts[1] in files and files[parts[1]]['header'].startswith('7f454c46')
                and not any(item['path'] == parts[1] for item in elfs) and parts[2].isdigit() and int(parts[2]) <= 255)
            mode, block, code, lines = 'ELF', parts[1], int(parts[2]), []
        elif key == 'JAVA_BEGIN':
            require(not seen_java and len(parts) == 2 and parts[1].isdigit() and int(parts[1]) <= 255)
            seen_java = True; mode, code, lines = 'JAVA', int(parts[1]), []
        elif key == 'RELEASE_BEGIN':
            require(not seen_release and len(parts) == 1)
            seen_release = True; mode, lines = 'RELEASE', []
        elif key == 'END':
            require(len(parts) == 4 and all(value.isdigit() for value in parts[1:])); counts = tuple(map(int, parts[1:]))
        else: raise ValueError('java_runtime_inventory_unverified')
        require(len(files) + len(links) <= 4096 and len(elfs) <= 256 and len(paths) <= 256)
    if tree_only:
        require(not elfs and not packages)
        elfs = [dict(path=name, sha256=file['sha256'], exit_code=None, dependencies=[], missing=[], loader_output_valid=False)
            for name, file in files.items() if file['header'].startswith('7f454c46')]
        require(len(elfs) <= 256)
    require(mode is None and counts == (len(files), len(links), len(elfs)) and seen_java and seen_release
        and set(fields) == {'OS_ID', 'OS_VERSION', 'ARCH', 'UID'} and len(elfs) > 0
        and sum(file['size'] for file in files.values()) <= 1024 * 1024 * 1024
        and {name for name, file in files.items() if file['header'].startswith('7f454c46')} == {elf['path'] for elf in elfs})
    require(re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,39}', fields['OS_ID'])
        and VERSION.fullmatch(fields['OS_VERSION']) and fields['UID'] == '10001')
    targets = {name: posixpath.normpath(target if target.startswith('/') else ROOT + '/' + posixpath.dirname(name) + '/' + target)
        for name, target in links.items()}
    contained = all(target.startswith(ROOT + '/') for target in targets.values())
    def resolve_file(name):
        visited = set()
        while name in links:
            if name in visited or not targets[name].startswith(ROOT + '/'): return None
            visited.add(name); name = targets[name][len(ROOT) + 1:]
        return files.get(name)
    def file_present(name):
        file = resolve_file(name)
        return file is not None and file['size'] > 0
    # find's order is undefined. Resolve every in-tree alias only after all
    # regular-file hashes and literal symlink targets have been collected.
    resolved_files = dict(files)
    for name in links:
        file = resolve_file(name)
        if file is not None: resolved_files[name] = file
    for elf in elfs:
        if not tree_only:
            dependencies, missing, valid = parse_ldd(elf.pop('_lines'), elf['exit_code'], resolved_files)
            elf.update(dependencies=dependencies, missing=missing, loader_output_valid=valid)
    tree = [dict(path=name, kind='file', sha256=file['sha256'], size=file['size']) for name, file in files.items()]
    tree.extend(dict(path=name, kind='symlink', target=target) for name, target in links.items())
    tree.sort(key=lambda item: item['path'])
    machine = 62 if architecture == 'amd64' else 183
    valid_headers = all(len(files[elf['path']]['header']) == 40 and files[elf['path']]['header'].startswith('7f454c460201')
        and int.from_bytes(bytes.fromhex(files[elf['path']]['header'][32:36]), 'little') in (2, 3)
        and int.from_bytes(bytes.fromhex(files[elf['path']]['header'][36:40]), 'little') == machine for elf in elfs)
    arch_names = ('x86_64', 'amd64') if architecture == 'amd64' else ('aarch64', 'aarch64')
    checks = dict(elf_platform_matches=valid_headers and fields['ARCH'] == arch_names[0],
        java_identity_matches=java.get('exit_code') == 0 and java.get('java.vendor') == 'Eclipse Adoptium'
            and java.get('java.version') == '17.0.20.1' and java.get('java.runtime.version') == '17.0.20.1+1'
            and java.get('os.arch') == arch_names[1],
        release_identity_matches=release.get('JAVA_VERSION') == '17.0.20.1' and release.get('IMPLEMENTOR') == 'Eclipse Adoptium'
            and release.get('JAVA_RUNTIME_VERSION') == '17.0.20.1+1',
        required_files_present=all(file_present(name) for name in ('release', 'legal/java.base/LICENSE', 'lib/security/cacerts')),
        symlinks_contained=contained, linkage_resolved=all(elf['loader_output_valid'] and not elf['missing'] for elf in elfs),
        package_inventory_complete=bool(packages), native_providers_verified=False)
    # Unknown Java/release values remain private rather than becoming public text.
    result = Inventory(inventory_complete=True, checks=checks,
        java=dict(exit_code=java['exit_code'], vendor='Eclipse Adoptium' if java.get('java.vendor') == 'Eclipse Adoptium' else None,
            version='17.0.20.1' if java.get('java.version') == '17.0.20.1' else None,
            runtime_version='17.0.20.1+1' if java.get('java.runtime.version') == '17.0.20.1+1' else None),
        os=dict(id=fields['OS_ID'], version=fields['OS_VERSION'], architecture=architecture),
        counts=dict(regular_files=len(files), symlinks=len(links), elf_files=len(elfs), legal_files=sum(name.startswith('legal/') for name in files),
            missing_dependencies=sum(len(elf['missing']) for elf in elfs), os_packages=len(packages)),
        jre_tree_sha256=digest(json.dumps(tree, sort_keys=True, separators=(',', ':'))) if contained else None,
        files=[{key: file[key] for key in ('path', 'sha256', 'size')} for name, file in sorted(files.items())],
        symlinks=[dict(path=name, target=target if targets[name].startswith(ROOT + '/') else None,
            target_sha256=digest(target), within_jre=targets[name].startswith(ROOT + '/')) for name, target in sorted(links.items())],
        packages=sorted(packages.values(), key=lambda item: item['name']), elfs=elfs)
    result.paths = paths
    result.resolved_files = resolved_files
    return result


def parse_providers(raw, requested, packages):
    rows = protocol(raw); require(rows[0] == 'PROVIDERS\t1')
    packages = {package['name']: package for package in packages}
    result, block, values, owners, ended = {}, None, {}, [], False
    for row in rows[1:]:
        parts = row.split('\t'); key = parts[0]
        require(not ended)
        if key == 'LIB_BEGIN':
            require(block is None and len(parts) == 2 and parts[1] in requested and parts[1] not in result)
            block, values, owners = parts[1], {}, []
        elif key in ('REAL', 'HASH', 'OWNER_CODE'):
            require(block is not None and len(parts) == 2 and key not in values); values[key] = parts[1]
        elif key == 'OWNER':
            require(block is not None and row.startswith('OWNER\t')); owners.append(row[6:])
        elif key == 'LIB_END':
            require(parts == ['LIB_END', block] and set(values) == {'REAL', 'HASH', 'OWNER_CODE'}
                and SHA.fullmatch(values['HASH']) and values['OWNER_CODE'].isdigit() and int(values['OWNER_CODE']) <= 255)
            real = library_path(values['REAL']); verified = values['OWNER_CODE'] == '0'; providers = {}
            for owner in owners:
                prefix, separator, path = owner.partition(': ')
                names = prefix.split(', ')
                if not separator or path not in (block, real) or any(name not in packages for name in names):
                    verified = False; continue
                providers.update((name, packages[name]) for name in names)
            result[block] = dict(sha256=values['HASH'], provider_verified=verified and bool(providers),
                providers=sorted(providers.values(), key=lambda item: item['name']))
            block = None
        elif key == 'END':
            require(block is None and len(parts) == 2 and parts[1].isdigit() and int(parts[1]) == len(result)); ended = True
        else: raise ValueError('java_runtime_inventory_unverified')
    require(ended and set(result) == set(requested))
    return result


def validate_container(record, image, owner):
    require(type(record) is dict and SHA.fullmatch(record.get('Id', '')) and record.get('Image') == image)
    config, host = record['Config'], record['HostConfig']
    require(config['Labels'].get('io.appguard.owner') == owner and config['Labels'].get('io.appguard.scope') == SCOPE
        and config.get('User') == '10001:10001' and host.get('ReadonlyRootfs') is True
        and host.get('Privileged') is False and host.get('NetworkMode') == 'none'
        and host.get('CapDrop') == ['ALL'] and not host.get('CapAdd') and not host.get('Binds')
        and host.get('SecurityOpt') == ['no-new-privileges:true'] and not host.get('PortBindings')
        and host.get('Memory') == host.get('MemorySwap') == 268435456 and host.get('NanoCpus') == 1000000000
        and host.get('PidsLimit') == 64 and host.get('RestartPolicy', {}).get('Name') == 'no'
        and host.get('LogConfig') == {'Type': 'none', 'Config': {}} and host.get('Tmpfs') == {'/tmp': TMPFS}
        and all(mount.get('Type') == 'tmpfs' and mount.get('Destination') == '/tmp' for mount in record.get('Mounts', []))
        and record.get('RestartCount') == 0 and record.get('State', {}).get('OOMKilled') is False)
    return record['Id']


def inspect_runtime(image, platform, output, docker_context='default', features=False, dependency_closure=False, package_profile='dpkg-v1'):
    require(type(image) is str and IMAGE.fullmatch(image) and platform in ('linux/amd64', 'linux/arm64') and docker_context == 'default')
    require(type(features) is bool and type(dependency_closure) is bool)
    require(package_profile in ('dpkg-v1', *rpm.PROFILES) and
        (package_profile == 'dpkg-v1' or features and not dependency_closure))
    is_rpm = package_profile in rpm.PROFILES
    output = _path(output, new=True)
    parent = output.parent.stat()
    require(parent.st_uid == os.getuid() and not parent.st_mode & 0o022)
    architecture = platform.split('/')[1]
    if is_rpm:
        require(host_platform.system() == 'Linux' and host_platform.machine() in
            (('x86_64','amd64') if architecture == 'amd64' else ('aarch64','arm64')))
    owner = secrets.token_hex(16); name = 'appguard-java-audit-' + owner
    report = dict(schema=3 if dependency_closure else 2 if features else 1, evidence_class='owned_java_runtime_inventory', image_id=image, platform=platform,
        inventory_complete=False, native_checks_passed=False, cleanup=False, release_ready=False,
        native_binary_coverage=False, coverage_complete=False, reason='inventory_unverified',
        limitations=['ldd resolves declared loader dependencies, not every dlopen/JNI path or native vulnerability',
            'ELF class and machine do not prove an ISA baseline or host-kernel compatibility',
            'whole JRE byte identity does not prove Java features or license completeness',
            'no external approval, production or physical-hardware evidence'])
    if features: report['features'] = None
    if dependency_closure: report['dependency_closure'] = None
    if is_rpm: report.update(rpm.initial_report(architecture, profile=package_profile), schema=4)
    with private_publication(output) as publication, tempfile.TemporaryDirectory(prefix='appguard-java-audit-') as temporary:
        state = Path(temporary).resolve(); state.chmod(0o700)
        home = state/'home'; home.mkdir(mode=0o700)
        docker_config = state/'docker'; docker_config.mkdir(mode=0o700)
        (docker_config/'config.json').write_text('{}'); (docker_config/'config.json').chmod(0o600)
        env = {key: os.environ[key] for key in ('PATH', 'SYSTEMROOT') if key in os.environ}
        if is_rpm:
            env.update({key: os.environ[key] for key in ('HOME','CODEX_HOME') if key in os.environ})
            env.update(DOCKER_CONFIG=str(docker_config), DOCKER_CONTEXT='default')
        else: env.update(HOME=str(home), DOCKER_CONFIG=str(docker_config), DOCKER_CONTEXT='default')
        executable = shutil.which('docker') or 'docker'
        deadline, created, identifier = time.monotonic() + 600, False, None
        def call(args, timeout=30):
            require(time.monotonic() < deadline)
            return bounded_command([executable, '--context', 'default', *args], env=env, cwd=state,
                timeout=min(timeout, max(.01, deadline-time.monotonic())), limit=MAX_PROTOCOL)
        def records(args):
            value = _json(('{"rows":' + call(args) + '}').encode())['rows']
            require(type(value) is list and len(value) == 1 and type(value[0]) is dict)
            return value[0]
        def owned(*, validate=False):
            record = records(['inspect', identifier or name])
            current = record.get('Id', '')
            labels = record.get('Config', {}).get('Labels') or {}
            require(SHA.fullmatch(current) and record.get('Image') == image
                and labels.get('io.appguard.owner') == owner and labels.get('io.appguard.scope') == SCOPE)
            require(identifier is None or current == identifier)
            if validate: validate_container(record, image, owner)
            return current
        try:
            validate_local_context(records(['context', 'inspect', 'default']))
            daemon = _json(call(['info', '--format', '{{json .}}']).encode())
            require(daemon.get('OSType') == 'linux' and daemon.get('Architecture') in
                (('x86_64', 'amd64') if architecture == 'amd64' else ('aarch64', 'arm64')))
            original_image = records(['image', 'inspect', image])
            require(original_image.get('Id') == image and original_image.get('Os') == 'linux'
                and original_image.get('Architecture') == architecture and not original_image.get('Config', {}).get('Volumes'))
            if is_rpm: rpm.validate_environment(original_image.get('Config', {}).get('Env'))
            created = True
            created_id = call(['create', '--label', 'io.appguard.owner=' + owner, '--label', 'io.appguard.scope=' + SCOPE,
                '--name', name, '--pull', 'never', '--platform', platform, '--network', 'none', '--read-only',
                '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--memory', '256m', '--memory-swap', '256m', '--cpus', '1', '--pids-limit', '64',
                '--restart', 'no', '--log-driver', 'none', '--tmpfs', '/tmp:' + TMPFS,
                '--entrypoint', rpm.JAVA if is_rpm else '/bin/sh', image,
                *(rpm.IDLE if is_rpm else ('-c', 'exec sleep 600'))]).strip()
            require(SHA.fullmatch(created_id)); identifier = created_id
            owned(validate=True)
            call(['start', identifier]); owned(validate=True)
            prefix = ['exec', identifier, '/usr/bin/env', '-i', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                'HOME=/tmp', 'LC_ALL=C', 'JAVA_HOME=' + ROOT, '/bin/sh', '-c']
            if is_rpm:
                def execute_rpm(command, timeout):
                    if time.monotonic() >= deadline: raise rpm.StopCollection('budget_exhausted')
                    try: owned(validate=True)
                    except (Exception, KeyboardInterrupt): raise rpm.StopCollection('identity_unverified') from None
                    return call(['exec', identifier, *command], timeout)
                rpm.collect(report, execute_rpm, architecture, parse_inventory, parse_ldd, library_path, profile=package_profile)
            else:
                parsed = parse_inventory(call([*prefix, INVENTORY_SCRIPT], timeout=300), architecture)
                report.update(parsed)
                if parsed.paths:
                    providers = parse_providers(call([*prefix, PROVIDER_SCRIPT, 'jre-providers', *sorted(parsed.paths)], timeout=120), parsed.paths, parsed['packages'])
                else: providers = {}
                by_hash = {digest(path): row for path, row in providers.items()}
                for elf in report['elfs']:
                    for dependency in elf['dependencies']:
                        if dependency['resolution'] == 'os':
                            row = by_hash[dependency['path_sha256']]
                            dependency.update(sha256=row['sha256'], providers=row['providers'])
                report['checks']['native_providers_verified'] = all(row['provider_verified'] for row in providers.values())
                if dependency_closure:
                    report['dependency_closure'] = parse_closure(call([*prefix, CLOSURE_SCRIPT], timeout=30),
                        read_lock(), architecture, report['packages'])
                    report['checks']['dependency_closure_verified'] = report['dependency_closure']['verified']
                if features:
                    report['features'] = parse_features(call(['exec', identifier, '/bin/sh', '-c', FEATURE_SCRIPT], timeout=120))
                    # Retain strictly validated partial diagnostics, but an unverified
                    # JVM/resource outcome must never complete the inventory.
                    require(report['features']['exit_code'] in (0, 1))
                    report['checks']['runtime_features_passed'] = report['features']['passed']
            owned(validate=True)
            final_image = records(['image', 'inspect', image])
            require(final_image.get('Id') == image)
            if is_rpm:
                require(final_image == original_image)
                final_identity = rpm.parse_envelope(call(['exec', identifier, rpm.JAVA, *rpm.FLAGS, 'identity']))
                require(final_identity['complete'] and rpm.parse_identity(final_identity['data'], architecture) == report['platform_observation'])
                final_daemon = _json(call(['info', '--format', '{{json .}}']).encode())
                require(final_daemon.get('OSType') == daemon.get('OSType') and final_daemon.get('Architecture') == daemon.get('Architecture'))
                require(host_platform.system() == 'Linux' and host_platform.machine() in
                    (('x86_64','amd64') if architecture == 'amd64' else ('aarch64','arm64')))
                owned(validate=True)
                report['platform_observation'].update(host_os='linux',host_machine='x86_64' if architecture=='amd64' else 'aarch64',
                    daemon_os='linux',daemon_architecture=architecture,verified=True)
                report['final_identity_verified'] = True
                rpm.finalize(report)
            else:
                report['native_checks_passed'] = all(report['checks'].values())
                report['reason'] = 'native_requirements_met' if report['native_checks_passed'] else 'native_requirements_unmet'
        except (Exception, KeyboardInterrupt):
            report.update(inventory_complete=False, native_checks_passed=False, reason='inventory_unverified')
        finally:
            # A command may fail after create succeeded: discover only our exact
            # unpredictable name, then validate labels/full identity before edits.
            deadline = time.monotonic() + 60
            try:
                if created:
                    identifier = owned()
                    call(['stop', '--time', '2', identifier], timeout=10); owned()
                    call(['rm', identifier], timeout=10)
                remaining = call(['ps', '-aq', '--no-trunc', '--filter', 'label=io.appguard.owner=' + owner,
                    '--filter', 'label=io.appguard.scope=' + SCOPE]).strip()
                report['cleanup'] = not remaining
            except (Exception, KeyboardInterrupt): report['cleanup'] = False
        if is_rpm: rpm.finalize(report)
        if not report['cleanup']: report.update(native_checks_passed=False, reason='cleanup_unverified')
        rpm_raw = report.pop('_rpm_raw', None)
        raw = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
        if len(raw) > MAX_REPORT:
            if is_rpm: rpm.truncate(report)
            else:
                for key in ('files', 'symlinks', 'packages', 'elfs'): report.pop(key, None)
                report.update(inventory_complete=False, native_checks_passed=False, reason='output_limit')
            raw = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
        require(len(raw) <= MAX_REPORT)
        check_private_parent(publication)
        if rpm_raw is not None: publication.write('rpm-inventory.tsv', rpm_raw)
        publication.write('java-runtime.json', raw); publication.publish()
        check_private_parent(publication)
    return report


class FixedParser(argparse.ArgumentParser):
    def error(self, message): raise ValueError('java_runtime_inventory_unverified')


def main(argv=None):
    parser = FixedParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--platform', choices=('linux/amd64', 'linux/arm64'), required=True)
    parser.add_argument('--docker-context', choices=('default',), default='default')
    parser.add_argument('--output', required=True)
    parser.add_argument('--features', action='store_true', help='Run baked-in Java feature probe in diagnostic images')
    parser.add_argument('--dependency-closure', action='store_true', help='Require fixed-snapshot dependency evidence in diagnostic image')
    parser.add_argument('--package-profile', choices=('dpkg-v1', *rpm.PROFILES), default='dpkg-v1')
    try:
        args = parser.parse_args(argv)
        with cancellation_scope(): result = inspect_runtime(args.image, args.platform, args.output, args.docker_context,
            features=args.features, dependency_closure=args.dependency_closure, package_profile=args.package_profile)
        print(json.dumps({key: result[key] for key in ('inventory_complete', 'native_checks_passed', 'cleanup', 'reason')}, sort_keys=True))
        return 0 if result['native_checks_passed'] else 1 if result.get('measurement_complete', result['inventory_complete'] and result['cleanup']) else 2
    except (Exception, KeyboardInterrupt):
        print('{"inventory_complete":false,"native_checks_passed":false,"reason":"inventory_unverified"}')
        return 2


if __name__ == '__main__': raise SystemExit(main())
