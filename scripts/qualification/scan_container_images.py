#!/usr/bin/env python3
"""Private vulnerability evidence for immutable images from owned qualification.

This checks reported image vulnerabilities, not complete native dependency
closure, secret scanning, external approval, or release readiness.
"""
import argparse
import ctypes
from datetime import datetime
import hashlib
import secrets
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'release'))
from assess import _read, _json, _path
from scan import install_tool, TOOLS

ROLES = ('gateway', 'backend', 'redis')
CHECKS = frozenset(('resource_and_isolation_inspection', 'effective_process_restrictions',
    'signed_fidelity', 'replay_rejected', 'backend_bypass_zero_dispatch',
    'absolute_upload_deadline_zero_dispatch', 'malformed_zero_dispatch',
    'owned_container_cleanup', 'provenance_unchanged', 'redis_outage_denied',
    'redis_recovery', 'redis_restart_replay_retained'))
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
MAX_REPORT = 16 * 1024 * 1024
MAX_STATUS = 2 * 1024 * 1024
MAX_DATABASE = 4 * 1024 * 1024 * 1024
MAX_METADATA = 64 * 1024
MAX_EXECUTABLE = 512 * 1024 * 1024
MAX_FINDINGS = 1024
IDENTIFIER = re.compile(r'[A-Z][A-Z0-9]{1,19}(?:-[A-Za-z0-9]+){1,9}\Z')
PACKAGE = re.compile(r'(?:[A-Za-z0-9][A-Za-z0-9._+:-]*|@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)\Z')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+~:!*-]*\Z')
PACKAGE_TYPE = re.compile(r'[a-z][a-z0-9-]{0,39}\Z')
UTC = re.compile(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z\Z')


def require(condition):
    if not condition:
        raise ValueError('container_scan_unverified')


def file_identity(path, maximum, *, keep=False):
    """Hash stable regular files in bounded chunks, without loading DBs in RAM."""
    path = _path(path)
    before = path.lstat()
    def stamp(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum)
    digest, size, raw = hashlib.sha256(), 0, bytearray()
    deadline = time.monotonic() + 120
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        current = os.fstat(stream.fileno())
        require(stat.S_ISREG(current.st_mode) and stamp(current) == stamp(before))
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            require(size <= maximum and time.monotonic() < deadline)
            digest.update(chunk)
            if keep: raw.extend(chunk)
        require(size == before.st_size and stamp(os.fstat(stream.fileno())) == stamp(before))
    require(stamp(path.lstat()) == stamp(before))
    result = dict(stamp=stamp(before), size=size, sha256=digest.hexdigest())
    return (result, bytes(raw)) if keep else result


def verify_files(pins):
    for path, (maximum, expected) in pins.items():
        require(file_identity(path, maximum) == expected)


def database_time(value):
    require(type(value) is str and len(value) <= 30)
    match = UTC.fullmatch(value)
    require(match is not None)
    # Keep nanoseconds separate: datetime alone truncates digits seven to nine.
    return datetime.fromisoformat(match[1]), int((match[2] or '').ljust(9, '0'))


def database_identities(cache):
    public, pins = {}, {}
    for name, directory, filename, schema in (('vulnerability', 'db', 'trivy.db', 2),
            ('java', 'java-db', 'trivy-java.db', 1)):
        metadata_path, database_path = cache / directory / 'metadata.json', cache / directory / filename
        metadata_pin, raw = file_identity(metadata_path, MAX_METADATA, keep=True)
        metadata = _json(raw)
        require(type(metadata.get('Version')) is int and metadata['Version'] == schema)
        updated, next_update, downloaded = (database_time(metadata.get(key))
            for key in ('UpdatedAt', 'NextUpdate', 'DownloadedAt'))
        require(updated <= downloaded and updated < next_update)
        database_pin = file_identity(database_path, MAX_DATABASE)
        pins.update({metadata_path: (MAX_METADATA, metadata_pin), database_path: (MAX_DATABASE, database_pin)})
        public[name] = dict(schema=schema, metadata_sha256=metadata_pin['sha256'],
            database_sha256=database_pin['sha256'], updated_at=metadata['UpdatedAt'],
            next_update=metadata['NextUpdate'], downloaded_at=metadata['DownloadedAt'])
    verify_files(pins)
    return public, pins


def finding_details(document):
    """Conserve every occurrence; incomplete projection never implies zero."""
    require(type(document.get('SchemaVersion')) is int and document['SchemaVersion'] == 2
        and type(document.get('Results')) is list and len(document['Results']) <= 4096)
    total, secrets_count = 0, 0
    for result in document['Results']:
        require(type(result) is dict and type(result.get('Vulnerabilities', [])) is list
            and type(result.get('Secrets', [])) is list)
        total += len(result.get('Vulnerabilities', []))
        secrets_count += len(result.get('Secrets', []))
    require(secrets_count == 0)
    if total > MAX_FINDINGS:
        return total, [], False
    findings = []
    try:
        for result_index, result in enumerate(document['Results']):
            for finding_index, row in enumerate(result.get('Vulnerabilities', [])):
                require(type(row) is dict)
                for key, pattern in (('VulnerabilityID', IDENTIFIER), ('PkgName', PACKAGE), ('InstalledVersion', VERSION)):
                    require(type(row.get(key)) is str and 0 < len(row[key]) <= 200 and pattern.fullmatch(row[key]))
                require(row.get('Severity') in ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
                    and result.get('Class') in ('os-pkgs', 'lang-pkgs')
                    and type(result.get('Type')) is str and PACKAGE_TYPE.fullmatch(result['Type']))
                fixed = row.get('FixedVersion', '')
                require(type(fixed) is str and len(fixed) <= 32 * 202)
                versions = [version.strip() for version in fixed.split(',')] if fixed.strip() else []
                require(len(versions) <= 32 and all(0 < len(version) <= 200 and VERSION.fullmatch(version) for version in versions))
                occurrence = dict(result_index=result_index, finding_index=finding_index,
                    target=result.get('Target'), pkg_id=row.get('PkgID'), pkg_path=row.get('PkgPath'))
                encoded = json.dumps(occurrence, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
                findings.append(dict(vulnerability_id=row['VulnerabilityID'], package=row['PkgName'],
                    installed_version=row['InstalledVersion'], fixed_versions=versions, severity=row['Severity'],
                    source_class=result['Class'], package_type=result['Type'], occurrence_sha256=hashlib.sha256(encoded).hexdigest()))
    except (ValueError, TypeError, UnicodeError):
        return total, [], False
    return total, findings, True


def status_bytes(status):
    raw = (json.dumps(status, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    if len(raw) > MAX_STATUS:
        for row in status['images'].values():
            row.update(findings=[], finding_details_complete=False)
        status.update(automated_checks_passed=False, finding_details_complete=False)
        if status['reason'] == 'local_images_checked': status['reason'] = 'container_scan_unverified'
        raw = (json.dumps(status, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    require(len(raw) <= MAX_STATUS)
    return raw


def validate_receipt(path):
    pin = _read(path, keep=True)
    data = pin['json']
    require(type(data.get('schema')) is int and data['schema'] == 1
        and data.get('evidence_class') == 'owned_container_deployment'
        and data.get('profile') == 'spring-loopback-mtls-containers-v1'
        and all(data.get(key) is True for key in ('cleanup', 'technical_verification', 'source_matches_commit')))
    require(type(data.get('candidate_commit')) is str
        and re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', data['candidate_commit']) is not None)
    checks = data.get('checks')
    require(type(checks) is dict and set(checks) == CHECKS and all(value is True for value in checks.values()))
    sources = data.get('source_sha256')
    require(type(sources) is dict and 0 < len(sources) <= 2048
        and all(type(key) is str and 0 < len(key) <= 4096 and type(value) is str
                and SHA.fullmatch(value) for key, value in sources.items()))
    containers = data.get('containers')
    require(type(containers) is dict)
    images = containers.get('image_ids')
    require(type(images) is dict and set(images) == set(ROLES)
        and all(type(value) is str and IMAGE.fullmatch(value) for value in images.values()))
    return pin, images


def verify_pin(path, pin):
    current = _read(path)
    require(all(current[key] == pin[key] for key in ('stamp', 'sha256', 'size')))


def bounded_command(command, *, env, cwd, timeout=30, report=None, pass_fds=()):
    """Bound CLI output, report growth and process group lifetime, including cancel."""
    import errno
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env=env, cwd=cwd, start_new_session=True, pass_fds=pass_fds)
    output = bytearray()
    deadline = time.monotonic() + timeout
    def group_absent():
        if child.poll() is None:
            return False
        until = time.monotonic() + .25
        while True:
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError as error:
                return error.errno == errno.ESRCH
            except OSError as error:
                if error.errno != errno.EPERM:
                    return False
            if time.monotonic() >= until:
                return False
            time.sleep(.01)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while child.poll() is None or selector.get_map():
                require(time.monotonic() < deadline)
                if report is not None:
                    info = os.fstat(report)
                    require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_REPORT)
                for event, _ in selector.select(.05):
                    chunk = os.read(event.fd, 65536)
                    if not chunk:
                        selector.unregister(event.fileobj)
                    else:
                        output.extend(chunk)
                        require(len(output) <= 2 * 1024 * 1024)
        return child.returncode, bytes(output)
    finally:
        # Successful leaders may leave grandchildren with stdout detached.
        # Always clean this newly owned group, including on cooperative cancel.
        try:
            for action in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(child.pid, action)
                except ProcessLookupError:
                    pass
                except PermissionError as error:
                    # Darwin's killpg1 skips SZOMB members and can report EPERM
                    # after TERM. Require the exact leader reaped AND ESRCH;
                    # successful/denied/unknown probes preserve the original error.
                    # https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_sig.c
                    if error.errno != errno.EPERM or not group_absent():
                        raise
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            child.wait(timeout=2)
        finally:
            child.stdout.close()


def context_endpoint(raw):
    # assess._json intentionally accepts only object roots; wrap Docker's list
    # without relaxing duplicate-key, finite-number, depth or size checks.
    records = _json(b'{"contexts":' + raw + b'}')['contexts']
    require(type(records) is list and len(records) == 1 and type(records[0]) is dict)
    endpoint = records[0].get('Endpoints', {}).get('docker', {}).get('Host')
    require(type(endpoint) is str and endpoint.startswith('unix:///') and len(endpoint) <= 4096)
    path = endpoint[len('unix://'):]
    require(Path(path).is_absolute() and str(Path(path)) == path and '..' not in Path(path).parts
        and all(ord(character) >= 32 and ord(character) != 127 for character in path))


def private_file(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(data)


def validate_inventory(document, role):
    """Check supported inventories separately from findings and native closure.

    Trivy v0.76.1 packaging and JAR analyzers report installed metadata or JAR
    paths, not complete native executable/runtime dependency closure. Requiring
    role-specific paths prevents a base-image pip/tool inventory satisfying the
    application's inventory check.
    """
    metadata = document.get('Metadata')
    operating_system = metadata.get('OS') if type(metadata) is dict else None
    os_identified = (type(operating_system) is dict and all(
        type(operating_system.get(key)) is str and operating_system[key].strip()
        for key in ('Family', 'Name')))
    results = document.get('Results')
    require(type(results) is list and len(results) <= 4096)
    os_packages, application_packages, observed = 0, 0, set()
    expected = ({'cryptography', 'redis', 'uvicorn', 'h11'} if role == 'gateway' else {
        'io.appguard:appguard-spring-boot-starter', 'io.appguard.examples:spring-ingress-backend',
        'org.springframework.boot:spring-boot', 'org.springframework:spring-web',
        'org.springframework.security:spring-security-core', 'org.springframework.data:spring-data-redis',
        'io.lettuce:lettuce-core'} if role == 'backend' else set())
    for result in results:
        require(type(result) is dict)
        packages = result.get('Packages', [])
        require(type(packages) is list)
        for package in packages:
            require(type(package) is dict and all(
                type(package.get(key)) is str and package[key].strip() for key in ('Name', 'Version')))
            if (os_identified and result.get('Class') == 'os-pkgs'
                    and result.get('Type') == operating_system['Family']):
                os_packages += 1
            if result.get('Class') != 'lang-pkgs':
                continue
            # Aggregated Python/JAR results carry package.FilePath; per-file
            # results can instead carry the enclosing path as result.Target.
            paths = [package.get('FilePath'), result.get('Target')]
            paths = [path.lstrip('/') for path in paths if type(path) is str
                     and '..' not in path.split('/') and '\x00' not in path]
            if role == 'gateway' and result.get('Type') == 'python-pkg':
                valid_path = any(re.fullmatch(
                    r'opt/appguard/\.venv/lib/python3\.11/site-packages/[^/]+\.dist-info/METADATA', path)
                    for path in paths)
                name = re.sub(r'[-_.]+', '-', package['Name'].lower())
            elif role == 'backend' and result.get('Type') == 'jar':
                valid_path = any(path == 'opt/appguard/backend.jar' or re.fullmatch(
                    r'opt/appguard/lib/[^/]+\.jar', path) for path in paths)
                name = package['Name']
            else:
                continue
            if valid_path:
                application_packages += 1
                observed.add(name)
    return {'os_inventory': bool(os_identified and os_packages > 0),
        'os_package_count': os_packages, 'application_package_count': application_packages,
        'application_inventory': expected <= observed if expected else None,
        'native_binary_coverage': False, 'coverage_complete': False}


class Publication:
    """All reports stay on owned descriptors until exclusive atomic publication.

    A swapped output ancestor can detach our pinned directory, but cannot redirect
    any read, scanner write, log write, cleanup, or rename into another directory.
    """
    def __init__(self, output):
        self.output = output
        self.parent_fd = self.stage_fd = None
        self.name = '.appguard-image-' + secrets.token_hex(16)
        self.published = False

    def __enter__(self):
        self.parent_fd = os.open(self.output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.check_parent()
            os.mkdir(self.name, mode=0o700, dir_fd=self.parent_fd)
            self.stage_fd = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=self.parent_fd)
        except BaseException:
            os.close(self.parent_fd)
            raise
        return self

    def check_parent(self):
        parent = _path(self.output.parent, directory=True)
        current, pinned = parent.stat(), os.fstat(self.parent_fd)
        require((current.st_dev, current.st_ino) == (pinned.st_dev, pinned.st_ino))

    def check_output(self):
        self.check_parent()
        current = os.stat(self.output.name, dir_fd=self.parent_fd, follow_symlinks=False)
        pinned = os.fstat(self.stage_fd)
        require(stat.S_ISDIR(current.st_mode)
            and (current.st_dev, current.st_ino) == (pinned.st_dev, pinned.st_ino))

    def write(self, name, data):
        require('/' not in name and name not in {'.', '..'})
        with os.fdopen(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=self.stage_fd), 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    @contextmanager
    def report(self, name):
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=self.stage_fd)
        try:
            yield descriptor
        finally:
            os.close(descriptor)

    def read(self, name):
        before = os.stat(name, dir_fd=self.stage_fd, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_REPORT)
        def stamp(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.stage_fd)
        with os.fdopen(descriptor, 'rb') as stream:
            require(stamp(before) == stamp(os.fstat(stream.fileno())))
            raw = stream.read(MAX_REPORT + 1)
            require(len(raw) <= MAX_REPORT and stamp(before) == stamp(os.fstat(stream.fileno())))
        require(stamp(before) == stamp(os.stat(name, dir_fd=self.stage_fd, follow_symlinks=False)))
        return {'stamp': stamp(before), 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                'json': _json(raw)}

    def verify(self, name, pin):
        current = self.read(name)
        require(all(current[key] == pin[key] for key in ('stamp', 'size', 'sha256')))

    def publish(self):
        self.check_parent()
        current, pinned = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False), os.fstat(self.stage_fd)
        require((current.st_dev, current.st_ino) == (pinned.st_dev, pinned.st_ino))
        # POSIX rename alone can replace an existing empty directory. These
        # platform primitives provide atomic NOREPLACE, with no unsafe fallback.
        libc = ctypes.CDLL(None, use_errno=True)
        if sys.platform == 'linux':
            rename = libc.renameat2
            flag = 1  # RENAME_NOREPLACE
        elif sys.platform == 'darwin':
            rename = libc.renameatx_np
            flag = 4  # RENAME_EXCL
        else:
            raise ValueError('container_scan_unverified')
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        require(rename(self.parent_fd, os.fsencode(self.name), self.parent_fd,
                       os.fsencode(self.output.name), flag) == 0)
        self.published = True
        self.check_output()

    def __exit__(self, kind, value, traceback):
        try:
            if kind is not None or not self.published:
                # Remove only entries in the descriptor-owned staging directory;
                # never follow or recursively remove a replacement path.
                for name in os.listdir(self.stage_fd):
                    try:
                        os.unlink(name, dir_fd=self.stage_fd)
                    except (IsADirectoryError, FileNotFoundError):
                        pass
                name = self.output.name if self.published else self.name
                try:
                    current, pinned = os.stat(name, dir_fd=self.parent_fd, follow_symlinks=False), os.fstat(self.stage_fd)
                    if (current.st_dev, current.st_ino) == (pinned.st_dev, pinned.st_ino):
                        os.rmdir(name, dir_fd=self.parent_fd)
                except FileNotFoundError:
                    pass
        finally:
            os.close(self.stage_fd)
            os.close(self.parent_fd)


@contextmanager
def cooperative_termination():
    def cancel(signum, frame):
        raise KeyboardInterrupt()
    original = signal.signal(signal.SIGTERM, cancel)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, original)


class TrivySession:
    """Fixed diagnostic commands share one private executable and DB snapshot.

    The production three-service policy below remains separate. Bounds cover
    elapsed time, input image size, files and output; host RSS is not hard capped.
    """
    seconds = 2760
    max_image_bytes = 2 * 1024 * 1024 * 1024

    def __init__(self, state):
        self.state = Path(state)
        self.deadline = time.monotonic() + self.seconds
        self.frozen = {}
        self.scanner = self.databases = None

    def prepare(self, *, require_docker=True):
        require(type(require_docker) is bool)
        home = self.state / 'home'; home.mkdir(mode=0o700)
        docker = self.state / 'docker'; docker.mkdir(mode=0o700)
        private_file(docker / 'config.json', b'{}')
        self.config = self.state / 'empty.json'; private_file(self.config, b'{}')
        self.ignore = self.state / 'empty.ignore'; private_file(self.ignore, b'')
        self.env = {key: os.environ[key] for key in ('PATH', 'SYSTEMROOT', 'SSL_CERT_FILE', 'SSL_CERT_DIR') if key in os.environ}
        self.env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), XDG_CACHE_HOME=str(self.state / 'cache'),
            DOCKER_CONFIG=str(docker), DOCKER_CONTEXT='default', TRIVY_SKIP_VERSION_CHECK='true',
            TRIVY_DISABLE_TELEMETRY='true', TRIVY_CACHE_DIR=str(self.state / 'cache/trivy'))
        for path in (docker / 'config.json', self.config, self.ignore):
            # file_identity excludes empty files; the empty ignore has an exact
            # separately checked identity instead of an unbounded content read.
            if path == self.ignore:
                self.ignore_stamp = path.stat()
            else:
                self.frozen[path] = (MAX_METADATA, file_identity(path, MAX_METADATA))
        if require_docker:
            code, raw = self.command(['docker', '--context', 'default', 'context', 'inspect', 'default'])
            require(code == 0); context_endpoint(raw)
        host = (platform.system(), platform.machine())
        require(host in TOOLS['trivy'] and TOOLS['trivy'][host]['version'] == '0.76.1')
        # Keep the reviewed checksum/extraction helper, but give its network
        # reads an owned process-group wall deadline in this diagnostic path.
        installer = ("import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
            "from scan import install_tool; install_tool('trivy',Path(sys.argv[2]))")
        code, _ = self.command([sys.executable, '-c', installer,
            str(Path(__file__).resolve().parents[1] / 'release'), str(self.state)], timeout=660)
        require(code == 0)
        self.trivy = self.state / 'trivy'
        executable = file_identity(self.trivy, MAX_EXECUTABLE)
        self.frozen[self.trivy] = (MAX_EXECUTABLE, executable)
        code, raw = self.command([str(self.trivy), 'version', '--format', 'json', '--config', str(self.config), '--quiet'])
        require(code == 0 and _json(raw).get('Version') == '0.76.1')
        self.scanner = dict(name='trivy', version='0.76.1', platform='-'.join(host),
            archive_sha256=TOOLS['trivy'][host]['sha256'], executable_sha256=executable['sha256'])
        for flag in ('--download-db-only', '--download-java-db-only'):
            code, _ = self.command([str(self.trivy), 'image', '--config', str(self.config), flag,
                '--timeout', '10m'], timeout=660)
            require(code == 0)
        self.databases, pins = database_identities(Path(self.env['TRIVY_CACHE_DIR']))
        self.frozen.update(pins)
        self.verify()

    def verify(self):
        verify_files(self.frozen)
        before = self.ignore_stamp; now = self.ignore.lstat()
        require(stat.S_ISREG(now.st_mode) and now.st_size == 0 and
            (now.st_dev, now.st_ino, now.st_mtime_ns, now.st_ctime_ns) ==
            (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns))

    def command(self, command, *, timeout=30, **kwargs):
        self.verify()
        remaining = self.deadline - time.monotonic(); require(remaining > 0)
        try:
            return bounded_command(command, env=self.env, cwd=self.state, timeout=min(timeout, remaining), **kwargs)
        finally:
            self.verify()

    def docker(self, args):
        code, raw = self.command(['docker', '--context', 'default', *args])
        require(code == 0)
        return raw

    def image_identity(self, image, architecture):
        rows = _json(b'{"rows":' + self.docker(['image', 'inspect', image]) + b'}')['rows']
        require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict)
        row = rows[0]
        require(row.get('Id') == image and row.get('Os') == 'linux' and row.get('Architecture') == architecture
            and type(row.get('Size')) is int and 0 < row['Size'] <= self.max_image_bytes)
        return {key: row[key] for key in ('Id', 'Os', 'Architecture', 'Size')}

    def report(self, publication, name, target, *, rootfs=False):
        command = [str(self.trivy), 'rootfs' if rootfs else 'image']
        if not rootfs: command += ['--image-src', 'docker']
        command += ['--config', str(self.config), '--ignorefile', str(self.ignore), '--list-all-pkgs',
            '--scanners', 'vuln', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
            '--skip-db-update', '--skip-java-db-update', '--offline-scan', '--parallel', '2',
            '--exit-code', '1', '--format', 'json', '--timeout', '1m' if rootfs else '10m']
        with publication.report(name + '.json') as descriptor:
            identity = os.fstat(descriptor)
            code, log = self.command(command + ['--output', '/dev/fd/' + str(descriptor), str(target)],
                timeout=75 if rootfs else 660, report=descriptor, pass_fds=(descriptor,))
            pin = publication.read(name + '.json')
            require(pin['stamp'][:2] == (identity.st_dev, identity.st_ino))
        publication.write(name + '.log', log)
        document = pin['json']
        require(type(document.get('Trivy')) is dict and document['Trivy'].get('Version') == '0.76.1')
        return code, document, pin


def scan(receipt, output, docker_context='default'):
    require(docker_context == 'default')
    receipt = _path(receipt)
    pin, images = validate_receipt(receipt)
    output = _path(output, new=True)
    require(receipt.parent != output and receipt.parent not in output.parents)
    status = {'schema': 2, 'evidence_class': 'owned_container_image_scan',
        'release_ready': False, 'automated_checks_passed': False,
        'reason': 'container_scan_unverified', 'qualification_sha256': pin['sha256'],
        'images': {}, 'scanners': ['vuln'], 'vulnerabilities': None, 'secrets': None,
        'scanner': None, 'databases': None, 'finding_details_complete': False,
        'coverage_complete': False, 'native_binary_coverage': False, 'complete_resolved_graph': False,
        'coverage_passed': False, 'coverage_limitations': ['redis_native_binary_unverified',
            'native_runtimes_unverified', 'complete_dependency_closure_unverified']}
    with Publication(output) as publication, tempfile.TemporaryDirectory(prefix='appguard-image-scan-') as directory:
        reports, frozen, integrity_verified = [], {}, False
        try:
            state = Path(directory).resolve()
            state.chmod(0o700)
            home = state / 'home'; home.mkdir(mode=0o700)
            docker = state / 'docker'; docker.mkdir(mode=0o700)
            private_file(docker / 'config.json', b'{}')
            config = state / 'empty.json'; private_file(config, b'{}')
            ignore = state / 'empty.ignore'; private_file(ignore, b'')
            env = {key: os.environ[key] for key in ('PATH', 'SYSTEMROOT', 'SSL_CERT_FILE', 'SSL_CERT_DIR') if key in os.environ}
            env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), XDG_CACHE_HOME=str(state / 'cache'),
                DOCKER_CONFIG=str(docker), DOCKER_CONTEXT='default', TRIVY_SKIP_VERSION_CHECK='true',
                TRIVY_DISABLE_TELEMETRY='true', TRIVY_CACHE_DIR=str(state / 'cache/trivy'))
            code, raw = bounded_command(['docker', '--context', 'default', 'context', 'inspect', 'default'],
                env=env, cwd=state)
            require(code == 0)
            context_endpoint(raw)
            host = (platform.system(), platform.machine())
            require(host in {('Linux', 'x86_64'), ('Darwin', 'arm64')}
                and host in TOOLS['trivy'] and TOOLS['trivy'][host]['version'] == '0.76.1')
            trivy = install_tool('trivy', state)
            executable = file_identity(trivy, MAX_EXECUTABLE)
            frozen[trivy] = (MAX_EXECUTABLE, executable)
            def frozen_command(command, **kwargs):
                verify_files(frozen)
                try:
                    return bounded_command(command, env=env, cwd=state, **kwargs)
                finally:
                    verify_files(frozen)
            # Config loading logs to stderr, which our bounded helper merges
            # with stdout. Quiet preserves a single strict JSON document.
            code, raw = frozen_command([str(trivy), 'version', '--format', 'json', '--config', str(config), '--quiet'])
            require(code == 0 and _json(raw).get('Version') == '0.76.1')
            status['scanner'] = dict(name='trivy', version='0.76.1', platform='-'.join(host),
                archive_sha256=TOOLS['trivy'][host]['sha256'], executable_sha256=executable['sha256'])
            for flag in ('--download-db-only', '--download-java-db-only'):
                code, _ = frozen_command([str(trivy), 'image', '--config', str(config), flag,
                    '--timeout', '10m'], timeout=660)
                require(code == 0)
            status['databases'], database_pins = database_identities(Path(env['TRIVY_CACHE_DIR']))
            frozen.update(database_pins)
            codes, total = [], 0
            for role in ROLES:
                verify_pin(receipt, pin)
                report = 'trivy-' + role + '.json'
                with publication.report(report) as report_fd:
                    identity = os.fstat(report_fd)
                    code, log = frozen_command([str(trivy), 'image', '--image-src', 'docker',
                        '--config', str(config), '--ignorefile', str(ignore), '--list-all-pkgs',
                        '--scanners', 'vuln', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
                        '--skip-db-update', '--skip-java-db-update',
                        '--exit-code', '1', '--format', 'json', '--timeout', '10m',
                        '--output', '/dev/fd/' + str(report_fd), images[role]], timeout=660,
                        report=report_fd, pass_fds=(report_fd,))
                    report_pin = publication.read(report)
                    publication.write(role + '.log', log)
                    require(report_pin['size'] <= MAX_REPORT
                        and report_pin['stamp'][:2] == (identity.st_dev, identity.st_ino))
                document = report_pin['json']
                require(type(document.get('Trivy')) is dict and document['Trivy'].get('Version') == '0.76.1'
                    and document.get('ArtifactType') == 'container_image'
                    and document.get('ArtifactName') == images[role]
                    and type(document.get('Metadata')) is dict
                    and document['Metadata'].get('ImageID') == images[role])
                count, findings, complete = finding_details(document)
                reports.append((report, report_pin))
                total += count
                codes.append(code)
                status['images'][role] = {'image_id': images[role], 'report_sha256': report_pin['sha256'],
                    'vulnerabilities': count, 'coverage': validate_inventory(document, role),
                    'findings': findings, 'finding_details_complete': complete}
                if len(status['images']) == len(ROLES): status['vulnerabilities'] = total
            verify_pin(receipt, pin)
            verify_files(frozen)
            for report, report_pin in reports:
                publication.verify(report, report_pin)
            integrity_verified = True
            status['coverage_passed'] = all(row['coverage']['os_inventory']
                and (row['coverage']['application_inventory'] is True if role != 'redis' else True)
                for role, row in status['images'].items())
            status['finding_details_complete'] = (all(code in (0, 1) for code in codes)
                and all(row['finding_details_complete'] for row in status['images'].values()))
            status['automated_checks_passed'] = (all(code == 0 for code in codes) and total == 0
                and status['coverage_passed'] and status['finding_details_complete'])
            status['reason'] = ('container_scan_unverified' if any(code not in (0, 1) for code in codes)
                else 'findings_present' if total else 'inventory_unverified' if not status['coverage_passed']
                else 'local_images_checked' if all(code == 0 for code in codes)
                else 'container_scan_unverified')
            if status['reason'] == 'container_scan_unverified': status['finding_details_complete'] = False
        except (Exception, KeyboardInterrupt):
            status.update(automated_checks_passed=False, finding_details_complete=False, reason='container_scan_unverified')
        publication.write('status.json', status_bytes(status))
        # The private cache remains alive through publication. Even findings-
        # positive detail/count claims retain their exact reports, tool and DBs.
        def final_guard():
            if integrity_verified:
                verify_pin(receipt, pin)
                verify_files(frozen)
                for report, report_pin in reports:
                    publication.verify(report, report_pin)
        final_guard()
        publication.publish()
        final_guard()
        publication.check_output()
    return status


class FixedParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('container_scan_unverified')


def main(argv=None):
    parser = FixedParser(description=__doc__)
    parser.add_argument('--receipt', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--docker-context', choices=['default'], default='default')
    try:
        args = parser.parse_args(argv)
        with cooperative_termination():
            status = scan(args.receipt, args.output, args.docker_context)
    except (Exception, KeyboardInterrupt):
        status = {'schema': 2, 'evidence_class': 'owned_container_image_scan', 'release_ready': False,
            'automated_checks_passed': False, 'reason': 'container_scan_unverified',
            'qualification_sha256': None, 'images': {}, 'scanners': ['vuln'], 'vulnerabilities': None, 'secrets': None,
            'scanner': None, 'databases': None, 'finding_details_complete': False,
            'coverage_complete': False, 'native_binary_coverage': False, 'complete_resolved_graph': False,
            'coverage_passed': False, 'coverage_limitations': ['redis_native_binary_unverified',
                'native_runtimes_unverified', 'complete_dependency_closure_unverified']}
    print(json.dumps(status, sort_keys=True))
    return 0 if status['automated_checks_passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
